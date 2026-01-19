use std::ffi::{c_char, CString};
use std::sync::Once;
use std::time::Instant;

use ooniauth_core::registration::UserAuthCredential;
use ooniauth_core::{scalar_u32, ServerState, UserState};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

static TRACING_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    });
}

fn push_line(log: &mut String, line: &str) {
    log.push_str(line);
    log.push('\n');
}

fn log_credential(
    log: &mut String,
    label: &str,
    cred: &UserAuthCredential,
) -> Result<(), String> {
    push_line(log, "");
    push_line(log, label);

    let nym_id = cred
        .nym_id
        .ok_or_else(|| "missing nym_id in credential".to_string())?;
    let age = cred
        .age
        .ok_or_else(|| "missing age in credential".to_string())?;
    let measurement_count = cred
        .measurement_count
        .ok_or_else(|| "missing measurement_count in credential".to_string())?;

    push_line(log, &format!("nym_id: {}", hex::encode(nym_id.to_bytes())));

    let age_value = scalar_u32(&age).ok_or_else(|| "age is not a u32".to_string())?;
    push_line(log, &format!("age: {}", age_value));

    let measurement_value = scalar_u32(&measurement_count)
        .ok_or_else(|| "measurement_count is not a u32".to_string())?;
    push_line(log, &format!("measurement_count: {}", measurement_value));

    Ok(())
}

fn run_basic_usage_demo() -> Result<String, String> {
    init_tracing();
    let mut log = String::new();
    push_line(&mut log, "=== OONI Auth Demo ===");

    let mut rng = rand::thread_rng();
    let now = Instant::now();
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();
    push_line(
        &mut log,
        &format!("Initialized server in {} ms", now.elapsed().as_millis()),
    );

    let now = Instant::now();
    let mut user = UserState::new(public_params);
    push_line(
        &mut log,
        &format!("Initialized user in {} ms", now.elapsed().as_millis()),
    );

    let now = Instant::now();
    let (reg_request, reg_state) = user
        .request(&mut rng)
        .map_err(|e| format!("registration request failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "Registration request created in {} ms",
            now.elapsed().as_millis()
        ),
    );
    let now = Instant::now();
    let reg_response = server
        .open_registration(reg_request)
        .map_err(|e| format!("registration response failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "Registration response created in {} ms",
            now.elapsed().as_millis()
        ),
    );
    let now = Instant::now();
    user.handle_response(reg_state, reg_response)
        .map_err(|e| format!("registration finalize failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "Registration finalized in {} ms",
            now.elapsed().as_millis()
        ),
    );
    push_line(&mut log, "Registration complete");

    match user.get_credential() {
        Some(cred) => log_credential(&mut log, "Initial credential", cred)?,
        None => return Err("credential missing after registration".to_string()),
    }

    let probe_cc = "US".to_string();
    let probe_asn = "AS1234".to_string();
    let today = ServerState::today();
    let age_range = (today - 30)..(today + 1);
    let measurement_count_range = 0..100;

    let now = Instant::now();
    let ((submit_request, submit_state), nym) = user
        .submit_request(
            &mut rng,
            probe_cc.clone(),
            probe_asn.clone(),
            age_range.clone(),
            measurement_count_range.clone(),
        )
        .map_err(|e| format!("submit request failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "Submit request created in {} ms",
            now.elapsed().as_millis()
        ),
    );

    let now = Instant::now();
    let submit_response = server
        .handle_submit(
            &mut rng,
            submit_request,
            &nym,
            &probe_cc,
            &probe_asn,
            age_range,
            measurement_count_range,
        )
        .map_err(|e| format!("submit handling failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "Submit handled in {} ms",
            now.elapsed().as_millis()
        ),
    );
    let now = Instant::now();
    user.handle_submit_response(submit_state, submit_response)
        .map_err(|e| format!("submit finalize failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "Submit finalized in {} ms",
            now.elapsed().as_millis()
        ),
    );
    push_line(&mut log, "Submit complete");

    match user.get_credential() {
        Some(cred) => log_credential(&mut log, "Updated credential", cred)?,
        None => return Err("credential missing after submit".to_string()),
    }

    Ok(log)
}

#[no_mangle]
pub extern "C" fn ooniauth_run_basic_usage() -> *mut c_char {
    let output = match run_basic_usage_demo() {
        Ok(log) => log,
        Err(err) => format!("error: {err}"),
    };

    CString::new(output)
        .unwrap_or_else(|_| CString::new("error: output contained nul byte").unwrap())
        .into_raw()
}

/// Caller must pass the pointer returned by `ooniauth_run_basic_usage`.
#[no_mangle]
pub unsafe extern "C" fn ooniauth_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}
