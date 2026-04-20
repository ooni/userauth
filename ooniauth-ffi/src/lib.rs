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

fn log_credential(log: &mut String, label: &str, cred: &UserAuthCredential) -> Result<(), String> {
    push_line(log, "");
    push_line(log, &format!("   === {label} ==="));

    let nym_id = cred
        .nym_id
        .ok_or_else(|| "missing nym_id in credential".to_string())?;
    let age = cred
        .age
        .ok_or_else(|| "missing age in credential".to_string())?;
    let measurement_count = cred
        .measurement_count
        .ok_or_else(|| "missing measurement_count in credential".to_string())?;

    push_line(
        log,
        &format!("   - nym_id: {}", hex::encode(nym_id.to_bytes())),
    );

    let age_value = scalar_u32(&age).ok_or_else(|| "age is not a u32".to_string())?;
    push_line(log, &format!("   - age: {}", age_value));

    let measurement_value = scalar_u32(&measurement_count)
        .ok_or_else(|| "measurement_count is not a u32".to_string())?;
    push_line(
        log,
        &format!("   - measurement_count: {}", measurement_value),
    );

    Ok(())
}

fn run_basic_usage_demo() -> Result<String, String> {
    init_tracing();
    let mut log = String::new();
    push_line(&mut log, "=== Anonymous Credential Example ===");
    push_line(&mut log, "");

    // Match the flow in ooniauth-core/examples/basic_usage.rs so the iOS app
    // surfaces identical outputs and timings.
    let mut rng = rand::thread_rng();
    push_line(&mut log, "1. Initializing server...");
    let now = Instant::now();
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();
    push_line(
        &mut log,
        &format!(
            "   Key generation completed in {} ms",
            now.elapsed().as_millis()
        ),
    );

    push_line(&mut log, "");
    push_line(&mut log, "2. Initializing user...");
    let now = Instant::now();
    let mut user = UserState::new(public_params);
    push_line(
        &mut log,
        &format!("   User initialized in {} ms", now.elapsed().as_millis()),
    );

    push_line(&mut log, "");
    push_line(&mut log, "3. User registration...");
    let now = Instant::now();
    let (reg_request, reg_state) = user
        .request(&mut rng)
        .map_err(|e| format!("registration request failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Registration request created in {} ms",
            now.elapsed().as_millis()
        ),
    );

    let request_bytes = reg_request.as_bytes();
    push_line(
        &mut log,
        &format!("   Request size: {} bytes", request_bytes.len()),
    );
    push_line(
        &mut log,
        &format!("   Request payload (hex): {}", hex::encode(&request_bytes)),
    );

    let now = Instant::now();
    let reg_response = server
        .open_registration(reg_request)
        .map_err(|e| format!("registration response failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Server processed registration in {} ms",
            now.elapsed().as_millis()
        ),
    );

    let response_bytes = reg_response.as_bytes();
    push_line(
        &mut log,
        &format!("   Response size: {} bytes", response_bytes.len()),
    );

    let now = Instant::now();
    user.handle_response(reg_state, reg_response)
        .map_err(|e| format!("registration finalize failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   User handled response in {} ms",
            now.elapsed().as_millis()
        ),
    );

    log_credential(
        &mut log,
        "Initial Credential Attributes",
        user.get_credential()
            .ok_or_else(|| "credential missing after registration".to_string())?,
    )?;

    push_line(&mut log, "");
    push_line(&mut log, "4. Creating anonymous report submission...");
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
            "   Submit request created for {probe_cc}/{probe_asn} in {} ms",
            now.elapsed().as_millis()
        ),
    );
    push_line(&mut log, "   Domain-specific pseudonym computed");
    push_line(&mut log, &format!("   NYM (hex): {}", hex::encode(nym)));
    let submit_request_bytes = submit_request.as_bytes();
    push_line(
        &mut log,
        &format!("   Request size: {} bytes", submit_request_bytes.len()),
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
            "   Server validated submission and issued updated credential in {} ms",
            now.elapsed().as_millis()
        ),
    );
    let submit_response_bytes = submit_response.as_bytes();
    push_line(
        &mut log,
        &format!("   Response size: {} bytes", submit_response_bytes.len()),
    );
    let now = Instant::now();
    user.handle_submit_response(submit_state, submit_response)
        .map_err(|e| format!("submit finalize failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   User handled submit response in {} ms",
            now.elapsed().as_millis()
        ),
    );

    log_credential(
        &mut log,
        "Updated Credential Attributes",
        user.get_credential()
            .ok_or_else(|| "credential missing after submit".to_string())?,
    )?;

    push_line(&mut log, "");
    push_line(&mut log, "5. Creating second submission...");
    let probe_cc2 = "UK".to_string();
    let probe_asn2 = "AS5678".to_string();

    let age_range2 = (today - 30)..(today + 1);
    let measurement_count_range2 = 0..100;

    let now = Instant::now();
    let ((submit_request2, submit_state2), nym2) = user
        .submit_request(
            &mut rng,
            probe_cc2.clone(),
            probe_asn2.clone(),
            age_range2.clone(),
            measurement_count_range2.clone(),
        )
        .map_err(|e| format!("submit request 2 failed: {e:?}"))?;

    push_line(
        &mut log,
        &format!(
            "   Submit request created for {probe_cc2}/{probe_asn2} in {} ms",
            now.elapsed().as_millis()
        ),
    );
    push_line(&mut log, "   Different domain produces different pseudonym");
    push_line(&mut log, &format!("   NYM (hex): {}", hex::encode(nym2)));

    let now = Instant::now();
    let submit_response2 = server
        .handle_submit(
            &mut rng,
            submit_request2,
            &nym2,
            &probe_cc2,
            &probe_asn2,
            age_range2,
            measurement_count_range2,
        )
        .map_err(|e| format!("submit handling 2 failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Second submit request handled by server in {} ms",
            now.elapsed().as_millis()
        ),
    );

    let now = Instant::now();
    user.handle_submit_response(submit_state2, submit_response2)
        .map_err(|e| format!("submit finalize 2 failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Second submit response handled by user in {} ms",
            now.elapsed().as_millis()
        ),
    );

    log_credential(
        &mut log,
        "Final Credential Attributes",
        user.get_credential()
            .ok_or_else(|| "credential missing after second submit".to_string())?,
    )?;

    Ok(log)
}

fn run_benchmark_table() -> Result<String, String> {
    ooniauth_core::benchmark::run_benchmark_table()
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

#[no_mangle]
pub extern "C" fn ooniauth_run_client_benchmarks() -> *mut c_char {
    let output = match run_benchmark_table() {
        Ok(table) => table,
        Err(err) => format!("error: {err}"),
    };

    CString::new(output)
        .unwrap_or_else(|_| CString::new("error: output contained nul byte").unwrap())
        .into_raw()
}

/// # Safety
/// Caller must pass the pointer returned by one of the `ooniauth_run_*`
/// functions in this file. The pointer must be valid, non-null, and freed
/// exactly once.
#[no_mangle]
pub unsafe extern "C" fn ooniauth_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}
