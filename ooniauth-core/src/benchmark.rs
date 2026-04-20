use std::ops::Range;
use std::time::Instant;

use rand::{CryptoRng, RngCore};

use crate::{ServerState, UserState};

const ITERATIONS: usize = 1000;

#[derive(Debug, Clone, Copy)]
struct Summary {
    mean_ms: f64,
    stddev_ms: f64,
}

#[derive(Debug, Clone, Copy)]
struct ProtocolSample {
    client_ms: f64,
    server_ms: f64,
}

fn measure_ms<T>(f: impl FnOnce() -> Result<T, String>) -> Result<(T, f64), String> {
    let start = Instant::now();
    let value = f()?;
    Ok((value, start.elapsed().as_secs_f64() * 1000.0))
}

fn summarize(samples: &[f64]) -> Result<Summary, String> {
    if samples.is_empty() {
        return Err("no samples collected".to_string());
    }

    let count = samples.len() as f64;
    let mean_ms = samples.iter().sum::<f64>() / count;
    let variance = if samples.len() > 1 {
        samples
            .iter()
            .map(|sample| {
                let delta = sample - mean_ms;
                delta * delta
            })
            .sum::<f64>()
            / (count - 1.0)
    } else {
        0.0
    };

    Ok(Summary {
        mean_ms,
        stddev_ms: variance.sqrt(),
    })
}

fn register_user(rng: &mut (impl RngCore + CryptoRng)) -> Result<(ServerState, UserState), String> {
    let server = ServerState::new(rng);
    let mut user = UserState::new(server.public_parameters());

    let (registration_request, registration_state) = user
        .request(rng)
        .map_err(|e| format!("registration request failed: {e:?}"))?;
    let registration_response = server
        .open_registration(registration_request)
        .map_err(|e| format!("registration response failed: {e:?}"))?;

    user.handle_response(registration_state, registration_response)
        .map_err(|e| format!("registration finalize failed: {e:?}"))?;

    Ok((server, user))
}

fn sample_reg_ms() -> Result<ProtocolSample, String> {
    let mut rng = rand::thread_rng();
    let server = ServerState::new(&mut rng);
    let mut user = UserState::new(server.public_parameters());

    let ((registration_request, registration_state), request_ms) = measure_ms(|| {
        user.request(&mut rng)
            .map_err(|e| format!("registration request failed: {e:?}"))
    })?;
    let (registration_response, server_ms) = measure_ms(|| {
        server
            .open_registration(registration_request)
            .map_err(|e| format!("registration response failed: {e:?}"))
    })?;

    let (_, handle_ms) = measure_ms(|| {
        user.handle_response(registration_state, registration_response)
            .map_err(|e| format!("registration finalize failed: {e:?}"))
    })?;

    Ok(ProtocolSample {
        client_ms: request_ms + handle_ms,
        server_ms,
    })
}

fn sample_submit_ms() -> Result<ProtocolSample, String> {
    let mut rng = rand::thread_rng();
    let (server, mut user) = register_user(&mut rng)?;
    let today = ServerState::today();
    let age_range: Range<u32> = (today - 30)..(today + 1);
    let measurement_count_range: Range<u32> = 0..100;

    let (((submit_request, submit_state), nym), request_ms) = measure_ms(|| {
        user.submit_request(
            &mut rng,
            "US".to_string(),
            "AS1234".to_string(),
            age_range.clone(),
            measurement_count_range.clone(),
        )
        .map_err(|e| format!("submit request failed: {e:?}"))
    })?;
    let (submit_response, server_ms) = measure_ms(|| {
        server
            .handle_submit(
                &mut rng,
                submit_request,
                &nym,
                "US",
                "AS1234",
                age_range,
                measurement_count_range,
            )
            .map_err(|e| format!("submit handling failed: {e:?}"))
    })?;

    let (_, handle_ms) = measure_ms(|| {
        user.handle_submit_response(submit_state, submit_response)
            .map_err(|e| format!("submit finalize failed: {e:?}"))
    })?;

    Ok(ProtocolSample {
        client_ms: request_ms + handle_ms,
        server_ms,
    })
}

fn sample_update_ms() -> Result<ProtocolSample, String> {
    let mut rng = rand::thread_rng();
    let (old_server, mut user) = register_user(&mut rng)?;
    let new_server = ServerState::new(&mut rng);
    user.pp = new_server.public_parameters();

    let ((update_request, update_state), request_ms) = measure_ms(|| {
        user.update_request(&mut rng)
            .map_err(|e| format!("update request failed: {e:?}"))
    })?;

    let (update_response, server_ms) = measure_ms(|| {
        new_server
            .handle_update(
                &mut rng,
                update_request,
                old_server.secret_key_ref(),
                old_server.public_parameters_ref(),
            )
            .map_err(|e| format!("update handling failed: {e:?}"))
    })?;

    let (_, handle_ms) = measure_ms(|| {
        user.handle_update_response(update_state, update_response)
            .map_err(|e| format!("update finalize failed: {e:?}"))
    })?;

    Ok(ProtocolSample {
        client_ms: request_ms + handle_ms,
        server_ms,
    })
}

fn collect_protocol_summaries(
    iterations: usize,
    mut sample: impl FnMut() -> Result<ProtocolSample, String>,
) -> Result<(Summary, Summary), String> {
    let mut client_samples = Vec::with_capacity(iterations);
    let mut server_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let sample = sample()?;
        client_samples.push(sample.client_ms);
        server_samples.push(sample.server_ms);
    }
    Ok((summarize(&client_samples)?, summarize(&server_samples)?))
}

fn format_row(label: &str, summary: Summary) -> String {
    format!("{label} {:.2} {:.2}", summary.mean_ms, summary.stddev_ms)
}

pub fn run_benchmark_table() -> Result<String, String> {
    run_benchmark_table_with_iterations(ITERATIONS)
}

fn run_benchmark_table_with_iterations(iterations: usize) -> Result<String, String> {
    let (client_reg, server_reg) = collect_protocol_summaries(iterations, sample_reg_ms)?;
    let (client_submit, server_submit) = collect_protocol_summaries(iterations, sample_submit_ms)?;
    let (client_update, server_update) = collect_protocol_summaries(iterations, sample_update_ms)?;

    let mut output = String::new();
    let rows = [
        ("client_reg", client_reg),
        ("client_submit", client_submit),
        ("client_update", client_update),
        ("server_reg", server_reg),
        ("server_submit", server_submit),
        ("server_update", server_update),
    ];

    for (idx, (label, summary)) in rows.into_iter().enumerate() {
        if idx > 0 {
            output.push('\n');
        }
        output.push_str(&format_row(label, summary));
    }

    Ok(output)
}
