use criterion::{criterion_group, criterion_main, Criterion};
use ooniauth_core::{ServerState, UserState};
use rand::thread_rng;
use std::hint::black_box;

fn run_basic_usage_flow() {
    let mut rng = thread_rng();
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();
    let mut user = UserState::new(public_params);

    let (reg_request, reg_state) = user.request(&mut rng).unwrap();
    let reg_response = server.open_registration(reg_request).unwrap();
    user.handle_response(reg_state, reg_response).unwrap();

    let today = ServerState::today();
    let age_range = (today - 30)..(today + 1);
    let measurement_count_range = 0..100;

    let ((submit_request, submit_state), nym) = user
        .submit_request(
            &mut rng,
            "US".to_string(),
            "AS1234".to_string(),
            age_range.clone(),
            measurement_count_range.clone(),
        )
        .unwrap();

    let submit_response = server
        .handle_submit(
            &mut rng,
            submit_request,
            &nym,
            "US",
            "AS1234",
            age_range,
            measurement_count_range,
        )
        .unwrap();
    user.handle_submit_response(submit_state, submit_response)
        .unwrap();

    let age_range2 = (today - 30)..(today + 1);
    let measurement_count_range2 = 0..100;

    let ((submit_request2, submit_state2), nym2) = user
        .submit_request(
            &mut rng,
            "UK".to_string(),
            "AS5678".to_string(),
            age_range2.clone(),
            measurement_count_range2.clone(),
        )
        .unwrap();

    let submit_response2 = server
        .handle_submit(
            &mut rng,
            submit_request2,
            &nym2,
            "UK",
            "AS5678",
            age_range2,
            measurement_count_range2,
        )
        .unwrap();
    user.handle_submit_response(submit_state2, submit_response2)
        .unwrap();

    black_box(user.get_credential().is_some());
}

fn bench_basic_usage(c: &mut Criterion) {
    c.bench_function("basic_usage_flow", |b| b.iter(run_basic_usage_flow));
}

criterion_group!(benches, bench_basic_usage);
criterion_main!(benches);
