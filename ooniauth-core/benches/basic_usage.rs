use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use ooniauth_core::{ServerState, UserState};
use rand::{rngs::ThreadRng, thread_rng};

fn setup() -> (ThreadRng, UserState, ServerState) {
    let mut rng = thread_rng();
    let server = ServerState::new(&mut rng);
    let pp = server.public_parameters();
    let user = UserState::new(pp);

    (rng, user, server)
}

fn bench_registration(c: &mut Criterion) {
    let (mut rng, user, server) = setup();

    let (registration_req , state)= user.request(&mut rng).unwrap();
    // c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
}

criterion_group!(benches, bench_registration);
criterion_main!(benches);