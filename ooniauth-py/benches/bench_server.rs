use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ooniauth_py::{ServerState, UserState};
use pyo3::{Py, Python, types::PyString};
use rand::{distributions::Alphanumeric, Rng};

fn random_ascii_string_mb(mb: usize) -> String {
    let byte_count = mb * 1024 * 1024;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(byte_count)
        .map(char::from)
        .collect()
}

fn bench_submit(c: &mut Criterion) {
    pyo3::Python::initialize();
    Python::attach(|py| {
        c.bench_function("server.handle_submit_request_with_hash", |b| {
            b.iter_batched(|| {
                let server = ServerState::new();
                let mut client = UserState::new(py, server.get_public_parameters(py)).unwrap();
                let req = client.make_registration_request(py).unwrap();
                let reg_response = server.handle_registration_request(py, req).unwrap();
                client
                    .handle_registration_response(py, reg_response)
                    .unwrap();

                let cc: Py<PyString> = PyString::new(py, "VE").into();
                let asn: Py<PyString> = PyString::new(py, "AS1234").into();
                let msm_body = random_ascii_string_mb(1);
                let measurement: Py<PyString> = PyString::new(py, msm_body.as_str()).into();
                let today = ServerState::today();
                let age_tuple = (today - 30, today + 1);
                let min_msm = 0u32;

                let submit_req = client
                    .make_submit_request_with_hash(
                        py,
                        cc.clone_ref(py),
                        asn.clone_ref(py),
                        measurement.clone_ref(py),
                        age_tuple,
                        min_msm,
                    )
                    .unwrap();

                (server, submit_req, cc, asn, measurement, age_tuple, min_msm)
            },
                |(server, submit_req, cc, asn, measurement, age_tuple, min_msm)| {
                server.handle_submit_request_with_hash(
                    py,
                    submit_req.nym,
                    submit_req.request,
                    cc,
                    asn,
                    measurement,
                    age_tuple,
                    min_msm
                )
            }, BatchSize::SmallInput);
        });
    });
}

criterion_group!(benches, bench_submit);
criterion_main!(benches);
