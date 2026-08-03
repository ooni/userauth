# OONI User Auth

See the [specification](https://github.com/ooni/spec/blob/master/backends/bk-006-anon-creds.md)
and the [academic paper](https://eprint.iacr.org/2026/794) for details and benchmarks.

Run example:
```bash
cargo run -p ooniauth-core --release --example basic_usage
```

Criterion benchmark (same flow):
```bash
cargo bench -p ooniauth-core
cargo bench -p ooniauth_py
```

To generate a flamegraph for ooniath_py benchmarks:
```bash
cargo bench -p ooniauth_py --bench bench_server  -- --profile-time 5
```

The resulting report will be stored on `target/criterion/server.handle_submit_request_with_hash/profile/flamegraph.svg`
