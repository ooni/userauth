# OONI User Auth

Run example:
```bash
cargo run -p ooniauth-core --release --example basic_usage
```

iOS build:
Open `ios/OoniAuthApp.xcodeproj` in Xcode.

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
