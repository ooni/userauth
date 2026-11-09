These are test-only keys and a client credential issued through registration
by unmodified UserAuth `4a08ed3`, using the versions in that commit's Cargo.lock
(CMZ 0.2.1, sigma-compiler 0.2.1, sigma-proofs 0.2.1).

To regenerate, use a separate checkout at `4a08ed3`, copy `generate.rs` to
`ooniauth-core/examples/legacy_fixture.rs`, and run:

```sh
cargo run --locked -p ooniauth-core --example legacy_fixture -- /absolute/path/to/these/fixtures
```

`legacy-server.bincode` contains the test issuer's saved state, including its
secret key. `legacy-credential.bincode` is the result of bincode 1 serializing
the client's fully issued credential, including the old empty private-key field.
The tests use the credential's saved issuance day rather than the current date.
