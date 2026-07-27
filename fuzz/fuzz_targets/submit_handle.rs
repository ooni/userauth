#![no_main]
//! Lead target: most remote-facing surface.
//!
//! Mirrors `ServerState::handle_submit_request` in `ooniauth-py`, which is just
//! `base64 -> bincode::deserialize::<SubmitRequest> -> ServerState::handle_submit`.
//! We feed raw bytes (== post-base64 input) straight into the bincode decoder
//! and the server submit handler.
//!
//! Phase 1 maximises coverage of the deserialization / wire-decode surface
//! (the primary remote DoS / panic vector). The server short-circuits when the
//! request's nym digest does not match `probe_id`; reaching the cryptographic
//! verify path with attacker-chosen nyms is the job of the later structured
//! harness, since `nym_point` is a private field here.
use libfuzzer_sys::fuzz_target;
use ooniauth_core::submit::SubmitRequest;
use ooniauth_core::ServerState;
use std::sync::OnceLock;

static SERVER: OnceLock<ServerState> = OnceLock::new();

fn server() -> &'static ServerState {
    // `ServerState::new` also runs `cmz_group_init`, which must happen before
    // any protocol handler is called.
    SERVER.get_or_init(|| ServerState::new(&mut rand::thread_rng()))
}

fuzz_target!(|data: &[u8]| {
    let Ok(req) = bincode::deserialize::<SubmitRequest>(data) else {
        return;
    };

    let server = server();
    let probe_id = [0u8; 32];
    let today = ServerState::today();
    let age_range = today.saturating_sub(30)..today.saturating_add(1);
    let measurement_count_range = 0u32..100u32;
    let measurement_hash = [1u8; 32];

    let mut rng = rand::thread_rng();
    let _ = server.handle_submit(
        &mut rng,
        req,
        &probe_id,
        "US",
        "AS1234",
        &measurement_hash,
        age_range,
        measurement_count_range,
    );
});
