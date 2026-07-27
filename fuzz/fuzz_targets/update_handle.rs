#![no_main]
//! Server-facing credential-update ingress.
//!
//! Mirrors `ServerState::handle_update_request` in `ooniauth-py`:
//! `base64 -> bincode::deserialize::<update::Request> ->
//! ServerState::handle_update`. The old-key material is held fixed; the fuzzer
//! controls only the request bytes (the remote-attacker-controlled input).
use libfuzzer_sys::fuzz_target;
use ooniauth_core::update::update;
use ooniauth_core::ServerState;
use std::sync::OnceLock;

static NEW_SERVER: OnceLock<ServerState> = OnceLock::new();
static OLD_SERVER: OnceLock<ServerState> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Ok(req) = bincode::deserialize::<update::Request>(data) else {
        return;
    };

    let new_server = NEW_SERVER.get_or_init(|| ServerState::new(&mut rand::thread_rng()));
    let old_server = OLD_SERVER.get_or_init(|| ServerState::new(&mut rand::thread_rng()));

    let mut rng = rand::thread_rng();
    let _ = new_server.handle_update(
        &mut rng,
        req,
        old_server.secret_key_ref(),
        old_server.public_parameters_ref(),
    );
});
