#![no_main]
//! Server-facing registration ingress.
//!
//! Mirrors `ServerState::handle_registration_request` in `ooniauth-py`:
//! `base64 -> bincode::deserialize::<open_registration::Request> ->
//! ServerState::open_registration`. Exercises the macro-generated wire decoder
//! and the `try_from(&bytes).unwrap()` re-decode inside the handler.
use libfuzzer_sys::fuzz_target;
use ooniauth_core::registration::open_registration;
use ooniauth_core::ServerState;
use std::sync::OnceLock;

static SERVER: OnceLock<ServerState> = OnceLock::new();

fn server() -> &'static ServerState {
    SERVER.get_or_init(|| ServerState::new(&mut rand::thread_rng()))
}

fuzz_target!(|data: &[u8]| {
    let Ok(req) = bincode::deserialize::<open_registration::Request>(data) else {
        return;
    };
    let _ = server().open_registration(req);
});
