use ooniauth_core::{registration::open_registration, update::update, ServerState};

#[test]
fn otf_013_update_rejects_crash_input() {
    // Exact audit input: crash-fbfec763af3f4f3e792af932dac036cf809616d5.
    let mut input = [0u8; 202];
    input[..3].copy_from_slice(&[126, 10, 42]);
    input[37..46].fill(255);
    input[61] = 8;
    input[201] = 202;
    let req = bincode::deserialize::<update::Request>(&input).unwrap();
    let rng = &mut rand::rng();
    let old = ServerState::new(rng);
    let new = ServerState::new(rng);
    assert!(matches!(
        new.handle_update(rng, req, old.secret_key_ref(), old.public_parameters_ref()),
        Err(cmz::CMZError::CliProofFailed)
    ));
}

#[test]
fn otf_016_registration_rejects_crash_input() {
    // Exact audit input: crash-65c49588a953807ec7d0ceab7bfc661069fb7fbd.
    let mut input = [0u8; 43];
    input[41..].copy_from_slice(&[189, 10]);
    let req = bincode::deserialize::<open_registration::Request>(&input).unwrap();
    assert!(matches!(
        ServerState::new(&mut rand::rng()).open_registration(req),
        Err(cmz::CMZError::IssProofFailed)
    ));
}
