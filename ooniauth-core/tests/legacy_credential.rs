use cmz::CMZCredential;
use ooniauth_core::{scalar_u32, submit::submit_measurement_hash, ServerState, UserState};

const CREDENTIAL: &[u8] = include_bytes!("fixtures/legacy-credential.bincode");

fn server() -> ServerState {
    let saved: ServerState =
        bincode::deserialize(include_bytes!("fixtures/legacy-server.bincode")).unwrap();
    ServerState::from_creds(saved.secret_key_ref().clone(), saved.public_parameters())
}

#[test]
fn legacy_credential_can_submit() {
    let server = server();
    let mut client = UserState::new(server.public_parameters());
    client.load_legacy_credential(CREDENTIAL).unwrap();
    let old = client.get_credential().unwrap().clone();
    old.verify_MAC(server.secret_key_ref()).unwrap();
    assert!(old.get_privkey().x.is_empty());
    let age = scalar_u32(old.age.as_ref().unwrap()).unwrap();
    let count = scalar_u32(old.measurement_count.as_ref().unwrap()).unwrap();
    let hash = submit_measurement_hash(b"legacy credential submission");
    let rng = &mut rand::rng();
    let ((request, state), nym) = client
        .submit_request(
            rng,
            "US".into(),
            "AS1234".into(),
            &hash,
            age - 30..age + 1,
            count..count + 100,
        )
        .unwrap();
    let reply = server
        .handle_submit(
            rng,
            request,
            &nym,
            "US",
            "AS1234",
            &hash,
            age - 30..age + 1,
            count..count + 100,
        )
        .unwrap();
    client.handle_submit_response(state, reply).unwrap();
    let credential = client.get_credential().unwrap();
    assert_eq!(credential.nym_id, old.nym_id);
    assert_eq!(credential.age, old.age);
    assert_eq!(
        scalar_u32(credential.measurement_count.as_ref().unwrap()),
        Some(count + 1)
    );
    credential.verify_MAC(server.secret_key_ref()).unwrap();
}
