use ooniauth_core::{ServerState, UserState};

fn main() {
    let mut rng = rand::thread_rng();
    let server = ServerState::new(&mut rng);
    let mut client = UserState::new(server.public_parameters());
    let (request, state) = client.request(&mut rng).unwrap();
    let reply = server.open_registration(request).unwrap();
    client.handle_response(state, reply).unwrap();
    let destination = std::env::args().nth(1).expect("fixture directory");
    for (name, bytes) in [
        (
            "legacy-server.bincode",
            bincode::serialize(&server).unwrap(),
        ),
        (
            "legacy-credential.bincode",
            bincode::serialize(client.get_credential().unwrap()).unwrap(),
        ),
    ] {
        std::fs::write(std::path::Path::new(&destination).join(name), bytes).unwrap();
    }
}
