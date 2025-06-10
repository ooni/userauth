/* A module for the protocol for the user to register with the OONI Authority (OA)
 * to receive their initial User Auth Credential
 * The credential will have attributes:
 * - nym_id: selected jointly by the user and OA
 * - age: set by the OA to the date at the time of issuance
 * - measurement_count: All new accounts will begin with 0
*/

use super::OONIAuth;
use super::{Scalar, G};
use cmz::*;
use group::Group;
use rand::RngCore;
use sha2::Sha512;

CMZ! { UserAuthCredential:
    nym_id,
    age,
    measurement_count
}

muCMZProtocol! {open_registration,
    ,
    UAC: UserAuthCredential { nym_id: J, age: S, measurement_count: I},
}

pub fn request(
    pubkeys: CMZPubkey<G>,
) -> Result<(open_registration::Request, open_registration::ClientState), CMZError> {
    let mut rng = rand::thread_rng();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    let mut UAC = UserAuthCredential::using_pubkey(&pubkeys);
    // nym_id is a random scalar that the user will keep secret but re-randomize at each request to
    // the OA
    // Generate random generic scalar
    let const_nym = Scalar::random(&mut rng);
    UAC.nym_id = Some(const_nym);

    match open_registration::prepare(&mut rng, UAC) {
        Ok(req_state) => Ok(req_state),
        Err(_) => Err(CMZError::CliProofFailed),
    }
}

impl OONIAuth {
    pub fn open_registration(
        &mut self,
        req: open_registration::Request,
    ) -> Result<open_registration::Reply, CMZError> {
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();

        let recvreq = open_registration::Request::try_from(&reqbytes[..]).unwrap();
        match open_registration::handle(
            &mut rng,
            recvreq,
            |UAC: &mut UserAuthCredential| {
                UAC.set_privkey(&self.privkey);
                UAC.measurement_count = Some(Scalar::ZERO);
                UAC.age = Some(self.today().into());
                Ok(())
            },
            |_UAC: &UserAuthCredential| Ok(()),
        ) {
            Ok((response, _UAC_issuer)) => Ok(response),
            Err(_) => Err(CMZError::IssProofFailed),
        }
    }
}

pub fn handle_response(
    state: open_registration::ClientState,
    rep: open_registration::Reply,
) -> Result<UserAuthCredential, CMZError> {
    let replybytes = rep.as_bytes();
    let recvreply = open_registration::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => Ok(cred),
        Err(_e) => Err(CMZError::IssProofFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        use curve25519_dalek::scalar::Scalar;
        let rng = &mut rand::thread_rng();
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));
        let (_server_keypair, client_pub) = UserAuthCredential::gen_keys(rng, true);

        let mut client_uac = UserAuthCredential::using_pubkey(&client_pub);
        client_uac.age = Some(Scalar::from(100u64));
        client_uac.measurement_count = Some(Scalar::from(0u64));

        // let server_uac = UserAuthCredential::using_privkey(privkey: &server_keypair.privkey);
        // register::prepare(rng, iss_cred_UAC)
    }

    #[test]
    fn test_submit() {}
}
