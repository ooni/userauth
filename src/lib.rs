use cmz::muCMZProtocol;
use cmz::CMZ;
use cmz::CMZCred;
use cmz::{Serialize, Deserialize};
use curve25519_dalek::ristretto::RistrettoPoint as G;
use cmz::serde_as;
use cmz::SerdeScalar;
use cmz::CMZPrivkey;
use rand::RngCore;
use cmz::cmz_privkey_to_pubkey;
use cmz::CMZPubkey;
use cmz::CMZMac;
use group::Group;
use cmz::CMZCredential;
use cmz::*;
//use sigma_compiler::*;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}


CMZ! {UserAuthCredential<G>:
    age,
    nym_id,
    measurement_count
}

muCMZProtocol! {register,
    ,
    UAC: UserAuthCredential { nym_id: J, age: S, measurement_count: I},
}

muCMZProtocol!(submit,
    Old: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    New: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    Old.nym_id == New.nym_id && Old.age == New.age && Old.measurement_count + Scalar::from(1u64) == New.measurement_count
);


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        use curve25519_dalek::scalar::Scalar;
        let rng = &mut rand::thread_rng();

        cmz_group_init(G::generator() + G::generator()); // XXX. this is insecure.
        let (_server_keypair, client_pub) = UserAuthCredential::gen_keys(rng, true);

        let mut client_uac = UserAuthCredential::using_pubkey(&client_pub);
        client_uac.age = Some(Scalar::from(100u64));
        client_uac.measurement_count = Some(Scalar::from(0u64));

        // let server_uac = UserAuthCredential::using_privkey(privkey: &server_keypair.privkey);
        // register::prepare(rng, iss_cred_UAC)
    }

    #[test]
    fn test_submit() {
        assert_eq!(1+1, 2);
    }
}
