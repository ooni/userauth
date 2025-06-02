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

// CMZ! {RangeCredential<G>: value}

muCMZProtocol! {register,
    ,
    UAC: UserAuthCredential { nym_id: J, age: R, measurement_count: R},
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
