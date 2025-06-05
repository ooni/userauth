// We want Scalars to be lowercase letters, and Points and credentials
// to be capital letters
#![allow(non_snake_case)]

use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint as G;
use registration::UserAuthCredential;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
pub mod registration;
pub mod submit;

#[derive(Debug, Serialize, Deserialize)]
pub struct OONIAuth {
    /// The private key for the main User Auth credential
    privkey: CMZPrivkey<G>,
    pubkey: CMZPubkey<G>,
}

impl OONIAuth {
    pub fn init() -> Self {
        // Initialization
        let mut rng = rand::thread_rng();
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));
        // Create the private and public keys for each of the types of
        // credential with 'true' to indicate uCMZ
        let (privkey, pubkey) = UserAuthCredential::gen_keys(&mut rng, true);
        Self { privkey, pubkey }
    }

    /// Get today's (real or simulated) date as u32
    pub fn today(&self) -> u32 {
        // We will not encounter negative Julian dates (~6700 years ago)
        // or ones larger than 32 bits
        (time::OffsetDateTime::now_utc().date())
            .to_julian_day()
            .try_into()
            .unwrap()
    }
}
