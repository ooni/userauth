// We want Scalars to be lowercase letters, and Points and credentials
// to be capital letters
#![allow(non_snake_case)]

use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint as G;
use group::Group;
type Scalar = <G as Group>::Scalar;
use registration::UserAuthCredential;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
pub mod errors;
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

// Try to extract a u32 from a Scalar
#[inline]
pub fn scalar_u32(s: &Scalar) -> Option<u32> {
    // Check that the top 28 bytes of the Scalar are 0
    let sbytes: &[u8; 32] = s.as_bytes();
    if sbytes[4..].ct_eq(&[0u8; 28]).unwrap_u8() == 0 {
        return None;
    }
    Some(u32::from_le_bytes(sbytes[..4].try_into().unwrap()))
}
