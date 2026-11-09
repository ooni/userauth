use crate::{
    errors::CredentialError, registration::UserAuthCredential, scalar_u32, Scalar, UserState, G,
};
use bincode::Options;
use cmz::{serde_as, CMZCredential, CMZMac, CMZPrivkey, CMZPubkey, SerdeScalar};
use group::Group;
use serde::Deserialize;

// CMZ 0.2 serialized the private-key field even for client credentials, where
// it was empty. CMZ 0.3 skips that field; decode the old layout explicitly.
#[serde_as]
#[derive(Deserialize)]
struct LegacyCredential {
    #[serde_as(as = "Option<SerdeScalar>")]
    nym_id: Option<Scalar>,
    #[serde_as(as = "Option<SerdeScalar>")]
    age: Option<Scalar>,
    #[serde_as(as = "Option<SerdeScalar>")]
    measurement_count: Option<Scalar>,
    #[serde(rename = "MAC")]
    mac: CMZMac<G>,
    _privkey: CMZPrivkey<G>,
    pubkey: CMZPubkey<G>,
}

impl UserState {
    /// Restore a client credential saved with CMZ 0.2 / bincode 1.
    ///
    /// The credential must contain all three attributes and match this user's
    /// public parameters. Legacy private-key material is discarded. This only
    /// decodes the credential; its MAC is authenticated on the next submission.
    /// On failure, the current credential is unchanged.
    pub fn load_legacy_credential(&mut self, bytes: &[u8]) -> Result<(), CredentialError> {
        let legacy: LegacyCredential = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(bytes.len() as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| CredentialError::InvalidField("credential".into(), e.to_string()))?;
        if legacy.pubkey != self.pp {
            return Err(CredentialError::CredentialMismatch);
        }
        if bool::from(legacy.mac.P.is_identity()) {
            return Err(CredentialError::InvalidField(
                "credential".into(),
                "MAC point P must not be the identity".into(),
            ));
        }
        if legacy.nym_id.is_none()
            || legacy.age.as_ref().and_then(scalar_u32).is_none()
            || legacy
                .measurement_count
                .as_ref()
                .and_then(scalar_u32)
                .is_none()
        {
            return Err(CredentialError::InvalidField(
                "credential".into(),
                "missing attribute or age/measurement_count outside u32".into(),
            ));
        }
        let mut credential = UserAuthCredential::using_pubkey(&legacy.pubkey);
        credential.nym_id = legacy.nym_id;
        credential.age = legacy.age;
        credential.measurement_count = legacy.measurement_count;
        credential.MAC = legacy.mac;
        self.credential = Some(credential);
        Ok(())
    }
}
