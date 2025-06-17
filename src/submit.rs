use std::u32;

use super::{scalar_u32, G};
use crate::errors::CredentialError;
use crate::registration::UserAuthCredential;
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use curve25519_dalek::RistrettoPoint;

muCMZProtocol!(submit<min_age_today, max_age, min_measurement_count, max_measurement_count>,
    Old: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    New: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    Old.nym_id = New.nym_id,
    Old.age = New.age,
    New.measurement_count = Old.measurement_count + Scalar::from(1),
    // NYM evaluation function
    // TODO: Fix syntax for group element equations
    // Old.nym_id * DOMAIN = NYM,

    // TODO: Fix constraint syntax - the macro doesn't support inequality constraints
    // Old.age >= min_age_today,
    // Old.age <= max_age,
    // Old.measurement_count >= min_measurement_count,
    // Old.measurement_count <= max_measurement_count,
);

// The submit request will take values that were received from a separate recent request
// to the server for a manifest file that contains the probe_cc, probe_asn, age_range, and
// measurement_count_range values. The server will have access to the same values but will require
// some indication that matches the request and probe_cc/probe_asn values
pub fn request(
    rng: &mut (impl RngCore + CryptoRng),
    Old: UserAuthCredential,
    probe_cc: String,
    probe_asn: String,
    age_range: std::ops::Range<u32>,
    measurement_count_range: std::ops::Range<u32>,
    pubkeys: CMZPubkey<G>,
    today: u32,
) -> Result<((submit::Request, submit::ClientState), RistrettoPoint), CredentialError> {
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    // TODO: Implement domain-specific generator and NYM computation
    // when group element equations are supported in the macro
    let domain_str = format!("OONI-DOMAIN-{}-{}", probe_cc, probe_asn);
    let DOMAIN = G::hash_from_bytes::<Sha512>(domain_str.as_bytes());
    let NYM = Old.nym_id.unwrap() * DOMAIN;

    // Ensure the credential timestamp is within the allowed range
    let age: u32 = match scalar_u32(&Old.age.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("age"),
                String::from("could not be converted to u32"),
            ))
        }
    };

    // Check if credential timestamp is within the allowed range
    // age_range represents the valid timestamp range (min_timestamp..max_timestamp)
    
    // Check if credential is too old (timestamp too early)
    if age < age_range.start {
        return Err(CredentialError::CredentialExpired);
    }

    // Check if credential is too new (timestamp too recent)
    if age >= age_range.end {
        return Err(CredentialError::TimeThresholdNotMet(age - age_range.end));
    }

    // The measurement count has to be within the allowed range
    let measurement_count: u32 = match scalar_u32(&Old.measurement_count.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("measurement_count"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if measurement_count < measurement_count_range.start {
        return Err(CredentialError::InvalidField(
            String::from("measurement_count"),
            format!(
                "measurement_count {} is below minimum {}",
                measurement_count, measurement_count_range.start
            ),
        ));
    }
    if measurement_count >= measurement_count_range.end {
        return Err(CredentialError::InvalidField(
            String::from("measurement_count"),
            format!(
                "measurement_count {} is at or above maximum {}",
                measurement_count, measurement_count_range.end
            ),
        ));
    }

    //let NYM = PRF(nym_id, nym_scope.format(probe_cc, probe_asn))
    let mut New = UserAuthCredential::using_pubkey(&pubkeys);
    New.nym_id = Old.nym_id;
    New.age = Old.age;
    New.measurement_count = Some((measurement_count + 1).into());
    let params = submit::Params {
        min_age_today: (today - age_range.start).into(),
        max_age: (today - age_range.end).into(),
        min_measurement_count: measurement_count_range.start.into(),
        max_measurement_count: measurement_count_range.end.into(),
    };

    match submit::prepare(rng, &Old, New, &params) {
        Ok(req_state) => Ok((req_state, NYM)),
        // Ok(req_state) => Ok(req_state),
        Err(_) => Err(CredentialError::CMZError(CMZError::CliProofFailed)),
    }
}
/*
impl OONIAuth {
    pub fn submit(&mut self, req: submit::Request) -> Result<submit::Reply, CMZError> {
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();

        let recvreq = submit::Request::try_from(&reqbytes[..]).unwrap();
        match submit::handle(
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
*/

pub fn handle_response(
    state: submit::ClientState,
    rep: submit::Reply,
) -> Result<UserAuthCredential, CMZError> {
    let replybytes = rep.as_bytes();
    let recvreply = submit::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => Ok(cred),
        Err(_e) => Err(CMZError::IssProofFailed),
    }
}
