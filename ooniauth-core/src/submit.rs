use super::{scalar_u32, ServerState, UserState, G};
use base64::{Engine, prelude::BASE64_STANDARD};
use crate::errors::CredentialError;
use crate::registration::UserAuthCredential;
use cmz::*;
use curve25519_dalek::RistrettoPoint;
use group::Group;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tracing::{debug, instrument, trace};

const SESSION_ID: &[u8] = b"submit";

muCMZProtocol!(submit<min_age_today, max_age, min_measurement_count,
        max_measurement_count, @DOMAIN, @NYM>,
    Old: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    New: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    Old.nym_id = New.nym_id,
    Old.age = New.age,
    New.measurement_count = Old.measurement_count + 1,
    NYM = Old.nym_id * DOMAIN,
    (min_age_today..=max_age).contains(Old.age),
    (min_measurement_count..=max_measurement_count).contains(Old.measurement_count)
);

/// A request for a measurement submission.
///
/// A [`SubmitRequest`] embeds the core submission request and the
/// nym, computed as an elliptic curve point.
///
/// The nym provided at the application layer is not the elliptic curve point,
/// but a hash of it. The reason for this is to avoid leaving DDH-related points
/// in the open database, and rather just have a "fingerprint" at the application layer.
///
/// The core verification funtionality still needs this points, it's added here for this reason.
#[derive(Serialize, Deserialize, Clone)]
pub struct SubmitRequest {
    core_request: submit::Request,
    nym_point: RistrettoPoint,
}

impl SubmitRequest {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("failed to serialize SubmitRequest")
    }
}

fn digest_point(point: RistrettoPoint) -> [u8; 32] {
    let digest = Sha256::digest(point.compress().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl UserState {
    #[instrument(skip(
        self,
        rng,
        probe_cc,
        probe_asn,
        age_range,
        measurement_count_range
    ))]
    pub fn submit_request(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        probe_cc: String,
        probe_asn: String,
        age_range: std::ops::Range<u32>,
        measurement_count_range: std::ops::Range<u32>,
    ) -> Result<((SubmitRequest, submit::ClientState), [u8; 32]), CredentialError> {
        trace!("Starting submit request");
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

        // Get the current credential
        let Old = self
            .credential
            .as_ref()
            .ok_or(CredentialError::InvalidField(
                String::from("credential"),
                String::from("No credential available"),
            ))?;

        // Domain-specific generator and NYM computation
        let domain_str = format!("ooni.org/{}/{}", probe_cc, probe_asn);
        trace!("Computing DOMAIN for submit request");
        let DOMAIN = G::hash_from_bytes::<Sha512>(domain_str.as_bytes());
        let NYM = Old.nym_id.unwrap() * DOMAIN;
        debug!("NYM computed successfully");

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
        let mut New = UserAuthCredential::using_pubkey(&self.pp);
        New.nym_id = Old.nym_id;
        New.age = Old.age;
        New.measurement_count = Some((measurement_count + 1).into());
        let params = submit::Params {
            min_age_today: age_range.start.into(),
            max_age: age_range.end.into(),
            min_measurement_count: measurement_count_range.start.into(),
            max_measurement_count: measurement_count_range.end.into(),
            DOMAIN,
            NYM,
        };

        trace!("Preparing submit proof with params");
        match submit::prepare(rng, SESSION_ID, Old, New, &params) {
            Ok((core_request, client_state)) => {
                debug!("Submit request prepared successfully");
                let probe_id = digest_point(NYM);
                let request = SubmitRequest {
                    core_request,
                    nym_point: NYM,
                };
                Ok(((request, client_state), probe_id))
            }
            Err(_) => {
                debug!("Failed to prepare submit request");
                Err(CredentialError::CMZError(CMZError::CliProofFailed))
            }
        }
    }

    pub fn handle_submit_response(
        &mut self,
        state: submit::ClientState,
        rep: submit::Reply,
    ) -> Result<(), CMZError> {
        let replybytes = rep.as_bytes();
        let recvreply = submit::Reply::try_from(&replybytes[..]).unwrap();
        match state.finalize(recvreply) {
            Ok(cred) => {
                self.credential = Some(cred);
                Ok(())
            }
            Err(_e) => Err(CMZError::IssProofFailed),
        }
    }
}

impl ServerState {
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(
        self,
        rng,
        req,
        probe_id,
        probe_cc,
        probe_asn,
        age_range,
        measurement_count_range
    ))]
    pub fn handle_submit(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        req: SubmitRequest,
        probe_id: &[u8; 32],
        probe_cc: &str,
        probe_asn: &str,
        age_range: std::ops::Range<u32>,
        measurement_count_range: std::ops::Range<u32>,
    ) -> Result<submit::Reply, CMZError> {
        // Ensure group is initialized for proof verification (same as from_creds;
        // required when handle_submit is used without prior client path in same process).
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

        trace!("Server handling submit request");
        let SubmitRequest {
            core_request: recvreq,
            nym_point,
        } = req;

        let domain_str = format!("ooni.org/{}/{}", probe_cc, probe_asn);
        let DOMAIN = G::hash_from_bytes::<Sha512>(domain_str.as_bytes());

        // The probe id is the same as the nym point.
        // Otherwise, return an error.
        // We do not really care about the server returning early here,
        // a malicious probe should already have computed the probe ID from the
        // (malicious) group element.
        if &digest_point(nym_point) != probe_id {
            return Err(CMZError::IssProofFailed);
        }

        let params = submit::Params {
            min_age_today: age_range.start.into(),
            max_age: age_range.end.into(),
            min_measurement_count: measurement_count_range.start.into(),
            max_measurement_count: measurement_count_range.end.into(),
            DOMAIN,
            NYM: nym_point,
        };

        let server_sk = self.sk.clone();
        let server_pp = self.pp.clone();
        match submit::handle(
            rng,
            SESSION_ID,
            recvreq,
            move |Old: &mut UserAuthCredential, New: &mut UserAuthCredential| {
                // Set the private key for the credentials - this is essential for the protocol
                Old.set_keypair(server_sk.clone(), server_pp.clone());
                New.set_keypair(server_sk.clone(), server_pp.clone());

                // The protocol should populate Old and New from the client's proof
                // We don't set the values here - they come from the client's proof
                // We just return the parameters to validate against
                Ok(params)
            },
            |_Old: &UserAuthCredential, _New: &UserAuthCredential| {
                // Additional validation callback
                Ok(())
            },
        ) {
            Ok((response, (_old_cred, _new_cred))) => {
                debug!("Submit request verified successfully");
                Ok(response)
            }
            Err(e) => {
                debug!("Submit request verification failed");
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G, PublicParameters, Scalar, SecretKey, ServerState, UserState};
    use base64::prelude::BASE64_STANDARD;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sha2::Sha512;

    fn seeded_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    const TEST_PUB_PARAMS_B64: &str = "AUrmHL6zoG37IMOJAVq6rnNY4wZesqqNFmzVFT5mpeMTAeRb3zWXBuHZGC2gdhJMjBhnbuzkr5VnsjWI9feG4QpHAwAAAAAAAAD0nVw/f98b9HKF4kDKhtHcgM00UOb6AqZ+rywgKFvYMrC2MlH0LVP/mwxPxgNIhLLvMlMyLUF5j18R4KYkp6FOMqiisoqkyhubBIeSDaETcEPihZMba6sijbyThqgqTHY=";
    const TEST_SEC_KEY_B64: &str = "ASf9fCU0Cd38qKNOAVcfWK/aXC2TP27fj5bJA82iucMDwKx9l46g5pP2ajP2b1+k3jPLo9EL/Akwf6r0oG8IfgsDAAAAAAAAAGxtJqQKiFjjMx+suXVGC/ZxUbRDLp9C49njgVxmdEoFdoAZToysiUVHOFX97RaxEum9OdyY5lGdZfmRLsrHpAOyr0yqV/68AtynR5t/WJc4xlHlZHHsu8QVBEW/3exIAw==";

    #[test]
    fn test_domain_nym_computation() {
        // Test the DOMAIN and NYM computation logic that will be used
        // when group element equations are supported in the macro

        let probe_cc = "US";
        let probe_asn = "AS1234";
        let domain_str = format!("ooni.org/{}/{}", probe_cc, probe_asn);
        let domain = G::hash_from_bytes::<Sha512>(domain_str.as_bytes());

        // Test with a known nym_id
        let nym_id = Scalar::from(42u32);
        let nym = nym_id * domain;

        // Different domain should produce different NYM
        let different_domain_str = format!("ooni.org/{}/{}", "UK", "AS5678");
        let different_domain = G::hash_from_bytes::<Sha512>(different_domain_str.as_bytes());
        let different_nym = nym_id * different_domain;

        assert_ne!(
            nym, different_nym,
            "Different domains should produce different NYMs"
        );
    }

    #[test]
    fn test_submit_request() {
        let rng = &mut seeded_rng();

        // Setup server and user
        let server_state = ServerState::new(rng);
        let mut user_state = UserState::new(server_state.public_parameters());

        // First do registration to get a credential
        let result = user_state.request(rng);
        assert!(result.is_ok(), "Registration request should succeed");
        let (reg_request, reg_client_state) = result.unwrap();

        let server_response = server_state.open_registration(reg_request);
        assert!(
            server_response.is_ok(),
            "Server should process registration request successfully"
        );
        let reg_response = server_response.unwrap();

        let result = user_state.handle_response(reg_client_state, reg_response);
        assert!(
            result.is_ok(),
            "User should handle server response successfully"
        );
        assert!(
            user_state.credential.is_some(),
            "User should receive a valid credential"
        );

        // Test submit request with valid parameters
        let probe_cc = "US".to_string();
        let probe_asn = "AS1234".to_string();
        let today = ServerState::today();
        let age_range = (today - 30)..(today + 1); // Credential valid for 30 days
        let measurement_count_range = 0..100;

        let result = user_state.submit_request(
            rng,
            probe_cc.clone(),
            probe_asn.clone(),
            age_range.clone(),
            measurement_count_range.clone(),
        );

        assert!(
            result.is_ok(),
            "Submit request should succeed with valid credential"
        );
        let ((request, client_state), nym) = result.unwrap();

        // Verify the request is valid
        assert!(
            !request.as_bytes().is_empty(),
            "Request should have content"
        );

        // Verify NYM is computed (check it's not all zeros)
        assert_ne!(&nym, &[0u8; 32], "NYM should not be all zeros");

        // Test server handling of submit request
        let server_result = server_state.handle_submit(
            rng,
            request,
            &nym,
            &probe_cc,
            &probe_asn,
            age_range,
            measurement_count_range,
        );
        assert!(
            server_result.is_ok(),
            "Server should handle submit request successfully"
        );
        let response = server_result.unwrap();

        // Test user handling of server response
        let handle_result = user_state.handle_submit_response(client_state, response);
        assert!(
            handle_result.is_ok(),
            "User should handle submit response successfully"
        );

        // Verify credential was updated
        assert!(
            user_state.credential.is_some(),
            "User should still have credential"
        );
        let updated_cred = user_state.credential.as_ref().unwrap();

        // Verify measurement count was incremented
        let new_count = scalar_u32(&updated_cred.measurement_count.unwrap()).unwrap();
        assert_eq!(new_count, 1, "Measurement count should be incremented to 1");
    }

    #[test]
    fn print_b64_creds() {
        let rng = &mut seeded_rng();
        let server_state = ServerState::new(rng);
        println!("\tSecret key: \n\n\t\t{}\n", BASE64_STANDARD.encode(bincode::serialize(&server_state.sk).unwrap()));
        println!("\tPublic Params: \n\n\t\t{}", BASE64_STANDARD.encode(bincode::serialize(&server_state.pp).unwrap()));
    }

    #[test]
    fn get_submit_payload() {
        let rng = &mut seeded_rng();

        let pub_bytes = BASE64_STANDARD.decode(TEST_PUB_PARAMS_B64).unwrap();
        let public_parameters: PublicParameters = bincode::deserialize(&pub_bytes).unwrap();

        let sec_bytes = BASE64_STANDARD.decode(TEST_SEC_KEY_B64).unwrap();
        let secret_key: SecretKey = bincode::deserialize(&sec_bytes).unwrap();

        // Setup server and user
        let server_state = ServerState::from_creds(secret_key, public_parameters);
        let mut user_state = UserState::new(server_state.public_parameters());

        // First do registration to get a credential
        let result = user_state.request(rng);
        assert!(result.is_ok(), "Registration request should succeed");
        let (reg_request, reg_client_state) = result.unwrap();

        let server_response = server_state.open_registration(reg_request);
        assert!(
            server_response.is_ok(),
            "Server should process registration request successfully"
        );
        let reg_response = server_response.unwrap();

        let result = user_state.handle_response(reg_client_state, reg_response);
        assert!(
            result.is_ok(),
            "User should handle server response successfully"
        );
        assert!(
            user_state.credential.is_some(),
            "User should receive a valid credential"
        );

        // Test submit request with valid parameters
        let probe_cc = "US".to_string();
        let probe_asn = "AS1234".to_string();
        let today = ServerState::today();
        let age_range = (today - 30)..(today + 1); // Credential valid for 30 days
        let measurement_count_range = 0..100;

        let result = user_state.submit_request(
            rng,
            probe_cc.clone(),
            probe_asn.clone(),
            age_range.clone(),
            measurement_count_range.clone(),
        );

        assert!(
            result.is_ok(),
            "Submit request should succeed with valid credential"
        );
        let ((request, client_state), nym) = result.unwrap();

        // Verify the request is valid
        assert!(request.as_bytes().len() > 0, "Request should have content");

        // Verify NYM is computed (check it's not all zeros)
        assert_ne!(&nym, &[0u8; 32], "NYM should not be all zeros");

        let submit_request_b64 = BASE64_STANDARD.encode(&request.as_bytes());
        let probe_id = BASE64_STANDARD.encode(&nym);

        println!("today: {}", today);
        println!("submission request: {}", submit_request_b64);
        println!("probe id: {}", probe_id);

        // Server handling of the submit request
        println!("handle_submit arguments:");
        println!("  request (base64): {}", BASE64_STANDARD.encode(request.as_bytes()));
        println!("  probe_id (base64): {}", BASE64_STANDARD.encode(&nym));
        println!("  probe_cc: {}", probe_cc);
        println!("  probe_asn: {}", probe_asn);
        println!("  age_range: {}..{}", age_range.start, age_range.end);
        println!("  measurement_count_range: {}..{}", measurement_count_range.start, measurement_count_range.end);

        let submit_response = server_state
            .handle_submit(
                rng,
                request.clone(),
                &nym,
                &probe_cc,
                &probe_asn,
                age_range.clone(),
                measurement_count_range.clone(),
            )
            .expect("Server should handle submit request successfully");

        // User handling of the server response
        user_state
            .handle_submit_response(client_state, submit_response)
            .expect("User should handle submit response successfully");

        assert!(
            user_state.credential.is_some(),
            "User should still have credential after submit"
        );
    }

    #[test]
    fn process_submission_payload() {
        let rng = &mut seeded_rng();

        let pub_bytes = BASE64_STANDARD.decode(TEST_PUB_PARAMS_B64).unwrap();
        let public_parameters: PublicParameters = bincode::deserialize(&pub_bytes).unwrap();

        let sec_bytes = BASE64_STANDARD.decode(TEST_SEC_KEY_B64).unwrap();
        let secret_key: SecretKey = bincode::deserialize(&sec_bytes).unwrap();

        // Setup server and user
        let server_state = ServerState::from_creds(secret_key, public_parameters);

        // we get these from the test above
        let request = "UlLaxyOyMcvcuunUFRXfDf8X4f8l+/nzPWH0LLTOWQJ0rQc7x/NRrk1B3WHxHyEq89OICRTG5H0U9f3kmjuoUqKD/vw9UBsIY08ei1QIjJ0l146BXkUYaj2OAonTK6dX/MZLndRDC+97Av2GoWarp8e4sYNQOygJi6b7EdVJeG9gvi8X3EzPqx75e0OgId6+0n1cYcfGHrPLhuaGLNzUbPysX3n3VgCuYWW1JHSqoQ3qFg4lhc5gJiI5hs2mbDcvSgsAAAAAAABkDn7RyqtoHKyNZMRGrRalNqnU+5/DAfqQ3KVWleKPAzpq5+fhFVNJ4z9r+qSxwRLQ/if80ohibsP8qqUnEAV2ok9d8Cp4eBwI7eUePHS7E1sybaEQfqE8C5FAkgTql0dGHPVE5W79lbfPsBJJmECzl1egpQR16llk8sCq5s+9I+Lw+UBDmKtiBm2YcOFcs3aDOdEecLJE160/u7ZzuswGTMPTboZ8QD5QvEkCGGKY7BWG8LHQZt8Lg/JkKzpkTH6YIaTkk2R+MT4FzoL7kkjqEuW5oaS38hnxdWL169qyf5rpv0picqGaMgXobSDqygnurjJeD9SYsQbGJUZMgWtgrFjHzBrO4MjbzctmEyGgRkjdTfRCu/VlBQs/bSPQg39QKI1tbfupFe80Lg1szk9t6sTKJGaWeFZ8VmRZM6QECS7bgNta9U2F4PHbe4SrTK5PzZZI6HakCBAqYSJar3hlbKHq+B68xlVDauaJtBBTb6kUUetW14wFrGsfB223pFIAIAAAAAyX2x6He5oPNSTwohfwRv/VcIU/3zpMarI0dmonyCpqqP71e601Cq6NW+p3prfdKxmjnQlHfedpPZdglCSD4whWnydhcqA1OrGxoUHyAAfkhFy+i40KH+ZsZNIXO8l4SM7mDK2+w1IVS75Wx0h/J5tBYvtmXjNJCkXZCYWC6cMIkMXWcogcY9mPVmICdMzPXRT6jXu9Y1EjqbNM3xJ67n3CbJfery82qERbHicpv2hqT/45iOmrvEUj0hMJN9AfZpBY6Rty0IO701ZcjaqYgr5xCsXgDhj6GpOPOUc+YpN7KIGhPALJMv9hY2JnhzP/QgFWnk77IbOHMhaMcF2DNS62QTN9N5bqs8egYbG7GrESHh6kpUojPKEInBl6MMirOb6YK//NsQgeqlQ/1GRIZMYEG1h5n1hvMlzbP9WSvbMyphCViBKQlUBYh9Z4Uh7hJ9frCrDqBO5KXkwwYVn0U27CiZNHR+xtobrLSz595cW3LMZj0pEKDTDjGyVZ/FDsK1Cnq6Xi24fT2HQHisk2ZPBXkbvVEu505mvaZzWaBXRMhoMHzlYebS9Dd8SiiJInH+eB7OOug/I8CzHOczurvEjUCTRih0/fG5rz48Ezfte+xjQsbN3nzUamjgAFeVkLQwaIcqwNG2VPAKllLK3xJHHBC07arSUiYKCHqRd+oAEeHFZiMxTRyA7mXleTh/hiSyGhDIt34rq+IXBtCtHKti0UpJvJhtDosFyfBnnZ9EX2+MYLObMIEC4UxrsBZBlcQXz5B2zs+XHm10OBEusZ0B8My2YU8NL6FYWOwlYRtm5YRpVrqLqHegW2640VdM3wRztQrDTAAW150d/xiimKTzQMl7q+YpapzSzDu+aCPnIc5CJZdn7LoIKfw0mq+MZANm6tExW49uyKlsiXaoEmF8d7nWp63lkJqDqu+QXHniFC6F8WveWLeILW7/ASuFfC2R+Z9Yn6TAgEJ+wPlH8n/E8I9IfjH7+08zivkZkCFp0aHsk3MXlP747xKZGRqU7CEzbv1jWjgXJnRIb18exIUmNaOJVNKLZycp9XoU0DLW8hlN4qB8Umtg65NARsd3faB2Jxf+/W7EIVyQpyE0TZx1LIx9aoRUxJizNEGbD3BYlJ1UV+efBczh73OMDxdfpPNt54HP48d25dNTEbkfyPwUEAA8D9meI5C9LFpkvxmnQu/BVKyIXiuJaApSnUXxNpTx7GsNXr76rtNv9FGrPAJy5oHrE/eFQ2kofMP3j7eme0P6rOKPDrVVh8OHRikVZVLhA/nzPSkY+33V7kjF/yN747ZIg7AgOm4OdWi5qe7HYWAB/lHD/Dx/o4t9CnzhJbkW9+wiPrmBUbMsLZ6PkKQBoALgAAAHa2pN4OGc2Zck3sApcTVwDykMuV5pDNk4ylI64kLUYICVx8xbnf82JxkwXOGV6nqfvT3xdY+5stjlYXs3Fp5AQRvSpjCgAnBpzh6BvhQOx2MbQFmhzFt+LCGjb2OhCqDZC8Yt6qrMyVzJzUKOv+4gpKVBbTZBRE7j5TcsV2ECsEfmIegBATspbzZyJd4H7EWEfEVkS3cSRrsgiPt6s9Yw+3f/kFP3sLcCLlbs20VLwZoLMq6C+38H2XLY1j4ZTwD14xs1Yv8ofFNGpW3Y7Y0POlygMufjquGiBkePUAYOwLQ+x5axAIw7moP9DiZQ+10xZpv5GwgQcq5g0xdzufswzZK++1ffWNRVpyMcd9p2f7TEqHY5rMhX7cyRTNJdkvDL5B+Ente/A7YUCKe97UxPnLMFHFLwBYsH0k9MySY8EM2yu7eoKN6XRIslHz9GTQDbKkry2Uwk5BRL6znAxCuA/OHaS0C3u2nvVLFlFAd4yO2nLrY3iznjjtaEiUyTyBBcCB92MThmncDDKXOIhpzFWvMKsKZEBH7CixDIZZpjkCW+8gYNggVtBAneB7DYwHvkctNoGVPtpBYAaCakg5Uwz4ZCxp0LSpTbB9IvZYU/LcYsHuR2/XZNaCNC9PCvZCDTHFsmDPJQJU43ssTqbF9lWDKpqDl9ySFZcR14rv82sJF7RzD+aCeGlZdJAim/d3zx/2j2GkE4lLeixOAb8dQwwNBSY1R9YE0FTXgivPZzKH8xTORLAAi2kdMKbTyhV6DdywIB5zw3lM23xk7C99MOezTtxKFT1kCIpCk4W2tD0GKyNCwwjAJRYauCoBL5pxs69egltnyz/LDfYgpEvrvwih+C1EGf562AMPcKkGefFWKznX53kowGwq8M+zbdCLCCEuLdruHCi0ULDzhCqMIj6CeamngFhWu1V8WUJX6lQKCpbS9OmFSD4VZATIBTH2+9yGsxvLsVHo02rplltZAA5QkpzI6G7fQqEN6h/Xy7w7j9LCFjzXgOAuhjJO+HpeD+BbGAPJ88DfK8MDK0cAsIKMedjD5u3BZNAwHxwaLywNc5w5yAFBRXPn5baLkDYBcEjdG8g+BdDVyeGvxQuEewEwlvm9l01cMyOMvOY92AvbUC6/Lv1dfiBpmIHqZajBAVhgyZzXC+AxjUZFPfUMR2Q7gOyT0NrOrdX79AJkky8PzvzVH+iy2tjieQ9zX17PxLNy3YZ9zSbyO1ls26QWIwWfnsu2i0r3Unc8U4JBrlRZBovNQ3hsj55QL0W/3PGjB5axc1tiAZUIqtAY/cP5iJf5OnGStkF1QOk0+DDCBeYE4hzPIzb8htKXergUI008ByGXyHVsaXXv/am8saq1kw+ZONXkIL4Xtt55Mhh0+nf9OxRJ71ertuN4fPlzPtfCBPh6SfaSrqd2urqI19zuUmb5bf4qA7WvztQYuUSMp2oBk3eHE+UXIQkm3r7xAmJDRrOyIBzJzY9oonusQPjI/QoZtTaDddfQJSbByqSL7xS+Mc/HcC/hIazV5D1Mi2qhA6kzTYgLDFlb4Wu0Dv3WwVpkaggBjjWFVzQxmVLGh8QC8lQ2U/kniHiKitL7bd82gUCAd3aAYx1y7tU86FRd9gQQAkTxCYhaYAgm51rZFpNyWbNOInf5mL2NjnGQTP4qBSc7HtsO3efM0K2Y/plvqgpnKd3Xhta4vGGC2joZePUKp5rHuhRxLP/x4DKigHRybwu7XoNmtL87GtiQzfxczQUeKcZpN2tKRzeapAeUd1lSmzOl03odu/hYumEHmC+lA+NlxxDsqNo7tAfNkCiBBk4G5lb42So89A3joqHANVAGan+iAvBKt0PLyeCFtW2r8xgkBL0XzJkWsVymaqvIowDXPU2hi3p0g1exEaXVTOAnm5StA4NVFO6Yxy5EidUMD3BOzlQlvPkzmtLxb++kEI1/DVcQZJHIXOgBdncKTssO7PGb+gVsBkNSoHpihC00B5HDJBgjhuaCS2Clh9HKiCc=";
        let nym_hash = "bCq4YKIfePyyUr//HqB75tJSXWXq929lwL5DY9SVprg=";

        let probe_id_bytes = BASE64_STANDARD.decode(nym_hash).unwrap();
        let mut probe_id: [u8; 32] = [0u8; 32];
        probe_id.copy_from_slice(&probe_id_bytes);


        let submit_request_decode = BASE64_STANDARD.decode(request).unwrap();
        let submit_request: SubmitRequest = bincode::deserialize(&submit_request_decode).unwrap();

        let probe_cc = "US".to_string();
        let probe_asn = "AS1234".to_string();
        // Use same "today" as when the hardcoded request was generated, so proof params match.
        let today = ServerState::today();
        let age_range = (today - 30)..(today + 1);
        let measurement_count_range = 0..100;

        println!("handle_submit arguments:");
        println!("  request (base64): {}", BASE64_STANDARD.encode(submit_request.as_bytes()));
        println!("  probe_id (base64): {}", BASE64_STANDARD.encode(&probe_id));
        println!("  probe_cc: {}", probe_cc);
        println!("  probe_asn: {}", probe_asn);
        println!("  age_range: {}..{}", age_range.start, age_range.end);
        println!("  measurement_count_range: {}..{}", measurement_count_range.start, measurement_count_range.end);

        server_state.handle_submit(
            rng,
            submit_request,
            &probe_id,
            &probe_cc,
            &probe_asn,
            age_range,
            measurement_count_range,
        ).unwrap();
    }
}
