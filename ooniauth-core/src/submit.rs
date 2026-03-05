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

    const TEST_PUB_PARAMS_B64: &str = "ASAAAAAAAAAAuFmB4DJuU0LM3F1Y6F55BB3wrMR2cKrR+4ZE+2uDoBABIAAAAAAAAADoYO80TTC4YZmaflLs2XAvaJmQyY2uaSY8jY2qYIygVwMAAAAAAAAAIAAAAAAAAADYv+zySHrpeSlzw+ja9rORU1iQSE2AgK03LYBadKmrJSAAAAAAAAAA2u031B1Du5mwhsNXKnanXGTi2jge+2e2CyccZ5JglmogAAAAAAAAAPL6h/cLXZRd7gd0sFCHnK1TAGL22E7EchVq7gzXtHhc";
    const TEST_SEC_KEY_B64: &str = "ASAAAAAAAAAAcNNtnOOPTHX8jwQRl38P4QNTRrPGxP8SWEP8uFapCQQgAAAAAAAAANOG9aJOSEDoUwBKpmvwW6pkCpBbiTwrWGJnV002gisBAwAAAAAAAAAgAAAAAAAAAOpHp/s+tj5EA8UWXRbmIzOB8YBnA3DuqMLnE31W+UwOIAAAAAAAAADuePKQFMtn9AOhAtQV2QsZ1W/WbwJ+07C+941Y2WpcBSAAAAAAAAAArtTXtdI2ZYq/3jH++IGRCAWi9a2RCEQEdWiWN2kSlQw=";

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
        let request = "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";
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
