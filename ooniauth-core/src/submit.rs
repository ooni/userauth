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
        let request = "IAAAAAAAAABGji1UZVzUqRSPyhP0SJtx90oBXlg2e4fVWub7LlB4PyAAAAAAAAAA3IVp98msBJZE8QZ+nDEKKtGrOgj8VSalwnUFaqSldRcgAAAAAAAAAOS2WEKb448DuUFSofboN3/A3LabZPz3NZcBQhu6mFUYIAAAAAAAAACCv+c6pCPwxsMRcezaSLxY3dQALbYY4srWkpZVlRX9CiAAAAAAAAAAYL4vF9xMz6se+XtDoCHevtJ9XGHHxh6zy4bmhizc1GwgAAAAAAAAAGQdWp2ijhmweQgZj2gxYPVhm4f6xtvoW4xhGF3b5zEfQAsAAAAAAADwHUUZwIgPfbNUJed4uIOGqfzQ+EmEJluwANtZQWZwXjAF1zN8MsXiYUAqYbrX2YyKj30mQ5rx7rGV6j/EqxosFOG2O6OpSHHKX8q7EUsaXC2ech38JAaKJUQlNGZEFXCuEmxeAq0pdolUEi3KZwGX3htWihiUkxB9xD59R8WPRRpHTt9a+iVQjvfMOgqveMlTuMfnMy+59g4ernN7t4BPBJmEkgkxOAj67oiaCqOHDRJreqGsC/Ki1givJMgk/CMO8ttQtpmSEU5N5KjZzoXxJAgQA3Ks+lD8WuKum/dHVZZpvpzwYlD/r0zCfd7Rz/Sz+yJLc4Fx88BVBjZZ+ddNClXsuIslwQu8lRPYY6wQE2++6QnF8AO1zJcqm1p9TGlYGb5uOoMzrhyT6Dm78Om/5pLAaNpxR9ETOMvkVpswHyqhI8LrwvWzi3/RY0JaiPkbZEwYr5KZTF04K+KU/Ys/olHYFxQuHSIo/A87c0oXd2s+ABu03E6p8T0OBybcOmsMl9seh3uaDzUk8KIX8Eb/1XCFP986TGqyNHZqJ8gqauAtYxQgYXs9HwzaWRuChaT/ufVU+1khMC+ktVl++JtEjrgQZWuhLQY7B9KeRaNAxI484FZMeLkGUM7YZW+5wz80681NikitMmRywZyJhShFYXntH5ql2bjrJFsLumtBT1YK/WnzS67uxGNjzKvJHUhnOJKrOuO/FS90IeWmC6MSwHlvKWdsIzBSiZPNC5Ok/NM0XnXFAowb+No/tPbk0DpoUDnds+Sq0Ot3HFH+aX/+pRWq+WqQW7g3vgcQLUX/NFQ/f/vGmP6PR77O0NAWBam+vuz/0wQhYLsl9GZ9LG9HelWrd2MDybpZaLNL3zrwK3qcjOfQ5hQ2EYbcCtVelDqATjT7s0d55bNamRJjaxzp4JeCSl+DRcto/XKyEE8BVIZNJnHtcRJAgFTsV3oK2mW+YLqywIzOK55B/u4Er5lrJr21C0K4067bDLQ9FdEzlVx8nhG6d/1aTkVFViva5QrWLQCcN8Q7Cjiy3kwFy6/8FWFyQjtkZ99eXnwKoyYZMfwCwzxuE5BNLdJXjr6yELNjwTKk4z7kZ8gxTYnhaykmgpk73IW/YLJL7mc6YC8YeR8YkmtA+q9S8uCrnSbIuw7ERd7EMzJZ4cJNf9f8lqJDVMFt0m/vvFmfTh/+05ngZ9aN2GZ7BhTT8q77OPSdZub9+HrZvZfM+zcV8Osj8c0q5sorCJ/4KjjnuH+nlbUKf6CY6A0JK8DANjFnoo12THTY8YTDrXTsPKTmhiL3GLDZET/S8vOqwx1Lwe99vz5EZHTcPhR4wFCZsXB6M8dcD0yugxExb699lvGKiMYp9ytNxNLNcRlqw+ThKkTZGgoqovYjbJkVkG3FM4OdErjmmm9UT6vXUwiOPsXHkK/A9U74GDB/snJl7v9aiaJFj6SmVKiDQatgfSFrMi4+03Kmgh1D5ZmaZ0ETj8eUSr47G/QLQGu5p9gBCKFeuPaZMsM3u2O0aqz5/ZqCH8EzWF/mk3byB8RPdqW3xXKnEKUgyU5aE0hGRPYorW1D0wrmvclyGkAxgLB2i3ebiJipN+s1asf38Ivd6Lh9jcRbpmkHaZ1OLupBKFvvlWm0PjgNjujEEpjwh4hV+GFJoK00XuriGQEI/r/jxAXlsCY+SJK/WltsTDqfIDHLnvtWirdZjTQdf1iNfYctXYcWoNhbNbCVDHxJCYbI07dFh6lD4U7UQJd9GvACicKmPGVtlN2ITgsqHy9Xe3tUbEXngJxUOh1xQ0eCMIal9I25NRCdV8Z484FMQ/kZsQLQ+2W+SVdPWjnhOjorCAbe0SdHc6mXoX7MLw63Rf1Ibv92CVq2thLe5/UPDEC4uV9xBMUXzl9OzcM5QWWT1kjjKGJOr5pNKTaUGF0JOuqyKVxFpoNihsswCgV8Oj/MpVfYx7OGdnZ817TGwAGWaPkwtHOaMjfsmjnq8ovw2NbpmRcNKOLo/GaMgFTiAIFQSzTwxEEnSd9GtbejteaW2F4iUOCtWgcZ1YgWYa0LuX2AJw15tKQqPJkm+BOzNHhYU1aeq9Ra7IA7KdIHmwxG1LXTC56ZtvaCEcrMAwv1cC4nxuspAzRF6GmvrSTUCEKf1WT21SJTtAVgEKUaEc+EsgHW0q4VicJfWgBm1nsI7IKd0Vw4vYkRjBFGMwIZVI3uY5iDEg5emL4wZyMU3w2Q7qucXP9GYDorbHPj3HDlKYQABArdMLCAWTceEhO+CMaj1DH2/ZaVJ+ErGOOkmQZ282lLye9hPUCPioDjeI0BKb1f/GAzrNmmrOThetINbfMlOtVtpVjww0JukjgIhAWBPMmUSGjtOJ6zeGPrctqOjHdAURZL9Z62ewu0pB3OAjmmWYYMsSjsR0BkCqswr1XMaYg4lzIM3GmGE2P3gcAMUzlIaoIGYEHaPpWBNi1HvgeMDXvgnUDQViDYYCDvWw1C9gpPLzSC1mTXb0fuwWLc8lNY9iJ9sE2ptNBpLGT4CWvz74rXEZcVktyXg5oqg1X2xaZOLHvjVAIlz2CyxTEK96JgJ3c6qqol/jJ91UXF6v7HAG282VQHg2bLomabRAwummv5zz5NyCfrPmETZJmiuTc0dq88T24PuizIGOw6Bj20toWTQooIZD0VStxOs+cwfS/sZHzbTHnDcx4gsNwEDk24RHXVcRiyl5x2rApL1NGvzFA5HCIh+NGxNXdouQiL0G2zz/AqbMAoeefXOStW8XkGqXAPA9h6/hlELfihClTqV0JZfFW7VliAp6l5gj4ijCqE87BQtCgc7totLiEOAFlblulq0+hRscsbs4bc+/YxBcgEZBU+SIXp9NKWCg9eevhOMoYu4IDXPBbC0o87vMvXH+oNoULfbujInJJQDSwvGhwfMNBkwe3mw9h5jIKwAEcrA8Mr38DzyQMYW+ABe4QLxa/hydXQBT7IG91IcAE2kIu25edzRUEByDmccwX0MABlMDhVMrlsEKBOyG/aTZSXooj2+tBvNV6MDZIrBKtMJVeM+2pmKyAzARRsI1aC3pgyrPOpDq7GsUTE0sYIAL6nH9SdyWyzHDfK87sl6S97qUZlEI9pSz6g4N3VtQO+zoMdXw4t5dw5NOmVF0lwLlFLa4hr8Cmk3tXdrowIAmPM7fZM/jXwI+oxYd3ZFeSYkKuz3FojM3nkxTiRX/ML74mK+nm/YLQboogAHv37jTuDLIvzvl9shR9W2IQSNAj1XtjuqBxk9fG5a2DYrlr8ubbN0/7ktlMqpeey6TSUBuZgTZlRGGmHC/plmCZZ4W1tul5v6ASsq4jMhvs6wVMN23D6hRTAL+McHINgNvslaqN/TMUUdNKZkaOd1I9Qeg+8RzGqV8Oy826t7BaPW3TpzYx0MPeNdVSQztoHD3ZvAEJO8hft+oEHM94I0HUIgKfRbeTFd/Vahj3vbmVq4gYBUjE1MPnrUTbDnJwAzecbBzYVd3MNzlIShksaB+tKRAUq/kyQcY6NvZj5dyJOs1lykxbZWucmCGBaiAnxRAIQBlZY8GCk0H1ZOd8Z8gxIQlx5bQ5JBNi3bVoZak+p+hsBLj3T81smNdhAvPmdjdnmwUFx9OyfC9ifnq1wL1NZmwdjEc0l5RxNCTwlK2FIezT1XTDm59xQk62Mlqa/aqrkBex+fjhpIJtQ2tAOWH13nH5zrhv1a7oicAdFSiEU/wwOPwkH0SxAo6vWVfcguAdWruRlRoFyvjQV9jrmpy5DAgw7p6/GNderMpn/Wod2UHcibtEzbvdnRjfekJOEIL7uAFhi0SkXaeseVx+z9VWA9QNGq7gTCJbJ1F2F3LOKOnAUx4zTFrjy3AASAwT1qP3i4ss2uGFA8hAUu6j3xEYIQA==";
        let nym_hash = "EfZTGIrG92UFKbe0dEDWJYeczJrtUimSoqJT7bkYpWU=";

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
