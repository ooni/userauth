use base64::prelude::*;
use ooniauth_core as ooni;
use ooniauth_core::registration::open_registration;
use ooniauth_core::submit::submit;
use pyo3::{
    prelude::*,
    types::{PyList, PyString},
};
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};

use crate::utils::{from_pystring, to_pystring};
use crate::{OoniErr, exceptions::OoniResult};

#[gen_stub_pyclass]
#[pyclass]
pub struct ServerState {
    pub state: ooni::ServerState,
}

#[gen_stub_pymethods]
#[pymethods]

impl ServerState {
    #[new]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            state: ooni::ServerState::new(&mut rng),
        }
    }

    /// Create a new server state from binary-serialized public and private keys
    /// This is meant to be used by the server, so it can store the keys somewhere and recreate the
    /// state when needed
    #[staticmethod]
    fn from_creds(
        py: Python<'_>,
        public_parameters: Py<PyString>,
        secret_key: Py<PyString>,
    ) -> OoniResult<Self> {
        let pp = from_pystring(py, &public_parameters)?;
        let sk = from_pystring(py, &secret_key)?;

        Ok(Self {
            state: ooni::ServerState::from_creds(sk, pp),
        })
    }

    fn get_secret_key(&self, py: Python<'_>) -> Py<PyString> {
        to_pystring(py, self.state.secret_key_ref())
    }

    fn get_public_parameters(&self, py: Python<'_>) -> Py<PyString> {
        to_pystring(py, self.state.public_parameters_ref())
    }

    fn handle_registration_request(
        &self,
        py: Python<'_>,
        registration_request: Py<PyString>,
    ) -> OoniResult<Py<PyString>> {
        let req = from_pystring(py, &registration_request)?;
        let reply = self.state.open_registration(req)?;
        let result = to_pystring(py, &reply);
        Ok(result)
    }

    #[staticmethod]
    fn today() -> u32 {
        ooni::ServerState::today()
    }

    fn handle_submit_request(
        &self,
        py: Python<'_>,
        nym: Py<PyString>,
        request: Py<PyString>,
        probe_cc: Py<PyString>,
        probe_asn: Py<PyString>,
        age_range: Py<PyList>,
        measurement_count_range: Py<PyList>,
    ) -> OoniResult<Py<PyString>> {
        // Convert arguments from py types to rust types
        let nym = nym.to_str(py).map_err(|e| OoniErr::DeserializationFailed {
            reason: e.to_string(),
        })?;

        let nym = BASE64_STANDARD
            .decode(nym)
            .map_err(|e| OoniErr::DeserializationFailed {
                reason: e.to_string(),
            })?;

        let mut nym_32: [u8; 32] = [0; 32];
        nym_32.copy_from_slice(nym.as_ref());

        let request = from_pystring::<submit::Request>(py, &request)?;

        let probe_cc = probe_cc.to_str(py).expect("Could not get str");
        let probe_asn = probe_asn.to_str(py).expect("Could not get str");

        let age_range = age_range
            .extract::<Vec<u32>>(py)
            .expect("could not get list");
        let measurement_count_range = measurement_count_range
            .extract::<Vec<u32>>(py)
            .expect("could not get list");

        // Handle submission
        let mut rng = rand::thread_rng();
        let result = self.state.handle_submit(
            &mut rng,
            request,
            &nym_32,
            probe_cc,
            probe_asn,
            age_range[0]..age_range[1],
            measurement_count_range[0]..measurement_count_range[1],
        )?;

        Ok(to_pystring(py, &result))
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

#[gen_stub_pyclass]
#[pyclass]
pub struct UserState {
    pub state: ooni::UserState,
    pub registration_client_state: Option<open_registration::ClientState>,
    pub submit_client_state: Option<submit::ClientState>,
}

#[gen_stub_pymethods]
#[pymethods]
impl UserState {
    #[new]
    pub fn new(py: Python<'_>, public_params: Py<PyString>) -> OoniResult<Self> {
        let params = from_pystring(py, &public_params)?;
        Ok(Self {
            state: ooni::UserState::new(params),
            registration_client_state: None,
            submit_client_state: None,
        })
    }

    pub fn get_credential(&self, py: Python<'_>) -> Option<Py<PyString>> {
        self.state.get_credential().map(|c| to_pystring(py, c))
    }

    pub fn make_registration_request(&mut self, py: Python<'_>) -> OoniResult<Py<PyString>> {
        let mut rng = rand::thread_rng();

        let (req, state) = self.state.request(&mut rng)?;

        self.registration_client_state = Some(state);

        let result = to_pystring(py, &req);
        Ok(result)
    }

    /// Handle a registration response sent by the server, updating your credentials
    ///
    /// Note that this function will only work if you previously called
    /// `make_registration_request`
    pub fn handle_registration_response(
        &mut self,
        py: Python<'_>,
        resp: Py<PyString>,
    ) -> OoniResult<()> {
        let response = from_pystring::<open_registration::Reply>(py, &resp)?;

        let client_state = self.registration_client_state.take().expect(
            "Calling `handle_registration_response` without a registration client state. \
                    Did you forget to call `make_registration_request` before?",
        );

        self.state.handle_response(client_state, response)?;

        Ok(())
    }

    pub fn make_submit_request(
        &mut self,
        py: Python<'_>,
        probe_cc: Py<PyString>,
        probe_asn: Py<PyString>,
        emission_date: u32,
    ) -> OoniResult<SubmitRequest> {
        let probe_cc = probe_cc.to_str(py).expect("unable to get string");
        let probe_asn = probe_asn.to_str(py).expect("unable to get string");

        let mut rng = rand::thread_rng();
        let ((result, client_state), nym) = self.state.submit_request(
            &mut rng,
            probe_cc.into(),
            probe_asn.into(),
            (emission_date - 30)..(emission_date + 1),
            0..100,
        )?;

        self.submit_client_state = Some(client_state);

        Ok(SubmitRequest {
            nym: to_pystring(py, &nym),
            request: to_pystring(py, &result),
        })
    }

    /// Handle a submit response sent by the server, updating your credentials
    ///
    /// Note that this function will only work if you previously called
    /// `make_submit_request`
    pub fn handle_submit_response(
        &mut self,
        py: Python<'_>,
        response: Py<PyString>,
    ) -> OoniResult<()> {
        let response = from_pystring::<submit::Reply>(py, &response)?;

        let submit_state = self.submit_client_state.take().expect(
            "Calling `handle_submit_response` without a submit client state. \
                    Did you forget to call `make_submit_request` before?",
        );

        self.state.handle_submit_response(submit_state, response)?;

        Ok(())
    }
}

#[gen_stub_pyclass]
#[pyclass]
pub struct SubmitRequest {
    #[pyo3(get)]
    nym: Py<PyString>,
    #[pyo3(get)]
    request: Py<PyString>,
}

#[cfg(test)]
mod tests {
    use base64::{Engine, prelude::BASE64_STANDARD};
    use ooniauth_core::{ServerState, UserState, registration::open_registration::Request};
    use pyo3::{
        Python,
        types::{PyList, PyString},
    };
    use rand::{rngs::ThreadRng, thread_rng};

    #[test]
    fn test_encoding_verifies() {
        // Check that the string encoding still let us verify
        let (mut rng, client, server) = setup();
        let (req, _state) = client.request(&mut rng).unwrap();
        let req_bin = req.as_bytes();
        let req_str = BASE64_STANDARD.encode(req_bin);
        let req_bin = BASE64_STANDARD.decode(req_str).unwrap();
        let req = bincode::deserialize::<Request>(&req_bin).unwrap();
        assert!(server.open_registration(req).is_ok());
    }

    #[test]
    fn test_basic_usage() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            // Test "serializing" the server to python
            let server = crate::ServerState::new();

            let (pub_key, secret_key) =
                (server.get_public_parameters(py), server.get_secret_key(py));

            let server = crate::ServerState::from_creds(py, pub_key, secret_key).unwrap();

            // Test registration
            let mut client = crate::UserState::new(py, server.get_public_parameters(py)).unwrap();
            let req = client.make_registration_request(py).unwrap();
            let reg_response = server.handle_registration_request(py, req).unwrap();
            assert!(
                client
                    .handle_registration_response(py, reg_response)
                    .is_ok()
            );

            // Test submit
            let cc = PyString::new(py, "VE");
            let asn = PyString::new(py, "AS1234");
            let today = ServerState::today();
            let submit_req = client
                .make_submit_request(py, cc.clone().into(), asn.clone().into(), today)
                .unwrap();

            let age_range = PyList::new(py, vec![today - 30, today + 1]).unwrap();
            let msm_range = PyList::new(py, vec![0, 100]).unwrap();
            assert!(
                server
                    .handle_submit_request(
                        py,
                        submit_req.nym,
                        submit_req.request,
                        cc.into(),
                        asn.into(),
                        age_range.into(),
                        msm_range.into()
                    )
                    .is_ok()
            );
        });
    }

    fn setup() -> (ThreadRng, UserState, ServerState) {
        let mut rng = thread_rng();
        let server = ServerState::new(&mut rng);
        let pp = server.public_parameters();
        let user = UserState::new(pp);

        (rng, user, server)
    }
}
