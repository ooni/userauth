use ooniauth_core as ooni;
use ooniauth_core::registration::open_registration;
use ooniauth_core::submit::submit;
use pyo3::{
    prelude::*,
    types::{PyBytes, PyList, PyString},
};
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};

use crate::exceptions::OoniResult;
use crate::utils::{from_pybytes, to_pybytes};

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
        public_parameters: Py<PyBytes>,
        secret_key: Py<PyBytes>,
    ) -> OoniResult<Self> {
        let pp = from_pybytes(py, &public_parameters)?;
        let sk = from_pybytes(py, &secret_key)?;

        Ok(Self {
            state: ooni::ServerState::from_creds(sk, pp),
        })
    }

    fn get_secret_key(&self, py: Python<'_>) -> Py<PyBytes> {
        to_pybytes(py, self.state.secret_key_ref())
    }

    fn get_public_parameters(&self, py: Python<'_>) -> Py<PyBytes> {
        to_pybytes(py, self.state.public_parameters_ref())
    }

    fn handle_registration_request(
        &self,
        py: Python<'_>,
        registration_request: Py<PyBytes>,
    ) -> OoniResult<Py<PyBytes>> {
        let req = from_pybytes(py, &registration_request)?;
        let reply = self.state.open_registration(req)?;
        Ok(to_pybytes(py, &reply))
    }

    #[staticmethod]
    fn today() -> u32 {
        ooni::ServerState::today()
    }

    fn handle_submit_request(
        &self,
        py: Python<'_>,
        nym: Py<PyBytes>,
        request: Py<PyBytes>,
        probe_cc: Py<PyString>,
        probe_asn: Py<PyString>,
        age_range: Py<PyList>,
        measurement_count_range: Py<PyList>,
    ) -> OoniResult<Py<PyBytes>> {
        // Convert arguments from py types to rust types
        let nym = nym.as_bytes(py);
        let mut nym_32: [u8; 32] = [0; 32];
        nym_32.copy_from_slice(nym);

        let request = from_pybytes::<submit::Request>(py, &request)?;

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

        Ok(to_pybytes(py, &result))
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
    pub fn new(py: Python<'_>, public_params: Py<PyBytes>) -> OoniResult<Self> {
        let params = from_pybytes(py, &public_params)?;
        Ok(Self {
            state: ooni::UserState::new(params),
            registration_client_state: None,
            submit_client_state: None,
        })
    }

    pub fn get_credential(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        self.state.get_credential().map(|c| to_pybytes(py, c))
    }

    pub fn make_registration_request(&mut self, py: Python<'_>) -> OoniResult<Py<PyBytes>> {
        let mut rng = rand::thread_rng();

        let (req, state) = self.state.request(&mut rng)?;

        self.registration_client_state = Some(state);

        Ok(to_pybytes(py, &req))
    }

    /// Handle a registration response sent by the server, updating your credentials
    ///
    /// Note that this function will only work if you previously called
    /// `make_registration_request`
    pub fn handle_registration_response(
        &mut self,
        py: Python<'_>,
        resp: Py<PyBytes>,
    ) -> OoniResult<()> {
        let response = from_pybytes::<open_registration::Reply>(py, &resp)?;

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
            nym: to_pybytes(py, &nym),
            request: to_pybytes(py, &result),
        })
    }

    /// Handle a submit response sent by the server, updating your credentials
    ///
    /// Note that this function will only work if you previously called
    /// `make_submit_request`
    pub fn handle_submit_response(
        &mut self,
        py: Python<'_>,
        response: Py<PyBytes>,
    ) -> OoniResult<()> {
        let response = from_pybytes::<submit::Reply>(py, &response)?;

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
    nym: Py<PyBytes>,
    #[pyo3(get)]
    request: Py<PyBytes>,
}
