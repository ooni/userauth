use ooniauth_core::registration::open_registration;
use ooniauth_core as ooni;
use pyo3::{prelude::*, types::PyBytes};
use pyo3_stub_gen::{
    define_stub_info_gatherer,
    derive::{gen_stub_pyclass, gen_stub_pymethods},
};
use rand;

mod utils;

use utils::{from_pybytes, to_pybytes};

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

    /* Create a new server state from binary-serialized public and private keys

       This is meant to be used by the server, so it can store the keys somewhere and recreate the
       state when needed
    */
    #[staticmethod]
    fn from_creds(py: Python<'_>, public_parameters: Py<PyBytes>, secret_key: Py<PyBytes>) -> Self {
        let pp = from_pybytes(py, &public_parameters);
        let sk = from_pybytes(py, &secret_key);

        Self {
            state: ooni::ServerState::from_creds(sk, pp),
        }
    }

    fn get_secret_key(&self, py: Python<'_>) -> Py<PyBytes> {
        to_pybytes(py, self.state.get_secret_key())
    }

    fn get_public_parameters(&self, py: Python<'_>) -> Py<PyBytes> {
        to_pybytes(py, self.state.get_public_parameters())
    }

    fn handle_registration_request(
        &mut self,
        py: Python<'_>,
        registration_request: Py<PyBytes>,
    ) -> Py<PyBytes> {
        let req = from_pybytes(py, &registration_request);
        let reply = self.state.open_registration(req).unwrap_or_else(|e| panic!("Error openning registration: {e}"));

        to_pybytes(py, &reply)
    }
}


#[gen_stub_pyclass]
#[pyclass]
pub struct UserState {
    pub state: ooni::UserState,
    pub client_state: Option<open_registration::ClientState>,
}

#[gen_stub_pymethods]
#[pymethods]
impl UserState {
    #[new]
    pub fn new(py: Python<'_>, public_params: Py<PyBytes>) -> Self {
        let params = from_pybytes(py, &public_params);
        Self {
            state: ooni::UserState::new(params),
            client_state: None,
        }
    }

    pub fn make_register_request(&mut self, py: Python<'_>) -> Py<PyBytes> {
        let mut rng = rand::thread_rng();
        // TODO Better error handling
        let (req, state) = self
            .state
            .request(&mut rng)
            .unwrap_or_else(|e| panic!("Couldn't make registration request: {e}"));
        self.client_state = Some(state);
        to_pybytes(py, &req)
    }

    pub fn handle_registration_response(&mut self, py: Python<'_>, resp : Py<PyBytes>) {
        let response = from_pybytes::<open_registration::Reply>(py, &resp);
        let client_state = self.client_state.take().expect("Trying to handle response without client state");
        self.state.handle_response(client_state, response).unwrap_or_else(|e| panic!("Could not handle registration response: {e}"));
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn ooniauth_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ServerState>()?;
    m.add_class::<UserState>()?;
    Ok(())
}

// Define a function to gather stub information.
define_stub_info_gatherer!(stub_info);
