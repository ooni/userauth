use pyo3::{prelude::*, types::PyBytes};
use pyo3_stub_gen::{define_stub_info_gatherer, derive::{gen_stub_pyclass, gen_stub_pyfunction, gen_stub_pymethods}};
use ooniauth_core::{self as ooni, PublicParameters};
use rand;

/// Formats the sum of two numbers as string.
#[gen_stub_pyfunction]
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

#[gen_stub_pyclass]
#[pyclass]
pub struct ServerState {
    pub state : ooni::ServerState
}

#[pymethods]
impl ServerState  {
    
    #[new]
    pub fn new() -> Self{
        let mut rng = rand::thread_rng();
        Self {
            state : ooni::ServerState::new(&mut rng),
        }
    }
}

#[gen_stub_pyclass]
#[pyclass]
pub struct UserState {
    pub state : ooni::UserState
}

#[gen_stub_pymethods]
#[pymethods]
impl UserState {
    
    #[new]
    pub fn new(py: Python<'_>, public_params : Py<PyBytes>) -> Self{
        let params = bincode::deserialize::<PublicParameters>(&public_params.as_bytes(py)).unwrap_or_else(|e| panic!("Unable to deserialize public parameters: {e}"));
        Self {
            state: ooni::UserState::new(params)
        }
    }
}

#[gen_stub_pyfunction]
#[pyfunction]
pub fn get_public_parameters(py: Python<'_>, server_state : &ServerState) -> Py<PyBytes> {
    let public_params = server_state.state.public_parameters() ;
    let bytes = bincode::serialize(&public_params).unwrap_or_else(|e| panic!("Error serializing public parameters: {e}"));
    PyBytes::new(py, bytes.as_ref()).into()
}

/// A Python module implemented in Rust.
#[pymodule]
fn ooniauth_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_function(wrap_pyfunction!(get_public_parameters, m)?)?;
    m.add_class::<ServerState>()?;
    m.add_class::<UserState>()?;
    Ok(())
}

// Define a function to gather stub information.
define_stub_info_gatherer!(stub_info);