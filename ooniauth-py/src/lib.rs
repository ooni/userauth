use pyo3::prelude::*;
use pyo3_stub_gen::{define_stub_info_gatherer, derive::{gen_stub_pyclass, gen_stub_pyfunction}};
use ooniauth_core as ooni;

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

/// A Python module implemented in Rust.
#[pymodule]
fn ooniauth_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_class::<ServerState>()?;
    Ok(())
}

// Define a function to gather stub information.
define_stub_info_gatherer!(stub_info);