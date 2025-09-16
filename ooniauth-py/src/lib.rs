use pyo3::prelude::*;
use pyo3_stub_gen::define_stub_info_gatherer;

pub mod exceptions;
pub mod protocol;
mod utils;

pub use protocol::*;

/// Here we define the python module itself and its members
#[pymodule]
fn ooniauth_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ServerState>()?;
    m.add_class::<UserState>()?;
    m.add_class::<SubmitRequest>()?;
    Ok(())
}

// Define a function to gather stub information.
define_stub_info_gatherer!(stub_info);
