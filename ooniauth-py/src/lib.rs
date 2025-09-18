use pyo3::prelude::*;
use pyo3_stub_gen::define_stub_info_gatherer;

pub mod exceptions;
pub mod protocol;
mod utils;

pub use exceptions::*;
pub use protocol::*;

/// Here we define the python module itself and its members
#[pymodule]
fn ooniauth_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ServerState>()?;
    m.add_class::<UserState>()?;
    m.add_class::<SubmitRequest>()?;
    m.add("AuthenticationFailed", m.py().get_type::<ProtocolError>())?;
    m.add(
        "SerializationFailed",
        m.py().get_type::<DeserializationFailed>(),
    )?;
    Ok(())
}

// Define a function to gather stub information.
define_stub_info_gatherer!(stub_info);
