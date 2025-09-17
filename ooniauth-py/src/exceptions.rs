use pyo3::exceptions::PyValueError;
use pyo3_stub_gen::create_exception;
use pyo3_stub_gen::type_info::*;
use pyo3_stub_gen::type_info;
use pyo3::PyErr;


// Note that the module name must be the name of the pyproject module name to prevent errors,
// we should create an issue in the pyo3_stub_gen repo about this. The thing is that 
// if the value of the module argument here is different of the pyproject one except for
// _ and -, it confuses itself and thinks that its a different module while writing in
// the same resulting .pyi, deleting parts of the content

create_exception!(ooniauth-py, AuthenticationFailed, PyValueError, "");
create_exception!(ooniauth-py, SerializationFailed, PyValueError, "");


#[derive(Debug)]
pub enum OoniErr {
    AuthenticationFailed{reason: String},
    DeserializationFailed{reason: String}
}

impl std::error::Error for OoniErr {}

impl std::fmt::Display for OoniErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OoniErr::AuthenticationFailed{reason} => write!(f, "Authentication Error: {reason}"),
            OoniErr::DeserializationFailed{reason} => write!(f, "Serialization Error: {reason}")
        }
    }
}

impl From<OoniErr> for PyErr {
    fn from(value: OoniErr) -> Self {
        match value {
            OoniErr::AuthenticationFailed{reason} => AuthenticationFailed::new_err(reason),
            OoniErr::DeserializationFailed {reason} => SerializationFailed::new_err(reason)
        }
    }
}