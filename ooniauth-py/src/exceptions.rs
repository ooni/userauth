use cmz::CMZError;
use pyo3::exceptions::PyException;
use pyo3_stub_gen::create_exception;
use pyo3::PyErr;


// Note that the module name must be the name of the pyproject module name to prevent errors,
// we should create an issue in the pyo3_stub_gen repo about this. The thing is that
// if the value of the module argument here is different of the pyproject one except for
// _ and -, it confuses itself and thinks that its a different module while writing in
// the same resulting .pyi, deleting parts of the content

// TODO Probably we need more exception classes for the protocol-related errors
create_exception!(
    ooniauth-py,
    ProtocolError,
    PyException,
    "There was an error completing the proocol. Could mean that the user credentials didn't verify,
    or that the server response didn't verify");

create_exception!(
    ooniauth-py,
    DeserializationFailed,
    PyException,
    "There was an error trying to deserialize a binary buffer"
);


#[derive(Debug)]
pub enum OoniErr {
    ProtocolError{reason: CMZError},
    DeserializationFailed{reason: String}
}

impl std::error::Error for OoniErr {}

impl std::fmt::Display for OoniErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OoniErr::ProtocolError{reason} => write!(f, "Protocol Error: {reason}"),
            OoniErr::DeserializationFailed{reason} => write!(f, "Deserialization Error: {reason}")
        }
    }
}

impl From<OoniErr> for PyErr {
    fn from(value: OoniErr) -> Self {
        // This function maps from rust variants to the corresponding python exception
        match value {
            OoniErr::ProtocolError{reason} => ProtocolError::new_err(format!("{reason}")),
            OoniErr::DeserializationFailed {reason} => DeserializationFailed::new_err(reason)
        }
    }
}