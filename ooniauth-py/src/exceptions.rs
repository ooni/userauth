use cmz::CMZError;
use ooniauth_core::errors as errors;
use pyo3::exceptions::PyException;
use pyo3_stub_gen::create_exception;
use pyo3::PyErr;


// Note that the module name must be the name of the pyproject module name to prevent errors,
// we should create an issue in the pyo3_stub_gen repo about this. The thing is that
// if the value of the module argument here is different of the pyproject one except for
// _ and -, it confuses itself and thinks that its a different module while writing in
// the same resulting .pyi, deleting parts of the content

// TODO Probably we need more exception classes for the protocol-related errors
create_exception!{
    ooniauth-py,
    ProtocolError,
    PyException,
    "An error performing the protocol"
}

create_exception!{
    ooniauth-py,
    DeserializationFailed,
    PyException,
    "An error trying to deserialize a binary buffer"
}

// TODO Q: should I create a new python exception per variant of errors::CredentialError?
create_exception!{
    ooniauth-py,
    CredentialError,
    PyException,
    "An authentication error"
}


#[derive(Debug)]
pub enum OoniErr {
    ProtocolError{reason: CMZError},
    CredentialError{reason: errors::CredentialError},
    DeserializationFailed{reason: String}
}

pub type OoniResult<T> = Result<T, OoniErr>;

impl std::error::Error for OoniErr {}

impl std::fmt::Display for OoniErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OoniErr::ProtocolError{reason} => write!(f, "Protocol Error: {reason}"),
            OoniErr::DeserializationFailed{reason} => write!(f, "Deserialization Error: {reason}"),
            OoniErr::CredentialError { reason} => write!(f, "Credential Error: {reason}")
        }
    }
}

impl From<OoniErr> for PyErr {
    fn from(value: OoniErr) -> Self {
        // This function maps from rust error enums to their corresponding python exception
        match value {
            OoniErr::ProtocolError{reason} => ProtocolError::new_err(format!("{reason}")),
            OoniErr::DeserializationFailed {reason} => DeserializationFailed::new_err(reason),
            OoniErr::CredentialError { reason: errors::CredentialError::CMZError(e) } => ProtocolError::new_err(format!("{e}")),
            OoniErr::CredentialError { reason } => CredentialError::new_err(format!("{reason}"))
        }
    }
}

impl From<CMZError> for OoniErr {
    fn from(value: CMZError) -> Self {
        OoniErr::ProtocolError { reason: value }
    }
}

impl From<errors::CredentialError> for OoniErr {
    fn from(value: errors::CredentialError) -> Self {
        OoniErr::CredentialError { reason: value }
    }
}