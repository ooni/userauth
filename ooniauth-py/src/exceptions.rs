use pyo3::prelude::*;
use pyo3::exceptions::*;

#[pyclass]
#[derive(Debug)]
pub enum OoniError {
    AuthenticationFailed,
    SerializationFailed
}

impl std::error::Error for OoniError {}

impl std::fmt::Display for OoniError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OoniError::AuthenticationFailed => write!(f, "Authentication Error"),
            OoniError::SerializationFailed => write!(f, "Serialization Error")
        }
    }
}
