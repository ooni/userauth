use pyo3::{prelude::*, types::PyBytes};

use crate::{exceptions::OoniErr, OoniResult};

pub fn to_pybytes<T: serde::Serialize>(py: Python<'_>, value: &T) -> Py<PyBytes> {
    // We consider a bad serialization as a programming error since most of the times
    // we want to serialize a structure made by us that should be well-formed
    let bytes =
        bincode::serialize(&value).unwrap_or_else(|e| panic!("Could not serialize value: {e}"));
    PyBytes::new(py, &bytes).into()
}

pub fn from_pybytes<'a, T: serde::Deserialize<'a>>(
    py: Python<'_>,
    bytes: &'a Py<PyBytes>,
) -> OoniResult<T> {
    // We consider bad deserialization an user error, since most of the time
    // what we are deserializing comes from the user in python world
    bincode::deserialize::<T>(bytes.as_bytes(py)).or_else(|e| {
        Err(OoniErr::DeserializationFailed {
            reason: e.to_string(),
        })
    })
}
