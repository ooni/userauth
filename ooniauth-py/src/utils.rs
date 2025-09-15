use pyo3::{prelude::*, types::PyBytes};

pub fn to_pybytes<T : serde::Serialize>(py: Python<'_>, value: &T) -> Py<PyBytes> {
    // TODO Better error handling
    let bytes = bincode::serialize(&value).unwrap_or_else(|e| panic!("Could not serialize value: {e}"));
    PyBytes::new(py, &bytes).into()
}

pub fn from_pybytes<'a, T : serde::Deserialize<'a>>(py: Python<'_>, bytes : &'a Py<PyBytes>) -> T {
    // TODO Better error handling
    bincode::deserialize::<T>(bytes.as_bytes(py))
    .unwrap_or_else(|e| panic!("Unable to deserialize registration request: {e}"))
}