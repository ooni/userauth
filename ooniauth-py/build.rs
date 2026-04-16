// Build helper for plain Cargo workflows.
fn main() {
    pyo3_build_config::add_extension_module_link_args();

    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-env-changed=PYTHON_SYS_EXECUTABLE");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CFLAGS");
    println!("cargo:rerun-if-env-changed=LDFLAGS");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rustc-check-cfg=cfg(Py_3_10)");
    println!("cargo:rustc-check-cfg=cfg(Py_3_11)");
    println!("cargo:rustc-check-cfg=cfg(Py_3_12)");
    println!("cargo:rustc-check-cfg=cfg(Py_3_13)");
    println!("cargo:rustc-check-cfg=cfg(Py_3_14)");
    println!("cargo:rustc-check-cfg=cfg(Py_3_15)");
}
