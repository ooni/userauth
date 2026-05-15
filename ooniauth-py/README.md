# ooniauth-py

This is the bindings library used to call the anonymous credentials library from Python land

We use this in our backend implement the anonymous credentials protocol in our API

## Installation

You can install this library by running:

```bash
pip install ooniauth-py
```

## Development requirements

These tools are required to contribute to this library

1. [maturin](https://github.com/PyO3/maturin): Is used to build the library itself, it's heavily used to develop this library


In order to use [maturin](https://github.com/PyO3/maturin), you need a virtual environment to manage
the resulting Python package during development, see more details
[here](https://www.maturin.rs/tutorial.html#install-and-configure-maturin-in-a-virtual-environment)

### Testing installation

Run the Rust tests with:

```bash
cargo test
```

The Python extension-module linker mode is enabled only for Maturin builds.
If you need to test against a specific Python interpreter, activate a virtualenv
or set `PYO3_PYTHON` before running the tests. The virtualenv must point to a
base Python installation which provides an embeddable shared library.

### Usage

1. Create a ready-to-use `.whl` to import in python: `make wheels`
  - **Note**: You will find the wheels file in: `/userauth/ooniauth-py/wheels`
2. Build the library and install it in a virtualenv for trying it in Python: `make dev`
  - **Note**: Requires an active virtual environment to install the library
3. Run tests: `make test`
