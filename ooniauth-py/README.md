# Python Bindings

This crate implements the Python bindings for the [core](https://github.com/ooni/userauth) library.

## Dependencies

**[Maturin](https://github.com/PyO3/maturin)**: This is used to generate the wheels with the bindings. With a virtual environment active, you can install it with the following command:
```bash
pip install maturin
```

## Building 
You can build the library using 
```
make all
```

This will create the wheels file in `userauth/target/wheels`. You can use this wheels file as any other python dependency!

