all: stubs
	maturin build --release

dev: stubs
	maturin develop

dev-release: stubs
	maturin develop --release

stubs: 
	cargo run --bin gen_stubs
