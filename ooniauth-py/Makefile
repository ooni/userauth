all: stubs
	maturin build 

dev: stubs
	maturin develop

stubs: 
	cargo run --bin gen_stubs
