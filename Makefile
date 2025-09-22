include:
	mkdir -p include/
	cd include && git clone https://github.com/sigma-rs/cmz.git || echo "cmz already cloned"
	cd include && git clone https://github.com/sigma-rs/sigma-compiler.git || echo "sigma-compiler already cloned"
	cd include && git clone https://github.com/sigma-rs/sigma-proofs.git || echo "sigma-proofs already cloned"

update:
	cd include/cmz && git pull
	cd include/sigma-compiler && git pull
	cd include/sigma-proofs && git pull
	@echo "All sublibraries updated."

clean:
	rm -rf include/

.PHONY: include update clean
