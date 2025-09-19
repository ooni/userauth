include:
	mkdir -p include/
	cd include && git clone git@github.com:sigma-rs/cmz.git
	cd include && git clone git@github.com:sigma-rs/sigma-compiler.git

update:
	cd include/cmz && git pull
	cd include/sigma-compiler && git pull
	@echo "All sublibraries updated."

.PHONY: include update
