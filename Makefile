include:
	mkdir -p include/
	cd include && git clone git@github.com:ooni/cmz.git
	cd include && git clone git@github.com:ooni/sigma_compiler.git
	cd include && git clone https://github.com/mmaker/sigma-rs.git

update:
	cd include/cmz && git pull
	cd include/sigma_compiler && git pull
	cd include/sigma-rs && git pull
	@echo "All sublibraries updated."

.PHONY: include update
