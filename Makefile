include:
	mkdir -p include/
	cd include && git clone git@github.com:ooni/cmz.git
	cd include && git clone git@github.com:ooni/sigma_compiler.git
	cd include && git clone https://github.com/mmaker/sigma-rs.git

.PHONY: include
