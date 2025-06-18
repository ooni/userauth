include:
	mkdir -p include/
	cd include && git clone gogs@git-crysp.uwaterloo.ca:SigmaProtocol/cmz.git
	cd include && git clone gogs@git-crysp.uwaterloo.ca:SigmaProtocol/sigma_compiler.git
	cd include && git clone gogs@git-crysp.uwaterloo.ca:SigmaProtocol/sigma.git

.PHONY: include
