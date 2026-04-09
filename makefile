CIRCOM_SRC := $(shell find circuits -type d -name 'test*' -prune -o -type f -name '*.circom' -print)
AK_FILES := $(wildcard verifier/cardano/validators/*.ak)
SHELL := /usr/bin/env bash

.PHONY: bn254 .bls12381 r1cs r1cs-bls12381 init

# Compile circuits for this curve and prepare everything for cargo run.
# This includes a 1-person setup and can be quite slow for large circuits

bn254: PTAU = ptau/bn254_22.ptau
bn254: CURVE = bn128 # circom uses a different naming scheme
bn254: zkey/.curve-bn254 zkey/sdjwt_es256_sha256_1claim.r1cs zkey/sdjwt_es256_sha256_1claim.zkey

# I haven't generated a large enough ptau file yet, so for testing this curve I'm using a smaller one
bls12381: PTAU = ptau/bls12381_22.ptau
bls12381: CURVE = bls12381
bls12381: zkey/.curve-bls12381 zkey/sdjwt_es256_sha256_1claim.r1cs zkey/sdjwt_es256_sha256_1claim.zkey

# Build all r1cs files but don't make the zkeys
r1cs: CURVE = bn128 # circom uses a different naming scheme
r1cs: zkey/sdjwt_es256_sha256_1claim.r1cs

r1cs-bls12381: CURVE = bls12381
r1cs-bls12381: zkey/sdjwt_es256_sha256_1claim.r1cs

# Prepare the repo:
# - initialize submodules
# - Fix circom imports going into node_modules, causing duplicate import issues
# - Avoid circom symbol conflicts
init:
	mkdir ptau
	mkdir zkey
	git submodule update --init --recursive
	scripts/circom_rename.sh circuits/circom-ecdsa-p256 ecdsa__

clean:
	rm -r zkey/*

# bls12381: zkey/.curve-bls12381 zkey/sdjwt_es256_sha256_1claim.zkey

####################
# Circom + snarkjs #
####################

zkey/%.r1cs: circuits/%.circom $(CIRCOM_SRC)
	@echo -e "\x1b[96mCompiling $*\x1b[0m"
	time circom $< -l circuits -o zkey --r1cs --wasm -p $(CURVE)
	cargo clean -p eudi2web3
	
zkey/%.zkey: zkey/%.r1cs
	$(MAKE) $(PTAU)
	@echo -e "\x1b[96mCircuit specific setup $*\x1b[0m"
	time NODE_OPTIONS="--max-old-space-size=8192" snarkjs groth16 setup $< $(PTAU) zkey/$*-insecure.zkey
	# Very important step for security. Can be skipped during development but without this the whole proof system is insecure.
	# See https://rekt.news/default-settings
	# See https://blog.zksecurity.xyz/posts/groth16-setup-exploit/
	time NODE_OPTIONS="--max-old-space-size=8192" snarkjs zkey contribute zkey/$*-insecure.zkey $@
	rm zkey/$*-insecure.zkey

zkey/%.vkey.json: zkey/%.zkey
	snarkjs zkey export verificationkey $< $@

# Marker files to store which curve was used to generate the files
# This is run whenever the curve does not match. It cleans the bad files.
zkey/.curve-%:
	@echo "DELETE"
	rm -f zkey/.curve-*
	rm -rf zkey/*
	touch $@

ptau/bn254_%.ptau:
	@echo -e "\x1b[96mDownloading ptau $*\x1b[0m"
	# https://github.com/privacy-ethereum/perpetualpowersoftau?tab=readme-ov-file#prepared-and-truncated-files
	time curl -fSL -o $@ https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_$*.ptau


# I could not find a good source for a bls12-381 ptau file that is large enough, so we have to generate it (will take a long time).
ptau/bls12381_%.ptau:
	time snarkjs -v powersoftau new bls12381 $* $@
	time snarkjs -v powersoftau contribute $@ $@.tmp --name="first"
	# 4 sections: tauG1, tauG2, alphaTauG1, betaTauG1
	# Each section goes up to fft PTAU
	time snarkjs -v powersoftau prepare phase2 $@.tmp $@ -v
	rm $@.tmp

###########
# CARDANO #
###########

me.sk me.vk &:
	rm me.addr
	cardano-cli address key-gen --verification-key-file me.vk --signing-key-file me.sk

me.addr: me.vk
	cardano-cli conway address build --testnet-magic 2 --payment-verification-key-file me.vk > me.addr

verifier/cardano/plutus.json: $(AK_FILES)
	(cd verifier/cardano && aiken build)

verifier/cardano/%.script: verifier/cardano/plutus.json
	PARAMS_CBOR=$(cargo run --bin vkey2cardano)
	aiken blueprint apply -i $< -o $@ -m $* &(PARAMS_CBOR)

