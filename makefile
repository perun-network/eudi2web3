CIRCOM_SRC := $(shell find circuits -type d -name 'test*' -prune -o -type f -name '*.circom' -print)
AK_FILES := $(wildcard verifier/cardano/validators/*.ak)
SHELL := /usr/bin/env bash

PTAU_SIZE_BN254 := 22
PTAU_SIZE_BLS12381 := 22

.PHONY: bn254 .bls12381 r1cs r1cs-bls12381 init
# Cryptographically relevant and expensive files we want to keep around.
# Note that these are rule names.
.PRECIOUS: %.zkey %.0001.zkey zkey/bn254/%.r1cs zkey/bls12-381/%.r1cs

# Compile circuits for this curve and prepare everything for cargo run.
# This includes a 1-person setup and can be quite slow for large circuits

# bn254: PTAU = ptau/bn254_22.ptau
# bn254: CURVE = bn128 # circom uses a different naming scheme
# bn254: zkey/.curve-bn254 zkey/sdjwt_es256_sha256_1claim.r1cs zkey/sdjwt_es256_sha256_1claim.zkey
# 
# # I haven't generated a large enough ptau file yet, so for testing this curve I'm using a smaller one
# bls12381: PTAU = ptau/bls12381_22.ptau
# bls12381: CURVE = bls12381
# bls12381: zkey/.curve-bls12381 zkey/sdjwt_es256_sha256_1claim.r1cs zkey/sdjwt_es256_sha256_1claim.zkey
# 
# # Build all r1cs files but don't make the zkeys
# r1cs: CURVE = bn128 # circom uses a different naming scheme
# r1cs: zkey/sdjwt_es256_sha256_1claim.r1cs
# 
# r1cs-bls12381: CURVE = bls12381
# r1cs-bls12381: zkey/sdjwt_es256_sha256_1claim.r1cs

# Prepare the repo:
# - initialize submodules
# - Fix circom imports going into node_modules, causing duplicate import issues
# - Avoid circom symbol conflicts
init:
	mkdir -p ptau
	mkdir -p zkey/bn254
	mkdir -p zkey/bls12-381
	git submodule update --init --recursive
	scripts/circom_rename.sh circuits/circom-ecdsa-p256 ecdsa__

clean:
	rm -r zkey/*

###################
# for convenience #
###################
# For some reason the @# is load-bearing
prep-lib-%-minimal: zkey/%/minimal.zkey zkey/bls12-381/minimal.cardano.json
	@#
prep-tests-%-minimal: prep-lib-%-minimal zkey/bls12-381/minimal.zkey
	@#
prep-lib-%-full: zkey/%/sdjwt_es256_sha256_1claim.zkey zkey/bls12-381/sdjwt_es256_sha256_1claim.cardano.json
	@#
prep-tests-%-full: prep-lib-%-full zkey/bls12-381/sdjwt_es256_sha256_1claim.zkey
	@#

##############
# ptau files #
##############

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


####################
# Circom + snarkjs #
####################

zkey/bn254/%.r1cs: circuits/%.circom $(CIRCOM_SRC)
	mkdir -p zkey/bn254
	@echo -e "\x1b[96mCompiling $*\x1b[0m"
	@# circom uses a different naming scheme
	time circom $< -l circuits -o zkey/bn254 --r1cs --wasm -p bn128
	cargo clean -p eudi2web3

zkey/bls12-381/%.r1cs: circuits/%.circom $(CIRCOM_SRC)
	mkdir -p zkey/bls12-381
	@echo -e "\x1b[96mCompiling $*\x1b[0m"
	time circom $< -l circuits -o zkey/bls12-381 --r1cs --wasm -p bls12381
	cargo clean -p eudi2web3

zkey/bn254/%.0000.zkey: zkey/bn254/%.r1cs ptau/bn254_$(PTAU_SIZE_BN254).ptau
	time NODE_OPTIONS="--max-old-space-size=8192" snarkjs groth16 setup $< ptau/bn254_$(PTAU_SIZE_BN254).ptau $@

zkey/bls12-381/%.0000.zkey: zkey/bls12-381/%.r1cs ptau/bls12-381_$(PTAU_SIZE_BLS12381).ptau
	@echo -e "\x1b[96mCircuit specific setup $*\x1b[0m"
	time NODE_OPTIONS="--max-old-space-size=8192" snarkjs groth16 setup $< ptau/bls12-381_$(PTAU_SIZE_BLS12381).ptau $@

%.0001.zkey: %.0000.zkey
	@echo -e "\x1b[96mCircuit specific contribution 1 $*\x1b[0m"
	@# Very important step for security. Can be skipped during development but without this the whole proof system is insecure.
	@# See https://rekt.news/default-settings
	@# See https://blog.zksecurity.xyz/posts/groth16-setup-exploit/
	time NODE_OPTIONS="--max-old-space-size=8192" snarkjs zkey contribute $< $@

%.zkey: %.0001.zkey
	ln -sfn $(notdir $<) $@

%.vkey.json: %.zkey
	snarkjs zkey export verificationkey $< $@


###########
# CARDANO #
###########

%.sk %.vk &:
	@# To make sure we don't accidentally use the addr we remove it immediately.
	rm me.addr
	cardano-cli address key-gen --verification-key-file $*.vk --signing-key-file $*.sk

%.addr: %.vk
	cardano-cli conway address build --testnet-magic 2 --payment-verification-key-file $< > $@

verifier/cardano/plutus.json: $(AK_FILES)
	(cd verifier/cardano && aiken build)

# Examples: zkey/bls12-381/minimal.eudi2web3.cardano.script
# Warning: Not useful for bn254
%.cardano.json: %.vkey.json verifier/cardano/plutus.json
	STEM=$*; aiken blueprint apply -i verifier/cardano/plutus.json -o $@ -m eudi2web3_demo \
		"$$(cargo run --bin vkey2cardano -- $<)"

