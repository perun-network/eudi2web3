CIRCOM_SRC := $(shell find circuits -type d -name 'test*' -prune -o -type f -name '*.circom' -print)
AK_FILES := $(wildcard verifier/cardano/validators/*.ak)
SHELL := /usr/bin/env bash

# Built with prep-release, those are supposed to always be included in builds
# TODO: small requires a larger ptau file due to very expensive base64 decoding for _sd `]` checking.
RELEASE_TARGETS := \
	circuit-bls12-381-tiny_nocrypto \
	circuit-bls12-381-tiny \
	circuit-bls12-381-small_nocrypto
# Build with prep-tests, those are expected to be present for cargo test.
TEST_TARGETS := \
	circuit-bn254-minimal \
	circuit-bn254-tiny_nocrypto \
	circuit-bn254-witness_test \
	circuit-bn254-blsbug1 \
	circuit-bn254-blsbug2 \
	circuit-bn254-blsbug3 \
	circuit-bls12-381-minimal \
	circuit-bls12-381-blsbug1 \
	circuit-bls12-381-blsbug2 \
	circuit-bls12-381-blsbug3
# Build with prep-tests-slow, those are expected to be present for cargo test -F slow-tests --release
SLOW_TEST_TARGETS := \
	circuit-bn254-small_nocrypto \
	circuit-bls12-381-tiny

PTAU_SIZE_BN254 := 22
PTAU_SIZE_BLS12381 := 22

.PHONY: bn254 .bls12381 r1cs r1cs-bls12381 init install_w2c2
# Cryptographically relevant and expensive files we want to keep around.
# Note that these are rule names.
.PRECIOUS: %.zkey %.0001.zkey zkey/bn254/%.r1cs zkey/bls12-381/%.r1cs ptau/bn254_%.ptau ptau/bls12381_%.ptau zkey/lib/libbn254_%.a zkey/lib/libbls12-381_%.a

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
prep-release: $(RELEASE_TARGETS)
	@#
prep-tests: $(TEST_TARGETS)
	@#
prep-tests-slow: prep-tests $(SLOW_TEST_TARGETS)
	@#
# Shorthand so we don't need to repeat ourselves for generating the most common combinations
circuit-bn254-%: zkey/lib/libbn254_%.a zkey/bn254/%.0001.zkey
	@#
circuit-bls12-381-%: zkey/lib/libbls12-381_%.a zkey/bls12-381/%.0001.zkey zkey/bls12-381/%.cardano.json
	@#


##############
# ptau files #
##############

ptau/bn254_%.ptau:
	@echo -e "\x1b[96mDownloading ptau $*\x1b[0m"
	# https://github.com/privacy-ethereum/perpetualpowersoftau?tab=readme-ov-file#prepared-and-truncated-files
	time curl -fSL -o $@ https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_$*.ptau


# I could not find a good source for a bls12-381 ptau file that is large enough, so we have to generate it (will take a long time).
ptau/bls12-381_%.ptau:
	time snarkjs -v powersoftau new bls12381 $* $@
	time snarkjs -v powersoftau contribute $@ $@.tmp --name="first" --entropy="$${SNARKJS_ENTROPY:-$$(uuidgen)}"
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
	time circom $< -l circuits -o zkey/bn254 --r1cs --wasm -p bn128 --sym
	cargo clean -p eudi2web3

zkey/bls12-381/%.r1cs: circuits/%.circom $(CIRCOM_SRC)
	mkdir -p zkey/bls12-381
	@echo -e "\x1b[96mCompiling $*\x1b[0m"
	time circom $< -l circuits -o zkey/bls12-381 --r1cs --wasm -p bls12381 --sym
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
	time NODE_OPTIONS="--max-old-space-size=8192" snarkjs zkey contribute $< $@ --entropy "$(SNARKJS_ENTROPY)"
%.zkey: %.0001.zkey
	ln -sfn $(notdir $<) $@

%.vkey.json: %.zkey
	snarkjs zkey export verificationkey $< $@

##########################
# Witness gen (via w2c2) #
##########################
target/w2c2 target/w2c2_includes/w2c2_base.h &:
	mkdir -p target/w2c2_includes
	scripts/install_w2c2.sh

# Also outputs .h
zkey/%.c zkey/%.h &: zkey/%.r1cs target/w2c2
	scripts/run_w2c2.sh $< zkey/$*.c

zkey/%.o: zkey/%.c zkey/%.h target/w2c2_includes/w2c2_base.h
	gcc -std=c99 -O3 -I target/w2c2_includes -c $< -o $@

zkey/lib/libbn254_%.a: zkey/bn254/%.o
	mkdir -p zkey/lib
	ar rcs $@ $<
zkey/lib/libbls12-381_%.a: zkey/bls12-381/%.o
	mkdir -p zkey/lib
	ar rcs $@ $<

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

