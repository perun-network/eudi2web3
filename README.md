# Installation
## Building from source
Install the required dependencies
```bash
# For Ubuntu
apt install rustup make npm curl pkg-config cmake

# Install the Rust toolchain
rustup default stable
# Install circom compiler
# See https://docs.circom.io/getting-started/installation/#installing-circom
# They have not pushed to crates.io
cargo install --git https://github.com/iden3/circom.git --locked
# Needed for the trusted setup
npm install -g snarkjs@latest

# Choose a curve and compile the circuit, run the trusted setup and build/run the binary
# Init only needs to be made once, it prepares the submodules and circom dependencies
make init bn254 && cargo run --release
# Alternative curve (significantly slower due to generating its own powersoftau)
make init bls12381 && cargo run --release
```

## Faster iteration times
Signature verification and hashing result in very large circuits, which can make execution slow.
During development I recommend setting CHECK_SIG=false in the circom file, that disables signature
verification and hashing, thus making the circuit a lot smaller but also insecure.

