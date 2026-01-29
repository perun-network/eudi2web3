# Installation
## Building from source
Compiling this project requires having circom installed and in the path. This can be done with the following command:
```bash
# See https://docs.circom.io/getting-started/installation/#installing-circom
# They have not pushed to crates.io
cargo install --git https://github.com/iden3/circom.git --locked
```

The easiest way to perform the trusted setup is with snarkjs:
```bash
npm install -g snarkjs@latest
```

