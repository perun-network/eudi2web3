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

- [ ] Add submodule initialization
- [ ] Add run `yarn` in these directories
    - circuits/zk-email-verify/packages/circuits
      NOTE: I'm not sure if this one is required
    - circuits/circom-ecdsa-p256
    - circuits/circom-ecdsa-p256/circuits/circom-pairing
- [ ] Add command to manually compile a circuit (instead of going through build.rs)

