# eudi2web3
## Setup
**Faucet**: https://docs.cardano.org/cardano-testnets/tools/faucet

```bash
# Generate key pair
cardano-cli address key-gen --verification-key-file me.vk --signing-key-file me.sk
cardano-cli conway address build --testnet-magic 2 --payment-verification-key-file me.vk | tee me.addr

# Convert aiken output into a format usable by cardano-cli
aiken blueprint convert > eudi2web3_demo.script
# Compute "contract" address
cardano-cli address build --testnet-magic 2 --payment-script-file eudi2web3_demo.script | tee eudi2web3_demo.addr

# Create UTXO with the script

```

## Configuring

**aiken.toml**
```toml
[config.default]
network_id = 41
```

Or, alternatively, write conditional environment modules under `env`.


## Resources

Find more on the [Aiken's user manual](https://aiken-lang.org).
