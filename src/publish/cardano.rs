use ark_serialize::CanonicalSerialize;
use circom_prover::prover::circom::{G1, G2};
use hex::ToHex;
use pallas_primitives::{Constr, Fragment, MaybeIndefArray, NetworkId, PlutusData};
use pallas_txbuilder::{
    BuildConway, ExUnits, Input, Output, ScriptKind::PlutusV3, StagingTransaction,
};
use pallas_wallet::PrivateKey;
use serde::Deserialize;

use crate::{MAX_VALUE_BYTES, prover::ProofWithPubInput};

const BLOCKFROST_URL: &str = "https://cardano-preview.blockfrost.io/api/v0";
const SCRIPT_VERSION: u8 = 3;

// TODO: This file contains a bunch of methods using unwrap instead of having proper error
// forwarding or retries.

pub async fn deploy(path: &str) {
    // Could be loaded once in the beginning and reused.
    let addr = tokio::fs::read_to_string("me.addr").await.unwrap();
    let (script_bytes, script_hash) = script_bytecode(path).await;
    // let script_hash = script_hash(&script_bytes, SCRIPT_VERSION);

    let fee = 400_000;
    let min_balance = 20_000_000;

    // Use the first UTXO we have as input
    let utxos = get_utxos(&addr).await;
    let (s_input, input) = select_utxo(&utxos, &script_hash, 2 * min_balance + fee);

    if s_input.is_some() {
        eprintln!("Script already deployed, doing nothing");
        return;
    }
    let addr = pallas_addresses::Address::from_bech32(&addr).unwrap();

    let tx = StagingTransaction::new()
        .network_id(NetworkId::Testnet.into())
        .input(input.to_input())
        .output(Output::new(
            addr.clone(),
            input.lovelace_balance() - fee - min_balance,
        ))
        .output(
            Output::new(addr, min_balance)
                .set_inline_script(PlutusV3, script_bytes)
                .set_inline_datum(vec![0xd8, 0x79, 0x80]), // Constr 0, empty array
        )
        .fee(fee)
        .build_conway_raw()
        .unwrap();

    let sk = read_sk().await;
    // Sign changes tx.tx_bytes (adding the signature)
    let tx = tx.sign(sk).unwrap();

    dbg!(tx.tx_bytes.encode_hex::<String>());

    // dbg!(&tx);

    submit_tx(tx.tx_bytes.0).await;
}

pub async fn publish(script_path: &str, proof: &ProofWithPubInput) -> [u8; 32] {
    let redeemer = encode_redeemer(proof);
    dbg!(hex::encode(&redeemer));
    publish_inner(script_path, redeemer).await
}

// Returns the transaction hash
async fn publish_inner(script_path: &str, redeemer: Vec<u8>) -> [u8; 32] {
    // Could be loaded once in the beginning and reused.
    let addr = tokio::fs::read_to_string("me.addr").await.unwrap();
    let (script_bytes, script_hash) = script_bytecode(script_path).await;
    // let script_hash = script_hash(&script_bytes, SCRIPT_VERSION);

    // Build inputs

    let fee = 200_000;
    let min_balance = 4_000_000;

    // Use the first UTXO we have as input
    let utxos = get_utxos(&addr).await;
    let (input_script, input_fees) = select_utxo(&utxos, &script_hash, fee + min_balance);
    let input_script = input_script.expect("Script not found");
    let addr = pallas_addresses::Address::from_bech32(&addr).unwrap();

    // Build transaction
    let tx = StagingTransaction::new()
        .network_id(NetworkId::Testnet.into())
        .input(input_script.to_input())
        .input(input_fees.to_input())
        .output(Output::new(
            addr.clone(),
            input_fees.lovelace_balance() - fee,
        ))
        .output(
            Output::new(addr, input_script.lovelace_balance())
                .set_inline_script(PlutusV3, script_bytes)
                .set_inline_datum(vec![0xd8, 0x79, 0x80]),
        )
        .fee(fee);
    let ex_units = eval_execution_units(&tx, input_script.to_input(), redeemer.clone()).await;
    let tx = tx
        .add_spend_redeemer(input_script.to_input(), redeemer, Some(ex_units))
        .build_conway_raw()
        .unwrap();

    let tx_bytes = hex::encode(&tx.tx_bytes.0);
    dbg!(tx_bytes);

    let sk = read_sk().await;
    // Sign changes tx.tx_bytes (adding the signature)
    let tx = tx.sign(sk).unwrap();

    dbg!(tx.tx_bytes.encode_hex::<String>());

    submit_tx(tx.tx_bytes.0).await;

    tx.tx_hash.0
}

fn encode_redeemer(proof: &ProofWithPubInput) -> Vec<u8> {
    build_redeemer(proof).encode_fragment().unwrap()
}

fn build_redeemer(proof: &ProofWithPubInput) -> PlutusData {
    let claim_value = &proof.pub_input[1..1 + MAX_VALUE_BYTES];
    let claim_value: Vec<u8> = claim_value
        .iter()
        .map(|x| {
            assert!(*x <= u8::MAX.into());
            let digits = x.to_u64_digits();
            let x = digits.first().copied().unwrap_or(0);
            assert!(x <= u8::MAX as u64);
            x as u8
        })
        .collect();

    // See https://cardano-c.readthedocs.io/en/latest/api/plutus_data/constr_plutus_data.html
    const TAG_CONSTR_0: u64 = 121;

    PlutusData::Constr(Constr {
        tag: TAG_CONSTR_0,
        any_constructor: None,
        fields: MaybeIndefArray::Def(vec![
            PlutusData::Constr(Constr {
                tag: TAG_CONSTR_0,
                any_constructor: None,
                fields: MaybeIndefArray::Def(vec![
                    PlutusData::BoundedBytes(bls_g1_to_bytes(&proof.proof.a).into()),
                    PlutusData::BoundedBytes(bls_g2_to_bytes(&proof.proof.b).into()),
                    PlutusData::BoundedBytes(bls_g1_to_bytes(&proof.proof.c).into()),
                ]),
            }),
            PlutusData::BoundedBytes(claim_value.into()),
        ]),
    })
}

// TODO: Wrong format
fn bls_g1_to_bytes(a: &G1) -> Vec<u8> {
    let a: ark_bls12_381::G1Projective = a.clone().to_bls12_381().into();
    let mut bytes = Vec::with_capacity(3 * 32);
    a.serialize_uncompressed(&mut bytes).unwrap();
    debug_assert_eq!(bytes.len(), 3 * 32);
    bytes
}
fn bls_g2_to_bytes(a: &G2) -> Vec<u8> {
    let a: ark_bls12_381::G2Projective = a.clone().to_bls12_381().into();
    let mut bytes = Vec::with_capacity(6 * 32);
    a.serialize_uncompressed(&mut bytes).unwrap();
    debug_assert_eq!(bytes.len(), 6 * 32);
    bytes
}

#[derive(Deserialize)]
struct PlutusJson {
    validators: Vec<Validator>,
}
#[derive(Deserialize)]
struct Validator {
    #[serde(rename = "compiledCode")]
    compiled_code: String,
    hash: String,
}

// Additionally returns hex(hash).
async fn script_bytecode(path: &str) -> (Vec<u8>, String) {
    let json = tokio::fs::read_to_string(path).await.unwrap();
    let plutus_json: PlutusJson = serde_json::from_str(&json).unwrap();
    let data = plutus_json.validators.into_iter().next().unwrap();
    let script = hex::decode(&data.compiled_code).expect("invalid hex");

    (script, data.hash)
}

// async fn script_bytecode(path: &str) -> Vec<u8> {
//     let script = tokio::fs::read_to_string(path).await.unwrap();
//     hex::decode(&script).expect("invalid hex")
// }
//
// fn script_hash(script: &[u8], plutus_version: u8) -> String {
//     type Blake2b224 = Blake2b<blake2::digest::consts::U28>;
//
//     let mut hasher = Blake2b224::new();
//     hasher.update([plutus_version]);
//     hasher.update(script);
//     let hash = hasher.finalize();
//     hex::encode(hash)
// }

#[derive(Deserialize)]
struct SecretKeyContainer {
    #[serde(rename = "cborHex")]
    cbor_hex: String,
}

async fn read_sk() -> PrivateKey {
    let json = tokio::fs::read_to_string("me.sk").await.unwrap();
    let container: SecretKeyContainer = serde_json::from_str(&json).unwrap();
    // cbor header: 0x58 means one byte containing the length
    assert!(container.cbor_hex.starts_with("5820"));
    let mut sk = [0; 32];
    hex::decode_to_slice(&container.cbor_hex[4..], &mut sk).unwrap();
    PrivateKey::Normal(sk.into())
}

#[derive(Deserialize)]
struct Utxo {
    // There are more fields, but for now we just need these.
    tx_hash: String,
    tx_index: u64,
    amount: Vec<BalanceEntry>,
    reference_script_hash: Option<String>,
}

#[derive(Deserialize)]
struct BalanceEntry {
    unit: String,
    quantity: String,
}

impl Utxo {
    fn lovelace_balance(&self) -> u64 {
        let mut sum = 0;
        for e in &self.amount {
            if e.unit == "lovelace" {
                sum += e.quantity.parse::<u64>().unwrap();
            }
        }
        sum
    }
    fn tx_hash(&self) -> [u8; 32] {
        let mut out = [0; 32];
        hex::decode_to_slice(&self.tx_hash, &mut out).unwrap();
        out
    }
    fn to_input(&self) -> Input {
        Input::new(self.tx_hash().into(), self.tx_index)
    }
}

async fn get_utxos(addr: &str) -> Vec<Utxo> {
    let blockfrost_key =
        std::env::var("BLOCKFROST_KEY").expect("No BLOCKFROST_KEY environment variable");

    let client = reqwest::Client::new();
    let request = client
        .get(format!("{BLOCKFROST_URL}/addresses/{addr}/utxos"))
        .header("project_id", blockfrost_key)
        .build()
        .unwrap();
    client
        .execute(request)
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn select_utxo<'a>(
    utxos: &'a [Utxo],
    script_hash: &str,
    min_balance: u64,
) -> (Option<&'a Utxo>, &'a Utxo) {
    let script = utxos
        .iter()
        .find(|u| u.reference_script_hash.as_deref() == Some(script_hash));
    let fee_payer = utxos.iter().find(|u| {
        u.reference_script_hash.is_none()
            && u.amount[0].unit == "lovelace"
            && u.amount[0].quantity.parse::<u64>().unwrap() >= min_balance
    });
    let Some(fee_payer) = fee_payer else {
        panic!("Insufficient funds");
    };
    (script, fee_payer)
}

/// I don't know how exactly this interacts with multiple redeemers or how the ex units would need
/// to be set for that.
async fn eval_execution_units(
    tx: &StagingTransaction,
    input: Input,
    plutus_data: Vec<u8>,
) -> ExUnits {
    let blockfrost_key =
        std::env::var("BLOCKFROST_KEY").expect("No BLOCKFROST_KEY environment variable");

    dbg!(tx);
    // I have not found a better way to do this, yet.
    let tx = tx
        .clone()
        .add_spend_redeemer(input, plutus_data, Some(ExUnits { mem: 0, steps: 0 }))
        .build_conway_raw()
        .unwrap();

    dbg!(hex::encode(&tx.tx_bytes));

    let client = reqwest::Client::new();
    let req = client
        .post(format!("{BLOCKFROST_URL}/utils/txs/evaluate"))
        .header("Content-Type", "application/cbor")
        .header("project_id", blockfrost_key)
        .body(tx.tx_bytes.0)
        .build()
        .unwrap();

    dbg!(&req);
    let res = client.execute(req).await.unwrap().text().await.unwrap();
    eprintln!("{res}");

    todo!()
}

async fn submit_tx(cbor: Vec<u8>) {
    let blockfrost_key =
        std::env::var("BLOCKFROST_KEY").expect("No BLOCKFROST_KEY environment variable");

    let client = reqwest::Client::new();
    let request = client
        .post(format!("{BLOCKFROST_URL}/tx/submit"))
        .header("Content-Type", "application/cbor")
        .header("project_id", blockfrost_key)
        .body(cbor)
        .build()
        .unwrap();

    let res = client.execute(request).await.unwrap().text().await.unwrap();

    // res
    //     .error_for_status()
    //     .unwrap()
    //     .text()
    //     .await
    //     .unwrap();

    println!("{res}");
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use circom_prover::prover::circom::{G1, G2, Proof};
    use num_bigint::BigUint;
    use pallas_primitives::{Fragment, PlutusData};

    use super::*;
    use crate::{
        MAX_VALUE_BYTES,
        prover::{MultiuseProver, ProofWithPubInput},
    };

    // This test is very basic and just checks the output length.
    #[test]
    fn g1_encoding_len() {
        let a = ark_bls12_381::G1Affine::rand(&mut rand::thread_rng());
        let a = G1::from_bls12_381(&a);
        let bytes = super::bls_g1_to_bytes(&a);
        assert_eq!(bytes.len(), 3 * 32);
    }
    #[test]
    fn g2_encoding_len() {
        let a = ark_bls12_381::G2Affine::rand(&mut rand::thread_rng());
        let a = G2::from_bls12_381(&a);
        let bytes = super::bls_g2_to_bytes(&a);
        assert_eq!(bytes.len(), 6 * 32);
    }

    #[test]
    fn redeemer_encoding_roundtrip() {
        let mut pub_input: Vec<BigUint> = Vec::with_capacity(1 + MAX_VALUE_BYTES);
        pub_input.push(1u64.into());
        for i in 0..MAX_VALUE_BYTES {
            pub_input.push(i.into())
        }

        // Doesn't need to be an acruate/working proof, we are only checking encoding.
        let proof = ProofWithPubInput {
            proof: Proof {
                a: G1 {
                    x: 10u64.into(),
                    y: 11u64.into(),
                    z: 12u64.into(),
                },
                b: G2 {
                    x: [20u64.into(), 30u64.into()],
                    y: [21u64.into(), 31u64.into()],
                    z: [22u64.into(), 32u64.into()],
                },
                c: G1 {
                    x: 40u64.into(),
                    y: 41u64.into(),
                    z: 42u64.into(),
                },
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            pub_input,
        };

        let bytes = super::encode_redeemer(&proof);
        dbg!(hex::encode(&bytes));

        // Snippet from pallas-txbuilder `build_conway_raw`
        let data = PlutusData::decode_fragment(bytes.as_ref())
            .expect("Encoding roundtrip should not fail");
        dbg!(data);
    }

    #[tokio::test]
    async fn e2e_minimal() {
        super::deploy("zkey/minimal.eudi2web3_demo.cardano.script").await;

        let mut wtns = Vec::with_capacity(1 + MAX_VALUE_BYTES);
        wtns.push(1.into());
        for i in 0..MAX_VALUE_BYTES {
            wtns.push((65 + i).into());
        }

        let prover = MultiuseProver::new("zkey/minimal.zkey").unwrap();
        let (proof, valid) = prover.prove(wtns).unwrap();
        assert!(valid);

        let tx_hash = super::publish("zkey/minimal.eudi2web3_demo.cardano.script", &proof).await;
        dbg!(tx_hash.encode_hex::<String>());
        // TODO: We may need to check if the txn succeeded.
    }
}
