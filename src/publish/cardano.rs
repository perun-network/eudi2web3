use circom_prover::prover::circom::{G1, G2};
use hex::{FromHex, ToHex};
use num_traits::Zero;
use pallas_addresses::{ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_primitives::{Constr, Fragment, MaybeIndefArray, NetworkId, PlutusData};
use pallas_txbuilder::{
    BuildConway, ExUnits, Input, Output, ScriptKind::PlutusV3, StagingTransaction,
};
use pallas_wallet::PrivateKey;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::{MAX_VALUE_BYTES, prover::ProofWithPubInput};

const BLOCKFROST_URL: &str = "https://cardano-preview.blockfrost.io/api/v0";

// TODO: This file contains a bunch of methods using unwrap instead of having proper error
// forwarding or retries.

pub async fn deploy(path: &str) {
    // Could be loaded once in the beginning and reused.
    let addr = tokio::fs::read_to_string("me.addr").await.unwrap();
    let (script_bytes, _, script_addr) = script_bytecode(path).await;

    let fee = 400_000;
    let min_balance = 20_000_000;
    let locked = 900_000;

    let script_utxos = get_utxos(&script_addr.to_bech32().unwrap()).await;
    if script_utxos.len() >= 1 {
        eprintln!("Script already deployed, doing nothing");
        return;
    }

    // Use the first UTXO we have as input
    let utxos = get_utxos(&addr).await;
    let input = select_utxo(&utxos, min_balance + fee);

    let addr = pallas_addresses::Address::from_bech32(&addr).unwrap();

    let tx = StagingTransaction::new()
        .network_id(NetworkId::Testnet.into())
        .input(input.to_input())
        .output(Output::new(
            addr.clone(),
            input.lovelace_balance() - fee - min_balance - locked,
        ))
        .output(
            Output::new(script_addr.clone(), min_balance)
                .set_inline_script(PlutusV3, script_bytes)
                .set_inline_datum(vec![0xd8, 0x79, 0x80]), // Constr 0, empty array
        )
        .output(
            Output::new(script_addr, locked).set_inline_datum(vec![0xd8, 0x79, 0x80]), // Constr 0, empty array
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
    let (script_bytes, _, script_addr) = script_bytecode(script_path).await;

    dbg!(&script_addr);
    dbg!(script_addr.to_bech32().unwrap());

    // Build inputs

    let fee = 600_000; // 436253
    let min_balance = 4_000_000;

    let utxos = get_utxos(&addr).await;
    let input_fees = select_utxo(&utxos, fee + min_balance);

    let script_utxos = get_utxos(&script_addr.to_bech32().unwrap()).await;
    dbg!(&script_utxos);
    let script_ref = script_utxos
        .iter()
        .find(|u| u.reference_script_hash.is_some())
        .expect("Not deployed");
    let script_locked = script_utxos
        .iter()
        .find(|u| u.reference_script_hash.is_none())
        .unwrap();

    dbg!(&script_ref, &script_locked, input_fees);

    let addr = pallas_addresses::Address::from_bech32(&addr).unwrap();

    let cost_model = get_cost_model_plutusv3().await;

    // Build transaction
    let tx = StagingTransaction::new()
        .network_id(NetworkId::Testnet.into())
        // .reference_input(script_ref.to_input())
        .script(PlutusV3, script_bytes)
        .input(script_locked.to_input())
        .input(input_fees.to_input())
        .collateral_input(input_fees.to_input())
        .output(Output::new(
            addr.clone(),
            input_fees.lovelace_balance() - fee,
        ))
        .output(
            Output::new(script_addr, script_locked.lovelace_balance())
                .set_inline_datum(vec![0xd8, 0x79, 0x80]),
        )
        .language_view(PlutusV3, cost_model)
        .fee(fee);
    dbg!(&tx.inputs);
    dbg!(script_locked.to_input());
    let ex_units = eval_execution_units(&tx, script_locked.to_input(), redeemer.clone()).await;
    let tx = tx
        .add_spend_redeemer(script_locked.to_input(), redeemer, Some(ex_units))
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
    let mut claim_value: Vec<u8> = claim_value
        .iter()
        .map(|x| {
            assert!(*x <= u8::MAX.into());
            let digits = x.to_u64_digits();
            let x = digits.first().copied().unwrap_or(0);
            assert!(x <= u8::MAX as u64);
            x as u8
        })
        .collect();

    // Intentionally invalidate proof for testing
    claim_value[30] = 0x42;

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

fn bls_g1_to_bytes(a: &G1) -> Vec<u8> {
    // There might be pre-build methods for this since we already have it as G1, but I could not
    // find them, so I'm implementing the encoding myself (as done for vkey in deployment).
    let infinity = a.x.is_zero() && a.y.is_zero();

    if infinity {
        let mut out = vec![0xc0];
        out.resize(48, 0);
        out
    } else {
        let mut out = a.x.to_bytes_le();

        assert!(out.len() <= 48);
        out.resize(48, 0);
        out.reverse();
        assert!(out[0] < 32, "upper 3 bits of x coordinate should be 0");
        out[0] |= 0x80; // Always in compressed form.

        let a = a.clone().to_bls12_381();

        let is_larger_y = a.y > -a.y;
        if is_larger_y {
            out[0] |= 0x20;
        }

        out
    }
}
fn bls_g2_to_bytes(a: &G2) -> Vec<u8> {
    let infinity = a.x[0].is_zero() && a.x[1].is_zero() && a.y[0].is_zero() && a.y[1].is_zero();

    if infinity {
        let mut out = vec![0xc0];
        out.resize(96, 0);
        out
    } else {
        let mut out = a.x[1].to_bytes_le();
        assert!(out.len() <= 48);
        out.resize(48, 0);
        out.reverse();
        assert!(out[0] < 32, "upper 3 bits of x coordinate should be 0");

        let mut x0 = a.x[0].to_bytes_le();
        assert!(x0.len() <= 48);
        x0.resize(48, 0);
        x0.reverse();
        assert!(x0[0] < 32, "upper 3 bits of x coordinate should be 0");

        out.extend(x0);

        out[0] |= 0x80; // Always in compressed form.

        let a = a.clone().to_bls12_381();

        let is_larger_y = a.y > -a.y;
        if is_larger_y {
            out[0] |= 0x20;
        }

        out
    }
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
async fn script_bytecode(path: &str) -> (Vec<u8>, [u8; 28], pallas_addresses::Address) {
    let json = tokio::fs::read_to_string(path).await.unwrap();
    let plutus_json: PlutusJson = serde_json::from_str(&json).unwrap();
    let data = plutus_json.validators.into_iter().next().unwrap();
    let script = hex::decode(&data.compiled_code).expect("invalid hex");
    let hash = <[u8; 28]>::from_hex(&data.hash).unwrap();

    let addr = ShelleyAddress::new(
        pallas_addresses::Network::Testnet,
        ShelleyPaymentPart::Script(hash.into()),
        ShelleyDelegationPart::Null,
    );
    let addr = pallas_addresses::Address::Shelley(addr);

    (script, hash, addr)
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

#[derive(Debug, Deserialize)]
struct Utxo {
    // There are more fields, but for now we just need these.
    tx_hash: String,
    tx_index: u64,
    amount: Vec<BalanceEntry>,
    reference_script_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
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
    let res = client.execute(request).await.unwrap();
    match res.status() {
        StatusCode::NOT_FOUND => vec![],
        StatusCode::OK => res.json().await.unwrap(),
        _ => todo!("Unexpected status code: {res:?}"),
    }
}

fn select_utxo<'a>(utxos: &'a [Utxo], min_balance: u64) -> &'a Utxo {
    let fee_payer = utxos.iter().find(|u| {
        u.amount[0].unit == "lovelace"
            && u.amount[0].quantity.parse::<u64>().unwrap() >= min_balance
    });
    let Some(fee_payer) = fee_payer else {
        panic!("Insufficient funds");
    };
    fee_payer
}

#[derive(Debug, Deserialize)]
struct EpochProtocolParams {
    cost_models_raw: CostModelsRaw,
}
#[derive(Debug, Deserialize)]
struct CostModelsRaw {
    #[serde(rename = "PlutusV3")]
    plutus_v3: Vec<i64>,
}

async fn get_cost_model_plutusv3() -> Vec<i64> {
    let blockfrost_key =
        std::env::var("BLOCKFROST_KEY").expect("No BLOCKFROST_KEY environment variable");

    let client = reqwest::Client::new();
    let req = client
        .get(format!("{BLOCKFROST_URL}/epochs/latest/parameters"))
        .header("project_id", blockfrost_key)
        .build()
        .unwrap();
    let res: EpochProtocolParams = client
        .execute(req)
        .await
        .expect("Could not send request")
        .error_for_status()
        .expect("Server returned unexpected status code")
        .json()
        .await
        .expect("Response could not be decoded into struct");

    res.cost_models_raw.plutus_v3
}

#[derive(Debug, Deserialize)]
struct EvalResult {
    result: EvalResult2,
}
#[derive(Debug, Deserialize)]
struct EvalResult2 {
    #[serde(rename = "EvaluationResult")]
    evaluation_result: EvalResult3,
}
#[derive(Debug, Deserialize)]
struct EvalResult3 {
    #[serde(rename = "spend:0", alias = "spend:1")]
    spend_1: EvalResult4,
}
#[derive(Debug, Deserialize)]
struct EvalResult4 {
    memory: u64,
    steps: u64,
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

    // I have not found a better way to do this, yet.
    let tx = tx
        .clone()
        .add_spend_redeemer(input, plutus_data, Some(ExUnits { mem: 1, steps: 1 }))
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

    let res: EvalResult = serde_json::from_str(&res).unwrap();
    let res = res.result.evaluation_result.spend_1;
    ExUnits {
        mem: res.memory,
        steps: res.steps,
    }
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

    #[test]
    fn redeemer_encoding_roundtrip() {
        let mut pub_input: Vec<BigUint> = Vec::with_capacity(1 + MAX_VALUE_BYTES);
        pub_input.push(1u64.into());
        for i in 0..MAX_VALUE_BYTES {
            pub_input.push(i.into())
        }

        let rng = &mut rand::thread_rng();

        // Doesn't need to be an acruate/working proof, we are only checking encoding.
        let proof = ProofWithPubInput {
            proof: Proof {
                a: G1::from_bls12_381(&ark_bls12_381::G1Affine::rand(rng)),
                b: G2::from_bls12_381(&ark_bls12_381::G2Affine::rand(rng)),
                c: G1::from_bls12_381(&ark_bls12_381::G1Affine::rand(rng)),
                protocol: "groth16".to_owned(),
                curve: "bls12381".to_owned(),
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
    #[cfg_attr(not(all(feature = "cardano-tests")), ignore = "-F cardano-tests")]
    async fn e2e_minimal() {
        super::deploy("zkey/bls12-381/minimal.cardano.json").await;

        let mut wtns = Vec::with_capacity(1 + MAX_VALUE_BYTES);
        wtns.push(1.into());
        for i in 0..MAX_VALUE_BYTES {
            wtns.push((65 + i).into());
        }

        let prover = MultiuseProver::new("zkey/bls12-381/minimal.zkey").unwrap();
        let (proof, valid) = prover.prove(wtns).unwrap();
        assert!(valid);

        let tx_hash = super::publish("zkey/bls12-381/minimal.cardano.json", &proof).await;
        dbg!(tx_hash.encode_hex::<String>());
        // TODO: We may need to check if the txn succeeded.
    }

    #[test]
    fn generator_encoding_g1() {
        // See https://cips.cardano.org/cip/CIP-0381#names-and-typeskinds-for-the-new-functions-or-types
        let bytes = super::bls_g1_to_bytes(&G1::from_bls12_381(&ark_bls12_381::G1Affine::new(
            ark_bls12_381::g1::G1_GENERATOR_X,
            ark_bls12_381::g1::G1_GENERATOR_Y,
        )));
        let expected: [u8; 48] = [
            151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104,
            140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249,
            122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187,
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn generator_encoding_g2() {
        // See https://cips.cardano.org/cip/CIP-0381#names-and-typeskinds-for-the-new-functions-or-types
        let bytes = super::bls_g2_to_bytes(&G2::from_bls12_381(&ark_bls12_381::G2Affine::new(
            ark_bls12_381::Fq2::new(
                ark_bls12_381::g2::G2_GENERATOR_X_C0,
                ark_bls12_381::g2::G2_GENERATOR_X_C1,
            ),
            ark_bls12_381::Fq2::new(
                ark_bls12_381::g2::G2_GENERATOR_Y_C0,
                ark_bls12_381::g2::G2_GENERATOR_Y_C1,
            ),
        )));
        let expected: [u8; 96] = [
            147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208,
            208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148,
            93, 87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5,
            39, 45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227,
            209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184,
        ];
        assert_eq!(bytes, expected);
    }
}
