use circom_prover::prover::circom::{G1, G2};
use hex::ToHex;
use pallas_primitives::{Constr, Fragment, MaybeIndefArray, NetworkId, PlutusData};
use pallas_txbuilder::{BuildConway, Input, Output, ScriptKind::PlutusV3, StagingTransaction};
use pallas_wallet::PrivateKey;
use serde::Deserialize;

use crate::{MAX_VALUE_BYTES, prover::ProofWithPubInput};

const BLOCKFROST_URL: &str = "https://cardano-preview.blockfrost.io/api/v0";

pub async fn deploy() {
    // Could be loaded once in the beginning and reused.
    let addr = tokio::fs::read_to_string("me.addr").await.unwrap();
    let (script_bytes, script_hash) = script_bytecode().await;

    let fee = 200_000;
    let min_balance = 4_000_000;

    // Use the first UTXO we have as input
    let utxos = get_utxos(&addr).await;
    let input = select_utxo_deployment(&utxos, &script_hash, 2 * min_balance + fee);
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

// Returns the transaction hash
pub async fn publish(proof: &ProofWithPubInput) -> [u8; 32] {
    // Could be loaded once in the beginning and reused.
    let addr = tokio::fs::read_to_string("me.addr").await.unwrap();
    let (script_bytes, script_hash) = script_bytecode().await;

    // Prepare data
    let claim_value = &proof.pub_input[1..1 + MAX_VALUE_BYTES];
    let claim_value: Vec<u8> = claim_value
        .iter()
        .map(|x| {
            let digits = x.to_u64_digits();
            assert_eq!(digits.len(), 1);
            assert!(digits[0] <= u8::MAX as u64);
            x.to_u64_digits()[0] as u8
        })
        .collect();

    // Build inputs
    let redeemer = PlutusData::Constr(Constr {
        tag: 0,
        any_constructor: None,
        fields: MaybeIndefArray::Def(vec![
            PlutusData::Constr(Constr {
                tag: 0,
                any_constructor: None,
                fields: MaybeIndefArray::Def(vec![
                    PlutusData::BoundedBytes(g1_to_bytes(&proof.proof.a).into()),
                    PlutusData::BoundedBytes(g2_to_bytes(&proof.proof.b).into()),
                    PlutusData::BoundedBytes(g1_to_bytes(&proof.proof.c).into()),
                ]),
            }),
            PlutusData::BoundedBytes(claim_value.into()),
        ]),
    });
    let redeemer = redeemer.encode_fragment().unwrap();

    let fee = 200_000;
    let min_balance = 4_000_000;

    // Use the first UTXO we have as input
    let utxos = get_utxos(&addr).await;
    let (input_script, input_fees) = select_utxo_publish(&utxos, &script_hash, fee + min_balance);
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
        .add_spend_redeemer(input_script.to_input(), redeemer, None)
        .fee(fee)
        .build_conway_raw()
        .unwrap();

    let sk = read_sk().await;
    // Sign changes tx.tx_bytes (adding the signature)
    let tx = tx.sign(sk).unwrap();

    dbg!(tx.tx_bytes.encode_hex::<String>());

    submit_tx(tx.tx_bytes.0).await;

    tx.tx_hash.0
}

// TODO: I'm not sure if these are in the correct order. We will find out if the proof doesn't
// verify.
fn g1_to_bytes(a: &G1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(3 * 32);
    bytes.extend(a.x.to_bytes_be());
    bytes.extend(a.y.to_bytes_be());
    bytes.extend(a.z.to_bytes_be());
    bytes
}
fn g2_to_bytes(a: &G2) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6 * 32);
    bytes.extend(a.x[0].to_bytes_be());
    bytes.extend(a.x[1].to_bytes_be());
    bytes.extend(a.y[0].to_bytes_be());
    bytes.extend(a.y[1].to_bytes_be());
    bytes.extend(a.z[0].to_bytes_be());
    bytes.extend(a.z[1].to_bytes_be());
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
async fn script_bytecode() -> (Vec<u8>, String) {
    let json = tokio::fs::read_to_string("verifier/cardano/plutus.json")
        .await
        .unwrap();
    let plutus_json: PlutusJson = serde_json::from_str(&json).unwrap();
    let data = plutus_json.validators.into_iter().next().unwrap();
    let script = hex::decode(&data.compiled_code).expect("invalid hex");

    (script, data.hash)
}

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
            if e.unit == "locelace" {
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

fn select_utxo_deployment<'a>(utxos: &'a [Utxo], script_hash: &str, min_balance: u64) -> &'a Utxo {
    // First check if it is already deployed and abort if it is.
    let deployed = utxos
        .iter()
        .find(|u| u.reference_script_hash.as_deref() == Some(script_hash));
    assert!(
        deployed.is_none(),
        "Account already has a UTXO with the script"
    );

    // Otherwise take utxos without a script until we have the desired balance.
    for u in utxos {
        assert_eq!(
            u.amount.len(),
            1,
            "Our code currently doesn't support utxos with multiple currencies"
        );
        if u.amount[0].unit != "lovelace" {
            continue;
        }
        if u.reference_script_hash.is_some() {
            continue;
        }
        if u.amount[0].quantity.parse::<u64>().unwrap() > min_balance {
            return u;
        }
    }
    panic!("Insufficient funds")
}

fn select_utxo_publish<'a>(
    utxos: &'a [Utxo],
    script_hash: &str,
    min_balance: u64,
) -> (&'a Utxo, &'a Utxo) {
    let mut script = None;
    let mut fee_payer;

    for u in utxos {
        if u.reference_script_hash.as_deref() == Some(script_hash) {
            script = Some(u);
            continue;
        }
        if u.amount.len() == 0 {
            continue;
        }
        if u.amount[0].unit != "lovelace" {
            continue;
        }
        if u.amount[0].quantity.parse::<u64>().unwrap() < min_balance {
            continue;
        }
        fee_payer = Some(u);
        let Some(script) = script else {
            continue;
        };
        let Some(fee_payer) = fee_payer else {
            continue;
        };
        return (script, fee_payer);
    }
    if script.is_none() {
        panic!("Script not found")
    }
    panic!("Insufficient funds")
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
