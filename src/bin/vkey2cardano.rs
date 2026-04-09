//! This is called by the makefile to convert the verification key into a format that aiken
//! blueprint understands, thus allowing us to do parametrization without hard coding the vkey or
//! building the plutus cbor manually.

use hex::ToHex;
use pallas_primitives::{BigInt, Constr, Fragment, Int, MaybeIndefArray, PlutusData};

type G1Hex = [String; 3];
type G2Hex = [[String; 2]; 3];

#[derive(Debug, serde::Deserialize)]
struct SnarkJsVkey {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: u64,
    vk_alpha_1: G1Hex,
    vk_beta_2: G2Hex,
    vk_gamma_2: G2Hex,
    vk_delta_2: G2Hex,
    vk_alphabeta_12: [G2Hex; 2],
    #[serde(rename = "IC")]
    ic: Vec<G1Hex>,
}

fn main() {
    let vkey_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "zkey/sdjwt_es256_sha256_1claim.vkey.json".to_owned());
    let vkey = std::fs::read_to_string(vkey_path).unwrap();
    let vkey: SnarkJsVkey = serde_json::from_str(&vkey).unwrap();

    assert_eq!(vkey.protocol, "groth16");
    assert_eq!(vkey.curve, "bls12381");

    const TAG_CONSTR_0: u64 = 121;

    let pdata = PlutusData::Constr(Constr {
        tag: TAG_CONSTR_0,
        any_constructor: None,
        fields: MaybeIndefArray::Def(vec![
            PlutusData::BigInt(BigInt::Int(Int(vkey.n_public.into()))),
            PlutusData::BoundedBytes(g1hex2bytes(&vkey.vk_alpha_1).into()),
            PlutusData::BoundedBytes(g2hex2bytes(&vkey.vk_beta_2).into()),
            PlutusData::BoundedBytes(g2hex2bytes(&vkey.vk_gamma_2).into()),
            PlutusData::BoundedBytes(g2hex2bytes(&vkey.vk_delta_2).into()),
            PlutusData::Array(MaybeIndefArray::Def(vec![
                PlutusData::BoundedBytes(g2hex2bytes(&vkey.vk_alphabeta_12[0]).into()),
                PlutusData::BoundedBytes(g2hex2bytes(&vkey.vk_alphabeta_12[1]).into()),
            ])),
            PlutusData::Array(MaybeIndefArray::Def(
                vkey.ic
                    .iter()
                    .map(|e| PlutusData::BoundedBytes(g1hex2bytes(e).into()))
                    .collect(),
            )),
        ]),
    });

    let pdata = pdata.encode_fragment().unwrap();

    // Format for cunsumption by `aiken blueprint apply`
    let pdata: String = pdata.encode_hex();
    println!("{pdata}");
}

fn g1hex2bytes(a: &G1Hex) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 * 32);
    push_u256hex_be(&mut out, &a[0]);
    push_u256hex_be(&mut out, &a[1]);
    push_u256hex_be(&mut out, &a[2]);
    out
}

fn g2hex2bytes(a: &G2Hex) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 * 32);
    push_u256hex_be(&mut out, &a[0][0]);
    push_u256hex_be(&mut out, &a[0][1]);
    push_u256hex_be(&mut out, &a[1][0]);
    push_u256hex_be(&mut out, &a[1][1]);
    push_u256hex_be(&mut out, &a[2][0]);
    push_u256hex_be(&mut out, &a[2][1]);
    out
}

fn push_u256hex_be(out: &mut Vec<u8>, s: &str) {
    let v = hex::decode(s).unwrap();
    assert!(v.len() <= 32);
    for _ in v.len()..32 {
        out.push(0);
    }
    out.extend(v);
}

// // Alternative implementation we likely don't need (if the contract accepts normalized
// // projective points).
// fn g1hex2bytes(a: &G1Hex) -> Vec<u8> {
//     // Format: x, y, infinity
//     let x = ark_bls12_381::Fq::from_be_bytes_mod_order(&hex::decode(&a[0]).unwrap());
//     let y = ark_bls12_381::Fq::from_be_bytes_mod_order(&hex::decode(&a[1]).unwrap());
//     debug_assert_eq!(a[2].len(), 1);
//
//     let a = ark_bls12_381::G1Affine {
//         x,
//         y,
//         infinity: a[2] == "1",
//     };
//     let a: ark_bls12_381::G1Projective = a.into();
//     let mut bytes = Vec::with_capacity(3 * 32);
//     a.serialize_uncompressed(&mut bytes).unwrap();
//     debug_assert_eq!(bytes.len(), 3 * 32);
//     bytes
// }
//
// fn g2hex2bytes(a: &G2Hex) -> Vec<u8> {
//     let x = ark_bls12_381::Fq::from_be_bytes_mod_order(&hex::decode(&a[0]).unwrap());
//     let y = ark_bls12_381::Fq::from_be_bytes_mod_order(&hex::decode(&a[1]).unwrap());
//
//     let mut out = Vec::with_capacity(6 * 32);
//     push_u256hex_be(&mut out, &a[0][0]);
//     push_u256hex_be(&mut out, &a[0][1]);
//     push_u256hex_be(&mut out, &a[1][0]);
//     push_u256hex_be(&mut out, &a[1][1]);
//     push_u256hex_be(&mut out, &a[2][0]);
//     push_u256hex_be(&mut out, &a[2][1]);
//     out
// }
