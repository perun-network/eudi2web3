//! This is called by the makefile to convert the verification key into a format that aiken
//! blueprint understands, thus allowing us to do parametrization without hard coding the vkey or
//! building the plutus cbor manually.

use ark_ff::{BigInteger384, Zero};
use hex::ToHex;
use num_bigint::BigUint;
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
    let vkey_path = std::env::args().nth(1).unwrap();
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
            PlutusData::BoundedBytes(g1hex2bytes(vkey.vk_alpha_1).into()),
            PlutusData::BoundedBytes(g2hex2bytes(vkey.vk_beta_2).into()),
            PlutusData::BoundedBytes(g2hex2bytes(vkey.vk_gamma_2).into()),
            PlutusData::BoundedBytes(g2hex2bytes(vkey.vk_delta_2).into()),
            PlutusData::Array(MaybeIndefArray::Def(
                vkey.vk_alphabeta_12
                    .into_iter()
                    .map(|v| PlutusData::BoundedBytes(g2hex2bytes(v).into()))
                    .collect(),
            )),
            PlutusData::Array(MaybeIndefArray::Def(
                vkey.ic
                    .into_iter()
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

// See https://cips.cardano.org/cip/CIP-0381#names-and-typeskinds-for-the-new-functions-or-types
// See https://github.com/supranational/blst#serialization-format
fn g1hex2bytes(a: G1Hex) -> Vec<u8> {
    // Input contains decimal (base 10) of a 48-byte number (381/384 bits)
    let x: BigUint = a[0].parse().unwrap();
    let y: BigUint = a[1].parse().unwrap();
    let infinity = x.is_zero() && y.is_zero();

    if infinity {
        let mut out = vec![0xc0];
        out.resize(48, 0);
        out
    } else {
        let mut out = x.to_bytes_le();

        assert!(out.len() <= 48);
        out.resize(48, 0);
        out.reverse();
        assert!(out[0] < 32, "upper 3 bits of x coordinate should be 0");
        out[0] |= 0x80; // Always in compressed form.

        let mut y = y.to_u64_digits();
        debug_assert!(y.len() <= 6);
        y.resize(6, 0);
        let y: [u64; 6] = y.try_into().unwrap();
        let y = ark_bls12_381::Fq::new(BigInteger384::new(y));

        let is_larger_y = y > -y;
        if is_larger_y {
            out[0] |= 0x20;
        }
        out
    }
}

fn g2hex2bytes(a: G2Hex) -> Vec<u8> {
    // Basically the same as G1, but not with individual flags. Only the first 3 bits store the
    // flags and y comparison must be on the G2 point, not two G1 points.
    let x0: BigUint = a[0][0].parse().unwrap();
    let x1: BigUint = a[0][1].parse().unwrap();
    let y0: BigUint = a[1][0].parse().unwrap();
    let y1: BigUint = a[1][1].parse().unwrap();
    let infinity = x0.is_zero() && x1.is_zero() && y0.is_zero() && y1.is_zero();

    if infinity {
        let mut out = vec![0xc0];
        out.resize(96, 0);
        out
    } else {
        let mut out = x1.to_bytes_le();
        assert!(out.len() <= 48);
        out.resize(48, 0);
        out.reverse();
        assert!(out[0] < 32, "upper 3 bits of x coordinate should be 0");

        let mut x0 = x0.to_bytes_le();
        assert!(x0.len() <= 48);
        x0.resize(48, 0);
        x0.reverse();
        assert!(x0[0] < 32, "upper 3 bits of x coordinate should be 0");

        out.extend(x0);

        out[0] |= 0x80; // Always in compressed form.

        let mut y0 = y0.to_u64_digits();
        let mut y1 = y1.to_u64_digits();
        debug_assert!(y0.len() <= 6);
        debug_assert!(y1.len() <= 6);
        y0.resize(6, 0);
        y1.resize(6, 0);
        let y0: [u64; 6] = y0.try_into().unwrap();
        let y1: [u64; 6] = y1.try_into().unwrap();
        let y0 = ark_bls12_381::Fq::new(BigInteger384::new(y0));
        let y1 = ark_bls12_381::Fq::new(BigInteger384::new(y1));
        let y = ark_bls12_381::Fq2::new(y0, y1);

        let is_larger_y = y > -y;
        if is_larger_y {
            out[0] |= 0x20;
        }
        out
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn generator_encoding_g1() {
        // See https://cips.cardano.org/cip/CIP-0381#names-and-typeskinds-for-the-new-functions-or-types
        let bytes = super::g1hex2bytes([
            ark_bls12_381::g1::G1_GENERATOR_X.to_string(),
            ark_bls12_381::g1::G1_GENERATOR_Y.to_string(),
            "1".to_owned(),
        ]);
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
        let bytes = super::g2hex2bytes([
            [
                ark_bls12_381::g2::G2_GENERATOR_X_C0.to_string(),
                ark_bls12_381::g2::G2_GENERATOR_X_C1.to_string(),
            ],
            [
                ark_bls12_381::g2::G2_GENERATOR_Y_C0.to_string(),
                ark_bls12_381::g2::G2_GENERATOR_Y_C1.to_string(),
            ],
            ["1".to_owned(), "1".to_owned()],
        ]);
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
