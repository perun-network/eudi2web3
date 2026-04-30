use std::{io::Write, path::Path};

use anyhow::Result;
use circom_prover::prover::circom::{G1, G2, Proof};
use num_bigint::{BigInt, BigUint};
use wtns_file::WtnsFile;

#[derive(Debug)]
pub struct ProofWithPubInput {
    pub proof: Proof,
    pub pub_input: Vec<BigUint>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SnarkjsProof {
    pub protocol: String,
    pub curve: String,
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

impl ProofWithPubInput {
    pub fn to_snarkjs_pubinput(&self) -> Vec<String> {
        self.pub_input
            .iter()
            .skip(1)
            .map(|v| v.to_string())
            .collect()
    }

    pub fn from_snarkjs_files(
        proof_path: impl AsRef<Path>,
        pubinput_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let f = std::fs::File::open(proof_path)?;
        let proof: SnarkjsProof = serde_json::from_reader(f)?;

        let f = std::fs::File::open(pubinput_path)?;
        let pubinput: Vec<String> = serde_json::from_reader(f)?;

        Ok(Self {
            proof: Proof {
                a: G1 {
                    x: proof.pi_a[0].parse().unwrap(),
                    y: proof.pi_a[1].parse().unwrap(),
                    z: proof.pi_a[2].parse().unwrap(),
                },
                b: G2 {
                    x: [
                        proof.pi_b[0][0].parse().unwrap(),
                        proof.pi_b[0][1].parse().unwrap(),
                    ],
                    y: [
                        proof.pi_b[1][0].parse().unwrap(),
                        proof.pi_b[1][1].parse().unwrap(),
                    ],
                    z: [
                        proof.pi_b[2][0].parse().unwrap(),
                        proof.pi_b[2][1].parse().unwrap(),
                    ],
                },
                c: G1 {
                    x: proof.pi_c[0].parse().unwrap(),
                    y: proof.pi_c[1].parse().unwrap(),
                    z: proof.pi_c[2].parse().unwrap(),
                },
                protocol: proof.protocol,
                curve: proof.curve,
            },
            pub_input: [1u64.into()]
                .into_iter()
                .chain(pubinput.into_iter().map(|s| s.parse().unwrap()))
                .collect(),
        })
    }
}

impl<'a> From<&'a ProofWithPubInput> for SnarkjsProof {
    fn from(value: &'a ProofWithPubInput) -> Self {
        SnarkjsProof {
            protocol: value.proof.protocol.clone(),
            curve: value.proof.curve.clone(),
            pi_a: vec![
                value.proof.a.x.to_string(),
                value.proof.a.y.to_string(),
                value.proof.a.z.to_string(),
            ],
            pi_b: vec![
                vec![
                    value.proof.b.x[0].to_string(),
                    value.proof.b.x[1].to_string(),
                ],
                vec![
                    value.proof.b.y[0].to_string(),
                    value.proof.b.y[1].to_string(),
                ],
                vec![
                    value.proof.b.z[0].to_string(),
                    value.proof.b.z[1].to_string(),
                ],
            ],
            pi_c: vec![
                value.proof.c.x.to_string(),
                value.proof.c.y.to_string(),
                value.proof.c.z.to_string(),
            ],
        }
    }
}

pub fn write_wtns_file(curve: &str, wit: &[BigInt], path: impl AsRef<Path>) -> Result<()> {
    let (prime_dec, field_size) = match curve {
        // https://docs.rs/ark-bn254/latest/ark_bn254/
        "bn254" => (
            b"21888242871839275222246405745257275088696311157297823662689037894645226208583"
                .as_slice(),
            32,
        ),
        // https://docs.rs/ark-bls12-381/latest/ark_bls12_381/
        "bls12381" | "bls12-381" => (
            b"52435875175126190479447740508185965837690552500527637822603658699938581184513"
                .as_slice(),
            48,
        ),
        _ => panic!("Unknown curve: {curve}"),
    };
    let prime = BigInt::parse_bytes(prime_dec, 10).unwrap();
    let (sign, mut prime) = prime.to_bytes_le();
    assert_ne!(sign, num_bigint::Sign::Minus);
    prime.resize(32, 0);
    let prime: [u8; 32] = prime.try_into().unwrap();
    let wtns_file = WtnsFile {
        version: 2,
        header: wtns_file::Header {
            field_size,
            prime: prime.into(),
            witness_len: wit.len() as u32,
        },
        witness: wtns_file::Witness(
            wit.iter()
                .map(|v| {
                    let (sign, mut v) = v.to_bytes_le();
                    assert_ne!(sign, num_bigint::Sign::Minus);
                    v.resize(32, 0);
                    let v: [u8; 32] = v.try_into().unwrap();
                    v.into()
                })
                .collect(),
        ),
    };
    let mut f = std::fs::File::create(path)?;
    wtns_file.write(&mut f)?;
    f.flush()?;
    drop(f);
    Ok(())
}
