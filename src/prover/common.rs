use anyhow::Result;
use circom_prover::prover::circom::{G1, G2, Proof};
use num_bigint::BigUint;

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

    #[allow(unused)]
    pub fn from_snarkjs_files(proof_path: &str, pubinput_path: &str) -> Result<Self> {
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
