use std::fs::File;

use anyhow::{Result, anyhow};
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField as _, UniformRand as _};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use circom_prover::prover::{
    CircomProof, ProofLib,
    ark_circom::{CircomReduction, ZkeyHeaderReader, read_zkey},
    circom::{G1, G2, Proof},
};
use num_bigint::{BigInt, BigUint};
use rand::thread_rng;

// Generated code to go from input to witness.
mod witness {
    rust_witness::witness!(dlpexample);
}

// We want to run proof generation multiple times. Simply calling CircomProver not only forces
// us into passing the input json encoded, it also reads the ZKey file once per proof which
// isn't ideal. This is why I pulled out the relevant functionality. `generate_circom_proof`
// also expects an owned string for the zkey path for no apparent reason.
// Simply calling `CircomProver::prove` would be easier, but this should be better/more
// performant when creating multiple proofs.
//
// The implementation provided by circom-prover also spawns a separate thread for generating the
// witness, which does not really make sense as it does nothing in paralell besides reading the
// ZKey, which can be done once in the beginning as shown here.
pub struct MultiuseProver<'a> {
    zkey: PKey,
    pub zkey_path: &'a str,
}

enum PKey {
    Bn256(ProvingKey<Bn254>, ConstraintMatrices<ark_bn254::Fr>),
    Bls12_381(ProvingKey<Bls12_381>, ConstraintMatrices<ark_bls12_381::Fr>),
}

#[derive(Debug)]
pub struct ProofWithPubInput {
    pub proof: Proof,
    pub pub_input: Vec<BigUint>,
}

impl<'z> MultiuseProver<'z> {
    pub fn new(zkey_path: &'z str) -> Result<Self> {
        // First: Figure out which key we need. For some reason circom-prover doesn't use an enum
        // and doesn't do this for us.
        // It is a bit odd to open the file twice, but that seems to be the easiest way and is what
        // circom-prover does, too.
        let mut header = ZkeyHeaderReader::new(zkey_path);
        header.read(); // Annoyingly this panicks and doesn't have a try variant.
        let file = File::open(zkey_path)?;
        let mut reader = std::io::BufReader::new(file);

        let zkey = if header.r == BigUint::from(ark_bn254::Fr::MODULUS) {
            dbg!("BN254");
            let x = read_zkey::<_, Bn254>(&mut reader)?;
            PKey::Bn256(x.0, x.1)
        } else if header.r == BigUint::from(ark_bls12_381::Fr::MODULUS) {
            dbg!("BLS12-381");
            let x = read_zkey::<_, Bls12_381>(&mut reader)?;
            PKey::Bls12_381(x.0, x.1)
        } else {
            return Err(anyhow!("Unexpected curve in zkey"));
        };

        Ok(Self { zkey, zkey_path })
    }

    pub fn verify(&self, proof: &ProofWithPubInput) -> Result<bool> {
        // Verify the proof so we know it is actually useful/correct
        circom_prover::CircomProver::verify(
            circom_prover::prover::ProofLib::Arkworks,
            circom_prover::prover::CircomProof {
                proof: proof.proof.clone(),
                pub_inputs: circom_prover::prover::PublicInputs(proof.pub_input[1..].to_vec()),
            },
            self.zkey_path.to_owned(),
        )
    }

    pub fn prove(&self, witness: Vec<BigInt>) -> Result<(ProofWithPubInput, bool)> {
        let proof = self.prove_noverify(witness)?;
        let valid = self.verify(&proof)?;

        Ok((proof, valid))
    }

    pub fn prove_noverify(&self, witness: Vec<BigInt>) -> Result<ProofWithPubInput> {
        // PERFORMANCE: This does mean we take up a bit more peak memory:
        //     public input, witness, transformed witness
        // but less memory during proof generation:
        //     public input, transformed witness
        // If we'd keep witness and take out the public input in the end we would need:
        //     witness, transformed witness
        //
        // This way we use slightly more peak memory (during the transformation) but quite a bit
        // less over the duration of proof generation because public input tends to be smaller than
        // witness.
        //
        // For some reason, circom-prover keeps all 3 around until the proof is finished. Unless
        // the compiler manages to drop `witness` early. They also convert the ScalarField values
        // back into a BigUint instead of taking what they already have.
        let pub_input: Vec<BigUint> = witness
            .iter()
            .take(self.zkey.num_instance_variables())
            .map(|w| w.to_biguint().expect("witness entries should be positive"))
            .collect();

        let proof = self.zkey.prove_arkworks(witness)?;

        // circom_prover::CircomProver::prove(proof_lib, wit_fn, json_input_str, zkey_path)
        Ok(ProofWithPubInput { proof, pub_input })
    }

    // I'd love to allow &str for keys, but the to_witness functions expect owned Strings. Even
    // though that's not strictly neccessary. The circom-prover implementation goes through even
    // more steps, json deserialization and multiple allocations to achieve the same (if
    // RustWitness is used.)
    pub fn prove2_noverify<I>(
        &self,
        to_witness: impl FnOnce(I) -> Vec<BigInt>,
        input: I,
    ) -> Result<ProofWithPubInput>
    where
        I: IntoIterator<Item = (String, Vec<BigInt>)>,
    {
        let witness: Vec<BigInt> = to_witness(input);
        self.prove_noverify(witness)
    }
}

impl PKey {
    fn num_instance_variables(&self) -> usize {
        match self {
            PKey::Bn256(_, m) => m.num_instance_variables,
            PKey::Bls12_381(_, m) => m.num_instance_variables,
        }
    }

    // We could accept a witness slice here, as we need to map over it anyways to convert it to SF
    // values (curve dependent). But that's likely not beneficial. Doing that would mean this
    // entire witness Vec lives until the entire proof was created, taking up memory. Instead we
    // take an owned value and (hopefully) drop it early, freeing up the relevant memory.
    fn prove_arkworks(&self, witness: Vec<BigInt>) -> Result<Proof> {
        let proof = match self {
            PKey::Bn256(pkey, matrices) => {
                Self::prove_arkworks_inner(pkey, matrices, witness)?.into()
            }
            PKey::Bls12_381(pkey, matrices) => {
                Self::prove_arkworks_inner(pkey, matrices, witness)?.into()
            }
        };
        Ok(proof)
    }

    // Mostly copied from circom-prover::prover::arkworks, which is sadly not public.
    fn prove_arkworks_inner<P>(
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: Vec<BigInt>,
    ) -> Result<ark_groth16::Proof<P>>
    where
        P: Pairing,
        P::ScalarField: From<BigUint>,
    {
        let witness: Vec<P::ScalarField> = witness
            .into_iter()
            .map(|w| {
                P::ScalarField::from(w.to_biguint().expect("witness entries should be positive"))
            })
            .collect();

        let rng = &mut thread_rng();
        let r = P::ScalarField::rand(rng);
        let s = P::ScalarField::rand(rng);
        let proof = Groth16::<P, CircomReduction>::create_proof_with_reduction_and_matrices(
            pkey,
            r,
            s,
            matrices,
            matrices.num_instance_variables, // Size of public data
            matrices.num_constraints,
            &witness,
        )?;

        Ok(proof)
    }
}

impl ProofWithPubInput {
    pub fn to_snarkjs_proof(&self) -> Result<String> {
        // let mut proof_json = std::collections::HashMap::new();
        let proof = SnarkjsProof {
            protocol: self.proof.protocol.clone(),
            curve: self.proof.curve.clone(),
            pi_a: vec![
                self.proof.a.x.to_string(),
                self.proof.a.y.to_string(),
                self.proof.a.z.to_string(),
            ],
            pi_b: vec![
                vec![self.proof.b.x[0].to_string(), self.proof.b.x[1].to_string()],
                vec![self.proof.b.y[0].to_string(), self.proof.b.y[1].to_string()],
                vec![self.proof.b.z[0].to_string(), self.proof.b.z[1].to_string()],
            ],
            pi_c: vec![
                self.proof.c.x.to_string(),
                self.proof.c.y.to_string(),
                self.proof.c.z.to_string(),
            ],
        };
        // proof_json.insert(
        //     "pi_a",
        //     serde_json::Value::Array(vec![
        //         self.proof.a.x.to_string().into(),
        //         self.proof.a.y.to_string().into(),
        //         self.proof.a.z.to_string().into(),
        //     ]),
        // );
        // proof_json.insert(
        //     "pi_b",
        //     serde_json::Value::Array(vec![
        //         serde_json::Value::Array(vec![
        //             self.proof.b.x[0].to_string().into(),
        //             self.proof.b.x[1].to_string().into(),
        //         ]),
        //         serde_json::Value::Array(vec![
        //             self.proof.b.y[0].to_string().into(),
        //             self.proof.b.y[1].to_string().into(),
        //         ]),
        //         serde_json::Value::Array(vec![
        //             self.proof.b.z[0].to_string().into(),
        //             self.proof.b.z[1].to_string().into(),
        //         ]),
        //     ]),
        // );
        // proof_json.insert(
        //     "pi_c",
        //     serde_json::Value::Array(vec![
        //         self.proof.c.x.to_string().into(),
        //         self.proof.c.y.to_string().into(),
        //         self.proof.c.z.to_string().into(),
        //     ]),
        // );
        // proof_json.insert(
        //     "protocol",
        //     serde_json::Value::String(self.proof.protocol.to_owned()),
        // );
        // proof_json.insert(
        //     "curve",
        //     serde_json::Value::String(self.proof.curve.to_owned()),
        // );
        Ok(serde_json::to_string_pretty(&proof)?)
    }

    pub fn to_snarkjs_pubinput(&self) -> Result<String> {
        let pub_input: Vec<String> = self
            .pub_input
            .iter()
            .skip(1)
            .map(|v| v.to_string())
            .collect();
        Ok(serde_json::to_string_pretty(&pub_input)?)
    }

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

#[derive(serde::Serialize, serde::Deserialize)]
struct SnarkjsProof {
    protocol: String,
    curve: String,
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}
