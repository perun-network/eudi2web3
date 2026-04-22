use std::fs::File;

use anyhow::{Result, anyhow};
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField as _, UniformRand as _};
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
use ark_relations::r1cs::ConstraintMatrices;
use ark_snark::SNARK;
use circom_prover::prover::{
    ark_circom::{CircomReduction, ZkeyHeaderReader, read_zkey},
    circom::Proof,
};
use num_bigint::{BigInt, BigUint};
use rand::thread_rng;

use crate::prover::{ProofWithPubInput, Prover};

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
#[derive(Debug)]
pub struct MultiuseProver {
    zkey: Key,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // 1840 vs 2544 bytes and we only have one instance
enum Key {
    Bn254 {
        pkey: ProvingKey<Bn254>,
        mats: ConstraintMatrices<ark_bn254::Fr>,
        vkey: PreparedVerifyingKey<Bn254>,
    },
    Bls12_381 {
        pkey: ProvingKey<Bls12_381>,
        mats: ConstraintMatrices<ark_bls12_381::Fr>,
        vkey: PreparedVerifyingKey<Bls12_381>,
    },
}

impl MultiuseProver {
    pub fn new(zkey_path: &str) -> Result<Self> {
        // First: Figure out which key we need. For some reason circom-prover doesn't use an enum
        // and doesn't do this for us.
        // It is a bit odd to open the file twice, but that seems to be the easiest way and is what
        // circom-prover does, too.
        let mut header = ZkeyHeaderReader::new(zkey_path);
        header.read(); // Annoyingly this panicks and doesn't have a try variant.
        let file = File::open(zkey_path)?;
        let mut reader = std::io::BufReader::new(file);

        let zkey = if header.r == BigUint::from(ark_bn254::Fr::MODULUS) {
            let (pkey, mats) = read_zkey::<_, Bn254>(&mut reader)?;
            let vkey = prepare_verifying_key(&pkey.vk);
            Key::Bn254 { pkey, mats, vkey }
        } else if header.r == BigUint::from(ark_bls12_381::Fr::MODULUS) {
            let (pkey, mats) = read_zkey::<_, Bls12_381>(&mut reader)?;
            let vkey = prepare_verifying_key(&pkey.vk);
            Key::Bls12_381 { pkey, mats, vkey }
        } else {
            return Err(anyhow!("Unexpected curve in zkey"));
        };

        Ok(Self { zkey })
    }
}

impl Prover for MultiuseProver {
    fn verify(&self, proof: &ProofWithPubInput) -> Result<bool> {
        // Verify the proof so we know it is actually useful/correct
        // For some reason loading the zkey with bls is really slow. To avoid doing that every time
        // we need to re-implement some code from circom_prover.
        self.zkey.verify_arkworks(proof)

        // circom_prover::CircomProver::verify(
        //     circom_prover::prover::ProofLib::Arkworks,
        //     circom_prover::prover::CircomProof {
        //         proof: proof.proof.clone(),
        //         pub_inputs: circom_prover::prover::PublicInputs(proof.pub_input[1..].to_vec()),
        //     },
        //     self.zkey_path.to_owned(),
        // )
    }

    fn prove_noverify(&self, witness: Vec<BigInt>) -> Result<ProofWithPubInput> {
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
}

impl Key {
    fn num_instance_variables(&self) -> usize {
        match self {
            Key::Bn254 { mats, .. } => mats.num_instance_variables,
            Key::Bls12_381 { mats, .. } => mats.num_instance_variables,
        }
    }

    // We could accept a witness slice here, as we need to map over it anyways to convert it to SF
    // values (curve dependent). But that's likely not beneficial. Doing that would mean this
    // entire witness Vec lives until the entire proof was created, taking up memory. Instead we
    // take an owned value and (hopefully) drop it early, freeing up the relevant memory.
    fn prove_arkworks(&self, witness: Vec<BigInt>) -> Result<Proof> {
        let proof = match self {
            Key::Bn254 { pkey, mats, .. } => {
                Self::prove_arkworks_inner(pkey, mats, witness)?.into()
            }
            Key::Bls12_381 { pkey, mats, .. } => {
                Self::prove_arkworks_inner(pkey, mats, witness)?.into()
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

    fn verify_arkworks(&self, proof: &ProofWithPubInput) -> Result<bool> {
        match self {
            Key::Bn254 { vkey, .. } => Self::verify_arkworks_inner(vkey, proof),
            Key::Bls12_381 { vkey, .. } => Self::verify_arkworks_inner(vkey, proof),
        }
    }
    fn verify_arkworks_inner<P>(
        vkey: &PreparedVerifyingKey<P>,
        proof: &ProofWithPubInput,
    ) -> Result<bool>
    where
        P: Pairing,
        P::ScalarField: From<BigUint>,
        ark_groth16::Proof<P>: From<Proof>,
    {
        let serialized_inputs: Vec<_> = proof.pub_input[1..]
            .iter()
            .map(|v| P::ScalarField::from(v.clone()))
            .collect();

        let valid = Groth16::<P, CircomReduction>::verify_with_processed_vk(
            vkey,
            &serialized_inputs,
            &proof.proof.clone().into(),
        )?;
        Ok(valid)
    }
}
