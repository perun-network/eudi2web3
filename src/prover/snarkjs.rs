use std::{io::Write, path::Path, process::Command};

use anyhow::{Result, bail};
use num_bigint::BigInt;
use tempfile::tempdir;

use crate::prover::{Prover, SnarkjsProof, common::write_wtns_file};

use super::ProofWithPubInput;

#[derive(Debug)]
pub struct SnarkjsProver {
    zkey_path: String,
    curve: String,
}

impl SnarkjsProver {
    pub fn new(zkey_path: String, curve: String) -> Result<Self> {
        Ok(Self { zkey_path, curve })
    }

    fn prove_inner(&self, dir: &Path, witness: Vec<BigInt>) -> Result<ProofWithPubInput> {
        let wtns_path = dir.join("witness.wtns");
        let proof_path = dir.join("proof.json");
        let pub_path = dir.join("pub.json");
        write_wtns_file(&self.curve, &witness, &wtns_path)?;
        let success = Command::new("snarkjs")
            .arg("g16p")
            .arg("-v")
            .arg(&self.zkey_path)
            .arg(&wtns_path)
            .arg(&proof_path)
            .arg(&pub_path)
            .spawn()?
            .wait()?
            .success();

        if !success {
            bail!("`snarkjs groth16 prove` failed");
        }

        ProofWithPubInput::from_snarkjs_files(&proof_path, &pub_path)
    }
    fn verify_inner(&self, vkey_path: &Path, proof_path: &Path, pub_path: &Path) -> Result<bool> {
        let success = Command::new("snarkjs")
            .arg("zkev")
            .arg(&self.zkey_path)
            .arg(vkey_path)
            .spawn()?
            .wait()?
            .success();
        if !success {
            bail!("`snarkjs groth16 export verificationkey` failed");
        }

        let success = Command::new("snarkjs")
            .arg("g16v")
            .arg(vkey_path)
            .arg(pub_path)
            .arg(proof_path)
            .spawn()?
            .wait()?
            .success();
        if !success {
            // TODO: Not sure if/how to distinguish errors from verification failure.
            bail!("`snarkjs groth16 verify` failed");
        }

        Ok(true)
    }
}

impl Prover for SnarkjsProver {
    fn verify(&self, proof: &ProofWithPubInput) -> Result<bool> {
        let tmp_dir = tempdir()?;
        let tmp_path = tmp_dir.path();
        let vkey_path = tmp_path.join("vkey.json");
        let proof_path = tmp_path.join("proof.json");
        let pub_path = tmp_path.join("pub.json");

        let pubinput = proof.to_snarkjs_pubinput();
        let mut f = std::fs::File::create(&pub_path)?;
        serde_json::to_writer(&mut f, &pubinput)?;
        f.flush()?;

        let snarkjs_proof: SnarkjsProof = proof.into();
        let mut f = std::fs::File::create(&proof_path)?;
        serde_json::to_writer(&mut f, &snarkjs_proof)?;
        f.flush()?;

        let res = self.verify_inner(&vkey_path, &proof_path, &pub_path);
        tmp_dir.close()?;
        res
    }

    fn prove_noverify(&self, witness: Vec<BigInt>) -> Result<ProofWithPubInput> {
        let tmp_dir = tempdir()?;

        let res = self.prove_inner(tmp_dir.path(), witness);
        tmp_dir.close()?;
        res
    }

    // By implementing this we can avoid writing back proof + pub
    fn prove(&self, witness: Vec<BigInt>) -> Result<(ProofWithPubInput, bool)> {
        let tmp_dir = tempdir()?;
        let tmp_path = tmp_dir.path();
        let vkey_path = tmp_path.join("vkey.json");
        let proof_path = tmp_path.join("proof.json");
        let pub_path = tmp_path.join("pub.json");

        let proof = self.prove_inner(tmp_dir.path(), witness)?;
        let valid = self.verify_inner(&vkey_path, &proof_path, &pub_path)?;
        tmp_dir.close()?;
        Ok((proof, valid))
    }
}
