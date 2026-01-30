use std::fs::File;

use anyhow::{Result, anyhow};
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField as _, UniformRand as _};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use base64::Engine;
use circom_prover::prover::{
    ark_circom::{CircomReduction, ZkeyHeaderReader, read_zkey},
    circom::Proof,
};
use num_bigint::{BigInt, BigUint};
use rand::thread_rng;

// Generated code to go from input to witness.
mod witness {
    rust_witness::witness!(dlpexample);
}

fn main() {
    /////////////////////////////////////////////////////////////////////////////////////
    // Credential creation (for testing)
    /////////////////////////////////////////////////////////////////////////////////////

    // Totally unsafe
    let issuer_secret = [0; 32];
    let issuer_key = jsonwebtoken::EncodingKey::from_secret(&issuer_secret);
    let mut issuer = sd_jwt_rs::SDJWTIssuer::new(issuer_key, Some("HS256".to_owned()));
    // let mut claims = serde_json::Map::new();
    // claims.insert(
    //     "given_name".to_owned(),
    //     serde_json::Value::String("foobar".repeat(100)),
    // );
    let claims = serde_json::json!({
        "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
            "region": "Sachsen-Anhalt".repeat(100),
            "country": "DE"
        },
        "birthdate": "1940-01-01",
        "given_name": "foobar".repeat(100),
        "foo": "bar",
        "baz": {
            "hello": "world"
        }
    });
    let sd_jwt = issuer
        .issue_sd_jwt(
            claims,
            sd_jwt_rs::ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            true,
            // Only seems to affect the outer encoding
            sd_jwt_rs::SDJWTSerializationFormat::Compact,
        )
        .unwrap();
    dbg!(&sd_jwt);
    let mut holder =
        sd_jwt_rs::SDJWTHolder::new(sd_jwt, sd_jwt_rs::SDJWTSerializationFormat::Compact).unwrap();
    let serde_json::Value::Object(claims_to_disclose) = serde_json::json!({
        "address": {
            "region": true,
            "country": true
        },
        "given_name": true,
    }) else {
        unreachable!()
    };
    // let mut claims_to_disclose = serde_json::Map::new();
    // claims_to_disclose.insert("given_name".to_owned(), serde_json::Value::Bool(true));
    // Not sure how to request subfields. This doesn't seem to work. Further
    // experimentation+reading code needed.
    // claims_to_disclose.insert(
    //     "address".to_owned(),
    //     serde_json::Value::Array(vec![serde_json::Value::String("region".to_owned())]),
    // );
    // claims_to_disclose.insert("foo".to_owned(), serde_json::Value::Bool(true));
    // claims_to_disclose.insert("baz".to_owned(), serde_json::Value::Bool(true));
    let presentation = holder
        .create_presentation(claims_to_disclose, None, None, None, None)
        .unwrap();
    dbg!(&presentation);
    let verified_claims = sd_jwt_rs::SDJWTVerifier::new(
        presentation.clone(),
        Box::new(move |_, _| jsonwebtoken::DecodingKey::from_secret(&issuer_secret)),
        None,
        None,
        sd_jwt_rs::SDJWTSerializationFormat::Compact,
    )
    .unwrap()
    .verified_claims;
    dbg!(&verified_claims);

    /////////////////////////////////////////////////////////////////////////////////////
    // Manual presentation decoding (exploration)
    /////////////////////////////////////////////////////////////////////////////////////
    let mut segments = presentation.split('~').enumerate();
    let (_, seg0) = segments.next().unwrap();
    let mut seg0_iter = seg0.split('.');
    let header = seg0_iter.next().unwrap();
    let body = seg0_iter.next().unwrap();
    let header = base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(header)
        .unwrap();
    let body = base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(body)
        .unwrap();
    let header = String::from_utf8_lossy(&header);
    let body = String::from_utf8_lossy(&body);
    dbg!(header, body);

    for (i, segment) in segments {
        // Segment 0: SD-JWT (contains sign_algorithm)
        // - Split into at least 2 parts at '.'
        //   - 0: JWT Header: base64url encoded json
        //   - 1: "unverified-input_sd_jwt_payload" (body): base64url encoded json
        // Segment 1: Input disclosures (one per requested claim if full SD, otherwise one for each last SD object)
        // - This specific implementation outputs in the requested order, but that's almost certainly not required by spec.
        // Last segment: Unverified input key binding JWT (so far often empty?)
        //
        // I might have gotten segment 1 and 2 swapped, they use next_back.
        // dbg!(segment);

        let segment = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(segment)
            .unwrap();
        let segment = String::from_utf8_lossy(&segment);
        dbg!(i, segment);
    }

    // let seg1 = segments.next().unwrap();
    // let seg2 = segments.next().unwrap();
    // let mut seg0_iter = seg0.split('.');
    // let header = seg0_iter.next().unwrap();
    // let body = seg0_iter.next().unwrap();
    // let header = base64::prelude::BASE64_URL_SAFE_NO_PAD
    //     .decode(header)
    //     .unwrap();
    // let body = base64::prelude::BASE64_URL_SAFE_NO_PAD
    //     .decode(body)
    //     .unwrap();
    // let seg1 = base64::prelude::BASE64_URL_SAFE_NO_PAD
    //     .decode(seg1)
    //     .unwrap();
    // let header = String::from_utf8_lossy(&header);
    // let body = String::from_utf8_lossy(&body);
    // let seg1 = String::from_utf8_lossy(&seg1);
    // dbg!(&header, &body, &seg1, seg2);

    // Cryptographic links
    // Raw Output of SHA256 hash of base64url encoded disclosure (segment 1..n-1) is base64url encoded.
    // - Do not base64 encode the hex of the hash (Cyberchef outputs the hex by default)
    // - By default sha2-256 is used and that is (almost certainly) set at issuance time, not on presentation time.

    /////////////////////////////////////////////////////////////////////////////////////
    // ZK Circuit (proof creation)
    /////////////////////////////////////////////////////////////////////////////////////

    let zkey_path = "zkey/dlpexample.zkey";
    let prover = MultiuseProver::new(zkey_path).unwrap();

    let input = [
        ("a".to_owned(), vec![3.into()]),
        ("b".to_owned(), vec![7.into()]),
    ];
    let proof = prover.prove(witness::dlpexample_witness, input).unwrap();
    dbg!(&proof);
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
struct MultiuseProver {
    zkey: PKey,
}

enum PKey {
    Bn256(ProvingKey<Bn254>, ConstraintMatrices<ark_bn254::Fr>),
    Bls12_381(ProvingKey<Bls12_381>, ConstraintMatrices<ark_bls12_381::Fr>),
}

#[derive(Debug)]
struct ProofWithPubInput {
    pub proof: Proof,
    pub pub_input: Vec<BigUint>,
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
            let x = read_zkey::<_, Bn254>(&mut reader)?;
            PKey::Bn256(x.0, x.1)
        } else if header.r == BigUint::from(ark_bls12_381::Fr::MODULUS) {
            let x = read_zkey::<_, Bls12_381>(&mut reader)?;
            PKey::Bls12_381(x.0, x.1)
        } else {
            return Err(anyhow!("Unexpected curve in zkey"));
        };

        Ok(Self { zkey })
    }

    // I'd love to allow &str for keys, but the to_witness functions expect owned Strings. Even
    // though that's not strictly neccessary. The circom-prover implementation goes through even
    // more steps, json deserialization and multiple allocations to achieve the same (if
    // RustWitness is used.)
    pub fn prove<I>(
        &self,
        to_witness: impl FnOnce(I) -> Vec<BigInt>,
        input: I,
    ) -> Result<ProofWithPubInput>
    where
        I: IntoIterator<Item = (String, Vec<BigInt>)>,
    {
        let witness: Vec<BigInt> = to_witness(input);

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
