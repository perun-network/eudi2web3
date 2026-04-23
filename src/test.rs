use std::time::Instant;

use crate::{
    presentation2input, print_execution_time,
    prover::{MultiuseProver, Prover, SnarkjsProver},
    sdjwt, str2binary_sha2padding,
    witness::CircuitId,
    zeropad_str,
};
use num_bigint::BigInt;
use serde_json::json;

enum Curve {
    Bn254,
    Bls12381,
}

const BLSBUG2_PAYLOAD_BYTES: usize = 8;
const BLSBUG3_PAYLOAD_BYTES: usize = 64;

impl std::fmt::Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Curve::Bn254 => "bn254",
            Curve::Bls12381 => "bls12-381",
        })
    }
}

fn normal_claims() -> serde_json::Value {
    json!({
        "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
            "region": "Sachsen-Anhalt",
            "country": "DE"
        },
        "birthdate": "1940-01-01",
        "given_name": "foobar",
        "foo": "bar",
        "baz": {
            "hello": "world"
        }
    })
}
fn small_claims() -> serde_json::Value {
    json!({
        "iss": "i",
        "exp": 1883000000,
        "given_name": "foobar",
    })
}

// This code comes from MS1
// In debug mode it is basically unusable, taking ~200 seconds (without signature verification
// in the proof). This test can be run with `cargo test --lib -F slow-tests --release`.
// It is also enabled when using -F insecure-circuit, as that makes the test way faster (0.159s).
#[test]
#[cfg_attr(
    not(all(feature = "slow-tests", not(debug_assertions)),),
    ignore = "-F slow-tests --release"
)]
fn compute_proof_using_generated_credential_bn254_full() {
    compute_proof_using_generated_credential_inner(
        &CircuitId {
            curve: "bn254".to_owned(),
            circuit: "sdjwt_es256_sha256_1claim".to_owned(),
            contributions: 1,
        },
        normal_claims(),
        true,
    );
}
#[test]
#[cfg_attr(
    not(all(feature = "slow-tests", not(debug_assertions)),),
    ignore = "-F slow-tests --release"
)]
fn compute_proof_using_generated_credential_bls12381_small() {
    compute_proof_using_generated_credential_inner(
        &CircuitId {
            curve: "bls12-381".to_owned(),
            circuit: "small".to_owned(),
            contributions: 1,
        },
        small_claims(),
        false,
    );
}
#[test]
fn compute_proof_using_generated_credential_bn254_small_nocrypto() {
    compute_proof_using_generated_credential_inner(
        &CircuitId {
            curve: "bn254".to_owned(),
            circuit: "small_nocrypto".to_owned(),
            contributions: 1,
        },
        small_claims(),
        false,
    );
}
fn compute_proof_using_generated_credential_inner(
    circuit: &CircuitId,
    claims: serde_json::Value,
    add_decoy_claims: bool,
) {
    let circuits = crate::witness::get_circuits();
    let e = circuits
        .get(circuit)
        .unwrap_or_else(|| match circuit.contributions {
            0 => panic!(
                "Trying to request circuit with no contributions (completely insecure proof system)"
            ),
            1 => panic!(
                "Circuit not found, try running `make circuit-{}-{}`",
                circuit.curve, circuit.circuit
            ),
            _ => panic!("Requested circuit with more contributions than we have: {circuit:?}"),
        });

    let sd_strategy = sd_jwt_rs::ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.given_name"]);
    let serde_json::Value::Object(claims_to_disclose) = json!({
        // "address": {
        //     "region": true,
        //     "country": true
        // },
        "given_name": true,
    }) else {
        unreachable!()
    };
    let presentation =
        sdjwt::new_presentation(claims, sd_strategy, claims_to_disclose, add_decoy_claims).unwrap();

    sdjwt::explain(&presentation);
    println!("{}", "-".repeat(100));

    // Just checking correctness (of the presentation and the claim extraction algorithm)
    sdjwt::verify_presentation_lib(presentation.clone()).unwrap();
    sdjwt::verify_extract_claim(&presentation, "given_name").unwrap();

    // Build the input
    let t0 = Instant::now();
    let input = presentation2input(
        e.params.expect("circuit has no params configured"),
        &presentation,
    )
    .unwrap();
    dbg!(&input.value);
    let input = vec![
        ("in".to_owned(), input.input),
        ("value".to_owned(), input.value),
    ];
    print_execution_time("Input preparation finished", t0);

    let prover = MultiuseProver::new(&circuit.zkey_path()).unwrap();
    run_proof_with_witness_gen(circuit, prover, input);
}

/// Useful to test if the bls proof validity bug still exists.
#[test]
fn proof_validity_bls12381_blsbug1() {
    run_proof_with_witness_gen_multiuse(
        Curve::Bls12381,
        "blsbug1",
        vec![("in".to_owned(), vec![42.into()])],
    );
}
#[test]
fn proof_validity_bls12381_blsbug1_snarkjs() {
    run_proof_with_witness_gen_snarkjs(
        Curve::Bls12381,
        "blsbug1",
        vec![("in".to_owned(), vec![42.into()])],
    );
}
#[test]
fn proof_validity_bn254_blsbug1() {
    run_proof_with_witness_gen_multiuse(
        Curve::Bn254,
        "blsbug1",
        vec![("in".to_owned(), vec![42.into()])],
    );
}

#[test]
#[ignore = "upstream bug: https://github.com/zkmopro/mopro/issues/697"]
fn proof_validity_bls12381_blsbug2() {
    run_proof_with_witness_gen_multiuse(
        Curve::Bls12381,
        "blsbug2",
        vec![("in".to_owned(), zeropad_str("DEAD", BLSBUG2_PAYLOAD_BYTES))],
    );
}
#[test]
fn proof_validity_bls12381_blsbug2_snarkjs() {
    run_proof_with_witness_gen_snarkjs(
        Curve::Bls12381,
        "blsbug2",
        vec![("in".to_owned(), zeropad_str("DEAD", BLSBUG2_PAYLOAD_BYTES))],
    );
}
#[test]
fn proof_validity_bn254_blsbug2() {
    run_proof_with_witness_gen_multiuse(
        Curve::Bn254,
        "blsbug2",
        vec![("in".to_owned(), zeropad_str("DEAD", BLSBUG2_PAYLOAD_BYTES))],
    );
}

#[test]
#[ignore = "upstream bug: https://github.com/zkmopro/mopro/issues/697"]
fn proof_validity_bls12381_blsbug3() {
    run_proof_with_witness_gen_multiuse(
        Curve::Bls12381,
        "blsbug3",
        vec![
            (
                "in".to_owned(),
                str2binary_sha2padding("DEADBEEF", BLSBUG3_PAYLOAD_BYTES).0,
            ),
            ("dotSep".to_owned(), vec![5.into()]),
        ],
    );
}
#[test]
fn proof_validity_bls12381_blsbug3_snarkjs() {
    run_proof_with_witness_gen_snarkjs(
        Curve::Bls12381,
        "blsbug3",
        vec![
            (
                "in".to_owned(),
                str2binary_sha2padding("DEADBEEF", BLSBUG3_PAYLOAD_BYTES).0,
            ),
            ("dotSep".to_owned(), vec![5.into()]),
        ],
    );
}
#[test]
fn proof_validity_bn254_blsbug3() {
    run_proof_with_witness_gen_multiuse(
        Curve::Bn254,
        "blsbug3",
        vec![
            (
                "in".to_owned(),
                str2binary_sha2padding("DEAD.BEEF", BLSBUG3_PAYLOAD_BYTES).0,
            ),
            ("dotSep".to_owned(), vec![5.into()]),
        ],
    );
}

#[test]
fn proof_validity_bls12381_minimal() {
    run_proof_with_witness_gen_multiuse(
        Curve::Bls12381,
        "minimal",
        vec![
            ("value_compressed".to_owned(), vec![42.into(), 42.into()]),
            ("valid".to_owned(), vec![65.into()]),
        ],
    );
}

fn run_proof_with_witness_gen_multiuse(
    curve: Curve,
    circuit: &str,
    input: Vec<(String, Vec<BigInt>)>,
) {
    let id = CircuitId {
        curve: curve.to_string(),
        circuit: circuit.to_owned(),
        contributions: 1,
    };
    let prover = MultiuseProver::new(&id.zkey_path()).unwrap();
    run_proof_with_witness_gen(&id, prover, input);
}
fn run_proof_with_witness_gen_snarkjs(
    curve: Curve,
    circuit: &str,
    input: Vec<(String, Vec<BigInt>)>,
) {
    let id = CircuitId {
        curve: curve.to_string(),
        circuit: circuit.to_owned(),
        contributions: 1,
    };
    let prover = SnarkjsProver::new(id.zkey_path(), curve.to_string()).unwrap();
    run_proof_with_witness_gen(&id, prover, input);
}
fn run_proof_with_witness_gen(
    circuit: &CircuitId,
    prover: impl Prover,
    input: Vec<(String, Vec<BigInt>)>,
) {
    let e = crate::witness::get_circuit(circuit).unwrap();

    println!("INFO: Generating witness ...");
    let t0 = Instant::now();
    let wit = (e.compute_witness)(input);
    print_execution_time("Witness generation finished", t0);

    println!("{:?}", &wit[..200.min(wit.len())]);

    run_proof(prover, wit);
}
fn run_proof(prover: impl Prover, wit: Vec<BigInt>) {
    println!("Loading zkey ...");
    let t0 = Instant::now();
    print_execution_time("ZKey loading finished", t0);

    println!("INFO: Generating proof ...");
    let t0 = Instant::now();
    let proof = prover.prove_noverify(wit).unwrap();
    print_execution_time("Proof generation finished", t0);

    println!("INFO: Verifying proof ...");
    let t0 = Instant::now();
    let valid = prover.verify(&proof).unwrap();
    print_execution_time("Proof verification finished", t0);

    // Print the output in a more useful form
    if valid {
        println!("Proof is valid");
    } else {
        println!("Proof is NOT valid");
    }

    assert!(valid);
}
