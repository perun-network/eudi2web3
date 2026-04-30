use std::time::Instant;

use crate::{
    ISSUER_PUBLIC, presentation2input, print_execution_time,
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

// A verifiable credentials presentation I've sent to the server.
// NOTE: This is too large for the small circuit.
// NOTE: This has the _sd entry early (index 0/8), which will not be the case for all circuits.
#[allow(unused)]
const VP: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSUMzekNDQW9XZ0F3SUJBZ0lVZjNsb2hUbURNQW1TL1lYL3E0aHFvUnlKQjU0d0NnWUlLb1pJemowRUF3SXdYREVlTUJ3R0ExVUVBd3dWVUVsRUlFbHpjM1ZsY2lCRFFTQXRJRlZVSURBeU1TMHdLd1lEVlFRS0RDUkZWVVJKSUZkaGJHeGxkQ0JTWldabGNtVnVZMlVnU1cxd2JHVnRaVzUwWVhScGIyNHhDekFKQmdOVkJBWVRBbFZVTUI0WERUSTFNRFF4TURFME16YzFNbG9YRFRJMk1EY3dOREUwTXpjMU1Wb3dVakVVTUJJR0ExVUVBd3dMVUVsRUlFUlRJQzBnTURFeExUQXJCZ05WQkFvTUpFVlZSRWtnVjJGc2JHVjBJRkpsWm1WeVpXNWpaU0JKYlhCc1pXMWxiblJoZEdsdmJqRUxNQWtHQTFVRUJoTUNWVlF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVM3V0FBV3FQemUwVXMzejhwYWp5VlBXQlJtclJiQ2k1WDJzOUd2bHliUXl0d1R1bWNabmVqOUJrTGZBZ2xsb1g1dHYrTmdXZkRmZ3QvMDZzKzV0VjRsbzRJQkxUQ0NBU2t3SHdZRFZSMGpCQmd3Rm9BVVlzZVVSeWk5RDZJV0lLZWF3a21VUlBFQjA4Y3dHd1lEVlIwUkJCUXdFb0lRYVhOemRXVnlMbVYxWkdsM0xtUmxkakFXQmdOVkhTVUJBZjhFRERBS0JnZ3JnUUlDQUFBQkFqQkRCZ05WSFI4RVBEQTZNRGlnTnFBMGhqSm9kSFJ3Y3pvdkwzQnlaWEJ5YjJRdWNHdHBMbVYxWkdsM0xtUmxkaTlqY213dmNHbGtYME5CWDFWVVh6QXlMbU55YkRBZEJnTlZIUTRFRmdRVXFsL29weGtRbFl5MGxsYVRvUGJERS9teUVjRXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1GMEdBMVVkRWdSV01GU0dVbWgwZEhCek9pOHZaMmwwYUhWaUxtTnZiUzlsZFMxa2FXZHBkR0ZzTFdsa1pXNTBhWFI1TFhkaGJHeGxkQzloY21Ob2FYUmxZM1IxY21VdFlXNWtMWEpsWm1WeVpXNWpaUzFtY21GdFpYZHZjbXN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU5KVlNEc3FUM0lrR2NLV1dnU2V1YmtET2RpNS9VRTliMUdGL1g1ZlFSRmFBaUJwNXQ2dEhoOFh3RmhQc3R6T0hNb3B2QkQvR3dtczBSQVVnbVNuNmt1OEdnPT0iXX0.eyJfc2QiOiBbIjcyNE5lZjZfcHpYU2V5ZDFUSE9oSXBVX2Nrenc2bnNBRkNrSlhPUjJSRkkiLCAiTGtIb3J0RUROMmUtVnJxUDRwSFNHbUhGdXlMdWpRV1ZaY0dQR3ZuYjI1ayIsICJaRmVDTGlNTlgxaGZiaDduWklnMnNQNjNLa1B1TTRzclV6SUpCWUJwZE5vIiwgImtsMlJXcm5EanljbldSbEZpNmo2LUJtYXJvaFpSOWFoYm5wM0RJY1BXcGMiLCAidFR0U1RHMm44ZmhPTTEzQnk5cjk0RDJlQ1ZHbHFqOHFMcVh2akV6S0J4QSIsICJ3VXQ4WlRKNlRHTjVaY19sZVRHNmFWSVNZNDJVZWNBM3h5QmxnendIa19ZIiwgInhZaTdZU2NmVVhfWVowc0pjQm5uTWIwQ0toQXR6M25EdE5CMGh2M3N2VjQiLCAieU5zTlBpaDdyN2dpSWE1aGhLZ1Bxc3A5aUNCWXhHa1JCRW51WksyOFZoSSJdLCAiaXNzIjogImh0dHBzOi8vYmFja2VuZC5pc3N1ZXIuZXVkaXcuZGV2IiwgImlhdCI6IDE3NzU2MDI4MDAsICJleHAiOiAxNzgzMzc4ODAwLCAidmN0IjogInVybjpldWRpOnBpZDoxIiwgInN0YXR1cyI6IHsic3RhdHVzX2xpc3QiOiB7ImlkeCI6IDcyNTcsICJ1cmkiOiAiaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2L3Rva2VuX3N0YXR1c19saXN0L0ZDL3VybjpldWRpOnBpZDoxL2Q4NDBjNTY4LTJlMzYtNGFhMC04Mjg5LWIyOWZkMWU5MWMwZiJ9fSwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIl91TUJvU2pqMG5HX0tJSnJCR1VJcG8xN3lqLWJ5Y1djSzFsSW9VckcxdXciLCAieSI6ICI4WTk3YWRaRGMxNlJ6X2UwOHJ0czlFZ2s3MVNJOFJNSERsOElYM3JGMFhNIn19fQ._3KRjhJ-a2MYsl00RVqGJ_X1dzTY-p2vEOzpqXBTk7UcKZYlfq96FKy-4nMIlSDuXwsd5dNwk3Rwouc7-WOh6w~WyJJcTByR0ZqTVFjeDZNZUhZVVJXempBIiwgImdpdmVuX25hbWUiLCAiZm9vYmFyOCJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoic1NJZmZ1V25VQllpWUl3QWJBdXJMSzF0eTd1VFdmVEZiV21UTW8zUUJVYyIsImF1ZCI6Ing1MDlfaGFzaDo0alB0Q1prUDF1NHd6OEJ3UlMtZmJEQU4tYW1TRTQ5Q010bWdtUXhUTWIwIiwibm9uY2UiOiJDY0JKTUEyMTFDMjVsQmtDNVNvQk42eUhldkZpempPTCIsImlhdCI6MTc3NjkzNDc2MX0.VADcrT6DX5T3z-zIkAUj7Ux3tU0ylfqMzejoD4bI-h8rNeOuXP9R4aVX_qLlmVqOfvs1uiIQu5PIpoZfwWfWlA";

const VP_LATE_SD_ENTRY: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSUMzekNDQW9XZ0F3SUJBZ0lVZjNsb2hUbURNQW1TL1lYL3E0aHFvUnlKQjU0d0NnWUlLb1pJemowRUF3SXdYREVlTUJ3R0ExVUVBd3dWVUVsRUlFbHpjM1ZsY2lCRFFTQXRJRlZVSURBeU1TMHdLd1lEVlFRS0RDUkZWVVJKSUZkaGJHeGxkQ0JTWldabGNtVnVZMlVnU1cxd2JHVnRaVzUwWVhScGIyNHhDekFKQmdOVkJBWVRBbFZVTUI0WERUSTFNRFF4TURFME16YzFNbG9YRFRJMk1EY3dOREUwTXpjMU1Wb3dVakVVTUJJR0ExVUVBd3dMVUVsRUlFUlRJQzBnTURFeExUQXJCZ05WQkFvTUpFVlZSRWtnVjJGc2JHVjBJRkpsWm1WeVpXNWpaU0JKYlhCc1pXMWxiblJoZEdsdmJqRUxNQWtHQTFVRUJoTUNWVlF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVM3V0FBV3FQemUwVXMzejhwYWp5VlBXQlJtclJiQ2k1WDJzOUd2bHliUXl0d1R1bWNabmVqOUJrTGZBZ2xsb1g1dHYrTmdXZkRmZ3QvMDZzKzV0VjRsbzRJQkxUQ0NBU2t3SHdZRFZSMGpCQmd3Rm9BVVlzZVVSeWk5RDZJV0lLZWF3a21VUlBFQjA4Y3dHd1lEVlIwUkJCUXdFb0lRYVhOemRXVnlMbVYxWkdsM0xtUmxkakFXQmdOVkhTVUJBZjhFRERBS0JnZ3JnUUlDQUFBQkFqQkRCZ05WSFI4RVBEQTZNRGlnTnFBMGhqSm9kSFJ3Y3pvdkwzQnlaWEJ5YjJRdWNHdHBMbVYxWkdsM0xtUmxkaTlqY213dmNHbGtYME5CWDFWVVh6QXlMbU55YkRBZEJnTlZIUTRFRmdRVXFsL29weGtRbFl5MGxsYVRvUGJERS9teUVjRXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1GMEdBMVVkRWdSV01GU0dVbWgwZEhCek9pOHZaMmwwYUhWaUxtTnZiUzlsZFMxa2FXZHBkR0ZzTFdsa1pXNTBhWFI1TFhkaGJHeGxkQzloY21Ob2FYUmxZM1IxY21VdFlXNWtMWEpsWm1WeVpXNWpaUzFtY21GdFpYZHZjbXN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU5KVlNEc3FUM0lrR2NLV1dnU2V1YmtET2RpNS9VRTliMUdGL1g1ZlFSRmFBaUJwNXQ2dEhoOFh3RmhQc3R6T0hNb3B2QkQvR3dtczBSQVVnbVNuNmt1OEdnPT0iXX0.eyJfc2QiOiBbIkpfMVNuWGJRVkhtQVplUVRtdjVlOUppS0JoQlRJZUYyeDQtbndja1h4YUkiLCAiTGJDZmV4SURoYnBPVm14Wl9vRHJCTktvaGhZSmVvdG4yR0ZCRmlaUmdlRSIsICJMdlpqWkhQSWk4LWZpaUk2Q1JSbm5ic1pOT0R4Q3Roc2gxVlVxeDlvdHhBIiwgIlc0d1RMUDl5aWJtNVM4bkx5amdWekRVdXdrZzVPSm5aWlF3WVhVME1UVzAiLCAiWEhKWGFuUHBCbHRPUGZnbGhIRFZLdTI0UG8yVkhmdXRFWml5elVzZldRbyIsICJiN0IweDVUbnZBR1M4RXE5YlNNa3d6QkhTakRNQjAxMmpsNDB4UXAtR093IiwgImNxbElFOWZWbVUtX0xoSHZwdllISW9kdUdyb0ZSUW92aXBabG91akphWGciLCAiekRCcnpuMDNHbm5KNlhNUGY4bW9XVkdsYkZQNjh6aGVaTGU2N0NCVDNlNCJdLCAiaXNzIjogImh0dHBzOi8vYmFja2VuZC5pc3N1ZXIuZXVkaXcuZGV2IiwgImlhdCI6IDE3NzU2MDI4MDAsICJleHAiOiAxNzgzMzc4ODAwLCAidmN0IjogInVybjpldWRpOnBpZDoxIiwgInN0YXR1cyI6IHsic3RhdHVzX2xpc3QiOiB7ImlkeCI6IDk5MiwgInVyaSI6ICJodHRwczovL2lzc3Vlci5ldWRpdy5kZXYvdG9rZW5fc3RhdHVzX2xpc3QvRkMvdXJuOmV1ZGk6cGlkOjEvZDg0MGM1NjgtMmUzNi00YWEwLTgyODktYjI5ZmQxZTkxYzBmIn19LCAiX3NkX2FsZyI6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiR1diMmtxUW0wS0NxWklvVUtka3A1Sk9HaHQzeTJpNEFIV2JfTkJBXy16QSIsICJ5IjogImNEa2hYb2prejNiVkRZWTFiT1NuejVlb0pGd0txT1BhcjctOW1TT19PcXcifX19.JVPMTiQ8sCPg0MkzESmc9iCLMsR-TRlJKN6LUut7o_6Kym0_uje5BRgrTXopa0TiJP_wAn2A-M5SBxBYt2NrkA~WyJTU2NfelJJZm1ld0JOLWtvTjdjZUxnIiwgImdpdmVuX25hbWUiLCAiZm9vYmFyOCJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiSnJlb09KdTd5ME9md0RKM3Q4YVhYeXhWSmpBREpkaXA4Z1k1TTVQdWhQZyIsImF1ZCI6Ing1MDlfaGFzaDo0alB0Q1prUDF1NHd6OEJ3UlMtZmJEQU4tYW1TRTQ5Q010bWdtUXhUTWIwIiwibm9uY2UiOiJ0NkpsbG5OaWhCUkY2YlVPUEtUUnpCVmlLRzRZQklIeSIsImlhdCI6MTc3Njk0ODU2Mn0.hXNo4fUzAzeNcmhbELNbgeIe7xHtogeph4Qm06crRXi3ZzshdgYoPPbIta8cLmvG-SSUY0gKK-PC3mNhgbPICg";

#[test]
fn verify_testing_issuer_credential_nocircuit() {
    // Just checking correctness (of the presentation and the claim extraction algorithm)

    // NOTE: The closure in this function doesn't properly work with this credential, as it does
    // not go through the certificate chain. The easiest implementation would probably be to
    // extract the leaf cert, but for now we just don't test this code.
    // sdjwt::verify_presentation_lib(VP.to_owned(), ISSUER_CA_UT02.to_vec()).unwrap();

    let claim = sdjwt::verify_extract_claim(VP_LATE_SD_ENTRY, "given_name").unwrap();
    assert_eq!(claim, serde_json::Value::String("foobar8".to_owned()))
}

#[test]
#[cfg_attr(
    not(all(feature = "slow-tests", not(debug_assertions)),),
    ignore = "-F slow-tests --release"
)]
fn compute_proof_testing_issuer_credential_bn254_small_nocrypto() {
    let circuit = CircuitId {
        curve: "bn254".to_owned(),
        // TODO: We are using nocrypto here, mainly because I don't have ptau file large enough for the one with crypto.
        circuit: "small_nocrypto".to_owned(),
        contributions: 1,
    };
    let e = crate::witness::get_circuit(&circuit).unwrap();

    // Build the input (this could probably run without -F slow-tests)
    let t0 = Instant::now();
    let input = presentation2input(
        e.params.expect("circuit has no params configured"),
        VP_LATE_SD_ENTRY,
    )
    .unwrap();
    dbg!(&input.value);
    let input = vec![
        ("in".to_owned(), input.input),
        ("value".to_owned(), input.value),
    ];
    print_execution_time("Input preparation finished", t0);

    let prover = MultiuseProver::new(&circuit.zkey_path()).unwrap();
    run_proof_with_witness_gen(&circuit, prover, input);
}
#[test]
#[cfg_attr(
    not(all(feature = "slow-tests", not(debug_assertions)),),
    ignore = "-F slow-tests --release"
)]
fn compute_proof_testing_issuer_credential_bls12381_small_nocrypto_snarkjs() {
    let circuit = CircuitId {
        curve: "bls12-381".to_owned(),
        // TODO: We are using nocrypto here, mainly because I don't have ptau file large enough for the one with crypto.
        circuit: "small_nocrypto".to_owned(),
        contributions: 1,
    };
    let e = crate::witness::get_circuit(&circuit).unwrap();

    // Build the input (this could probably run without -F slow-tests)
    let t0 = Instant::now();
    let input = presentation2input(
        e.params.expect("circuit has no params configured"),
        VP_LATE_SD_ENTRY,
    )
    .unwrap();
    dbg!(&input.value);
    let input = vec![
        ("in".to_owned(), input.input),
        ("value".to_owned(), input.value),
    ];
    print_execution_time("Input preparation finished", t0);

    let prover = SnarkjsProver::new(circuit.zkey_path(), "bls12-381".to_owned()).unwrap();
    run_proof_with_witness_gen(&circuit, prover, input);
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
fn compute_proof_using_generated_credential_bn254_small_nocrypto() {
    compute_proof_using_generated_credential_inner(
        &CircuitId {
            curve: "bn254".to_owned(),
            circuit: "small_nocrypto".to_owned(),
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
fn compute_proof_using_generated_credential_bls12381_tiny() {
    compute_proof_using_generated_credential_inner(
        &CircuitId {
            curve: "bls12-381".to_owned(),
            circuit: "tiny".to_owned(),
            contributions: 1,
        },
        small_claims(),
        false,
    );
}
#[test]
fn compute_proof_using_generated_credential_bn254_tiny_nocrypto() {
    compute_proof_using_generated_credential_inner(
        &CircuitId {
            curve: "bn254".to_owned(),
            circuit: "tiny_nocrypto".to_owned(),
            contributions: 1,
        },
        small_claims(),
        false,
    );
}
#[test]
fn compute_proof_using_generated_credential_bls12381_tiny_nocrypto_snarkjs() {
    compute_proof_using_generated_credential_inner_with_prover(
        &CircuitId {
            curve: "bls12-381".to_owned(),
            circuit: "tiny_nocrypto".to_owned(),
            contributions: 1,
        },
        small_claims(),
        false,
        |p| SnarkjsProver::new(p, "bls12-381".to_owned()).unwrap(),
    );
}
fn compute_proof_using_generated_credential_inner(
    circuit: &CircuitId,
    claims: serde_json::Value,
    add_decoy_claims: bool,
) {
    compute_proof_using_generated_credential_inner_with_prover(
        circuit,
        claims,
        add_decoy_claims,
        |p| MultiuseProver::new(&p).unwrap(),
    );
}
fn compute_proof_using_generated_credential_inner_with_prover<P: Prover>(
    circuit: &CircuitId,
    claims: serde_json::Value,
    add_decoy_claims: bool,
    get_prover: impl FnOnce(String) -> P,
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
    sdjwt::verify_presentation_lib(presentation.clone(), ISSUER_PUBLIC.to_vec()).unwrap();
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

    run_proof_with_witness_gen(circuit, get_prover(circuit.zkey_path()), input);
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
