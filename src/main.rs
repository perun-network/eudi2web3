use std::time::Instant;

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use num_bigint::BigInt;
use prover::MultiuseProver;
use serde_json::json;

// Generated code to go from input to witness.
mod witness {
    // Contains non-mangled symbols called from C
    mod runtime;

    // rust_witness::witness!(dlpexample);
    rust_witness::witness!(sdjwtes256sha2561claim);
}

mod keyfinder;
mod prover;
mod sdjwt;

// Configuration of the circuit
const MAX_PAYLOAD_BYTES: usize = 1024;
const MAX_VALUE_BYTES: usize = 32;

#[derive(Debug)]
struct CircuitInput {
    input: Vec<BigInt>,
    value: Vec<BigInt>,
}

fn presentation2input(presentation: &str, issuer_pk: [u8; 64]) -> CircuitInput {
    // Get the relevant data from the credential to pass to input
    let mut segments = presentation.split('~');
    let (message, sig) = segments
        .next()
        .expect("At least one segment")
        .rsplit_once('.')
        .expect("header.body.sig");

    let (header, body) = message.split_once('.').unwrap();
    let sig = BASE64_URL_SAFE_NO_PAD.decode(sig).unwrap();
    assert_eq!(sig.len(), 64);

    // Find the message offset for the key we are interested in.
    let body_json = BASE64_URL_SAFE_NO_PAD.decode(body).unwrap();
    let mut pos = keyfinder::find_key_jsonbytes(&body_json, "given_name").expect("invalid json");
    if pos.is_none() {
        pos = keyfinder::find_key_jsonbytes(&body_json, "_sd").expect("invalid json");
    }
    let Some(pos) = pos else {
        // TODO: Handle this gracefully, the JWT does not have this claim.
        panic!("Could not find the key 'given_name' or '_sd'");
    };
    // We need the character before the quote to make sure it isn't an escaped quote and thus part
    // of a string.
    let payload_off = header.len() + 1 + (pos.key_start_quote - 1) / 3 * 4;
    let json_align = (pos.key_start_quote - 1) % 3;
    // dbg!(&pos, payload_off, json_align);

    // Build the input
    // IMPORTANT: rust_witness fails silently if any input signal is missing, setting all
    // intermediate and output signals to 0.
    let pk_x = bebytes2limbs(&issuer_pk[..32]);
    let pk_y = bebytes2limbs(&issuer_pk[32..]);
    let sig_r = bebytes2limbs(&sig[..32]);
    let sig_s = bebytes2limbs(&sig[32..]);
    let (payload, payload_padded_len) = str2binary_sha2padding(message, MAX_PAYLOAD_BYTES);
    let lengths = vec![
        payload_padded_len.into(),
        header.len().into(),
        payload_off.into(),
        json_align.into(),
    ];
    CircuitInput {
        input: [pk_x, pk_y, sig_r, sig_s, payload, lengths]
            .into_iter()
            .flatten()
            .collect(),
        value: zeropad_str(pos.value, MAX_VALUE_BYTES),
    }
}

/*
fn witness2txt(wit: &[BigInt], path: impl AsRef<Path>) {
    let mut f = std::fs::File::create(path).unwrap();
    for (i, v) in wit.iter().enumerate() {
        writeln!(f, "{i:08}: {v}").unwrap();
    }
    f.flush().unwrap();
}
fn witness2wtns(wit: &[BigInt], path: impl AsRef<Path>) {
    let prime = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
        // b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();
    let (sign, mut prime) = prime.to_bytes_be();
    assert_ne!(sign, num_bigint::Sign::Minus);
    prime.resize(32, 0);
    let prime: [u8; 32] = prime.try_into().unwrap();
    let wtns_file = WtnsFile {
        version: 2,
        header: wtns_file::Header {
            field_size: 32,
            prime: prime.into(),
            witness_len: wit.len() as u32,
        },
        witness: wtns_file::Witness(
            wit.iter()
                .map(|v| {
                    let (sign, mut v) = v.to_bytes_be();
                    assert_ne!(sign, num_bigint::Sign::Minus);
                    v.resize(32, 0);
                    let v: [u8; 32] = v.try_into().unwrap();
                    v.into()
                })
                .collect(),
        ),
    };
    let mut f = std::fs::File::create(path).unwrap();
    wtns_file.write(&mut f).unwrap();
    f.flush().unwrap();
    drop(f);
}
*/

fn main() {
    // Create a credential for testing
    let claims = json!({
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
    });
    let sd_strategy = sd_jwt_rs::ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.address"]);
    let serde_json::Value::Object(claims_to_disclose) = json!({
        // "address": {
        //     "region": true,
        //     "country": true
        // },
        "given_name": true,
    }) else {
        unreachable!()
    };
    let presentation = sdjwt::new_presentation(claims, sd_strategy, claims_to_disclose).unwrap();

    sdjwt::explain(&presentation);
    println!("{}", "-".repeat(100));

    // Just checking correctness (of the presentation and the claim extraction algorithm)
    sdjwt::verify_presentation_lib(presentation.clone()).unwrap();
    sdjwt::verify_extract_claim(&presentation, "given_name").unwrap();

    // Setup prover and load key material
    println!("Loading zkey ...");
    let zkey_path = "zkey/sdjwt_es256_sha256_1claim.zkey";
    let t0 = Instant::now();
    let prover = MultiuseProver::new(zkey_path).unwrap();
    print_execution_time("ZKey loading finished", t0);

    // We test with hard coded issuer public key. In the long run this likely gets more complex.
    let issuer_pk = pem::parse(&crate::sdjwt::ISSUER_PUBLIC).unwrap();
    let issuer_pk = issuer_pk.contents();
    let issuer_pk = &issuer_pk[issuer_pk.len() - 65..];
    assert_eq!(issuer_pk[0], 0x04);
    let issuer_pk: [u8; 64] = issuer_pk[1..].try_into().unwrap();

    // Build the input
    let t0 = Instant::now();
    let input = presentation2input(&presentation, issuer_pk);
    let input = [
        ("in".to_owned(), input.input),
        ("value".to_owned(), input.value),
    ];
    print_execution_time("Input preparation finished", t0);

    println!("INFO: Generating witness ...");
    let t0 = Instant::now();
    let wit = witness::sdjwtes256sha2561claim_witness(input);
    print_execution_time("Witness generation finished", t0);

    println!("INFO: Generating proof ...");
    let t0 = Instant::now();
    let proof = prover.prove_noverify(wit).unwrap();
    print_execution_time("Proof generation finished", t0);

    println!("INFO: Verifying proof ...");
    let t0 = Instant::now();
    let valid = prover.verify(&proof).unwrap();
    print_execution_time("Proof verification finished", t0);

    // Print the output in a more useful form
    let pub_input_bytes: Vec<u8> = proof
        .pub_input
        .iter()
        .skip(1)
        .take(MAX_VALUE_BYTES)
        .map(|v| v.try_into().unwrap_or(255))
        .collect();
    let pub_input_str = String::from_utf8_lossy(&pub_input_bytes);
    println!("Value (from pub_input): {pub_input_str}");
    if valid {
        println!("Proof is valid");
    } else {
        println!("Proof is NOT valid");
    }

    assert!(valid);
}

fn print_execution_time(msg: &str, start: Instant) {
    let d = start.elapsed();
    println!(
        "INFO: {msg} {}.{:03} seconds",
        d.as_secs(),
        d.subsec_millis()
    );
}

fn bebytes2limbs(coord: &[u8]) -> Vec<BigInt> {
    assert_eq!(coord.len(), 32);
    let mut limbs = Vec::new();
    let mut n = BigInt::from_bytes_be(num_bigint::Sign::Plus, coord); // or from_bytes_le depending on circom convention
    let mask = (BigInt::from(1u64) << 43) - 1u64;
    for _ in 0..6 {
        limbs.push((&n & &mask).into());
        n >>= 43;
    }
    limbs
}

// Returns the bytes with sha256 padding to the next 512-bit block, then padded to
// max_padded_len*8. Second return value is the Size in bits before that second padding, as that is
// what we need to pass to the circuit.
fn str2binary_sha2padding(s: &str, max_padded_len: usize) -> (Vec<BigInt>, usize) {
    // Sanity check, the sha256 dependency requires a multiple of 512 bits for the max size.
    assert!(max_padded_len % 64 == 0);
    // Make sure the data actually fits
    assert!(s.len() * 8 + 1 + 64 <= max_padded_len * 8);

    let mut out = Vec::with_capacity(max_padded_len * 8);

    // The data (as bits), sadly terrible in terms of memory allocation but that's nothing I can
    // change.
    for c in s.bytes() {
        for b in 0..8u8 {
            let bit = (c >> (7 - b)) & 1;
            out.push(bit.into())
        }
    }

    let input_bits = s.len() * 8;
    // input_bits + 1 + padding_bits + 64 == n*512
    let padding_bits = (512 - (input_bits + 1 + 64) % 512) % 512;
    // let padding_bits = 0usize.wrapping_sub(input_bits + 1 + 64) % 512;

    // Sha2 padding:
    // Always one '1' bit, followed by '0' bits as padding, finished with a 64-bit big endian
    // containing the original length
    out.push(1.into());
    for _ in 0..padding_bits {
        out.push(0.into());
    }
    for i in 0..64 {
        let bit = (input_bits >> (63 - i)) & 1;
        out.push(bit.into());
    }

    // Sanity check to make sure our padding isn't compltely wrong.
    let sha2padded_bits = out.len();
    assert!(sha2padded_bits % 512 == 0);

    // Set the remaining inputs to 0, they don't matter but we need to fill max length.
    out.resize(max_padded_len * 8, 0.into());

    (out, sha2padded_bits)
}

fn zeropad_str(s: &str, len: usize) -> Vec<BigInt> {
    assert!(s.len() <= len);
    let mut out = vec![0.into(); len];
    for (i, b) in s.as_bytes().iter().enumerate() {
        out[i] = (*b).into()
    }
    out
}
