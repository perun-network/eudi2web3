use std::ffi::{CStr, c_char, c_void};
use std::{fs::File, io::Write};

use ark_bn254::{Bn254, G1Affine};
use ark_ec::pairing::Pairing as _;
use ark_ec::{bls12::Bls12, bn::Bn};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalDeserialize;
use circom_prover::prover::{ark_circom, arkworks::verify_circom_proof};
use num_bigint::BigInt;
use prover::MultiuseProver;
use sha2::Digest as _;
use witness::sdjwtes256sha2561claim_witness;
use wtns_file::WtnsFile;

// Generated code to go from input to witness.
mod witness {
    rust_witness::witness!(dlpexample);
    // rust_witness::witness!(sdjwt_es256_sha256_1claim);
    rust_witness::witness!(sdjwtes256sha2561claim);
}

mod mdoc;
mod prover;
mod sdjwt;

// Functions rust_witness normally implements as a NOP.
mod runtime {
    use std::ffi::{CStr, c_char, c_void};

    #[unsafe(no_mangle)]
    #[allow(non_snake_case)]
    extern "C" fn runtime__exceptionHandler(_arg: *const c_void) {
        eprintln!(
            "runtime__exceptionHandler called, don't know which circuit or how to parse the argument"
        );
    }

    #[unsafe(no_mangle)]
    #[allow(non_snake_case)]
    extern "C" fn runtime__printErrorMessage(_arg: *const c_void) {
        eprintln!(
            "runtime__printErrorMessage called, don't know which circuit or how to parse the argument"
        );
    }

    #[unsafe(no_mangle)]
    #[allow(non_snake_case)]
    extern "C" fn circuit_runtime__exceptionHandler(
        circuit_name: *const c_char,
        _arg: *const c_void,
    ) {
        // SAFETY: Our codegen always sets this to a const string.
        let circuit_name = unsafe { CStr::from_ptr(circuit_name) };
        let circuit_name = circuit_name.to_string_lossy();
        eprintln!("[{circuit_name}] exceptionHandler called")
    }

    #[unsafe(no_mangle)]
    #[allow(non_snake_case)]
    extern "C" fn circuit_log_signal(
        circuit_name: *const c_char,
        _instance: *const c_void,
        len: u32,
        data: *const u32,
    ) {
        // SAFETY: Our codegen always sets this to a const string.
        let circuit_name = unsafe { CStr::from_ptr(circuit_name) };
        let circuit_name = circuit_name.to_string_lossy();
        // SAFETY: Our codegen always sets this to a pointer to the stack (even if len==0)
        let data = unsafe { std::slice::from_raw_parts(data, len as usize) };

        let value = num_bigint::BigUint::from_slice(data);

        eprintln!("[{circuit_name}] {value}");
    }
    // See https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/test/circuit2/circuit_js/witness_calculator.cjs#L44
    #[unsafe(no_mangle)]
    #[allow(non_snake_case)]
    extern "C" fn circuit_log_message(
        circuit_name: *const c_char,
        _instance: *const c_void,
        _typ: u32,
        message: *const c_char,
    ) {
        // SAFETY: Our codegen always sets this to a const string.
        let circuit_name = unsafe { CStr::from_ptr(circuit_name) };
        let circuit_name = circuit_name.to_string_lossy();
        // SAFETY: Our codegen always gives us a valid pointer to the stack, with 0 at the end.
        let message = unsafe { CStr::from_ptr(message) };
        let message = message.to_string_lossy();
        let message = message.strip_suffix('\n').unwrap_or(&message);
        if message.len() > 0 {
            eprintln!("[{circuit_name}] {message}");
        }
    }
}

fn main() {
    let credential = sdjwt::explore();

    println!();
    println!("{}", "-".repeat(64));
    println!();

    mdoc::explore();

    println!();
    println!("{}", "-".repeat(64));
    println!();

    /////////////////////////////////////////////////////////////////////////////////////
    // Test circuit
    /////////////////////////////////////////////////////////////////////////////////////

    // let zkey_path = "zkey/dlpexample.zkey";
    // let prover = MultiuseProver::new(zkey_path).unwrap();
    let witness = witness::dlpexample_witness([
        ("a".to_owned(), vec![3.into()]),
        ("b".to_owned(), vec![7.into()]),
    ]);
    dbg!(&witness);
    // let (proof, valid) = prover.prove(witness).unwrap();
    // dbg!(&proof, valid);
    // assert!(valid);

    println!();
    println!("{}", "-".repeat(64));
    println!();

    /////////////////////////////////////////////////////////////////////////////////////
    // PoC circuit
    /////////////////////////////////////////////////////////////////////////////////////

    // let zkey_path = "zkey/sdjwt_es256_sha256_1claim.zkey";
    // let prover = MultiuseProver::new(zkey_path).unwrap();

    // Test with hard coded issuer public key.
    let key = pem::parse(&crate::sdjwt::ISSUER_PUBLIC).unwrap();
    let key = key.contents();
    let key = &key[key.len() - 65..];
    assert_eq!(key[0], 0x04);

    // Get the relevant data from the credential to pass to input
    let mut segments = credential.split('~');
    let (message, sig) = segments
        .next()
        .expect("At least one segment")
        .rsplit_once('.')
        .expect("header.body.sig");

    // Configuration of the circuit
    const MAX_PAYLOAD_BYTES: usize = 1024;

    // Build the input
    // IMPORTANT: rust_witness fails silently if any input signal is missing, setting all
    // intermediate and output signals to 0.
    let pk_x = bytes_to_limbs(&key[1..1 + 32]);
    let pk_y = bytes_to_limbs(&key[1 + 32..]);
    let sig_r = [1, 2, 3, 4, 5, 6].into_iter().map(|v| v.into()).collect();
    let sig_s = [7, 8, 9, 1, 2, 3].into_iter().map(|v| v.into()).collect();
    let (payload, payload_padded_len) = str2binary_sha2padding(message, MAX_PAYLOAD_BYTES);
    let payload_len = vec![payload_padded_len.into()];
    dbg!(&payload_len);
    let input = [(
        "in".into(),
        [pk_x, pk_y, sig_r, sig_s, payload, payload_len]
            .into_iter()
            .flatten()
            .collect(),
    )];
    let wit = witness::sdjwtes256sha2561claim_witness(input);
    let mut f = std::fs::File::create("./witness.txt").unwrap();
    for (i, v) in wit.iter().enumerate() {
        writeln!(f, "{i:08}: {v}").unwrap();
    }
    f.flush().unwrap();
    drop(f);

    let prime = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
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
    let mut f = std::fs::File::create("witness.wtns").unwrap();
    wtns_file.write(&mut f).unwrap();
    f.flush().unwrap();
    drop(f);

    dbg!(wit.len());
    dbg!(&wit[..10.min(wit.len())]);
    // dbg!(&witness[..(1 + 256)]);
    // dbg!(&witness[(1+256+)..()]);

    let expected: [u8; 32] = sha2::Sha256::digest(message).into();
    dbg!(expected);

    // let (proof, valid) = prover.prove(witness).unwrap();
    // dbg!(&proof);
    // assert!(valid);

    // let x = circom_prover::CircomProver::prove(
    //     circom_prover::prover::ProofLib::Arkworks,
    //     circom_prover::witness::WitnessFn::RustWitness(witness::sdjwtes256sha2561claim_witness),
    //     r"{}".to_owned(),
    //     "zkey_tmp/sdjwt_es256_sha256_1claim.zkey".to_owned(),
    // )
    // .unwrap();
    // dbg!(x);
}

fn bytes_to_limbs(coord: &[u8]) -> Vec<BigInt> {
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

    dbg!(
        s.len(),
        input_bits,
        padding_bits,
        input_bits + 1 + padding_bits + 64
    );

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
