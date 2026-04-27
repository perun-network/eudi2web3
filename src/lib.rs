use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, atomic::AtomicU64},
    time::Instant,
};

use base64::{
    Engine as _,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use crossbeam::channel::Receiver;
use num_bigint::{BigInt, BigUint};
use num_traits::cast::ToPrimitive;
use prover::{MultiuseProver, ProofWithPubInput};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::net::{TcpListener, UnixListener};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    prover::{Prover, SnarkjsProver},
    witness::{CircuitEntry, CircuitId, CircuitParams},
};

// Generated code to go from input to witness.
mod witness;

pub mod publish {
    pub mod cardano;
}
mod prover {
    use anyhow::Result;
    use num_bigint::BigInt;

    mod common;
    mod multiuse;
    mod snarkjs;

    pub use common::{ProofWithPubInput, SnarkjsProof};
    pub use multiuse::MultiuseProver;
    pub use snarkjs::SnarkjsProver;

    pub trait Prover: std::fmt::Debug + Send + Sync {
        fn verify(&self, proof: &ProofWithPubInput) -> Result<bool>;
        /// It is up to the prover implementation whether this verifies the proof.
        fn prove_noverify(&self, witness: Vec<BigInt>) -> Result<ProofWithPubInput>;
        #[allow(unused)]
        fn prove(&self, witness: Vec<BigInt>) -> Result<(ProofWithPubInput, bool)> {
            let proof = self.prove_noverify(witness)?;
            let valid = self.verify(&proof)?;

            Ok((proof, valid))
        }
    }
}

mod keyfinder;
mod routes;

#[cfg(test)]
mod sdjwt;

#[cfg(test)]
mod test;

// Configuration of the circuit (must be the same as in the circom file),
// only contains values that are the same for all circuits, the others are defined in
// witness::circuit_params.
const MAX_VALUE_SIGNALS: usize = 2;
const MAX_VALUE_BYTES: usize = MAX_VALUE_SIGNALS * 31; // Output value

const ISSUER_PUBLIC: &[u8] = b"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw7JAoU/gJbZJvV+zCOvU9yFJq0FN
C/edCMRM78P8eQTBCDUTK1ywSYaszvQZvneiW6gNtWEJndSreEcyyUdVvg==
-----END PUBLIC KEY-----
";

// https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/tree/4826899e09dcfc17d1aac792ca2759eba0106d5d/resources-logic/src/main/res/raw
#[allow(unused)]
const ISSUER_CA_UT02: &[u8] = b"
-----BEGIN CERTIFICATE-----
MIIC3TCCAoOgAwIBAgIUEwybFc9Jw+az3r188OiHDaxCfHEwCgYIKoZIzj0EAwMw
XDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAyMS0wKwYDVQQKDCRFVURJ
IFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4X
DTI1MDMyNDIwMjYxNFoXDTM0MDYyMDIwMjYxM1owXDEeMBwGA1UEAwwVUElEIElz
c3VlciBDQSAtIFVUIDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2Ug
SW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEesDKj9rCIcrGj0wbSXYvCV953bOPSYLZH5TNmhTz2xa7VdlvQgQeGZRg
1PrF5AFwt070wvL9qr1DUDdvLp6a1qOCASEwggEdMBIGA1UdEwEB/wQIMAYBAf8C
AQAwHwYDVR0jBBgwFoAUYseURyi9D6IWIKeawkmURPEB08cwEwYDVR0lBAwwCgYI
K4ECAgAAAQcwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5l
dWRpdy5kZXYvY3JsL3BpZF9DQV9VVF8wMi5jcmwwHQYDVR0OBBYEFGLHlEcovQ+i
FiCnmsJJlETxAdPHMA4GA1UdDwEB/wQEAwIBBjBdBgNVHRIEVjBUhlJodHRwczov
L2dpdGh1Yi5jb20vZXUtZGlnaXRhbC1pZGVudGl0eS13YWxsZXQvYXJjaGl0ZWN0
dXJlLWFuZC1yZWZlcmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMDA0gAMEUCIQCe
4R9rO4JhFp821kO8Gkb8rXm4qGG/e5/Oi2XmnTQqOQIgfFs+LDbnP2/j1MB4rwZ1
FgGdpr4oyrFB9daZyRIcP90=
-----END CERTIFICATE-----
";

#[derive(Debug)]
struct CircuitInput {
    input: Vec<BigInt>,
    value: Vec<BigInt>,
}

// Errors that should be shown to the user.
#[derive(Debug, Serialize, Copy, Clone, PartialEq, Eq)]
enum UserError {
    JwtTooLarge,
    HeaderTooLarge,
    ValueTooLarge,
    BadJwtFormat,
    ClaimNotFound,
    UnexpectedSigLen,
    UnknownErrorInvalidProof,
    CircuitNotFound,
    UnsupportedSigAlg,
}

#[derive(Debug)]
enum SigAlg {
    ES256,
}
#[derive(Debug)]
enum HashAlg {
    Sha2_256,
}

// I'm not sure if this is the best layout, given that the last segment will never have an
// sd_index/sd_count. But having those be for the parent would be confusing.
#[derive(Debug)]
#[allow(dead_code)] // For now only printed via Debug
struct PresentationSize {
    sig_alg: SigAlg,
    hash_alg: HashAlg,
    header: usize, // b64(header)
    segments: Vec<SegmentSize>,
}

#[derive(Debug)]
#[allow(dead_code)] // For now only printed via Debug
struct SegmentSize {
    sd_index: usize,
    sd_count: usize,
    length: usize,
    payload_offset: usize,
}

// TODO: This function is a mess.
fn presentation2input(
    params: CircuitParams,
    presentation: &str,
) -> Result<CircuitInput, UserError> {
    // Get the relevant data from the credential to pass to input
    let segments: Vec<&str> = presentation.split('~').collect();
    let (message, sig) = segments
        .first()
        .ok_or(UserError::BadJwtFormat)?
        .rsplit_once('.')
        .ok_or(UserError::BadJwtFormat)?;

    let (header, body) = message.split_once('.').ok_or(UserError::BadJwtFormat)?;
    let sig = BASE64_URL_SAFE_NO_PAD.decode(sig).map_err(|e| {
        dbg!(e);
        UserError::BadJwtFormat
    })?;
    if sig.len() != 64 {
        return Err(UserError::UnexpectedSigLen);
    }

    // For now we consider the issuer to be public data and trusted. In the long term we probably
    // want to verify it against the root certificate(s), and ideally the validity of the
    // certificate chain would be proven by the zk circuit (expensive).
    // TODO: Don't just assume we have a valid chain (ISSUER_CA_UT02)
    // TODO: Ideally prove the chain is valid.
    // For now: Extract the pubkey and assume it is trusted.
    // SECURITY: This is of course not secure.
    let header_json = BASE64_URL_SAFE_NO_PAD.decode(header).map_err(|e| {
        dbg!(header, e);
        UserError::BadJwtFormat
    })?;
    let header_decoded: Header = serde_json::from_slice(&header_json).map_err(|e| {
        dbg!(e);
        UserError::BadJwtFormat
    })?;
    if header_decoded.alg != "ES256" {
        return Err(UserError::UnsupportedSigAlg);
    }
    let sig_alg = SigAlg::ES256;
    let issuer_pk = match header_decoded.x5c.last() {
        Some(leaf_cert) => {
            let der = BASE64_STANDARD.decode(leaf_cert).map_err(|e| {
                dbg!(e);
                UserError::BadJwtFormat
            })?;
            let (_, cert) = X509Certificate::from_der(&der).map_err(|e| {
                dbg!(e);
                UserError::BadJwtFormat
            })?;
            let pk = cert.public_key().subject_public_key.as_ref();
            assert_eq!(pk.len(), 65);
            pk[1..].try_into().unwrap()
        }
        None => {
            let issuer_pk = pem::parse(ISSUER_PUBLIC).unwrap();
            let issuer_pk = issuer_pk.contents();
            let issuer_pk = &issuer_pk[issuer_pk.len() - 65..];
            assert_eq!(issuer_pk[0], 0x04);
            let issuer_pk: [u8; 64] = issuer_pk[1..].try_into().unwrap();
            issuer_pk
        }
    };

    // Find the message offset for the key we are interested in.
    let body_json = BASE64_URL_SAFE_NO_PAD.decode(body).map_err(|e| {
        dbg!(e);
        UserError::BadJwtFormat
    })?;
    // TODO: Cleanup this mess
    let mut pos = keyfinder::find_key_jsonbytes(&body_json, "given_name").map_err(|e| {
        dbg!(e);
        UserError::BadJwtFormat
    })?;
    let mut distance2quote = 0;
    // TODO: This currently does not support any other number of disclosure entries (0 is
    // technically allowed). It is also quite a mess. Probably best to rewrite this such that body
    // is used like a disclosure segment and have it repeat as often as needed.
    let seg0 = segments.get(1).unwrap_or(&"");
    let mut seg0_payload_off = 0;
    let mut seg0_json_align = 0;
    let mut sd_index = 0;
    let mut sd_count = 0;
    let seg0_bytes;
    let value = match &pos {
        Some(pos) => pos.value,
        None => {
            let hash = sha2::Sha256::digest(seg0);
            let hash = BASE64_URL_SAFE_NO_PAD.encode(hash);

            dbg!(&hash);

            // TODO: Circuit does not have proper support for selective disclosure, yet and treaing _sd
            // is too large for the current MAX_VALUE_BYTES. For testing we use "iss" instead if
            // "given_name" is not in the root.
            let arr_pos = keyfinder::find_array_entry_by_str_value(&body_json, "_sd", &hash)
                .map_err(|e| {
                    dbg!(e);
                    UserError::BadJwtFormat
                })?;
            // pos = keyfinder::find_key_jsonbytes(&body_json, "iss")
            //     .map_err(|_| UserError::BadJwtFormat)?;

            dbg!(&pos, &arr_pos);

            match &arr_pos {
                Some(arr_pos) => {
                    sd_index = arr_pos.array_index;
                    sd_count = arr_pos.array_len;
                    pos = Some(arr_pos.pos);

                    // 0 is minified json (: and [ are not included).
                    // We need to subtract an additional character because pos.value_start does not point
                    // at the quote.
                    distance2quote = arr_pos.pos.value_start - arr_pos.pos.key_end_quote - 3;

                    seg0_bytes = BASE64_URL_SAFE_NO_PAD.decode(seg0).map_err(|e| {
                        dbg!(e);
                        UserError::BadJwtFormat
                    })?;

                    let pos2 =
                        keyfinder::find_array_follower_by_str_value(&seg0_bytes, "given_name")
                            .map_err(|e| {
                                dbg!(e);
                                UserError::ClaimNotFound
                            })?;

                    // TODO: Properly handle nested SDs.
                    let pos2 = pos2.unwrap();
                    dbg!(&pos2);

                    seg0_payload_off = (pos2.key_start_quote - 1) / 3 * 4;
                    seg0_json_align = (pos2.key_start_quote - 1) % 3;

                    dbg!(&seg0[seg0_payload_off..]);

                    pos2.value
                }
                None => return Err(UserError::ClaimNotFound),
            }
        }
    };
    let Some(pos) = pos else {
        return Err(UserError::ClaimNotFound);
    };
    // We need the character before the quote to make sure it isn't an escaped quote and thus part
    // of a string.
    let payload_off = header.len() + 1 + (pos.key_start_quote - 1) / 3 * 4;
    let json_align = (pos.key_start_quote - 1) % 3;
    dbg!(
        &pos,
        payload_off,
        json_align,
        distance2quote,
        seg0_payload_off,
        seg0_json_align,
        &value,
        message.len(),
        message,
    );

    let segment_sizes = match segments.len() {
        0 | 1 => unreachable!(), // Checked by code above
        2 => vec![SegmentSize {
            sd_index: 0,
            sd_count: 0,
            length: body.len(),
            payload_offset: payload_off,
        }],
        3 => vec![
            // TODO: If there are no disclosure segments we are lying with this length.
            SegmentSize {
                sd_index,
                sd_count,
                length: body.len(),
                payload_offset: payload_off,
            },
            SegmentSize {
                sd_index: 0,
                sd_count: 0,
                length: seg0.len(),
                payload_offset: seg0_payload_off,
            },
        ],
        _ => unimplemented!("Currently does not support arbitrary disclosure counts"),
    };

    let size = PresentationSize {
        sig_alg,
        hash_alg: HashAlg::Sha2_256, // TODO: Check that in the JWT body.
        header: header.len(),
        segments: segment_sizes,
    };
    // TODO: We probably want to store this in a file or DB so we can see which sizes are actually
    // relevant for improving circuit sizes.
    dbg!(size);

    // Various checks whether the circuit can process this VP
    if sha2padded_len(message.len()) > params.payload {
        return Err(UserError::JwtTooLarge);
    }
    if header.len() > params.header {
        return Err(UserError::HeaderTooLarge);
    }
    if pos.value.len() > MAX_VALUE_BYTES {
        return Err(UserError::ValueTooLarge);
    }

    // TODO: Return a nicer error if the disclosure is larger than params.sdbytes

    // Quick fix for testing with issued credentials (which are not minified)
    let value = format!(" {}", value);
    // let value = pos.value;

    // Build the input
    // IMPORTANT: rust_witness fails silently if any input signal is missing, setting all
    // intermediate and output signals to 0.
    let pk_x = bebytes2limbs(&issuer_pk[..32]);
    let pk_y = bebytes2limbs(&issuer_pk[32..]);
    let sig_r = bebytes2limbs(&sig[..32]);
    let sig_s = bebytes2limbs(&sig[32..]);
    let (payload, payload_padded_len) = str2binary_sha2padding(message, params.payload);
    let (seg0_data, seg0_len) = str2binary_sha2padding(seg0, params.sdbytes);
    Ok(CircuitInput {
        input: [
            pk_x,
            pk_y,
            sig_r,
            sig_s,
            payload,
            vec![payload_padded_len.into()],
            seg0_data,
            vec![
                seg0_len.into(),
                seg0_payload_off.into(),
                seg0_json_align.into(),
            ],
            vec![
                header.len().into(),
                payload_off.into(),
                json_align.into(),
                distance2quote.into(),
            ],
        ]
        .into_iter()
        .flatten()
        .collect(),
        value: zeropad_str(&value, MAX_VALUE_BYTES),
    })
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    x5c: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ParsedPubInput {
    pub value: String,
}

// We could also take this from the input data instead of the witness (after proof gen). That would
// be simpler. But this way we show it can be calculated from the public input (and how).
fn pubinput2parsed(pub_input: &[BigUint]) -> ParsedPubInput {
    // 1 because it includes the "always 1" value
    assert_eq!(pub_input.len(), 1 + MAX_VALUE_SIGNALS);

    ParsedPubInput {
        value: pub_input[1..1 + MAX_VALUE_SIGNALS]
            .iter()
            .map_while(|v| v.to_u32().and_then(char::from_u32))
            .collect(),
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
*/

#[derive(Debug)]
struct AppState {
    /// Incomplete jobs (e.g. still waiting on credential VP)
    pub jobs: tokio::sync::Mutex<HashMapAutokey<Job>>,
    pub queue: crossbeam::channel::Sender<QueuedJob>,
    pub queue_head: AtomicU64,
    /// PERFORMANCE: We may want to separate circuit lookup from storage and use Vec + index in job
    /// storage. Main downside to that is that they are invalidated on restarts, but we currently
    /// don't store jobs permanently either.
    pub circuits: HashMap<CircuitId, CircuitEntry>,
}

// #[derive(Debug)]
// struct ProverEntry {
//     pub compute_witness: fn(Vec<(String, Vec<BigInt>)>) -> Vec<BigInt>,
//     pub prover: Arc<MultiuseProver>,
// }

// // Apparently not ideal, but could be used in the future to lazily load zkeys while having them
// // unloadable.
// impl AppState {
//     pub fn get_or_load_prover(&self, id: &CircuitId<'_>) -> Option<ProverEntry> {
//         let e = self.circuits.get(id)?;
//         // Keep the mutex locked while loading the zkey, that way only one worker will load it.
//         let mut guard = e.prover.lock().unwrap();
//         match &*guard {
//             Some(prover) => Some(ProverEntry {
//                 compute_witness: e.compute_witness,
//                 prover: Arc::clone(prover),
//             }),
//             None => {
//                 let zkey_path = format!(
//                     "zkey/{}/{}.{:04}.zkey",
//                     id.curve, id.circuit, id.contributions_phase2
//                 );
//                 let prover = match MultiuseProver::new(&zkey_path) {
//                     Ok(p) => p,
//                     Err(e) => {
//                         // Drop the mutex before panicking.
//                         drop(guard);
//                         todo!("could not load zkey file: {e:?}");
//                     }
//                 };
//                 let prover = Arc::new(prover);
//                 *guard = Some(prover.clone());
//
//                 Some(ProverEntry {
//                     compute_witness: e.compute_witness,
//                     prover: prover,
//                 })
//             }
//         }
//     }
// }

#[derive(Debug)]
struct HashMapAutokey<T> {
    data: HashMap<u64, T>,
    next: u64,
}

impl<T> Default for HashMapAutokey<T> {
    fn default() -> Self {
        Self {
            data: Default::default(),
            next: 0,
        }
    }
}
impl<T> HashMapAutokey<T> {
    pub fn push(&mut self, value: T) -> u64 {
        let key = self.next;
        self.next += 1;
        self.data.insert(key, value);
        key
    }
}

type JobID = u64;

// TODO: Rename
#[derive(Debug)]
enum Job {
    Partial {
        cardano_addr: String,
        publish: bool,
        circuit: CircuitId,
    },
    // This is not 100% accurate, multiple jobs can end up with the same queue position in here,
    // but that shouldn't matter since it is primarily used for indicating progress in the
    // frontend.
    Queued {
        pos: u64,
    },
    Completed(Box<CompletedJob>), // CompletedJob is significantly larger than the other variants
    Error(UserError),
}

#[derive(Debug)]
struct CompletedJob {
    proof: ProofWithPubInput,
    tx: Option<[u8; 32]>,
}

#[derive(Debug)]
struct QueuedJob {
    id: JobID,
    // TODO: This must be bound in the zk circuit, otherwise the proof could be reused.
    #[allow(unused)]
    cardano_addr: String,
    publish: bool,
    vp_token: String,
    circuit: CircuitId,
}

pub async fn run_server() {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    let mut circuits = witness::get_circuits();

    // TODO: This is not ideal as it blocks the entire API, but I didn't want to bother with lazy loading
    // of the provers, yet.
    println!("Loading {} zkeys ...", circuits.len());
    let t0 = Instant::now();
    for (id, e) in &mut circuits {
        let zkey_path = id.zkey_path();
        let t1 = Instant::now();
        let prover: Box<dyn Prover> = match id.curve.as_str() {
            "bn254" => Box::new(MultiuseProver::new(&zkey_path).unwrap()),
            "bls12381" | "bls12-381" => {
                Box::new(SnarkjsProver::new(zkey_path.clone(), id.curve.clone()).unwrap())
            }
            _ => panic!("Unknown curve"),
        };
        e.prover = Some(prover);
        // Not really useful for bls when SnarkjsProver is used, but I prefer having the full list
        // of circuits logged at startup.
        print_execution_time(&zkey_path, t1);
    }
    print_execution_time("ZKey loading finished", t0);

    let job_queue = crossbeam::channel::unbounded();
    let state = Arc::new(AppState {
        jobs: Default::default(),
        queue: job_queue.0,
        queue_head: 0.into(),
        circuits,
    });

    let workers = std::thread::available_parallelism().unwrap_or(NonZeroUsize::new(2).unwrap());
    start_workers(workers, job_queue.1, state.clone());

    let app = routes::build_router().with_state(state);
    if bind.starts_with('/') {
        let listener = UnixListener::bind(bind).unwrap();
        axum::serve(listener, app).await.unwrap();
    } else {
        let listener = TcpListener::bind(bind).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    };
}

fn start_workers(workers: NonZeroUsize, input: Receiver<QueuedJob>, state: Arc<AppState>) {
    for _ in 0..workers.into() {
        let input = input.clone();
        let state = state.clone();
        let rt = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            while let Ok(job) = input.recv() {
                let Some(circuit) = state.circuits.get(&job.circuit) else {
                    state.update_job_queued(job.id, Job::Error(UserError::CircuitNotFound));
                    continue;
                };

                let t0 = Instant::now();
                let res = compute_proof(circuit, &job);
                print_execution_time("compute_proof finished", t0);
                match res {
                    Ok(proof) if job.publish => {
                        let s = state.clone();
                        rt.spawn(async move {
                            let t0 = Instant::now();
                            let tx = Some(
                                publish::cardano::publish(&job.circuit.cardano_path(), &proof)
                                    .await,
                            );
                            print_execution_time("cardano::publish finished", t0);
                            s.update_job_queued(
                                job.id,
                                Job::Completed(Box::new(CompletedJob { proof, tx })),
                            );
                        });
                    }
                    Ok(proof) => {
                        state.update_job_queued(
                            job.id,
                            Job::Completed(Box::new(CompletedJob { proof, tx: None })),
                        );
                    }
                    Err(err) => {
                        state.update_job_queued(job.id, Job::Error(err));
                        continue;
                    }
                };
            }
        });
    }
}

fn compute_proof(circuit: &CircuitEntry, job: &QueuedJob) -> Result<ProofWithPubInput, UserError> {
    // TODO: The user address should be part of the (public) zk input, otherwise someone could Just
    // copy the proof and use it for their own address.
    dbg!(&job);

    let prover = circuit.prover.as_ref().unwrap();

    // Circuit input format is not compatible, so we report InvalidCircuit, even though we know the
    // circuit itself.
    let params = circuit.params.ok_or(UserError::CircuitNotFound)?;

    // Build the input
    let t0 = Instant::now();
    let input = presentation2input(params, &job.vp_token)?;
    let input = vec![
        ("in".to_owned(), input.input),
        ("value".to_owned(), input.value),
    ];
    print_execution_time(&format!("[{}] Input preparation finished", job.id), t0);

    println!("INFO: Generating witness ...");
    let t0 = Instant::now();
    let wit = (circuit.compute_witness)(input);
    print_execution_time("Witness generation finished", t0);

    println!("INFO: Generating proof ...");
    let t0 = Instant::now();
    let proof = prover.prove_noverify(wit).unwrap();
    print_execution_time("Proof generation finished", t0);

    println!("INFO: Verifying proof ...");
    let t0 = Instant::now();
    let valid = prover.verify(&proof).unwrap();
    print_execution_time("Proof verification finished", t0);

    dbg!(valid);

    if valid {
        Ok(proof)
    } else {
        // Usually happens if there is an assert or constraint in the circuit that isn't detected
        // in advance in the Rust code. We don't get this info earlier because error reporting of
        // rust_witness isn't good (doesn't even exist without modifications).
        Err(UserError::UnknownErrorInvalidProof)
    }
}

impl AppState {
    fn update_job_queued(&self, id: JobID, new: Job) {
        match self.jobs.blocking_lock().data.get_mut(&id) {
            Some(j @ Job::Queued { .. }) => *j = new,
            Some(j) => {
                if cfg!(debug_assertions) {
                    panic!("Unexpected Job state: {j:?}");
                } else {
                    println!(
                        "ERROR: update_job_queued: Unexpected Job state, not writing new state: {j:?}"
                    );
                }
            }
            None => println!("WARN: update_job_queued: Job does not exist"),
        }
    }
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
        limbs.push(&n & &mask);
        n >>= 43;
    }
    limbs
}

fn sha2padded_len(len: usize) -> usize {
    (len + 1 + 8).div_ceil(64) * 64
}

// Returns the bytes with sha256 padding to the next 512-bit block, then padded to
// max_padded_len*8. Second return value is the Size in bits before that second padding, as that is
// what we need to pass to the circuit.
fn str2binary_sha2padding(s: &str, max_padded_len: usize) -> (Vec<BigInt>, usize) {
    // Sanity check, the sha256 dependency requires a multiple of 512 bits for the max size.
    assert!(max_padded_len.is_multiple_of(64));
    // Make sure the data actually fits. Both asserts should check the same thing (esp. since the 1
    // bit always needs 8 bits of space).
    assert!(sha2padded_len(s.len()) <= max_padded_len);
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
