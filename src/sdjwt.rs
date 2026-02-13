use std::collections::HashMap;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, EncodingKey};
use ring::signature::ECDSA_P256_SHA256_FIXED;
use sd_jwt_rs::{
    ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat,
    SDJWTVerifier,
};
use serde::Deserialize;
use serde_json::json;
use sha2::Digest as _;

const ISSUER_PRIVATE: &[u8] = b"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWTFfCGljY6aw3Hrt
kHmPRiazukxPLb6ilpRAewjW8nihRANCAATDskChT+Altkm9X7MI69T3IUmrQU0L
950IxEzvw/x5BMEINRMrXLBJhqzO9Bm+d6JbqA21YQmd1Kt4RzLJR1W+
-----END PRIVATE KEY-----
";

pub const ISSUER_PUBLIC: &[u8] = b"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw7JAoU/gJbZJvV+zCOvU9yFJq0FN
C/edCMRM78P8eQTBCDUTK1ywSYaszvQZvneiW6gNtWEJndSreEcyyUdVvg==
-----END PUBLIC KEY-----
";

// Method used to explore SD-JWT credential creation and its format.
// Returns a SD-JWT Presentation
pub fn explore() -> String {
    // let issuer_secret = [0; 32];
    // let issuer_key = EncodingKey::from_secret(&issuer_secret);
    let issuer_key = EncodingKey::from_ec_pem(ISSUER_PRIVATE).unwrap();
    // let mut issuer = SDJWTIssuer::new(issuer_key, Some("HS256".to_owned()));
    let mut issuer = SDJWTIssuer::new(issuer_key, Some("ES256".to_owned()));
    // let mut claims = serde_json::Map::new();
    // claims.insert(
    //     "given_name".to_owned(),
    //     serde_json::Value::String("foobar".repeat(100)),
    // );
    let claims = json!({
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
        "given_name": "foobar",
        "foo": "bar",
        "baz": {
            "hello": "world"
        }
    });
    let sd_jwt = issuer
        .issue_sd_jwt(
            claims,
            // ClaimsForSelectiveDisclosureStrategy::AllLevels,
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.address"]),
            None,
            true,
            // Only seems to affect the outer encoding
            SDJWTSerializationFormat::Compact,
        )
        .unwrap();
    dbg!(&sd_jwt);
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let serde_json::Value::Object(claims_to_disclose) = json!({
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
    let verified_claims = SDJWTVerifier::new(
        presentation.clone(),
        // Box::new(move |_, _| DecodingKey::from_secret(&issuer_secret)),
        Box::new(move |_, _| DecodingKey::from_ec_pem(ISSUER_PUBLIC).unwrap()),
        None,
        None,
        SDJWTSerializationFormat::Compact,
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
    let header = BASE64_URL_SAFE_NO_PAD.decode(header).unwrap();
    let body = BASE64_URL_SAFE_NO_PAD.decode(body).unwrap();
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

        let segment = BASE64_URL_SAFE_NO_PAD.decode(segment).unwrap();
        let segment = String::from_utf8_lossy(&segment);
        dbg!(i, segment);
    }

    let value = verify_extract_claim(&presentation, "given_name");
    assert_eq!(value, Some(serde_json::Value::String("foobar".to_owned())));
    let value = verify_extract_claim(&presentation, "address.country");
    assert_eq!(value, Some(serde_json::Value::String("DE".to_owned())));

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

    presentation
}

// This function roughly showcases how we could implement the "extract a single claim value" with a
// ZK circuit.
//
// Rough input data layout for the ZK circuit:
// - Key/Path length + string (pub)
// - Claim value (pub)
// - Issuer pubkey (pub)
// - signature bytes
// - Various lengths and indicies (could also be part of the data below of course)
// - message (`b64(header).b64(body)`)
// - base64 decoded body (unless calculated during witness generation)
// - base64 encoded segments, sorted in the order they are needed.
// - base64 decoded segments (unless calculated during witness generation)
//
// NOTE: This implementation only supports objects being part of the claim path. Not array
// indicies, though those can be added if required.
fn verify_extract_claim(presentation: &str, claim: &str) -> Option<serde_json::Value> {
    // We do need the issuer public key from somewhere, and it probably has to be in the public
    // input in some form. Convert it to the right format (there are probably better/more reliable ways)
    let key = pem::parse(&ISSUER_PUBLIC).unwrap();
    let key = key.contents();
    let key = &key[key.len() - 65..];

    // Decode outer format (can happen outside of ZK and be passed as lengths).
    // Sadly, the signature is over `header.body`, so we keep them as one for now.
    let mut segments = presentation.split('~');
    let (message, sig) = segments
        .next()
        .expect("At least one segment")
        .rsplit_once('.')
        .expect("header.body.sig");
    let (header, body) = message.split_once('.').unwrap();
    // Collect all disclosure entries and make them easy to find by key. Can happen outside of ZK
    // as long as the ZK circuit checks that the key is correct.
    let segments: HashMap<String, &str> = segments
        .filter_map(|s| {
            if s.len() == 0 {
                return None;
            }
            let disclosure = BASE64_URL_SAFE_NO_PAD.decode(s).unwrap();
            let (_, key, _): (&str, String, serde_json::Value) =
                serde_json::from_slice(&disclosure).expect("invalid json");
            Some((key, s))
        })
        .collect();

    // Make sure it is a supported signature algorithm (can happen outside of ZK)
    let header = BASE64_URL_SAFE_NO_PAD.decode(header).unwrap();
    let header: Header = serde_json::from_slice(&header).unwrap();
    assert_eq!(header.alg, "ES256"); // Could be used for circuit selection if needed.

    // B64 decode the signature (can happen outside of ZK)
    let sig = BASE64_URL_SAFE_NO_PAD.decode(sig).unwrap();
    assert_eq!(sig.len(), 64);

    // Check signature (must happen in ZK)
    let pk = ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key);
    pk.verify(message.as_bytes(), &sig)
        .expect("signature is invalid");

    // B64 decode body (must happen in ZK because we need to verify the decoding matches the
    // signed bytes).
    let body = BASE64_URL_SAFE_NO_PAD.decode(body).unwrap();

    // Chain to the claim data (starting from the JWT body). Can be done outside of ZK, as the
    // order does not matter and is not required.
    // claim.split('.').map(|key| )

    // What data we need (must in some way be part of the public data or hard-coded).
    let mut path = claim.split('.');

    // Decode json and find the data we need. Must happen in ZK, but can get help from the outside.
    let mut current: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let payload = current.as_object().expect("JWT payload is no object");
    assert_eq!(
        payload.get("_sd_alg"),
        Some(&serde_json::Value::String("sha-256".to_owned()))
    );

    loop {
        let key = path.next();
        // dbg!(&key, &current);
        let Some(key) = key else {
            println!("Found the value");
            break;
        };

        let obj = current.as_object().expect("Not an object");

        // Variant 1: Value is always disclosed
        if let Some(value) = obj.get(key) {
            println!("Found always-disclosed value for {key}");
            current = value.clone();
            continue;
        }

        // Variant 2: Selective disclosure
        // 2.1: Get the next segment (note that this might not be the correct one)
        let Some(&seg) = segments.get(key) else {
            println!("No segment with key {key}");
            return None;
        };

        // 2.2: Decode and check key
        let seg_bytes = BASE64_URL_SAFE_NO_PAD.decode(seg).unwrap();
        let (_, k, value): (&str, String, serde_json::Value) =
            serde_json::from_slice(&seg_bytes).expect("invalid json");
        assert_eq!(key, k, "Prover provided wrong segment");

        // 2.3: Compute hash
        let hash = sha2::Sha256::digest(seg);
        let hash = BASE64_URL_SAFE_NO_PAD.encode(hash);

        // 2.4: Make sure this hash is in the list
        let valid = obj
            .get("_sd")
            .expect("_sd not found")
            .as_array()
            .expect("_sd is not an array")
            .contains(&serde_json::Value::String(hash));
        assert!(valid, "Could not find hash in _sd list");

        println!("Found valid Disclosure for {key}");
        current = value;
    }
    Some(current)
}

#[derive(Deserialize)]
struct Header<'a> {
    alg: &'a str,
}
