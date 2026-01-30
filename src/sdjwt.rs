use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sd_jwt_rs::{
    ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat,
    SDJWTVerifier,
};
use serde_json::json;

// Method used to explore SD-JWT credential creation and its format.
pub fn explore() {
    // Totally unsafe
    let issuer_secret = [0; 32];
    let issuer_key = EncodingKey::from_secret(&issuer_secret);
    let mut issuer = SDJWTIssuer::new(issuer_key, Some("HS256".to_owned()));
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
        "given_name": "foobar".repeat(100),
        "foo": "bar",
        "baz": {
            "hello": "world"
        }
    });
    let sd_jwt = issuer
        .issue_sd_jwt(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
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
        Box::new(move |_, _| DecodingKey::from_secret(&issuer_secret)),
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
}
