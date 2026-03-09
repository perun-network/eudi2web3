use axum::{
    Form, Json, Router, body,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use bhx5chain::X509Trust;
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, de::value};
use serde_json::json;
use sha2::Digest as _;

use crate::sdjwt::{ISSUER_PRIVATE, ISSUER_PUBLIC};

pub fn build_router() -> Router {
    Router::new()
        .route("/request", post(request_proof))
        .route("/request_jwt", post(request_jwt))
        .route("/auth", post(auth))
}

#[derive(Debug, Deserialize)]
struct RequestData {
    addr: String,
}

const DOMAIN: &str = "eudi2web3.erdstall.dev";

/// Submit the address as the first step (will request a credential presentation)
async fn request_proof(Json(data): Json<RequestData>) -> impl IntoResponse {
    dbg!(data);

    // Requirements: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2-2.2
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();

    //  credentials[].meta.vct_values contains a list of allowed credential types,
    //  see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.5
    let dcql = serde_json::to_string(&json!({
        "credentials": [{
            "id": "0",
            "format": "dc+sd-jwt",
            "meta": {
                "vct_values": ["urn:eudi:pid:1"]
            },
            "claims": [
                {"path": ["given_name"]}
            ]

        }]
    }))
    .unwrap();
    let dcql = urlencoding::encode(&dcql);

    let client_id = format!("https://{DOMAIN}/auth");
    let client_id = urlencoding::encode(&client_id);

    // Specification: https://openid.net/specs/openid-connect-core-1_0-31.html#SelfIssuedRequest
    //  - REQUIRED scope: https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes#standard-claims
    //  - REQUIRED response_type: vp_token tells the wallet we want a verifiable presentation
    //  - REQUIRED client_id: Probably the unique identifier for the request, useful for the server
    //
    // Added/Changed by https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request
    //  - REQUIRED dcql_query XOR scope
    //  - REQURIED nonce
    //  - REQUIRED client_id
    //  - Somtimes required state
    let url = format!(
        // "openid-vp://?presentation_request_uri=https://127.0.0.1:8080/presentation_request/{}",
        // binding_id
        // "openid-vp://?presentation_request={request}",
        // IMPORTANT: The x509_hash is not mine, it is random (for testing)
        "\
openid4vp://{DOMAIN}/auth?\
client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb&\
response_type=vp_token&\
response_mode=direct_post&\
nonce={nonce}&\
dcql_query={dcql}"
    );
    // client_id=x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk&\
    // client_id=redirect_uri:https://example.com&\
    //
    // openid4vp://eudi2web3.erdstall.dev/auth?client_id=redirect_uri:https://example.com&response_type=vp_token&response_mode=direct_post&nonce=YYlLQppRsJvMzPH2UVR1&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%220%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%2C%22meta%22%3A%7B%22vct_values%22%3A%5B%22urn%3Aeudi%3Apid%3A1%22%5D%7D%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22given_name%22%5D%7D%5D%7D%5D%7D

    let request_endpoint = format!("https://{DOMAIN}/api/request_jwt");
    let request_endpoint = urlencoding::encode(&request_endpoint);

    let url = format!(
        "\
openid4vp://{DOMAIN}/auth?\
client_id=x509_hash%3ALTHlBmrN6Wc9oE3TxFZp47fET6iFBQIiwMJiu3BLcqw&\
request_uri={request_endpoint}&\
request_uri_method=post"
    );

    (StatusCode::OK, url)
}

#[derive(Deserialize)]
struct WalletRequest {
    wallet_nonce: String,
}

async fn request_jwt(Form(w): Form<WalletRequest>) -> impl IntoResponse {
    // The wallet wants the certificate chain as base64 encoded DER. It probably can't be
    // self-signed. Easiest (+ recommended) way I've found was to use the TLS certificate.
    let certs =
        std::fs::read_to_string("/etc/letsencrypt/live/eudi2web3.erdstall.dev/fullchain.pem")
            .unwrap();
    let certs = pem::parse_many(certs).unwrap();

    // Compute the x509_hash value (for client_id)
    // > MUST be a hash and match the hash of the leaf certificate passed with the request. [...]
    // > The value of x509_hash is the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate.
    let x509_hash = sha2::Sha256::digest(certs[0].contents());
    let x509_hash = BASE64_URL_SAFE_NO_PAD.encode(&x509_hash);

    // Encode certificates for the header (we could probably skip the re-encoding by not using the
    // pem dependency).
    let certs = certs
        .iter()
        .map(|p| BASE64_URL_SAFE_NO_PAD.encode(p.contents()))
        .collect();

    // The certificate chain must be in the JWT header
    let header = jsonwebtoken::Header {
        typ: Some("oauth-authz-req+jwt".to_string()),
        alg: jsonwebtoken::Algorithm::ES256,
        x5c: Some(certs),
        ..jsonwebtoken::Header::default()
    };

    // The JWT must be signed with the private key from that certificate chain
    let privkey =
        std::fs::read("/etc/letsencrypt/live/eudi2web3.erdstall.dev/privkey.pem").unwrap();
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(&privkey).unwrap();

    let body = json!({
        "response_uri": format!("https://{DOMAIN}/auth"),
        "client_id": format!("x509_hash:{x509_hash}"),
        "response_mode": "direct_post.jwt",
        "response_type": "vp_token",
        "wallet_nonce": w.wallet_nonce,
        "dcql_query": {
            "credentials": [
                {
                    "id": "query_0",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": [
                            "urn:eudi:pid:1"
                        ]
                    },
                    "claims": [
                        {
                            "path": [
                                "given_name"
                            ]
                        }
                    ]
                }
            ]
        },
    });
    let jwt = jsonwebtoken::encode(&header, &body, &key).unwrap();
    (StatusCode::OK, jwt)
}

/// Endpoint to receive the credential
///
/// See https://openid.net/specs/openid-connect-core-1_0.html
async fn auth() {
    dbg!("auth");
}
