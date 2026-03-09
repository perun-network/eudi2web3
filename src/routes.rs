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

const DOMAIN: &str = "eudi2web3.erdstall.dev";

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

/// Submit the address as the first step (will request a credential presentation)
async fn request_proof(Json(data): Json<RequestData>) -> impl IntoResponse {
    let request_endpoint = format!("https://{DOMAIN}/api/request_jwt");
    let request_endpoint = urlencoding::encode(&request_endpoint);

    let certs = std::fs::read_to_string("/var/www/eudi2web3/fubar_cert.pem").unwrap();
    let certs = pem::parse_many(certs).unwrap();

    // Compute the x509_hash value (for client_id)
    // > MUST be a hash and match the hash of the leaf certificate passed with the request. [...]
    // > The value of x509_hash is the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate.
    let x509_hash = sha2::Sha256::digest(certs[0].contents());
    let x509_hash = BASE64_URL_SAFE_NO_PAD.encode(&x509_hash);

    let url = format!(
        "\
openid4vp://{DOMAIN}/auth?\
client_id=x509_hash%3A{x509_hash}&\
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
    let certs = std::fs::read_to_string("/var/www/eudi2web3/fubar_cert.pem").unwrap();
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
    let privkey = std::fs::read("/var/www/eudi2web3/fubar_privkey.pem").unwrap();
    let key = jsonwebtoken::EncodingKey::from_ec_pem(&privkey).unwrap();

    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let body = json!({
        "response_uri": format!("https://{DOMAIN}/api/auth"),
        "client_id": format!("x509_hash:{x509_hash}"),
        "response_mode": "direct_post",
        "response_type": "vp_token",
        "wallet_nonce": w.wallet_nonce,
        "nonce": nonce,
        "dcql_query": {
            "credentials": [
                {
                    "id": "q0",
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
        "client_metadata": {
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": [
                        "ES256"
                    ],
                    "kb-jwt_alg_values": [
                        "ES256"
                    ]
                }
            },
        }
    });
    let jwt = jsonwebtoken::encode(&header, &body, &key).unwrap();
    (StatusCode::OK, jwt)
}

#[derive(Debug, Deserialize)]
struct AuthData {
    vp_token: String,
}

#[derive(Debug, Deserialize)]
struct VpToken {
    q0: Vec<String>,
}

/// Endpoint to receive the credential
///
/// See https://openid.net/specs/openid-connect-core-1_0.html
async fn auth(Form(data): Form<AuthData>) -> StatusCode {
    dbg!("auth");
    dbg!(&data);

    let data: VpToken = serde_json::from_str(&data.vp_token).unwrap();
    dbg!(&data.q0);

    StatusCode::OK
}
