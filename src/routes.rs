use axum::{Form, Json, Router, http::StatusCode, response::IntoResponse, routing::post};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{Rng, distributions::Alphanumeric};
use serde::Deserialize;
use serde_json::json;
use sha2::Digest as _;

const DOMAIN: &str = "eudi2web3.erdstall.dev";
const REQUEST_CERT: &str = "/var/www/eudi2web3/fubar_cert.pem";
const REQUEST_PRIVKEY: &str = "/var/www/eudi2web3/fubar_privkey.pem";

pub fn build_router() -> Router {
    Router::new()
        .route("/submit_data", post(submit_data))
        .route("/vp_request", post(vp_request))
        .route("/vp_auth", post(vp_auth))
}

#[derive(Debug, Deserialize)]
struct RequestData {
    addr: String,
}

/// Submit the address as the first step (will request a credential presentation)
async fn submit_data(Json(data): Json<RequestData>) -> impl IntoResponse {
    let certs = std::fs::read_to_string(REQUEST_CERT).unwrap();
    let certs = pem::parse_many(certs).unwrap();

    // Compute the x509_hash value (for client_id)
    // > MUST be a hash and match the hash of the leaf certificate passed with the request. [...]
    // > The value of x509_hash is the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate.
    let x509_hash = sha2::Sha256::digest(certs[0].contents());
    let x509_hash = BASE64_URL_SAFE_NO_PAD.encode(&x509_hash);

    let url = format!(
        "\
openid4vp://?\
client_id=x509_hash%3A{x509_hash}&\
request_uri=https%3A%2F%2F{DOMAIN}%2Fapi%2Fvp_request&\
request_uri_method=post"
    );

    (StatusCode::OK, url)
}

#[derive(Deserialize)]
struct WalletRequest {
    wallet_nonce: String,
}

async fn vp_request(Form(w): Form<WalletRequest>) -> impl IntoResponse {
    // The wallet wants the certificate chain as base64 encoded DER. It probably can't be
    // self-signed. Easiest (+ recommended) way I've found was to use the TLS certificate.
    let certs = std::fs::read_to_string(REQUEST_CERT).unwrap();
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
    let privkey = std::fs::read(REQUEST_PRIVKEY).unwrap();
    let key = jsonwebtoken::EncodingKey::from_ec_pem(&privkey).unwrap();

    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let body = json!({
        "response_uri": format!("https://{DOMAIN}/api/vp_auth"),
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
async fn vp_auth(Form(data): Form<AuthData>) -> StatusCode {
    dbg!("auth");
    dbg!(&data);

    let data: VpToken = serde_json::from_str(&data.vp_token).unwrap();
    dbg!(&data.q0);

    StatusCode::OK
}
