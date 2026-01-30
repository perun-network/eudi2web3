use std::collections::HashMap;

use bh_jws_utils::{Es256Signer, Es256Verifier, SignerWithChain};
use bhmdoc::{
    Device, DeviceKey, Issuer,
    models::{
        Claims, DateTime, DeviceRequest, DocRequest,
        data_retrieval::{common::DocType, device_retrieval::issuer_auth::ValidityInfo},
    },
};
use bhx5chain::X5Chain;
use rand::thread_rng;
use serde_json::json;

const DOCUMENT_TYPE_PID: &str = "eu.europa.ec.eudi.pid.1";

pub fn explore() {
    // See https://eudi.dev/1.7.0/annexes/annex-3/annex-3.01-pid-rulebook/
    // NOTE: Mandatory attributes SHOULD be added. So when we get a credential it might not contain
    // them.
    let mut pid = HashMap::new();
    pid.insert("family_name".into(), "Stormblessed".into());
    pid.insert("given_name".into(), "Kaladin".into());
    pid.insert("birth_date".into(), "2000-01-01T00:00:00Z".into());
    pid.insert("birth_place".into(), "Alethkar".into());
    pid.insert("nationality".into(), "AL".into());
    let mut name_spaces = HashMap::new();
    name_spaces.insert(DOCUMENT_TYPE_PID.into(), pid);

    let signer = Es256Signer::generate("foo".to_owned()).unwrap();
    let device_key = signer.public_jwk().unwrap();
    let device_key = DeviceKey::from_jwk(&device_key).unwrap();
    let chain = bhx5chain::Builder::dummy()
        .generate_x5chain(&signer.public_key_pem().unwrap(), None)
        .unwrap();
    let signer = SignerWithChain::new(signer, chain).unwrap();

    let doc = Issuer
        .issue(
            DocType(DOCUMENT_TYPE_PID.to_owned()),
            Claims(name_spaces),
            device_key,
            &signer,
            &mut thread_rng(),
            ValidityInfo::new(
                0u64.try_into().unwrap(),
                0u64.try_into().unwrap(),
                100u64.try_into().unwrap(),
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();

    let device = Device::verify_issued(
        &doc.serialize_issuer_signed().unwrap(),
        DOCUMENT_TYPE_PID.into(),
        50,
        |_| Some(&Es256Verifier),
    )
    .unwrap();

    let request = DeviceRequest::new(vec![
        DocRequest::builder(DOCUMENT_TYPE_PID.into())
            .add_name_space(
                DOCUMENT_TYPE_PID.into(),
                HashMap::from([("given_name".into(), false.into())]),
            )
            .build(),
    ]);
    let response = device
        .present(
            51,
            &request,
            "client_id",
            "response_uri",
            "nonce",
            "mdoc_generated_nonce",
            &signer,
        )
        .unwrap();
    let token = response.to_base64_cbor().unwrap();
    dbg!(&token);
}
