#[tokio::main]
async fn main() {
    let script_path = std::env::args().nth(1).unwrap();
    eudi2web3::publish::cardano::deploy(&script_path).await;
}
