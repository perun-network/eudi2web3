#[tokio::main]
async fn main() {
    eudi2web3::publish::cardano::deploy().await;
}
