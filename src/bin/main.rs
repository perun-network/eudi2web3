#[tokio::main]
async fn main() {
    eudi2web3::init_tracing();
    eudi2web3::run_server().await;
}
