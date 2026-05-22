#[tokio::main]
async fn main() {
    if let Err(error) = xray_bench::run_cli(std::env::args()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
