#[tokio::main]
async fn main() {
    #[cfg(unix)]
    if std::env::args().nth(1).as_deref() == Some("protocol-run") {
        let result = xray_bench::protocol_bench::run(std::env::args().skip(2).collect()).await;
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = xray_bench::run_cli(std::env::args()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
