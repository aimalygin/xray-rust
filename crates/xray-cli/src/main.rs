#[tokio::main]
async fn main() {
    if let Err(error) = xray_cli::run_cli_with_shutdown(std::env::args(), async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to wait for shutdown signal: {error}");
        }
    })
    .await
    {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
