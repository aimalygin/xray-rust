#[tokio::main]
async fn main() {
    if let Err(error) = xray_cli::run_cli_with_shutdown(std::env::args(), async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to wait for shutdown signal: {error}");
        }
    })
    .await
    {
        let code = match &error {
            xray_cli::CliError::ConfigCheckFailed { code } => i32::from(*code),
            xray_cli::CliError::InvalidArguments(_) | xray_cli::CliError::Output { .. } => 2,
            _ => 1,
        };
        // A check has already emitted its complete text or JSON report.
        if !matches!(error, xray_cli::CliError::ConfigCheckFailed { .. }) {
            eprintln!("{error}");
        }
        std::process::exit(code);
    }
}
