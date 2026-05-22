use std::path::PathBuf;

use xray_cli::{parse_cli_args, CliArgs, CliError};

#[test]
fn parses_run_dash_config() {
    let args = parse_cli_args(["xray-rust", "run", "-config", "client.json"]).unwrap();

    assert_eq!(
        args,
        CliArgs::Run {
            config_path: PathBuf::from("client.json")
        }
    );
}

#[test]
fn parses_run_double_dash_config() {
    let args = parse_cli_args(["xray-rust", "run", "--config", "client.json"]).unwrap();

    assert_eq!(
        args,
        CliArgs::Run {
            config_path: PathBuf::from("client.json")
        }
    );
}

#[test]
fn rejects_unknown_command() {
    let error = parse_cli_args(["xray-rust", "version"]).unwrap_err();

    assert!(matches!(
        error,
        CliError::InvalidArguments(message) if message.contains("usage:")
    ));
}

#[test]
fn rejects_missing_config_path() {
    let error = parse_cli_args(["xray-rust", "run", "-config"]).unwrap_err();

    assert!(matches!(
        error,
        CliError::InvalidArguments(message) if message.contains("missing config path")
    ));
}
