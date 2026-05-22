use std::{fs, net::SocketAddr, path::PathBuf};

use tokio::sync::oneshot;
use xray_cli::{
    format_bound_inbounds, load_config, parse_cli_args, run_cli_with_shutdown, run_with_shutdown,
    CliArgs, CliError,
};

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

#[test]
fn load_config_reports_json_parse_diagnostics() {
    let temp_dir = std::env::temp_dir().join(format!(
        "xray-cli-invalid-config-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let config_path = temp_dir.join("bad.json");
    fs::write(&config_path, "{").unwrap();

    let error = load_config(&config_path).unwrap_err().to_string();

    assert!(error.contains("config parse failed"));
    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn format_bound_inbounds_includes_tag_and_address() {
    let rendered = format_bound_inbounds(&[(
        Some("socks-in".to_owned()),
        "127.0.0.1:1080".parse::<SocketAddr>().unwrap(),
    )]);

    assert_eq!(rendered, "bound inbound socks-in at 127.0.0.1:1080");
}

#[tokio::test]
async fn run_with_shutdown_starts_and_stops_core() {
    let temp_dir = std::env::temp_dir().join(format!(
        "xray-cli-runtime-config-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let config_path = temp_dir.join("client.json");
    fs::write(
        &config_path,
        r#"{
          "inbounds": [
            { "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0 }
          ],
          "outbounds": [
            {
              "tag": "proxy",
              "protocol": "vless",
              "settings": {
                "vnext": [
                  {
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [
                      { "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none" }
                    ]
                  }
                ]
              },
              "streamSettings": { "network": "tcp" }
            }
          ]
        }"#,
    )
    .unwrap();
    let config = load_config(&config_path).unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let result = run_with_shutdown(config, async move {
        shutdown_tx.send(()).unwrap();
        shutdown_rx.await.unwrap();
    })
    .await;

    assert!(result.is_ok());
    let _ = fs::remove_dir_all(temp_dir);
}

#[tokio::test]
async fn run_cli_with_shutdown_rejects_missing_config() {
    let result = run_cli_with_shutdown(["xray-rust", "run", "-config"], async {}).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing config path"));
}
