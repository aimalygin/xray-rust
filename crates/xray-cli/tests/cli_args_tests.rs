use std::{fs, net::SocketAddr, path::PathBuf};

use tokio::sync::oneshot;
use xray_cli::{
    format_bound_inbounds, load_config, parse_cli_args, parse_tun_fd_env_from_pairs,
    parse_tun_runtime_options_env_from_pairs, run_cli_with_shutdown, run_with_shutdown, CliArgs,
    CliError,
};
use xray_core_rs::{TunFdClosePolicy, TunFdPacketFormat, TunRuntimeProfile};

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
    let temp_dir =
        std::env::temp_dir().join(format!("xray-cli-invalid-config-{}", std::process::id()));
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

#[test]
fn tun_fd_env_is_absent_without_fd() {
    let config = parse_tun_fd_env_from_pairs([] as [(&str, &str); 0]).unwrap();

    assert!(config.is_none());
}

#[test]
fn tun_fd_env_parses_darwin_utun_fd() {
    let config = parse_tun_fd_env_from_pairs([
        ("XRAY_TUN_FD", "7"),
        ("XRAY_TUN_FD_PACKET_FORMAT", "darwin-utun"),
    ])
    .unwrap()
    .expect("tun fd config");

    assert_eq!(config.fd(), 7);
    assert_eq!(config.packet_format(), TunFdPacketFormat::DarwinUtun);
    assert_eq!(config.close_policy(), TunFdClosePolicy::Borrowed);
}

#[test]
fn tun_fd_env_rejects_unknown_packet_format() {
    let error = parse_tun_fd_env_from_pairs([
        ("XRAY_TUN_FD", "7"),
        ("XRAY_TUN_FD_PACKET_FORMAT", "tun-pi"),
    ])
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("unsupported TUN fd packet format"));
}

#[test]
fn tun_runtime_options_env_parses_profile_and_quic_blocking() {
    let options = parse_tun_runtime_options_env_from_pairs([
        ("XRAY_TUN_PROFILE", "low-memory"),
        ("XRAY_TUN_BLOCK_QUIC", "true"),
        ("XRAY_TUN_COLLECT_TCP_TIMINGS", "true"),
    ])
    .unwrap();

    assert_eq!(options.profile, TunRuntimeProfile::LowMemory);
    assert!(options.block_quic);
    assert!(options.collect_tcp_timings);
}

#[test]
fn tun_runtime_options_env_parses_mobile_plus_profile_aliases() {
    for raw in ["mobile-plus", "mobile_plus", "mobileplus"] {
        let options =
            parse_tun_runtime_options_env_from_pairs([("XRAY_TUN_PROFILE", raw)]).unwrap();

        assert_eq!(options.profile, TunRuntimeProfile::MobilePlus);
    }
}

#[test]
fn tun_runtime_options_env_rejects_unknown_profile() {
    let error =
        parse_tun_runtime_options_env_from_pairs([("XRAY_TUN_PROFILE", "tiny")]).unwrap_err();

    assert!(error
        .to_string()
        .contains("unsupported TUN runtime profile"));
}

#[tokio::test]
async fn run_with_shutdown_starts_and_stops_core() {
    let temp_dir =
        std::env::temp_dir().join(format!("xray-cli-runtime-config-{}", std::process::id()));
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

    assert!(result.is_ok(), "{result:?}");
    let _ = fs::remove_dir_all(temp_dir);
}

#[tokio::test]
async fn run_cli_with_shutdown_rejects_missing_config() {
    let result = run_cli_with_shutdown(["xray-rust", "run", "-config"], async {}).await;

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("missing config path"));
}
