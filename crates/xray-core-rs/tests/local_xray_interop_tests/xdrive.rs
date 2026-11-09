//! VLESS over XDRIVE against Xray-core v26.10.31's own XDRIVE server, the
//! two meeting in a `local` folder: TCP and UDP of both families through
//! Mux.Cool, VLESS encryption with X25519 and ML-KEM-768 authentication,
//! and sessions cut into many small segments.
//!
//! Targets are documentation addresses: Xray's server hands each flow to a
//! freedom outbound whose redirect sends it to the loopback echo servers,
//! keeping the port.
use super::masque::{core, echo_servers, tcp_echo, udp_echo, ECHO_V4, ECHO_V6};
use super::*;
use serde_json::{json, Value};

/// Fast polling on both ends keeps each exchange in milliseconds.
fn tuning() -> Value {
    json!({"flushIntervalMs": 5, "pollIntervalMs": 5, "maxPollIntervalMs": 50,
        "sessionTtlSeconds": 30})
}

/// The Xray-core binary under test: the one the check script built, or a
/// fresh build of the checkout.
fn xray_binary(checkout: &Path, temp_dir: &TempDir) -> PathBuf {
    env::var_os("XRAY_VLESS_FULL_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let binary = temp_dir
                .path
                .join(format!("xray{}", env::consts::EXE_SUFFIX));
            let output = Command::new("go")
                .args(["build", "-o"])
                .arg(&binary)
                .arg("./main")
                .current_dir(checkout)
                .output()
                .expect("start go build for Xray-core");
            assert!(
                output.status.success(),
                "go build ./main failed: {output:?}"
            );
            binary
        })
}

/// A fresh `xray vlessenc` pair, `(decryption, encryption)`, for X25519 or
/// ML-KEM-768 authentication.
fn vlessenc(binary: &Path, ml_kem: bool) -> (String, String) {
    let output = Command::new(binary)
        .arg("vlessenc")
        .output()
        .expect("run xray vlessenc");
    assert!(output.status.success(), "xray vlessenc failed: {output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let section = text
        .split("Authentication: ")
        .find(|section| section.starts_with(if ml_kem { "ML-KEM-768" } else { "X25519" }))
        .expect("an authentication section");
    let value = |key: &str| {
        section
            .lines()
            .find_map(|line| line.strip_prefix(&format!("\"{key}\": \"")))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("no {key} in {section}"))
            .to_owned()
    };
    (value("decryption"), value("encryption"))
}

struct Session {
    server: XrayServer,
    folder: PathBuf,
    encryption: String,
}

/// Xray-core's VLESS inbound over XDRIVE in `folder`, with `decryption`, and
/// a freedom outbound redirected to the loopback.
async fn start_server(ml_kem: bool) -> Session {
    let checkout = resolve_xray_checkout();
    let temp_dir = create_temp_dir("xray-rust-xdrive-interop");
    let binary = xray_binary(&checkout, &temp_dir);
    let (decryption, encryption) = vlessenc(&binary, ml_kem);
    let folder = temp_dir.path.join("drive");
    let config_path = temp_dir.path.join("server.json");
    let stdout_path = temp_dir.path.join("xray.stdout.log");
    let stderr_path = temp_dir.path.join("xray.stderr.log");
    let mut xdrive = tuning();
    xdrive["service"] = "local".into();
    xdrive["remoteFolder"] = folder.to_str().unwrap().into();
    // XDRIVE binds no socket: the port only names the inbound.
    let port = allocate_loopback_port();
    let config = json!({
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless", "tag": "xdrive-in",
            "settings": {"clients": [{"id": TEST_UUID}], "decryption": decryption},
            "streamSettings": {"network": "xdrive", "xdriveSettings": xdrive}
        }],
        // A VLESS inbound's freedom blocks private targets unless told.
        "outbounds": [
            {"tag": "direct", "protocol": "freedom",
                "settings": {"redirect": "127.0.0.1:0", "finalRules": [{"action": "allow"}]}}
        ]
    });
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
        .spawn()
        .expect("start xray process");
    wait_for_xray_startup(&mut child, &stdout_path, &stderr_path).await;
    Session {
        server: XrayServer {
            child,
            _temp_dir: temp_dir,
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            stdout_path,
            stderr_path,
            tls_client_config: None,
        },
        folder,
        encryption,
    }
}

/// Our client: a SOCKS inbound and VLESS with encryption and Mux over
/// XDRIVE in the server's folder, with `xdrive` merged into its settings.
fn client_config(session: &Session, xdrive: Value) -> Value {
    let mut settings = tuning();
    settings["service"] = "local".into();
    settings["remoteFolder"] = session.folder.to_str().unwrap().into();
    for (key, value) in xdrive.as_object().unwrap() {
        settings[key] = value.clone();
    }
    json!({
        "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": 0,
            "settings": {"udp": true}}],
        "outbounds": [{"tag": "xdrive", "protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": 443, "id": TEST_UUID,
                "encryption": session.encryption},
            "streamSettings": {"network": "xdrive", "xdriveSettings": settings},
            "mux": {"enabled": true, "concurrency": 8, "xudpConcurrency": 8,
                "xudpProxyUDP443": "allow"}}]
    })
}

async fn check(
    server: &XrayServer,
    case: &str,
    run: impl std::future::Future<Output = std::io::Result<()>>,
) {
    eprintln!("XDRIVE {case}");
    let result = timeout(Duration::from_secs(60), run).await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{case}: {result:?}; {}",
        server.logs()
    );
}

/// Sessions Xray-core's server took, by its log.
fn accepted_sessions(server: &XrayServer) -> usize {
    server.logs().matches("accepted session ").count()
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_local_carries_tcp_and_udp_through_mux() {
    let session = start_server(false).await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let mut core = core(client_config(&session, json!({}))).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(server, "TCP over IPv4", tcp_echo(proxy, ECHO_V4, tcp_port)).await;
    check(server, "TCP over IPv6", tcp_echo(proxy, ECHO_V6, tcp_port)).await;
    check(server, "UDP over IPv4", udp_echo(proxy, ECHO_V4, udp_port)).await;
    check(server, "UDP over IPv6", udp_echo(proxy, ECHO_V6, udp_port)).await;
    check(server, "eight parallel TCP flows", async {
        let flows = (0..8).map(|_| tcp_echo(proxy, ECHO_V4, tcp_port));
        for result in futures_util::future::join_all(flows).await {
            result?;
        }
        Ok(())
    })
    .await;
    // Mux carries the flows on a few sessions, not one each.
    let sessions = accepted_sessions(server);
    assert!(
        (1..=4).contains(&sessions),
        "{sessions} sessions for twelve flows: {}",
        server.logs()
    );
    core.stop().await.unwrap();
    // The server reads and deletes every segment the client stored.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let leftover = uplink_segments(&session.folder);
        if leftover == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{leftover} uplink segments were never read: {}",
            server.logs()
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_local_takes_ml_kem_and_many_small_segments() {
    let session = start_server(true).await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    // 128 KiB echoes cut into 4 KiB segments, two stored at a time.
    let mut core = core(client_config(
        &session,
        json!({"segmentBytes": 4096, "concurrency": 2}),
    ))
    .await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(
        server,
        "ML-KEM TCP in small segments",
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    check(server, "ML-KEM UDP", udp_echo(proxy, ECHO_V6, udp_port)).await;
    core.stop().await.unwrap();
}

/// `.seg` files still waiting under every session's `c2s`.
fn uplink_segments(folder: &Path) -> usize {
    let Ok(sessions) = fs::read_dir(folder.join("streams")) else {
        return 0;
    };
    sessions
        .filter_map(Result::ok)
        .filter_map(|session| fs::read_dir(session.path().join("c2s")).ok())
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".seg"))
        .count()
}
