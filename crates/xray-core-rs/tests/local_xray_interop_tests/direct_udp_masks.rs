//! FinalMask's UDP masks on the sockets that carry plain datagrams, freedom's
//! flows and WireGuard's, against Xray-core v26.10.31 applying the same masks
//! on its side: a `tunnel` inbound for freedom, the WireGuard inbound for
//! WireGuard. Xray-core's `FinalMask.DialUDP` wraps both client sockets.
use super::masque::{core, echo_servers, socks, tcp_echo, udp_echo};
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

/// A documentation address inside the WireGuard tunnel: Xray-core's freedom
/// redirects it to the loopback echo servers, keeping the port.
const INNER_TARGET: &str = "198.51.100.7";

fn salamander(password: &str) -> Value {
    json!({"type": "salamander", "settings": {"password": password}})
}

fn noise() -> Value {
    json!({"type": "noise", "settings": {"noise": [
        {"type": "str", "packet": "synthetic-noise", "delay": 2},
        {"rand": "16-32", "delay": 1}]}})
}

fn header_custom() -> Value {
    json!({"type": "header-custom", "settings": {"mode": "prefix",
        "client": [{"rand": 8, "capture": "token"}, {"type": "str", "packet": "hello"}],
        "server": [{"reuse": "token"}, {"transform": {"op": "be16", "args": [{"u64": 443}]}}]}})
}

/// The client's request goes alone and holds the first datagram until the
/// server answers it, again five seconds after each answer.
fn standalone() -> Value {
    json!({"type": "header-custom", "settings": {"mode": "standalone",
        "client": [{"rand": 8, "capture": "token"}, {"type": "str", "packet": "hello"}],
        "server": [{"reuse": "token"}, {"type": "str", "packet": "world"}]}})
}

fn sudoku() -> Value {
    json!({"type": "sudoku", "settings": {"password": "synthetic-sudoku"}})
}

/// Xray-core running `config`, once its UDP `port` is bound.
async fn xray(config: Value, port: u16) -> XrayServer {
    let temp_dir = create_temp_dir("xray-direct-udp-masks");
    let config_path = temp_dir.path.join("config.json");
    let stdout_path = temp_dir.path.join("stdout.log");
    let stderr_path = temp_dir.path.join("stderr.log");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let binary = env::var_os("XRAY_VLESS_FULL_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let binary = temp_dir
                .path
                .join(format!("xray{}", env::consts::EXE_SUFFIX));
            let output = Command::new("go")
                .args(["build", "-o"])
                .arg(&binary)
                .arg("./main")
                .current_dir(resolve_xray_checkout())
                .output()
                .expect("start go build for Xray-core");
            assert!(
                output.status.success(),
                "go build ./main failed: {output:?}"
            );
            binary
        });
    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
        .spawn()
        .expect("start xray process");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    wait_for_udp_listener(&mut child, addr, &stdout_path, &stderr_path).await;
    XrayServer {
        child,
        _temp_dir: temp_dir,
        addr,
        stdout_path,
        stderr_path,
        tls_client_config: None,
    }
}

/// Xray-core's `tunnel` inbound on UDP `port` under `masks`, forwarding each
/// datagram to the loopback UDP echo on `echo_port`.
async fn tunnel_server(port: u16, echo_port: u16, masks: &Value) -> XrayServer {
    xray(
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{"protocol": "tunnel", "listen": "127.0.0.1", "port": port,
                "settings": {"address": "127.0.0.1", "port": echo_port, "network": "udp"},
                "streamSettings": {"finalmask": {"udp": masks}}}],
            "outbounds": [{"protocol": "freedom",
                "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
        }),
        port,
    )
    .await
}

/// Our client: SOCKS in, freedom out under `masks`.
fn freedom_client(masks: &Value) -> Value {
    json!({
        "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1",
            "port": 0, "settings": {"udp": true}}],
        "outbounds": [{"protocol": "freedom", "tag": "direct",
            "streamSettings": {"finalmask": {"udp": masks}}}]
    })
}

/// One SOCKS UDP association to `port` on the loopback, echoing `sizes`.
/// Replies other than the echo are skipped: a noise datagram the server
/// unmasks goes to the echo too, and comes back.
async fn udp_echo_through(proxy: SocketAddr, port: u16, sizes: &[usize]) -> std::io::Result<()> {
    let (_control, relay) = socks(proxy, 3, "0.0.0.0", 0).await?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    for &size in sizes {
        let payload: Vec<u8> = (0..size).map(|n| (n * 13 + size) as u8).collect();
        let mut datagram = vec![0, 0, 0, 1, 127, 0, 0, 1];
        datagram.extend(port.to_be_bytes());
        datagram.extend(&payload);
        let mut reply = vec![0; 8192];
        let mut echoed = false;
        'attempts: for _ in 0..10 {
            socket.send_to(&datagram, relay).await?;
            let deadline = Instant::now() + Duration::from_millis(500);
            while let Ok(result) =
                tokio::time::timeout_at(deadline, socket.recv_from(&mut reply)).await
            {
                let (n, _) = result?;
                if n >= 10 && reply[10..n] == payload[..] {
                    echoed = true;
                    break 'attempts;
                }
            }
        }
        if !echoed {
            return Err(std::io::Error::other(format!(
                "no UDP echo of {size} bytes"
            )));
        }
    }
    Ok(())
}

/// Freedom's UDP flows under each mask set reach a UDP echo through
/// Xray-core's `tunnel` inbound under the same masks, the client's noise
/// inside Salamander included. Another password carries nothing.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-hysteria-interop.sh"]
async fn freedom_udp_flows_run_under_masks() {
    let (_, echo_port, _tcp, _udp) = echo_servers().await;
    let password = "synthetic-salamander";
    let sizes: &[usize] = &[1, 512, 1200];
    // Xray-core's header masks, Salamander among them, write at most 4096
    // bytes a datagram, and sudoku quadruples one.
    let small: &[usize] = &[1, 512];
    for (case, client, server, sizes) in [
        (
            "salamander",
            json!([salamander(password)]),
            json!([salamander(password)]),
            sizes,
        ),
        (
            "noise inside salamander",
            json!([noise(), salamander(password)]),
            json!([salamander(password)]),
            sizes,
        ),
        (
            "header-custom",
            json!([header_custom()]),
            json!([header_custom()]),
            sizes,
        ),
        (
            "header-custom standalone",
            json!([standalone()]),
            json!([standalone()]),
            sizes,
        ),
        ("sudoku", json!([sudoku()]), json!([sudoku()]), sizes),
        (
            "sudoku inside salamander",
            json!([sudoku(), salamander(password)]),
            json!([sudoku(), salamander(password)]),
            small,
        ),
    ] {
        eprintln!("freedom UDP {case}");
        let port = allocate_loopback_udp_port();
        let xray = tunnel_server(port, echo_port, &server).await;
        let core = core(freedom_client(&client)).await;
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
        let result = timeout(
            Duration::from_secs(30),
            udp_echo_through(socks_addr, port, sizes),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "{case}: {result:?}; {}",
            xray.logs()
        );
        drop(core);
        drop(xray);
    }

    eprintln!("freedom UDP salamander with another password");
    let port = allocate_loopback_udp_port();
    let xray = tunnel_server(port, echo_port, &json!([salamander(password)])).await;
    let core = core(freedom_client(&json!([salamander("another-password")]))).await;
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
    let result = timeout(
        Duration::from_secs(8),
        udp_echo_through(socks_addr, port, &[1, 512]),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(()))),
        "another password carried data"
    );
    drop(core);
    drop(xray);
}

/// Synthetic WireGuard keys: the server's and the client's.
fn wireguard_keys() -> (StaticSecret, StaticSecret) {
    (
        StaticSecret::from([0x53; 32]),
        StaticSecret::from([0x42; 32]),
    )
}

/// Xray-core's WireGuard inbound on UDP `port` under `masks`, its freedom
/// redirecting every flow to the loopback, keeping the port.
async fn wireguard_server(port: u16, masks: &Value) -> XrayServer {
    let (server, client) = wireguard_keys();
    xray(
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{"protocol": "wireguard", "listen": "127.0.0.1", "port": port,
                "settings": {"secretKey": STANDARD.encode(server.to_bytes()),
                    "address": ["10.44.0.1/32"], "mtu": 1420,
                    "peers": [{"publicKey": STANDARD.encode(PublicKey::from(&client).as_bytes()),
                        "allowedIPs": ["10.44.0.2/32"]}]},
                "streamSettings": {"finalmask": {"udp": masks}}}],
            "outbounds": [{"protocol": "freedom", "settings": {"redirect": "127.0.0.1:0",
                "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
        }),
        port,
    )
    .await
}

/// Our client: SOCKS in, WireGuard out to `port` under `masks`.
fn wireguard_client(port: u16, masks: &Value) -> Value {
    let (server, client) = wireguard_keys();
    json!({
        "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1",
            "port": 0, "settings": {"udp": true}}],
        "outbounds": [{"protocol": "wireguard", "tag": "proxy",
            "settings": {"secretKey": STANDARD.encode(client.to_bytes()),
                "address": ["10.44.0.2/32"], "mtu": 1420,
                "peers": [{"publicKey": STANDARD.encode(PublicKey::from(&server).as_bytes()),
                    "endpoint": format!("127.0.0.1:{port}"), "allowedIPs": ["0.0.0.0/0"]}]},
            "streamSettings": {"finalmask": {"udp": masks}}}]
    })
}

/// WireGuard under each mask set carries TCP and UDP through Xray-core's
/// WireGuard inbound under the same masks, noise on either side of
/// Salamander included. Another password carries nothing.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-hysteria-interop.sh"]
async fn wireguard_runs_under_masks() {
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let password = "synthetic-salamander";
    for (case, client, server) in [
        (
            "noise inside salamander",
            json!([noise(), salamander(password)]),
            json!([salamander(password)]),
        ),
        (
            "noise outside salamander",
            json!([salamander(password), noise()]),
            json!([salamander(password)]),
        ),
        (
            "header-custom",
            json!([header_custom()]),
            json!([header_custom()]),
        ),
        (
            "header-custom standalone",
            json!([standalone()]),
            json!([standalone()]),
        ),
        ("sudoku", json!([sudoku()]), json!([sudoku()])),
    ] {
        eprintln!("WireGuard {case}");
        let port = allocate_loopback_udp_port();
        let xray = wireguard_server(port, &server).await;
        let core = core(wireguard_client(port, &client)).await;
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
        let result = timeout(Duration::from_secs(60), async {
            tcp_echo(socks_addr, INNER_TARGET, tcp_port).await?;
            udp_echo(socks_addr, INNER_TARGET, udp_port).await
        })
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "{case}: {result:?}; {}",
            xray.logs()
        );
        drop(core);
        drop(xray);
    }

    eprintln!("WireGuard salamander with another password");
    let port = allocate_loopback_udp_port();
    let xray = wireguard_server(port, &json!([salamander(password)])).await;
    let core = core(wireguard_client(
        port,
        &json!([salamander("another-password")]),
    ))
    .await;
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
    let result = timeout(
        Duration::from_secs(8),
        tcp_echo(socks_addr, INNER_TARGET, tcp_port),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(()))),
        "another password carried data"
    );
    drop(core);
    drop(xray);
}
