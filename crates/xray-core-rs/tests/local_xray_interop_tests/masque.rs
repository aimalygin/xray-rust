//! The MASQUE client against Xray-core v26.10.31's own MASQUE server:
//! CONNECT-IP over HTTP/3 and HTTP/2, TCP and UDP of both families through
//! the tunnel's stack, destination names resolved through the tunnel,
//! authentication, tunnel reuse, and the UDP masks under HTTP/3, realm's
//! introduction among them (xicmp's is in its own suite, which runs as
//! root).
//!
//! Targets are documentation addresses: Xray's server hands each flow to a
//! freedom outbound whose redirect sends it to the loopback echo servers,
//! keeping the port, and answers DNS for `echo.masque.test` from its hosts.
use super::proxy_carriers::certificate_pin;
use super::*;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv6Addr};
use tokio::net::UdpSocket;

const USER: &str = "masque@test";
const PASS: &str = "synthetic-masque-pass";
const PATH: &str = "/masque/{target}/{ipproto}/";
pub(super) const ECHO_V4: &str = "192.0.2.10";
pub(super) const ECHO_V6: &str = "2001:db8::10";
const ECHO_NAME: &str = "echo.masque.test";
const DNS_V4: &str = "192.0.2.53";
const DNS_V6: &str = "2001:db8::53";

pub(super) struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Resolver;
#[async_trait::async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
        panic!("the MASQUE server is an IP address, yet {domain} was looked up");
    }
}

/// Xray-core's MASQUE server on `alpn`, with one user, an IPv4 and an IPv6
/// pool, a freedom outbound redirected to the loopback and a DNS outbound.
pub(super) async fn start_server(
    checkout: &Path,
    alpn: &str,
    customize: impl FnOnce(&mut Value),
) -> XrayServer {
    let temp_dir = create_temp_dir("xray-rust-masque-interop");
    let config_path = temp_dir.path.join("server.json");
    let stdout_path = temp_dir.path.join("xray.stdout.log");
    let stderr_path = temp_dir.path.join("xray.stderr.log");
    let h3 = alpn == "h3";
    let port = if h3 {
        allocate_loopback_udp_port()
    } else {
        allocate_loopback_port()
    };
    let identity = generate_tls_identity(&temp_dir, TLS_SERVER_NAME);
    let mut config = json!({
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "masque", "tag": "masque-in",
            "settings": {
                "users": [{"email": USER, "pass": PASS}],
                "address": ["10.77.0.1/24", "fd77::1/64"]
            },
            "streamSettings": {
                "network": "masque", "security": "tls",
                "tlsSettings": {
                    "alpn": [alpn],
                    "certificates": [{
                        "certificateFile": identity.cert_path,
                        "keyFile": identity.key_path
                    }]
                },
                "masqueSettings": {"path": PATH}
            }
        }],
        // Since v26.11.9 freedom blocks private addresses for the MASQUE
        // inbound by default; the redirect to the loopback echo servers is
        // allowed by a rule of its own, which wins over the default.
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:0", "finalRules": [{"action": "allow"}]}},
            {"tag": "dns-out", "protocol": "dns"}
        ],
        "dns": {"hosts": {ECHO_NAME: [ECHO_V4, ECHO_V6]}},
        "routing": {"rules": [
            {"type": "field", "ip": [DNS_V4, DNS_V6], "port": 53, "outboundTag": "dns-out"}
        ]}
    });
    customize(&mut config);
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
                .current_dir(checkout)
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
    // An xicmp server reads raw ICMP and binds no UDP port.
    let xicmp = config["inbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array()
        .is_some_and(|masks| masks.iter().any(|mask| mask["type"] == "xicmp"));
    if xicmp {
        wait_for_xray_startup(&mut child, &stdout_path, &stderr_path).await;
    } else if h3 {
        wait_for_udp_listener(&mut child, addr, &stdout_path, &stderr_path).await;
    } else {
        wait_for_tcp_listener(&mut child, addr, &stdout_path, &stderr_path).await;
    }
    XrayServer {
        child,
        _temp_dir: temp_dir,
        addr,
        stdout_path,
        stderr_path,
        tls_client_config: None,
    }
}

/// Our client: a SOCKS inbound and the MASQUE outbound to `server`.
pub(super) fn client_config(server: &XrayServer, alpn: &str, masque: Value) -> Value {
    client_config_with(server, alpn, masque, json!({}))
}

/// [`client_config`] with more `tlsSettings`.
fn client_config_with(server: &XrayServer, alpn: &str, masque: Value, tls: Value) -> Value {
    let mut config = json!({
        "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": 0,
            "settings": {"udp": true}},
            {"protocol": "http", "tag": "http-in", "listen": "127.0.0.1", "port": 0}],
        "outbounds": [{"tag": "masque", "protocol": "masque",
            "settings": {"address": "127.0.0.1", "port": server.addr.port(),
                "remoteDNS": [DNS_V4, DNS_V6]},
            "streamSettings": {"network": "masque", "security": "tls",
                "tlsSettings": {"serverName": TLS_SERVER_NAME, "alpn": [alpn],
                    "pinnedPeerCertSha256": certificate_pin(server)},
                "masqueSettings": masque}}]
    });
    for (key, value) in tls.as_object().unwrap() {
        config["outbounds"][0]["streamSettings"]["tlsSettings"][key] = value.clone();
    }
    config
}

pub(super) fn credentials() -> Value {
    json!({"path": PATH, "user": USER, "pass": PASS})
}

/// SOCKS5 CONNECT or UDP ASSOCIATE to an address or a name.
pub(super) async fn socks(
    proxy: SocketAddr,
    command: u8,
    target: &str,
    port: u16,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, command, 0];
    match target.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend(ip.octets());
        }
        Err(_) => {
            request.push(3);
            request.push(target.len() as u8);
            request.extend(target.as_bytes());
        }
    }
    request.extend(port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS reply {}", head[1])));
    }
    let bound = match head[3] {
        1 => {
            let mut rest = [0; 6];
            stream.read_exact(&mut rest).await?;
            SocketAddr::from((
                [rest[0], rest[1], rest[2], rest[3]],
                u16::from_be_bytes([rest[4], rest[5]]),
            ))
        }
        4 => {
            let mut rest = [0; 18];
            stream.read_exact(&mut rest).await?;
            let ip: [u8; 16] = rest[..16].try_into().unwrap();
            SocketAddr::from((Ipv6Addr::from(ip), u16::from_be_bytes([rest[16], rest[17]])))
        }
        other => return Err(std::io::Error::other(format!("SOCKS address type {other}"))),
    };
    Ok((stream, bound))
}

/// A loopback TCP echo that greets first, and a UDP echo.
pub(super) async fn echo_servers() -> (u16, u16, Task, Task) {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let tcp_task = Task(tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                return;
            };
            tokio::spawn(async move {
                stream.write_all(b"greeting").await.unwrap();
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    }));
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let udp_task = Task(tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                return;
            };
            let _ = udp.send_to(&buf[..n], from).await;
        }
    }));
    (tcp_port, udp_port, tcp_task, udp_task)
}

/// One TCP flow echoing 128 KiB through the tunnel to `target`.
pub(super) async fn tcp_echo(proxy: SocketAddr, target: &str, port: u16) -> std::io::Result<()> {
    let (mut stream, _) = socks(proxy, 1, target, port).await?;
    let mut greeting = [0; 8];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(&greeting, b"greeting");
    let payload: Vec<u8> = (0..131_077u32).map(|n| (n * 197 + 31) as u8).collect();
    let (mut reader, mut writer) = stream.split();
    let mut echoed = vec![0; payload.len()];
    let (written, read) = tokio::join!(writer.write_all(&payload), reader.read_exact(&mut echoed));
    written?;
    read?;
    assert!(echoed == payload, "the echo through the tunnel differs");
    Ok(())
}

/// One HTTP CONNECT tunnel through the HTTP inbound, echoing 64 KiB.
async fn http_connect_echo(proxy: SocketAddr, target: &str, port: u16) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(proxy).await?;
    let authority = format!("{target}:{port}");
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    if !head.starts_with("HTTP/1.1 200") {
        return Err(std::io::Error::other(format!("CONNECT answered {head}")));
    }
    let mut greeting = [0; 8];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(&greeting, b"greeting");
    let payload: Vec<u8> = (0..65_536u32).map(|n| (n * 7 + 3) as u8).collect();
    let (mut reader, mut writer) = stream.split();
    let mut echoed = vec![0; payload.len()];
    let (written, read) = tokio::join!(writer.write_all(&payload), reader.read_exact(&mut echoed));
    written?;
    read?;
    assert!(
        echoed == payload,
        "the HTTP CONNECT echo through the tunnel differs"
    );
    Ok(())
}

/// One UDP association echoing three sizes through the tunnel to `target`.
pub(super) async fn udp_echo(proxy: SocketAddr, target: &str, port: u16) -> std::io::Result<()> {
    let (_control, relay) = socks(proxy, 3, "0.0.0.0", 0).await?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    for size in [1usize, 512, 1200] {
        let payload: Vec<u8> = (0..size).map(|n| (n * 13 + size) as u8).collect();
        let mut datagram = vec![0, 0, 0];
        match target.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                datagram.push(1);
                datagram.extend(ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                datagram.push(4);
                datagram.extend(ip.octets());
            }
            Err(_) => {
                datagram.push(3);
                datagram.push(target.len() as u8);
                datagram.extend(target.as_bytes());
            }
        }
        datagram.extend(port.to_be_bytes());
        datagram.extend(&payload);
        let mut reply = vec![0; 4096];
        let mut received = None;
        // The first datagram may wait for the tunnel; resend until it comes.
        for _ in 0..20 {
            socket.send_to(&datagram, relay).await?;
            if let Ok(result) =
                timeout(Duration::from_millis(500), socket.recv_from(&mut reply)).await
            {
                received = Some(result?.0);
                break;
            }
        }
        let n = received
            .ok_or_else(|| std::io::Error::other(format!("no UDP echo of {size} bytes")))?;
        assert!(
            reply[..n].ends_with(&payload),
            "UDP echo of {size} bytes differs"
        );
    }
    Ok(())
}

pub(super) async fn core(config: Value) -> Core {
    let dialer = Arc::new(TransportDialer::system().unwrap());
    let mut core = Core::with_runtime_dependencies(
        parse_xray_json(&config.to_string()).unwrap().config,
        Arc::new(Resolver),
        dialer,
    )
    .unwrap();
    core.start().await.unwrap();
    core
}

pub(super) async fn check(
    server: &XrayServer,
    case: &str,
    run: impl Future<Output = std::io::Result<()>>,
) {
    eprintln!("MASQUE {case}");
    let result = timeout(Duration::from_secs(60), run).await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{case}: {result:?}; {}",
        server.logs()
    );
}

use std::future::Future;

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h3_carries_tcp_and_udp_of_both_families() {
    carries_tcp_and_udp_of_both_families("h3", json!({})).await;
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h2_carries_tcp_and_udp_of_both_families() {
    carries_tcp_and_udp_of_both_families("h2", json!({})).await;
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h2_runs_over_a_utls_fingerprint() {
    carries_tcp_and_udp_of_both_families("h2", json!({"fingerprint": "chrome"})).await;
}

/// A change of the OS network, as the host reports it through
/// `xray_core_rebind_hysteria`: the tunnel over HTTP/3 moves to a fresh
/// socket, the one its QUIC datagrams and so its IP packets travel on, and a
/// TCP flow through the tunnel goes on against Xray-core's own server. The
/// relay gives every client source its own upstream socket, so Xray sees
/// each change as a new path.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h3_keeps_a_flow_across_network_changes() {
    let checkout = resolve_xray_checkout();
    let server = start_server(&checkout, "h3", |_| {}).await;
    let relay = UdpHopRelay::start(server.addr).await;
    let (tcp_port, _udp_port, _tcp, _udp) = echo_servers().await;
    let mut config = client_config(&server, "h3", credentials());
    config["outbounds"][0]["settings"]["port"] = json!(relay.address.port());
    let core = core(config).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let (mut stream, _) = socks(proxy, 1, ECHO_V4, tcp_port).await.unwrap();
    let mut greeting = [0; 8];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"greeting");

    // One flow in one tunnel: data before any change, then after each of two.
    for round in 0_u8..3 {
        if round > 0 {
            assert_eq!(
                core.rebind_quic(),
                1,
                "the one MASQUE tunnel follows the change"
            );
            // The tunnel's own task takes the socket; let it run before the
            // round's data, which then leaves from the new one.
            sleep(Duration::from_millis(200)).await;
        }
        let payload: Vec<u8> = (0..32 * 1024 + u32::from(round))
            .map(|n| (n * 197 + 31) as u8)
            .collect();
        let mut echoed = vec![0; payload.len()];
        stream.write_all(&payload).await.unwrap();
        let read = timeout(Duration::from_secs(15), stream.read_exact(&mut echoed)).await;
        assert!(
            matches!(read, Ok(Ok(_))),
            "echo after {round} network changes: {read:?}; {}",
            server.logs()
        );
        assert!(echoed == payload, "round {round}: the echo differs");
        assert_eq!(
            relay.sources.load(Ordering::SeqCst),
            usize::from(round) + 1,
            "each change moves the tunnel to one fresh socket"
        );
    }
}

async fn carries_tcp_and_udp_of_both_families(alpn: &str, tls: Value) {
    let checkout = resolve_xray_checkout();
    let server = start_server(&checkout, alpn, |_| {}).await;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let mut core = core(client_config_with(&server, alpn, credentials(), tls)).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let h = alpn.to_ascii_uppercase();
    check(
        &server,
        &format!("{h} TCP over IPv4"),
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    check(
        &server,
        &format!("{h} TCP over IPv6"),
        tcp_echo(proxy, ECHO_V6, tcp_port),
    )
    .await;
    check(
        &server,
        &format!("{h} TCP to a name resolved in the tunnel"),
        tcp_echo(proxy, ECHO_NAME, tcp_port),
    )
    .await;
    let http = core.inbound_addr(Some("http-in")).unwrap();
    check(
        &server,
        &format!("{h} TCP through the HTTP inbound"),
        http_connect_echo(http, ECHO_V4, tcp_port),
    )
    .await;
    check(
        &server,
        &format!("{h} UDP over IPv4"),
        udp_echo(proxy, ECHO_V4, udp_port),
    )
    .await;
    check(
        &server,
        &format!("{h} UDP over IPv6"),
        udp_echo(proxy, ECHO_V6, udp_port),
    )
    .await;
    check(
        &server,
        &format!("{h} UDP to a name resolved in the tunnel"),
        udp_echo(proxy, ECHO_NAME, udp_port),
    )
    .await;
    // Eight flows at once share the one tunnel.
    check(&server, &format!("{h} eight parallel TCP flows"), async {
        let flows = (0..8).map(|_| tcp_echo(proxy, ECHO_V4, tcp_port));
        for result in futures_util::future::join_all(flows).await {
            result?;
        }
        Ok(())
    })
    .await;
    let logs = fs::read_to_string(&server.stdout_path).unwrap_or_default()
        + &fs::read_to_string(&server.stderr_path).unwrap_or_default();
    assert_eq!(
        logs.matches("MASQUE: tunnel from").count(),
        1,
        "every flow should share one tunnel: {logs}"
    );
    core.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h3_with_a_wrong_password_carries_nothing() {
    a_wrong_password_carries_nothing("h3").await;
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h2_with_a_wrong_password_carries_nothing() {
    a_wrong_password_carries_nothing("h2").await;
}

async fn a_wrong_password_carries_nothing(alpn: &str) {
    let checkout = resolve_xray_checkout();
    let server = start_server(&checkout, alpn, |_| {}).await;
    let (tcp_port, _, _tcp, _udp) = echo_servers().await;
    let mut core = core(client_config(
        &server,
        alpn,
        json!({"path": PATH, "user": USER, "pass": "not-the-password"}),
    ))
    .await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let result = timeout(Duration::from_secs(30), tcp_echo(proxy, ECHO_V4, tcp_port)).await;
    assert!(
        !matches!(result, Ok(Ok(()))),
        "a wrong password must not carry a flow"
    );
    let logs = fs::read_to_string(&server.stdout_path).unwrap_or_default();
    assert!(logs.contains("authentication failed"), "{}", server.logs());
    core.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h3_takes_the_default_path_and_a_custom_user_agent() {
    let checkout = resolve_xray_checkout();
    let server = start_server(&checkout, "h3", |config| {
        config["inbounds"][0]["streamSettings"]["masqueSettings"] = json!({});
    })
    .await;
    let (tcp_port, _, _tcp, _udp) = echo_servers().await;
    let mut core = core(client_config(
        &server,
        "h3",
        json!({"user": USER, "pass": PASS, "headers": {"User-Agent": "firefox"}}),
    ))
    .await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(
        &server,
        "H3 default path",
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    core.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h2_takes_the_default_path_go_user_agent_and_no_keepalive() {
    let checkout = resolve_xray_checkout();
    let server = start_server(&checkout, "h2", |config| {
        config["inbounds"][0]["streamSettings"]["masqueSettings"] = json!({});
    })
    .await;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let mut core = core(client_config(
        &server,
        "h2",
        json!({"user": USER, "pass": PASS, "headers": {"User-Agent": "golang"},
            "xmux": {"hKeepAlivePeriod": -1}}),
    ))
    .await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(
        &server,
        "H2 default path",
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    check(
        &server,
        "H2 UDP on the default path",
        udp_echo(proxy, ECHO_V6, udp_port),
    )
    .await;
    core.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h3_runs_xrays_bbr_profiles() {
    let checkout = resolve_xray_checkout();
    let server = start_server(&checkout, "h3", |_| {}).await;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    for profile in ["conservative", "aggressive"] {
        let mut config = client_config(&server, "h3", credentials());
        config["outbounds"][0]["streamSettings"]["finalmask"] =
            json!({"quicParams": {"bbrProfile": profile}});
        let mut core = core(config).await;
        let proxy = core.inbound_addr(Some("socks-in")).unwrap();
        check(
            &server,
            &format!("H3 TCP with the {profile} BBR profile"),
            tcp_echo(proxy, ECHO_V4, tcp_port),
        )
        .await;
        check(
            &server,
            &format!("H3 UDP with the {profile} BBR profile"),
            udp_echo(proxy, ECHO_V4, udp_port),
        )
        .await;
        core.stop().await.unwrap();
    }
}

/// A stand-in for Cloudflare's WARP endpoint, built from Xray-core's own
/// warp tests (`tools/masque-oracle/warp_server_test.go`).
struct WarpServer {
    child: std::process::Child,
    dir: TempDir,
    port: u16,
    /// Its key, in base64, for `publicKey`.
    spki: String,
}

impl Drop for WarpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl WarpServer {
    fn file(&self, name: &str) -> String {
        fs::read_to_string(self.dir.path.join(name)).unwrap_or_default()
    }
}

/// A device key: `privateKey` in base64 and its SubjectPublicKeyInfo.
fn warp_device_key() -> (String, Vec<u8>) {
    use base64::Engine as _;
    use rcgen::PublicKeyData as _;
    let key = rcgen::KeyPair::generate().unwrap();
    (
        base64::engine::general_purpose::STANDARD.encode(key.serialize_der()),
        key.subject_public_key_info(),
    )
}

/// The stand-in binary: the one the check script built, or a fresh build of
/// the overlay test in the pinned checkout, kept in `dir`. Neither gate that
/// runs every ignored test builds it.
fn warp_server_binary(dir: &TempDir) -> PathBuf {
    env::var_os("XRAY_MASQUE_WARP_SERVER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let checkout = resolve_xray_checkout();
            let source = fs::canonicalize(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tools/masque-oracle/warp_server_test.go"),
            )
            .unwrap();
            let overlay = dir.path.join("overlay.json");
            let target = checkout.join("transport/internet/masque/xray_rust_warp_server_test.go");
            fs::write(
                &overlay,
                json!({"Replace": {target.to_str().unwrap(): source.to_str().unwrap()}})
                    .to_string(),
            )
            .unwrap();
            let binary = dir.path.join("warp-server");
            let output = Command::new("go")
                .args(["test", "-c", "-mod=readonly", "-overlay"])
                .arg(&overlay)
                .arg("-o")
                .arg(&binary)
                .arg("./transport/internet/masque")
                .current_dir(&checkout)
                .output()
                .expect("start go test -c for the WARP stand-in");
            assert!(
                output.status.success(),
                "building the WARP stand-in failed: {output:?}"
            );
            binary
        })
}

async fn warp_server(binary: &Path, mode: &str, device: &[u8]) -> WarpServer {
    let dir = create_temp_dir("xray-rust-warp-server");
    fs::write(dir.path.join("client.spki"), device).unwrap();
    let child = Command::new(binary)
        .args(["-test.run", "^TestXrayRustWarpServer$"])
        .env("MASQUE_WARP_SERVER_DIR", &dir.path)
        .env("MASQUE_WARP_SERVER_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            fs::File::create(dir.path.join("stderr")).unwrap(),
        ))
        .spawn()
        .expect("start the WARP stand-in");
    let mut server = WarpServer {
        child,
        dir,
        port: 0,
        spki: String::new(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while server.file("port").is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the WARP stand-in did not start: {}",
            server.file("stderr")
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    server.port = server.file("port").trim().parse().unwrap();
    server.spki = server.file("spki");
    server
}

fn warp_client(server: &WarpServer, alpn: &str, private_key: &str, public_key: &str) -> Value {
    json!({
        "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": 0,
            "settings": {"udp": true}}],
        "outbounds": [{"tag": "masque", "protocol": "masque",
            "settings": {"address": "127.0.0.1", "port": server.port},
            "streamSettings": {"network": "masque", "security": "tls",
                "tlsSettings": {"serverName": "consumer-masque.cloudflareclient.com", "alpn": [alpn]},
                "masqueSettings": {"warp": {"privateKey": private_key, "publicKey": public_key,
                    "address": ["172.16.0.2/32", "fd00::2/128"]}}}}]
    })
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_warp_carries_udp_through_cloudflares_handshake() {
    let (private_key, device) = warp_device_key();
    let build_dir = create_temp_dir("xray-rust-warp-build");
    let binary = warp_server_binary(&build_dir);
    for (mode, alpn) in [
        ("h3-draft", "h3"),
        ("h3-rfc", "h3"),
        ("h2", "h2"),
        ("h2-noalpn", "h2"),
    ] {
        let server = warp_server(&binary, mode, &device).await;
        let mut core = core(warp_client(&server, alpn, &private_key, &server.spki)).await;
        let proxy = core.inbound_addr(Some("socks-in")).unwrap();
        for target in [ECHO_V4, ECHO_V6] {
            eprintln!("MASQUE WARP {mode} UDP to {target}");
            let result = timeout(Duration::from_secs(60), udp_echo(proxy, target, 9)).await;
            assert!(
                matches!(result, Ok(Ok(()))),
                "WARP {mode} to {target}: {result:?}; {}{}",
                server.file("errors"),
                server.file("stderr")
            );
        }
        core.stop().await.unwrap();
        assert_eq!(server.file("errors"), "", "WARP {mode}");
        assert_eq!(
            server.file("tunnels").lines().count(),
            1,
            "WARP {mode}: one tunnel"
        );
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_warp_refuses_an_endpoint_with_another_key() {
    use base64::Engine as _;
    let (private_key, device) = warp_device_key();
    let (_, other) = warp_device_key();
    let other = base64::engine::general_purpose::STANDARD.encode(other);
    let build_dir = create_temp_dir("xray-rust-warp-build");
    let binary = warp_server_binary(&build_dir);
    for (mode, alpn) in [("h3-draft", "h3"), ("h2", "h2")] {
        let server = warp_server(&binary, mode, &device).await;
        let mut core = core(warp_client(&server, alpn, &private_key, &other)).await;
        let proxy = core.inbound_addr(Some("socks-in")).unwrap();
        let result = timeout(Duration::from_secs(30), udp_echo(proxy, ECHO_V4, 9)).await;
        assert!(
            !matches!(result, Ok(Ok(()))),
            "WARP {mode} took an endpoint with another key"
        );
        assert_eq!(server.file("tunnels"), "", "WARP {mode}");
        core.stop().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h3_runs_under_udp_masks() {
    let checkout = resolve_xray_checkout();
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let header = json!({"type": "header-custom", "settings": {
        "client": [{"type": "str", "packet": "synthetic-hello"}],
        "server": [{"type": "str", "packet": "synthetic-ok"}]}});
    let sudoku = |password: &str| json!({"type": "sudoku", "settings": {"password": password, "paddingMin": 5, "paddingMax": 25}});
    let noise = json!({"type": "noise", "settings": {"noise": [
        {"type": "str", "packet": "synthetic-noise", "delay": 2}]}});
    let salamander =
        json!({"type": "salamander", "settings": {"password": "synthetic-salamander"}});
    let gecko = json!({"type": "salamander", "settings": {
        "password": "synthetic-salamander", "packetSize": "512-1200"}});
    for (case, server_masks, client_masks) in [
        ("header-custom", json!([header]), json!([header])),
        (
            "sudoku with noise inside",
            json!([sudoku("synthetic-sudoku")]),
            json!([noise.clone(), sudoku("synthetic-sudoku")]),
        ),
        (
            "salamander with noise inside",
            json!([salamander]),
            json!([noise, salamander]),
        ),
        ("salamander with gecko", json!([gecko]), json!([gecko])),
    ] {
        let server = start_server(&checkout, "h3", |config| {
            config["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": server_masks});
        })
        .await;
        let mut config = client_config(&server, "h3", credentials());
        config["outbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": client_masks});
        let mut core = core(config).await;
        let proxy = core.inbound_addr(Some("socks-in")).unwrap();
        check(
            &server,
            &format!("H3 TCP under {case}"),
            tcp_echo(proxy, ECHO_V4, tcp_port),
        )
        .await;
        check(
            &server,
            &format!("H3 UDP over IPv6 under {case}"),
            udp_echo(proxy, ECHO_V6, udp_port),
        )
        .await;
        core.stop().await.unwrap();
    }

    // The mask is applied: another password carries nothing.
    let server = start_server(&checkout, "h3", |config| {
        config["inbounds"][0]["streamSettings"]["finalmask"] =
            json!({"udp": [sudoku("synthetic-sudoku")]});
    })
    .await;
    let mut config = client_config(&server, "h3", credentials());
    config["outbounds"][0]["streamSettings"]["finalmask"] =
        json!({"udp": [sudoku("another-password")]});
    let mut core = core(config).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let result = timeout(Duration::from_secs(30), tcp_echo(proxy, ECHO_V4, tcp_port)).await;
    assert!(
        !matches!(result, Ok(Ok(()))),
        "another sudoku password must carry nothing"
    );
    core.stop().await.unwrap();
}

/// realm: the tunnel's QUIC socket is introduced to Xray's server through a
/// local rendezvous first, then the tunnel runs over the punched path.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h3_is_introduced_by_realm() {
    use super::realm_rendezvous::{stun_server, Rendezvous};
    let checkout = resolve_xray_checkout();
    let rendezvous = Rendezvous::start("interop-token").await;
    let (stun, _stun) = stun_server().await;
    let name = "masque-realm";
    let realm = json!({"type": "realm", "settings": {
        "url": rendezvous.url(name), "stunServers": [stun.to_string()]}});
    let server = start_server(&checkout, "h3", |config| {
        config["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": [realm.clone()]});
    })
    .await;
    rendezvous.registered(name).await;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let mut config = client_config(&server, "h3", credentials());
    config["outbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": [realm]});
    let mut core = core(config).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(
        &server,
        "H3 TCP over realm",
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    check(
        &server,
        "H3 UDP over realm",
        udp_echo(proxy, ECHO_V6, udp_port),
    )
    .await;
    assert_eq!(
        rendezvous.connects(),
        1,
        "one tunnel, one introduction; {}",
        server.logs()
    );
    core.stop().await.unwrap();
}

/// The TCP masks over HTTP/2: Xray's server takes them on its TCP listener,
/// the client on its TCP carrier, under TLS.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_h2_runs_under_tcp_masks() {
    let checkout = resolve_xray_checkout();
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let sudoku = |password: &str| json!({"type": "sudoku", "settings": {"password": password}});
    let header = json!({"type": "header-custom", "settings": {
        "clients": [[{"type": "str", "packet": "synthetic-hello"}]],
        "servers": [[{"type": "str", "packet": "synthetic-ok"}]]}});
    for (case, masks) in [
        ("sudoku", json!([sudoku("synthetic-sudoku")])),
        ("header-custom", json!([header])),
    ] {
        let server = start_server(&checkout, "h2", |config| {
            config["inbounds"][0]["streamSettings"]["finalmask"] = json!({"tcp": masks});
        })
        .await;
        let mut config = client_config(&server, "h2", credentials());
        config["outbounds"][0]["streamSettings"]["finalmask"] = json!({"tcp": masks});
        let mut core = core(config).await;
        let proxy = core.inbound_addr(Some("socks-in")).unwrap();
        check(
            &server,
            &format!("H2 TCP under {case}"),
            tcp_echo(proxy, ECHO_V4, tcp_port),
        )
        .await;
        check(
            &server,
            &format!("H2 UDP over IPv6 under {case}"),
            udp_echo(proxy, ECHO_V6, udp_port),
        )
        .await;
        core.stop().await.unwrap();
    }

    // The mask is applied: another password carries nothing.
    let server = start_server(&checkout, "h2", |config| {
        config["inbounds"][0]["streamSettings"]["finalmask"] =
            json!({"tcp": [sudoku("synthetic-sudoku")]});
    })
    .await;
    let mut config = client_config(&server, "h2", credentials());
    config["outbounds"][0]["streamSettings"]["finalmask"] =
        json!({"tcp": [sudoku("another-password")]});
    let mut core = core(config).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let result = timeout(Duration::from_secs(30), tcp_echo(proxy, ECHO_V4, tcp_port)).await;
    assert!(
        !matches!(result, Ok(Ok(()))),
        "another sudoku password must carry nothing"
    );
    core.stop().await.unwrap();
}
