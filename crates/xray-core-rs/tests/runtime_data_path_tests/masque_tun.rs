//! TUN TCP and UDP through the MASQUE outbound, over HTTP/3 and HTTP/2, to
//! Xray-core v26.10.31's own MASQUE server, whose freedom outbound redirects
//! each flow from its documentation address to the loopback echo servers.
use super::*;
use sha2::Digest as _;

const MASQUE_USER: &str = "masque@test";
const MASQUE_PASS: &str = "synthetic-masque-pass";
const ECHO: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

struct Reference {
    child: std::process::Child,
    directory: std::path::PathBuf,
    port: u16,
    pin: String,
}

impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "xray log:\n{}",
                std::fs::read_to_string(self.directory.join("xray.log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// Xray-core's MASQUE server on `alpn`: HTTP/3 on UDP, HTTP/2 on TCP.
async fn reference(alpn: &str) -> Reference {
    let binary =
        std::env::var_os("XRAY_CLIENT_PROTOCOL_BINARY").expect("run check-masque-interop.sh");
    let directory = std::env::temp_dir().join(format!(
        "xray-masque-tun-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["masque.test".to_owned()]).unwrap();
    std::fs::write(directory.join("cert.pem"), pem("CERTIFICATE", cert.der())).unwrap();
    std::fs::write(
        directory.join("key.pem"),
        pem("PRIVATE KEY", &signing_key.serialize_der()),
    )
    .unwrap();
    let pin = Sha256::digest(cert.der())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let port = if alpn == "h3" {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let config = serde_json::json!({
        "log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "masque",
            "settings": {"users": [{"email": MASQUE_USER, "pass": MASQUE_PASS}],
                "address": ["10.78.0.1/24"]},
            "streamSettings": {"network": "masque", "security": "tls",
                "tlsSettings": {"alpn": [alpn], "certificates": [{
                    "certificateFile": directory.join("cert.pem"),
                    "keyFile": directory.join("key.pem")}]}}}],
        // Since v26.11.9 freedom blocks private addresses for the MASQUE
        // inbound unless a rule allows them.
        "outbounds": [{"protocol": "freedom",
            "settings": {"redirect": "127.0.0.1:0", "finalRules": [{"action": "allow"}]}}]
    });
    std::fs::write(directory.join("config.json"), config.to_string()).unwrap();
    let log = std::fs::File::create(directory.join("xray.log")).unwrap();
    let child = std::process::Command::new(binary)
        .args(["run", "-config"])
        .arg(directory.join("config.json"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let reference = Reference {
        child,
        directory,
        port,
        pin,
    };
    let deadline = TokioInstant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(reference.directory.join("xray.log"))
        .unwrap_or_default()
        .contains("started")
    {
        assert!(TokioInstant::now() < deadline, "Xray-core did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    reference
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_tun_tcp_and_udp_reach_xrays_masque_server() {
    tun_tcp_and_udp("h3").await;
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-masque-interop.sh"]
async fn masque_tun_over_h2_tcp_and_udp_reach_xrays_masque_server() {
    tun_tcp_and_udp("h2").await;
}

async fn tun_tcp_and_udp(alpn: &str) {
    timeout(Duration::from_secs(60), async {
        let server = reference(alpn).await;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        let _tcp = tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        let udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let _udp = tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                let _ = udp.send_to(&buf[..n], from).await;
            }
        });
        let profile = serde_json::json!({
            "inbounds": [{"tag": "tun-in", "protocol": "tun"}],
            "outbounds": [{"tag": "masque", "protocol": "masque",
                "settings": {"address": "127.0.0.1", "port": server.port},
                "streamSettings": {"network": "masque", "security": "tls",
                    "tlsSettings": {"serverName": "masque.test", "alpn": [alpn],
                    "pinnedPeerCertSha256": server.pin},
                    "masqueSettings": {"user": MASQUE_USER, "pass": MASQUE_PASS}}}]
        });
        let mut core = Core::new(parse_xray_json(&profile.to_string()).unwrap().config).unwrap();
        core.start().await.unwrap();

        let mut client = TunTcpClient::new();
        client.connect(SocketAddr::from((ECHO, tcp_port)));
        // The first flow waits for the tunnel.
        pump_tun_until_with_timeout(
            &mut client,
            core.tun(),
            Duration::from_secs(10),
            TunTcpClient::may_send,
        )
        .await;
        // One write the client's 8 KiB buffer takes whole.
        let payload: Vec<u8> = (0..6000u32).map(|n| (n * 31 + 7) as u8).collect();
        client.send_payload(&payload);
        let mut received = Vec::new();
        pump_tun_until_with_timeout(&mut client, core.tun(), Duration::from_secs(10), |client| {
            received.extend_from_slice(&client.recv_available());
            received.len() >= payload.len()
        })
        .await;
        assert_eq!(
            received, payload,
            "the TUN TCP echo through the tunnel differs"
        );

        let client_ip = Ipv4Addr::new(10, 10, 0, 2);
        let udp_payload = vec![0x5a; 1200];
        let reply = loop {
            core.tun()
                .push_inbound(Bytes::from(ipv4_udp_packet(
                    client_ip,
                    49154,
                    ECHO,
                    udp_port,
                    &udp_payload,
                )))
                .await
                .unwrap();
            let reply = timeout(
                Duration::from_secs(1),
                poll_tun_outbound_until_with_timeout(
                    core.tun(),
                    Duration::from_secs(1),
                    |packet| ipv4_udp_payload(packet).is_some_and(|p| p == udp_payload),
                ),
            )
            .await;
            if let Ok(reply) = reply {
                break reply;
            }
        };
        assert_ipv4_udp_packet(&reply, ECHO, udp_port, client_ip, 49154, &udp_payload);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}
