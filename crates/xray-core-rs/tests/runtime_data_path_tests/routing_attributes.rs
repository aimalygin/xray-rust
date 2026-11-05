//! Routing rules on the attributes Xray-core's HTTP sniffer records:
//! `attrs`.

use super::*;

const ATTRIBUTES_CONFIG: &str = r#"{
    "inbounds": [
        {"tag": "sniffed-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
         "settings": {"auth": "noauth"},
         "sniffing": {"enabled": true, "destOverride": []}},
        {"tag": "plain-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
         "settings": {"auth": "noauth"}},
        {"tag": "tun-in", "protocol": "tun",
         "sniffing": {"enabled": true, "destOverride": ["http"], "routeOnly": true}}
    ],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}
    ],
    "routing": {"rules": [
        {"attrs": {"User-Agent": "^curl/", ":method": "GET"}, "outboundTag": "block"}
    ]}
}"#;

async fn start_attributes_core() -> Core {
    let config = parse_xray_json(ATTRIBUTES_CONFIG)
        .expect("synthetic attrs config parses")
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

fn request(method: &str, agent: &str) -> Vec<u8> {
    format!("{method} / HTTP/1.1\r\nHost: sniffed.example\r\nUser-Agent: {agent}\r\n\r\n")
        .into_bytes()
}

/// Sends `payload` through the SOCKS inbound at `socks_addr` to a fresh echo
/// server and reports whether it came back.
async fn echoes_through(socks_addr: SocketAddr, payload: &[u8]) -> bool {
    // Each echo server answers one connection.
    let (echo_addr, _echo_handle) = spawn_echo_server().await;
    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;
    if client.write_all(payload).await.is_err() {
        return false;
    }
    let mut received = Vec::new();
    let mut buffer = vec![0; payload.len()];
    while received.len() < payload.len() {
        match timeout(Duration::from_secs(2), client.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => received.extend_from_slice(&buffer[..read]),
        }
    }
    received == payload
}

#[tokio::test]
async fn socks_flows_route_by_their_request_attributes() {
    timeout(Duration::from_secs(10), async {
        let core = start_attributes_core().await;
        let sniffed = core.inbound_addr(Some("sniffed-in")).unwrap();

        // `destOverride` is empty, yet the request is read for its attributes.
        assert!(!echoes_through(sniffed, &request("GET", "curl/8.7")).await);
        // Every named attribute must match, the method case-sensitively.
        assert!(echoes_through(sniffed, &request("POST", "curl/8.7")).await);
        assert!(echoes_through(sniffed, &request("get", "curl/8.7")).await);
        assert!(echoes_through(sniffed, &request("GET", "Mozilla/5.0")).await);

        // Without sniffing a flow has no attributes, so no attrs rule applies.
        let plain = core.inbound_addr(Some("plain-in")).unwrap();
        assert!(echoes_through(plain, &request("GET", "curl/8.7")).await);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_tcp_flows_route_by_their_request_attributes() {
    timeout(Duration::from_secs(5), async {
        let mut core = start_attributes_core().await;
        let mut client = TunTcpClient::new();
        client.connect("192.0.2.31:80".parse().unwrap());
        let mut sent = false;
        let mut received = Vec::new();
        pump_tun_until(&mut client, core.tun(), |client| {
            if !sent && client.may_send() {
                client.send_payload(&request("GET", "curl/8.7"));
                sent = true;
            }
            received.extend_from_slice(&client.recv_available());
            received.starts_with(b"HTTP/1.1 403")
        })
        .await;
        assert!(received.starts_with(b"HTTP/1.1 403 Forbidden"));
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}
