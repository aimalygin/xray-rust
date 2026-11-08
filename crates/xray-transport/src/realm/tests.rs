use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A STUN server that answers every Binding request with its source.
async fn stun_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((length, from)) = socket.recv_from(&mut buf).await {
            if length == 20 && buf[..2] == [0, 1] {
                let id: [u8; 12] = buf[8..20].try_into().unwrap();
                let _ = socket.send_to(&stun::binding_success(id, from), from).await;
            }
        }
    });
    (address, task)
}

struct Introduction {
    request: String,
    body: serde_json::Value,
}

/// A rendezvous that answers one connect with `server`'s address, after
/// `server` has punched towards the client's addresses with the attempt's
/// key, as a registered Xray-core server does.
async fn rendezvous(
    server: Arc<UdpSocket>,
    status: u16,
) -> (SocketAddr, tokio::task::JoinHandle<Introduction>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 4096];
        let (head_end, length) = loop {
            let read = stream.read(&mut buf).await.unwrap();
            received.extend_from_slice(&buf[..read]);
            if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&received[..end]).to_string();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                break (end + 4, length);
            }
        };
        while received.len() < head_end + length {
            let read = stream.read(&mut buf).await.unwrap();
            received.extend_from_slice(&buf[..read]);
        }
        let request = String::from_utf8_lossy(&received[..head_end]).to_string();
        let body: serde_json::Value = serde_json::from_slice(&received[head_end..]).unwrap();
        let unhex = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        };
        let meta = punch::PunchMetadata {
            nonce: unhex(body["nonce"].as_str().unwrap()).try_into().unwrap(),
            obfs: unhex(body["obfs"].as_str().unwrap()).try_into().unwrap(),
        };
        let clients: Vec<SocketAddr> = body["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().parse().unwrap())
            .collect();
        if status == 200 {
            for client in &clients {
                server
                    .send_to(&punch::encode(punch::PacketType::Hello, &meta), client)
                    .await
                    .unwrap();
            }
        }
        let answer = if status == 200 {
            format!(
                r#"{{"addresses":["{}"],"nonce":"x","obfs":"y"}}"#,
                server.local_addr().unwrap()
            )
        } else {
            r#"{"error":"realm_not_found","message":"realm not registered"}"#.to_owned()
        };
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{answer}",
            answer.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        Introduction { request, body }
    });
    (address, task)
}

fn config(rendezvous: SocketAddr, stun: SocketAddr) -> RealmConfig {
    RealmConfig {
        scheme: RealmScheme::Http,
        host: "127.0.0.1".into(),
        port_text: rendezvous.port().to_string(),
        port: rendezvous.port(),
        token: Arc::new(zeroize::Zeroizing::new("secret-token".into())),
        id: "test-realm".into(),
        stun_servers: vec![RealmStunServer {
            host: "127.0.0.1".into(),
            port_text: stun.port().to_string(),
            port: stun.port(),
        }],
        tls: None,
        family: RealmFamily::V4,
    }
}

fn env() -> RealmEnv {
    RealmEnv {
        resolver: Arc::new(crate::SystemDnsResolver),
        tls: TlsConnector::system().unwrap(),
        protector: None,
    }
}

#[tokio::test]
async fn introduces_the_client_to_the_server_that_punched_first() {
    let (stun, _stun_task) = stun_server().await;
    let server = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let (rendezvous, introduction) = rendezvous(server.clone(), 200).await;
    let udp = RealmUdp::open(RealmFamily::V4, None).unwrap();
    let client = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), udp.local_addr().unwrap().port());
    let peer = establish(&udp, &config(rendezvous, stun), &env())
        .await
        .unwrap();
    assert_eq!(peer, server.local_addr().unwrap());
    let introduction = introduction.await.unwrap();
    assert!(introduction.request.starts_with(&format!(
        "POST /v1/test-realm/connect HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: ",
        rendezvous.port()
    )));
    assert!(introduction.request.ends_with(
        "\r\nAuthorization: Bearer secret-token\r\nContent-Type: application/json\r\nAccept-Encoding: gzip\r\n\r\n"
    ));
    assert_eq!(
        introduction.body["addresses"],
        serde_json::json!([client.to_string()])
    );
    // The client acknowledged the server's hello.
    let mut buf = [0u8; 2048];
    let mut acked = false;
    while let Ok(Ok((length, _))) =
        tokio::time::timeout(Duration::from_millis(500), server.recv_from(&mut buf)).await
    {
        let unhex = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        };
        let meta = punch::PunchMetadata {
            nonce: unhex(introduction.body["nonce"].as_str().unwrap())
                .try_into()
                .unwrap(),
            obfs: unhex(introduction.body["obfs"].as_str().unwrap())
                .try_into()
                .unwrap(),
        };
        if punch::decode(&buf[..length], &meta).map(|(kind, _)| kind)
            == Some(punch::PacketType::Ack)
        {
            acked = true;
            break;
        }
    }
    assert!(acked);
}

#[tokio::test]
async fn a_rendezvous_error_fails_the_dial() {
    let (stun, _stun_task) = stun_server().await;
    let server = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
    let (rendezvous, _introduction) = rendezvous(server, 404).await;
    let udp = RealmUdp::open(RealmFamily::V4, None).unwrap();
    let error = establish(&udp, &config(rendezvous, stun), &env())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, RealmError::Status { status: 404, detail } if detail == ": realm_not_found: realm not registered"),
        "{error}"
    );
}

#[tokio::test(start_paused = true)]
async fn no_stun_answer_means_no_locals() {
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp = RealmUdp::open(RealmFamily::V4, None).unwrap();
    let mut config = config("127.0.0.1:9".parse().unwrap(), silent.local_addr().unwrap());
    config.stun_servers[0].port = silent.local_addr().unwrap().port();
    let error = establish(&udp, &config, &env()).await.unwrap_err();
    assert!(matches!(error, RealmError::NoLocals), "{error}");
}

/// What `tools/realm-oracle` recorded of Xray-core's realm code.
fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/realm/vectors.json"
    ))
    .unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn stun_answers_read_as_pion_and_xray_read_them() {
    let vectors = vectors();
    let cases = vectors["stun"].as_array().unwrap();
    let mut read = 0;
    for case in cases {
        let packet = unhex(case["packet"].as_str().unwrap());
        let parsed = stun::parse_binding_response(&packet);
        match case.get("mapped") {
            Some(mapped) => {
                let parsed = parsed.unwrap_or_else(|| panic!("{}", case["name"]));
                let ip = match parsed.mapped.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                    std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
                };
                let written = format!("{}/{}", punch::hex(&ip), parsed.mapped.port());
                assert_eq!(written, mapped.as_str().unwrap(), "{}", case["name"]);
                assert_eq!(
                    parsed.transaction_id.to_vec(),
                    unhex(case["transaction"].as_str().unwrap()),
                    "{}",
                    case["name"]
                );
                read += 1;
            }
            None => assert!(parsed.is_none(), "{}: {parsed:?}", case["name"]),
        }
    }
    assert!(cases.len() > 500 && read > 100, "{} {read}", cases.len());
}

#[test]
fn punch_packets_read_as_decode_punch_packet_reads_them() {
    let vectors = vectors();
    let cases = vectors["punch"].as_array().unwrap();
    for case in cases {
        let meta = punch::PunchMetadata {
            nonce: unhex(case["nonce"].as_str().unwrap()).try_into().unwrap(),
            obfs: unhex(case["obfs"].as_str().unwrap()).try_into().unwrap(),
        };
        let packet = unhex(case["packet"].as_str().unwrap());
        let decoded = punch::decode(&packet, &meta);
        match case["type"].as_u64().unwrap() {
            0 => assert!(decoded.is_none(), "{}", case["packet"]),
            kind => {
                let (decoded, padding) = decoded.unwrap();
                assert_eq!(decoded as u64, kind);
                assert_eq!(padding as u64, case["padding"].as_u64().unwrap());
                // The same salt and padding encode to the same bytes.
                let salt: [u8; 8] = packet[..8].try_into().unwrap();
                let plain_padding = {
                    let mut plain = packet[8..].to_vec();
                    let mask = {
                        use sha2::Digest;
                        sha2::Sha256::new()
                            .chain_update(meta.obfs)
                            .chain_update(salt)
                            .finalize()
                    };
                    for (i, byte) in plain.iter_mut().enumerate() {
                        *byte ^= mask[i % 32];
                    }
                    plain[25..].to_vec()
                };
                assert_eq!(
                    punch::encode_with(decoded, &meta, salt, &plain_padding),
                    packet
                );
            }
        }
    }
}

#[test]
fn candidates_are_those_xray_punches() {
    for case in vectors()["candidates"].as_array().unwrap() {
        let list = |key: &str| -> Vec<SocketAddr> {
            case[key]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|a| a.as_str().unwrap().parse().unwrap())
                        .collect()
                })
                .unwrap_or_default()
        };
        let family = match case["family"].as_u64().unwrap() {
            0 => RealmFamily::Dual,
            1 => RealmFamily::V4,
            _ => RealmFamily::V6,
        };
        let punched = candidates::punch_candidates(&list("locals"), &list("peers"), family);
        assert_eq!(punched, list("punched"), "{case}");
    }
}

#[test]
fn addresses_parse_as_parse_addr_ports_parses_them() {
    for case in vectors()["addrPorts"].as_array().unwrap() {
        let addresses: Vec<String> = case["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_owned())
            .collect();
        let parsed = candidates::parse_addr_ports(&addresses);
        // A named IPv6 zone parses in Go and not here: the whole list is
        // then lost, as Go loses it to any bad entry.
        if addresses.iter().any(|a| a.contains("%eth0")) {
            assert!(parsed.is_empty());
            continue;
        }
        let expected: Vec<SocketAddr> = case["parsed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().parse().unwrap())
            .collect();
        assert_eq!(parsed, expected, "{addresses:?}");
    }
}

#[tokio::test]
async fn the_rendezvous_request_and_answers_are_those_of_gos_client() {
    let vectors = vectors();
    for case in vectors["http"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let response = unhex(case["response"].as_str().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let read = stream.read(&mut buf).await.unwrap();
                received.extend_from_slice(&buf[..read]);
                if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&received[..end]).to_string();
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if received.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(&response).await.unwrap();
            let _ = stream.shutdown().await;
            String::from_utf8(received).unwrap()
        });
        let port_text = format!("{}{port}", case["portText"].as_str().unwrap());
        let config = RealmConfig {
            port_text: port_text.clone(),
            port,
            token: Arc::new(zeroize::Zeroizing::new(
                case["token"].as_str().unwrap().to_owned(),
            )),
            id: case["id"].as_str().unwrap().to_owned(),
            ..config(
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
            )
        };
        let meta = punch::PunchMetadata {
            nonce: [0xab; 16],
            obfs: [0x01; 32],
        };
        let answer = rendezvous::connect(
            &config,
            &env(),
            &["203.0.113.5:4000".into(), "[2001:db8::5]:4000".into()],
            &meta,
        )
        .await;
        let request = server.await.unwrap().replace(
            &format!("127.0.0.1:{port_text}"),
            &format!("127.0.0.1:{}{{port}}", case["portText"].as_str().unwrap()),
        );
        assert_eq!(request, case["request"].as_str().unwrap(), "{name}");
        match (&answer, case["error"].as_bool().unwrap_or(false)) {
            (Ok(addresses), false) => {
                let expected: Vec<String> = case["result"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(addresses, &expected, "{name}");
            }
            (Err(RealmError::Status { status, .. }), true) => {
                assert_eq!(
                    u64::from(*status),
                    case["status"].as_u64().unwrap(),
                    "{name}"
                )
            }
            (Err(error), true) => assert!(case.get("status").is_none(), "{name}: {error}"),
            (answer, _) => panic!("{name}: {answer:?}"),
        }
    }
}

#[tokio::test]
async fn a_dual_stack_socket_reaches_ipv4_and_reads_it_back_canonical() {
    let udp = RealmUdp::open(RealmFamily::Dual, None).unwrap();
    if !udp.dual_stack {
        return;
    }
    assert!(udp.local_addr().unwrap().is_ipv6());
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = peer.local_addr().unwrap();
    udp.send_to(b"ping", address).await.unwrap();
    let mut buf = [0u8; 16];
    let (length, from) = peer.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..length], b"ping");
    peer.send_to(b"pong", from).await.unwrap();
    let (length, from) = udp.recv_from(&mut buf).await.unwrap();
    assert_eq!((&buf[..length], from), (&b"pong"[..], address));
}

/// A resolver with fixed answers.
struct Answers(Vec<(&'static str, Vec<IpAddr>)>);

#[async_trait::async_trait]
impl DnsResolver for Answers {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, crate::TransportError> {
        self.resolve_all(domain, port)
            .await?
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| crate::TransportError::NoResolvedAddress(domain.into(), port))
    }

    async fn resolve_all(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<crate::DnsLookup, crate::TransportError> {
        let ips = self
            .0
            .iter()
            .find(|(name, _)| *name == domain)
            .map(|(_, ips)| ips.clone())
            .ok_or_else(|| crate::TransportError::NoResolvedAddress(domain.into(), port))?;
        Ok(crate::DnsLookup::from_ips(ips, port, None))
    }
}

#[tokio::test]
async fn stun_servers_take_the_first_address_no_server_took_with_that_port_text() {
    let udp = RealmUdp::open(RealmFamily::V4, None).unwrap();
    let ip = |text: &str| text.parse::<IpAddr>().unwrap();
    let server = |host: &str, port_text: &str, port| RealmStunServer {
        host: host.into(),
        port_text: port_text.into(),
        port,
    };
    let config = RealmConfig {
        stun_servers: vec![
            server("stun.test", "3478", 3478),
            server("stun.test", "3478", 3478),
            server("stun.test", "+3478", 3478),
            server("missing.test", "3478", 3478),
            server("2001:db8::1", "3478", 3478),
            server("192.0.2.9", "1", 1),
        ],
        ..config(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        )
    };
    let env = RealmEnv {
        resolver: Arc::new(Answers(vec![(
            "stun.test",
            vec![ip("192.0.2.1"), ip("2001:db8::2"), ip("192.0.2.2")],
        )])),
        ..env()
    };
    let servers = resolve_stun_servers(&udp, &config, &env).await;
    let expected: Vec<SocketAddr> = [
        "192.0.2.1:3478",
        "192.0.2.2:3478",
        "192.0.2.1:3478",
        "192.0.2.9:1",
    ]
    .iter()
    .map(|a| a.parse().unwrap())
    .collect();
    assert_eq!(servers, expected);
}

#[tokio::test]
async fn discovery_keeps_answers_to_its_own_requests() {
    // A STUN server answering each request twice, once for a transaction
    // nobody asked about.
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((_, from)) = socket.recv_from(&mut buf).await {
            let id: [u8; 12] = buf[8..20].try_into().unwrap();
            let stranger: SocketAddr = "192.0.2.77:7".parse().unwrap();
            let _ = socket
                .send_to(&stun::binding_success([0xEE; 12], stranger), from)
                .await;
            let _ = socket.send_to(&stun::binding_success(id, from), from).await;
        }
    });
    let udp = RealmUdp::open(RealmFamily::V4, None).unwrap();
    let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), udp.local_addr().unwrap().port());
    let locals = discover(&udp, &[address, address]).await;
    assert_eq!(locals, vec![local, local]);
}
