#[path = "support/fault_relay.rs"]
mod fault_relay;
mod support;

use fault_relay::{Fault, Relay};
use serde_json::json;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinSet,
    time::{timeout, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_proxy::wireguard::KeyMaterial;
use xray_wireguard::{Client, Config, PeerConfig};

const DEADLINE: Duration = Duration::from_secs(5);
fn config(endpoint: SocketAddr) -> Config {
    let key = |bytes: &[u8; 32]| {
        KeyMaterial::parse(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap()
    };
    Config {
        secret_key: key(&[0x42; 32]),
        peers: vec![PeerConfig {
            public_key: key(PublicKey::from(&StaticSecret::from([0x53; 32])).as_bytes()),
            preshared_key: Some(key(&[0x64; 32])),
            endpoint,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            keepalive: 0,
        }],
        addresses: vec!["10.44.0.2".parse().unwrap(), "fd44::2".parse().unwrap()],
        mtu: 1420,
    }
}
async fn reference() -> support::Reference {
    assert!(std::env::var_os("NATIVE_WIREGUARD_BINARY").is_some());
    support::Reference::start_with_psk(
        &StaticSecret::from([0x53; 32]),
        &PublicKey::from(&StaticSecret::from([0x42; 32])),
        Some(&[0x64; 32]),
    )
    .await
}
struct Echo {
    tcp: u16,
    udp: u16,
    _tasks: JoinSet<()>,
}
impl Echo {
    async fn start() -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tcp_port, udp_port) = (
            tcp.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
        );
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = tcp.accept() => {
                        let (mut socket, _) = accepted.unwrap();
                        connections.spawn(async move {
                            let (mut r, mut w) = socket.split();
                            let _ = tokio::io::copy(&mut r, &mut w).await;
                            let _ = w.shutdown().await;
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        tasks.spawn(async move {
            let mut buffer = [0; 2048];
            loop {
                let (n, from) = udp.recv_from(&mut buffer).await.unwrap();
                assert_eq!(udp.send_to(&buffer[..n], from).await.unwrap(), n);
            }
        });
        Self {
            tcp: tcp_port,
            udp: udp_port,
            _tasks: tasks,
        }
    }
}
async fn matrix(client: &Client, echo: &Echo, relay: &Relay, label: &str) {
    // Match the failed Android probe's order and keep a single UDP request.
    for ip in ["198.51.100.7", "2001:db8::7"] {
        for protocol in ["tcp", "udp"] {
            let payload = format!("{label}/{ip}/{protocol}");
            relay.mark(json!({"request": payload}));
            let start = Instant::now();
            timeout(DEADLINE, async {
                if protocol == "tcp" {
                    let mut stream = client
                        .connect(SocketAddr::new(ip.parse().unwrap(), echo.tcp))
                        .await
                        .unwrap();
                    stream.write_all(payload.as_bytes()).await.unwrap();
                    let mut reply = vec![0; payload.len()];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, payload.as_bytes());
                    stream.shutdown().await.unwrap();
                    let mut remainder = Vec::new();
                    stream.read_to_end(&mut remainder).await.unwrap();
                    assert!(remainder.is_empty());
                } else {
                    let session = client
                        .open_udp(SocketAddr::new(ip.parse().unwrap(), echo.udp))
                        .await
                        .unwrap();
                    session.send(payload.as_bytes()).await.unwrap();
                    assert_eq!(&session.recv().await.unwrap()[..], payload.as_bytes());
                }
            })
            .await
            .unwrap_or_else(|_| {
                relay.save("failed-lifecycle");
                panic!("single-request deadline: {payload}")
            });
            relay.mark(
                json!({"received": payload, "requestElapsedUs": start.elapsed().as_micros()}),
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires official wireguard-go; use check-wireguard-timeouts.sh"]
async fn native_single_request_cold_restart_and_rebind_matrix() {
    let repeats: usize = std::env::var("WIREGUARD_TIMEOUT_REPEATS")
        .unwrap_or_else(|_| "10".into())
        .parse()
        .unwrap();
    assert!((1..=1000).contains(&repeats));
    let echo = Echo::start().await;
    for iteration in 0..repeats {
        // Fresh server per iteration avoids exhausting the fixture's 32-slot
        // forwarding budget with old UDP mappings (10-second idle lifetime).
        let _server = reference().await;
        let relay = Relay::start(_server.address).await;
        let client = Client::start(config(relay.address), None).await.unwrap();
        matrix(&client, &echo, &relay, "cold").await;
        timeout(DEADLINE, client.shutdown()).await.unwrap();
        assert_eq!(client.available_udp_slots(), 512);
        assert_eq!(client.available_tcp_slots(), 16);
        // A separate rapid-restart case records the peer's 20 ms handshake
        // flood guard. This ordinary lifecycle case explicitly stays outside it.
        relay.mark(json!({"restartGapMs": 50}));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = Client::start(config(relay.address), None).await.unwrap();
        matrix(&client, &echo, &relay, "restart").await;
        assert!(client.rebind());
        matrix(&client, &echo, &relay, "rebind").await;
        timeout(DEADLINE, client.shutdown()).await.unwrap();
        relay.save(&format!("lifecycle-{iteration:03}"));
    }
}

#[tokio::test]
#[ignore = "requires official wireguard-go and real handshake retry timer"]
async fn native_lost_handshake_preserves_one_pending_udp_without_application_retry() {
    for (name, fault) in [
        ("initiation", Fault::FirstInitiation),
        ("response", Fault::FirstResponse),
    ] {
        let _server = reference().await;
        let relay = Relay::start(_server.address).await;
        let echo = Echo::start().await;
        relay.arm(fault);
        let client = Client::start(config(relay.address), None).await.unwrap();
        let session = client
            .open_udp(SocketAddr::new("2001:db8::7".parse().unwrap(), echo.udp))
            .await
            .unwrap();
        let start = Instant::now();
        session.send(b"one pending IPv6 UDP").await.unwrap();
        let early = timeout(DEADLINE, session.recv()).await;
        relay.mark(json!({"originalFiveSecondDeadlinePassed": early.is_ok(), "elapsedUs": start.elapsed().as_micros()}));
        let reply = match early {
            Ok(reply) => reply.unwrap(),
            Err(_) => timeout(Duration::from_secs(8), session.recv())
                .await
                .expect("pending packet must recover without resending")
                .unwrap(),
        };
        assert_eq!(&reply[..], b"one pending IPv6 UDP");
        relay.mark(
            json!({"eventualRecoveryUs": start.elapsed().as_micros(), "applicationSends": 1}),
        );
        timeout(DEADLINE, client.shutdown()).await.unwrap();
        relay.save(&format!("lost-{name}"));
    }
}

#[tokio::test]
#[ignore = "requires official wireguard-go and original five-second UDP deadline"]
async fn native_lost_established_udp_does_not_stall_next_request() {
    for (name, fault) in [
        ("upload", Fault::NextClientData),
        ("download", Fault::NextServerData),
    ] {
        let _server = reference().await;
        let relay = Relay::start(_server.address).await;
        let echo = Echo::start().await;
        let client = Client::start(config(relay.address), None).await.unwrap();
        matrix(&client, &echo, &relay, "warmup").await;
        let session = client
            .open_udp(SocketAddr::new("2001:db8::7".parse().unwrap(), echo.udp))
            .await
            .unwrap();
        relay.arm(fault);
        session.send(b"intentionally lost").await.unwrap();
        assert!(timeout(DEADLINE, session.recv()).await.is_err());
        relay.mark(json!({"originalFiveSecondDeadlinePassed": false, "intentionalLoss": name}));
        session.send(b"next independent request").await.unwrap();
        assert_eq!(
            &timeout(DEADLINE, session.recv()).await.unwrap().unwrap()[..],
            b"next independent request"
        );
        relay.mark(json!({"nextRequestPassed": true}));
        timeout(DEADLINE, client.shutdown()).await.unwrap();
        relay.save(&format!("lost-data-{name}"));
    }
}

#[tokio::test]
#[ignore = "requires official wireguard-go; characterizes rapid restart and its real retry timer"]
async fn native_rapid_restart_retains_pending_udp_across_peer_flood_guard() {
    let server = reference().await;
    let relay = Relay::start(server.address).await;
    let echo = Echo::start().await;
    let endpoint = SocketAddr::new("2001:db8::7".parse().unwrap(), echo.udp);
    let first = Client::start(config(relay.address), None).await.unwrap();
    let session = first.open_udp(endpoint).await.unwrap();
    session.send(b"before immediate restart").await.unwrap();
    assert_eq!(
        &timeout(DEADLINE, session.recv()).await.unwrap().unwrap()[..],
        b"before immediate restart"
    );
    timeout(DEADLINE, first.shutdown()).await.unwrap();
    let client = Client::start(config(relay.address), None).await.unwrap();
    let session = client.open_udp(endpoint).await.unwrap();
    let started = Instant::now();
    session
        .send(b"one request after immediate restart")
        .await
        .unwrap();
    let early = timeout(DEADLINE, session.recv()).await;
    relay.mark(json!({"originalFiveSecondDeadlinePassed": early.is_ok(), "applicationSends": 1}));
    let reply = match early {
        Ok(reply) => reply.unwrap(),
        Err(_) => timeout(Duration::from_secs(8), session.recv())
            .await
            .expect("rapid restart recovery")
            .unwrap(),
    };
    assert_eq!(&reply[..], b"one request after immediate restart");
    relay.mark(json!({"eventualRecoveryUs": started.elapsed().as_micros()}));
    let log = std::fs::read_to_string(server.directory.join("log")).unwrap();
    relay.mark(json!({"referenceReportedHandshakeFlood": log.contains("handshake flood")}));
    if let Some(directory) = std::env::var_os("WIREGUARD_TIMEOUT_REPORT_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("rapid-restart-reference.log"),
            log,
        )
        .unwrap();
    }
    timeout(DEADLINE, client.shutdown()).await.unwrap();
    relay.save("rapid-restart-recovery");
}
