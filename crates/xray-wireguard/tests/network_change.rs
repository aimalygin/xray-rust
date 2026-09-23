mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_proxy::wireguard::KeyMaterial;
use xray_transport::{SocketHandle, SocketProtector};
use xray_wireguard::{Client, Config, PeerConfig};

#[derive(Default)]
struct Protector {
    calls: AtomicUsize,
    fail_at: usize,
}
impl SocketProtector for Protector {
    fn protect(&self, _: SocketHandle) -> io::Result<()> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.fail_at {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}
fn config(endpoint: SocketAddr) -> Config {
    let key = |bytes: &[u8]| KeyMaterial::parse(&STANDARD.encode(bytes)).unwrap();
    Config {
        secret_key: key(&[0x42; 32]),
        peers: vec![PeerConfig {
            public_key: key(PublicKey::from(&StaticSecret::from([0x53; 32])).as_bytes()),
            preshared_key: Some(key(&[0x64; 32])),
            endpoint,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            keepalive: 1,
        }],
        addresses: vec!["10.44.0.2".parse().unwrap(), "fd44::2".parse().unwrap()],
        mtu: 1420,
    }
}

#[tokio::test]
async fn rebind_protection_failure_closes_client_and_releases_flows() {
    let protector = Arc::new(Protector {
        fail_at: 2,
        ..Default::default()
    });
    let client = Client::start(
        config("127.0.0.1:9".parse().unwrap()),
        Some(protector.clone()),
    )
    .await
    .unwrap();
    let flow = client
        .open_udp("198.51.100.7:9".parse().unwrap())
        .await
        .unwrap();
    assert!(client.rebind());
    timeout(Duration::from_secs(2), async {
        while client.is_live() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(flow.send(b"must not escape protection").await.is_err());
    client.shutdown().await;
    assert_eq!(protector.calls.load(Ordering::SeqCst), 2);
    assert!(!client.rebind());
    assert_eq!(client.available_udp_slots(), 512);
}

#[tokio::test]
#[ignore = "requires official wireguard-go; use check-native-wireguard-interop.sh"]
async fn native_rebind_preserves_existing_tcp_udp_flows_in_both_outer_families() {
    assert!(std::env::var_os("NATIVE_WIREGUARD_BINARY").is_some());
    timeout(Duration::from_secs(45), async {
        for ip in ["127.0.0.1", "::1"] {
            let outer: IpAddr = ip.parse().unwrap();
            let reference = support::Reference::start_custom(
                &StaticSecret::from([0x53; 32]),
                &PublicKey::from(&StaticSecret::from([0x42; 32])),
                Some(&[0x64; 32]),
                outer,
                0,
            )
            .await;
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_port = tcp.local_addr().unwrap().port();
            let tcp_task = tokio::spawn(async move {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write).await.unwrap();
            });
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_port = udp.local_addr().unwrap().port();
            let udp_task = tokio::spawn(async move {
                let mut data = [0; 2048];
                loop {
                    let (n, addr) = udp.recv_from(&mut data).await.unwrap();
                    udp.send_to(&data[..n], addr).await.unwrap();
                }
            });
            let protector = Arc::new(Protector::default());
            let client = Client::start(config(reference.address), Some(protector.clone()))
                .await
                .unwrap();
            let mut stream = client
                .connect(SocketAddr::new("198.51.100.7".parse().unwrap(), tcp_port))
                .await
                .unwrap();
            let datagrams = client
                .open_udp(SocketAddr::new("2001:db8::7".parse().unwrap(), udp_port))
                .await
                .unwrap();
            for iteration in 0..3 {
                if iteration > 0 {
                    // A burst is bounded; none of these requests opens new
                    // inner application flows or creates a new client.
                    for _ in 0..10 {
                        assert!(client.rebind());
                    }
                    timeout(Duration::from_secs(2), async {
                        while protector.calls.load(Ordering::SeqCst) < iteration + 1 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .unwrap();
                }
                let payload = vec![iteration as u8 + 1; 32_768];
                let (mut read, mut write) = tokio::io::split(&mut stream);
                let mut received = vec![0; payload.len()];
                timeout(Duration::from_secs(8), async {
                    let (sent, got) =
                        tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
                    sent.unwrap();
                    got.unwrap();
                })
                .await
                .unwrap();
                assert_eq!(received, payload);
                // UDP may lose a datagram while the sockets are being replaced.
                timeout(Duration::from_secs(8), async {
                    loop {
                        datagrams.send(b"same inner UDP flow").await.unwrap();
                        if let Ok(reply) =
                            timeout(Duration::from_millis(250), datagrams.recv()).await
                        {
                            assert_eq!(&reply.unwrap()[..], b"same inner UDP flow");
                            break;
                        }
                    }
                })
                .await
                .unwrap();
            }
            assert_eq!(
                protector.calls.load(Ordering::SeqCst),
                3,
                "one new protected socket per coalesced burst"
            );
            client.shutdown().await;
            assert_eq!(client.available_tcp_slots(), 16);
            assert_eq!(client.available_udp_slots(), 512);
            tcp_task.abort();
            udp_task.abort();
        }
    })
    .await
    .expect("network rebind deadline");
}

/// Exercise a fresh TCP flow across two spaced carrier rebinds, with queued
/// replies and a short carrier outage. Healthy-loopback rebinds do not cover
/// the in-flight data that is present when an iPhone returns to Wi-Fi.
#[tokio::test]
#[ignore = "requires official wireguard-go; use check-native-wireguard-interop.sh"]
async fn native_rebind_during_tcp_transfer_recovers_without_reopening() {
    use std::collections::VecDeque;
    use tokio::time::{sleep, Instant};
    assert!(std::env::var_os("NATIVE_WIREGUARD_BINARY").is_some());
    for ip in ["127.0.0.1", "::1"] {
        let reference = support::Reference::start_custom(
            &StaticSecret::from([0x53; 32]),
            &PublicKey::from(&StaticSecret::from([0x42; 32])),
            Some(&[0x64; 32]),
            ip.parse().unwrap(),
            0,
        )
        .await;
        let front = UdpSocket::bind((ip, 0)).await.unwrap();
        let endpoint = front.local_addr().unwrap();
        let back = UdpSocket::bind((ip, 0)).await.unwrap();
        let server = reference.address;
        let epoch = Instant::now();
        let initiations = Arc::new(AtomicUsize::new(0));
        let observed_initiations = initiations.clone();
        let relay = tokio::spawn(async move {
            let mut client = None;
            let mut outgoing = VecDeque::new();
            let mut a = [0; 2048];
            let mut b = [0; 2048];
            loop {
                let due = outgoing
                    .front()
                    .map(|(at, _, _, _)| *at)
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
                tokio::select! {
                    packet = front.recv_from(&mut a) => {
                        let (n, source) = packet.unwrap();
                        client = Some(source);
                        if a[..n].starts_with(&[1,0,0,0]) { observed_initiations.fetch_add(1, Ordering::SeqCst); }
                        if !(Duration::from_millis(650)..Duration::from_millis(1100)).contains(&epoch.elapsed()) {
                            assert!(outgoing.len() < 256, "bounded relay queue");
                            outgoing.push_back((Instant::now() + Duration::from_millis(100), false, server, a[..n].to_vec()));
                        }
                    },
                    packet = back.recv_from(&mut b) => {
                        let (n, source) = packet.unwrap();
                        assert_eq!(source, server);
                        if let Some(client) = client {
                            assert!(outgoing.len() < 256, "bounded relay queue");
                            outgoing.push_back((Instant::now() + Duration::from_millis(100), true, client, b[..n].to_vec()));
                        }
                    },
                    _ = tokio::time::sleep_until(due) => {
                        let (_, to_client, address, bytes) = outgoing.pop_front().unwrap();
                        let socket = if to_client { &front } else { &back };
                        socket.send_to(&bytes, address).await.unwrap();
                    }
                }
            }
        });
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        let protector = Arc::new(Protector::default());
        let client = Client::start(config(endpoint), Some(protector.clone()))
            .await
            .unwrap();
        let rebind_client = client.clone();
        let changes = tokio::spawn(async move {
            sleep(Duration::from_millis(700)).await;
            assert!(rebind_client.rebind());
            sleep(Duration::from_millis(1500)).await;
            assert!(rebind_client.rebind());
        });
        let started = Instant::now();
        let result = timeout(Duration::from_secs(8), async {
            let mut stream = client
                .connect(SocketAddr::new("198.51.100.7".parse().unwrap(), port))
                .await
                .unwrap();
            let payload = vec![0x67; 65_536];
            let mut received = vec![0; payload.len()];
            let (mut read, mut write) = tokio::io::split(&mut stream);
            let (sent, got) =
                tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
            sent.unwrap();
            got.unwrap();
            assert_eq!(payload, received);
        })
        .await;
        eprintln!(
            "{ip}: first TCP transfer across rebinds took {:?}",
            started.elapsed()
        );
        changes.await.unwrap();
        client.shutdown().await;
        relay.abort();
        echo.abort();
        assert_eq!(protector.calls.load(Ordering::SeqCst), 3);
        assert_eq!(client.available_tcp_slots(), 16);
        result.expect("first TCP flow must recover without an application retry");
        assert_eq!(
            initiations.load(Ordering::SeqCst),
            1,
            "carrier changes must retain the authenticated WireGuard session"
        );
    }
}
