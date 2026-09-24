#[path = "multi_peer/raw.rs"]
mod raw;
use raw::{key, reply, RawPeer};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::timeout;
use xray_transport::{SocketHandle, SocketProtector};
use xray_wireguard::{Client, Config};

#[derive(Default)]
struct Protector(AtomicUsize);
impl SocketProtector for Protector {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn overlapping_peers_route_and_reject_authenticated_source_spoofing_in_both_families() {
    timeout(Duration::from_secs(20), async {
        let mut peers = [
            RawPeer::start(0x53, false, &["0.0.0.0/0", "::/0"]).await,
            RawPeer::start(
                0x63,
                true,
                &[
                    "198.51.100.1/24",
                    "2001:db8:b::1/64",
                    "198.51.100.7/32",
                    "2001:db8:b::7/128",
                ],
            )
            .await,
            RawPeer::start(0x73, false, &["198.51.100.99/24", "2001:db8:b::99/64"]).await,
        ];
        let protector = Arc::new(Protector::default());
        let client = Client::start(
            Config {
                secret_key: key(&[0x42; 32]),
                peers: peers.iter().map(|p| p.config.clone()).collect(),
                addresses: vec!["10.44.0.2".parse().unwrap(), "fd44::2".parse().unwrap()],
                mtu: 1420,
            },
            Some(protector.clone()),
        )
        .await
        .unwrap();
        for addresses in [
            ["192.0.2.10:443", "198.51.100.7:443", "198.51.100.8:443"],
            [
                "[2001:db8:a::10]:443",
                "[2001:db8:b::7]:443",
                "[2001:db8:b::8]:443",
            ],
        ] {
            let mut sessions = Vec::new();
            let mut requests = Vec::new();
            for (index, address) in addresses.into_iter().enumerate() {
                let session = client.open_udp(address.parse().unwrap()).await.unwrap();
                session.send(b"request!").await.unwrap();
                // This also proves selection: longest prefix wins, then last
                // configured peer for identical normalized prefixes.
                let request = peers[index].received.recv().await.unwrap().into_bytes();
                peers[index]
                    .inject
                    .send(reply(&request, b"correct!"))
                    .await
                    .unwrap();
                assert_eq!(&session.recv().await.unwrap()[..], b"correct!");
                requests.push(request);
                sessions.push(session);
            }
            for owner in 0..3 {
                for attacker in 0..3 {
                    if attacker == owner {
                        continue;
                    }
                    peers[attacker]
                        .inject
                        .send(reply(&requests[owner], b"spoofed!"))
                        .await
                        .unwrap();
                    // The attacker's own authenticated flow is live too.
                    peers[attacker]
                        .inject
                        .send(reply(&requests[attacker], b"barrier!"))
                        .await
                        .unwrap();
                    assert_eq!(&sessions[attacker].recv().await.unwrap()[..], b"barrier!");
                    assert!(
                        timeout(Duration::from_millis(100), sessions[owner].recv())
                            .await
                            .is_err(),
                        "peer {attacker} impersonated peer {owner}"
                    );
                    peers[owner]
                        .inject
                        .send(reply(&requests[owner], b"correct!"))
                        .await
                        .unwrap();
                    assert_eq!(&sessions[owner].recv().await.unwrap()[..], b"correct!");
                }
            }
        }
        assert_eq!(
            protector.0.load(Ordering::SeqCst),
            2,
            "sockets are shared by endpoint family"
        );
        client.shutdown().await;
        assert_eq!(client.available_tcp_slots(), 16);
        assert_eq!(client.available_udp_slots(), 512);
        for peer in &mut peers {
            peer.shutdown().await;
        }
    })
    .await
    .expect("multi-peer isolation deadline");
}

#[tokio::test]
async fn unavailable_specific_peer_never_falls_back_to_broader_peer_and_budgets_stay_shared() {
    for dead_peer_count in [1u8, 2, 7] {
        timeout(Duration::from_secs(10), async {
            let mut healthy = RawPeer::start(0x53, false, &["0.0.0.0/0"]).await;
            let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut peers = vec![healthy.config.clone()];
            for i in 0..dead_peer_count {
                peers.push(xray_wireguard::PeerConfig {
                    public_key: key(x25519_dalek::PublicKey::from(
                        &x25519_dalek::StaticSecret::from([0x63 + i; 32]),
                    )
                    .as_bytes()),
                    endpoint: blackhole.local_addr().unwrap(),
                    allowed_ips: vec![format!("198.51.100.{}/32", 7 + i).parse().unwrap()],
                    preshared_key: None,
                    keepalive: 0,
                });
            }
            let client = Client::start(
                Config {
                    secret_key: key(&[0x42; 32]),
                    peers,
                    addresses: vec!["10.44.0.2".parse().unwrap()],
                    mtu: 1420,
                },
                None,
            )
            .await
            .unwrap();
            let mut sessions = Vec::new();
            for i in 0..511 {
                let session = client
                    .open_udp(
                        format!("198.51.100.{}:443", 7 + i % usize::from(dead_peer_count))
                            .parse()
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                for _ in 0..if i < 16 { 32 } else { 1 } {
                    session.send(b"private!").await.unwrap();
                }
                sessions.push(session);
            }
            let good = client
                .open_udp("192.0.2.10:443".parse().unwrap())
                .await
                .unwrap();
            good.send(b"healthy!").await.unwrap();
            let request = healthy.received.recv().await.unwrap().into_bytes();
            healthy
                .inject
                .send(reply(&request, b"healthy!"))
                .await
                .unwrap();
            assert_eq!(&good.recv().await.unwrap()[..], b"healthy!");
            assert!(
                timeout(Duration::from_millis(200), healthy.received.recv())
                    .await
                    .is_err(),
                "private traffic escaped via default peer"
            );
            assert!(matches!(
                client.open_udp("192.0.2.11:443".parse().unwrap()).await,
                Err(xray_wireguard::Error::Busy)
            ));
            client.shutdown().await;
            assert_eq!(client.available_udp_slots(), 512);
            healthy.shutdown().await;
        })
        .await
        .unwrap();
    }
}
