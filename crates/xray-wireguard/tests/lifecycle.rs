use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};
use xray_proxy::wireguard::KeyMaterial;
use xray_transport::{SocketHandle, SocketProtector};
use xray_wireguard::{Client, Config, Error};

fn config(endpoint: SocketAddr) -> Config {
    Config {
        secret_key: KeyMaterial::parse(&"42".repeat(32)).unwrap(),
        peers: vec![xray_wireguard::PeerConfig {
            public_key: KeyMaterial::parse(&"53".repeat(32)).unwrap(),
            preshared_key: None,
            endpoint,
            allowed_ips: vec!["198.51.100.0/24".parse().unwrap()],
            keepalive: 0,
        }],
        addresses: vec!["10.44.0.2".parse().unwrap()],
        mtu: 1420,
    }
}
fn target() -> SocketAddr {
    "198.51.100.7:443".parse().unwrap()
}
async fn wait_slots(client: &Client, tcp: usize, udp: usize) {
    timeout(Duration::from_secs(2), async {
        while client.available_tcp_slots() != tcp || client.available_udp_slots() != udp {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("flow permits returned");
}

#[tokio::test]
async fn short_udp_requests_do_not_exhaust_capacity_while_tun_retains_idle_flows() {
    // A TUN does not observe DatagramSocket::close. Its completed UDP requests
    // remain live until the 60-second flow idle timeout. One fresh source port
    // per second must not exhaust WireGuard after just sixteen requests.
    timeout(Duration::from_secs(5), async {
        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = Client::start(config(blackhole.local_addr().unwrap()), None)
            .await
            .unwrap();
        let capacity = client.available_udp_slots();
        let mut idle = Vec::new();
        for _ in 0..64 {
            let session = client.open_udp(target()).await.unwrap();
            session.send(b"one short request").await.unwrap();
            idle.push(session);
        }
        assert_eq!(client.available_udp_slots(), capacity - idle.len());
        drop(idle);
        wait_slots(&client, 16, capacity).await;
        client.shutdown().await;
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn pending_tcp_cancellation_udp_pressure_and_shutdown_release_all_slots() {
    timeout(Duration::from_secs(10), async {
        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = Client::start(config(blackhole.local_addr().unwrap()), None)
            .await
            .unwrap();
        let mut opens = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let client = client.clone();
            opens.spawn(async move { client.connect(target()).await });
        }
        wait_slots(&client, 0, 512).await;
        assert!(matches!(client.connect(target()).await, Err(Error::Busy)));
        opens.abort_all();
        while let Some(result) = opens.join_next().await {
            assert!(matches!(result, Err(error) if error.is_cancelled()));
        }
        wait_slots(&client, 16, 512).await;
        let mut sessions = Vec::new();
        for index in 0..512 {
            let session = client.open_udp(target()).await.unwrap();
            for _ in 0..if index < 16 { 32 } else { 1 } {
                session.send(b"unreachable peer").await.unwrap();
            }
            sessions.push(session);
        }
        assert!(matches!(client.open_udp(target()).await, Err(Error::Busy)));
        assert!(matches!(
            sessions[0].send(&[0; 1393]).await,
            Err(Error::PacketTooLarge)
        ));
        timeout(Duration::from_secs(2), client.shutdown())
            .await
            .expect("stop cannot wait on blocked packet queues");
        wait_slots(&client, 16, 512).await;
        assert!(matches!(sessions[0].recv().await, Err(Error::Closed)));
        assert!(matches!(
            sessions[0].send(b"closed").await,
            Err(Error::Closed)
        ));
        assert!(matches!(client.connect(target()).await, Err(Error::Closed)));
    })
    .await
    .unwrap();
}
struct Reject(AtomicUsize);
impl SocketProtector for Reject {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("synthetic reject"))
    }
}
#[tokio::test]
async fn validation_and_socket_protection_precede_network_io() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let reject = Arc::new(Reject(AtomicUsize::new(0)));
    let mut invalid = config(server.local_addr().unwrap());
    invalid.peers[0].public_key = KeyMaterial::parse(&"00".repeat(32)).unwrap();
    assert!(matches!(
        Client::start(invalid, Some(reject.clone())).await,
        Err(Error::Configuration)
    ));
    assert_eq!(reject.0.load(Ordering::SeqCst), 0);
    assert!(matches!(
        Client::start(config(server.local_addr().unwrap()), Some(reject.clone())).await,
        Err(Error::SocketProtection)
    ));
    assert_eq!(reject.0.load(Ordering::SeqCst), 1);
    assert!(
        timeout(Duration::from_millis(30), server.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn no_route_is_rejected_and_dropping_client_closes_retained_udp_session() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client = Client::start(config(server.local_addr().unwrap()), None)
        .await
        .unwrap();
    assert!(matches!(
        client.open_udp("192.0.2.1:443".parse().unwrap()).await,
        Err(Error::NoRoute)
    ));
    assert!(matches!(
        client.connect("[2001:db8::7]:443".parse().unwrap()).await,
        Err(Error::NoRoute)
    ));
    let session = client.open_udp(target()).await.unwrap();
    drop(client);
    assert!(matches!(
        timeout(Duration::from_secs(2), session.recv())
            .await
            .unwrap(),
        Err(Error::Closed)
    ));
}

#[test]
fn all_peer_identities_endpoints_and_aggregate_limits_are_validated() {
    let mut valid = config("127.0.0.1:51820".parse().unwrap());
    valid.peers = (0..8)
        .map(|i| {
            let mut peer = valid.peers[0].clone();
            peer.public_key = KeyMaterial::parse(&format!("{:02x}", 0x53 + i).repeat(32)).unwrap();
            peer.allowed_ips = vec!["0.0.0.0/0".parse().unwrap(); 32];
            peer
        })
        .collect();
    valid.validate().unwrap();
    for mutation in 0..7 {
        let mut cfg = valid.clone();
        match mutation {
            0 => cfg.peers.clear(),
            1 => cfg.peers.push(cfg.peers[0].clone()),
            2 => cfg.peers[7].public_key = cfg.peers[0].public_key.clone(),
            3 => cfg.peers[7].allowed_ips.push("::/0".parse().unwrap()),
            4 => cfg.peers[7].allowed_ips.clear(),
            5 => cfg.peers[7].endpoint.set_port(0),
            6 => cfg.peers[7].public_key = KeyMaterial::parse(&"00".repeat(32)).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            matches!(cfg.validate(), Err(Error::Configuration)),
            "mutation {mutation}"
        );
    }
}
struct RejectSecond(AtomicUsize);
impl SocketProtector for RejectSecond {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 1 {
            Err(std::io::Error::other("second socket rejected"))
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn second_family_protection_failure_sends_nothing_from_either_socket() {
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
    let reject = Arc::new(RejectSecond(AtomicUsize::new(0)));
    let mut cfg = config(v4.local_addr().unwrap());
    cfg.peers[0].keepalive = 1;
    let mut second = cfg.peers[0].clone();
    second.public_key = KeyMaterial::parse(&"63".repeat(32)).unwrap();
    second.endpoint = v6.local_addr().unwrap();
    cfg.peers.push(second);
    assert!(matches!(
        Client::start(cfg, Some(reject.clone())).await,
        Err(Error::SocketProtection)
    ));
    assert_eq!(reject.0.load(Ordering::SeqCst), 2);
    let mut v4_bytes = [0; 2048];
    let mut v6_bytes = [0; 2048];
    tokio::select! {
        _ = v4.recv(&mut v4_bytes) => panic!("unprotected partial device sent IPv4"),
        _ = v6.recv(&mut v6_bytes) => panic!("unprotected partial device sent IPv6"),
        _ = tokio::time::sleep(Duration::from_millis(100)) => {},
    }
}
