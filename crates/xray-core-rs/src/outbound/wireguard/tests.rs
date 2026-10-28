use super::*;
use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Notify;

#[path = "../../../../xray-wireguard/tests/support/mod.rs"]
mod reference;

/// Exercises the actual DNS carrier, including TTL expiry and TCP retry, over
/// encrypted WireGuard packets to the pinned Go reference. All DNS stays local
/// to the test via the reference's documentation-IP redirect.
#[tokio::test]
#[ignore = "requires XRAY_WIREGUARD_BINARY or NATIVE_WIREGUARD_BINARY"]
async fn wireguard_runtime_remote_dns_ttl_tcp_fallback_and_cancellation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn response(query: &[u8], tcp: bool) -> Vec<u8> {
        let label = &query[13..13 + usize::from(query[12])];
        let flags: u16 = if label == b"missing" {
            0x8183
        } else if label == b"fallback" && !tcp {
            0x8380
        } else {
            0x8180
        };
        let mut reply = query.to_vec();
        reply[2..4].copy_from_slice(&flags.to_be_bytes());
        reply[6..12].fill(0);
        if flags == 0x8180 {
            reply[7] = 1;
            // A / IN, one-second TTL, synthetic address.
            reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 198, 51, 100, 7]);
        }
        reply
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let queries = Arc::new(Mutex::new(
            std::collections::HashMap::<Vec<u8>, usize>::new(),
        ));
        let pending = Arc::new(Notify::new());
        let udp_task = {
            let queries = queries.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                let mut buffer = [0; 4096];
                loop {
                    let (n, peer) = udp.recv_from(&mut buffer).await.unwrap();
                    let query = &buffer[..n];
                    let label = &query[13..13 + usize::from(query[12])];
                    *queries.lock().unwrap().entry(label.to_vec()).or_default() += 1;
                    if label == b"pending" {
                        pending.notify_one();
                        continue;
                    }
                    let reply = response(query, false);
                    let mut unrelated = reply.clone();
                    unrelated[0] ^= 0xff;
                    udp.send_to(&unrelated, peer).await.unwrap();
                    udp.send_to(&reply, peer).await.unwrap();
                }
            })
        };
        let tcp_queries = Arc::new(AtomicUsize::new(0));
        let tcp_task = {
            let tcp_queries = tcp_queries.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    let n = usize::from(stream.read_u16().await.unwrap());
                    let mut query = vec![0; n];
                    stream.read_exact(&mut query).await.unwrap();
                    tcp_queries.fetch_add(1, Ordering::SeqCst);
                    let reply = response(&query, true);
                    stream.write_u16(reply.len() as u16).await.unwrap();
                    stream.write_all(&reply).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            })
        };
        let server_key = StaticSecret::from([0x53; 32]);
        let server = reference::Reference::start_custom(
            &server_key,
            &PublicKey::from(&StaticSecret::from([0x42; 32])),
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            port,
        )
        .await;
        let mut config = configured();
        let OutboundSettings::Wireguard(settings) = &mut config.settings else {
            panic!()
        };
        settings.addresses.retain(IpAddr::is_ipv4);
        settings.remote_dns = vec!["198.51.100.53".parse().unwrap()];
        settings.peers[0].endpoint = TargetAddr::Ip(server.address.ip());
        settings.peers[0].port = server.address.port();
        settings.peers[0].public_key = xray_proxy::wireguard::KeyMaterial::parse(
            &PublicKey::from(&server_key)
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        let outbound = WireguardOutbound::new(&config).unwrap();
        let host_dns = PendingDns::default();
        let dialer = TransportDialer::system().unwrap();
        let destination = |name: &str| {
            Target::new(
                RoutingTargetAddr::Domain(format!("{name}.example")),
                443,
                RoutingNetwork::Udp,
            )
        };
        for _ in 0..2 {
            outbound
                .open_udp(&destination("cached"), &host_dns, &host_dns, &dialer)
                .await
                .unwrap();
        }
        assert_eq!(queries.lock().unwrap().get(b"cached".as_slice()), Some(&1));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        outbound
            .open_udp(&destination("cached"), &host_dns, &host_dns, &dialer)
            .await
            .unwrap();
        assert_eq!(queries.lock().unwrap().get(b"cached".as_slice()), Some(&2));
        outbound
            .open_udp(&destination("fallback"), &host_dns, &host_dns, &dialer)
            .await
            .unwrap();
        assert_eq!(tcp_queries.load(Ordering::SeqCst), 1);
        for _ in 0..2 {
            assert!(outbound
                .open_udp(&destination("missing"), &host_dns, &host_dns, &dialer)
                .await
                .is_err());
        }
        assert_eq!(queries.lock().unwrap().get(b"missing".as_slice()), Some(&1));
        let target = destination("pending");
        let attempt = outbound.open_udp(&target, &host_dns, &host_dns, &dialer);
        tokio::pin!(attempt);
        tokio::select! {
            _ = pending.notified() => {},
            _ = &mut attempt => panic!("pending DNS completed before close"),
        }
        outbound.close();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), attempt)
                .await
                .unwrap(),
            Err(CoreError::Wireguard(Error::Closed))
        ));
        assert_eq!(
            host_dns.calls.load(Ordering::SeqCst),
            0,
            "destination DNS must never reach the host resolver"
        );
        udp_task.abort();
        tcp_task.abort();
    })
    .await
    .unwrap();
}

fn configured() -> OutboundConfig {
    xray_config::parse_xray_json(include_str!(
        "../../../../../tests/fixtures/configs/wireguard.json"
    ))
    .unwrap()
    .config
    .outbounds
    .remove(0)
}

#[derive(Default)]
struct PendingDns {
    entered: Notify,
    active: AtomicUsize,
    calls: AtomicUsize,
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl DnsResolver for PendingDns {
    async fn resolve(&self, _domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
        self.active.fetch_add(1, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _active = Active(&self.active);
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[test]
fn typed_wireguard_contract_is_checked_before_runtime_start() {
    for mutation in 0..12 {
        let mut config = configured();
        let OutboundSettings::Wireguard(settings) = &mut config.settings else {
            panic!()
        };
        if mutation >= 7 {
            let mut second = settings.peers[0].clone();
            second.public_key =
                xray_proxy::wireguard::KeyMaterial::parse(&"63".repeat(32)).unwrap();
            settings.peers.push(second);
        }
        match mutation {
            0 => settings.mtu = 9000,
            1 => {
                settings.peers[0].public_key =
                    xray_proxy::wireguard::KeyMaterial::parse(&"00".repeat(32)).unwrap()
            }
            2 => settings.addresses.push(settings.addresses[0]),
            3 => settings.peers[0].allowed_ips.clear(),
            4 => settings.peers[0].port = 0,
            5 => settings.peers[0].endpoint = TargetAddr::Domain("invalid host".into()),
            6 => config.stream.network = Network::Udp,
            7 => settings.peers[1].public_key = settings.peers[0].public_key.clone(),
            8 => settings.peers[1].endpoint = TargetAddr::Domain("invalid host".into()),
            9 => settings.peers[1].allowed_ips = vec!["::/0".parse().unwrap(); 256],
            10 => settings.peers = vec![settings.peers[0].clone(); 9],
            11 => {
                settings.peers[1].public_key =
                    xray_proxy::wireguard::KeyMaterial::parse(&"00".repeat(32)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(WireguardOutbound::new(&config).is_err());
        let mut whole = xray_config::parse_xray_json(include_str!(
            "../../../../../tests/fixtures/configs/wireguard.json"
        ))
        .unwrap()
        .config;
        whole.outbounds[0] = config;
        assert!(crate::Core::new(whole).is_err());
    }
}
fn target() -> Target {
    Target::new(
        RoutingTargetAddr::Ip("198.51.100.7".parse().unwrap()),
        443,
        RoutingNetwork::Udp,
    )
}

#[tokio::test]
async fn wireguard_rebind_during_creation_is_not_lost_and_idle_clients_stay_lazy() {
    struct RebindOnProtect {
        owner: std::sync::Weak<Owner>,
        calls: AtomicUsize,
    }
    impl xray_transport::SocketProtector for RebindOnProtect {
        fn protect(&self, _: xray_transport::SocketHandle) -> std::io::Result<()> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                assert!(!WireguardOutbound(self.owner.upgrade().unwrap()).rebind());
            }
            Ok(())
        }
    }
    let mut config = configured();
    let OutboundSettings::Wireguard(settings) = &mut config.settings else {
        panic!()
    };
    for peer in &mut settings.peers {
        peer.endpoint = TargetAddr::Ip("127.0.0.1".parse().unwrap());
        peer.port = 9;
    }
    let outbound = WireguardOutbound::new(&config).unwrap();
    assert!(!outbound.rebind());
    assert!(outbound.0.session.lock().unwrap().is_none());
    let protector = Arc::new(RebindOnProtect {
        owner: Arc::downgrade(&outbound.0),
        calls: AtomicUsize::new(0),
    });
    let dialer = TransportDialer::system()
        .unwrap()
        .with_socket_protector(protector.clone());
    let dns = PendingDns::default();
    let _flow = outbound
        .open_udp(&target(), &dns, &dns, &dialer)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while protector.calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(protector.calls.load(Ordering::SeqCst), 2);
    let client = outbound
        .0
        .session
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .client
        .clone();
    outbound.close();
    client.shutdown().await;
    assert!(!outbound.rebind());
}
#[tokio::test]
async fn wireguard_close_cancels_bootstrap_and_waiting_callers() {
    let outbound = WireguardOutbound::new(&configured()).unwrap();
    let dns = Arc::new(PendingDns::default());
    let dialer = Arc::new(TransportDialer::system().unwrap());
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let outbound = outbound.clone();
        let dns = dns.clone();
        let dialer = dialer.clone();
        attempts.spawn(async move {
            outbound
                .open_udp(&target(), dns.as_ref(), dns.as_ref(), &dialer)
                .await
                .err()
        });
    }
    dns.entered.notified().await;
    outbound.close();
    while let Some(result) = tokio::time::timeout(Duration::from_secs(1), attempts.join_next())
        .await
        .unwrap()
    {
        assert!(matches!(
            result.unwrap(),
            Some(CoreError::Wireguard(Error::Closed))
        ));
    }
    assert_eq!(dns.active.load(Ordering::SeqCst), 0);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        outbound
            .open_udp(&target(), dns.as_ref(), dns.as_ref(), &dialer)
            .await,
        Err(CoreError::Wireguard(Error::Closed))
    ));
}

#[tokio::test(start_paused = true)]
async fn wireguard_total_deadline_and_caller_cancellation_release_single_flight() {
    let outbound = WireguardOutbound::new(&configured()).unwrap();
    let dns = PendingDns::default();
    let dialer = TransportDialer::system().unwrap();
    let start = tokio::time::Instant::now();
    assert!(matches!(
        outbound.open_udp(&target(), &dns, &dns, &dialer).await,
        Err(CoreError::Wireguard(Error::Timeout))
    ));
    assert_eq!(start.elapsed(), Duration::from_secs(10));
    assert_eq!(dns.active.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        assert!(tokio::time::timeout(
            Duration::from_millis(1),
            outbound.open_udp(&target(), &dns, &dns, &dialer)
        )
        .await
        .is_err());
        assert_eq!(dns.active.load(Ordering::SeqCst), 0);
    }
    assert_eq!(
        dns.calls.load(Ordering::SeqCst),
        3,
        "cancelled owner must release the connection admission lock"
    );
}
