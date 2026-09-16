use super::*;
use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Notify;

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
