use super::*;
use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Notify;

fn configured() -> OutboundConfig {
    xray_config::parse_xray_json(include_str!(
        "../../../../../tests/fixtures/configs/hysteria2.json"
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
fn typed_hysteria_contract_is_checked_before_runtime_start() {
    for mutation in 0..7 {
        let mut config = configured();
        match mutation {
            0 => config.stream.network = Network::Tcp,
            1 => config.stream.security = StreamSecurity::None,
            2 => {
                if let StreamSecurity::Tls(tls) = &mut config.stream.security {
                    tls.allow_insecure = true;
                }
            }
            3 => {
                if let StreamSecurity::Tls(tls) = &mut config.stream.security {
                    tls.fingerprint = Some("chrome".into());
                }
            }
            4 => {
                if let StreamSecurity::Tls(tls) = &mut config.stream.security {
                    tls.alpn = vec!["h2".into()];
                }
            }
            5 => {
                if let StreamTransport::Hysteria(auth) = &mut config.stream.transport {
                    auth.auth = zeroize::Zeroizing::new("secret\r\n".into());
                }
            }
            6 => {
                if let OutboundSettings::Hysteria(server) = &mut config.settings {
                    server.port = 0;
                }
            }
            _ => unreachable!(),
        }
        assert!(HysteriaOutbound::new(&config).is_err());
        let mut whole = xray_config::parse_xray_json(include_str!(
            "../../../../../tests/fixtures/configs/hysteria2.json"
        ))
        .unwrap()
        .config;
        whole.outbounds[0] = config;
        assert!(
            crate::Core::new(whole).is_err(),
            "typed invalid config must fail before start"
        );
    }
}

#[tokio::test]
async fn hysteria_close_cancels_bootstrap_and_waiting_callers() {
    let outbound = HysteriaOutbound::new(&configured()).unwrap();
    let dns = Arc::new(PendingDns::default());
    let dialer = Arc::new(TransportDialer::system().unwrap());
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let outbound = outbound.clone();
        let dns = dns.clone();
        let dialer = dialer.clone();
        attempts.spawn(async move { outbound.open_udp(dns.as_ref(), &dialer).await.err() });
    }
    dns.entered.notified().await;
    outbound.close();
    while let Some(result) = tokio::time::timeout(Duration::from_secs(1), attempts.join_next())
        .await
        .unwrap()
    {
        assert!(matches!(
            result.unwrap(),
            Some(CoreError::Hysteria(HysteriaError::Closed))
        ));
    }
    assert_eq!(dns.active.load(Ordering::SeqCst), 0);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        outbound.open_udp(dns.as_ref(), &dialer).await,
        Err(CoreError::Hysteria(HysteriaError::Closed))
    ));
}

#[tokio::test(start_paused = true)]
async fn hysteria_total_deadline_and_caller_cancellation_release_single_flight() {
    let outbound = HysteriaOutbound::new(&configured()).unwrap();
    let dns = PendingDns::default();
    let dialer = TransportDialer::system().unwrap();
    let start = tokio::time::Instant::now();
    assert!(matches!(
        outbound.open_udp(&dns, &dialer).await,
        Err(CoreError::Hysteria(HysteriaError::Timeout))
    ));
    assert_eq!(start.elapsed(), Duration::from_secs(10));
    assert_eq!(dns.active.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        assert!(
            tokio::time::timeout(Duration::from_millis(1), outbound.open_udp(&dns, &dialer))
                .await
                .is_err()
        );
        assert_eq!(dns.active.load(Ordering::SeqCst), 0);
    }
    assert_eq!(
        dns.calls.load(Ordering::SeqCst),
        3,
        "cancelled owner must release the connection admission lock"
    );
}

#[path = "../../../../xray-transport/tests/hysteria/support.rs"]
mod rebind_reference;

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn hysteria_rebind_during_auth_is_not_lost_and_idle_clients_stay_lazy() {
    struct DuringProtect {
        owner: std::sync::Weak<SessionOwner>,
        calls: AtomicUsize,
    }
    impl xray_transport::SocketProtector for DuringProtect {
        fn protect(&self, _: xray_transport::SocketHandle) -> std::io::Result<()> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let outbound = HysteriaOutbound {
                    inner: self.owner.upgrade().unwrap(),
                };
                assert!(!outbound.rebind());
            }
            Ok(())
        }
    }
    let server = rebind_reference::ReferenceServer::start().await;
    let mut config = configured();
    let OutboundSettings::Hysteria(settings) = &mut config.settings else {
        panic!()
    };
    settings.server = TargetAddr::Ip(server.address.ip());
    settings.port = server.address.port();
    let StreamSecurity::Tls(tls) = &mut config.stream.security else {
        panic!()
    };
    tls.server_name = Some("localhost".into());
    let StreamTransport::Hysteria(auth) = &mut config.stream.transport else {
        panic!()
    };
    auth.auth = zeroize::Zeroizing::new(rebind_reference::AUTH.into());
    let outbound = HysteriaOutbound::new(&config).unwrap();
    assert!(!outbound.rebind());
    assert!(outbound.inner.session.lock().unwrap().is_none());
    let protector = Arc::new(DuringProtect {
        owner: Arc::downgrade(&outbound.inner),
        calls: AtomicUsize::new(0),
    });
    let dialer = TransportDialer::with_tls_connector(server.connector.clone())
        .with_socket_protector(protector.clone());
    let dns = PendingDns::default();
    let _flow = outbound.open_udp(&dns, &dialer).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while protector.calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(protector.calls.load(Ordering::SeqCst), 2);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    outbound.close();
    assert!(!outbound.rebind());
}
