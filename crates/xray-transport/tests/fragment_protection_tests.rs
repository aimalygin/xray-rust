use std::{
    io,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    ConnectorConfig, RealityClientConfig, SocketHandle, SocketProtector, TcpFragmentConfig,
    TlsClientConfig, TransportDialer, TransportError,
};

struct Protector {
    calls: AtomicUsize,
    deny: bool,
}
impl SocketProtector for Protector {
    fn protect(&self, _: SocketHandle) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.deny {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic protect failure",
            ))
        } else {
            Ok(())
        }
    }
}
fn fragments() -> Arc<TcpFragmentConfig> {
    Arc::new(TcpFragmentConfig::new(vec![2..=2], vec![0..=0], 0..=0).unwrap())
}

#[tokio::test]
async fn fragmented_tcp_protects_before_first_connection_and_preserves_followup_bytes() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        deny: false,
    });
    let dialer = TransportDialer::system()
        .unwrap()
        .with_socket_protector(protector.clone())
        .with_tcp_fragment(fragments());
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
    let mut client = dialer
        .connect_resolved(&ConnectorConfig::Tcp, &target, &[addr], None)
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    assert_eq!(protector.calls.load(Ordering::SeqCst), 1);
    client
        .write_all(&[22, 3, 1, 0, 4, 1, 2, 3, 4])
        .await
        .unwrap();
    client.write_all(b"later").await.unwrap();
    client.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(
        bytes,
        [22, 3, 1, 0, 2, 1, 2, 22, 3, 1, 0, 2, 3, 4, b'l', b'a', b't', b'e', b'r']
    );
}

#[tokio::test]
async fn protect_rejection_sends_no_tcp_tls_or_reality_bytes() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        deny: true,
    });
    let dialer = TransportDialer::system()
        .unwrap()
        .with_socket_protector(protector.clone())
        .with_tcp_fragment(fragments());
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
    for connector in [
        ConnectorConfig::Tcp,
        ConnectorConfig::Tls(TlsClientConfig {
            server_name: "example.com".into(),
            allow_insecure: false,
            pinned_peer_cert_sha256: vec![],
            verify_peer_cert_by_name: vec![],
            alpn: vec![],
            fingerprint: None,
        }),
        ConnectorConfig::Reality(RealityClientConfig {
            server_name: "example.com".into(),
            fingerprint: "chrome".into(),
            public_key: [1; 32],
            short_id: vec![1, 2],
            spider_x: "/".into(),
            mldsa65_verify: None,
        }),
    ] {
        let result = dialer
            .connect_resolved(&connector, &target, &[addr], None)
            .await;
        assert!(matches!(result, Err(TransportError::SocketProtection(_))));
    }
    assert_eq!(protector.calls.load(Ordering::SeqCst), 3);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}
