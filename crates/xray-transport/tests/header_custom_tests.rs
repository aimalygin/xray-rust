//! The dialer runs the `header-custom` handshake on every TCP carrier as soon
//! as it connects: before the fragment mask, TLS and REALITY.
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    header_custom::{CustomArg, CustomExpr, CustomItem, HeaderCustomTcpConfig},
    ConnectorConfig, RealityClientConfig, TcpFragmentConfig, TlsClientConfig, TransportDialer,
};

fn packet(bytes: &[u8]) -> CustomItem {
    CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: bytes.to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    }
}

/// The client sends `HI` and its own port, the server answers `OK`.
fn config() -> Arc<HeaderCustomTcpConfig> {
    let port = CustomItem {
        transform: Some(CustomExpr {
            op: "be16".into(),
            args: vec![CustomArg::Metadata("local_port".into())],
        }),
        ..packet(b"")
    };
    Arc::new(HeaderCustomTcpConfig {
        clients: vec![vec![packet(b"HI"), port]],
        servers: vec![vec![packet(b"OK")]],
    })
}

/// Accepts one connection, checks the handshake and answers `reply`; returns
/// the next `count` bytes the client sends.
async fn serve(listener: TcpListener, reply: &'static [u8], count: usize) -> Vec<u8> {
    let (mut server, peer): (TcpStream, _) = listener.accept().await.unwrap();
    let mut handshake = [0; 4];
    server.read_exact(&mut handshake).await.unwrap();
    assert_eq!(&handshake[..2], b"HI");
    assert_eq!(
        u16::from_be_bytes([handshake[2], handshake[3]]),
        peer.port()
    );
    server.write_all(reply).await.unwrap();
    let mut rest = vec![0; count];
    let _ = tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut rest)).await;
    rest
}

fn target(listener: &TcpListener) -> (Target, std::net::SocketAddr) {
    let address = listener.local_addr().unwrap();
    (
        Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp),
        address,
    )
}

#[tokio::test]
async fn a_plain_carrier_carries_data_after_the_handshake() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (target, address) = target(&listener);
    let server = tokio::spawn(serve(listener, b"OK", 4));
    let dialer = TransportDialer::system()
        .unwrap()
        .with_tcp_header_custom(config());
    let mut client = dialer
        .connect_resolved(&ConnectorConfig::Tcp, &target, &[address], None)
        .await
        .unwrap();
    client.write_all(b"data").await.unwrap();
    assert_eq!(server.await.unwrap(), b"data");
}

#[tokio::test]
async fn other_bytes_from_the_server_fail_the_dial() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (target, address) = target(&listener);
    let server = tokio::spawn(serve(listener, b"NO", 0));
    let dialer = TransportDialer::system()
        .unwrap()
        .with_tcp_header_custom(config());
    let Err(error) = dialer
        .connect_resolved(&ConnectorConfig::Tcp, &target, &[address], None)
        .await
    else {
        panic!("the dial succeeded");
    };
    assert!(error.to_string().contains("header auth failed"), "{error}");
    server.await.unwrap();
}

#[tokio::test]
async fn tls_and_reality_start_after_the_handshake() {
    let connectors = [
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
    ];
    for connector in connectors {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (target, address) = target(&listener);
        let server = tokio::spawn(serve(listener, b"OK", 3));
        let dialer = TransportDialer::system()
            .unwrap()
            .with_tcp_header_custom(config());
        let client = tokio::spawn(async move {
            let _ = dialer
                .connect_resolved(&connector, &target, &[address], None)
                .await;
        });
        // A TLS record carrying the ClientHello comes after the handshake.
        assert_eq!(server.await.unwrap(), [22, 3, 1]);
        client.abort();
    }
}

#[tokio::test]
async fn the_fragment_mask_splits_the_tls_hello_after_the_handshake() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (target, address) = target(&listener);
    let server = tokio::spawn(serve(listener, b"OK", 14));
    let dialer = TransportDialer::system()
        .unwrap()
        .with_tcp_fragment(Arc::new(
            TcpFragmentConfig::new(vec![2..=2], vec![0..=0], 0..=0).unwrap(),
        ))
        .with_tcp_header_custom(config());
    let mut client = dialer
        .connect_resolved(&ConnectorConfig::Tcp, &target, &[address], None)
        .await
        .unwrap();
    client
        .write_all(&[22, 3, 1, 0, 4, 1, 2, 3, 4])
        .await
        .unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        server.await.unwrap(),
        [22, 3, 1, 0, 2, 1, 2, 22, 3, 1, 0, 2, 3, 4]
    );
}

/// A chained carrier, which another outbound opens: Xray's reads 0.0.0.0:0
/// for both of its ends.
struct Chained(std::net::SocketAddr);

#[async_trait::async_trait]
impl xray_transport::ResolvedTcpConnector for Chained {
    async fn connect_resolved(
        &self,
        _: &Target,
        _: &[std::net::SocketAddr],
        _: Option<&xray_transport::HappyEyeballsConfig>,
    ) -> Result<xray_transport::BoxedTransportStream, xray_transport::TransportError> {
        Ok(Box::new(TcpStream::connect(self.0).await.unwrap()))
    }
}

#[tokio::test]
async fn a_chained_carrier_runs_the_handshake_with_unspecified_addresses() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (target, address) = target(&listener);
    let server = tokio::spawn(async move {
        let (mut server, _) = listener.accept().await.unwrap();
        let mut handshake = [0; 4];
        server.read_exact(&mut handshake).await.unwrap();
        server.write_all(b"OK").await.unwrap();
        handshake
    });
    let dialer = TransportDialer::system()
        .unwrap()
        .with_resolved_tcp_connector(Arc::new(Chained(address)))
        .with_tcp_header_custom(config());
    let _client = dialer
        .connect_resolved(&ConnectorConfig::Tcp, &target, &[address], None)
        .await
        .unwrap();
    // The local port reads as zero.
    assert_eq!(server.await.unwrap(), [b'H', b'I', 0, 0]);
}
