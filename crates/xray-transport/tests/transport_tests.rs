mod transport_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{
        BoxedTransportStream, ConnectorConfig, RealityClientConfig, TcpConnector, TlsClientConfig,
        TransportConnector, TransportError,
    };

    async fn spawn_echo_once() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo listener");
        let addr = listener.local_addr().expect("read listener address");

        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept echo client");
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.expect("read ping");
            stream.write_all(&buf).await.expect("write pong");
        });

        (addr, handle)
    }

    async fn assert_boxed_transport_stream(mut stream: BoxedTransportStream) {
        stream.write_all(b"ping").await.expect("write ping");

        let mut echoed = [0u8; 4];
        stream
            .read_exact(&mut echoed)
            .await
            .expect("read echoed bytes");

        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn tcp_connector_reports_target_without_network_io_when_resolved() {
        let config = ConnectorConfig::Tcp;
        let connector = TcpConnector::new(config);
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );

        assert_eq!(connector.describe_target(&target), "127.0.0.1:9");
    }

    #[tokio::test]
    async fn tcp_connector_returns_boxed_transport_stream() {
        let (addr, handle) = spawn_echo_once().await;
        let connector = TcpConnector::new(ConnectorConfig::Tcp);
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);

        let stream = connector
            .connect(&target)
            .await
            .expect("connect TCP target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("echo task should complete");
    }

    #[tokio::test]
    async fn tcp_connector_requires_dns_for_domain_targets() {
        let config = ConnectorConfig::Tcp;
        let connector = TcpConnector::new(config);
        let target = Target::new(
            TargetAddr::Domain("example.com".to_string()),
            443,
            Network::Tcp,
        );

        let result = connector.connect(&target).await;

        assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "example.com"));
    }

    #[tokio::test]
    async fn tcp_connector_rejects_tls_config_without_plaintext_downgrade() {
        let connector = TcpConnector::new(ConnectorConfig::Tls(TlsClientConfig {
            server_name: "example.com".to_owned(),
        }));
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );

        let result = connector.connect(&target).await;

        assert!(matches!(
            result,
            Err(TransportError::UnsupportedConnectorConfig("tls"))
        ));
    }

    #[tokio::test]
    async fn tcp_connector_rejects_reality_config_without_plaintext_downgrade() {
        let connector = TcpConnector::new(ConnectorConfig::Reality(RealityClientConfig {
            server_name: "www.example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [1; 32],
            short_id: vec![2, 3, 4, 5],
            spider_x: "/".to_owned(),
        }));
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );

        let result = connector.connect(&target).await;

        assert!(matches!(
            result,
            Err(TransportError::UnsupportedConnectorConfig("reality"))
        ));
    }
}
