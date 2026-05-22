mod transport_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{
        BoxedTransportStream, ConnectorConfig, RealityClientConfig, RealityTlsEngine, TcpConnector,
        TlsClientConfig, TlsConnector, TransportConnector, TransportDialer, TransportError,
    };

    #[derive(Debug)]
    struct RecordingRealityEngine {
        stream: Mutex<Option<tokio::io::DuplexStream>>,
        seen: Mutex<Option<(RealityClientConfig, Target)>>,
    }

    impl RecordingRealityEngine {
        fn new(stream: tokio::io::DuplexStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
                seen: Mutex::new(None),
            }
        }

        fn seen(&self) -> Option<(RealityClientConfig, Target)> {
            self.seen.lock().expect("seen lock").clone()
        }
    }

    #[async_trait]
    impl RealityTlsEngine for RecordingRealityEngine {
        async fn connect(
            &self,
            config: &RealityClientConfig,
            target: &Target,
        ) -> Result<BoxedTransportStream, TransportError> {
            *self.seen.lock().expect("seen lock") = Some((config.clone(), target.clone()));
            let stream = self
                .stream
                .lock()
                .expect("stream lock")
                .take()
                .expect("fake reality stream should be used once");

            Ok(Box::new(stream))
        }
    }

    fn reality_test_config() -> RealityClientConfig {
        RealityClientConfig {
            server_name: "www.example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [1; 32],
            short_id: vec![2, 3, 4, 5],
            spider_x: "/".to_owned(),
        }
    }

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

    fn tls_test_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["server.test".to_owned()])
                .expect("generate self-signed certificate");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add test root");
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build TLS server config");

        (Arc::new(client_config), Arc::new(server_config))
    }

    async fn spawn_tls_echo_once(
        server_config: Arc<rustls::ServerConfig>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TLS echo listener");
        let addr = listener.local_addr().expect("read listener address");
        let acceptor = TlsAcceptor::from(server_config);

        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS echo client");
            let mut stream = acceptor.accept(stream).await.expect("accept TLS stream");
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.expect("read ping");
            stream.write_all(&buf).await.expect("write pong");
        });

        (addr, handle)
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
    async fn tls_connector_returns_boxed_transport_stream() {
        let (client_config, server_config) = tls_test_configs();
        let (addr, handle) = spawn_tls_echo_once(server_config).await;
        let connector = TlsConnector::with_client_config(client_config);
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
        };

        let stream = connector
            .connect(&target, &config)
            .await
            .expect("connect TLS target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("TLS echo task should complete");
    }

    #[tokio::test]
    async fn tls_connector_requires_dns_for_domain_targets() {
        let (client_config, _) = tls_test_configs();
        let connector = TlsConnector::with_client_config(client_config);
        let target = Target::new(
            TargetAddr::Domain("server.test".to_owned()),
            443,
            Network::Tcp,
        );
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
        };

        let result = connector.connect(&target, &config).await;

        assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "server.test"));
    }

    #[tokio::test]
    async fn tls_connector_rejects_invalid_server_name_before_network_io() {
        let (client_config, _) = tls_test_configs();
        let connector = TlsConnector::with_client_config(client_config);
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );
        let config = TlsClientConfig {
            server_name: "bad name".to_owned(),
            allow_insecure: false,
        };

        let result = connector.connect(&target, &config).await;

        assert!(matches!(
            result,
            Err(TransportError::InvalidTlsServerName(name)) if name == "bad name"
        ));
    }

    #[tokio::test]
    async fn transport_dialer_routes_tls_configs_to_tls_connector() {
        let (client_config, server_config) = tls_test_configs();
        let (addr, handle) = spawn_tls_echo_once(server_config).await;
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = ConnectorConfig::Tls(TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
        });

        let stream = dialer
            .connect(&config, &target)
            .await
            .expect("dial TLS target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("TLS echo task should complete");
    }

    #[tokio::test]
    async fn transport_dialer_routes_tcp_configs_to_tcp_connector() {
        let (client_config, _) = tls_test_configs();
        let (addr, handle) = spawn_echo_once().await;
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = ConnectorConfig::Tcp;

        let stream = dialer
            .connect(&config, &target)
            .await
            .expect("dial TCP target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("echo task should complete");
    }

    #[tokio::test]
    async fn transport_dialer_rejects_reality_configs_without_plaintext_downgrade() {
        let (client_config, _) = tls_test_configs();
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );
        let config = ConnectorConfig::Reality(reality_test_config());

        let result = dialer.connect(&config, &target).await;

        assert!(matches!(
            result,
            Err(TransportError::UnsupportedConnectorConfig("reality"))
        ));
    }

    #[tokio::test]
    async fn transport_dialer_routes_reality_configs_to_injected_engine() {
        let (client_config, _) = tls_test_configs();
        let (client, mut server) = tokio::io::duplex(1024);
        let engine = Arc::new(RecordingRealityEngine::new(client));
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
                .with_reality_engine(engine.clone());
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            443,
            Network::Tcp,
        );
        let reality_config = reality_test_config();
        let config = ConnectorConfig::Reality(reality_config.clone());

        let mut stream = dialer
            .connect(&config, &target)
            .await
            .expect("dial injected REALITY engine");
        stream.write_all(b"ping").await.expect("write ping");
        stream.flush().await.expect("flush ping");

        let mut received = [0u8; 4];
        server
            .read_exact(&mut received)
            .await
            .expect("read protected stream bytes");
        assert_eq!(&received, b"ping");

        let (seen_config, seen_target) = engine.seen().expect("engine saw config and target");
        assert_eq!(seen_config, reality_config);
        assert_eq!(seen_target.addr, target.addr);
        assert_eq!(seen_target.port, target.port);
        assert_eq!(seen_target.network, target.network);
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
            allow_insecure: false,
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
