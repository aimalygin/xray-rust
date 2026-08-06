mod transport_tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{
        BoxedTransportStream, ConnectorConfig, HappyEyeballsConfig, RealityClientConfig,
        RealityTlsEngine, SocketHandle, SocketProtector, TcpConnector, TlsClientConfig,
        TlsConnector, TransportConnector, TransportDialer, TransportError,
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

    #[derive(Debug)]
    struct RecordingSocketAddrRealityEngine {
        stream: Mutex<Option<tokio::io::DuplexStream>>,
        seen: Mutex<Option<(Target, SocketAddr)>>,
    }

    impl RecordingSocketAddrRealityEngine {
        fn new(stream: tokio::io::DuplexStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
                seen: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl RealityTlsEngine for RecordingSocketAddrRealityEngine {
        async fn connect(
            &self,
            _config: &RealityClientConfig,
            _target: &Target,
        ) -> Result<BoxedTransportStream, TransportError> {
            panic!("resolved dialing should use connect_socket_addr")
        }

        async fn connect_socket_addr(
            &self,
            _config: &RealityClientConfig,
            original_target: &Target,
            candidate: SocketAddr,
        ) -> Result<BoxedTransportStream, TransportError> {
            *self.seen.lock().expect("resolved candidate lock") =
                Some((original_target.clone(), candidate));
            let stream = self
                .stream
                .lock()
                .expect("resolved stream lock")
                .take()
                .expect("resolved fake stream should be used once");
            Ok(Box::new(stream))
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSocketProtector {
        seen: Mutex<Vec<i64>>,
    }

    impl RecordingSocketProtector {
        fn seen(&self) -> Vec<i64> {
            self.seen.lock().expect("seen socket lock").clone()
        }
    }

    impl SocketProtector for RecordingSocketProtector {
        fn protect(&self, socket: SocketHandle) -> std::io::Result<()> {
            self.seen
                .lock()
                .expect("seen socket lock")
                .push(socket.raw());
            Ok(())
        }
    }

    fn reality_test_config() -> RealityClientConfig {
        RealityClientConfig {
            server_name: "www.example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [1; 32],
            short_id: vec![2, 3, 4, 5],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        }
    }

    fn happy_eyeballs_config(try_delay: Duration) -> HappyEyeballsConfig {
        HappyEyeballsConfig {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay,
            max_concurrent: NonZeroUsize::new(2).expect("non-zero concurrency"),
        }
    }

    async fn refused_loopback_addr() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("reserve refused candidate");
        let addr = listener.local_addr().expect("read refused candidate");
        drop(listener);
        addr
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
    async fn tcp_connector_invokes_socket_protector_before_connect() {
        let (addr, handle) = spawn_echo_once().await;
        let protector = Arc::new(RecordingSocketProtector::default());
        let connector =
            TcpConnector::new(ConnectorConfig::Tcp).with_socket_protector(protector.clone());
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);

        let stream = connector
            .connect(&target)
            .await
            .expect("connect protected TCP target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("echo task should complete");
        assert_eq!(protector.seen().len(), 1);
        assert!(protector.seen()[0] >= 0);
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
            alpn: Vec::new(),
            fingerprint: None,
        };

        let stream = connector
            .connect(&target, &config)
            .await
            .expect("connect TLS target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("TLS echo task should complete");
    }

    #[tokio::test]
    async fn tls_connector_wraps_existing_transport_stream() {
        let (client_config, server_config) = tls_test_configs();
        let (client_raw, server_raw) = tokio::io::duplex(4096);
        let acceptor = TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let mut stream = acceptor
                .accept(server_raw)
                .await
                .expect("accept TLS stream");
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.expect("read ping");
            stream.write_all(&buf).await.expect("write pong");
        });

        let connector = TlsConnector::with_client_config(client_config);
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: None,
        };

        let stream = connector
            .connect_stream(Box::new(client_raw), &config)
            .await
            .expect("wrap existing stream with TLS");

        assert_boxed_transport_stream(stream).await;
        server.await.expect("TLS server task should complete");
    }

    #[tokio::test]
    async fn tls_connector_invokes_socket_protector_before_connect() {
        let (client_config, server_config) = tls_test_configs();
        let (addr, handle) = spawn_tls_echo_once(server_config).await;
        let protector = Arc::new(RecordingSocketProtector::default());
        let connector = TlsConnector::with_client_config(client_config)
            .with_socket_protector(protector.clone());
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: None,
        };

        let stream = connector
            .connect(&target, &config)
            .await
            .expect("connect protected TLS target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("TLS echo task should complete");
        assert_eq!(protector.seen().len(), 1);
        assert!(protector.seen()[0] >= 0);
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
            alpn: Vec::new(),
            fingerprint: None,
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
            alpn: Vec::new(),
            fingerprint: None,
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
            alpn: Vec::new(),
            fingerprint: None,
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
    async fn transport_dialer_resolved_tcp_falls_back_after_fast_failure() {
        let (client_config, _) = tls_test_configs();
        let (success, handle) = spawn_echo_once().await;
        let refused = refused_loopback_addr().await;
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
        let original_target = Target::new(
            TargetAddr::Domain("origin.test".to_owned()),
            443,
            Network::Tcp,
        );
        let config = ConnectorConfig::Tcp;
        let race_config = happy_eyeballs_config(Duration::from_secs(60));

        let stream = dialer
            .connect_resolved(
                &config,
                &original_target,
                &[refused, success],
                Some(&race_config),
            )
            .await
            .expect("second TCP candidate should connect");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("echo task should complete");
    }

    #[tokio::test]
    async fn transport_dialer_zero_delay_preserves_first_candidate_behavior() {
        let (client_config, _) = tls_test_configs();
        let refused = refused_loopback_addr().await;
        let success_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind unused fallback candidate");
        let success = success_listener
            .local_addr()
            .expect("read fallback candidate");
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
        let target = Target::new(
            TargetAddr::Domain("origin.test".to_owned()),
            443,
            Network::Tcp,
        );
        let race_config = happy_eyeballs_config(Duration::ZERO);

        let result = dialer
            .connect_resolved(
                &ConnectorConfig::Tcp,
                &target,
                &[refused, success],
                Some(&race_config),
            )
            .await;

        assert!(matches!(result, Err(TransportError::Tcp(_))));
    }

    #[tokio::test]
    async fn transport_dialer_resolved_tls_handshakes_after_tcp_fallback() {
        let (client_config, server_config) = tls_test_configs();
        let (success, handle) = spawn_tls_echo_once(server_config).await;
        let refused = refused_loopback_addr().await;
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
        let original_target = Target::new(
            TargetAddr::Domain("origin.test".to_owned()),
            443,
            Network::Tcp,
        );
        let config = ConnectorConfig::Tls(TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: None,
        });
        let race_config = happy_eyeballs_config(Duration::from_secs(60));

        let stream = dialer
            .connect_resolved(
                &config,
                &original_target,
                &[refused, success],
                Some(&race_config),
            )
            .await
            .expect("TLS should use the winning TCP candidate");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("TLS echo task should complete");
    }

    #[tokio::test]
    async fn tls_handshake_failure_does_not_race_another_tcp_candidate() {
        let (client_config, _) = tls_test_configs();
        let plaintext_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind plaintext candidate");
        let plaintext = plaintext_listener
            .local_addr()
            .expect("read plaintext candidate");
        let fallback_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fallback candidate");
        let fallback = fallback_listener
            .local_addr()
            .expect("read fallback candidate");
        let first_server = tokio::spawn(async move {
            let (stream, _) = plaintext_listener
                .accept()
                .await
                .expect("accept first raw TCP winner");
            drop(stream);
        });
        let protector = Arc::new(RecordingSocketProtector::default());
        let connector = TlsConnector::with_client_config(client_config)
            .with_socket_protector(protector.clone());
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: None,
        };
        let race_config = happy_eyeballs_config(Duration::from_secs(60));

        let result = connector
            .connect_candidates(&[plaintext, fallback], &config, &race_config)
            .await;

        assert!(matches!(result, Err(TransportError::Tls(_))));
        first_server
            .await
            .expect("plaintext server should complete");
        assert_eq!(protector.seen().len(), 1);
    }

    #[tokio::test]
    async fn tls_candidate_connect_rejects_invalid_sni_before_sockets() {
        let (client_config, _) = tls_test_configs();
        let protector = Arc::new(RecordingSocketProtector::default());
        let connector = TlsConnector::with_client_config(client_config)
            .with_socket_protector(protector.clone());
        let config = TlsClientConfig {
            server_name: "bad name".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: None,
        };
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9, 17, 42));
        let result = connector.connect_socket_addr(scoped, &config).await;

        assert!(matches!(
            result,
            Err(TransportError::InvalidTlsServerName(name)) if name == "bad name"
        ));
        assert!(protector.seen().is_empty());
    }

    #[tokio::test]
    async fn transport_dialer_carries_socket_protector_to_tcp_connects() {
        let (client_config, _) = tls_test_configs();
        let (addr, handle) = spawn_echo_once().await;
        let protector = Arc::new(RecordingSocketProtector::default());
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
                .with_socket_protector(protector.clone());
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = ConnectorConfig::Tcp;

        let stream = dialer
            .connect(&config, &target)
            .await
            .expect("dial protected TCP target");

        assert_boxed_transport_stream(stream).await;
        handle.await.expect("echo task should complete");
        assert_eq!(protector.seen().len(), 1);
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
    async fn resolved_legacy_reality_engine_receives_first_candidate_once() {
        let (client_config, _) = tls_test_configs();
        let (client, _server) = tokio::io::duplex(1024);
        let engine = Arc::new(RecordingRealityEngine::new(client));
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
                .with_reality_engine(engine.clone());
        let original_target = Target::new(
            TargetAddr::Domain("origin.test".to_owned()),
            443,
            Network::Tcp,
        );
        let first = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8443));
        let second = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 9443));
        let race_config = happy_eyeballs_config(Duration::from_millis(250));

        let stream = dialer
            .connect_resolved(
                &ConnectorConfig::Reality(reality_test_config()),
                &original_target,
                &[first, second],
                Some(&race_config),
            )
            .await
            .expect("legacy REALITY engine should remain usable");
        drop(stream);

        let (_, seen_target) = engine.seen().expect("legacy engine should be called once");
        assert_eq!(seen_target.addr, TargetAddr::Ip(first.ip()));
        assert_eq!(seen_target.port, first.port());
        assert_eq!(seen_target.network, Network::Tcp);
    }

    #[tokio::test]
    async fn resolved_reality_engine_receives_full_scoped_ipv6_candidate() {
        let (client_config, _) = tls_test_configs();
        let (client, _server) = tokio::io::duplex(1024);
        let engine = Arc::new(RecordingSocketAddrRealityEngine::new(client));
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
                .with_reality_engine(engine.clone());
        let original_target = Target::new(
            TargetAddr::Domain("origin.test".to_owned()),
            443,
            Network::Tcp,
        );
        let candidate = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1234".parse().expect("link-local IPv6"),
            8443,
            17,
            42,
        ));

        let stream = dialer
            .connect_resolved(
                &ConnectorConfig::Reality(reality_test_config()),
                &original_target,
                &[candidate],
                None,
            )
            .await
            .expect("custom REALITY engine should receive resolved candidate");
        drop(stream);

        let seen = engine
            .seen
            .lock()
            .expect("resolved candidate lock")
            .clone()
            .expect("resolved candidate should be recorded");
        assert_eq!(seen.0, original_target);
        assert_eq!(seen.1, candidate);
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
            alpn: Vec::new(),
            fingerprint: None,
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
    async fn connect_tcp_stream_enables_nodelay() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let stream = xray_transport::connect_tcp_stream(addr, None)
            .await
            .expect("connect");

        assert!(stream.nodelay().expect("query nodelay"));
    }

    #[tokio::test]
    async fn connect_tcp_stream_dials_ipv4_mapped_ipv6_as_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind IPv4 listener");
        let ipv4_addr = listener.local_addr().expect("listener addr");
        let mapped_addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            ipv4_addr.port(),
            17,
            42,
        ));

        let stream = xray_transport::connect_tcp_stream(mapped_addr, None)
            .await
            .expect("connect through mapped IPv6 address");

        assert_eq!(stream.peer_addr().expect("peer addr"), ipv4_addr);
    }

    #[tokio::test]
    async fn tcp_connector_rejects_reality_config_without_plaintext_downgrade() {
        let connector = TcpConnector::new(ConnectorConfig::Reality(RealityClientConfig {
            server_name: "www.example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [1; 32],
            short_id: vec![2, 3, 4, 5],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
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

    #[test]
    fn tls_connector_memoizes_configs_per_shape() {
        let connector = TlsConnector::system().expect("system roots must load");

        let chrome = TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        };
        let firefox = TlsClientConfig {
            fingerprint: Some("firefox".to_owned()),
            ..chrome.clone()
        };

        let first = connector.client_config_for(&chrome).expect("chrome config");
        let again = connector.client_config_for(&chrome).expect("chrome config");
        let other = connector
            .client_config_for(&firefox)
            .expect("firefox config");

        assert!(
            Arc::ptr_eq(&first, &again),
            "the same shape must reuse one config"
        );
        assert!(
            !Arc::ptr_eq(&first, &other),
            "different fingerprints must not share a config"
        );
    }

    #[test]
    fn tls_connector_rejects_unknown_fingerprints() {
        let connector = TlsConnector::system().expect("system roots must load");

        let error = connector
            .client_config_for(&TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                alpn: Vec::new(),
                fingerprint: Some("nosuchbrowser".to_owned()),
            })
            .expect_err("an unknown fingerprint must fail");

        assert!(error.to_string().contains("nosuchbrowser"));
    }
}
