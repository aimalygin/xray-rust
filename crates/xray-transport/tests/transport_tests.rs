mod transport_tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use rcgen::{
        date_time_ymd, generate_simple_self_signed, BasicConstraints, CertificateParams,
        CertifiedKey, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        PublicKeyData,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
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

    fn tls_pin_test_config(
        expired_leaf: bool,
    ) -> (Arc<rustls::ServerConfig>, [u8; 32], [u8; 32], [u8; 32]) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .expect("empty CA subject alt names are valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf_params = CertificateParams::new(vec![
            "server.test".to_owned(),
            Ipv4Addr::LOCALHOST.to_string(),
        ])
        .expect("valid leaf names");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired_leaf {
            leaf_params.not_before = date_time_ymd(2000, 1, 1);
            leaf_params.not_after = date_time_ymd(2001, 1, 1);
        }
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .expect("sign leaf with CA");

        let leaf_der = leaf_cert.der().clone();
        let ca_der = ca_cert.der().clone();
        let leaf_pin = Sha256::digest(leaf_der.as_ref()).into();
        let ca_pin = Sha256::digest(ca_der.as_ref()).into();
        let leaf_spki_pin = Sha256::digest(leaf_key.subject_public_key_info()).into();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![leaf_der, ca_der], key_der)
        .expect("build chained TLS server config");

        (Arc::new(server_config), leaf_pin, ca_pin, leaf_spki_pin)
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

    async fn spawn_tls_handshake_once(
        server_config: Arc<rustls::ServerConfig>,
    ) -> (SocketAddr, tokio::task::JoinHandle<bool>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TLS handshake listener");
        let addr = listener.local_addr().expect("read listener address");
        let acceptor = TlsAcceptor::from(server_config);

        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS client");
            acceptor.accept(stream).await.is_ok()
        });
        (addr, handle)
    }

    fn pinned_tls_config(server_name: &str, pin: [u8; 32]) -> TlsClientConfig {
        TlsClientConfig {
            server_name: server_name.to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: vec![pin],
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: None,
        }
    }

    fn pinned_tls_config_with_verification_names(
        server_name: &str,
        pin: [u8; 32],
        names: &[&str],
    ) -> TlsClientConfig {
        let mut config = pinned_tls_config(server_name, pin);
        config.verify_peer_cert_by_name = names.iter().map(|name| (*name).to_owned()).collect();
        config
    }

    #[tokio::test]
    async fn tls_leaf_der_pin_short_circuits_name_and_chain_verification() {
        let (server_config, leaf_pin, _, _) = tls_pin_test_config(true);
        let (addr, handle) = spawn_tls_handshake_once(server_config).await;
        let connector = TlsConnector::system().expect("system TLS connector");

        let config = pinned_tls_config_with_verification_names(
            "wrong-sni.test",
            leaf_pin,
            &["also-wrong.test"],
        );
        connector
            .connect_socket_addr(addr, &config)
            .await
            .expect("Xray accepts an exact leaf DER pin before checking names or validity");
        assert!(handle.await.expect("TLS server task"));
    }

    #[tokio::test]
    async fn tls_ca_pin_ors_verification_names_independently_from_sni_for_dns_and_ip_sans() {
        let (server_config, _, ca_pin, _) = tls_pin_test_config(false);
        let connector = TlsConnector::system().expect("system TLS connector");

        for names in [["bad name", "server.test"], ["wrong.test", "127.0.0.1"]] {
            let (addr, handle) = spawn_tls_handshake_once(Arc::clone(&server_config)).await;
            let config =
                pinned_tls_config_with_verification_names("wrong-sni.test", ca_pin, &names);
            connector
                .connect_socket_addr(addr, &config)
                .await
                .expect("one matching DNS/IP SAN must satisfy the OR list despite a different SNI");
            assert!(handle.await.expect("TLS server task"));
        }
    }

    #[tokio::test]
    async fn tls_ca_pin_rejects_when_every_verification_name_misses() {
        let (server_config, _, ca_pin, _) = tls_pin_test_config(false);
        let (addr, handle) = spawn_tls_handshake_once(server_config).await;
        let connector = TlsConnector::system().expect("system TLS connector");
        let config = pinned_tls_config_with_verification_names(
            "server.test",
            ca_pin,
            &["wrong-one.test", "wrong-two.test"],
        );

        assert!(connector.connect_socket_addr(addr, &config).await.is_err());
        assert!(!handle.await.expect("TLS server task"));
    }

    #[tokio::test]
    async fn tls_ca_der_pin_verifies_dns_name_and_ip_san() {
        let (server_config, _, ca_pin, _) = tls_pin_test_config(false);
        let connector = TlsConnector::system().expect("system TLS connector");

        for server_name in ["server.test", "127.0.0.1"] {
            let (addr, handle) = spawn_tls_handshake_once(Arc::clone(&server_config)).await;
            connector
                .connect_socket_addr(addr, &pinned_tls_config(server_name, ca_pin))
                .await
                .expect("a pinned presented CA still verifies the configured DNS/IP name");
            assert!(handle.await.expect("TLS server task"));
        }
    }

    #[tokio::test]
    async fn tls_ca_pin_wrong_name_and_unmatched_pin_fail_closed() {
        let (server_config, _, ca_pin, leaf_spki_pin) = tls_pin_test_config(false);
        let connector = TlsConnector::system().expect("system TLS connector");

        for config in [
            pinned_tls_config("wrong.test", ca_pin),
            pinned_tls_config("server.test", leaf_spki_pin),
        ] {
            let (addr, handle) = spawn_tls_handshake_once(Arc::clone(&server_config)).await;
            if connector.connect_socket_addr(addr, &config).await.is_ok() {
                panic!("a wrong CA name or unmatched certificate pin must reject TLS");
            }
            assert!(!handle.await.expect("TLS server task"));
        }
    }

    #[test]
    fn tls_pins_cannot_be_combined_with_allow_insecure_or_a_prebuilt_config() {
        let mut config = pinned_tls_config("server.test", [0x11; 32]);
        config.allow_insecure = true;
        let system = TlsConnector::system().expect("system TLS connector");
        assert!(matches!(
            system.client_config_for(&config),
            Err(TransportError::TlsConfig(_))
        ));

        config.allow_insecure = false;
        let (prebuilt, _) = tls_test_configs();
        let prebuilt = TlsConnector::with_pinned_client_config(prebuilt);
        assert!(matches!(
            prebuilt.client_config_for(&config),
            Err(TransportError::TlsConfig(_))
        ));

        let mut verification_names = pinned_tls_config("server.test", [0x11; 32]);
        verification_names.pinned_peer_cert_sha256.clear();
        verification_names.verify_peer_cert_by_name = vec!["server.test".to_owned()];
        assert!(matches!(
            prebuilt.client_config_for(&verification_names),
            Err(TransportError::TlsConfig(_))
        ));
        verification_names.allow_insecure = true;
        assert!(matches!(
            system.client_config_for(&verification_names),
            Err(TransportError::TlsConfig(_))
        ));
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
        let connector = TlsConnector::with_pinned_client_config(client_config);
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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

        let connector = TlsConnector::with_pinned_client_config(client_config);
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
        let connector = TlsConnector::with_pinned_client_config(client_config)
            .with_socket_protector(protector.clone());
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
        let connector = TlsConnector::with_pinned_client_config(client_config);
        let target = Target::new(
            TargetAddr::Domain("server.test".to_owned()),
            443,
            Network::Tcp,
        );
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: None,
        };

        let result = connector.connect(&target, &config).await;

        assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "server.test"));
    }

    #[tokio::test]
    async fn tls_connector_rejects_invalid_server_name_before_network_io() {
        let (client_config, _) = tls_test_configs();
        let connector = TlsConnector::with_pinned_client_config(client_config);
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );
        let config = TlsClientConfig {
            server_name: "bad name".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ));
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let config = ConnectorConfig::Tls(TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ));
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ));
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ));
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ));
        let original_target = Target::new(
            TargetAddr::Domain("origin.test".to_owned()),
            443,
            Network::Tcp,
        );
        let config = ConnectorConfig::Tls(TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
        let connector = TlsConnector::with_pinned_client_config(client_config)
            .with_socket_protector(protector.clone());
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
        let connector = TlsConnector::with_pinned_client_config(client_config)
            .with_socket_protector(protector.clone());
        let config = TlsClientConfig {
            server_name: "bad name".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ))
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ));
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ))
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ))
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
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ))
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
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
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

    /// The cache sits behind the connector's own `Arc`, so cloning shares it.
    /// Nothing else here pins that: a clone that built its own map would pass
    /// every other test in this file while rebuilding each shape once per
    /// clone -- and handing the two clones separate resumption session stores,
    /// which is the split `ClientConfigKey` exists to avoid.
    #[test]
    fn tls_connector_clones_share_one_config_cache() {
        let connector = TlsConnector::system().expect("system roots must load");
        let clone = connector.clone();

        let chrome = TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        };

        let original = connector.client_config_for(&chrome).expect("chrome config");
        let cloned = clone.client_config_for(&chrome).expect("chrome config");

        assert!(
            Arc::ptr_eq(&original, &cloned),
            "clones of one connector must share the config cache"
        );
    }

    /// `alpn` earns its place in the key only because it now reaches the
    /// unshaped config too. Were it still ignored there, two outbounds to one
    /// server differing only in ALPN would get byte-identical configs on
    /// separate resumption session stores -- a split with no upside. So assert
    /// the key both ways *and* that the distinction it draws is real.
    #[test]
    fn tls_connector_keys_unshaped_configs_on_alpn() {
        let connector = TlsConnector::system().expect("system roots must load");

        let h2 = TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: vec!["h2".to_owned()],
            fingerprint: Some("unsafe".to_owned()),
        };
        let http11 = TlsClientConfig {
            alpn: vec!["http/1.1".to_owned()],
            ..h2.clone()
        };

        let first = connector.client_config_for(&h2).expect("h2 config");
        let again = connector.client_config_for(&h2).expect("h2 config");
        let other = connector.client_config_for(&http11).expect("http/1.1");

        assert!(
            Arc::ptr_eq(&first, &again),
            "one ALPN list must reuse one config"
        );
        assert!(
            !Arc::ptr_eq(&first, &other),
            "different ALPN lists must not share a config"
        );
        assert_eq!(
            first.alpn_protocols,
            vec![b"h2".to_vec()],
            "the split must reflect a real difference in the config"
        );
        assert_eq!(other.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// `allow_insecure` picks between two different certificate verifiers, so
    /// sharing a config across it would hand a verifying connection the one
    /// that accepts every certificate.
    #[test]
    fn tls_connector_does_not_share_configs_across_allow_insecure() {
        let connector = TlsConnector::system().expect("system roots must load");

        let verifying = TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        };
        let insecure = TlsClientConfig {
            allow_insecure: true,
            ..verifying.clone()
        };

        let verifying_config = connector
            .client_config_for(&verifying)
            .expect("verifying config");
        let insecure_config = connector
            .client_config_for(&insecure)
            .expect("insecure config");

        assert!(
            !Arc::ptr_eq(&verifying_config, &insecure_config),
            "a verifying connection must not receive the insecure config"
        );
    }

    #[test]
    fn tls_connector_keys_configs_on_certificate_pins() {
        let connector = TlsConnector::system().expect("system roots must load");
        let first = pinned_tls_config("example.com", [0x11; 32]);
        let second = pinned_tls_config("example.com", [0x22; 32]);

        let first_config = connector
            .client_config_for(&first)
            .expect("first pin config");
        let first_again = connector
            .client_config_for(&first)
            .expect("cached first pin config");
        let second_config = connector
            .client_config_for(&second)
            .expect("second pin config");

        assert!(Arc::ptr_eq(&first_config, &first_again));
        assert!(
            !Arc::ptr_eq(&first_config, &second_config),
            "different trust pins must never share a verifier or session cache"
        );
    }

    #[test]
    fn tls_connector_keys_configs_on_verification_name_lists() {
        let connector = TlsConnector::system().expect("system roots must load");
        let mut first = pinned_tls_config("example.com", [0x11; 32]);
        first.verify_peer_cert_by_name = vec!["first.example".to_owned()];
        let mut second = first.clone();
        second.verify_peer_cert_by_name = vec!["second.example".to_owned()];

        let first_config = connector
            .client_config_for(&first)
            .expect("first verification-name config");
        let first_again = connector
            .client_config_for(&first)
            .expect("cached first verification-name config");
        let second_config = connector
            .client_config_for(&second)
            .expect("second verification-name config");

        assert!(Arc::ptr_eq(&first_config, &first_again));
        assert!(
            !Arc::ptr_eq(&first_config, &second_config),
            "different verification-name lists must never share a verifier or session cache"
        );
    }

    /// The pinned config wins over every shape, including one that
    /// `system()` would reject outright.
    #[test]
    fn pinned_connector_ignores_shape_and_fingerprint_validation() {
        let (client_config, _server_config) = tls_test_configs();
        let connector = TlsConnector::with_pinned_client_config(Arc::clone(&client_config));

        let chrome = TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        };
        let unknown = TlsClientConfig {
            fingerprint: Some("nosuchbrowser".to_owned()),
            ..chrome.clone()
        };

        for config in [&chrome, &unknown] {
            let pinned = connector
                .client_config_for(config)
                .expect("a pinned connector validates nothing");
            assert!(
                Arc::ptr_eq(&pinned, &client_config),
                "the pinned config must win over every shape"
            );
        }
    }

    #[test]
    fn tls_connector_rejects_unknown_fingerprints() {
        let connector = TlsConnector::system().expect("system roots must load");

        let error = connector
            .client_config_for(&TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
                fingerprint: Some("nosuchbrowser".to_owned()),
            })
            .expect_err("an unknown fingerprint must fail");

        assert!(error.to_string().contains("nosuchbrowser"));
    }
}
