mod utls_tls_shaping_tests {
    use std::net::Ipv4Addr;

    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{plain_tls_client_hello_bytes, TlsClientConfig, TlsConnector};

    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_ALPN: u16 = 0x0010;
    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    const CHROME_GREASE_CIPHER: u16 = 0x0a0a;

    /// uTLS ClientHello shapes emitted by the pinned Go oracle
    /// (`tools/reality-oracle/clienthello_shape.go`) and checked in so this
    /// coverage runs under a plain `cargo test`. Regenerate with:
    ///
    /// ```text
    /// go run -tags reality_oracle_clienthello_shape \
    ///   ./tools/reality-oracle/clienthello_shape.go -fingerprint android \
    ///   > tests/fixtures/reality/clienthello_shape_android.json
    /// ```
    const CLIENTHELLO_SHAPE_ANDROID_JSON: &str =
        include_str!("../../../tests/fixtures/reality/clienthello_shape_android.json");
    const CLIENTHELLO_SHAPE_HELLOCHROME_58_JSON: &str =
        include_str!("../../../tests/fixtures/reality/clienthello_shape_hellochrome_58.json");

    /// The same oracle run with `-websocket-alpn`, which applies Xray's
    /// `WebsocketHandshakeContext` ALPN rebuild before emitting the shape.
    /// Regenerate with:
    ///
    /// ```text
    /// go run -tags reality_oracle_clienthello_shape \
    ///   ./tools/reality-oracle/clienthello_shape.go -fingerprint android \
    ///   -websocket-alpn \
    ///   > tests/fixtures/reality/clienthello_shape_android_websocket_alpn.json
    /// ```
    const CLIENTHELLO_SHAPE_CHROME_WEBSOCKET_ALPN_JSON: &str = include_str!(
        "../../../tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn.json"
    );
    const CLIENTHELLO_SHAPE_ANDROID_WEBSOCKET_ALPN_JSON: &str = include_str!(
        "../../../tests/fixtures/reality/clienthello_shape_android_websocket_alpn.json"
    );

    fn config(fingerprint: &str, alpn: &[&str]) -> TlsClientConfig {
        TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            alpn: alpn.iter().map(|value| (*value).to_owned()).collect(),
            fingerprint: Some(fingerprint.to_owned()),
        }
    }

    /// Walks the ClientHello extension list and returns the ALPN protocol
    /// names, in order, or `None` when the hello carries no ALPN extension at
    /// all -- a distinction an empty list would hide. Layout: record header
    /// (5) + handshake header (4) + version (2) + random (32) + session id +
    /// cipher suites + compression methods + extensions.
    fn alpn_protocols(hello: &[u8]) -> Option<Vec<String>> {
        let mut cursor = 5 + 4 + 2 + 32;
        let session_id_len = usize::from(hello[cursor]);
        cursor += 1 + session_id_len;
        let cipher_suites_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2 + cipher_suites_len;
        let compression_len = usize::from(hello[cursor]);
        cursor += 1 + compression_len;
        let extensions_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        let end = cursor + extensions_len;

        while cursor + 4 <= end {
            let extension_type = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
            let payload_len =
                usize::from(u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]));
            let payload = &hello[cursor + 4..cursor + 4 + payload_len];
            cursor += 4 + payload_len;

            if extension_type != EXT_ALPN {
                continue;
            }

            let mut protocols = Vec::new();
            let mut offset = 2;
            while offset < payload.len() {
                let len = usize::from(payload[offset]);
                offset += 1;
                protocols
                    .push(String::from_utf8_lossy(&payload[offset..offset + len]).into_owned());
                offset += len;
            }
            return Some(protocols);
        }

        None
    }

    fn alpn(protocols: &[&str]) -> Option<Vec<String>> {
        Some(
            protocols
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect(),
        )
    }

    fn cipher_suites(hello: &[u8]) -> Vec<u16> {
        let mut cursor = 5 + 4 + 2 + 32;
        cursor += 1 + usize::from(hello[cursor]);
        let len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        hello[cursor..cursor + len]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect()
    }

    #[test]
    fn chrome_fingerprint_shapes_the_client_hello() {
        let hello = plain_tls_client_hello_bytes(&config("chrome", &[]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(
            cipher_suites(&hello).first().copied(),
            Some(CHROME_GREASE_CIPHER),
            "a shaped Chrome hello leads with a GREASE cipher suite"
        );
    }

    #[test]
    fn alpn_defaults_to_the_profile_list() {
        let hello = plain_tls_client_hello_bytes(&config("chrome", &[]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), alpn(&["h2", "http/1.1"]));
    }

    #[test]
    fn http11_alpn_overrides_the_profile_list() {
        let hello = plain_tls_client_hello_bytes(&config("chrome", &["http/1.1"]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), alpn(&["http/1.1"]));
    }

    #[test]
    fn other_alpn_lists_do_not_override_the_profile() {
        // The RAW transport reaches the ALPN-forcing handshake only when the
        // configured list is exactly ["http/1.1"] (tcp/dialer.go); any other
        // list takes the plain handshake and keeps the profile's own ALPN.
        // ws and httpupgrade invert this -- they force http/1.1 for every list
        // except exactly ["h2", "http/1.1"] -- but they call a different
        // handshake, and they land in a later plan with their own gate.
        let hello = plain_tls_client_hello_bytes(&config("chrome", &["h2"]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), alpn(&["h2", "http/1.1"]));
    }

    #[test]
    fn profiles_without_an_alpn_extension_stay_without_one() {
        let hello = plain_tls_client_hello_bytes(&config("android", &[]))
            .expect("android ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), None);
    }

    #[test]
    fn the_override_appends_alpn_to_a_profile_that_carries_none() {
        // Xray appends an ALPNExtension when the fingerprint has none, so the
        // override must reach the wire even here -- otherwise the connection
        // offers no ALPN at all where Xray offers http/1.1.
        let hello = plain_tls_client_hello_bytes(&config("android", &["http/1.1"]))
            .expect("android ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), alpn(&["http/1.1"]));
    }

    /// The two assertions above state what the override *should* do; this one
    /// checks it against what uTLS actually does when Xray drives it, so the
    /// expectation cannot drift on a guess.
    ///
    /// Every other shape in this repo is oracle-checked per fingerprint, but
    /// that comparison only ever sees the profile's own ALPN -- the override is
    /// applied after `BuildHandshakeState`, so no per-fingerprint fixture
    /// covers it.
    ///
    /// `chrome` alone would prove close to nothing: its profile already
    /// declares `["h2", "http/1.1"]`, so the override just narrows a list that
    /// was already there, in a slot that was already there. `android` declares
    /// no ALPN extension at all, so the override has to insert one -- Xray's
    /// `if !hasALPNExtension` append -- and *where* it lands is precisely what
    /// a hand-written expectation gets wrong. Hence both.
    #[test]
    fn the_http11_override_matches_the_utls_oracle() {
        #[derive(serde::Deserialize)]
        struct WebsocketAlpnShape {
            fingerprint: String,
            #[serde(default)]
            websocket_alpn: bool,
            alpn_protocols: Vec<String>,
            extension_order: Vec<String>,
        }

        for shape_json in [
            CLIENTHELLO_SHAPE_CHROME_WEBSOCKET_ALPN_JSON,
            CLIENTHELLO_SHAPE_ANDROID_WEBSOCKET_ALPN_JSON,
        ] {
            let shape: WebsocketAlpnShape = serde_json::from_str(shape_json)
                .expect("the websocket-ALPN shape fixture should decode");
            let fingerprint = shape.fingerprint.as_str();
            assert!(
                shape.websocket_alpn,
                "{fingerprint}: the fixture must come from the oracle's -websocket-alpn mode, \
                 or it is just the plain profile shape and asserts nothing"
            );

            let hello = plain_tls_client_hello_bytes(&config(fingerprint, &["http/1.1"]))
                .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}"));

            assert_eq!(
                alpn_protocols(&hello),
                Some(shape.alpn_protocols),
                "{fingerprint}: the override must offer the ALPN uTLS offers"
            );

            // Same single divergence Task 5A pinned: rustls emits
            // `supported_versions` on every hello it builds and cannot be made
            // to leave it out, so a TLS-1.2-era shape carries it at the tail
            // and uTLS' own order stays an exact prefix.
            let mut expected = shape.extension_order;
            let supported_versions = format!("0x{EXT_SUPPORTED_VERSIONS:04x}");
            if !expected.contains(&supported_versions) {
                expected.push(supported_versions);
            }

            assert_eq!(
                extension_order(&hello),
                expected,
                "{fingerprint}: the override must leave the extension order where uTLS puts it, \
                 an appended ALPN included"
            );
        }
    }

    #[test]
    fn unsafe_fingerprint_leaves_the_hello_unshaped() {
        let hello = plain_tls_client_hello_bytes(&TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("unsafe".to_owned()),
        })
        .expect("unshaped ClientHello must be produced");

        assert_ne!(
            cipher_suites(&hello).first().copied(),
            Some(CHROME_GREASE_CIPHER),
            "the unsafe sentinel must leave rustls' own hello alone"
        );
    }

    /// Xray's `unsafe` sentinel falls through to stock `tls.Client`, and stock
    /// Go TLS sends `tlsConfig.NextProtos` -- so an unshaped hello still has to
    /// carry the configured ALPN. The list reaches the wire verbatim here:
    /// the `["http/1.1"]` override rule belongs to the shaped path.
    #[test]
    fn an_unshaped_hello_advertises_the_configured_alpn() {
        for fingerprint in [Some("unsafe".to_owned()), None] {
            let hello = plain_tls_client_hello_bytes(&TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
                fingerprint: fingerprint.clone(),
            })
            .expect("unshaped ClientHello must be produced");

            assert_eq!(
                alpn_protocols(&hello),
                alpn(&["h2", "http/1.1"]),
                "{fingerprint:?}: an unshaped hello must advertise the configured ALPN"
            );
        }
    }

    /// The other side of that boundary: the ALPN carry-through is gated on the
    /// configured list being non-empty, never on the fingerprint value, so the
    /// `fingerprint: None` + empty-list shape every legacy call site passes
    /// keeps emitting the hello it always did -- one with no ALPN extension at
    /// all, which is distinct from an empty one.
    #[test]
    fn an_empty_alpn_list_leaves_the_unshaped_hello_without_the_extension() {
        for fingerprint in [Some("unsafe".to_owned()), None] {
            let hello = plain_tls_client_hello_bytes(&TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                alpn: Vec::new(),
                fingerprint: fingerprint.clone(),
            })
            .expect("unshaped ClientHello must be produced");

            assert_eq!(
                alpn_protocols(&hello),
                None,
                "{fingerprint:?}: an empty list must not add an ALPN extension"
            );
        }
    }

    /// Pins the layout contract the helpers above walk on: exactly one
    /// handshake record, header included, with lengths covering the whole
    /// flight. A shaped hello that ever spanned two records -- or a change
    /// that returned the bare handshake message -- would silently shift every
    /// offset in this file.
    #[test]
    fn both_paths_return_one_well_formed_handshake_record() {
        for fingerprint in ["chrome", "unsafe"] {
            let hello = plain_tls_client_hello_bytes(&config(fingerprint, &[]))
                .expect("ClientHello must be produced");

            assert_eq!(hello[0], 0x16, "{fingerprint}: handshake record type");
            assert_eq!(
                &hello[1..3],
                &[0x03, 0x01],
                "{fingerprint}: legacy record version"
            );
            assert_eq!(
                usize::from(u16::from_be_bytes([hello[3], hello[4]])),
                hello.len() - 5,
                "{fingerprint}: record length covers the whole flight"
            );
            assert_eq!(hello[5], 0x01, "{fingerprint}: ClientHello handshake type");
            let handshake_len = (usize::from(hello[6]) << 16)
                | (usize::from(hello[7]) << 8)
                | usize::from(hello[8]);
            assert_eq!(
                handshake_len,
                hello.len() - 9,
                "{fingerprint}: handshake length covers the whole message"
            );
        }
    }

    #[test]
    fn reality_incapable_fingerprints_are_usable_on_plain_tls() {
        let hello = plain_tls_client_hello_bytes(&config("hellochrome_58", &[]))
            .expect("a REALITY-incapable fingerprint must still shape plain TLS");

        assert!(!hello.is_empty());
    }

    /// Walks the extension list and renders it the way the Go oracle's
    /// `extension_order` field does: `GREASE` for any GREASE value, a
    /// `0x`-prefixed hex type otherwise.
    fn extension_order(hello: &[u8]) -> Vec<String> {
        let mut cursor = 5 + 4 + 2 + 32;
        cursor += 1 + usize::from(hello[cursor]);
        let cipher_suites_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2 + cipher_suites_len;
        cursor += 1 + usize::from(hello[cursor]);
        let extensions_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        let end = cursor + extensions_len;

        let mut order = Vec::new();
        while cursor + 4 <= end {
            let extension_type = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
            let payload_len =
                usize::from(u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]));
            cursor += 4 + payload_len;
            order.push(if is_grease(extension_type) {
                "GREASE".to_owned()
            } else {
                format!("0x{extension_type:04x}")
            });
        }
        order
    }

    fn is_grease(value: u16) -> bool {
        let [high, low] = value.to_be_bytes();
        high == low && high & 0x0f == 0x0a
    }

    fn oracle_extension_order(shape_json: &str) -> (String, Vec<String>) {
        let shape: serde_json::Value =
            serde_json::from_str(shape_json).expect("uTLS shape fixture should decode");
        let fingerprint = shape["fingerprint"]
            .as_str()
            .expect("fixture names its fingerprint")
            .to_owned();
        let order = shape["extension_order"]
            .as_array()
            .expect("fixture carries an extension order")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("extension order entries are strings")
                    .to_owned()
            })
            .collect();
        (fingerprint, order)
    }

    /// The TLS-1.2-era profiles -- the ones whose uTLS hello carries no
    /// `supported_versions` extension -- must still emit their extensions in
    /// uTLS' order.
    ///
    /// rustls emits `supported_versions` on every ClientHello it builds, TLS
    /// 1.2-only configs included, and refuses both to have it disabled and to
    /// have it left out of a pinned order. So the one permitted divergence is
    /// that single extension, kept at the very end: everything before it is
    /// uTLS' own order, byte for byte.
    #[test]
    fn tls12_era_profiles_pin_the_utls_extension_order() {
        for shape_json in [
            CLIENTHELLO_SHAPE_ANDROID_JSON,
            CLIENTHELLO_SHAPE_HELLOCHROME_58_JSON,
        ] {
            let (fingerprint, mut expected) = oracle_extension_order(shape_json);
            assert!(
                !expected.contains(&format!("0x{EXT_SUPPORTED_VERSIONS:04x}")),
                "{fingerprint}: fixture is meant to be a TLS-1.2-era shape"
            );
            expected.push(format!("0x{EXT_SUPPORTED_VERSIONS:04x}"));

            let hello = plain_tls_client_hello_bytes(&config(&fingerprint, &[]))
                .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}"));

            assert_eq!(extension_order(&hello), expected, "{fingerprint}");
        }
    }

    /// A ClientHello whose extension order is reshuffled per connection is
    /// itself a fingerprint: no real client does that. rustls randomizes the
    /// order of any extension it was not given an explicit position for, so
    /// every profile has to pin one.
    #[test]
    fn every_fingerprint_emits_a_stable_extension_order() {
        for fingerprint in xray_utls::XRAY_UTLS_FINGERPRINTS {
            for alpn in [&[][..], &["http/1.1"][..]] {
                let first = plain_tls_client_hello_bytes(&config(fingerprint, alpn))
                    .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}"));
                for _ in 0..8 {
                    let next = plain_tls_client_hello_bytes(&config(fingerprint, alpn))
                        .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}"));
                    assert_eq!(
                        extension_order(&next),
                        extension_order(&first),
                        "{fingerprint} (alpn {alpn:?}): extension order must not vary per connection"
                    );
                }
            }
        }
    }

    /// RFC 6066 forbids SNI for an IP address, so rustls omits the extension
    /// when the server name is an IP literal -- but the shaping plan is built
    /// from a browser fingerprint that has no idea what the server name will
    /// be, so it still lists `server_name` and still counts GREASE positions
    /// against it. Reconciling those is `shaped-rustls`' job; it failed to,
    /// and every shaped dial to an IP-addressed server died after the TCP
    /// connect with an error naming neither the fingerprint nor the SNI. Two
    /// ordinary configs land here: a DoT outbound with no `serverName`, and a
    /// VLESS outbound whose `serverName` is an IP literal.
    ///
    /// uTLS keeps a zero-length `SNIExtension` in its list and writes nothing
    /// for it, so the whole shape is the domain shape with that one extension
    /// gone -- which is what this asserts, per fingerprint, against the very
    /// hello the domain SNI produces.
    #[test]
    fn an_ip_literal_sni_shapes_the_hello_without_the_server_name_extension() {
        for fingerprint in xray_utls::XRAY_UTLS_FINGERPRINTS {
            for alpn in [&[][..], &["http/1.1"][..]] {
                let ip = plain_tls_client_hello_bytes(&TlsClientConfig {
                    server_name: "203.0.113.10".to_owned(),
                    allow_insecure: true,
                    alpn: alpn.iter().map(|value| (*value).to_owned()).collect(),
                    fingerprint: Some((*fingerprint).to_owned()),
                })
                .unwrap_or_else(|error| {
                    panic!("{fingerprint} (alpn {alpn:?}): IP-literal ClientHello: {error}")
                });

                let mut expected = extension_order(
                    &plain_tls_client_hello_bytes(&config(fingerprint, alpn))
                        .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}")),
                );
                let server_name = format!("0x{EXT_SERVER_NAME:04x}");
                let position = expected
                    .iter()
                    .position(|extension| *extension == server_name)
                    .unwrap_or_else(|| {
                        panic!("{fingerprint}: a domain SNI must produce a server_name extension")
                    });
                expected.remove(position);

                assert_eq!(
                    extension_order(&ip),
                    expected,
                    "{fingerprint} (alpn {alpn:?}): an IP-literal SNI must drop server_name \
                     and leave every other extension, GREASE included, where it was"
                );
            }
        }
    }

    #[test]
    fn unknown_fingerprints_are_rejected() {
        let error = plain_tls_client_hello_bytes(&config("nosuchbrowser", &[]))
            .expect_err("an unknown fingerprint must not silently fall back");

        assert!(
            error.to_string().contains("nosuchbrowser"),
            "the error must name the offending fingerprint, got: {error}"
        );
    }

    /// Dials `connector` at a throwaway loopback listener and hands back the
    /// first TLS record that listener saw. It never replies, so the handshake
    /// dies right after -- by then the bytes under test are already on the wire.
    async fn recorded_client_hello(connector: &TlsConnector, config: &TlsClientConfig) -> Vec<u8> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener must bind");
        let addr = listener
            .local_addr()
            .expect("listener must report its address");

        let recorded = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            // One read is not one record: a shaped hello runs past a kilobyte,
            // and a short one would truncate the extension list into a parse
            // that walks off the end of the buffer.
            let mut record = vec![0u8; 5];
            stream
                .read_exact(&mut record)
                .await
                .expect("the record header must arrive");
            let payload_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
            record.resize(5 + payload_len, 0);
            stream
                .read_exact(&mut record[5..])
                .await
                .expect("the whole record must arrive");
            record
        });

        // The handshake cannot complete against a listener that never speaks;
        // which error it dies with is not what this is about.
        let _ = connector
            .connect(
                &Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp),
                config,
            )
            .await;

        recorded.await.expect("the recording task must finish")
    }

    /// Every other test in this file inspects a hello synthesized without a
    /// socket. This one inspects the bytes a real dial puts on the wire, so a
    /// change to the connect path cannot silently unshape live handshakes while
    /// the synthesized tests stay green.
    #[tokio::test]
    async fn dialed_connections_send_the_shaped_hello() {
        // `system()` plus `allow_insecure: true` is the only combination that
        // gives both shaping and a self-signed local listener. Do NOT reach for
        // `with_pinned_client_config` here: it bypasses the cache *and* the
        // fingerprint validation, so this test would pass while shaping never
        // ran -- which is precisely the failure it exists to detect, and
        // precisely what the repo's other live-handshake test
        // (`crates/xray-core-rs/tests/local_xray_interop_tests.rs`) does.
        let connector = TlsConnector::system().expect("system roots must load");
        let config = TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: true,
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        };

        // Twice through the same connector. The second dial takes the memoized
        // config, and with it the `Arc`-shared customizer -- the path every
        // connection after the first takes in production, and the one no
        // synthesized test can reach: `plain_tls_client_hello_bytes` builds a
        // fresh config per call, so a customizer that shaped only its first
        // hello would leave every test above green.
        let dialed = [
            ("first", recorded_client_hello(&connector, &config).await),
            ("second", recorded_client_hello(&connector, &config).await),
        ];
        let synthesized =
            plain_tls_client_hello_bytes(&config).expect("chrome ClientHello must be produced");

        for (dial, hello) in &dialed {
            assert_eq!(
                cipher_suites(hello).first().copied(),
                Some(CHROME_GREASE_CIPHER),
                "{dial} dial: the hello on the wire must be shaped"
            );
            assert_eq!(
                alpn_protocols(hello),
                alpn(&["h2", "http/1.1"]),
                "{dial} dial: the hello on the wire must carry the profile's ALPN"
            );

            // Those two spot checks would still pass if the wire hello lost its
            // pinned extension order -- the part rustls randomizes per
            // connection when nobody pins it, and the part the oracle fixtures
            // above exist to hold. Comparing the whole shape against the hello
            // built from this very config carries that oracle coverage onto the
            // wire instead of restating a fraction of it.
            assert_eq!(
                cipher_suites(hello),
                cipher_suites(&synthesized),
                "{dial} dial: the wire cipher suites must be the shaped ones"
            );
            assert_eq!(
                extension_order(hello),
                extension_order(&synthesized),
                "{dial} dial: the wire extension order must be the shaped one"
            );
        }
    }
}
