mod utls_tls_shaping_tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ProtocolVersion;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{
        plain_tls_client_hello_bytes, TlsClientConfig, TlsConnector, TransportError,
    };

    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_ALPN: u16 = 0x0010;
    const EXT_CERTIFICATE_COMPRESSION: u16 = 0x001b;
    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    const EXT_KEY_SHARE: u16 = 0x0033;
    const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
    const GROUP_SECP256R1: u16 = 0x0017;
    const CHROME_GREASE_CIPHER: u16 = 0x0a0a;
    const CHROME_PROVIDER_SUPPORTED_CIPHERS: &[u16] = &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    ];
    const CHROME_LEGACY_TLS12_CIPHERS: &[u16] = &[0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];

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

    fn extension_payload(hello: &[u8], wanted_type: u16) -> Option<&[u8]> {
        let mut cursor = 5 + 4 + 2 + 32;
        cursor += 1 + usize::from(hello[cursor]);
        let cipher_suites_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2 + cipher_suites_len;
        cursor += 1 + usize::from(hello[cursor]);
        let extensions_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        let end = cursor + extensions_len;

        while cursor + 4 <= end {
            let extension_type = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
            let payload_len =
                usize::from(u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]));
            let payload_start = cursor + 4;
            cursor = payload_start + payload_len;
            if extension_type == wanted_type {
                return Some(&hello[payload_start..cursor]);
            }
        }

        None
    }

    fn certificate_compression_algorithms(hello: &[u8]) -> Option<Vec<u16>> {
        let payload = extension_payload(hello, EXT_CERTIFICATE_COMPRESSION)?;
        let algorithms_len = usize::from(*payload.first()?);
        let algorithms = payload.get(1..1 + algorithms_len)?;
        Some(
            algorithms
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect(),
        )
    }

    fn key_share(hello: &[u8], wanted_group: u16) -> Option<&[u8]> {
        let payload = extension_payload(hello, EXT_KEY_SHARE)?;
        let shares_len = usize::from(u16::from_be_bytes([*payload.first()?, *payload.get(1)?]));
        let mut cursor = 2;
        let end = cursor + shares_len;

        while cursor + 4 <= end {
            let group = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
            let key_exchange_len = usize::from(u16::from_be_bytes([
                payload[cursor + 2],
                payload[cursor + 3],
            ]));
            let key_exchange_start = cursor + 4;
            cursor = key_exchange_start + key_exchange_len;
            if group == wanted_group {
                return Some(&payload[key_exchange_start..cursor]);
            }
        }

        None
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

    fn provider_cipher_suites(versions: &[ProtocolVersion]) -> BTreeSet<u16> {
        rustls::crypto::aws_lc_rs::default_provider()
            .cipher_suites
            .iter()
            .filter(|suite| versions.contains(&suite.version().version))
            .map(|suite| u16::from(suite.suite()))
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
    fn legacy_cipher_advertisement_keeps_chrome_order_and_grease() {
        let hello = plain_tls_client_hello_bytes(&config("chrome", &[]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(
            cipher_suites(&hello),
            CHROME_PROVIDER_SUPPORTED_CIPHERS,
            "filtering must preserve the profile order and its leading GREASE slot"
        );
    }

    #[test]
    fn legacy_cipher_advertisement_is_supported_for_every_selectable_profile() {
        for fingerprint in selectable_fingerprints() {
            let hello = plain_tls_client_hello_bytes(&config(fingerprint, &[]))
                .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}"));
            let versions = if TLS12_ERA_FINGERPRINTS.contains(&fingerprint) {
                &[ProtocolVersion::TLSv1_2][..]
            } else {
                &[ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2][..]
            };
            let supported = provider_cipher_suites(versions);
            let advertised = cipher_suites(&hello)
                .into_iter()
                .filter(|suite| !is_grease(*suite))
                .collect::<Vec<_>>();

            assert!(
                !advertised.is_empty(),
                "{fingerprint}: a selectable profile needs a negotiable suite"
            );
            assert!(
                advertised.iter().all(|suite| supported.contains(suite)),
                "{fingerprint}: advertised {advertised:04x?}, provider supports {supported:04x?}"
            );
        }
    }

    #[test]
    fn safari_and_firefox_keep_their_certificate_compression_fingerprint() {
        let safari = plain_tls_client_hello_bytes(&config("safari", &[]))
            .expect("Safari ClientHello must be produced");
        let firefox = plain_tls_client_hello_bytes(&config("firefox", &[]))
            .expect("Firefox ClientHello must be produced");

        assert_eq!(certificate_compression_algorithms(&safari), Some(vec![1]));
        assert_eq!(
            certificate_compression_algorithms(&firefox),
            Some(vec![1, 2, 3]),
            "Firefox's zlib/brotli/zstd order is part of the fingerprint"
        );
    }

    #[test]
    fn firefox_plain_tls_uses_a_real_p256_key_share() {
        let hello = plain_tls_client_hello_bytes(&config("firefox", &[]))
            .expect("Firefox ClientHello must be produced");
        let p256 = key_share(&hello, GROUP_SECP256R1)
            .expect("the Firefox profile must carry a P-256 key share");

        assert_eq!(p256.len(), 65);
        assert_eq!(p256[0], 0x04, "P-256 uses an uncompressed SEC1 point");
        assert!(
            p256[1..].iter().any(|byte| *byte != 0),
            "the key share must be generated, not a zero-filled placeholder"
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

    /// Nearly all of them, at least: `hello360_7_5` is REALITY-incapable and
    /// unusable on plain TLS too, for a second and unrelated reason --
    /// `a_fingerprint_with_no_implemented_cipher_suite_is_refused`.
    #[test]
    fn reality_incapable_fingerprints_are_usable_on_plain_tls() {
        let hello = plain_tls_client_hello_bytes(&config("hellochrome_58", &[]))
            .expect("a REALITY-incapable fingerprint must still shape plain TLS");

        assert!(!hello.is_empty());
    }

    /// Rewrites every field a fresh handshake regenerates -- the hello random,
    /// the legacy session id, each key share's key exchange, and ECH GREASE's
    /// AEAD id, config id, encapsulated key and payload -- to zero, so two
    /// hellos compare equal exactly when they have the same *shape*.
    ///
    /// Comparing raw bytes without this would compare fresh entropy and always
    /// differ; comparing only the extension order would miss a profile swap
    /// that happened to preserve it.
    fn shape_signature(hello: &[u8]) -> Vec<u8> {
        let mut hello = hello.to_vec();
        let mut cursor = 5 + 4 + 2;

        hello[cursor..cursor + 32].fill(0);
        cursor += 32;
        let session_id_len = usize::from(hello[cursor]);
        cursor += 1;
        hello[cursor..cursor + session_id_len].fill(0);
        cursor += session_id_len;

        let cipher_suites_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2 + cipher_suites_len;
        cursor += 1 + usize::from(hello[cursor]);
        let extensions_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        let end = cursor + extensions_len;

        while cursor + 4 <= end {
            let extension_type = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
            let payload_len =
                usize::from(u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]));
            let payload_start = cursor + 4;
            cursor = payload_start + payload_len;

            match extension_type {
                EXT_KEY_SHARE => {
                    let mut share = payload_start + 2;
                    while share + 4 <= payload_start + payload_len {
                        let key_exchange_len =
                            usize::from(u16::from_be_bytes([hello[share + 2], hello[share + 3]]));
                        hello[share + 4..share + 4 + key_exchange_len].fill(0);
                        share += 4 + key_exchange_len;
                    }
                }
                EXT_ENCRYPTED_CLIENT_HELLO => {
                    // Outer hello (`u_ech.go:177`): type and KDF id are fixed
                    // by the profile, then an AEAD id, a config id and two
                    // length-prefixed fields -- the encapsulated key and the
                    // payload -- that uTLS redraws per connection just like a
                    // key share. The AEAD is drawn from the profile's
                    // `CandidateCipherSuites`, so it is only constant for the
                    // profiles that declare one suite; blanking it here is what
                    // lets the Firefox scheme's coin flip reduce to one shape.
                    hello[payload_start + 3] = 0;
                    hello[payload_start + 4] = 0;
                    hello[payload_start + 5] = 0;
                    let mut field = payload_start + 6;
                    for _ in 0..2 {
                        let field_len =
                            usize::from(u16::from_be_bytes([hello[field], hello[field + 1]]));
                        hello[field + 2..field + 2 + field_len].fill(0);
                        field += 2 + field_len;
                    }
                }
                _ => {}
            }
        }

        hello
    }

    fn shape_of(fingerprint: &str) -> Vec<u8> {
        shape_signature(
            &plain_tls_client_hello_bytes(&config(fingerprint, &[]))
                .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}")),
        )
    }

    /// Xray seeds `random` from `crypto/rand` at process start, so the name
    /// means a different real browser on every install. A fixed answer would
    /// hand our whole user base one shared signature -- the opposite of what
    /// the name promises.
    ///
    /// A thousand draws from eleven names leave a given name unseen with
    /// probability `(10/11)^1000`, about `4e-42`, so requiring all eleven is
    /// not a flaky assertion; it is how a stuck draw gets caught.
    #[test]
    fn the_random_draw_covers_every_modern_fingerprint() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            let drawn = xray_transport::draw_modern_fingerprint();
            assert!(
                xray_utls::XRAY_MODERN_FINGERPRINTS.contains(&drawn),
                "drew {drawn}, which is not one of Xray's ModernFingerprints"
            );
            seen.insert(drawn);
        }

        assert_eq!(
            seen.len(),
            xray_utls::XRAY_MODERN_FINGERPRINTS.len(),
            "every modern fingerprint must be reachable, saw {seen:?}"
        );
    }

    /// Two connections on one fixed name must reduce to one shape, or the
    /// `random` assertions below are testing the entropy in a hello rather
    /// than the profile behind it.
    ///
    /// Every modern fingerprint is checked rather than one representative,
    /// because which name exposes a per-connection field moves with the
    /// profiles. `hellofirefox_120` is what catches it today: its ECH GREASE
    /// redraws a config id, an X25519 encapsulated key, a payload *and* the HPKE
    /// AEAD id per hello, so a signature that leaves any of the four alone
    /// differs between connections, whereas `chrome` cannot expose the AEAD at
    /// all -- `BoringGREASEECH` declares a single cipher suite
    /// (`u_ech.go:296`), so an unmasked AEAD id sails past it, which is how the
    /// AEAD stayed unmasked here until it started failing the `random` tests
    /// below. Naming either one blinds the guard to the other: `chrome` pins one
    /// of uTLS's four ECH payload lengths (`ECH_GREASE_BORING`,
    /// `crates/xray-transport/src/utls_profiles.rs:68`) whose own doc records
    /// unpinning as intended work, and the day that lands `chrome`'s hello
    /// varies per connection while `hellofirefox_120`'s still does not.
    ///
    /// Only a handful of the eleven names carry ECH at all, so a field left
    /// unblanked reaches
    /// `random_names_are_stable_for_the_life_of_the_process` as a failure on
    /// the few runs in eleven that draw an affected name. Repeating each draw
    /// makes this guard itself deterministic instead: sixteen further hellos
    /// agree with the first by chance with probability 2^-16.
    #[test]
    fn every_fingerprint_reduces_to_one_shape_across_connections() {
        for fingerprint in xray_utls::XRAY_MODERN_FINGERPRINTS {
            let first = shape_of(fingerprint);

            for _ in 0..16 {
                assert_eq!(
                    shape_of(fingerprint),
                    first,
                    "{fingerprint} must reduce to one shape across connections"
                );
            }
        }
    }

    /// The drawn name has to resolve to the very profile that name resolves to
    /// on its own -- a real browser shape, not a synthesized one.
    #[test]
    fn random_names_resolve_to_a_modern_fingerprints_shape() {
        let candidates = xray_utls::XRAY_MODERN_FINGERPRINTS
            .iter()
            .map(|fingerprint| shape_of(fingerprint))
            .collect::<Vec<_>>();

        for fingerprint in ["random", "randomized"] {
            let shape = shape_of(fingerprint);
            assert!(
                candidates.contains(&shape),
                "{fingerprint} must emit one of the modern fingerprints' shapes"
            );
        }
    }

    /// A client whose hello changes between connections is more
    /// distinguishable than one that never changes, so the draw is made once
    /// and cached for the process.
    #[test]
    fn random_names_are_stable_for_the_life_of_the_process() {
        for fingerprint in ["random", "randomized"] {
            for alpn in [&[][..], &["http/1.1"][..]] {
                let first = shape_signature(
                    &plain_tls_client_hello_bytes(&config(fingerprint, alpn))
                        .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}")),
                );
                for _ in 0..16 {
                    let next = shape_signature(
                        &plain_tls_client_hello_bytes(&config(fingerprint, alpn))
                            .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}")),
                    );
                    assert_eq!(
                        next, first,
                        "{fingerprint} (alpn {alpn:?}): the draw must not change between connections"
                    );
                }
            }
        }
    }

    /// `randomizednoalpn` keeps its frozen snapshot on purpose: every modern
    /// fingerprint carries ALPN, so drawing one would add the extension the
    /// name exists to suppress. Documented in `docs/config-compatibility.md`.
    #[test]
    fn randomizednoalpn_still_emits_no_alpn_extension() {
        let hello = plain_tls_client_hello_bytes(&config("randomizednoalpn", &[]))
            .expect("randomizednoalpn ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), None);
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

    /// The HPKE AEAD id inside the ECH GREASE extension, if the profile emits
    /// one. The body is `type(1) | kdf(2) | aead(2) | ...`.
    fn ech_aead_id(hello: &[u8]) -> Option<u16> {
        let mut cursor = 5 + 4 + 2 + 32;
        cursor += 1 + usize::from(hello[cursor]);
        let cipher_suites_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2 + cipher_suites_len;
        cursor += 1 + usize::from(hello[cursor]);
        let extensions_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        let end = cursor + extensions_len;

        while cursor + 4 <= end {
            let extension_type = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
            let payload_len =
                usize::from(u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]));
            let body = &hello[cursor + 4..cursor + 4 + payload_len];
            if extension_type == 0xfe0d {
                return Some(u16::from_be_bytes([body[3], body[4]]));
            }
            cursor += 4 + payload_len;
        }
        None
    }

    #[test]
    fn ech_grease_draws_every_candidate_aead() {
        // uTLS gives the Firefox parrots two HPKE cipher suites and picks one
        // per connection. Sending AES-128-GCM every time would make a handful
        // of connections from one client conclusive, so this is the property
        // the byte-oracle cannot see: it runs under a zeroed `crypto/rand` and
        // can only ever record the first candidate.
        //
        // A fair draw misses a side across 40 tries with probability 2^-40.
        let mut seen = BTreeSet::new();
        for _ in 0..40 {
            let hello = plain_tls_client_hello_bytes(&config("firefox", &[]))
                .expect("firefox ClientHello must be produced");
            seen.insert(ech_aead_id(&hello).expect("firefox carries an ECH GREASE extension"));
        }

        assert_eq!(
            seen,
            BTreeSet::from([0x0001, 0x0003]),
            "Firefox draws between AES-128-GCM and ChaCha20-Poly1305"
        );
    }

    #[test]
    fn ech_grease_holds_the_chrome_aead_fixed() {
        // `BoringGREASEECH` declares a single cipher suite, so varying this
        // would be its own tell rather than a fix.
        for _ in 0..20 {
            let hello = plain_tls_client_hello_bytes(&config("chrome", &[]))
                .expect("chrome ClientHello must be produced");
            assert_eq!(
                ech_aead_id(&hello),
                Some(0x0001),
                "Chrome always offers AES-128-GCM"
            );
        }
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
        for fingerprint in selectable_fingerprints() {
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
        for fingerprint in selectable_fingerprints() {
            for alpn in [&[][..], &["http/1.1"][..]] {
                let ip = plain_tls_client_hello_bytes(&TlsClientConfig {
                    server_name: "203.0.113.10".to_owned(),
                    allow_insecure: true,
                    alpn: alpn.iter().map(|value| (*value).to_owned()).collect(),
                    fingerprint: Some(fingerprint.to_owned()),
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

    /// The fingerprints whose uTLS parrot emits a TLS-1.2-era ClientHello: one
    /// carrying no `supported_versions` extension at all.
    ///
    /// uTLS reads that absence as a version range rather than ignoring it.
    /// `SetTLSVers` defaults to TLS 1.0-1.2 when the parrot declares neither
    /// `TLSVersMin`/`TLSVersMax` nor the extension, then writes the ceiling
    /// into `config.MaxVersion`
    /// (`utls@v1.8.3-0.20260301010127-aa6edf4b11af/u_conn.go:728-752`). A Go
    /// client on one of these names therefore never claims TLS 1.3, so it never
    /// reaches its own downgrade check. Measured, not inferred: each parrot
    /// against a Go `tls.Listen` with `MaxVersion: VersionTLS13` negotiates TLS
    /// 1.2 and completes.
    ///
    /// The two `randomized` names are here on their frozen snapshots, not on
    /// uTLS' live behaviour: uTLS re-rolls those specs per call and lands on TLS
    /// 1.3 some of the time. `docs/config-compatibility.md` covers why we hold
    /// one recorded spec instead.
    ///
    /// Every name a profile answers to is listed, because a name is what a
    /// config file carries.
    const TLS12_ERA_FINGERPRINTS: &[&str] = &[
        "android",
        "helloandroid_11_okhttp",
        "randomizednoalpn",
        "hellorandomizednoalpn",
        "hellorandomizedalpn",
        "hellofirefox_55",
        "hellofirefox_56",
        "hellochrome_58",
        "hellochrome_62",
        "helloios_11_1",
        "helloios_12_1",
    ];

    /// `hello360_7_5` under each of its names -- the one TLS-1.2-era parrot
    /// that a version fix cannot rescue.
    ///
    /// Its twenty cipher suites are CBC, RC4 or 3DES, not an AEAD among them
    /// (`utls@v1.8.3-.../u_parrots.go:2352-2374`), while rustls' TLS 1.2 half is
    /// six AEAD suites -- so the two lists do not intersect. uTLS does negotiate
    /// it: a Go server keeping its legacy suites enabled picks
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` (0xc009), which makes this our
    /// limit rather than the parrot's.
    const UNNEGOTIABLE_FINGERPRINTS: &[&str] = &["360", "hello360_auto", "hello360_7_5"];

    /// Every fingerprint a config can select: Xray's whole list, less the ones
    /// the client refuses outright.
    ///
    /// The sweeping tests want this rather than the raw list. A refused
    /// fingerprint has no ClientHello for them to inspect, and pretending
    /// otherwise -- by building one down a path no dial takes -- would be
    /// coverage of nothing. What it does instead is pinned by
    /// `a_fingerprint_with_no_implemented_cipher_suite_is_refused`.
    fn selectable_fingerprints() -> impl Iterator<Item = &'static str> {
        xray_utls::XRAY_UTLS_FINGERPRINTS
            .iter()
            .copied()
            .filter(|fingerprint| !UNNEGOTIABLE_FINGERPRINTS.contains(fingerprint))
    }

    /// A TLS-1.3-capable loopback listener that reports the version it settled
    /// on.
    ///
    /// Capable matters: RFC 8446 §4.1.3's downgrade sentinel only appears in a
    /// ServerHello random when a server that could have spoken TLS 1.3 settles
    /// for TLS 1.2, which is what every current server does with these hellos.
    /// Reporting matters too: a dial that returns `Ok` says nothing about which
    /// version carried it.
    async fn spawn_version_reporting_tls_server() -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<ProtocolVersion, String>>,
    ) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["server.test".to_owned()])
                .expect("a self-signed certificate must generate");
        let certificate = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the provider must support the default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("the TLS server config must build");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener must bind");
        let addr = listener
            .local_addr()
            .expect("listener must report its address");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let served = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let stream = acceptor.accept(stream).await.map_err(|e| e.to_string())?;
            stream
                .get_ref()
                .1
                .protocol_version()
                .ok_or_else(|| "the server negotiated no version".to_owned())
        });

        (addr, served)
    }

    /// Minimal TLS 1.2 legacy-only peer. It reads the real wire ClientHello,
    /// records its suites, then sends the handshake_failure a server with no
    /// common cipher is required to produce. The suites are intentionally the
    /// compatibility tail Chrome used to advertise despite being unusable by
    /// our provider.
    async fn spawn_tls12_legacy_only_server() -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<Vec<u16>, String>>,
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener must bind");
        let addr = listener
            .local_addr()
            .expect("listener must report its address");

        let served = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let mut record = vec![0u8; 5];
            stream
                .read_exact(&mut record)
                .await
                .map_err(|e| e.to_string())?;
            let payload_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
            record.resize(5 + payload_len, 0);
            stream
                .read_exact(&mut record[5..])
                .await
                .map_err(|e| e.to_string())?;
            let offered = cipher_suites(&record);

            // fatal handshake_failure, encoded as a TLS 1.2 alert record.
            stream
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
                .await
                .map_err(|e| e.to_string())?;
            Ok(offered)
        });

        (addr, served)
    }

    /// A TLS 1.3 listener that always chooses its sole compressor when the
    /// client advertises it. A successful handshake therefore exercises the
    /// client's decompression path, not just its ClientHello bytes.
    async fn spawn_compressed_certificate_tls_server(
        compressor: &'static dyn rustls::compress::CertCompressor,
    ) -> (SocketAddr, tokio::task::JoinHandle<Result<(), String>>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["server.test".to_owned()])
                .expect("a self-signed certificate must generate");
        let certificate = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the provider must support the default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("the TLS server config must build");
        server_config.cert_compressors = vec![compressor];

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener must bind");
        let addr = listener
            .local_addr()
            .expect("listener must report its address");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let served = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            acceptor
                .accept(stream)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        (addr, served)
    }

    #[derive(Debug)]
    struct ZstdCertificateCompressor;

    impl rustls::compress::CertCompressor for ZstdCertificateCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: rustls::compress::CompressionLevel,
        ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
            let level = match level {
                rustls::compress::CompressionLevel::Interactive => 1,
                rustls::compress::CompressionLevel::Amortized => 3,
            };
            zstd::bulk::compress(&input, level).map_err(|_| rustls::compress::CompressionFailed)
        }

        fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
            rustls::CertificateCompressionAlgorithm::Zstd
        }
    }

    static ZSTD_CERTIFICATE_COMPRESSOR: ZstdCertificateCompressor = ZstdCertificateCompressor;

    /// Dials `addr` with one fingerprint through the shaping path.
    ///
    /// `system()` plus `allow_insecure: true` for the reason
    /// `dialed_connections_send_the_shaped_hello` gives: a pinned config would
    /// skip shaping altogether and pass whatever the fingerprint is.
    async fn dial_shaped(fingerprint: &str, addr: SocketAddr) -> Result<(), TransportError> {
        let connector = TlsConnector::system().expect("system roots must load");
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: true,
            alpn: Vec::new(),
            fingerprint: Some(fingerprint.to_owned()),
        };

        connector
            .connect(
                &Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp),
                &config,
            )
            .await
            .map(|_| ())
    }

    /// A fingerprint that cannot finish a handshake is a fingerprint nobody can
    /// select, and `security: "tls"` with any of these was exactly that: the
    /// rustls config offered TLS 1.3 while the shaped hello said nothing about
    /// it, so the server's TLS 1.2 ServerHello carried the downgrade sentinel
    /// and rustls read it as an attack.
    #[tokio::test]
    async fn tls12_era_fingerprints_complete_a_handshake() {
        for fingerprint in TLS12_ERA_FINGERPRINTS {
            let (addr, served) = spawn_version_reporting_tls_server().await;

            dial_shaped(fingerprint, addr)
                .await
                .unwrap_or_else(|error| panic!("{fingerprint}: the dial must succeed: {error}"));

            let negotiated = served.await.expect("the server task must finish");
            assert_eq!(
                negotiated,
                Ok(ProtocolVersion::TLSv1_2),
                "{fingerprint}: a hello with no supported_versions must land on TLS 1.2"
            );
        }
    }

    /// The control: capping the config at TLS 1.2 must follow the profile, not
    /// the shaping path, or the fix above would quietly downgrade every
    /// fingerprint anyone actually uses.
    #[tokio::test]
    async fn a_modern_fingerprint_still_negotiates_tls13() {
        let (addr, served) = spawn_version_reporting_tls_server().await;

        dial_shaped("chrome", addr)
            .await
            .expect("chrome must still complete a handshake");

        let negotiated = served.await.expect("the server task must finish");
        assert_eq!(negotiated, Ok(ProtocolVersion::TLSv1_3));
    }

    #[tokio::test]
    async fn legacy_cipher_advertisement_has_no_chrome_tls12_legacy_server_overlap() {
        let (addr, served) = spawn_tls12_legacy_only_server().await;

        dial_shaped("chrome", addr)
            .await
            .expect_err("a legacy-only server has no common cipher with this provider");
        let offered = served
            .await
            .expect("the server task must finish")
            .expect("the server must read the ClientHello");
        let overlap = offered
            .iter()
            .copied()
            .filter(|suite| CHROME_LEGACY_TLS12_CIPHERS.contains(suite))
            .collect::<Vec<_>>();

        assert!(
            overlap.is_empty(),
            "Chrome advertised legacy-only suites the provider cannot finish: {overlap:04x?}"
        );
    }

    #[tokio::test]
    async fn safari_and_firefox_accept_a_zlib_compressed_certificate() {
        for fingerprint in ["safari", "firefox"] {
            let (addr, served) =
                spawn_compressed_certificate_tls_server(rustls::compress::ZLIB_COMPRESSOR).await;

            dial_shaped(fingerprint, addr)
                .await
                .unwrap_or_else(|error| {
                    panic!("{fingerprint}: the zlib-compressed handshake must succeed: {error}")
                });

            served
                .await
                .expect("the server task must finish")
                .unwrap_or_else(|error| panic!("{fingerprint}: server handshake: {error}"));
        }
    }

    #[tokio::test]
    async fn firefox_accepts_a_zstd_compressed_certificate() {
        let (addr, served) =
            spawn_compressed_certificate_tls_server(&ZSTD_CERTIFICATE_COMPRESSOR).await;

        dial_shaped("firefox", addr)
            .await
            .unwrap_or_else(|error| panic!("zstd-compressed handshake: {error}"));

        served
            .await
            .expect("the server task must finish")
            .unwrap_or_else(|error| panic!("server handshake: {error}"));
    }

    /// uTLS puts 32 random bytes in the legacy session id of every ClientHello,
    /// TLS-1.2-era parrots included: `makeClientHello` fills it unconditionally
    /// for anything that is not QUIC
    /// (`utls@v1.8.3-.../handshake_client.go:126-136`), and reading
    /// `HandshakeState.Hello.SessionId` off each parrot above reports 32.
    ///
    /// rustls empties it the moment its config stops offering TLS 1.3
    /// (`rustls/src/client/hs.rs:125`), which is a trap laid directly under the
    /// version fix: capping the config alone would buy a working handshake at
    /// the price of a hello 32 bytes shorter than any real client's.
    #[test]
    fn tls12_era_fingerprints_keep_a_32_byte_session_id() {
        for fingerprint in TLS12_ERA_FINGERPRINTS {
            let hello = plain_tls_client_hello_bytes(&config(fingerprint, &[]))
                .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}"));

            assert_eq!(
                session_id_len(&hello),
                32,
                "{fingerprint}: uTLS sends a 32-byte legacy session id"
            );
        }
    }

    /// Reads the legacy session id's length. Layout: record header (5) +
    /// handshake header (4) + version (2) + random (32).
    fn session_id_len(hello: &[u8]) -> usize {
        usize::from(hello[5 + 4 + 2 + 32])
    }

    /// Faking support would mean advertising suites we cannot use and losing
    /// the connection at ServerHello with `SelectedUnofferedCipherSuite`, after
    /// a socket, a round trip and an error naming neither the fingerprint nor
    /// the reason. Refusing the config says the same thing for free.
    #[test]
    fn a_fingerprint_with_no_implemented_cipher_suite_is_refused() {
        for fingerprint in UNNEGOTIABLE_FINGERPRINTS {
            let error = plain_tls_client_hello_bytes(&config(fingerprint, &[])).expect_err(
                "a fingerprint whose suites rustls cannot implement must not build a config",
            );
            let message = error.to_string();

            assert!(
                message.contains(fingerprint),
                "{fingerprint}: the error must name the fingerprint, got: {message}"
            );
            assert!(
                message.contains("cipher suite"),
                "{fingerprint}: the error must name the reason, got: {message}"
            );
        }
    }

    /// Together the two lists above are Xray's REALITY-incapable set, and this
    /// is what keeps them exhaustive as profiles are added.
    ///
    /// A profile with no TLS 1.3 declares no key share, and a REALITY
    /// ClientHello without an X25519 key share has nowhere to put its
    /// authentication -- so Xray's REALITY-incapable set is exactly the set of
    /// TLS-1.2-era parrots, under every alias.
    #[test]
    fn the_tls12_era_lists_cover_every_reality_incapable_fingerprint() {
        let listed = TLS12_ERA_FINGERPRINTS
            .iter()
            .chain(UNNEGOTIABLE_FINGERPRINTS)
            .collect::<BTreeSet<_>>();
        let reality_incapable = xray_utls::XRAY_REALITY_INCAPABLE_FINGERPRINTS
            .iter()
            .collect::<BTreeSet<_>>();

        assert_eq!(listed, reality_incapable);
    }
}
