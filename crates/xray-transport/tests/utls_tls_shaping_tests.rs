mod utls_tls_shaping_tests {
    use xray_transport::{plain_tls_client_hello_bytes, TlsClientConfig};

    const EXT_ALPN: u16 = 0x0010;
    const CHROME_GREASE_CIPHER: u16 = 0x0a0a;

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

    /// The shaped hello is reframed by hand, the unshaped one comes framed by
    /// rustls; both must hand back the same layout or every parser above --
    /// including the helpers in this file -- reads the wrong offsets.
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

    #[test]
    fn unknown_fingerprints_are_rejected() {
        let error = plain_tls_client_hello_bytes(&config("nosuchbrowser", &[]))
            .expect_err("an unknown fingerprint must not silently fall back");

        assert!(
            error.to_string().contains("nosuchbrowser"),
            "the error must name the offending fingerprint, got: {error}"
        );
    }
}
