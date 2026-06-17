mod reality_clienthello_tests {
    use serde::Deserialize;
    use xray_transport::reality::{
        prepare_reality_handshake, validate_reality_client_hello_metadata,
        RealityClientHelloKeyShareGroup, RealityError, RealityHandshakeInput,
        RealityPreparedClientHello,
    };

    const CLIENTHELLO_FIXTURE_JSON: &str =
        include_str!("../../../tests/fixtures/reality/clienthello_chrome_auto.json");
    const SERVER_PUBLIC_KEY_HEX: &str =
        "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20";
    const PLAIN_X25519_PRIVATE_KEY_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const PLAIN_X25519_PUBLIC_KEY_HEX: &str =
        "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
    const TLS_GROUP_X25519: u16 = 0x001d;
    const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;

    #[derive(Debug, Deserialize)]
    struct ClientHelloFixture {
        fingerprint: String,
        server_name: String,
        raw_client_hello_hex: String,
        hello_random_hex: String,
        session_id_offset: usize,
        local_x25519_private_key_hex: String,
        key_share_group: String,
        key_share_x25519_public_key_offset: usize,
        key_share_x25519_public_key_hex: String,
    }

    fn fixture() -> ClientHelloFixture {
        serde_json::from_str(CLIENTHELLO_FIXTURE_JSON)
            .expect("clienthello fixture JSON must deserialize")
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex string length must be even");
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&hex[index..index + 2], 16)
                    .expect("fixture hex must contain only hex digits")
            })
            .collect()
    }

    fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = decode_hex(hex);
        bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| {
            panic!("expected {N} bytes, got {}", bytes.len());
        })
    }

    fn prepared_from_fixture(fixture: &ClientHelloFixture) -> RealityPreparedClientHello {
        RealityPreparedClientHello {
            fingerprint: fixture.fingerprint.clone(),
            raw_client_hello: decode_hex(&fixture.raw_client_hello_hex),
            hello_random: decode_hex_array(&fixture.hello_random_hex),
            session_id_offset: fixture.session_id_offset,
            local_x25519_private_key: decode_hex_array(&fixture.local_x25519_private_key_hex),
        }
    }

    fn prepared_client_hello_with_key_shares(
        key_shares: &[(u16, Vec<u8>)],
    ) -> (RealityPreparedClientHello, Vec<usize>) {
        let hello_random = [0x10; 32];
        let mut raw_client_hello = Vec::new();

        raw_client_hello.push(0x01);
        let handshake_length_offset = raw_client_hello.len();
        raw_client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);
        raw_client_hello.extend_from_slice(&[0x03, 0x03]);
        raw_client_hello.extend_from_slice(&hello_random);
        raw_client_hello.push(32);
        let session_id_offset = raw_client_hello.len();
        raw_client_hello.extend_from_slice(&[0u8; 32]);
        raw_client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        raw_client_hello.extend_from_slice(&[0x01, 0x00]);

        let extensions_length_offset = raw_client_hello.len();
        raw_client_hello.extend_from_slice(&[0x00, 0x00]);
        let extensions_start = raw_client_hello.len();

        raw_client_hello.extend_from_slice(&[0x00, 0x33]);
        let key_share_extension_length_offset = raw_client_hello.len();
        raw_client_hello.extend_from_slice(&[0x00, 0x00]);
        let key_share_extension_data_start = raw_client_hello.len();

        let key_share_vector_length_offset = raw_client_hello.len();
        raw_client_hello.extend_from_slice(&[0x00, 0x00]);
        let key_share_vector_start = raw_client_hello.len();
        let mut key_exchange_offsets = Vec::new();
        for (group, key_exchange) in key_shares {
            assert!(key_exchange.len() <= u16::MAX as usize);
            raw_client_hello.extend_from_slice(&group.to_be_bytes());
            raw_client_hello.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
            key_exchange_offsets.push(raw_client_hello.len());
            raw_client_hello.extend_from_slice(key_exchange);
        }

        let key_share_vector_length = raw_client_hello.len() - key_share_vector_start;
        raw_client_hello[key_share_vector_length_offset..key_share_vector_length_offset + 2]
            .copy_from_slice(&(key_share_vector_length as u16).to_be_bytes());

        let key_share_extension_length = raw_client_hello.len() - key_share_extension_data_start;
        raw_client_hello[key_share_extension_length_offset..key_share_extension_length_offset + 2]
            .copy_from_slice(&(key_share_extension_length as u16).to_be_bytes());

        let extensions_length = raw_client_hello.len() - extensions_start;
        raw_client_hello[extensions_length_offset..extensions_length_offset + 2]
            .copy_from_slice(&(extensions_length as u16).to_be_bytes());

        let handshake_length = raw_client_hello.len() - 4;
        raw_client_hello[handshake_length_offset] = ((handshake_length >> 16) & 0xff) as u8;
        raw_client_hello[handshake_length_offset + 1] = ((handshake_length >> 8) & 0xff) as u8;
        raw_client_hello[handshake_length_offset + 2] = (handshake_length & 0xff) as u8;

        assert_eq!(session_id_offset, 39);

        (
            RealityPreparedClientHello {
                fingerprint: "chrome".to_owned(),
                raw_client_hello,
                hello_random,
                session_id_offset,
                local_x25519_private_key: decode_hex_array(PLAIN_X25519_PRIVATE_KEY_HEX),
            },
            key_exchange_offsets,
        )
    }

    fn plain_x25519_prepared_client_hello() -> (RealityPreparedClientHello, usize) {
        let key_shares = [(
            TLS_GROUP_X25519,
            decode_hex_array::<32>(PLAIN_X25519_PUBLIC_KEY_HEX).to_vec(),
        )];
        let (prepared, key_exchange_offsets) = prepared_client_hello_with_key_shares(&key_shares);

        (prepared, key_exchange_offsets[0])
    }

    fn expected_group(fixture: &ClientHelloFixture) -> RealityClientHelloKeyShareGroup {
        match fixture.key_share_group.as_str() {
            "x25519" => RealityClientHelloKeyShareGroup::X25519,
            "x25519mlkem768" => RealityClientHelloKeyShareGroup::X25519MlKem768,
            value => panic!("unexpected key-share group {value}"),
        }
    }

    #[test]
    fn clienthello_fixture_has_xray_reality_shape() {
        let fixture = fixture();
        let raw_client_hello = decode_hex(&fixture.raw_client_hello_hex);
        let hello_random = decode_hex(&fixture.hello_random_hex);
        let key_share_public_key = decode_hex(&fixture.key_share_x25519_public_key_hex);

        assert_eq!(fixture.fingerprint, "chrome");
        assert_eq!(fixture.server_name, "example.com");
        assert_eq!(raw_client_hello[0], 0x01);
        assert_eq!(&raw_client_hello[6..38], hello_random.as_slice());
        assert_eq!(raw_client_hello[38], 32);
        assert_eq!(fixture.session_id_offset, 39);
        assert!(
            raw_client_hello[fixture.session_id_offset..fixture.session_id_offset + 32]
                .iter()
                .all(|value| *value == 0)
        );
        assert_eq!(
            &raw_client_hello[fixture.key_share_x25519_public_key_offset
                ..fixture.key_share_x25519_public_key_offset + 32],
            key_share_public_key.as_slice()
        );
    }

    #[test]
    fn validator_accepts_clienthello_fixture() {
        let fixture = fixture();
        let prepared = prepared_from_fixture(&fixture);
        let validation = validate_reality_client_hello_metadata(&prepared).unwrap();

        assert_eq!(validation.session_id_offset, fixture.session_id_offset);
        assert_eq!(validation.key_share.group, expected_group(&fixture));
        assert_eq!(
            validation.key_share.offset,
            fixture.key_share_x25519_public_key_offset
        );
        assert_eq!(
            validation.key_share.public_key,
            decode_hex_array::<32>(&fixture.key_share_x25519_public_key_hex)
        );
    }

    #[test]
    fn validator_accepts_plain_x25519_key_share() {
        let (prepared, public_key_offset) = plain_x25519_prepared_client_hello();
        let validation = validate_reality_client_hello_metadata(&prepared).unwrap();

        assert_eq!(validation.session_id_offset, 39);
        assert_eq!(
            validation.key_share.group,
            RealityClientHelloKeyShareGroup::X25519
        );
        assert_eq!(validation.key_share.offset, public_key_offset);
        assert_eq!(
            validation.key_share.public_key,
            decode_hex_array::<32>(PLAIN_X25519_PUBLIC_KEY_HEX)
        );
    }

    #[test]
    fn validator_accepts_later_x25519_key_share_after_unsupported_group() {
        let key_shares = [
            (0x1234, vec![0xaa]),
            (
                TLS_GROUP_X25519,
                decode_hex_array::<32>(PLAIN_X25519_PUBLIC_KEY_HEX).to_vec(),
            ),
        ];
        let (prepared, key_exchange_offsets) = prepared_client_hello_with_key_shares(&key_shares);

        let validation = validate_reality_client_hello_metadata(&prepared).unwrap();

        assert_eq!(
            validation.key_share.group,
            RealityClientHelloKeyShareGroup::X25519
        );
        assert_eq!(validation.key_share.offset, key_exchange_offsets[1]);
    }

    #[test]
    fn validator_rejects_mismatched_hello_random() {
        let fixture = fixture();
        let mut prepared = prepared_from_fixture(&fixture);
        prepared.hello_random[0] ^= 0xff;

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert_eq!(err, RealityError::ClientHelloRandomMismatch);
    }

    #[test]
    fn validator_accepts_xray_core_fingerprint() {
        let fixture = fixture();
        let mut prepared = prepared_from_fixture(&fixture);
        prepared.fingerprint = "firefox".to_owned();

        validate_reality_client_hello_metadata(&prepared)
            .expect("known xray-core fingerprint should validate");
    }

    #[test]
    fn validator_rejects_unsupported_fingerprint() {
        let fixture = fixture();
        let mut prepared = prepared_from_fixture(&fixture);
        prepared.fingerprint = "madeup-browser".to_owned();

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert_eq!(
            err,
            RealityError::UnsupportedRealityFingerprint("madeup-browser".to_owned())
        );
    }

    #[test]
    fn validator_rejects_incorrect_session_id_offset() {
        let fixture = fixture();
        let mut prepared = prepared_from_fixture(&fixture);
        prepared.session_id_offset += 1;

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert_eq!(
            err,
            RealityError::ClientHelloSessionIdOffsetMismatch {
                expected: fixture.session_id_offset,
                actual: fixture.session_id_offset + 1,
            }
        );
    }

    #[test]
    fn validator_rejects_missing_session_id() {
        let fixture = fixture();
        let mut prepared = prepared_from_fixture(&fixture);
        prepared.raw_client_hello[38] = 31;

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert_eq!(err, RealityError::MissingClientHelloSessionId);
    }

    #[test]
    fn validator_rejects_mismatched_local_private_key() {
        let fixture = fixture();
        let mut prepared = prepared_from_fixture(&fixture);
        prepared.local_x25519_private_key[0] ^= 0x80;

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert_eq!(err, RealityError::ClientHelloKeyShareMismatch);
    }

    #[test]
    fn validator_rejects_missing_x25519_key_share() {
        let (mut prepared, public_key_offset) = plain_x25519_prepared_client_hello();
        let group_offset = public_key_offset - 4;
        prepared.raw_client_hello[group_offset..group_offset + 2].copy_from_slice(&[0x12, 0x34]);

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert_eq!(err, RealityError::MissingClientHelloX25519KeyShare);
    }

    #[test]
    fn validator_rejects_hybrid_key_share_with_invalid_length() {
        let mut key_exchange = vec![0u8; 1217 - 32];
        key_exchange.extend_from_slice(&decode_hex_array::<32>(PLAIN_X25519_PUBLIC_KEY_HEX));
        let key_shares = [(TLS_GROUP_X25519_MLKEM768, key_exchange)];
        let (prepared, _) = prepared_client_hello_with_key_shares(&key_shares);

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert!(matches!(
            err,
            RealityError::InvalidClientHello {
                reason: "invalid X25519MLKEM768 key-share length"
            }
        ));
    }

    #[test]
    fn validator_rejects_truncated_clienthello() {
        let fixture = fixture();
        let mut prepared = prepared_from_fixture(&fixture);
        prepared.raw_client_hello.truncate(12);

        let err = validate_reality_client_hello_metadata(&prepared).unwrap_err();

        assert!(matches!(err, RealityError::InvalidClientHello { .. }));
    }

    #[test]
    fn prepare_reality_handshake_accepts_validated_fixture_and_patches_session_id() {
        let fixture = fixture();
        let prepared = prepared_from_fixture(&fixture);
        validate_reality_client_hello_metadata(&prepared).unwrap();

        let session_id_offset = prepared.session_id_offset;
        let original_client_hello = prepared.raw_client_hello.clone();
        let result = prepare_reality_handshake(RealityHandshakeInput {
            version: [0x00, 0x01, 0x02],
            unix_time: 0x0102_0304,
            short_id: vec![0xaa, 0xbb, 0xcc],
            server_public_key: decode_hex_array(SERVER_PUBLIC_KEY_HEX),
            prepared_client_hello: prepared,
        })
        .unwrap();

        assert_eq!(result.patched_client_hello[0], 0x01);
        assert_eq!(
            &result.patched_client_hello[..session_id_offset],
            &original_client_hello[..session_id_offset]
        );
        assert_ne!(
            &result.patched_client_hello[session_id_offset..session_id_offset + 32],
            [0u8; 32].as_slice()
        );
        assert_eq!(
            result.session_id.as_slice(),
            &result.patched_client_hello[session_id_offset..session_id_offset + 32]
        );
        assert_eq!(
            &result.patched_client_hello[session_id_offset + 32..],
            &original_client_hello[session_id_offset + 32..]
        );
    }
}
