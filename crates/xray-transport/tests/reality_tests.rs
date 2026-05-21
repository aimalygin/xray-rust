mod reality_tests {
    use serde::Deserialize;
    use xray_transport::reality::{build_reality_session_id, RealityError, RealitySessionIdInput};

    const SESSION_ID_VECTORS_JSON: &str =
        include_str!("../../../tests/fixtures/reality/session_id_vectors.json");

    #[derive(Debug, Deserialize)]
    struct SessionIdVector {
        #[allow(dead_code)]
        name: String,
        version_hex: String,
        unix_time: u32,
        short_id_hex: String,
        shared_secret_hex: String,
        hello_random_hex: String,
        #[allow(dead_code)]
        session_id_offset: usize,
        raw_client_hello_before_hex: String,
        expected_session_id_hex: String,
        #[allow(dead_code)]
        expected_client_hello_after_hex: String,
    }

    fn session_id_vectors() -> Vec<SessionIdVector> {
        serde_json::from_str(SESSION_ID_VECTORS_JSON).unwrap()
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex string length must be even");

        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = decode_hex(hex);
        bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| {
            panic!("expected {N} bytes, got {}", bytes.len());
        })
    }

    fn input_from_vector(vector: &SessionIdVector) -> RealitySessionIdInput {
        RealitySessionIdInput {
            version: decode_hex_array(&vector.version_hex),
            unix_time: vector.unix_time,
            short_id: decode_hex(&vector.short_id_hex),
            shared_secret: decode_hex_array(&vector.shared_secret_hex),
            hello_random: decode_hex_array(&vector.hello_random_hex),
        }
    }

    #[test]
    fn reality_session_id_matches_oracle_vectors() {
        for vector in session_id_vectors() {
            let input = input_from_vector(&vector);
            let raw_client_hello_before_seal = decode_hex(&vector.raw_client_hello_before_hex);
            let expected_session_id = decode_hex_array(&vector.expected_session_id_hex);

            let session_id =
                build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap();

            assert_eq!(session_id, expected_session_id, "{}", vector.name);
        }
    }

    #[test]
    fn reality_session_id_changes_when_aad_changes() {
        let vector = session_id_vectors().remove(0);
        let input = input_from_vector(&vector);
        let mut raw_client_hello_before_seal = decode_hex(&vector.raw_client_hello_before_hex);
        let baseline = build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap();

        raw_client_hello_before_seal.push(0xff);
        let changed = build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap();

        assert_ne!(baseline, changed);
    }

    #[test]
    fn reality_session_id_changes_when_nonce_changes() {
        let vector = session_id_vectors().remove(0);
        let mut input = input_from_vector(&vector);
        let raw_client_hello_before_seal = decode_hex(&vector.raw_client_hello_before_hex);
        let baseline = build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap();

        input.hello_random[20] ^= 0xff;
        let changed = build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap();

        assert_ne!(baseline, changed);
    }

    #[test]
    fn reality_short_id_lengths_zero_and_eight_are_accepted() {
        let vector = session_id_vectors().remove(0);
        let mut input = input_from_vector(&vector);
        let raw_client_hello_before_seal = decode_hex(&vector.raw_client_hello_before_hex);

        input.short_id.clear();
        build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap();

        input.short_id = vec![0, 1, 2, 3, 4, 5, 6, 7];
        build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap();
    }

    #[test]
    fn reality_short_id_longer_than_eight_is_rejected() {
        let vector = session_id_vectors().remove(0);
        let mut input = input_from_vector(&vector);
        input.short_id = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let raw_client_hello_before_seal = decode_hex(&vector.raw_client_hello_before_hex);

        let err = build_reality_session_id(&input, &raw_client_hello_before_seal).unwrap_err();

        assert_eq!(err, RealityError::ShortIdTooLong);
    }

    #[test]
    fn reality_session_id_input_debug_redacts_secret_fields() {
        let input = RealitySessionIdInput {
            version: [1, 2, 3],
            unix_time: 42,
            short_id: vec![4, 5, 6],
            shared_secret: [0xab; 32],
            hello_random: [0xcd; 32],
        };

        let debug = format!("{input:?}");

        assert!(debug.contains("version: [1, 2, 3]"));
        assert!(debug.contains("unix_time: 42"));
        assert!(debug.contains("short_id: [4, 5, 6]"));
        assert!(debug.contains("shared_secret: \"<redacted>\""));
        assert!(debug.contains("hello_random: \"<redacted>\""));
        assert!(!debug.contains("171, 171, 171, 171"));
        assert!(!debug.contains("205, 205, 205, 205"));
    }
}
