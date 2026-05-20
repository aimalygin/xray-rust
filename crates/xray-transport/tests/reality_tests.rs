mod reality_tests {
    use xray_transport::reality::{build_reality_session_id, RealityHelloInput};

    fn deterministic_input() -> RealityHelloInput {
        RealityHelloInput {
            version: [26, 5, 9],
            unix_time: 1_700_000_000,
            short_id: vec![0x02, 0x03, 0x04, 0x05],
            shared_secret: [7u8; 32],
            hello_random_prefix: [9u8; 20],
            hello_random_suffix: [11u8; 12],
            hello_raw: vec![0x16, 0x03, 0x01, 0x00, 0x20],
        }
    }

    #[test]
    fn reality_session_id_is_sealed_with_hkdf_auth_key() {
        let input = deterministic_input();

        let sealed = build_reality_session_id(&input).unwrap();

        assert_eq!(sealed.len(), 32);
        assert_ne!(
            &sealed[..16],
            &[26, 5, 9, 0, 0x65, 0x53, 0xf1, 0x00, 2, 3, 4, 5, 0, 0, 0, 0]
        );
    }

    #[test]
    fn reality_session_id_is_deterministic_for_same_input() {
        let input = deterministic_input();

        let first = build_reality_session_id(&input).unwrap();
        let second = build_reality_session_id(&input).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn reality_session_id_changes_when_aad_or_nonce_changes() {
        let input = deterministic_input();
        let baseline = build_reality_session_id(&input).unwrap();

        let mut aad_changed = input.clone();
        aad_changed.hello_raw.push(0xff);
        let aad_sealed = build_reality_session_id(&aad_changed).unwrap();

        let mut nonce_changed = input;
        nonce_changed.hello_random_suffix[0] ^= 0xff;
        let nonce_sealed = build_reality_session_id(&nonce_changed).unwrap();

        assert_ne!(baseline, aad_sealed);
        assert_ne!(baseline, nonce_sealed);
    }

    #[test]
    fn reality_session_id_uses_only_first_eight_short_id_bytes() {
        let mut left = deterministic_input();
        left.short_id = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut right = deterministic_input();
        right.short_id = vec![1, 2, 3, 4, 5, 6, 7, 8, 10, 11];

        let left_sealed = build_reality_session_id(&left).unwrap();
        let right_sealed = build_reality_session_id(&right).unwrap();

        assert_eq!(left_sealed, right_sealed);
    }
}
