mod reality_tests {
    use hmac::{Hmac, Mac};
    use rcgen::generate_simple_self_signed;
    use serde::Deserialize;
    use sha2::Sha512;
    use xray_transport::reality::{
        build_reality_session_id, seal_reality_client_hello, verify_reality_certificate_binding,
        verify_reality_certificate_der, RealityCertificateInput, RealityCertificateVerification,
        RealityClientHelloPatch, RealityError, RealitySessionIdInput,
    };

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

    type HmacSha512 = Hmac<Sha512>;

    fn reality_certificate_signature(
        auth_key: &[u8; 32],
        ed25519_public_key: &[u8; 32],
    ) -> [u8; 64] {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(auth_key).unwrap();
        mac.update(ed25519_public_key);
        mac.finalize().into_bytes().into()
    }

    fn push_der_length(out: &mut Vec<u8>, len: usize) {
        match len {
            0..=127 => out.push(len as u8),
            128..=255 => {
                out.push(0x81);
                out.push(len as u8);
            }
            _ => panic!("test DER helper only supports lengths up to 255 bytes"),
        }
    }

    fn push_der_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
        out.push(tag);
        push_der_length(out, content.len());
        out.extend_from_slice(content);
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_der_tlv(&mut out, tag, content);
        out
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        der_tlv(0x30, content)
    }

    fn der_bit_string(unused_bits: u8, bytes: &[u8]) -> Vec<u8> {
        let mut content = Vec::with_capacity(bytes.len() + 1);
        content.push(unused_bits);
        content.extend_from_slice(bytes);
        der_tlv(0x03, &content)
    }

    fn der_utc_time(value: &[u8; 13]) -> Vec<u8> {
        der_tlv(0x17, value)
    }

    fn ed25519_algorithm_identifier() -> Vec<u8> {
        vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
    }

    fn ed25519_algorithm_identifier_with_null_params() -> Vec<u8> {
        vec![0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00]
    }

    fn ed25519_leaf_der(public_key: &[u8], signature: &[u8]) -> Vec<u8> {
        ed25519_leaf_der_with_options(
            public_key,
            0,
            signature,
            0,
            &ed25519_algorithm_identifier(),
            &ed25519_algorithm_identifier(),
        )
    }

    fn ed25519_leaf_der_with_options(
        public_key: &[u8],
        public_key_unused_bits: u8,
        signature: &[u8],
        signature_unused_bits: u8,
        spki_algorithm: &[u8],
        signature_algorithm: &[u8],
    ) -> Vec<u8> {
        let algorithm = ed25519_algorithm_identifier();

        let mut validity_content = Vec::new();
        validity_content.extend_from_slice(&der_utc_time(b"250101000000Z"));
        validity_content.extend_from_slice(&der_utc_time(b"260101000000Z"));
        let validity = der_sequence(&validity_content);

        let mut spki_content = Vec::new();
        spki_content.extend_from_slice(spki_algorithm);
        spki_content.extend_from_slice(&der_bit_string(public_key_unused_bits, public_key));
        let spki = der_sequence(&spki_content);

        let mut tbs_content = Vec::new();
        tbs_content.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
        tbs_content.extend_from_slice(&[0x02, 0x01, 0x01]);
        tbs_content.extend_from_slice(&algorithm);
        tbs_content.extend_from_slice(&[0x30, 0x00]);
        tbs_content.extend_from_slice(&validity);
        tbs_content.extend_from_slice(&[0x30, 0x00]);
        tbs_content.extend_from_slice(&spki);
        let tbs = der_sequence(&tbs_content);

        let mut cert_content = Vec::new();
        cert_content.extend_from_slice(&tbs);
        cert_content.extend_from_slice(signature_algorithm);
        cert_content.extend_from_slice(&der_bit_string(signature_unused_bits, signature));
        der_sequence(&cert_content)
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
    fn reality_client_hello_patch_matches_oracle_vectors() {
        for vector in session_id_vectors() {
            let input = input_from_vector(&vector);
            let patch = RealityClientHelloPatch {
                session_id_offset: vector.session_id_offset,
            };
            let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
            let expected_session_id = decode_hex_array(&vector.expected_session_id_hex);
            let expected_client_hello_after = decode_hex(&vector.expected_client_hello_after_hex);

            let session_id =
                seal_reality_client_hello(&input, patch, &mut raw_client_hello).unwrap();

            assert_eq!(session_id, expected_session_id, "{}", vector.name);
            assert_eq!(
                raw_client_hello, expected_client_hello_after,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn reality_client_hello_patch_zeroes_session_id_before_sealing() {
        let vector = session_id_vectors().remove(0);
        let input = input_from_vector(&vector);
        let patch = RealityClientHelloPatch {
            session_id_offset: vector.session_id_offset,
        };
        let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let end = vector.session_id_offset + 32;
        raw_client_hello[vector.session_id_offset..end].fill(0xa5);
        let expected_session_id = decode_hex_array(&vector.expected_session_id_hex);
        let expected_client_hello_after = decode_hex(&vector.expected_client_hello_after_hex);

        let session_id = seal_reality_client_hello(&input, patch, &mut raw_client_hello).unwrap();

        assert_eq!(session_id, expected_session_id);
        assert_eq!(raw_client_hello, expected_client_hello_after);
    }

    #[test]
    fn reality_client_hello_patch_rejects_invalid_offsets() {
        let vector = session_id_vectors().remove(0);
        let input = input_from_vector(&vector);
        let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let original_client_hello = raw_client_hello.clone();
        let len = raw_client_hello.len();

        let err = seal_reality_client_hello(
            &input,
            RealityClientHelloPatch {
                session_id_offset: len - 31,
            },
            &mut raw_client_hello,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RealityError::InvalidSessionIdRange {
                offset: len - 31,
                end: len + 1,
                len
            }
        );
        assert_eq!(raw_client_hello, original_client_hello);

        let err = seal_reality_client_hello(
            &input,
            RealityClientHelloPatch {
                session_id_offset: usize::MAX,
            },
            &mut raw_client_hello,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RealityError::InvalidSessionIdRange {
                offset: usize::MAX,
                end: usize::MAX,
                len
            }
        );
        assert_eq!(raw_client_hello, original_client_hello);
    }

    #[test]
    fn reality_client_hello_patch_rejects_long_short_id_without_mutating() {
        let vector = session_id_vectors().remove(0);
        let mut input = input_from_vector(&vector);
        input.short_id = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let patch = RealityClientHelloPatch {
            session_id_offset: vector.session_id_offset,
        };
        let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let end = vector.session_id_offset + 32;
        raw_client_hello[vector.session_id_offset..end].fill(0xa5);
        let original_client_hello = raw_client_hello.clone();

        let err = seal_reality_client_hello(&input, patch, &mut raw_client_hello).unwrap_err();

        assert_eq!(err, RealityError::ShortIdTooLong);
        assert_eq!(raw_client_hello, original_client_hello);
    }

    #[test]
    fn reality_client_hello_patch_accepts_exact_boundary_offset() {
        let vector = session_id_vectors().remove(0);
        let input = input_from_vector(&vector);
        let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        raw_client_hello.resize(vector.session_id_offset + 32, 0);
        let patch = RealityClientHelloPatch {
            session_id_offset: raw_client_hello.len() - 32,
        };
        let mut expected_client_hello_after = raw_client_hello.clone();
        expected_client_hello_after[vector.session_id_offset..].fill(0);
        let expected_session_id =
            build_reality_session_id(&input, &expected_client_hello_after).unwrap();
        expected_client_hello_after[vector.session_id_offset..]
            .copy_from_slice(&expected_session_id);

        let session_id = seal_reality_client_hello(&input, patch, &mut raw_client_hello).unwrap();

        assert_eq!(session_id, expected_session_id);
        assert_eq!(raw_client_hello, expected_client_hello_after);
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
        assert!(debug.contains("short_id: \"<redacted>\""));
        assert!(debug.contains("shared_secret: \"<redacted>\""));
        assert!(debug.contains("hello_random: \"<redacted>\""));
        assert!(!debug.contains("short_id: [4, 5, 6]"));
        assert!(!debug.contains("171, 171, 171, 171"));
        assert!(!debug.contains("205, 205, 205, 205"));
    }

    #[test]
    fn reality_certificate_binding_verifies_hmac_signature() {
        let auth_key = [0x11; 32];
        let public_key = [0x22; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);

        let result = verify_reality_certificate_binding(RealityCertificateInput {
            auth_key: &auth_key,
            ed25519_public_key: &public_key,
            certificate_signature: &signature,
        });

        assert_eq!(result, RealityCertificateVerification::Verified);
    }

    #[test]
    fn reality_certificate_binding_rejects_changed_signature() {
        let auth_key = [0x11; 32];
        let public_key = [0x22; 32];
        let mut signature = reality_certificate_signature(&auth_key, &public_key);
        signature[0] ^= 0xff;

        let result = verify_reality_certificate_binding(RealityCertificateInput {
            auth_key: &auth_key,
            ed25519_public_key: &public_key,
            certificate_signature: &signature,
        });

        assert_eq!(result, RealityCertificateVerification::NotReality);
    }

    #[test]
    fn reality_certificate_binding_rejects_changed_public_key() {
        let auth_key = [0x11; 32];
        let public_key = [0x22; 32];
        let changed_public_key = [0x23; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);

        let result = verify_reality_certificate_binding(RealityCertificateInput {
            auth_key: &auth_key,
            ed25519_public_key: &changed_public_key,
            certificate_signature: &signature,
        });

        assert_eq!(result, RealityCertificateVerification::NotReality);
    }

    #[test]
    fn reality_certificate_input_debug_redacts_secret_fields() {
        let auth_key = [0xab; 32];
        let public_key = [0xcd; 32];
        let signature = [0xef; 64];
        let input = RealityCertificateInput {
            auth_key: &auth_key,
            ed25519_public_key: &public_key,
            certificate_signature: &signature,
        };

        let debug = format!("{input:?}");

        assert!(debug.contains("auth_key: \"<redacted>\""));
        assert!(debug.contains("ed25519_public_key: \"<redacted>\""));
        assert!(debug.contains("certificate_signature: \"<redacted>\""));
        assert!(!debug.contains("171, 171, 171, 171"));
        assert!(!debug.contains("205, 205, 205, 205"));
        assert!(!debug.contains("239, 239, 239, 239"));
    }

    #[test]
    fn reality_certificate_der_adapter_verifies_ed25519_hmac_fixture() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);
        let leaf_der = ed25519_leaf_der(&public_key, &signature);

        let result = verify_reality_certificate_der(&auth_key, &leaf_der).unwrap();

        assert_eq!(result, RealityCertificateVerification::Verified);
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_mismatched_signature() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 32];
        let wrong_signature = [0x55; 64];
        let leaf_der = ed25519_leaf_der(&public_key, &wrong_signature);

        let result = verify_reality_certificate_der(&auth_key, &leaf_der).unwrap();

        assert_eq!(result, RealityCertificateVerification::NotReality);
    }

    #[test]
    fn reality_certificate_der_adapter_returns_not_reality_for_non_ed25519_leaf() {
        let auth_key = [0x31; 32];
        let cert = generate_simple_self_signed(vec!["example.test".to_owned()])
            .expect("generate non-Ed25519 certificate");

        let result = verify_reality_certificate_der(&auth_key, cert.cert.der().as_ref()).unwrap();

        assert_eq!(result, RealityCertificateVerification::NotReality);
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_malformed_der() {
        let auth_key = [0x31; 32];

        let err = verify_reality_certificate_der(&auth_key, &[0x30, 0x03, 0x02])
            .expect_err("malformed DER should fail");

        assert_eq!(err, RealityError::InvalidRealityCertificateDer);
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_trailing_der_bytes() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);
        let mut leaf_der = ed25519_leaf_der(&public_key, &signature);
        leaf_der.push(0x00);

        let err = verify_reality_certificate_der(&auth_key, &leaf_der)
            .expect_err("trailing DER bytes should fail");

        assert_eq!(err, RealityError::InvalidRealityCertificateDer);
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_invalid_ed25519_key_length() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 31];
        let signature = [0x55; 64];
        let leaf_der = ed25519_leaf_der(&public_key, &signature);

        let err = verify_reality_certificate_der(&auth_key, &leaf_der)
            .expect_err("invalid Ed25519 public key length should fail");

        assert_eq!(
            err,
            RealityError::InvalidRealityCertificatePublicKey { len: 31 }
        );
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_public_key_bit_string_unused_bits() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);
        let algorithm = ed25519_algorithm_identifier();
        let leaf_der =
            ed25519_leaf_der_with_options(&public_key, 1, &signature, 0, &algorithm, &algorithm);

        let err = verify_reality_certificate_der(&auth_key, &leaf_der)
            .expect_err("public key unused bits should fail");

        assert_eq!(err, RealityError::InvalidRealityCertificateBitString);
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_spki_ed25519_null_params() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);
        let algorithm = ed25519_algorithm_identifier();
        let algorithm_with_null_params = ed25519_algorithm_identifier_with_null_params();
        let leaf_der = ed25519_leaf_der_with_options(
            &public_key,
            0,
            &signature,
            0,
            &algorithm_with_null_params,
            &algorithm,
        );

        let err = verify_reality_certificate_der(&auth_key, &leaf_der)
            .expect_err("SPKI Ed25519 NULL params should fail");

        assert_eq!(err, RealityError::InvalidRealityCertificateDer);
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_signature_algorithm_ed25519_null_params() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);
        let algorithm = ed25519_algorithm_identifier();
        let algorithm_with_null_params = ed25519_algorithm_identifier_with_null_params();
        let leaf_der = ed25519_leaf_der_with_options(
            &public_key,
            0,
            &signature,
            0,
            &algorithm,
            &algorithm_with_null_params,
        );

        let err = verify_reality_certificate_der(&auth_key, &leaf_der)
            .expect_err("signature Ed25519 NULL params should fail");

        assert_eq!(err, RealityError::InvalidRealityCertificateDer);
    }

    #[test]
    fn reality_certificate_der_adapter_rejects_signature_bit_string_unused_bits() {
        let auth_key = [0x31; 32];
        let public_key = [0x42; 32];
        let mut signature = reality_certificate_signature(&auth_key, &public_key);
        signature[63] &= 0xfe;
        let algorithm = ed25519_algorithm_identifier();
        let leaf_der =
            ed25519_leaf_der_with_options(&public_key, 0, &signature, 1, &algorithm, &algorithm);

        let err = verify_reality_certificate_der(&auth_key, &leaf_der)
            .expect_err("signature unused bits should fail");

        assert_eq!(err, RealityError::InvalidRealityCertificateBitString);
    }
}
