use std::{collections::BTreeSet, env, fmt::Write as _, fs, path::Path, process::Command};

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use xray_transport::{
    reality::{
        prepare_reality_handshake, validate_reality_client_hello_metadata, RealityHandshakeInput,
    },
    reality_connector::{RealityClientHelloRequest, RealityTlsSessionProvider},
    RustlsRealityTlsSessionProvider,
};

const TLS_GROUP_X25519: u16 = 0x001d;
const TLS_GROUP_SECP256R1: u16 = 0x0017;
const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const TLS_GROUP_X25519_MLKEM768_DRAFT: u16 = 0x6399;
const X25519_PUBLIC_KEY_LEN: usize = 32;
const CLIENTHELLO_SHAPE_HELLOCHROME_100_JSON: &str =
    include_str!("../../../tests/fixtures/reality/clienthello_shape_hellochrome_100.json");

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
struct ClientHelloShape {
    fingerprint: String,
    utls_id: String,
    server_name: String,
    handshake_length: usize,
    legacy_version: String,
    cipher_suites: Vec<String>,
    compression_methods: Vec<String>,
    extension_order: Vec<String>,
    extensions: Vec<ExtensionShape>,
    #[serde(default)]
    supported_versions: Vec<String>,
    #[serde(default)]
    supported_groups: Vec<String>,
    #[serde(default)]
    ec_point_formats: Vec<String>,
    #[serde(default)]
    signature_algorithms: Vec<String>,
    #[serde(default)]
    delegated_credentials_algorithms: Vec<String>,
    #[serde(default)]
    alpn_protocols: Vec<String>,
    #[serde(default)]
    key_shares: Vec<KeyShareShape>,
    #[serde(default)]
    psk_key_exchange_modes: Vec<String>,
    #[serde(default)]
    certificate_compression_algorithms: Vec<String>,
    record_size_limit: Option<String>,
    #[serde(default)]
    application_settings: Vec<ApplicationAlpsShape>,
    padding_length: Option<usize>,
    encrypted_client_hello_length: Option<usize>,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
struct ExtensionShape {
    r#type: String,
    length: usize,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
struct KeyShareShape {
    group: String,
    key_exchange_length: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KeySharePayload {
    group: u16,
    key_exchange: Vec<u8>,
}

/// Applies the one deliberate divergence from the uTLS shape oracle: suites
/// this build cannot negotiate are removed from the wire. BoringSSL padding
/// absorbs the shorter cipher vector when the profile carries it; otherwise
/// the handshake itself becomes shorter.
fn apply_provider_cipher_filter(shape: &mut ClientHelloShape) {
    let offers_tls13 = shape
        .supported_versions
        .iter()
        .any(|version| version == "0x0304");
    let supported = rustls::crypto::aws_lc_rs::default_provider()
        .cipher_suites
        .iter()
        .filter(|suite| {
            suite.version().version == rustls::ProtocolVersion::TLSv1_2
                || (offers_tls13 && suite.version().version == rustls::ProtocolVersion::TLSv1_3)
        })
        .map(|suite| format!("0x{:04x}", u16::from(suite.suite())))
        .collect::<BTreeSet<_>>();
    let before = shape.cipher_suites.len();
    shape
        .cipher_suites
        .retain(|suite| suite == "GREASE" || supported.contains(suite));
    let removed_bytes = (before - shape.cipher_suites.len()) * 2;
    if removed_bytes == 0 {
        return;
    }

    if let Some(padding_length) = shape.padding_length.as_mut() {
        *padding_length += removed_bytes;
        shape
            .extensions
            .iter_mut()
            .find(|extension| extension.r#type == "0x0015")
            .expect("a recorded padding length must have a padding extension")
            .length += removed_bytes;
    } else {
        shape.handshake_length -= removed_bytes;
    }
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
struct ApplicationAlpsShape {
    r#type: String,
    protocols: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
struct RawClientHelloOracle {
    fingerprint: String,
    utls_id: String,
    server_name: String,
    client_hello_hex: String,
}

#[test]
fn rustls_reality_provider_prepares_valid_zero_session_clienthello() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let session = provider
        .create_session(RealityClientHelloRequest {
            server_name: "www.example.com",
            fingerprint: "chrome",
        })
        .expect("chrome REALITY session should be created");
    let prepared = session
        .prepared_client_hello()
        .expect("prepared ClientHello should be available");
    let validation = validate_reality_client_hello_metadata(&prepared)
        .expect("prepared ClientHello should satisfy REALITY metadata contract");

    assert_eq!(prepared.fingerprint, "chrome");
    assert_eq!(prepared.session_id_offset, validation.session_id_offset);
    assert_eq!(
        &prepared.raw_client_hello[prepared.session_id_offset..prepared.session_id_offset + 32],
        &[0u8; 32]
    );
}

#[test]
fn rustls_reality_provider_prepares_xray_core_fingerprint_clienthello() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let session = provider
        .create_session(RealityClientHelloRequest {
            server_name: "www.example.com",
            fingerprint: "hellochrome_131",
        })
        .expect("known xray-core REALITY fingerprint should be created");
    let prepared = session
        .prepared_client_hello()
        .expect("prepared ClientHello should be available");
    let validation = validate_reality_client_hello_metadata(&prepared)
        .expect("prepared ClientHello should satisfy REALITY metadata contract");

    assert_eq!(prepared.fingerprint, "hellochrome_131");
    assert_eq!(prepared.session_id_offset, validation.session_id_offset);
}

#[test]
fn rustls_reality_provider_uses_real_hybrid_key_share_for_chrome() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let session = provider
        .create_session(RealityClientHelloRequest {
            server_name: "www.example.com",
            fingerprint: "chrome",
        })
        .expect("chrome REALITY session should be created");
    let prepared = session
        .prepared_client_hello()
        .expect("prepared ClientHello should be available");
    let key_exchange = key_share_payload(&prepared.raw_client_hello, TLS_GROUP_X25519_MLKEM768)
        .expect("chrome ClientHello should advertise X25519MLKEM768");

    assert!(key_exchange.len() > X25519_PUBLIC_KEY_LEN);
    let mlkem_public_key = &key_exchange[..key_exchange.len() - X25519_PUBLIC_KEY_LEN];
    assert!(
        mlkem_public_key.iter().any(|byte| *byte != 0),
        "X25519MLKEM768 key share must contain a real ML-KEM public key, not a zero placeholder"
    );
}

#[test]
fn rustls_reality_provider_uses_real_p256_alongside_fixed_x25519() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let session = provider
        .create_session(RealityClientHelloRequest {
            server_name: "www.example.com",
            fingerprint: "firefox",
        })
        .expect("Firefox REALITY session should be created");
    let prepared = session
        .prepared_client_hello()
        .expect("prepared ClientHello should be available");
    let p256 = key_share_payload(&prepared.raw_client_hello, TLS_GROUP_SECP256R1)
        .expect("Firefox ClientHello should advertise P-256");

    assert_eq!(p256.len(), 65);
    assert_eq!(p256[0], 0x04, "P-256 uses an uncompressed SEC1 point");
    assert!(
        p256[1..].iter().any(|byte| *byte != 0),
        "the P-256 share must be provider-generated, not a zero placeholder"
    );
}

#[test]
fn rustls_reality_provider_uses_prepared_x25519_material_for_all_reality_capable_fingerprints() {
    let provider = RustlsRealityTlsSessionProvider::new();

    for fingerprint in xray_utls::XRAY_REALITY_CAPABLE_FINGERPRINTS {
        let session = provider
            .create_session(RealityClientHelloRequest {
                server_name: "www.example.com",
                fingerprint,
            })
            .unwrap_or_else(|error| {
                panic!("{fingerprint}: REALITY session should be created: {error}")
            });
        let prepared = session
            .prepared_client_hello()
            .unwrap_or_else(|error| panic!("{fingerprint}: prepared ClientHello: {error}"));
        let expected_x25519_public_key = x25519_public_key(prepared.local_x25519_private_key);
        let key_shares = key_share_payloads(&prepared.raw_client_hello)
            .unwrap_or_else(|error| panic!("{fingerprint}: key_share payloads: {error}"));
        let mut x25519_compatible_shares = 0;

        for key_share in key_shares {
            match key_share.group {
                TLS_GROUP_X25519 => {
                    x25519_compatible_shares += 1;
                    assert_eq!(
                        key_share.key_exchange, expected_x25519_public_key,
                        "{fingerprint}: X25519 key share must use the prepared REALITY public key"
                    );
                }
                TLS_GROUP_X25519_MLKEM768 => {
                    x25519_compatible_shares += 1;
                    assert!(
                        key_share.key_exchange.len() > X25519_PUBLIC_KEY_LEN,
                        "{fingerprint}: X25519MLKEM768 key share must include ML-KEM and X25519 material"
                    );
                    let x25519_offset = key_share.key_exchange.len() - X25519_PUBLIC_KEY_LEN;
                    let (_mlkem_public_key, x25519_public_key) =
                        key_share.key_exchange.split_at(x25519_offset);
                    assert_eq!(
                        x25519_public_key, expected_x25519_public_key,
                        "{fingerprint}: X25519MLKEM768 key share must embed the prepared REALITY X25519 public key"
                    );
                }
                TLS_GROUP_X25519_MLKEM768_DRAFT => {
                    x25519_compatible_shares += 1;
                    assert!(
                        key_share.key_exchange.len() > X25519_PUBLIC_KEY_LEN,
                        "{fingerprint}: draft hybrid key share must include X25519 and Kyber material"
                    );
                    let (x25519_public_key, kyber_public_key) =
                        key_share.key_exchange.split_at(X25519_PUBLIC_KEY_LEN);
                    assert_eq!(
                        x25519_public_key,
                        expected_x25519_public_key,
                        "{fingerprint}: draft hybrid key share must embed the prepared REALITY X25519 public key before Kyber material"
                    );
                    assert!(
                        kyber_public_key.iter().any(|byte| *byte != 0),
                        "{fingerprint}: draft hybrid key share must contain real Kyber public key material, not a zero placeholder"
                    );
                }
                _ => {}
            }
        }

        assert!(
            x25519_compatible_shares > 0,
            "{fingerprint}: REALITY-capable fingerprint must have an X25519-compatible key share"
        );
    }
}

#[test]
fn rustls_reality_provider_matches_utls_hellochrome_100_shape_oracle() {
    let mut expected: ClientHelloShape =
        serde_json::from_str(CLIENTHELLO_SHAPE_HELLOCHROME_100_JSON)
            .expect("uTLS ClientHello shape fixture should decode");
    apply_provider_cipher_filter(&mut expected);
    let provider = RustlsRealityTlsSessionProvider::new();

    let session = provider
        .create_session(RealityClientHelloRequest {
            server_name: "example.com",
            fingerprint: "hellochrome_100",
        })
        .expect("hellochrome_100 REALITY session should be created");
    let prepared = session
        .prepared_client_hello()
        .expect("prepared ClientHello should be available");
    let actual = parse_client_hello_shape(
        "hellochrome_100",
        "Chrome-100",
        "example.com",
        &prepared.raw_client_hello,
    )
    .expect("rustls ClientHello shape should parse");

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "requires Go uTLS oracle; run while bringing xray-core fingerprints to parity"]
fn rustls_reality_provider_matches_utls_xray_fingerprints_in_order() {
    let provider = RustlsRealityTlsSessionProvider::new();

    for fingerprint in xray_utls::XRAY_REALITY_CAPABLE_FINGERPRINTS {
        if DRAWN_PER_PROCESS_FINGERPRINTS.contains(fingerprint) {
            // No fixed shape to compare: these resolve to a per-process draw
            // over Xray's ModernFingerprints, each of which this loop already
            // checks under its own name.
            continue;
        }

        let mut expected = utls_client_hello_shape_from_oracle(fingerprint);
        apply_provider_cipher_filter(&mut expected);
        let session = provider
            .create_session(RealityClientHelloRequest {
                server_name: "example.com",
                fingerprint,
            })
            .unwrap_or_else(|error| {
                panic!("{fingerprint}: REALITY session should be created: {error}")
            });
        let prepared = session
            .prepared_client_hello()
            .unwrap_or_else(|error| panic!("{fingerprint}: prepared ClientHello: {error}"));
        let actual = parse_client_hello_shape(
            fingerprint,
            &expected.utls_id,
            "example.com",
            &prepared.raw_client_hello,
        )
        .unwrap_or_else(|error| panic!("{fingerprint}: rustls ClientHello shape: {error}"));

        assert_eq!(actual, expected, "{fingerprint}");
    }
}

/// The fingerprints whose raw bytes are compared with the Go uTLS oracle, each
/// paired with the oracle output committed for it.
///
/// "Risky" is the shaping we would not trust a shape comparison to police:
/// normalised shape JSON records an extension as a type and a length, so any
/// divergence inside a body of the right length is invisible to it. ECH GREASE
/// spent from before v0.1.1 until this table existed emitting a zero-length
/// `enc` -- a body no ECH parser accepts -- at exactly the promised 186 bytes.
///
/// Reading committed fixtures rather than spawning `go run` is what lets these
/// tests run in the plain `cargo test --workspace` CI job instead of sitting
/// behind `#[ignore]`. The fixtures are held to the real thing from the other
/// side: `scripts/verify-oracle-fixtures.py` regenerates every one of them
/// against live uTLS in the `go-oracles` job, so neither half can drift alone.
const RISKY_FINGERPRINT_RAW_ORACLES: &[(&str, &str)] = &[
    (
        "chrome",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_chrome.json"),
    ),
    (
        "helloios_13",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_helloios_13.json"),
    ),
    (
        "hellochrome_120_pq",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_pq.json"),
    ),
    (
        "hello360_11_0",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hello360_11_0.json"),
    ),
    (
        "hellofirefox_63",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_63.json"),
    ),
    (
        "hellofirefox_65",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_65.json"),
    ),
    (
        "hellofirefox_99",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_99.json"),
    ),
    (
        "hellofirefox_102",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_102.json"),
    ),
    (
        "hellofirefox_105",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_105.json"),
    ),
    (
        "hellofirefox_120",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_120.json"),
    ),
    (
        "hellofirefox_auto",
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_auto.json"),
    ),
];

#[test]
fn rustls_reality_provider_raw_clienthello_matches_utls_oracle_for_risky_fingerprints() {
    let provider = RustlsRealityTlsSessionProvider::new();

    for (fingerprint, oracle) in RISKY_FINGERPRINT_RAW_ORACLES {
        let fingerprint = *fingerprint;
        let expected = utls_client_hello_raw_from_fixture(fingerprint, oracle);
        let session = provider
            .create_session(RealityClientHelloRequest {
                server_name: "example.com",
                fingerprint,
            })
            .unwrap_or_else(|error| {
                panic!("{fingerprint}: REALITY session should be created: {error}")
            });
        let prepared = session
            .prepared_client_hello()
            .unwrap_or_else(|error| panic!("{fingerprint}: prepared ClientHello: {error}"));

        let expected_raw = decode_hex(&expected.client_hello_hex)
            .unwrap_or_else(|error| panic!("{fingerprint}: Go raw hex decode: {error}"));
        assert_masked_client_hello_eq(fingerprint, &prepared.raw_client_hello, &expected_raw);
    }
}

#[test]
fn rustls_reality_provider_final_reality_clienthello_matches_utls_oracle_for_risky_fingerprints() {
    let provider = RustlsRealityTlsSessionProvider::new();
    let server_public_key = X25519PublicKey::from(&X25519StaticSecret::from([7u8; 32])).to_bytes();

    for (fingerprint, oracle) in RISKY_FINGERPRINT_RAW_ORACLES {
        let fingerprint = *fingerprint;
        let expected = utls_client_hello_raw_from_fixture(fingerprint, oracle);
        let expected_raw = decode_hex(&expected.client_hello_hex)
            .unwrap_or_else(|error| panic!("{fingerprint}: Go raw hex decode: {error}"));
        let session = provider
            .create_session(RealityClientHelloRequest {
                server_name: "example.com",
                fingerprint,
            })
            .unwrap_or_else(|error| {
                panic!("{fingerprint}: REALITY session should be created: {error}")
            });
        let prepared_client_hello = session
            .prepared_client_hello()
            .unwrap_or_else(|error| panic!("{fingerprint}: prepared ClientHello: {error}"));
        let prepared_handshake = prepare_reality_handshake(RealityHandshakeInput {
            version: [0, 0, 1],
            unix_time: 1_700_000_000,
            short_id: vec![0x12, 0x34],
            server_public_key,
            prepared_client_hello,
        })
        .unwrap_or_else(|error| panic!("{fingerprint}: prepare REALITY handshake: {error}"));

        assert_masked_client_hello_eq(
            fingerprint,
            &prepared_handshake.patched_client_hello,
            &expected_raw,
        );
    }
}

#[test]
#[ignore = "requires Go uTLS oracle; set XRAY_UTLS_REPORT_MD to write a Markdown report"]
fn rustls_reality_provider_reports_utls_xray_fingerprint_parity() {
    let results = collect_fingerprint_parity_results();
    let report = build_fingerprint_parity_report(&results);

    if let Ok(report_path) = env::var("XRAY_UTLS_REPORT_MD") {
        let report_path = workspace_root().join(report_path);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("failed to create {}: {error}", parent.display()));
        }
        fs::write(&report_path, &report)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", report_path.display()));
        println!("wrote {}", report_path.display());
    } else {
        println!("{report}");
    }

    assert_eq!(results.len(), xray_utls::XRAY_UTLS_FINGERPRINTS.len());
    assert!(
        results.iter().all(|result| !result.is_tooling_error()),
        "report includes oracle or rustls generation errors"
    );
    assert!(
        results.iter().all(|result| result.status() != "mismatch"),
        "report includes a fixed fingerprint whose provider-filtered shape differs from uTLS"
    );
}

#[test]
fn rustls_reality_provider_rejects_unknown_fingerprint() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let result = provider.create_session(RealityClientHelloRequest {
        server_name: "www.example.com",
        fingerprint: "madeup-browser",
    });

    assert!(matches!(
        result,
        Err(xray_transport::reality::RealityError::UnsupportedRealityFingerprint(fingerprint))
            if fingerprint == "madeup-browser"
    ));
}

#[test]
fn rustls_reality_provider_rejects_known_fingerprint_without_x25519_key_share() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let result = provider.create_session(RealityClientHelloRequest {
        server_name: "www.example.com",
        fingerprint: "hellochrome_58",
    });

    assert!(matches!(
        result,
        Err(
            xray_transport::reality::RealityError::RealityFingerprintNotRealityCapable(fingerprint)
        ) if fingerprint == "hellochrome_58"
    ));
}

fn utls_client_hello_shape_from_oracle(fingerprint: &str) -> ClientHelloShape {
    try_utls_client_hello_shape_from_oracle(fingerprint)
        .unwrap_or_else(|error| panic!("{fingerprint}: {error}"))
}

fn try_utls_client_hello_shape_from_oracle(fingerprint: &str) -> Result<ClientHelloShape, String> {
    let output = Command::new("go")
        .current_dir(workspace_root())
        .args([
            "run",
            // The repository's root `vendor/` contains a patched Rust crate,
            // not a Go module vendor tree. Keep the oracle on go.mod/go.sum
            // instead of letting Go mis-detect that directory.
            "-mod=readonly",
            "-tags",
            "reality_oracle_clienthello_shape",
            "./tools/reality-oracle/clienthello_shape.go",
            "-fingerprint",
            fingerprint,
        ])
        .output()
        .map_err(|error| format!("failed to run Go uTLS oracle: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "Go uTLS oracle failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("uTLS ClientHello shape JSON: {error}"))
}

/// Parses one committed `clienthello_shape.go -raw` fixture.
///
/// The fingerprint and SNI the fixture records are checked against the ones it
/// was looked up under, so a table entry pointing at the wrong file compares
/// two unrelated hellos loudly rather than quietly.
fn utls_client_hello_raw_from_fixture(fingerprint: &str, oracle: &str) -> RawClientHelloOracle {
    let oracle: RawClientHelloOracle = serde_json::from_str(oracle)
        .unwrap_or_else(|error| panic!("{fingerprint}: raw ClientHello fixture JSON: {error}"));

    assert_eq!(
        oracle.fingerprint, fingerprint,
        "raw ClientHello fixture records another fingerprint"
    );
    assert_eq!(
        oracle.server_name, "example.com",
        "{fingerprint}: raw ClientHello fixture records another SNI"
    );

    oracle
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err(format!("hex length is odd: {}", input.len()));
    }

    let mut out = Vec::with_capacity(input.len() / 2);
    for index in (0..input.len()).step_by(2) {
        let byte = u8::from_str_radix(&input[index..index + 2], 16)
            .map_err(|error| format!("invalid hex byte at {index}: {error}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn assert_masked_client_hello_eq(fingerprint: &str, actual: &[u8], expected: &[u8]) {
    let actual_ciphers = raw_client_hello_cipher_suites(actual)
        .unwrap_or_else(|error| panic!("{fingerprint}: parse actual cipher suites: {error}"));
    let expected_ciphers = raw_client_hello_cipher_suites(expected)
        .unwrap_or_else(|error| panic!("{fingerprint}: parse expected cipher suites: {error}"));
    let expected_offers_tls13 = raw_client_hello_offers_tls13(expected)
        .unwrap_or_else(|error| panic!("{fingerprint}: parse expected TLS versions: {error}"));
    let supported = rustls::crypto::aws_lc_rs::default_provider()
        .cipher_suites
        .iter()
        .filter(|suite| {
            suite.version().version == rustls::ProtocolVersion::TLSv1_2
                || (expected_offers_tls13
                    && suite.version().version == rustls::ProtocolVersion::TLSv1_3)
        })
        .map(|suite| u16::from(suite.suite()))
        .collect::<BTreeSet<_>>();
    let removed_cipher_bytes = expected_ciphers
        .len()
        .checked_sub(actual_ciphers.len())
        .and_then(|removed| removed.checked_mul(2))
        .expect("provider filtering cannot add cipher suites");
    let expected_ciphers = expected_ciphers
        .into_iter()
        .filter(|suite| is_grease(*suite) || supported.contains(suite))
        .collect::<Vec<_>>();
    assert_eq!(
        actual_ciphers, expected_ciphers,
        "{fingerprint}: provider-filtered cipher suite vector differs from the uTLS profile"
    );

    let actual_padding = raw_client_hello_padding(actual)
        .unwrap_or_else(|error| panic!("{fingerprint}: parse actual padding: {error}"));
    let expected_padding = raw_client_hello_padding(expected)
        .unwrap_or_else(|error| panic!("{fingerprint}: parse expected padding: {error}"));
    assert_eq!(
        actual_padding.is_some(),
        expected_padding.is_some(),
        "{fingerprint}: padding extension presence differs from uTLS"
    );
    if let (Some(actual_padding), Some(expected_padding)) = (actual_padding, expected_padding) {
        assert!(
            actual_padding.iter().all(|byte| *byte == 0),
            "{fingerprint}: provider padding contains a non-zero byte"
        );
        assert!(
            expected_padding.iter().all(|byte| *byte == 0),
            "{fingerprint}: committed uTLS padding contains a non-zero byte"
        );
        assert_eq!(
            actual_padding.len(),
            expected_padding.len() + removed_cipher_bytes,
            "{fingerprint}: padding did not absorb exactly the filtered cipher bytes"
        );
    }

    let actual_masked = canonical_client_hello_for_raw_oracle(actual)
        .unwrap_or_else(|error| panic!("{fingerprint}: canonicalize actual ClientHello: {error}"));
    let expected_masked = canonical_client_hello_for_raw_oracle(expected).unwrap_or_else(|error| {
        panic!("{fingerprint}: canonicalize expected ClientHello: {error}")
    });

    if actual_masked == expected_masked {
        return;
    }

    let difference = first_byte_difference(&actual_masked, &expected_masked)
        .map(|index| {
            format!(
                "byte {index}: actual 0x{:02x}, expected 0x{:02x}\nactual:   {}\nexpected: {}",
                actual_masked.get(index).copied().unwrap_or_default(),
                expected_masked.get(index).copied().unwrap_or_default(),
                hex_window(&actual_masked, index),
                hex_window(&expected_masked, index)
            )
        })
        .unwrap_or_else(|| {
            format!(
                "length differs: actual {}, expected {}",
                actual_masked.len(),
                expected_masked.len()
            )
        });

    panic!("{fingerprint}: masked raw ClientHello differs: {difference}");
}

/// Removes the two byte ranges whose lengths intentionally change when the
/// local rustls provider cannot negotiate every suite in a uTLS profile.
///
/// The cipher vector is asserted independently above. BoringSSL-style
/// profiles absorb its shorter wire length by growing their all-zero padding
/// payload. Padding presence, position, header and exact growth are asserted
/// independently too; only its already-checked payload is removed here.
/// Length fields are rewritten before removal, leaving a canonical
/// ClientHello in which every other byte, extension, and ordering decision
/// remains byte-exact.
fn canonical_client_hello_for_raw_oracle(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut canonical = masked_client_hello_for_raw_oracle(raw)?;
    let mut cursor = ByteCursor::new(raw);
    let handshake_type = cursor.read_u8("missing handshake type")?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }
    cursor.read_u24("missing handshake length")?;
    cursor.read_u16("missing legacy version")?;
    cursor.take(32, "missing ClientHello random")?;
    let session_id_len = cursor.read_u8("missing legacy session id length")?;
    cursor.take(session_id_len, "truncated legacy session id")?;

    let cipher_length_offset = cursor.offset;
    let cipher_bytes = cursor.read_u16("missing cipher suites length")?;
    if cipher_bytes % 2 != 0 {
        return Err(format!("cipher suites length is odd: {cipher_bytes}"));
    }
    let cipher_data_offset = cursor.offset;
    cursor.take(cipher_bytes, "truncated cipher suites")?;
    let cipher_data_end = cursor.offset;

    let compression_methods_len = cursor.read_u8("missing compression methods length")?;
    cursor.take(compression_methods_len, "truncated compression methods")?;
    let extensions_length_offset = cursor.offset;
    let extensions_len = cursor.read_u16("missing extensions length")?;
    let extensions_end = cursor.checked_end(extensions_len, "truncated extensions")?;
    if extensions_end != raw.len() {
        return Err(format!(
            "extensions length mismatch: ended at {extensions_end} expected raw length {}",
            raw.len()
        ));
    }

    let mut padding = None;
    while cursor.offset < extensions_end {
        let extension_type = cursor.read_u16("missing extension type")? as u16;
        let extension_length_offset = cursor.offset;
        let extension_len = cursor.read_u16("missing extension length")?;
        let extension_data_offset = cursor.offset;
        cursor.take(extension_len, "truncated extension data")?;
        if extension_type == 0x0015
            && padding
                .replace((
                    extension_length_offset,
                    extension_data_offset,
                    cursor.offset,
                ))
                .is_some()
        {
            return Err("ClientHello contains more than one padding extension".to_owned());
        }
    }

    let padding_bytes = padding.map_or(0, |(_, start, end)| end - start);
    let canonical_handshake_len = raw
        .len()
        .checked_sub(4 + cipher_bytes + padding_bytes)
        .ok_or_else(|| "canonical ClientHello length underflow".to_owned())?;
    let canonical_extensions_len = extensions_len
        .checked_sub(padding_bytes)
        .ok_or_else(|| "canonical extensions length underflow".to_owned())?;
    if canonical_handshake_len > 0x00ff_ffff || canonical_extensions_len > u16::MAX as usize {
        return Err("canonical ClientHello length does not fit its wire field".to_owned());
    }

    canonical[1] = ((canonical_handshake_len >> 16) & 0xff) as u8;
    canonical[2] = ((canonical_handshake_len >> 8) & 0xff) as u8;
    canonical[3] = (canonical_handshake_len & 0xff) as u8;
    canonical[cipher_length_offset..cipher_length_offset + 2].copy_from_slice(&[0, 0]);
    canonical[extensions_length_offset..extensions_length_offset + 2]
        .copy_from_slice(&(canonical_extensions_len as u16).to_be_bytes());
    if let Some((padding_length_offset, _, _)) = padding {
        canonical[padding_length_offset..padding_length_offset + 2].copy_from_slice(&[0, 0]);
    }

    let mut ranges = vec![(cipher_data_offset, cipher_data_end)];
    if let Some((_, padding_start, padding_end)) = padding {
        ranges.push((padding_start, padding_end));
    }
    ranges.sort_unstable_by_key(|(start, _)| *start);
    for (start, end) in ranges.into_iter().rev() {
        canonical.drain(start..end);
    }

    Ok(canonical)
}

fn raw_client_hello_cipher_suites(raw: &[u8]) -> Result<Vec<u16>, String> {
    let mut cursor = ByteCursor::new(raw);
    let handshake_type = cursor.read_u8("missing handshake type")?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }
    cursor.read_u24("missing handshake length")?;
    cursor.read_u16("missing legacy version")?;
    cursor.take(32, "missing ClientHello random")?;
    let session_id_len = cursor.read_u8("missing legacy session id length")?;
    cursor.take(session_id_len, "truncated legacy session id")?;
    cursor.read_u16_list("cipher suites")
}

fn raw_client_hello_offers_tls13(raw: &[u8]) -> Result<bool, String> {
    let Some(versions) = raw_client_hello_extension(raw, 0x002b)? else {
        return Ok(false);
    };
    let Some((&listed_len, listed)) = versions.split_first() else {
        return Err("supported_versions extension is empty".to_owned());
    };
    if listed_len as usize != listed.len() || listed.len() % 2 != 0 {
        return Err(format!(
            "supported_versions list length is invalid: header={listed_len} payload={}",
            listed.len()
        ));
    }
    Ok(listed.chunks_exact(2).any(|pair| pair == [0x03, 0x04]))
}

fn raw_client_hello_padding(raw: &[u8]) -> Result<Option<&[u8]>, String> {
    raw_client_hello_extension(raw, 0x0015)
}

fn raw_client_hello_extension(raw: &[u8], wanted: u16) -> Result<Option<&[u8]>, String> {
    let mut cursor = ByteCursor::new(raw);
    let handshake_type = cursor.read_u8("missing handshake type")?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }
    cursor.read_u24("missing handshake length")?;
    cursor.read_u16("missing legacy version")?;
    cursor.take(32, "missing ClientHello random")?;
    let session_id_len = cursor.read_u8("missing legacy session id length")?;
    cursor.take(session_id_len, "truncated legacy session id")?;
    cursor.read_u16_list("cipher suites")?;
    let compression_methods_len = cursor.read_u8("missing compression methods length")?;
    cursor.take(compression_methods_len, "truncated compression methods")?;
    let extensions_len = cursor.read_u16("missing extensions length")?;
    let extensions_end = cursor.checked_end(extensions_len, "truncated extensions")?;
    if extensions_end != raw.len() {
        return Err(format!(
            "extensions length mismatch: ended at {extensions_end} expected raw length {}",
            raw.len()
        ));
    }
    let mut found = None;
    while cursor.offset < extensions_end {
        let extension_type = cursor.read_u16("missing extension type")? as u16;
        let extension_len = cursor.read_u16("missing extension length")?;
        let payload = cursor.take(extension_len, "truncated extension data")?;
        if extension_type == wanted && found.replace(payload).is_some() {
            return Err(format!(
                "ClientHello contains more than one 0x{wanted:04x} extension"
            ));
        }
    }
    Ok(found)
}

fn masked_client_hello_for_raw_oracle(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut masked = raw.to_vec();
    let mut cursor = ByteCursor::new(raw);
    let handshake_type = cursor.read_u8("missing handshake type")?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }

    let handshake_len = cursor.read_u24("missing handshake length")?;
    if handshake_len != raw.len() - 4 {
        return Err(format!(
            "handshake length mismatch: header={handshake_len} raw={}",
            raw.len() - 4
        ));
    }

    cursor.read_u16("missing legacy version")?;
    let random_offset = cursor.offset;
    cursor.take(32, "missing ClientHello random")?;
    mask_range(&mut masked, random_offset, 32);

    let session_id_len = cursor.read_u8("missing legacy session id length")?;
    let session_id_offset = cursor.offset;
    cursor.take(session_id_len, "truncated legacy session id")?;
    mask_range(&mut masked, session_id_offset, session_id_len);

    cursor.read_u16_list("missing cipher suites")?;
    let compression_methods_len = cursor.read_u8("missing compression methods length")?;
    cursor.take(compression_methods_len, "truncated compression methods")?;
    let extensions_len = cursor.read_u16("missing extensions length")?;
    let extensions_end = cursor.checked_end(extensions_len, "truncated extensions")?;
    if extensions_end != raw.len() {
        return Err(format!(
            "extensions length mismatch: ended at {extensions_end} expected raw length {}",
            raw.len()
        ));
    }

    while cursor.offset < extensions_end {
        let extension_type = cursor.read_u16("missing extension type")? as u16;
        let extension_len = cursor.read_u16("missing extension length")?;
        let extension_data_offset = cursor.offset;
        cursor.take(extension_len, "truncated extension data")?;

        // Padding (0x0015) is deliberately absent: both sides zero fill it --
        // uTLS through `FakePaddingExtension`, rustls through `zero_padding`
        // -- so there is nothing per-connection to hide, and comparing it
        // keeps the BoringSSL pad-to-512 arithmetic under the same guard as
        // everything else. Seven of the eleven fingerprints below carry one.
        match extension_type {
            0x0033 => {
                mask_key_share_exchange_ranges(
                    raw,
                    extension_data_offset,
                    extension_len,
                    &mut masked,
                )?;
            }
            0xfe0d => {
                mask_encrypted_client_hello_random_ranges(
                    raw,
                    extension_data_offset,
                    extension_len,
                    &mut masked,
                )?;
            }
            value if is_grease(value) => {
                mask_range(&mut masked, extension_data_offset, extension_len);
            }
            _ => {}
        }
    }

    if cursor.offset != extensions_end {
        return Err(format!(
            "extensions length mismatch: ended at {} expected {extensions_end}",
            cursor.offset
        ));
    }

    Ok(masked)
}

fn mask_key_share_exchange_ranges(
    raw: &[u8],
    extension_data_offset: usize,
    extension_len: usize,
    masked: &mut [u8],
) -> Result<(), String> {
    let extension_end = extension_data_offset
        .checked_add(extension_len)
        .filter(|end| *end <= raw.len())
        .ok_or_else(|| {
            format!(
                "key_share extension range out of bounds: offset={extension_data_offset} len={extension_len} raw={}",
                raw.len()
            )
        })?;
    let mut cursor = ByteCursor::new(&raw[extension_data_offset..extension_end]);
    let shares_len = cursor.read_u16("missing key_share client_shares length")?;
    let shares_end = cursor.checked_end(shares_len, "truncated key_share client_shares")?;
    if shares_end != extension_len {
        return Err(format!(
            "key_share client_shares length mismatch: end={shares_end} len={extension_len}"
        ));
    }

    while cursor.offset < shares_end {
        cursor.read_u16("missing key_share group")?;
        let key_exchange_length = cursor.read_u16("missing key_exchange length")?;
        let key_exchange_offset = extension_data_offset + cursor.offset;
        cursor.take(key_exchange_length, "truncated key_exchange")?;
        mask_range(masked, key_exchange_offset, key_exchange_length);
    }

    Ok(())
}

/// Masks the three ECH GREASE fields uTLS redraws per connection, leaving the
/// structure around them to be compared byte for byte.
///
/// Blanking the whole extension instead -- which this used to do -- hides
/// everything that makes an outer ECH well formed: the `enc` length prefix in
/// particular, which spent several releases reading 0 with no key behind it
/// while the extension still measured the length the profile promised. What is
/// left comparable here is exactly what a DPI reading past the length header
/// sees: the outer type, the HPKE cipher suite, and the two length prefixes.
///
/// The Go oracle runs under a zeroed `crypto/rand`, so its config id is 0, its
/// key is the one X25519 point a zero seed derives, and its payload is zero
/// filled. None of those are what a real client sends, which is why they are
/// masked rather than compared.
fn mask_encrypted_client_hello_random_ranges(
    raw: &[u8],
    extension_data_offset: usize,
    extension_len: usize,
    masked: &mut [u8],
) -> Result<(), String> {
    let extension_end = extension_data_offset
        .checked_add(extension_len)
        .filter(|end| *end <= raw.len())
        .ok_or_else(|| {
            format!(
                "encrypted_client_hello extension range out of bounds: offset={extension_data_offset} len={extension_len} raw={}",
                raw.len()
            )
        })?;
    let mut cursor = ByteCursor::new(&raw[extension_data_offset..extension_end]);

    let client_hello_type = cursor.read_u8("missing ECHClientHello type")?;
    if client_hello_type != 0 {
        return Err(format!(
            "encrypted_client_hello is not an outer hello: type={client_hello_type}"
        ));
    }
    cursor.read_u16("missing ECH HPKE KDF id")?;

    // The AEAD id is masked, unlike the KDF id beside it, because uTLS draws it
    // per connection wherever a profile offers more than one: Firefox picks
    // between AES-128-GCM and ChaCha20-Poly1305, so this side legitimately
    // disagrees with the oracle half the time. The oracle runs under a zeroed
    // `crypto/rand` and so always records the first candidate, which means this
    // comparison could only ever pin one of the two -- it cannot see the draw at
    // all. `ech_grease_draws_every_candidate_aead` guards that instead.
    let aead_id_offset = extension_data_offset + cursor.offset;
    cursor.read_u16("missing ECH HPKE AEAD id")?;
    mask_range(masked, aead_id_offset, 2);

    let config_id_offset = extension_data_offset + cursor.offset;
    cursor.read_u8("missing ECH config id")?;
    mask_range(masked, config_id_offset, 1);

    let encapsulated_key_len = cursor.read_u16("missing ECH enc length")?;
    let encapsulated_key_offset = extension_data_offset + cursor.offset;
    cursor.take(encapsulated_key_len, "truncated ECH enc")?;
    mask_range(masked, encapsulated_key_offset, encapsulated_key_len);

    let payload_len = cursor.read_u16("missing ECH payload length")?;
    let payload_offset = extension_data_offset + cursor.offset;
    cursor.take(payload_len, "truncated ECH payload")?;
    mask_range(masked, payload_offset, payload_len);

    if cursor.offset != extension_len {
        return Err(format!(
            "encrypted_client_hello has {} trailing byte(s) after the payload",
            extension_len - cursor.offset
        ));
    }

    Ok(())
}

fn mask_range(raw: &mut [u8], offset: usize, len: usize) {
    for byte in &mut raw[offset..offset + len] {
        *byte = 0xa5;
    }
}

fn first_byte_difference(actual: &[u8], expected: &[u8]) -> Option<usize> {
    actual
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected)
        .or_else(|| (actual.len() != expected.len()).then_some(actual.len().min(expected.len())))
}

fn hex_window(raw: &[u8], index: usize) -> String {
    let start = index.saturating_sub(16);
    let end = (index + 17).min(raw.len());
    raw[start..end]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xray-transport should live under crates/")
}

struct FingerprintParityResult {
    fingerprint: &'static str,
    expected: Result<ClientHelloShape, String>,
    actual: Result<ClientHelloShape, String>,
}

/// Names that stand for a per-process draw over Xray's `ModernFingerprints`
/// rather than a fixed shape, so there is nothing for the oracle to compare
/// them against: the oracle answers `random` with `utls.HelloRandomized` under
/// a zeroed `crypto/rand`, which is neither what Xray's `init()` produces nor
/// what we produce. See `docs/config-compatibility.md`.
const DRAWN_PER_PROCESS_FINGERPRINTS: &[&str] = &["random", "randomized"];

impl FingerprintParityResult {
    fn status(&self) -> &'static str {
        if DRAWN_PER_PROCESS_FINGERPRINTS.contains(&self.fingerprint) {
            return "drawn-per-process";
        }

        match (&self.expected, &self.actual) {
            (Err(_), _) => "oracle-error",
            _ if !xray_utls::is_reality_fingerprint_supported(self.fingerprint) => {
                "not-reality-capable"
            }
            (Ok(expected), Ok(actual)) if expected == actual => "match",
            (Ok(_), Ok(_)) => "mismatch",
            (_, Err(_)) => "rustls-error",
        }
    }

    fn is_tooling_error(&self) -> bool {
        matches!(self.status(), "oracle-error" | "rustls-error")
    }

    fn utls_id(&self) -> &str {
        self.expected
            .as_ref()
            .map(|shape| shape.utls_id.as_str())
            .unwrap_or("n/a")
    }

    fn first_difference(&self) -> String {
        match (&self.expected, &self.actual) {
            (Ok(expected), Ok(actual)) if expected == actual => "none".to_owned(),
            (Ok(expected), Ok(actual)) => first_shape_difference(actual, expected),
            (Err(error), _) => one_line(error),
            (_, Err(error)) => one_line(error),
        }
    }
}

fn collect_fingerprint_parity_results() -> Vec<FingerprintParityResult> {
    let provider = RustlsRealityTlsSessionProvider::new();

    xray_utls::XRAY_UTLS_FINGERPRINTS
        .iter()
        .map(|&fingerprint| {
            let expected = try_utls_client_hello_shape_from_oracle(fingerprint).map(|mut shape| {
                apply_provider_cipher_filter(&mut shape);
                shape
            });
            let actual = if DRAWN_PER_PROCESS_FINGERPRINTS.contains(&fingerprint) {
                Err(
                    "skipped: resolved from a per-process draw over Xray's ModernFingerprints, so it has no fixed shape to compare"
                        .to_owned(),
                )
            } else if !xray_utls::is_reality_fingerprint_supported(fingerprint) {
                Err(
                    "skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share"
                        .to_owned(),
                )
            } else {
                match &expected {
                Ok(expected) => {
                    rustls_client_hello_shape(&provider, fingerprint, expected.utls_id.as_str())
                }
                Err(error) => Err(format!("skipped because oracle failed: {error}")),
                }
            };

            FingerprintParityResult {
                fingerprint,
                expected,
                actual,
            }
        })
        .collect()
}

fn rustls_client_hello_shape(
    provider: &RustlsRealityTlsSessionProvider,
    fingerprint: &str,
    utls_id: &str,
) -> Result<ClientHelloShape, String> {
    let session = provider
        .create_session(RealityClientHelloRequest {
            server_name: "example.com",
            fingerprint,
        })
        .map_err(|error| format!("REALITY session should be created: {error}"))?;
    let prepared = session
        .prepared_client_hello()
        .map_err(|error| format!("prepared ClientHello: {error}"))?;

    parse_client_hello_shape(
        fingerprint,
        utls_id,
        "example.com",
        &prepared.raw_client_hello,
    )
    .map_err(|error| format!("rustls ClientHello shape: {error}"))
}

fn build_fingerprint_parity_report(results: &[FingerprintParityResult]) -> String {
    let matches = results
        .iter()
        .filter(|result| result.status() == "match")
        .count();
    let mismatches = results
        .iter()
        .filter(|result| result.status() == "mismatch")
        .count();
    let oracle_errors = results
        .iter()
        .filter(|result| result.status() == "oracle-error")
        .count();
    let rustls_errors = results
        .iter()
        .filter(|result| result.status() == "rustls-error")
        .count();
    let not_reality_capable = results
        .iter()
        .filter(|result| result.status() == "not-reality-capable")
        .count();
    let drawn_per_process = results
        .iter()
        .filter(|result| result.status() == "drawn-per-process")
        .count();
    let mut report = String::new();

    writeln!(report, "# shaped-rustls uTLS Fingerprint Parity Report\n").unwrap();
    writeln!(
        report,
        "This report compares every fingerprint in `xray_utls::XRAY_UTLS_FINGERPRINTS` against the Go uTLS oracle used by xray-core-compatible REALITY tests.\n"
    )
    .unwrap();
    writeln!(report, "## What a `match` here does and does not mean\n").unwrap();
    writeln!(
        report,
        "Every row below compares normalised shape JSON, in which an extension is a type and a length. Anything wrong *inside* a body of the right length is a `match` here. ECH is the worked example: this report recorded `encrypted_client_hello_length: 186` and called it parity while the body underneath declared a zero-length `enc`, carried no X25519 key, and padded the remaining 176 bytes with zeroes -- a structure no ECH parser accepts and a DPI can pick out deterministically. It shipped that way from before v0.1.1.\n"
    )
    .unwrap();
    writeln!(
        report,
        "Byte-level agreement is a separate guard, and the one to reach for when a body's contents matter: `rustls_reality_provider_raw_clienthello_matches_utls_oracle_for_risky_fingerprints` compares whole ClientHellos against committed oracle output, masking only what uTLS redraws per connection, and runs in the ordinary `cargo test --workspace` CI job.\n"
    )
    .unwrap();
    writeln!(report, "## Reproduce\n").unwrap();
    writeln!(
        report,
        "```sh\nXRAY_UTLS_REPORT_MD=docs/shaped-rustls-utls-fingerprint-parity-report.md cargo test -p xray-transport --test reality_rustls_tests rustls_reality_provider_reports_utls_xray_fingerprint_parity -- --ignored --nocapture\n```\n"
    )
    .unwrap();
    writeln!(report, "## Summary\n").unwrap();
    writeln!(report, "- Total fingerprints: `{}`", results.len()).unwrap();
    writeln!(report, "- Matches: `{matches}`").unwrap();
    writeln!(report, "- Mismatches: `{mismatches}`").unwrap();
    writeln!(
        report,
        "- Not REALITY-capable fingerprints: `{not_reality_capable}`"
    )
    .unwrap();
    writeln!(
        report,
        "- Drawn per process (no fixed shape to compare): `{drawn_per_process}`"
    )
    .unwrap();
    writeln!(report, "- Go uTLS oracle errors: `{oracle_errors}`").unwrap();
    writeln!(report, "- Rust generation errors: `{rustls_errors}`\n").unwrap();
    writeln!(report, "## Agent Task\n").unwrap();
    writeln!(
        report,
        "- Work in the shaped-rustls fork, currently expected at `aimalygin/shaped-rustls` branch `xray/rustls-0.23.40`."
    )
    .unwrap();
    writeln!(
        report,
        "- Use this report as the current wire-parity oracle after applying xray-rust's deliberate provider-capability cipher filter to the uTLS expectation. Every other tracked field remains the shaped-rustls byte-shape oracle: advertised versions/groups, real key shares, exact extension payloads, duplicate signature algorithms, ALPS, ECH, and GREASE."
    )
    .unwrap();
    writeln!(
        report,
        "- Treat this as the regression oracle for shaped-rustls ClientHello shaping. All REALITY-capable rows should remain `match`; the TLS1.2-only rows should remain `not-reality-capable` in xray-rust."
    )
    .unwrap();
    writeln!(
        report,
        "- This is a byte-shape oracle only. It does not prove key-share cryptographic validity or REALITY prepare/complete ClientHello reproducibility; those must stay covered by dedicated runtime invariants."
    )
    .unwrap();
    writeln!(
        report,
        "- Acceptance criterion: rerun the reproduce command from this report and get all REALITY-capable provider-filtered fingerprints as `match`, `0` mismatches, `0` Go uTLS oracle errors, `0` Rust generation errors, and keep the known TLS1.2-only rows as `not-reality-capable`.\n"
    )
    .unwrap();
    writeln!(report, "## Current Findings\n").unwrap();
    writeln!(
        report,
        "- shaped-rustls now represents GREASE extension positions relative to the final non-GREASE extension order, including slots before padding and after the final real extension. xray-rust passes those positions through without the old workaround that compensated for previously inserted GREASE entries."
    )
    .unwrap();
    writeln!(
        report,
        "- All REALITY-capable xray-core/uTLS fingerprints currently match the provider-filtered Go uTLS byte-shape fields tracked by this report."
    )
    .unwrap();
    writeln!(
        report,
        "- xray-rust uses real rustls key shares for X25519, P-256, P-384, final `X25519MLKEM768`, and draft `X25519Kyber768Draft00`. `FixedX25519KeyShare` keeps REALITY's X25519 public key stable inside X25519 and both hybrid shares."
    )
    .unwrap();
    writeln!(
        report,
        "- Runtime REALITY completion uses shaped-rustls' ClientHello finalizer to seal the actual generated ClientHello before transcript/write. Dedicated tests assert nonzero final `X25519MLKEM768` ML-KEM material and finalizer-derived auth/session state; this report remains the byte-shape oracle."
    )
    .unwrap();
    writeln!(
        report,
        "- The `not-reality-capable` rows are TLS1.2-only uTLS fingerprints with no X25519-compatible key_share extension. That is not a shaped-rustls primitive gap: REALITY cannot derive the server-side shared secret without a ClientHello X25519 public key. xray-rust intentionally rejects these before ClientHello generation."
    )
    .unwrap();
    writeln!(
        report,
        "- If xray-rust decides to expose non-REALITY uTLS shaping later, those TLS1.2-only profiles should be tested outside the REALITY provider path."
    )
    .unwrap();
    writeln!(report).unwrap();
    writeln!(report, "## Per-Fingerprint Results\n").unwrap();
    writeln!(
        report,
        "| # | fingerprint | uTLS ID | status | first actionable difference |"
    )
    .unwrap();
    writeln!(report, "|---:|---|---|---|---|").unwrap();
    for (index, result) in results.iter().enumerate() {
        writeln!(
            report,
            "| {} | `{}` | `{}` | `{}` | {} |",
            index + 1,
            result.fingerprint,
            result.utls_id(),
            result.status(),
            markdown_cell(&result.first_difference())
        )
        .unwrap();
    }

    writeln!(report, "\n## Detailed Non-Match Rows").unwrap();
    for (index, result) in results
        .iter()
        .filter(|result| result.status() != "match")
        .enumerate()
    {
        writeln!(
            report,
            "\n### {}. `{}`\n\n- Status: `{}`\n- uTLS ID: `{}`\n- First actionable difference: {}\n",
            index + 1,
            result.fingerprint,
            result.status(),
            result.utls_id(),
            inline_code(&result.first_difference())
        )
        .unwrap();

        match (&result.expected, &result.actual) {
            (Ok(expected), Ok(actual)) => {
                writeln!(report, "Expected Go uTLS shape:\n").unwrap();
                report.push_str(&shape_markdown(expected));
                writeln!(report, "\nActual shaped-rustls shape:\n").unwrap();
                report.push_str(&shape_markdown(actual));
            }
            (Err(error), _) => {
                writeln!(report, "Go uTLS oracle error:\n\n```text\n{}\n```", error).unwrap();
            }
            (_, Err(error)) => {
                let heading = match result.status() {
                    "not-reality-capable" => "REALITY capability skip",
                    "drawn-per-process" => "Per-process draw skip",
                    _ => "Rust generation error",
                };
                writeln!(report, "{heading}:\n\n```text\n{}\n```", error).unwrap();
            }
        }
    }

    report
}

fn first_shape_difference(actual: &ClientHelloShape, expected: &ClientHelloShape) -> String {
    let comparisons = [
        (
            "cipher_suites",
            format_values(&actual.cipher_suites),
            format_values(&expected.cipher_suites),
        ),
        (
            "extension_order",
            format_values(&actual.extension_order),
            format_values(&expected.extension_order),
        ),
        (
            "extensions",
            format_extensions(&actual.extensions),
            format_extensions(&expected.extensions),
        ),
        (
            "supported_versions",
            format_values(&actual.supported_versions),
            format_values(&expected.supported_versions),
        ),
        (
            "supported_groups",
            format_values(&actual.supported_groups),
            format_values(&expected.supported_groups),
        ),
        (
            "ec_point_formats",
            format_values(&actual.ec_point_formats),
            format_values(&expected.ec_point_formats),
        ),
        (
            "signature_algorithms",
            format_values(&actual.signature_algorithms),
            format_values(&expected.signature_algorithms),
        ),
        (
            "delegated_credentials_algorithms",
            format_values(&actual.delegated_credentials_algorithms),
            format_values(&expected.delegated_credentials_algorithms),
        ),
        (
            "alpn_protocols",
            format_values(&actual.alpn_protocols),
            format_values(&expected.alpn_protocols),
        ),
        (
            "key_shares",
            format_key_shares(&actual.key_shares),
            format_key_shares(&expected.key_shares),
        ),
        (
            "psk_key_exchange_modes",
            format_values(&actual.psk_key_exchange_modes),
            format_values(&expected.psk_key_exchange_modes),
        ),
        (
            "certificate_compression_algorithms",
            format_values(&actual.certificate_compression_algorithms),
            format_values(&expected.certificate_compression_algorithms),
        ),
        (
            "record_size_limit",
            format_optional(&actual.record_size_limit),
            format_optional(&expected.record_size_limit),
        ),
        (
            "application_settings",
            format_application_settings(&actual.application_settings),
            format_application_settings(&expected.application_settings),
        ),
        (
            "padding_length",
            format_option_usize(actual.padding_length),
            format_option_usize(expected.padding_length),
        ),
        (
            "encrypted_client_hello_length",
            format_option_usize(actual.encrypted_client_hello_length),
            format_option_usize(expected.encrypted_client_hello_length),
        ),
        (
            "handshake_length",
            actual.handshake_length.to_string(),
            expected.handshake_length.to_string(),
        ),
        (
            "legacy_version",
            actual.legacy_version.clone(),
            expected.legacy_version.clone(),
        ),
        (
            "compression_methods",
            format_values(&actual.compression_methods),
            format_values(&expected.compression_methods),
        ),
    ];

    comparisons
        .into_iter()
        .find_map(|(field, actual, expected)| {
            (actual != expected).then(|| format!("{field}: actual {actual}, expected {expected}"))
        })
        .unwrap_or_else(|| "shape differs only in unreported fields".to_owned())
}

fn shape_markdown(shape: &ClientHelloShape) -> String {
    let mut out = String::new();
    writeln!(out, "- fingerprint: `{}`", shape.fingerprint).unwrap();
    writeln!(out, "- uTLS ID: `{}`", shape.utls_id).unwrap();
    writeln!(out, "- server_name: `{}`", shape.server_name).unwrap();
    writeln!(out, "- handshake_length: `{}`", shape.handshake_length).unwrap();
    writeln!(out, "- legacy_version: `{}`", shape.legacy_version).unwrap();
    writeln!(
        out,
        "- cipher_suites: `{}`",
        format_values(&shape.cipher_suites)
    )
    .unwrap();
    writeln!(
        out,
        "- compression_methods: `{}`",
        format_values(&shape.compression_methods)
    )
    .unwrap();
    writeln!(
        out,
        "- extension_order: `{}`",
        format_values(&shape.extension_order)
    )
    .unwrap();
    writeln!(
        out,
        "- extensions: `{}`",
        format_extensions(&shape.extensions)
    )
    .unwrap();
    writeln!(
        out,
        "- supported_versions: `{}`",
        format_values(&shape.supported_versions)
    )
    .unwrap();
    writeln!(
        out,
        "- supported_groups: `{}`",
        format_values(&shape.supported_groups)
    )
    .unwrap();
    writeln!(
        out,
        "- ec_point_formats: `{}`",
        format_values(&shape.ec_point_formats)
    )
    .unwrap();
    writeln!(
        out,
        "- signature_algorithms: `{}`",
        format_values(&shape.signature_algorithms)
    )
    .unwrap();
    writeln!(
        out,
        "- delegated_credentials_algorithms: `{}`",
        format_values(&shape.delegated_credentials_algorithms)
    )
    .unwrap();
    writeln!(
        out,
        "- alpn_protocols: `{}`",
        format_values(&shape.alpn_protocols)
    )
    .unwrap();
    writeln!(
        out,
        "- key_shares: `{}`",
        format_key_shares(&shape.key_shares)
    )
    .unwrap();
    writeln!(
        out,
        "- psk_key_exchange_modes: `{}`",
        format_values(&shape.psk_key_exchange_modes)
    )
    .unwrap();
    writeln!(
        out,
        "- certificate_compression_algorithms: `{}`",
        format_values(&shape.certificate_compression_algorithms)
    )
    .unwrap();
    writeln!(
        out,
        "- record_size_limit: `{}`",
        format_optional(&shape.record_size_limit)
    )
    .unwrap();
    writeln!(
        out,
        "- application_settings: `{}`",
        format_application_settings(&shape.application_settings)
    )
    .unwrap();
    writeln!(
        out,
        "- padding_length: `{}`",
        format_option_usize(shape.padding_length)
    )
    .unwrap();
    writeln!(
        out,
        "- encrypted_client_hello_length: `{}`",
        format_option_usize(shape.encrypted_client_hello_length)
    )
    .unwrap();
    out
}

fn format_values(values: &[String]) -> String {
    if values.is_empty() {
        "[]".to_owned()
    } else {
        format!("[{}]", values.join(", "))
    }
}

fn format_optional(value: &Option<String>) -> String {
    value.as_deref().unwrap_or("none").to_owned()
}

fn format_extensions(extensions: &[ExtensionShape]) -> String {
    if extensions.is_empty() {
        return "[]".to_owned();
    }

    let values = extensions
        .iter()
        .map(|extension| format!("{}:{}", extension.r#type, extension.length))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(", "))
}

fn format_key_shares(key_shares: &[KeyShareShape]) -> String {
    if key_shares.is_empty() {
        return "[]".to_owned();
    }

    let values = key_shares
        .iter()
        .map(|share| format!("{}:{}", share.group, share.key_exchange_length))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(", "))
}

fn format_application_settings(settings: &[ApplicationAlpsShape]) -> String {
    if settings.is_empty() {
        return "[]".to_owned();
    }

    let values = settings
        .iter()
        .map(|setting| format!("{}:[{}]", setting.r#type, setting.protocols.join(", ")))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(", "))
}

fn format_option_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn inline_code(value: &str) -> String {
    format!("`{}`", one_line(value).replace('`', "'"))
}

fn markdown_cell(value: &str) -> String {
    inline_code(&value.replace('|', "\\|"))
}

fn one_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_client_hello_shape(
    fingerprint: &str,
    utls_id: &str,
    server_name: &str,
    raw: &[u8],
) -> Result<ClientHelloShape, String> {
    let mut cursor = ByteCursor::new(raw);
    let handshake_type = cursor.read_u8("missing handshake type")?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }

    let handshake_len = cursor.read_u24("missing handshake length")?;
    if handshake_len != raw.len() - 4 {
        return Err(format!(
            "handshake length mismatch: header={handshake_len} raw={}",
            raw.len() - 4
        ));
    }

    let legacy_version = cursor.read_u16("missing legacy version")?;
    cursor.take(32, "missing ClientHello random")?;
    let session_id_len = cursor.read_u8("missing legacy session id length")?;
    cursor.take(session_id_len, "truncated legacy session id")?;
    let cipher_suites = cursor.read_u16_list("missing cipher suites")?;
    let compression_methods_len = cursor.read_u8("missing compression methods length")?;
    let compression_methods =
        cursor.take(compression_methods_len, "truncated compression methods")?;
    let extensions_len = cursor.read_u16("missing extensions length")?;
    let extensions_end = cursor.checked_end(extensions_len, "truncated extensions")?;
    if extensions_end != raw.len() {
        return Err(format!(
            "extensions length mismatch: ended at {extensions_end} expected raw length {}",
            raw.len()
        ));
    }

    let mut shape = ClientHelloShape {
        fingerprint: fingerprint.to_owned(),
        utls_id: utls_id.to_owned(),
        server_name: server_name.to_owned(),
        handshake_length: raw.len(),
        legacy_version: format_u16(legacy_version as u16),
        cipher_suites: format_u16s(&cipher_suites),
        compression_methods: format_u8s(compression_methods),
        extension_order: Vec::new(),
        extensions: Vec::new(),
        supported_versions: Vec::new(),
        supported_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        signature_algorithms: Vec::new(),
        delegated_credentials_algorithms: Vec::new(),
        alpn_protocols: Vec::new(),
        key_shares: Vec::new(),
        psk_key_exchange_modes: Vec::new(),
        certificate_compression_algorithms: Vec::new(),
        record_size_limit: None,
        application_settings: Vec::new(),
        padding_length: None,
        encrypted_client_hello_length: None,
    };

    while cursor.offset < extensions_end {
        let extension_type = cursor.read_u16("missing extension type")? as u16;
        let extension_len = cursor.read_u16("missing extension length")?;
        let extension_data = cursor.take(extension_len, "truncated extension data")?;
        let extension_type_label = format_u16(extension_type);
        shape.extension_order.push(extension_type_label.clone());
        shape.extensions.push(ExtensionShape {
            r#type: extension_type_label,
            length: extension_len,
        });

        parse_extension_shape(extension_type, extension_data, &mut shape)?;
    }

    Ok(shape)
}

fn parse_extension_shape(
    extension_type: u16,
    data: &[u8],
    shape: &mut ClientHelloShape,
) -> Result<(), String> {
    let mut cursor = ByteCursor::new(data);
    let parsed_payload = match extension_type {
        0x002b => {
            let values = cursor.read_u8_length_prefixed_u16_list("missing supported_versions")?;
            shape.supported_versions = format_u16s(&values);
            true
        }
        0x000a => {
            let values = cursor.read_u16_list("missing supported_groups")?;
            shape.supported_groups = format_u16s(&values);
            true
        }
        0x000b => {
            let values = cursor.read_u8_list("missing ec_point_formats")?;
            shape.ec_point_formats = format_u8s(&values);
            true
        }
        0x000d => {
            let values = cursor.read_u16_list("missing signature_algorithms")?;
            shape.signature_algorithms = format_u16s(&values);
            true
        }
        0x0022 => {
            let values = cursor.read_u16_list("missing delegated_credentials algorithms")?;
            shape.delegated_credentials_algorithms = format_u16s(&values);
            true
        }
        0x0010 => {
            shape.alpn_protocols = cursor.read_protocol_name_list("missing ALPN protocols")?;
            true
        }
        0x0033 => {
            shape.key_shares = parse_key_shares(data)?;
            false
        }
        0x002d => {
            let values = cursor.read_u8_list("missing psk_key_exchange_modes")?;
            shape.psk_key_exchange_modes = format_u8s(&values);
            true
        }
        0x001b => {
            let values = cursor
                .read_u8_length_prefixed_u16_list("missing compress_certificate algorithms")?;
            shape.certificate_compression_algorithms = format_u16s(&values);
            true
        }
        0x001c => {
            let value = cursor.read_u16("missing record_size_limit")? as u16;
            shape.record_size_limit = Some(format_u16(value));
            true
        }
        0x4469 | 0x44cd => {
            let protocols =
                cursor.read_protocol_name_list("missing application_settings protocols")?;
            shape.application_settings.push(ApplicationAlpsShape {
                r#type: format_u16(extension_type),
                protocols,
            });
            true
        }
        0x0015 => {
            shape.padding_length = Some(data.len());
            false
        }
        0xfe0d => {
            shape.encrypted_client_hello_length = Some(data.len());
            false
        }
        _ => false,
    };

    if parsed_payload && cursor.offset != data.len() {
        return Err(format!(
            "trailing extension data: parsed={} length={}",
            cursor.offset,
            data.len()
        ));
    }
    Ok(())
}

fn parse_key_shares(data: &[u8]) -> Result<Vec<KeyShareShape>, String> {
    let mut cursor = ByteCursor::new(data);
    let shares_len = cursor.read_u16("missing key_share client_shares length")?;
    let shares_end = cursor.checked_end(shares_len, "truncated key_share client_shares")?;
    if shares_end != data.len() {
        return Err(format!(
            "key_share client_shares length mismatch: end={shares_end} len={}",
            data.len()
        ));
    }

    let mut shares = Vec::new();
    while cursor.offset < shares_end {
        let group = cursor.read_u16("missing key_share group")? as u16;
        let key_exchange_length = cursor.read_u16("missing key_exchange length")?;
        cursor.take(key_exchange_length, "truncated key_exchange")?;
        shares.push(KeyShareShape {
            group: format_u16(group),
            key_exchange_length,
        });
    }

    Ok(shares)
}

fn key_share_payload(raw: &[u8], group: u16) -> Result<Vec<u8>, String> {
    let mut cursor = ByteCursor::new(raw);
    let handshake_type = cursor.read_u8("missing handshake type")?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }

    let handshake_len = cursor.read_u24("missing handshake length")?;
    if handshake_len != raw.len() - 4 {
        return Err(format!(
            "handshake length mismatch: header={handshake_len} raw={}",
            raw.len() - 4
        ));
    }

    cursor.read_u16("missing legacy version")?;
    cursor.take(32, "missing ClientHello random")?;
    let session_id_len = cursor.read_u8("missing legacy session id length")?;
    cursor.take(session_id_len, "truncated legacy session id")?;
    cursor.read_u16_list("missing cipher suites")?;
    let compression_methods_len = cursor.read_u8("missing compression methods length")?;
    cursor.take(compression_methods_len, "truncated compression methods")?;
    let extensions_len = cursor.read_u16("missing extensions length")?;
    let extensions_end = cursor.checked_end(extensions_len, "truncated extensions")?;

    while cursor.offset < extensions_end {
        let extension_type = cursor.read_u16("missing extension type")? as u16;
        let extension_len = cursor.read_u16("missing extension length")?;
        let extension_data = cursor.take(extension_len, "truncated extension data")?;
        if extension_type == 0x0033 {
            return key_share_payload_from_extension(extension_data, group);
        }
    }

    Err("missing key_share extension".to_owned())
}

fn key_share_payload_from_extension(data: &[u8], group: u16) -> Result<Vec<u8>, String> {
    let mut cursor = ByteCursor::new(data);
    let shares_len = cursor.read_u16("missing key_share client_shares length")?;
    let shares_end = cursor.checked_end(shares_len, "truncated key_share client_shares")?;
    while cursor.offset < shares_end {
        let share_group = cursor.read_u16("missing key_share group")? as u16;
        let key_exchange_length = cursor.read_u16("missing key_exchange length")?;
        let key_exchange = cursor.take(key_exchange_length, "truncated key_exchange")?;
        if share_group == group {
            return Ok(key_exchange.to_vec());
        }
    }

    Err(format!("missing key_share group 0x{group:04x}"))
}

fn key_share_payloads(raw: &[u8]) -> Result<Vec<KeySharePayload>, String> {
    let mut cursor = ByteCursor::new(raw);
    let handshake_type = cursor.read_u8("missing handshake type")?;
    if handshake_type != 0x01 {
        return Err(format!(
            "not a ClientHello handshake: 0x{handshake_type:02x}"
        ));
    }

    let handshake_len = cursor.read_u24("missing handshake length")?;
    if handshake_len != raw.len() - 4 {
        return Err(format!(
            "handshake length mismatch: header={handshake_len} raw={}",
            raw.len() - 4
        ));
    }

    cursor.read_u16("missing legacy version")?;
    cursor.take(32, "missing ClientHello random")?;
    let session_id_len = cursor.read_u8("missing legacy session id length")?;
    cursor.take(session_id_len, "truncated legacy session id")?;
    cursor.read_u16_list("missing cipher suites")?;
    let compression_methods_len = cursor.read_u8("missing compression methods length")?;
    cursor.take(compression_methods_len, "truncated compression methods")?;
    let extensions_len = cursor.read_u16("missing extensions length")?;
    let extensions_end = cursor.checked_end(extensions_len, "truncated extensions")?;

    while cursor.offset < extensions_end {
        let extension_type = cursor.read_u16("missing extension type")? as u16;
        let extension_len = cursor.read_u16("missing extension length")?;
        let extension_data = cursor.take(extension_len, "truncated extension data")?;
        if extension_type == 0x0033 {
            return key_share_payloads_from_extension(extension_data);
        }
    }

    Err("missing key_share extension".to_owned())
}

fn key_share_payloads_from_extension(data: &[u8]) -> Result<Vec<KeySharePayload>, String> {
    let mut cursor = ByteCursor::new(data);
    let shares_len = cursor.read_u16("missing key_share client_shares length")?;
    let shares_end = cursor.checked_end(shares_len, "truncated key_share client_shares")?;
    let mut key_shares = Vec::new();

    while cursor.offset < shares_end {
        let group = cursor.read_u16("missing key_share group")? as u16;
        let key_exchange_length = cursor.read_u16("missing key_exchange length")?;
        let key_exchange = cursor
            .take(key_exchange_length, "truncated key_exchange")?
            .to_vec();
        key_shares.push(KeySharePayload {
            group,
            key_exchange,
        });
    }

    Ok(key_shares)
}

fn x25519_public_key(private_key: [u8; 32]) -> [u8; X25519_PUBLIC_KEY_LEN] {
    let secret = X25519StaticSecret::from(private_key);
    X25519PublicKey::from(&secret).to_bytes()
}

fn format_u16s(values: &[u16]) -> Vec<String> {
    values.iter().copied().map(format_u16).collect()
}

fn format_u8s(values: &[u8]) -> Vec<String> {
    values.iter().copied().map(format_u8).collect()
}

fn format_u16(value: u16) -> String {
    if is_grease(value) {
        "GREASE".to_owned()
    } else {
        format!("0x{value:04x}")
    }
}

fn format_u8(value: u8) -> String {
    format!("0x{value:02x}")
}

fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

struct ByteCursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn checked_end(&self, length: usize, message: &str) -> Result<usize, String> {
        self.offset
            .checked_add(length)
            .filter(|end| *end <= self.raw.len())
            .ok_or_else(|| {
                format!(
                    "{message}: need {length} bytes at offset {}, have {}",
                    self.offset,
                    self.raw.len().saturating_sub(self.offset)
                )
            })
    }

    fn take(&mut self, length: usize, message: &str) -> Result<&'a [u8], String> {
        let end = self.checked_end(length, message)?;
        let out = &self.raw[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn read_u8(&mut self, message: &str) -> Result<usize, String> {
        let bytes = self.take(1, message)?;
        Ok(bytes[0] as usize)
    }

    fn read_u16(&mut self, message: &str) -> Result<usize, String> {
        let bytes = self.take(2, message)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
    }

    fn read_u24(&mut self, message: &str) -> Result<usize, String> {
        let bytes = self.take(3, message)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    fn read_u16_list(&mut self, message: &str) -> Result<Vec<u16>, String> {
        let length = self.read_u16(&format!("{message} length"))?;
        if length % 2 != 0 {
            return Err(format!("{message} length is odd: {length}"));
        }
        let end = self.checked_end(length, &format!("truncated {message}"))?;
        let mut values = Vec::with_capacity(length / 2);
        while self.offset < end {
            values.push(self.read_u16(&format!("missing {message} value"))? as u16);
        }
        Ok(values)
    }

    fn read_u8_list(&mut self, message: &str) -> Result<Vec<u8>, String> {
        let length = self.read_u8(&format!("{message} length"))?;
        Ok(self.take(length, &format!("truncated {message}"))?.to_vec())
    }

    fn read_u8_length_prefixed_u16_list(&mut self, message: &str) -> Result<Vec<u16>, String> {
        let length = self.read_u8(&format!("{message} length"))?;
        if length % 2 != 0 {
            return Err(format!("{message} length is odd: {length}"));
        }
        let end = self.checked_end(length, &format!("truncated {message}"))?;
        let mut values = Vec::with_capacity(length / 2);
        while self.offset < end {
            values.push(self.read_u16(&format!("missing {message} value"))? as u16);
        }
        Ok(values)
    }

    fn read_protocol_name_list(&mut self, message: &str) -> Result<Vec<String>, String> {
        let length = self.read_u16(&format!("{message} length"))?;
        let end = self.checked_end(length, &format!("truncated {message}"))?;
        let mut protocols = Vec::new();
        while self.offset < end {
            let protocol_len = self.read_u8("missing protocol name length")?;
            let protocol = self.take(protocol_len, "truncated protocol name")?;
            protocols.push(
                std::str::from_utf8(protocol)
                    .map_err(|error| format!("protocol name is not utf-8: {error}"))?
                    .to_owned(),
            );
        }
        Ok(protocols)
    }
}
