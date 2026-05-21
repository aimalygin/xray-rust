use xray_transport::{
    reality::RealityPreparedClientHello,
    reality_connector::{
        RealityClientHelloProvider, RealityClientHelloRequest, RealityConnector,
        RealityHandshakeContext, RealityHandshakePlan,
    },
    ConnectorConfig, RealityClientConfig,
};

const CLIENTHELLO_FIXTURE_JSON: &str =
    include_str!("../../../tests/fixtures/reality/clienthello_chrome_auto.json");

#[derive(Debug, serde::Deserialize)]
struct ClientHelloFixture {
    raw_client_hello_hex: String,
    hello_random_hex: String,
    session_id_offset: usize,
    local_x25519_private_key_hex: String,
}

#[derive(Debug)]
struct FixtureClientHelloProvider {
    fixture: ClientHelloFixture,
}

impl RealityClientHelloProvider for FixtureClientHelloProvider {
    fn prepare_client_hello(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        assert_eq!(request.server_name, "www.example.com");
        assert_eq!(request.fingerprint, "chrome");
        Ok(prepared_from_fixture(&self.fixture))
    }
}

#[derive(Debug, Default)]
struct PanickingClientHelloProvider;

impl RealityClientHelloProvider for PanickingClientHelloProvider {
    fn prepare_client_hello(
        &self,
        _request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        panic!("unsupported connector fingerprint should be rejected before provider invocation")
    }
}

fn reality_config_with_short_id(short_id: Vec<u8>) -> RealityClientConfig {
    RealityClientConfig {
        server_name: "www.example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [9u8; 32],
        short_id,
        spider_x: "/".to_owned(),
    }
}

fn clienthello_fixture() -> ClientHelloFixture {
    serde_json::from_str(CLIENTHELLO_FIXTURE_JSON).expect("fixture json should decode")
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string length must be even");
    (0..hex.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&hex[idx..idx + 2], 16).expect("valid hex byte"))
        .collect()
}

fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = decode_hex(hex);
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("hex string should decode to {N} bytes"))
}

fn prepared_from_fixture(fixture: &ClientHelloFixture) -> RealityPreparedClientHello {
    RealityPreparedClientHello {
        fingerprint: "chrome".to_owned(),
        raw_client_hello: decode_hex(&fixture.raw_client_hello_hex),
        hello_random: decode_hex_array(&fixture.hello_random_hex),
        session_id_offset: fixture.session_id_offset,
        local_x25519_private_key: decode_hex_array(&fixture.local_x25519_private_key_hex),
    }
}

fn handshake_context() -> RealityHandshakeContext {
    RealityHandshakeContext {
        version: [1, 8, 0],
        unix_time: 1_700_000_000,
    }
}

#[test]
fn reality_connector_accepts_chrome_fingerprint_for_first_slice() {
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));

    assert!(connector.is_fingerprint_supported());
}

#[test]
fn reality_connector_builds_handshake_plan_without_network_io() {
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));

    let plan = connector.handshake_plan();
    assert_eq!(plan.server_name, "www.example.com");
    assert_eq!(plan.short_id, vec![2, 3, 4, 5]);
    assert_eq!(plan.fingerprint, "chrome");
}

#[test]
fn reality_connector_rejects_unsupported_fingerprint_for_first_slice() {
    let mut config = reality_config_with_short_id(vec![2, 3, 4, 5]);
    config.fingerprint = "firefox".to_owned();
    let connector = RealityConnector::new(config);

    assert!(!connector.is_fingerprint_supported());
}

#[test]
fn reality_connector_handshake_plan_clones_short_id_bytes_exactly() {
    let connector = RealityConnector::new(reality_config_with_short_id(vec![0, 15, 255]));

    let plan = connector.handshake_plan();
    assert_eq!(
        plan,
        RealityHandshakePlan {
            server_name: "www.example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [9u8; 32],
            short_id: vec![0, 15, 255],
            spider_x: "/".to_owned(),
        }
    );
}

#[test]
fn reality_debug_output_redacts_short_id_bytes() {
    let config = reality_config_with_short_id(vec![2, 3, 4, 5]);
    let config_debug = format!("{config:?}");
    assert!(config_debug.contains("short_id: \"<redacted>\""));
    assert!(!config_debug.contains("short_id: [2, 3, 4, 5]"));

    let connector_config = ConnectorConfig::Reality(reality_config_with_short_id(vec![2, 3, 4, 5]));
    let connector_config_debug = format!("{connector_config:?}");
    assert!(connector_config_debug.contains("short_id: \"<redacted>\""));
    assert!(!connector_config_debug.contains("short_id: [2, 3, 4, 5]"));

    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));
    let connector_debug = format!("{connector:?}");
    assert!(connector_debug.contains("short_id: \"<redacted>\""));
    assert!(!connector_debug.contains("short_id: [2, 3, 4, 5]"));

    let plan = connector.handshake_plan();
    let plan_debug = format!("{plan:?}");
    assert!(plan_debug.contains("short_id: \"<redacted>\""));
    assert!(!plan_debug.contains("short_id: [2, 3, 4, 5]"));
}

#[test]
fn reality_connector_prepares_handshake_from_validated_clienthello_provider() {
    let fixture = clienthello_fixture();
    let provider = FixtureClientHelloProvider { fixture };
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));
    let original_client_hello = decode_hex(&provider.fixture.raw_client_hello_hex);

    let prepared = connector
        .prepare_handshake(&provider, handshake_context())
        .expect("valid provider output should prepare REALITY handshake");

    assert_ne!(prepared.auth_key, [0u8; 32]);
    assert_ne!(prepared.session_id, [0u8; 32]);
    assert_ne!(
        &prepared.patched_client_hello
            [provider.fixture.session_id_offset..provider.fixture.session_id_offset + 32],
        &original_client_hello
            [provider.fixture.session_id_offset..provider.fixture.session_id_offset + 32]
    );
}

#[test]
fn reality_connector_prepares_handshake_from_prepared_clienthello() {
    let fixture = clienthello_fixture();
    let original_client_hello = decode_hex(&fixture.raw_client_hello_hex);
    let session_id_offset = fixture.session_id_offset;
    let prepared_client_hello = prepared_from_fixture(&fixture);
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));

    let prepared = connector
        .prepare_handshake_with_client_hello(prepared_client_hello, handshake_context())
        .expect("valid prepared ClientHello should prepare REALITY handshake");

    assert_ne!(prepared.auth_key, [0u8; 32]);
    assert_ne!(prepared.session_id, [0u8; 32]);
    assert_eq!(
        &prepared.patched_client_hello[session_id_offset..session_id_offset + 32],
        &prepared.session_id[..]
    );
    assert_ne!(
        &prepared.patched_client_hello[session_id_offset..session_id_offset + 32],
        &original_client_hello[session_id_offset..session_id_offset + 32]
    );
}

#[test]
fn reality_connector_rejects_invalid_prepared_clienthello_metadata() {
    let fixture = clienthello_fixture();
    let mut prepared_client_hello = prepared_from_fixture(&fixture);
    prepared_client_hello.hello_random[0] ^= 0xff;
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));

    let err = connector
        .prepare_handshake_with_client_hello(prepared_client_hello, handshake_context())
        .unwrap_err();

    assert_eq!(
        err,
        xray_transport::reality::RealityError::ClientHelloRandomMismatch
    );
}

#[test]
fn reality_connector_rejects_invalid_provider_clienthello_metadata() {
    let mut fixture = clienthello_fixture();
    fixture.hello_random_hex.replace_range(0..2, "ff");
    let provider = FixtureClientHelloProvider { fixture };
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));

    let err = connector
        .prepare_handshake(&provider, handshake_context())
        .unwrap_err();

    assert_eq!(
        err,
        xray_transport::reality::RealityError::ClientHelloRandomMismatch
    );
}

#[test]
fn reality_connector_rejects_unsupported_config_fingerprint_before_provider() {
    let mut config = reality_config_with_short_id(vec![2, 3, 4, 5]);
    config.fingerprint = "firefox".to_owned();
    let connector = RealityConnector::new(config);

    let err = connector
        .prepare_handshake(&PanickingClientHelloProvider, handshake_context())
        .unwrap_err();

    assert_eq!(
        err,
        xray_transport::reality::RealityError::UnsupportedRealityFingerprint("firefox".to_owned())
    );
}
