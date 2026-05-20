use xray_transport::{
    reality_connector::{RealityConnector, RealityHandshakePlan},
    RealityClientConfig,
};

fn reality_config_with_short_id(short_id: Vec<u8>) -> RealityClientConfig {
    RealityClientConfig {
        server_name: "www.example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [1u8; 32],
        short_id,
        spider_x: "/".to_owned(),
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
            public_key: [1u8; 32],
            short_id: vec![0, 15, 255],
            spider_x: "/".to_owned(),
        }
    );
}
