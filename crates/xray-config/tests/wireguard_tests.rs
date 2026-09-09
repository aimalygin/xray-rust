use serde_json::{json, Value};
use xray_config::{parse_xray_json, OutboundSettings, WireguardDomainStrategy};
fn example() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/configs/wireguard.json"
    ))
    .unwrap()
}
#[test]
fn wireguard_canonical_keys_addresses_and_defaults_are_bounded_and_redacted() {
    let mut value = example();
    let parsed = parse_xray_json(&value.to_string()).unwrap();
    assert!(parsed.diagnostics.is_empty());
    let OutboundSettings::Wireguard(settings) = &parsed.config.outbounds[0].settings else {
        panic!()
    };
    assert_eq!(settings.addresses.len(), 2);
    assert_eq!(settings.mtu, 1420);
    assert_eq!(settings.domain_strategy, WireguardDomainStrategy::ForceIp);
    assert!(!format!("{parsed:?}").contains(&"42".repeat(32)));
    for key in ["address", "mtu"] {
        value["outbounds"][0]["settings"]
            .as_object_mut()
            .unwrap()
            .remove(key);
    }
    value["outbounds"][0]["settings"]["peers"][0]
        .as_object_mut()
        .unwrap()
        .remove("allowedIPs");
    assert!(parse_xray_json(&value.to_string()).is_ok());
}
#[test]
fn wireguard_rejects_invalid_keys_limits_types_and_unsupported_options() {
    for (key, bad) in [
        ("secretKey", json!("invalid-secret-value")),
        ("secretKey", Value::Null),
        ("address", json!([])),
        ("address", json!(["10.44.0.2/33"])),
        ("address", json!(["10.44.0.2", "10.44.0.3"])),
        ("address", json!(["fe80::2"])),
        ("mtu", json!(1279)),
        ("mtu", json!(1421)),
        ("mtu", json!("1420")),
        ("reserved", json!([1, 2, 3])),
        ("domainStrategy", json!("AsIs")),
        ("noKernelTun", Value::Null),
        ("remoteDNS", json!("192.0.2.1")),
    ] {
        let mut value = example();
        value["outbounds"][0]["settings"][key] = bad;
        let error = parse_xray_json(&value.to_string()).unwrap_err();
        assert!(!format!("{error:?}").contains("invalid-secret-value"));
    }
    for (key, bad) in [
        ("preSharedKey", json!("sensitive-psk")),
        ("publicKey", json!("00".repeat(32))),
        ("keepAlive", json!(65536)),
        ("keepAlive", Value::Null),
        ("endpoint", json!("[::1]:0")),
        ("endpoint", json!("[fe80::1%3]:51820")),
        ("endpoint", json!("a:bad")),
        ("allowedIPs", json!([])),
        ("allowedIPs", json!(["0.0.0.0/33"])),
        ("allowedIPs", json!(vec!["0.0.0.0/0"; 257])),
    ] {
        let mut value = example();
        value["outbounds"][0]["settings"]["peers"][0][key] = bad;
        let error = parse_xray_json(&value.to_string()).unwrap_err();
        assert!(!format!("{error:?}").contains("sensitive-psk"));
    }
    let mut value = example();
    value["outbounds"][0]["streamSettings"] = json!({});
    assert!(parse_xray_json(&value.to_string()).is_err());
    let mut value = example();
    let second = value["outbounds"][0]["settings"]["peers"][0].clone();
    value["outbounds"][0]["settings"]["peers"]
        .as_array_mut()
        .unwrap()
        .push(second);
    assert!(parse_xray_json(&value.to_string()).is_err());
}

#[test]
fn wireguard_psk_accepts_key_spellings_and_redacts_parsed_and_cloned_configs() {
    use base64::{engine::general_purpose, Engine};
    let bytes = std::array::from_fn::<_, 32, _>(|i| (0xe0 + i) as u8);
    for encoded in [
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        general_purpose::STANDARD.encode(bytes),
        general_purpose::STANDARD_NO_PAD.encode(bytes),
        general_purpose::URL_SAFE.encode(bytes),
        general_purpose::URL_SAFE_NO_PAD.encode(bytes),
    ] {
        let mut value = example();
        value["outbounds"][0]["settings"]["peers"][0]["preSharedKey"] = json!(encoded);
        let parsed = parse_xray_json(&value.to_string()).unwrap();
        let OutboundSettings::Wireguard(settings) = &parsed.config.outbounds[0].settings else {
            panic!()
        };
        assert_eq!(
            settings.peers[0]
                .preshared_key
                .as_ref()
                .unwrap()
                .expose_bytes(),
            &bytes
        );
        let debug = format!("{:?}", parsed.config.clone());
        assert!(!debug.contains(&encoded));
        assert!(!debug.contains("224, 225, 226"));
        assert!(debug.contains("preshared_key: Some(KeyMaterial(<redacted>))"));
    }
}
#[test]
fn wireguard_psk_absent_empty_and_zero_are_unset_and_invalid_values_are_rejected() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    for value in [
        json!(""),
        json!("00".repeat(32)),
        json!(STANDARD.encode([0; 32])),
    ] {
        let mut config = example();
        config["outbounds"][0]["settings"]["peers"][0]["preSharedKey"] = value;
        let parsed = parse_xray_json(&config.to_string()).unwrap();
        let OutboundSettings::Wireguard(settings) = &parsed.config.outbounds[0].settings else {
            panic!()
        };
        assert!(settings.peers[0].preshared_key.is_none());
    }
    for value in [
        Value::Null,
        json!(0),
        json!([]),
        json!(STANDARD.encode([0x64; 31])),
        json!(STANDARD.encode([0x64; 33])),
        json!("secret-psk-invalid"),
        json!("64".repeat(8192)),
    ] {
        let mut config = example();
        config["outbounds"][0]["settings"]["peers"][0]["preSharedKey"] = value.clone();
        let error = parse_xray_json(&config.to_string()).unwrap_err();
        if let Some(secret) = value.as_str() {
            assert!(!format!("{error:?}").contains(secret));
        }
    }
}

#[test]
fn wireguard_multi_peer_order_keys_and_aggregate_prefix_budget() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut value = example();
    let original = value["outbounds"][0]["settings"]["peers"][0].clone();
    let peers: Vec<_> = (0..8)
        .map(|index| {
            let mut peer = original.clone();
            peer["publicKey"] = json!(STANDARD.encode([0x53 + index; 32]));
            peer["allowedIPs"] = json!(vec!["198.51.100.7/24"; 32]);
            peer["keepAlive"] = json!(index);
            peer
        })
        .collect();
    value["outbounds"][0]["settings"]["peers"] = json!(peers);
    let parsed = parse_xray_json(&value.to_string()).unwrap();
    let OutboundSettings::Wireguard(settings) = &parsed.config.outbounds[0].settings else {
        panic!()
    };
    assert_eq!(settings.peers.len(), 8);
    for (index, peer) in settings.peers.iter().enumerate() {
        assert_eq!(peer.public_key.expose_bytes(), &[0x53 + index as u8; 32]);
        assert_eq!(peer.keepalive, index as u16);
        assert_eq!(
            peer.allowed_ips[0].network(),
            "198.51.100.0".parse::<std::net::IpAddr>().unwrap()
        );
    }
    let mut overflow = value.clone();
    overflow["outbounds"][0]["settings"]["peers"][7]["allowedIPs"]
        .as_array_mut()
        .unwrap()
        .push(json!("::/0"));
    assert!(parse_xray_json(&overflow.to_string()).is_err());
    let mut overflow = value.clone();
    let mut ninth = original.clone();
    ninth["publicKey"] = json!("63".repeat(32));
    overflow["outbounds"][0]["settings"]["peers"]
        .as_array_mut()
        .unwrap()
        .push(ninth);
    assert!(parse_xray_json(&overflow.to_string()).is_err());
    for (field, bad) in [
        ("publicKey", json!("53".repeat(32))), // same decoded key, different spelling
        ("publicKey", json!("00".repeat(32))),
        ("endpoint", json!("[::1]:0")),
        ("unknown", json!(true)),
    ] {
        let mut bad_config = value.clone();
        bad_config["outbounds"][0]["settings"]["peers"][7][field] = bad;
        assert!(
            parse_xray_json(&bad_config.to_string()).is_err(),
            "last peer: {field}"
        );
    }
    value["outbounds"][0]["settings"]["peers"] = json!([]);
    assert!(parse_xray_json(&value.to_string()).is_err());
}
