use xray_config::{
    parse_xray_json, DiagnosticSeverity, OutboundSettings, RealityShortId, StreamSecurity,
    TargetAddr,
};

#[test]
fn parses_vless_reality_vision_subset() {
    let raw = include_str!("../../../tests/fixtures/configs/vless_reality_vision.json");
    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.inbounds.len(), 2);
    assert_eq!(parsed.config.outbounds.len(), 1);
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(parsed.config.outbounds[0].tag.as_deref(), Some("proxy"));

    let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings;
    assert_eq!(
        vless.server,
        TargetAddr::Domain("server.example".to_owned())
    );
    assert_eq!(vless.port, 443);
    assert_eq!(vless.users[0].flow.as_deref(), Some("xtls-rprx-vision"));

    let StreamSecurity::Reality(reality) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected reality security");
    };
    assert_eq!(reality.public_key, [1; 32]);
    assert_eq!(
        reality.short_id,
        RealityShortId::try_from_slice(&[2, 3, 4, 5]).unwrap()
    );
}

#[test]
fn rejects_unsupported_outbound_protocol_with_path() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [
            { "protocol": "trojan", "settings": {} }
        ]
    }"#;

    let err = parse_xray_json(raw).unwrap_err();
    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(
        err.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].protocol")
    );
}

#[test]
fn rejects_invalid_reality_public_key_length_with_path() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [{
        "tag": "proxy",
        "protocol": "vless",
        "settings": { "vnext": [{ "address": "server.example", "port": 443, "users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }] }] },
        "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "serverName": "server.example", "fingerprint": "chrome", "publicKey": "AQE", "shortId": "02030405" } }
      }]
    }"#;

    let err = parse_xray_json(raw).unwrap_err();
    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(
        err.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].streamSettings.realitySettings.publicKey")
    );
}

#[test]
fn rejects_invalid_reality_public_key_tail_bits_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF",
        "02030405",
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.publicKey",
    );
}

#[test]
fn rejects_missing_vless_users_with_path() {
    let raw = vless_raw("", "", 443, valid_public_key(), "02030405");

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users");
}

#[test]
fn rejects_empty_vless_users_with_path() {
    let raw = vless_raw(r#""users": []"#, "", 443, valid_public_key(), "02030405");

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users");
}

#[test]
fn rejects_empty_vless_server_address_with_path() {
    let raw = vless_raw_with_address(
        "",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].address");
}

#[test]
fn rejects_zero_vless_port_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        0,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].port");
}

#[test]
fn rejects_unsupported_vless_user_encryption_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "aes-128-gcm" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users[0].encryption");
}

#[test]
fn accepts_missing_none_and_explicit_none_vless_user_encryption() {
    for users in [
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none" }]"#,
    ] {
        let raw = vless_raw(users, "", 443, valid_public_key(), "02030405");

        let parsed = parse_xray_json(&raw).expect("config should parse");
        let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings;
        assert_eq!(vless.users[0].encryption, "none");
    }
}

#[test]
fn rejects_unsupported_vless_user_flow_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": "xtls-rprx-direct" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users[0].flow");
}

#[test]
fn accepts_missing_empty_and_vision_vless_user_flow() {
    for (users, expected_flow) in [
        (
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
            None,
        ),
        (
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": "" }]"#,
            None,
        ),
        (
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": "xtls-rprx-vision" }]"#,
            Some("xtls-rprx-vision"),
        ),
    ] {
        let raw = vless_raw(users, "", 443, valid_public_key(), "02030405");

        let parsed = parse_xray_json(&raw).expect("config should parse");
        let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings;
        assert_eq!(vless.users[0].flow.as_deref(), expected_flow);
    }
}

#[test]
fn rejects_multiple_vless_vnext_entries_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        r#", { "address": "backup.example", "port": 443, "users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }] }"#,
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext");
}

#[test]
fn rejects_malformed_reality_short_id_with_path() {
    for short_id in ["123", "0203040z", "000102030405060708"] {
        let raw = vless_raw(
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
            "",
            443,
            valid_public_key(),
            short_id,
        );

        assert_parse_error_path(
            &raw,
            "$.outbounds[0].streamSettings.realitySettings.shortId",
        );
    }
}

#[test]
fn rejects_vless_port_overflow_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        65536,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].port");
}

#[test]
fn rejects_udp_stream_network_with_path() {
    let raw = vless_raw_with_network(
        "udp",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.network");
}

#[test]
fn rejects_other_stream_network_with_path() {
    let raw = vless_raw_with_network(
        "ws",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.network");
}

#[test]
fn rejects_missing_reality_server_name_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "chrome""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.serverName",
    );
}

#[test]
fn rejects_empty_reality_server_name_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "chrome""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.serverName",
    );
}

#[test]
fn rejects_missing_reality_fingerprint_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.fingerprint",
    );
}

#[test]
fn rejects_unsupported_reality_fingerprint_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "firefox""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.fingerprint",
    );
}

fn assert_parse_error_path(raw: &str, path: &str) {
    let err = parse_xray_json(raw).unwrap_err();
    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(err.diagnostics[0].path.as_deref(), Some(path));
}

fn valid_public_key() -> &'static str {
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
}

fn vless_raw(
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    vless_raw_with_address(
        "server.example",
        users_field,
        extra_vnext,
        port,
        public_key,
        short_id,
    )
}

fn vless_raw_with_address(
    address: &str,
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    vless_raw_with_network_and_address(
        "tcp",
        address,
        users_field,
        extra_vnext,
        port,
        public_key,
        short_id,
    )
}

fn vless_raw_with_network(
    network: &str,
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    vless_raw_with_network_and_address(
        network,
        "server.example",
        users_field,
        extra_vnext,
        port,
        public_key,
        short_id,
    )
}

fn vless_raw_with_network_and_address(
    network: &str,
    address: &str,
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    let users_comma = if users_field.is_empty() { "" } else { "," };

    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "{address}",
                  "port": {port}
                  {users_comma}
                  {users_field}
                }}
                {extra_vnext}
              ]
            }},
            "streamSettings": {{
              "network": "{network}",
              "security": "reality",
              "realitySettings": {{
                "serverName": "server.example",
                "fingerprint": "chrome",
                "publicKey": "{public_key}",
                "shortId": "{short_id}"
              }}
            }}
          }}]
        }}"#
    )
}

fn vless_raw_with_reality_settings(reality_settings: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "server.example",
                  "port": 443,
                  "users": [{{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }}]
                }}
              ]
            }},
            "streamSettings": {{
              "network": "tcp",
              "security": "reality",
              "realitySettings": {{
                {reality_settings}
              }}
            }}
          }}]
        }}"#
    )
}
