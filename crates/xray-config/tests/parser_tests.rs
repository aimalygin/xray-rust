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
        "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "publicKey": "AQE", "shortId": "02030405" } }
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
                  "address": "server.example",
                  "port": {port}
                  {users_comma}
                  {users_field}
                }}
                {extra_vnext}
              ]
            }},
            "streamSettings": {{
              "network": "tcp",
              "security": "reality",
              "realitySettings": {{
                "publicKey": "{public_key}",
                "shortId": "{short_id}"
              }}
            }}
          }}]
        }}"#
    )
}
