use serde_json::Value;
use xray_config::profile_import::{import_profile, ProfileFormat};

#[test]
fn trojan_uri_preserves_encoded_credentials_plus_ipv6_and_name() {
    let profile = import_profile(
        ProfileFormat::Trojan,
        "trojan://p%40ss+%3A%F0%9F%94%91@[2001:db8::1]:8443?sni=example.test#Test%20%E2%9C%93",
        None,
        &[],
    )
    .unwrap();
    assert_eq!(profile.name, "Test ✓");
    assert_eq!(profile.server_address, "2001:db8::1");
    let config: Value = serde_json::from_str(&profile.config_json).unwrap();
    assert_eq!(config["outbounds"][0]["settings"]["password"], "p@ss+:🔑");
    assert_eq!(config["outbounds"][0]["settings"]["port"], 8443);
    assert_eq!(config["outbounds"][0]["streamSettings"]["security"], "tls");
    assert!(!format!("{profile:?}").contains("p@ss"));
}

#[test]
fn trojan_uri_projects_stream_settings_through_the_shared_validator() {
    for query in [
        "type=tcp",
        "type=ws&host=cdn.example.test&path=%2Fpath%3Fed%3D2048",
        "type=httpupgrade&path=%2Ftrojan",
        "type=grpc&serviceName=test&alpn=h2",
        "type=xhttp&mode=stream-one&path=%2Ftrojan&alpn=h2",
    ] {
        let profile = import_profile(
            ProfileFormat::Trojan,
            &format!("trojan://synthetic-trojan-test-secret@example.test?{query}"),
            None,
            &[],
        )
        .unwrap();
        assert!(xray_config::parse_xray_json(&profile.config_json).is_ok());
    }
}

#[test]
fn trojan_uri_rejects_duplicates_unsupported_and_unsafe_fields() {
    for suffix in [
        "?sni=a.test&peer=b.test",
        "?type=ws&type=raw",
        "?%73ni=a.test&sni=a.test",
        "?insecure=1",
        "?allowInsecure=true",
        "?security=unknown",
        "?flow=xtls-rprx-vision",
        "?type=grpc&path=/ignored",
        "?plugin=test",
        "?type=raw&pbk=ignored",
        "?type=ws&path=%xx",
        "?sni=bad%0Ahost",
        "#bad%00name",
    ] {
        assert!(
            import_profile(
                ProfileFormat::Trojan,
                &format!("trojan://synthetic-trojan-test-secret@example.test{suffix}"),
                None,
                &[]
            )
            .is_err(),
            "{suffix}"
        );
    }
    for uri in [
        "trojan://@example.test",
        "trojan://p@ss@example.test",
        "trojan://pass@example.test:0",
        "trojan://pass@example.test:65536",
        "trojan://pass@[::1",
        "trojan://pass@example.test/path",
        "trojan://pass@public.example.com?security=none",
    ] {
        assert!(
            import_profile(ProfileFormat::Trojan, uri, None, &[]).is_err(),
            "{uri}"
        );
    }
}
