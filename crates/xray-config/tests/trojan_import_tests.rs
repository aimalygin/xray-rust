use serde_json::Value;
use xray_config::profile_import::{import_profile, ImportError, ProfileFormat};

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

/// The parser only warns on a REALITY fingerprint without the hybrid share,
/// because servers older than v26.10.21 accept it; the import must not turn
/// that warning into a failure. A fingerprint with no X25519 share at all is
/// still a configuration error.
#[test]
fn trojan_uri_keeps_reality_fingerprints_older_servers_accept() {
    let reality = "security=reality&sni=www.example.com&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=02030405";
    for fingerprint in [
        "chrome",
        "randomizednoalpn",
        "ios",
        "edge",
        "qq",
        "hellochrome_100",
    ] {
        let profile = import_profile(
            ProfileFormat::Trojan,
            &format!(
                "trojan://synthetic-trojan-test-secret@example.test?{reality}&fp={fingerprint}"
            ),
            None,
            &[],
        )
        .unwrap_or_else(|error| panic!("{fingerprint}: {error:?}"));
        let config: Value = serde_json::from_str(&profile.config_json).unwrap();
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"],
            fingerprint
        );
    }
    assert!(import_profile(
        ProfileFormat::Trojan,
        &format!("trojan://synthetic-trojan-test-secret@example.test?{reality}&fp=android"),
        None,
        &[],
    )
    .is_err());
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

fn stream(query: &str) -> Value {
    let profile = import_profile(
        ProfileFormat::Trojan,
        &format!("trojan://synthetic-trojan-test-secret@example.test?{query}"),
        None,
        &[],
    )
    .unwrap_or_else(|error| panic!("{query}: {error:?}"));
    let config: Value = serde_json::from_str(&profile.config_json).unwrap();
    config["outbounds"][0]["streamSettings"].clone()
}

fn import_error(query: &str) -> ImportError {
    import_profile(
        ProfileFormat::Trojan,
        &format!("trojan://synthetic-trojan-test-secret@example.test?{query}"),
        None,
        &[],
    )
    .unwrap_err()
}

/// Remnawave writes gRPC `mode` on every gRPC link and `headerType` whenever
/// a RAW header object exists, so a value matching the core's behaviour must
/// import; one asking for an unimplemented mode names the parameter.
#[test]
fn trojan_uri_accepts_remnawave_carrier_parameters() {
    let grpc = stream("type=grpc&serviceName=test&mode=gun&security=tls");
    assert_eq!(grpc["grpcSettings"]["serviceName"], "test");
    assert!(grpc["grpcSettings"].get("multiMode").is_none());
    let grpc = stream("type=grpc&serviceName=test&mode=multi");
    assert_eq!(grpc["grpcSettings"]["multiMode"], true);
    assert_eq!(
        import_error("type=grpc&mode=guna"),
        ImportError::UnsupportedParameter("mode")
    );

    for header in ["none", ""] {
        let raw = stream(&format!("type=tcp&headerType={header}"));
        assert_eq!(raw["network"], "tcp");
    }
    let error = import_error("type=tcp&headerType=http&host=cdn.example.test&path=%2F");
    assert_eq!(error, ImportError::UnsupportedParameter("headerType"));
    assert_eq!(
        error.to_string(),
        "profile contains an unsupported value for `headerType`"
    );
    // headerType belongs to RAW only.
    assert_eq!(
        import_error("type=ws&headerType=none"),
        ImportError::Unsupported
    );

    let ws = stream("type=ws&path=%2Fws&heartbeatPeriod=30");
    assert_eq!(ws["wsSettings"]["heartbeatPeriod"], 30);
    for period in ["", "-1", "+30", "4294967296", "30s"] {
        assert_eq!(
            import_error(&format!("type=ws&heartbeatPeriod={period}")),
            ImportError::Syntax,
            "{period}"
        );
    }
}

#[test]
fn trojan_uri_maps_xhttp_extra_through_the_shared_validator() {
    let extra = "%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22noGRPCHeader%22%3Atrue%7D";
    let xhttp = stream(&format!(
        "type=xhttp&path=%2Fx&mode=packet-up&extra={extra}"
    ));
    assert_eq!(xhttp["xhttpSettings"]["path"], "/x");
    assert_eq!(xhttp["xhttpSettings"]["mode"], "packet-up");
    assert_eq!(xhttp["xhttpSettings"]["extra"]["xPaddingBytes"], "100-1000");
    assert_eq!(xhttp["xhttpSettings"]["extra"]["noGRPCHeader"], true);

    for extra in ["", "%5B%5D", "%7B", "1"] {
        assert_eq!(
            import_error(&format!("type=xhttp&extra={extra}")),
            ImportError::Syntax,
            "{extra}"
        );
    }
    // The parser still rejects what canonical JSON would reject.
    assert_eq!(
        import_error("type=xhttp&extra=%7B%22unknownField%22%3A1%7D"),
        ImportError::Configuration
    );
}

#[test]
fn trojan_uri_maps_tls_pins_and_rejects_cipher_suites() {
    let pin = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
    let compact = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    let tls = stream(&format!(
        "security=tls&sni=example.test&pcs={pin}%2C{compact}&vcn=cdn.example.test"
    ));
    assert_eq!(
        tls["tlsSettings"]["pinnedPeerCertSha256"],
        format!("{pin},{compact}")
    );
    assert_eq!(
        tls["tlsSettings"]["verifyPeerCertByName"],
        "cdn.example.test"
    );

    for pcs in ["00ff", "zz", &compact[..62]] {
        assert_eq!(
            import_error(&format!("pcs={pcs}")),
            ImportError::Configuration,
            "{pcs}"
        );
    }
    assert_eq!(
        import_error("pcs=x&security=reality&sni=www.example.com&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
        ImportError::Unsupported
    );
    assert_eq!(
        import_error("cs=TLS_AES_128_GCM_SHA256"),
        ImportError::UnsupportedParameter("cs")
    );
}
