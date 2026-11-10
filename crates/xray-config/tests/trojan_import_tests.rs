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
        // The parser only warns that HTTPUpgrade early data waits for the 101.
        "type=httpupgrade&path=%2F%3Fed%3D2560",
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

/// A share link carries `spx` verbatim into `spiderX`, as v2rayN does, so a
/// value Xray-core would refuse at load time is refused at import.
#[test]
fn trojan_uri_spider_x_follows_xray_core_rules() {
    let reality = "security=reality&sni=www.example.com&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=02030405&fp=chrome";
    let import = |spx: &str| {
        import_profile(
            ProfileFormat::Trojan,
            &format!("trojan://synthetic-trojan-test-secret@example.test?{reality}&spx={spx}"),
            None,
            &[],
        )
    };
    let profile = import("%2Fcrawl%3Fp%3D1").unwrap();
    let config: Value = serde_json::from_str(&profile.config_json).unwrap();
    assert_eq!(
        config["outbounds"][0]["streamSettings"]["realitySettings"]["spiderX"],
        "/crawl?p=1"
    );
    assert!(matches!(import("crawl"), Err(ImportError::Configuration)));
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

/// An ALPN protocol name is 1..255 bytes (RFC 7301), and Go's TLS client
/// refuses an empty one at the handshake, so the import refuses it up front.
#[test]
fn trojan_uri_rejects_empty_or_padded_alpn_entries() {
    assert_eq!(
        stream("alpn=h2%2Chttp%2F1.1")["tlsSettings"]["alpn"],
        serde_json::json!(["h2", "http/1.1"])
    );
    for alpn in ["", "h2%2C%2Chttp%2F1.1", "h2%2C", "h2%2C%20http%2F1.1"] {
        assert_eq!(
            import_error(&format!("alpn={alpn}")),
            ImportError::UnsupportedParameter("alpn"),
            "{alpn}"
        );
    }
}

/// Percent-encodes a finalmask as Remnawave's `encodeURIComponent` does.
fn fm(mask: &Value) -> String {
    mask.to_string()
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Remnawave writes a host's whole finalmask as `fm`; it lands verbatim in
/// `streamSettings.finalmask`, and the parser decides what the core can carry.
#[test]
fn trojan_uri_maps_fm_to_finalmask_through_the_shared_validator() {
    let mask = serde_json::json!({"tcp":[{"type":"fragment","settings":{
        "packets":"tlshello","length":"100-200","delay":"10-20"}}]});
    let tls = stream(&format!("security=tls&sni=example.test&fm={}", fm(&mask)));
    assert_eq!(tls["finalmask"], mask);
    // VMess URIs share the stream mapping.
    let profile = import_profile(
        ProfileFormat::Vmess,
        &format!(
            "vmess://8a7c5d4e-1b2c-4d3e-8f9a-0b1c2d3e4f5a@example.test:443?security=tls&fm={}",
            fm(&mask)
        ),
        None,
        &[],
    )
    .unwrap();
    let config: Value = serde_json::from_str(&profile.config_json).unwrap();
    assert_eq!(config["outbounds"][0]["streamSettings"]["finalmask"], mask);
    // A header-custom TCP mask goes through as well.
    let header = serde_json::json!({"tcp":[{"type":"header-custom","settings":{
        "clients":[[{"type":"str","packet":"HELLO"}]],"servers":[[{"type":"str","packet":"OK"}]]}}]});
    let tls = stream(&format!("security=tls&sni=example.test&fm={}", fm(&header)));
    assert_eq!(tls["finalmask"], header);
    // And a sudoku TCP mask.
    let sudoku = serde_json::json!({"tcp":[{"type":"sudoku","settings":{"password":"synthetic"}}]});
    let tls = stream(&format!("security=tls&sni=example.test&fm={}", fm(&sudoku)));
    assert_eq!(tls["finalmask"], sudoku);
    // And an xmc TCP mask.
    let xmc = serde_json::json!({"tcp":[{"type":"xmc","settings":{"password":"synthetic",
        "profiles":[{"username":"Steve","uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f",
            "texturesValue":"dGV4dHVyZXM=","texturesSignature":"c2lnbmF0dXJl"}]}}]});
    let tls = stream(&format!("security=tls&sni=example.test&fm={}", fm(&xmc)));
    assert_eq!(tls["finalmask"], xmc);
    // So does a fragment mask that cuts writes into raw pieces.
    let pieces = serde_json::json!({"tcp":[{"type":"fragment","settings":{
        "packets":"1-3","length":"100-200","delay":"10-20"}}]});
    let tls = stream(&format!("security=tls&sni=example.test&fm={}", fm(&pieces)));
    assert_eq!(tls["finalmask"], pieces);
    // And a filter, which a client validates and ignores.
    let filter = serde_json::json!({"tcp":[{"type":"filter","settings":{
        "blockedSourceIPs":["10.0.0.0/8"]}}]});
    let tls = stream(&format!("security=tls&sni=example.test&fm={}", fm(&filter)));
    assert_eq!(tls["finalmask"], filter);
    // An empty `fm` is no mask.
    assert!(stream("fm=").get("finalmask").is_none());

    for text in ["%7B", "%5B%5D", "1", "%22tcp%22", "null"] {
        assert_eq!(
            import_error(&format!("fm={text}")),
            ImportError::Syntax,
            "{text}"
        );
    }
    assert_eq!(import_error("fm=%7B%7D&fm=%7B%7D"), ImportError::Duplicate);
    // What the core does not implement, or the parser refuses, names `fm`
    // instead of being dropped.
    for mask in [
        serde_json::json!({"udp":[{"type":"noise","settings":{"noise":[{"rand":"10-20"}]}}]}),
        serde_json::json!({"tcp":[{"type":"fragment","settings":{"packets":"0-3","length":"100-200"}}]}),
        serde_json::json!({"tcp":[{"type":"filter","settings":{"blockedSourceIPs":["10.0.0.0/33"]}}]}),
        serde_json::json!({"tcp":[{"type":"xmc","settings":{}}]}),
        serde_json::json!({"unknown":[]}),
    ] {
        assert_eq!(
            import_error(&format!("fm={}", fm(&mask))),
            ImportError::UnsupportedParameter("fm"),
            "{mask}"
        );
    }
}
