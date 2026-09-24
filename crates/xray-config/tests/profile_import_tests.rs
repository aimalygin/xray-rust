use serde_json::{json, Value};
use xray_config::profile_import::{
    import_profile, import_request, ImportError, ProfileFormat, MAX_REQUEST_BYTES, MAX_TEXT_BYTES,
};

const WG: &str = include_str!("../../../tests/fixtures/profile-import/wireguard.conf");
const HY: &str = include_str!("../../../tests/fixtures/profile-import/hysteria2.txt");
fn config(format: ProfileFormat, text: &str) -> Value {
    serde_json::from_str(&import_profile(format, text, None, &[]).unwrap().config_json).unwrap()
}
#[test]
fn hysteria_credentials_utf8_and_tls_are_preserved() {
    let profile = import_profile(ProfileFormat::Hysteria2, HY, None, &[]).unwrap();
    assert_eq!(profile.name, "Test ✓");
    assert_eq!(profile.server_address, "Server.Example.");
    let root: Value = serde_json::from_str(&profile.config_json).unwrap();
    assert_eq!(
        root["outbounds"][0]["settings"],
        json!({"version":2,"address":"Server.Example.","port":8443})
    );
    let stream = &root["outbounds"][0]["streamSettings"];
    assert_eq!(stream["hysteriaSettings"]["auth"], "user:p@ss:+✓");
    assert_eq!(
        stream["tlsSettings"],
        json!({"serverName":"tls.example","alpn":["h3"]})
    );
    assert_eq!(root["dns"]["fakeIp"]["enabled"], true);
    assert_eq!(root["inbounds"][0]["protocol"], "tun");
    assert!(root["inbounds"][0].get("sniffing").is_none());
    let serialized: Value = serde_json::from_str(&profile.to_json().unwrap()).unwrap();
    assert_eq!(serialized["schemaVersion"], 1);
    assert_eq!(serialized["configJSON"], profile.config_json.as_str());
    assert!(!format!("{profile:?}").contains("user"));
}
#[test]
fn hysteria_alias_default_port_ipv6_literal_plus_and_dns_override() {
    for scheme in ["hy2", "hysteria2", "HYSTERIA2"] {
        let p = import_profile(
            ProfileFormat::Hysteria2,
            &format!("{scheme}://auth+plus@[2001:db8::7]"),
            Some("Named"),
            &["192.0.2.53".into()],
        )
        .unwrap();
        let root: Value = serde_json::from_str(&p.config_json).unwrap();
        assert_eq!(p.name, "Named");
        assert_eq!(p.server_address, "2001:db8::7");
        assert_eq!(root["outbounds"][0]["settings"]["port"], 443);
        assert_eq!(
            root["outbounds"][0]["streamSettings"]["hysteriaSettings"]["auth"],
            "auth+plus"
        );
        assert_eq!(root["dns"], json!({"servers":["192.0.2.53"]}));
    }
}
#[test]
fn hysteria_rejects_unsupported_or_ambiguous_links_with_redacted_errors() {
    for text in [
        "hy2://secret@server.example?insecure=1",
        "hy2://secret@server.example?obfs=salamander",
        "hy2://secret@server.example?pinSHA256=secret",
        "hy2://secret@server.example?ech=secret",
        "hy2://secret@server.example?upmbps=10",
        "hy2://secret@server.example?sni=x&s%6ei=y",
        "hy2://secret@server.example?insecure=0&insecure=0",
        "hy2://secret@server.example:443,444",
        "hy2://secret@server.example/path",
        "hy2://secret@server.example?auth=other",
        "hy2://secret%@server.example",
        "hy2://secret%FF@server.example",
        "hy2://secret%00@server.example",
        "hy2://secret%0A@server.example",
        "hy2://secret@server.example:0",
        "hy2://secret@server.example:65536",
        "hy2://secret@2001:db8::7",
        "hy2://secret@[fe80::1%1]:443",
        "hy2://secret@@server.example",
        "hy2://server.example",
        "hysteria://secret@server.example",
        "hy2://secret@server.example#one#two",
    ] {
        let error = import_profile(ProfileFormat::Hysteria2, text, None, &[]).unwrap_err();
        assert!(!error.to_string().contains("secret"));
        assert!(!format!("{error:?}").contains(text));
    }
}
#[test]
fn wireguard_keeps_multi_peer_psk_and_split_routes() {
    let root = config(ProfileFormat::Wireguard, WG);
    assert_eq!(root["outbounds"][0]["protocol"], "freedom");
    let settings = &root["outbounds"][1]["settings"];
    assert_eq!(settings["address"], json!(["10.44.0.2/32", "fd44::2/128"]));
    assert_eq!(settings["peers"][0]["endpoint"], "First.Example.:51820");
    assert_eq!(settings["peers"][1]["endpoint"], "[2001:db8::7]:51821");
    assert_eq!(settings["peers"][0]["keepAlive"], 25);
    assert_eq!(
        settings["peers"][0]["preSharedKey"],
        "ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ="
    );
    assert_eq!(
        root["dns"],
        json!({"servers":["192.0.2.53","2001:db8::53"]})
    );
    assert_eq!(root["routing"]["domainStrategy"], "IPOnDemand");
    assert_eq!(
        root["routing"]["rules"][0]["ip"],
        json!([
            "198.51.100.0/24",
            "2001:db8:a::/64",
            "198.51.100.7/32",
            "2001:db8:a::7/128"
        ])
    );
    assert_eq!(root["routing"]["rules"][0]["outboundTag"], "proxy");
}
#[test]
fn wireguard_repeated_lists_comments_crlf_and_case_are_supported() {
    let text = WG
        .replace(
            "Address = 10.44.0.2/32, fd44::2/128",
            "address = 10.44.0.2/32\nAddress=fd44::2/128 # comment",
        )
        .replace("PersistentKeepalive = 25", "PersistentKeepalive=off")
        .replace('\n', "\r\n");
    let root = config(ProfileFormat::Wireguard, &text);
    assert_eq!(
        root["outbounds"][1]["settings"]["address"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(root["outbounds"][1]["settings"]["peers"][0]["keepAlive"], 0);
}
#[test]
fn wireguard_requires_explicit_dns_and_never_inserts_a_public_resolver() {
    let text = WG.replace("DNS = 192.0.2.53, 2001:db8::53\n", "");
    assert_eq!(
        import_profile(ProfileFormat::Wireguard, &text, None, &[]).unwrap_err(),
        ImportError::Dns
    );
    let p = import_profile(
        ProfileFormat::Wireguard,
        &text,
        None,
        &["192.0.2.54".into()],
    )
    .unwrap();
    assert!(p.config_json.contains("192.0.2.54"));
    assert_eq!(
        import_profile(ProfileFormat::Wireguard, WG, None, &["192.0.2.54".into()]).unwrap_err(),
        ImportError::Duplicate
    );
    for dns in [
        "search.example",
        "198.18.0.1",
        "fd00:7872::2",
        "0.0.0.0",
        "224.0.0.1",
    ] {
        assert_eq!(
            import_profile(ProfileFormat::Wireguard, &text, None, &[dns.into()]).unwrap_err(),
            ImportError::Dns
        );
    }
}
#[test]
fn wireguard_rejects_hooks_extensions_duplicate_scalars_and_invalid_peers() {
    for field in [
        "PreUp=secret",
        "PostUp=secret",
        "PreDown=secret",
        "PostDown=secret",
        "Table=off",
        "SaveConfig=true",
        "ListenPort=1234",
        "FwMark=42",
        "Jc=4",
        "PrivateKey=secret",
        "DNS=search.example",
    ] {
        let text = WG.replace("[Interface]", &format!("[Interface]\n{field}"));
        let err = import_profile(ProfileFormat::Wireguard, &text, None, &[]).unwrap_err();
        assert!(!err.to_string().contains("secret"));
    }
    for text in [
        WG.replace("MTU = 1420", "MTU=1500"),
        WG.replace("PublicKey =", "Unknown ="),
        WG.replace("AllowedIPs =", "NotAllowedIPs ="),
        WG.replace("[Peer]", "[Other]"),
        WG.replace("198.51.100.0/24", "::ffff:198.51.100.0/120"),
        WG.replace(
            "Endpoint = First.Example.:51820",
            "Endpoint=[fe80::1%1]:51820",
        ),
        WG.replace("PersistentKeepalive = 25", "PersistentKeepalive=65536"),
    ] {
        assert!(import_profile(ProfileFormat::Wireguard, &text, None, &[]).is_err());
    }
}
#[test]
fn import_request_limits_unknown_duplicate_fields_and_diagnostics_are_bounded() {
    let request = json!({"format":"hysteria2","text":HY,"name":"Imported"}).to_string();
    assert_eq!(import_request(&request).unwrap().name, "Imported");
    for text in [
        r#"{"format":"hysteria2","format":"wireguard","text":"secret"}"#,
        r#"{"format":"hysteria2","text":"secret","secret":"secret"}"#,
        r#"{"format":"other-secret","text":"secret"}"#,
    ] {
        assert_eq!(import_request(text).unwrap_err(), ImportError::Request);
    }
    assert_eq!(
        import_request(&" ".repeat(MAX_REQUEST_BYTES + 1)).unwrap_err(),
        ImportError::TooLarge
    );
    assert_eq!(
        import_profile(
            ProfileFormat::Wireguard,
            &"x".repeat(MAX_TEXT_BYTES + 1),
            None,
            &[]
        )
        .unwrap_err(),
        ImportError::TooLarge
    );
    for name in ["", "line\nbreak", &"x".repeat(129)] {
        assert_eq!(
            import_profile(ProfileFormat::Hysteria2, HY, Some(name), &[]).unwrap_err(),
            ImportError::Name
        );
    }
}

#[test]
fn wireguard_peer_prefix_address_and_dns_budgets_fail_before_output() {
    let (interface, first_peer) = WG.split_once("[Peer]").unwrap();
    let first_peer = first_peer.split("[Peer]").next().unwrap();
    let nine_peers = format!("{interface}{}", format!("[Peer]{first_peer}").repeat(9));
    assert_eq!(
        import_profile(ProfileFormat::Wireguard, &nine_peers, None, &[]).unwrap_err(),
        ImportError::TooLarge
    );
    let prefixes = std::iter::repeat_n("198.51.100.0/24", 257)
        .collect::<Vec<_>>()
        .join(",");
    let too_many = WG.replace("198.51.100.0/24, 2001:db8:a::/64", &prefixes);
    assert_eq!(
        import_profile(ProfileFormat::Wireguard, &too_many, None, &[]).unwrap_err(),
        ImportError::TooLarge
    );
    let addresses = WG.replace("Address =", "Address = 10.1.0.2/32, ");
    assert_eq!(
        import_profile(ProfileFormat::Wireguard, &addresses, None, &[]).unwrap_err(),
        ImportError::TooLarge
    );
    let dns = WG.replace(
        "DNS = 192.0.2.53, 2001:db8::53",
        &format!("DNS = {}", ["192.0.2.53"; 9].join(",")),
    );
    assert_eq!(
        import_profile(ProfileFormat::Wireguard, &dns, None, &[]).unwrap_err(),
        ImportError::TooLarge
    );
}

#[test]
fn wireguard_file_keys_require_standard_padded_base64_and_full_routes_are_preserved() {
    let secret = WG
        .lines()
        .find_map(|l| l.strip_prefix("PrivateKey = "))
        .unwrap();
    for invalid in [
        "42".repeat(32),
        secret.trim_end_matches('=').into(),
        "_".repeat(43) + "=",
    ] {
        assert!(import_profile(
            ProfileFormat::Wireguard,
            &WG.replace(secret, &invalid),
            None,
            &[]
        )
        .is_err());
    }
    let root = config(
        ProfileFormat::Wireguard,
        &WG.replace("198.51.100.0/24, 2001:db8:a::/64", "0.0.0.0/0, ::/0"),
    );
    assert_eq!(root["routing"]["rules"][0]["ip"][0], "0.0.0.0/0");
    assert_eq!(root["routing"]["rules"][0]["ip"][1], "::/0");
    assert!(root["inbounds"][0].get("sniffing").is_none());
}
