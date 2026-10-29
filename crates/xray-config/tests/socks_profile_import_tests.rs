use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use xray_config::profile_import::{import_profile, import_request, ImportError, ProfileFormat};

const FIXTURE: &str = include_str!("../../../tests/fixtures/profile-import/socks.txt");

fn config(text: &str) -> Value {
    let imported = import_profile(ProfileFormat::Socks, text, None, &[]).unwrap();
    assert_eq!(imported.format, ProfileFormat::Socks);
    let parsed = xray_config::parse_xray_json(&imported.config_json).unwrap();
    assert!(parsed.diagnostics.is_empty());
    serde_json::from_str(&imported.config_json).unwrap()
}

#[test]
fn imports_percent_encoded_credentials_and_mobile_dns_without_resolving_names() {
    let imported = import_profile(ProfileFormat::Socks, FIXTURE, None, &[]).unwrap();
    assert_eq!(imported.name, "Test ✓");
    assert_eq!(imported.server_address, "Socks.Example.");
    let root = config(FIXTURE);
    assert_eq!(
        root["outbounds"],
        json!([{"tag":"proxy", "protocol":"socks", "settings": {
            "address":"Socks.Example.", "port":1080, "user":"synthetic:user", "pass":"p@ss:+✓"
        }}])
    );
    assert_eq!(
        root["inbounds"],
        json!([{"tag":"tun-in", "protocol":"tun", "settings":{}}])
    );
    assert_eq!(
        root["routing"],
        json!({"domainStrategy":"AsIs", "rules":[]})
    );
    assert_eq!(
        root["dns"],
        json!({"queryStrategy":"UseIPv4", "fakeIp":{
            "enabled":true, "ipv4Pool":"198.19.0.0/16", "poolSize":32768, "ttl":60
        }})
    );
    assert!(!format!("{imported:?}").contains("synthetic"));
    assert!(!format!("{imported:?}").contains("Socks.Example"));
}

#[test]
fn aliases_hosts_and_empty_exported_accounts_import_as_noauth() {
    for scheme in ["socks", "socks5", "SOCKS", "SoCkS5"] {
        for (authority, host) in [
            ("server.example:1080", "server.example"),
            ("192.0.2.10:1", "192.0.2.10"),
            ("[2001:db8::7]:65535", "2001:db8::7"),
        ] {
            for userinfo in ["", ":@", "%3A@", "Og==@", "Og@", "Og%3D%3D@"] {
                let text = format!(" \n{scheme}://{userinfo}{authority}/?#\r\n");
                let root = config(&text);
                let settings = &root["outbounds"][0]["settings"];
                assert_eq!(settings["address"], host);
                assert!(settings.get("user").is_none());
                assert!(settings.get("pass").is_none());
                assert_eq!(settings.as_object().unwrap().len(), 2);
            }
        }
    }
    let p = import_profile(
        ProfileFormat::Socks,
        "socks://server.example:1080",
        None,
        &[],
    )
    .unwrap();
    assert_eq!(p.name, "SOCKS5");
}

#[test]
fn base64_variants_preserve_literal_password_bytes_without_double_decoding() {
    let credentials = "synthetic:ÿÿ?%40:+/✓";
    for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        let token = engine.encode(credentials);
        for token in [
            token.clone(),
            token
                .replace('=', "%3D")
                .replace('/', "%2F")
                .replace('+', "%2B"),
        ] {
            let root = config(&format!("socks://{token}@server.example:1080"));
            assert_eq!(root["outbounds"][0]["settings"]["user"], "synthetic");
            assert_eq!(root["outbounds"][0]["settings"]["pass"], "ÿÿ?%40:+/✓");
        }
    }
    for userinfo in ["synthetic:p%2540ss+word", "synthetic%3Ap%2540ss+word"] {
        let root = config(&format!("socks5://{userinfo}@server.example:1080"));
        assert_eq!(root["outbounds"][0]["settings"]["pass"], "p%40ss+word");
    }
}

#[test]
fn accepts_exact_rfc1929_byte_limits_and_rejects_oversized_utf8() {
    let max = format!("{}a", "é".repeat(127));
    assert_eq!(max.len(), 255);
    for userinfo in [
        format!("{max}:{max}"),
        STANDARD.encode(format!("{max}:{max}")),
    ] {
        let root = config(&format!("socks://{userinfo}@server.example:1080"));
        assert_eq!(root["outbounds"][0]["settings"]["user"], max);
        assert_eq!(root["outbounds"][0]["settings"]["pass"], max);
    }
    for (user, pass) in [
        ("x".repeat(256), "p".into()),
        ("u".into(), "é".repeat(128)),
        ("".into(), "p".into()),
        ("u".into(), "".into()),
    ] {
        let plain = format!("{user}:{pass}");
        for userinfo in [plain.clone(), STANDARD.encode(plain)] {
            assert!(import_profile(
                ProfileFormat::Socks,
                &format!("socks://{userinfo}@server.example:1080"),
                None,
                &[]
            )
            .is_err());
        }
    }
}

#[test]
fn names_dns_and_json_request_use_the_shared_import_contract() {
    let imported = import_request(&json!({
        "format":"socks", "text":FIXTURE, "name":"Named + ✓", "dnsServers":["192.0.2.53", "2001:db8::53"]
    }).to_string()).unwrap();
    assert_eq!(imported.name, "Named + ✓");
    let root: Value = serde_json::from_str(&imported.config_json).unwrap();
    assert_eq!(
        root["dns"],
        json!({"servers":["192.0.2.53", "2001:db8::53"]})
    );
    let response: Value = serde_json::from_str(&imported.to_json().unwrap()).unwrap();
    assert_eq!(response["schemaVersion"], 1);
    assert_eq!(response["configJSON"], imported.config_json.as_str());
    assert_eq!(
        import_profile(
            ProfileFormat::Socks,
            "socks://server.example:1080#Name+%2520",
            None,
            &[]
        )
        .unwrap()
        .name,
        "Name+%20"
    );
    for dns in ["search.example", "0.0.0.0", "198.18.0.1", "fd00:7872::2"] {
        assert_eq!(
            import_profile(ProfileFormat::Socks, FIXTURE, None, &[dns.into()]).unwrap_err(),
            ImportError::Dns
        );
    }
    for suffix in ["%00", "%0A", "%FF", "bad%", "one#two"] {
        assert!(import_profile(
            ProfileFormat::Socks,
            &format!("socks://server.example:1080#{suffix}"),
            None,
            &[]
        )
        .is_err());
    }
    assert!(import_profile(
        ProfileFormat::Socks,
        &format!("socks://server.example:1080#{}", "x".repeat(129)),
        None,
        &[]
    )
    .is_err());
}

#[test]
fn rejects_ambiguous_unsupported_or_malformed_links_without_echoing_secrets() {
    for text in [
        "socks4://synthetic-secret:p@server.example:1080",
        "socks5h://synthetic-secret:p@server.example:1080",
        "http://synthetic-secret:p@server.example:1080",
        "socks://synthetic-secret:p@server.example",
        "socks://synthetic-secret:p@server.example:0",
        "socks://synthetic-secret:p@server.example:65536",
        "socks://synthetic-secret:p@server.example:+1080",
        "socks://synthetic-secret:p@server.example:1080/path",
        "socks://synthetic-secret:p@server.example:1080//",
        "socks://synthetic-secret:p@server.example:1080?security=tls",
        "socks://synthetic-secret:p@server.example:1080?udp=0",
        "socks://synthetic-secret:p@server.example:1080?unknown=1",
        "socks://synthetic-secret:p@@server.example:1080",
        "socks://synthetic-secret:p@2001:db8::1:1080",
        "socks://synthetic-secret:p@[fe80::1%25en0]:1080",
        "socks://synthetic-secret:p@[::ffff:192.0.2.1]:1080",
        "socks://synthetic-secret:p@0.0.0.0:1080",
        "socks://synthetic-secret:p@server.example:1080:1081",
        "socks://synthetic-secret%00:p@server.example:1080",
        "socks://synthetic-secret:p%0A@server.example:1080",
        "socks://synthetic-secret:p%FF@server.example:1080",
        "socks://synthetic-secret:p%@server.example:1080",
        "socks://synthetic-secret: p@server.example:1080",
        "socks://synthetic-secret:p\0@server.example:1080",
        "socks://@server.example:1080",
        "socks://c3ludGhldGljLXNlY3JldA==@server.example:1080", // no separator
        "socks://dTr/@server.example:1080",                     // invalid UTF-8
        "socks://dToA@server.example:1080",                     // decoded NUL
        "socks://dToK@server.example:1080",                     // decoded newline
        "socks://dTpw===@server.example:1080",                  // malformed padding
        "socks://c2VydmVyLmV4YW1wbGU6MTA4MA==",                 // legacy encoded authority
    ] {
        let err = import_profile(ProfileFormat::Socks, text, None, &[]).unwrap_err();
        assert!(!err.to_string().contains("synthetic-secret"));
        assert!(!format!("{err:?}").contains(text));
    }
}
