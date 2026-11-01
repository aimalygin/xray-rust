use serde_json::{json, Value};
use xray_config::profile_import::{import_profile, import_request, ImportError, ProfileFormat};

fn config(text: &str) -> Value {
    let profile = import_profile(ProfileFormat::Http, text, None, &[]).unwrap();
    assert_eq!(profile.format, ProfileFormat::Http);
    assert!(xray_config::parse_xray_json(&profile.config_json)
        .unwrap()
        .diagnostics
        .is_empty());
    serde_json::from_str(&profile.config_json).unwrap()
}

#[test]
fn http_authorities_defaults_and_tls_policy() {
    for (text, host, port, tls) in [
        ("http://Proxy.Example.", "Proxy.Example.", 80, false),
        ("HTTPS://Proxy.Example./", "Proxy.Example.", 443, true),
        ("http://192.0.2.7:8080", "192.0.2.7", 8080, false),
        ("https://[2001:db8::7]:8443", "2001:db8::7", 8443, true),
        ("https://[2001:db8::7]", "2001:db8::7", 443, true),
        (
            " \nHtTp://proxy.example:65535/?#\n",
            "proxy.example",
            65535,
            false,
        ),
    ] {
        let profile = import_profile(ProfileFormat::Http, text, None, &[]).unwrap();
        assert_eq!(profile.server_address, host);
        assert_eq!(profile.name, if tls { "HTTPS" } else { "HTTP" });
        let root = config(text);
        assert_eq!(root["inbounds"][0]["protocol"], "tun");
        assert_eq!(root["outbounds"].as_array().unwrap().len(), 1);
        let proxy = &root["outbounds"][0];
        assert_eq!(proxy["protocol"], "http");
        assert_eq!(proxy["settings"], json!({"address":host,"port":port}));
        assert_eq!(
            proxy["streamSettings"]["security"],
            if tls { "tls" } else { "none" }
        );
        if tls {
            assert_eq!(
                proxy["streamSettings"]["tlsSettings"],
                json!({"serverName":host,"alpn":["http/1.1"]})
            );
        } else {
            assert!(proxy["streamSettings"].get("tlsSettings").is_none());
        }
        assert_eq!(root["routing"]["domainStrategy"], "AsIs");
        assert_eq!(root["dns"]["fakeIp"]["enabled"], true);
    }
}

#[test]
fn http_credentials_decode_once_without_guessing_base64() {
    for (userinfo, user, pass) in [
        ("synthetic:p%40ss:%2B%E2%9C%93", "synthetic", "p@ss:+✓"),
        ("synthetic+user:p+%2540", "synthetic+user", "p+%40"),
        ("synthetic", "synthetic", ""),
        ("synthetic:", "synthetic", ""),
        ("c3ludGhldGljOnBhc3M=", "c3ludGhldGljOnBhc3M=", ""),
        ("Og==", "Og==", ""),
        ("synthetic:p%2F%5C", "synthetic", "p/\\"),
    ] {
        let root = config(&format!("https://{userinfo}@proxy.example"));
        assert_eq!(root["outbounds"][0]["settings"]["user"], user);
        assert_eq!(root["outbounds"][0]["settings"]["pass"], pass);
    }
    for (u, p) in [
        ("u".repeat(1024), "p".repeat(1024)),
        ("é".repeat(512), String::new()),
    ] {
        config(&format!("http://{u}:{p}@proxy.example"));
    }
    for (u, p) in [
        ("u".repeat(1025), "p".into()),
        ("é".repeat(513), "p".into()),
        ("u".into(), "p".repeat(1025)),
    ] {
        assert!(import_profile(
            ProfileFormat::Http,
            &format!("http://{u}:{p}@proxy.example"),
            None,
            &[]
        )
        .is_err());
    }
}

#[test]
fn http_dns_uses_tcp_and_names_are_shared_with_mobile() {
    let profile = import_request(
        &json!({"format":"http", "text":"https://proxy.example/#Test%20%E2%9C%93",
        "dnsServers":["192.0.2.53","2001:db8::53"]})
        .to_string(),
    )
    .unwrap();
    assert_eq!(profile.name, "Test ✓");
    let root: Value = serde_json::from_str(&profile.config_json).unwrap();
    assert_eq!(
        root["dns"],
        json!({"servers":["tcp://192.0.2.53:53","tcp://[2001:db8::53]:53"]})
    );
    assert_eq!(
        import_profile(
            ProfileFormat::Http,
            "http://proxy.example#URI",
            Some("Override ✓"),
            &[]
        )
        .unwrap()
        .name,
        "Override ✓"
    );
    for ip in [
        "dns.example",
        "tcp://192.0.2.53",
        "0.0.0.0",
        "198.18.0.1",
        "::",
        "ff02::1",
    ] {
        assert!(import_profile(
            ProfileFormat::Http,
            "http://proxy.example",
            None,
            &[ip.into()]
        )
        .is_err());
    }
    assert!(import_profile(
        ProfileFormat::Http,
        "http://proxy.example",
        None,
        &vec!["192.0.2.53".into(); 9]
    )
    .is_err());
}

#[test]
fn http_refuses_legacy_base64_authorities_but_keeps_one_label_hosts() {
    // Base64 of `secret:secret@198.51.100.7:8080`, `secret:password@proxy.example:8443`
    // and `secret@192.0.2.1:3128`: imported as one-label hosts, they would go to DNS.
    for text in [
        "http://c2VjcmV0OnNlY3JldEAxOTguNTEuMTAwLjc6ODA4MA",
        "https://c2VjcmV0OnBhc3N3b3JkQHByb3h5LmV4YW1wbGU6ODQ0Mw#Office",
        "http://c2VjcmV0QDE5Mi4wLjIuMTozMTI4/",
    ] {
        let error = import_profile(ProfileFormat::Http, text, None, &[]).unwrap_err();
        assert!(
            matches!(error, ImportError::Unsupported),
            "{text}: {error:?}"
        );
        assert!(!error.to_string().contains("secret"));
    }
    // Labels that are not an encoded authority, including valid Base64 of `abcd`.
    for host in ["proxy", "gateway1", "YWJjZA"] {
        let root = config(&format!("http://{host}"));
        assert_eq!(root["outbounds"][0]["settings"]["address"], host);
    }
}

#[test]
fn http_rejects_ambiguous_or_unsupported_links_without_leaking_secrets() {
    for text in [
        "socks://proxy.example:80",
        "http://",
        "https://:443",
        "http://proxy.example:",
        "http://proxy.example:0",
        "https://proxy.example:65536",
        "http://proxy.example:+80",
        "http://2001:db8::7:80",
        "http://[fe80::1%25en0]:80",
        "http://proxy.example/path",
        "https://proxy.example?allowInsecure=1",
        "http://proxy.example?type=ws",
        "http://@proxy.example",
        "http://:secret@proxy.example",
        "http://:@proxy.example",
        "http://secret%3Auser:p@proxy.example",
        "http://secret%00:p@proxy.example",
        "http://secret:p%0D%0A@proxy.example",
        "http://secret%FF:p@proxy.example",
        "http://secret%:p@proxy.example",
        "http://secret/p:q@proxy.example",
        "http://secret:p@x@proxy.example",
        "http://proxy.example#one#two",
        "http://proxy.example#secret%00",
        "http://proxy.example#secret%FF",
        "http://secret user:p@proxy.example",
        "http://proxy.example//",
    ] {
        let error = import_profile(ProfileFormat::Http, text, None, &[]).unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }
    for length in [129, 65537] {
        assert!(import_profile(
            ProfileFormat::Http,
            &format!("http://proxy.example#{}", "n".repeat(length)),
            None,
            &[]
        )
        .is_err());
    }
}
