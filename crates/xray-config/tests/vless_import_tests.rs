use serde_json::Value;
use xray_config::profile_import::{import_profile, ImportError, ProfileFormat};

const ID: &str = "6c027102-b0fb-4e85-a77c-9a0a8607101b";
const PBK: &str = "kZ4NDkIZkxCcdw0iPsMfsjun8jdTfh4ngEuPlJ4yUY8";
const ENCRYPTION_KEY: &str = "lg4KZ0UKj0A31Ub9ujqmFfY18928RLo9VCOqY_6VNkk";

fn import(link: &str) -> Result<Value, ImportError> {
    let profile = import_profile(ProfileFormat::Vless, link, None, &[])?;
    assert!(xray_config::parse_xray_json(&profile.config_json).is_ok());
    assert!(!format!("{profile:?}").contains(ID));
    Ok(serde_json::from_str(&profile.config_json).unwrap())
}

fn proxy(config: &Value) -> &Value {
    &config["outbounds"][0]
}

fn user(config: &Value) -> &Value {
    &proxy(config)["settings"]["vnext"][0]["users"][0]
}

fn stream(config: &Value) -> &Value {
    &proxy(config)["streamSettings"]
}

fn reality_link() -> String {
    format!(
        "vless://{ID}@192.0.2.10:32134?type=tcp&encryption=none&security=reality&pbk={PBK}\
         &fp=chrome&sni=example.com&sid=6a75829e&spx=%2F&flow=xtls-rprx-vision\
         &headerType=none#example%20reality%20%E2%9C%93"
    )
}

#[test]
fn vless_reality_vision_link_imports_with_name_and_flow() {
    let profile = import_profile(ProfileFormat::Vless, &reality_link(), None, &[]).unwrap();
    assert_eq!(profile.name, "example reality ✓");
    assert_eq!(profile.server_address, "192.0.2.10");
    let config: Value = serde_json::from_str(&profile.config_json).unwrap();
    let proxy = proxy(&config);
    assert_eq!(proxy["protocol"], "vless");
    let server = &proxy["settings"]["vnext"][0];
    assert_eq!(server["address"], "192.0.2.10");
    assert_eq!(server["port"], 32134);
    assert_eq!(user(&config)["id"], ID);
    assert_eq!(user(&config)["encryption"], "none");
    assert_eq!(user(&config)["flow"], "xtls-rprx-vision");
    let stream = &proxy["streamSettings"];
    assert_eq!(stream["security"], "reality");
    let reality = &stream["realitySettings"];
    assert_eq!(reality["serverName"], "example.com");
    assert_eq!(reality["publicKey"], PBK);
    assert_eq!(reality["fingerprint"], "chrome");
    assert_eq!(reality["shortId"], "6a75829e");
    assert_eq!(reality["spiderX"], "/");
    assert!(xray_config::parse_xray_json(&profile.config_json).is_ok());
}

#[test]
fn vless_link_names_the_profile_after_the_endpoint_without_a_fragment() {
    let link = format!("vless://{ID}@[2001:db8::10]:443?type=xhttp&security=tls&sni=example.com");
    let profile = import_profile(ProfileFormat::Vless, &link, None, &[]).unwrap();
    assert_eq!(profile.name, "[2001:db8::10]:443");
    assert_eq!(profile.server_address, "2001:db8::10");
    let config = import(&link).unwrap();
    assert_eq!(
        proxy(&config)["settings"]["vnext"][0]["address"],
        "2001:db8::10"
    );
    let named = import_profile(ProfileFormat::Vless, &link, Some("Override"), &[]).unwrap();
    assert_eq!(named.name, "Override");
}

#[test]
fn vless_tls_links_import_across_transports() {
    let tls = "security=tls&sni=example.com&fp=firefox&alpn=h2%2Chttp%2F1.1";
    for (query, network, block) in [
        ("type=tcp&flow=xtls-rprx-vision-udp443", "tcp", None),
        ("type=raw&headerType=none&allowInsecure=0", "raw", None),
        (
            "type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048",
            "ws",
            Some(("wsSettings", "path", "/ws?ed=2048")),
        ),
        (
            "type=httpupgrade&host=cdn.example.com&path=%2Fup",
            "httpupgrade",
            Some(("httpupgradeSettings", "path", "/up")),
        ),
        // The Kotlin importer's vector: Xray-core accepts `ed` on HTTPUpgrade.
        (
            "type=httpupgrade&host=cdn.example.com&path=%2Fws%3Fed%3D2048",
            "httpupgrade",
            Some(("httpupgradeSettings", "path", "/ws?ed=2048")),
        ),
        (
            "type=grpc&serviceName=tunnel&authority=cdn.example.com&mode=multi",
            "grpc",
            Some(("grpcSettings", "serviceName", "tunnel")),
        ),
        (
            "type=xhttp&host=cdn.example.com&path=%2Fx&mode=stream-up",
            "xhttp",
            Some(("xhttpSettings", "mode", "stream-up")),
        ),
        (
            "type=splithttp&path=%2Fx",
            "splithttp",
            Some(("xhttpSettings", "path", "/x")),
        ),
    ] {
        let link = format!("vless://{ID}@example.com:443?{tls}&{query}");
        let config = import(&link).unwrap_or_else(|e| panic!("{query}: {e}"));
        let stream = stream(&config);
        assert_eq!(stream["network"], network, "{query}");
        assert_eq!(stream["security"], "tls", "{query}");
        assert_eq!(stream["tlsSettings"]["serverName"], "example.com");
        assert_eq!(stream["tlsSettings"]["fingerprint"], "firefox");
        assert_eq!(
            stream["tlsSettings"]["alpn"],
            serde_json::json!(["h2", "http/1.1"])
        );
        if let Some((block, field, value)) = block {
            assert_eq!(stream[block][field], value, "{query}");
        }
    }
}

#[test]
fn vless_reality_over_grpc_and_xhttp_defaults_the_server_name() {
    for query in [
        "type=grpc&serviceName=tunnel&mode=gun",
        "type=xhttp&path=%2Freality&mode=stream-one&alpn=h2",
    ] {
        let link = format!(
            "vless://{ID}@reality.example.com:443?security=reality&pbk={PBK}&fp=chrome&sid=&{query}"
        );
        let config = import(&link).unwrap_or_else(|e| panic!("{query}: {e}"));
        let reality = &stream(&config)["realitySettings"];
        assert_eq!(reality["serverName"], "reality.example.com");
        assert_eq!(reality["shortId"], "");
        assert!(stream(&config).get("tlsSettings").is_none());
    }
}

#[test]
fn vless_reality_without_sid_uses_the_empty_short_id() {
    // Xray-core reads a missing shortId as the empty one.
    for query in ["type=grpc&serviceName=tunnel", "type=tcp&fp=chrome"] {
        let link = format!("vless://{ID}@example.com:443?security=reality&pbk={PBK}&{query}");
        let config = import(&link).unwrap_or_else(|e| panic!("{query}: {e}"));
        assert_eq!(stream(&config)["realitySettings"]["shortId"], "", "{query}");
    }
}

#[test]
fn vless_xhttp_h3_needs_the_chrome_parrot_acknowledgement() {
    let link = format!("vless://{ID}@example.com:443?type=xhttp&security=tls&alpn=h3");
    assert_eq!(import(&link).unwrap_err(), ImportError::Configuration);
    let config = import(&format!(
        "{link}&fm=%7B%22quicParams%22%3A%7B%22disableChromeParrot%22%3Atrue%7D%7D"
    ))
    .unwrap();
    assert_eq!(
        stream(&config)["tlsSettings"]["alpn"],
        serde_json::json!(["h3"])
    );
}

#[test]
fn vless_flow_is_stored_with_the_user() {
    let config = import(&reality_link()).unwrap();
    assert_eq!(
        user(&config),
        &serde_json::json!({"id": ID, "encryption": "none", "flow": "xtls-rprx-vision"})
    );
}

#[test]
fn vless_query_names_are_case_insensitive_and_unknown_ones_ignored() {
    let link = format!(
        "vless://{ID}@example.com:443?TYPE=ws&Security=tls&SNI=example.com\
         &packetEncoding=xudp&spiderx=ignored&host=&path=%2Fws"
    );
    let config = import(&link).unwrap();
    assert_eq!(stream(&config)["network"], "ws");
    assert_eq!(stream(&config)["wsSettings"]["path"], "/ws");
    assert_eq!(stream(&config)["tlsSettings"]["serverName"], "example.com");
}

#[test]
fn vless_xhttp_extra_imports_once_or_twice_encoded() {
    let once = "%7B%22noGRPCHeader%22%3Afalse%2C%22xmux%22%3A%7B%22maxConnections%22%3A16%7D%7D";
    let twice = once.replace('%', "%25");
    for extra in [once.to_owned(), twice] {
        let link =
            format!("vless://{ID}@example.com:443?type=xhttp&security=tls&path=%2F&extra={extra}");
        let config = import(&link).unwrap();
        let xhttp = &stream(&config)["xhttpSettings"];
        assert_eq!(xhttp["extra"]["noGRPCHeader"], false);
        assert_eq!(xhttp["extra"]["xmux"]["maxConnections"], 16);
    }
    let thrice = once.replace('%', "%2525");
    let link = format!("vless://{ID}@example.com:443?type=xhttp&security=tls&extra={thrice}");
    assert_eq!(import(&link).unwrap_err(), ImportError::Syntax);
}

#[test]
fn vless_final_mask_reaches_every_transport() {
    let mask = "%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%2C%22settings%22%3A%7B%22packets%22%3A%22tlshello%22%2C%22length%22%3A%22100-200%22%7D%7D%5D%7D";
    for query in [
        "type=tcp&security=tls".to_owned(),
        format!("type=tcp&security=reality&pbk={PBK}&fp=chrome&sni=example.com&sid=0123"),
        "type=xhttp&security=tls&path=%2F".to_owned(),
        "type=ws&security=tls&path=%2Fws".to_owned(),
        "type=grpc&security=tls&serviceName=svc".to_owned(),
    ] {
        let config = import(&format!("vless://{ID}@192.0.2.10:443?{query}&FM={mask}")).unwrap();
        assert_eq!(
            stream(&config)["finalmask"]["tcp"][0]["type"],
            "fragment",
            "{query}"
        );
    }
    let empty = import(&format!(
        "vless://{ID}@192.0.2.10:443?type=tcp&security=tls&fm="
    ))
    .unwrap();
    assert!(stream(&empty).get("finalmask").is_none());
    for bad in ["%5B%5D", "null", "%7Bbroken"] {
        let link = format!("vless://{ID}@192.0.2.10:443?type=tcp&security=tls&fm={bad}");
        assert_eq!(import(&link).unwrap_err(), ImportError::Syntax, "{bad}");
    }
}

#[test]
fn vless_encryption_carries_vision_over_any_carrier() {
    let encryption = format!("mlkem768x25519plus.native.0rtt.{ENCRYPTION_KEY}");
    for query in ["type=tcp&security=none", "type=ws&security=tls&path=%2Fws"] {
        let link = format!(
            "vless://{ID}@example.com:443?{query}&encryption={encryption}&flow=xtls-rprx-vision"
        );
        let config = import(&link).unwrap_or_else(|e| panic!("{query}: {e}"));
        assert_eq!(user(&config)["encryption"], encryption.as_str());
        assert_eq!(user(&config)["flow"], "xtls-rprx-vision");
    }
}

#[test]
fn vless_cleartext_follows_the_parser_policy() {
    // Plaintext VLESS reaches only private destinations, as in Xray-core.
    let private = import(&format!(
        "vless://{ID}@edge.example:80?type=xhttp&security=none&sni=ignored.example"
    ))
    .unwrap();
    assert_eq!(stream(&private)["security"], "none");
    assert_eq!(
        import(&format!(
            "vless://{ID}@192.0.2.20:80?type=xhttp&security=none"
        ))
        .unwrap_err(),
        ImportError::Configuration
    );
}

/// IDs read as Xray-core's `uuid.ParseString` reads them, as in VMess links:
/// a UUID without its hyphens, and 1 to 30 bytes of text.
#[test]
fn vless_ids_read_as_xray_core_reads_them() {
    for id in ["my-short-id".to_owned(), ID.replace('-', "")] {
        let link = format!("vless://{id}@example.com:443?security=tls");
        let profile = import_profile(ProfileFormat::Vless, &link, None, &[])
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(!format!("{profile:?}").contains(&id));
        let config: Value = serde_json::from_str(&profile.config_json).unwrap();
        assert_eq!(user(&config)["id"], id.as_str());
    }
}

#[test]
fn vless_rejects_malformed_links() {
    for (link, expected) in [
        // 31 bytes, and no bytes, name no ID, in Xray-core or here.
        (
            "vless://1234567890123456789012345678901@example.com:443?security=tls".to_owned(),
            ImportError::Configuration,
        ),
        (
            "vless://@example.com:443?security=tls".to_owned(),
            ImportError::Configuration,
        ),
        (
            format!("vless://{ID}@example.com?security=tls"),
            ImportError::Syntax,
        ),
        (
            format!("vless://{ID}@example.com:0?security=tls"),
            ImportError::Syntax,
        ),
        (
            format!("vless://{ID}@example.com:65536?security=tls"),
            ImportError::Syntax,
        ),
        (
            format!("vless://{ID}@[192.0.2.1]:443?security=tls"),
            ImportError::Syntax,
        ),
        (
            format!("vless://{ID}@example.com:443?security=tls#a#b"),
            ImportError::Syntax,
        ),
        (
            format!("vless://{ID}@example.com:443?security=tls&host=%zz"),
            ImportError::Syntax,
        ),
        (
            format!("vmess://{ID}@example.com:443?security=tls"),
            ImportError::Unsupported,
        ),
        (
            format!(
                "vless://{ID}@example.com:443?security=tls&sni=a.example.com&sni=b.example.com"
            ),
            ImportError::Duplicate,
        ),
    ] {
        assert_eq!(import(&link).unwrap_err(), expected, "{link}");
    }
}

#[test]
fn vless_rejects_unsupported_security_transport_and_flow() {
    let reality = format!("security=reality&pbk={PBK}&fp=chrome&sid=");
    for (query, parameter) in [
        (
            "type=ws&security=tls&flow=xtls-rprx-vision".to_owned(),
            "flow",
        ),
        (
            "type=grpc&security=tls&flow=xtls-rprx-vision".to_owned(),
            "flow",
        ),
        (
            "type=tcp&security=tls&flow=xtls-rprx-direct".to_owned(),
            "flow",
        ),
        ("type=ws&".to_owned() + &reality, "security"),
        ("type=httpupgrade&".to_owned() + &reality, "security"),
        ("type=xhttp&alpn=http%2F1.1&".to_owned() + &reality, "alpn"),
        (
            "type=tcp&security=tls&allowInsecure=1".to_owned(),
            "allowInsecure",
        ),
        (
            "type=ws&security=tls&allowInsecure=true".to_owned(),
            "allowInsecure",
        ),
        ("type=tcp&security=tls&encryption=".to_owned(), "encryption"),
        ("type=tcp&security=tls&pbk=".to_owned() + PBK, "pbk"),
        ("type=xhttp&security=tls&sid=".to_owned(), "sid"),
        ("type=tcp&security=tls&ech=sensitive".to_owned(), "ech"),
        ("type=ws&security=tls&extra=%7B%7D".to_owned(), "extra"),
        (
            "type=ws&security=tls&serviceName=tunnel".to_owned(),
            "serviceName",
        ),
        (
            "type=grpc&security=tls&host=cdn.example.com".to_owned(),
            "host",
        ),
        ("type=grpc&security=tls&mode=guna".to_owned(), "mode"),
        (
            "type=tcp&security=tls&headerType=http".to_owned(),
            "headerType",
        ),
        ("type=tcp&security=tls&alpn=".to_owned(), "alpn"),
        (
            "type=tcp&security=tls&alpn=h2%2C%2Chttp%2F1.1".to_owned(),
            "alpn",
        ),
        (
            "type=ws&security=tls&alpn=h2%2C%20http%2F1.1".to_owned(),
            "alpn",
        ),
        (
            "type=tcp&security=tls&cs=TLS_AES_128_GCM_SHA256".to_owned(),
            "cs",
        ),
        (
            "type=grpc&cs=TLS_AES_128_GCM_SHA256&".to_owned() + &reality,
            "cs",
        ),
    ] {
        let link = format!("vless://{ID}@example.com:443?{query}");
        assert_eq!(
            import(&link).unwrap_err(),
            ImportError::UnsupportedParameter(parameter),
            "{query}"
        );
    }
    for query in [
        "type=tcp&security=xtls",
        "type=kcp&security=tls",
        "type=tcp&security=",
    ] {
        let link = format!("vless://{ID}@example.com:443?{query}");
        assert_eq!(
            import(&link).unwrap_err(),
            ImportError::Unsupported,
            "{query}"
        );
    }
}

#[test]
fn vless_rejects_reality_without_key_and_invalid_parser_values() {
    for query in [
        // REALITY needs its public key.
        "type=tcp&security=reality&sni=example.com&fp=chrome&sid=".to_owned(),
        // Xray-core takes only an empty spiderX or a path.
        format!("type=tcp&security=reality&pbk={PBK}&sni=example.com&fp=chrome&spx=crawl"),
        "type=tcp&security=tls&encryption=mlkem768x25519plus.native.1rtt.short".to_owned(),
        "type=xhttp&security=tls&mode=burst".to_owned(),
    ] {
        let link = format!("vless://{ID}@example.com:443?{query}");
        assert_eq!(
            import(&link).unwrap_err(),
            ImportError::Configuration,
            "{query}"
        );
    }
}

#[test]
fn vless_import_request_uses_the_format_name() {
    let request = serde_json::json!({
        "format": "vless",
        "text": reality_link(),
        "dnsServers": ["192.0.2.53"],
    });
    let profile = xray_config::profile_import::import_request(&request.to_string()).unwrap();
    assert_eq!(profile.format, ProfileFormat::Vless);
    let config: Value = serde_json::from_str(&profile.config_json).unwrap();
    assert_eq!(config["dns"]["servers"], serde_json::json!(["192.0.2.53"]));
}
