use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use xray_config::profile_import::{import_profile, ProfileFormat};

const ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
fn link() -> Value {
    json!({"v":"2","ps":"Test ✓","add":"vmess.example","port":"443","id":ID,"aid":"0","scy":"chacha20-poly1305","net":"ws","type":"none","host":"front.example","path":"/a+b","tls":"tls","sni":"tls.example","alpn":"http/1.1"})
}
#[test]
fn vmess_json_and_uri_dialects_preserve_credentials_and_transport() {
    let source = link().to_string();
    for text in [format!("vmess://{}", STANDARD.encode(&source)), format!("vmess://{}", URL_SAFE_NO_PAD.encode(&source)),
        format!("vmess://{ID}@vmess.example:443?encryption=chacha20-poly1305&type=ws&host=front.example&path=%2Fa+b&security=tls&sni=tls.example&alpn=http%2F1.1#Test%20%E2%9C%93")] {
        let profile = import_profile(ProfileFormat::Vmess, &text, None, &[]).unwrap();
        assert_eq!(profile.name, "Test ✓");
        assert_eq!(profile.server_address, "vmess.example");
        let root: Value = serde_json::from_str(&profile.config_json).unwrap();
        let outbound = &root["outbounds"][0];
        assert_eq!(outbound["settings"]["id"], ID);
        assert_eq!(outbound["settings"]["security"], "chacha20-poly1305");
        assert_eq!(outbound["streamSettings"]["wsSettings"]["path"], "/a+b");
        assert_eq!(outbound["streamSettings"]["tlsSettings"]["serverName"], "tls.example");
        assert!(!format!("{profile:?}").contains(ID));
    }
}
#[test]
fn vmess_ipv6_numeric_fields_grpc_and_fragment_override() {
    let mut source = link();
    for (k, v) in [
        ("add", json!("2001:db8::8")),
        ("port", json!(8443)),
        ("aid", json!(0)),
        ("net", json!("grpc")),
        ("type", json!("gun")),
        ("path", json!("service")),
        ("alpn", json!("h2")),
    ] {
        source[k] = v;
    }
    let profile = import_profile(
        ProfileFormat::Vmess,
        &format!("vmess://{}#Override", STANDARD.encode(source.to_string())),
        None,
        &[],
    )
    .unwrap();
    assert_eq!(profile.name, "Override");
    let root: Value = serde_json::from_str(&profile.config_json).unwrap();
    assert_eq!(
        root["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"],
        "service"
    );
    let uri = format!("vmess://{ID}@[2001:db8::8]:8443?scy=aes-128-gcm&aid=0");
    assert_eq!(
        import_profile(ProfileFormat::Vmess, &uri, None, &[])
            .unwrap()
            .server_address,
        "2001:db8::8"
    );
}
#[test]
fn vmess_rejects_duplicate_aliases_legacy_auth_unsafe_tls_and_malformed_json() {
    let mut cases = vec![
        format!("vmess://{ID}@example.test?aid=0&alterId=0"),
        format!("vmess://{ID}@example.test?encryption=auto&scy=auto"),
        format!("vmess://{ID}@example.test?security=tls&allowInsecure=true"),
        format!("vmess://{ID}@example.test?type=tcp&host=ignored.example"),
        "vmess://%%%".into(),
        format!(
            "vmess://{}",
            STANDARD.encode(format!(r#"{{"id":"{ID}","id":"{ID}"}}"#))
        ),
    ];
    for (k, v) in [
        ("aid", json!(1)),
        ("scy", json!("none")),
        ("v", json!("1")),
        ("type", json!("http")),
        ("unknown", json!("synthetic-secret")),
        ("id", json!({"nested":true})),
        ("port", json!(65536)),
    ] {
        let mut source = link();
        source[k] = v;
        cases.push(format!("vmess://{}", STANDARD.encode(source.to_string())));
    }
    for text in cases {
        let error = import_profile(ProfileFormat::Vmess, &text, None, &[]).unwrap_err();
        assert!(!format!("{error:?}").contains(ID));
        assert!(!format!("{error:?}").contains("synthetic-secret"));
    }
}
