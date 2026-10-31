use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use xray_config::profile_import::{import_profile, ProfileFormat};
#[test]
fn sip002_plain_and_base64_userinfo_preserve_key_chains_ipv6_and_names() {
    let credentials = "2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ==:AgICAgICAgICAgICAgICAg==";
    for user in [credentials.to_owned(), URL_SAFE_NO_PAD.encode(credentials)] {
        let uri = format!("ss://{user}@[2001:db8::8]:8388/#Test%20%E2%9C%93");
        let profile = import_profile(ProfileFormat::Shadowsocks2022, &uri, None, &[]).unwrap();
        assert_eq!(profile.name, "Test ✓");
        assert_eq!(profile.server_address, "2001:db8::8");
        assert!(profile
            .config_json
            .contains("AQEBAQEBAQEBAQEBAQEBAQ==:AgICAgICAgICAgICAgICAg=="));
        assert!(!format!("{profile:?}").contains("AQEB"));
    }
}
#[test]
fn rejects_unsupported_ciphers_plugins_missing_ports_and_bad_keys() {
    let empty = URL_SAFE_NO_PAD.encode("aes-128-gcm:");
    let none = URL_SAFE_NO_PAD.encode("none:synthetic-secret");
    for uri in [
        "ss://none:synthetic-secret@example.test:8388",
        "ss://plain:synthetic-secret@example.test:8388",
        "ss://rc4-md5:synthetic-secret@example.test:8388",
        "ss://aes-128-cfb:synthetic-secret@example.test:8388",
        "ss://aes-128-gcm@example.test:8388",
        "ss://aes-128-gcm:synthetic-secret@example.test",
        "ss://aes-128-gcm:synthetic-secret@example.test:8388/?plugin=v2ray-plugin",
        &format!("ss://{empty}@example.test:8388"),
        &format!("ss://{none}@example.test:8388"),
        "ss://2022-blake3-aes-128-gcm:synthetic-secret@example.test:8388",
        "ss://2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ==@example.test",
        "ss://2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ==@example.test:8388?plugin=obfs",
        "ss://%FF@example.test:8388",
    ] {
        let error = import_profile(ProfileFormat::Shadowsocks2022, uri, None, &[]).unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret"));
    }
}

#[test]
fn sip002_aead_links_import_base64url_padded_and_plain_userinfo() {
    let credentials = "chacha20-ietf-poly1305:synthetic:pass+word/=";
    for user in [
        URL_SAFE_NO_PAD.encode(credentials),
        URL_SAFE.encode(credentials),
        STANDARD.encode(credentials),
        "chacha20-ietf-poly1305:synthetic%3Apass%2Bword%2F%3D".to_owned(),
    ] {
        let uri = format!("ss://{user}@192.0.2.8:8388#");
        let profile = import_profile(ProfileFormat::Shadowsocks2022, &uri, None, &[]).unwrap();
        assert_eq!(profile.name, "Shadowsocks");
        assert_eq!(profile.server_address, "192.0.2.8");
        let config: serde_json::Value = serde_json::from_str(&profile.config_json).unwrap();
        let settings = &config["outbounds"][0]["settings"];
        assert_eq!(settings["method"], "chacha20-ietf-poly1305");
        assert_eq!(settings["password"], "synthetic:pass+word/=");
        assert!(!format!("{profile:?}").contains("synthetic"));
    }
    for method in [
        "aes-128-gcm",
        "AES-256-GCM",
        "chacha20-poly1305",
        "xchacha20-poly1305",
    ] {
        let user = URL_SAFE_NO_PAD.encode(format!("{method}:synthetic-secret"));
        let uri = format!("ss://{user}@example.test:8388/#Classic");
        let profile = import_profile(ProfileFormat::Shadowsocks2022, &uri, None, &[]).unwrap();
        assert_eq!(profile.name, "Classic");
    }
}
