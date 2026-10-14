use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
fn rejects_legacy_cipher_plugins_missing_ports_and_bad_keys() {
    for uri in [
        "ss://aes-128-gcm:synthetic-secret@example.test:8388",
        "ss://2022-blake3-aes-128-gcm:synthetic-secret@example.test:8388",
        "ss://2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ==@example.test",
        "ss://2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ==@example.test:8388?plugin=obfs",
        "ss://%FF@example.test:8388",
    ] {
        let error = import_profile(ProfileFormat::Shadowsocks2022, uri, None, &[]).unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret"));
    }
}
