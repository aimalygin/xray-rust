use serde_json::{json, Value};
use xray_config::parse_xray_json;

fn config(stream: Value) -> String {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":stream}]})
    .to_string()
}

fn tcp(masks: Value) -> String {
    config(
        json!({"network":"raw","security":"tls","tlsSettings":{"serverName":"server.example"},
        "finalmask":{"tcp":masks}}),
    )
}

fn errors(text: &str) -> Vec<String> {
    parse_xray_json(text)
        .unwrap_err()
        .diagnostics
        .into_iter()
        .map(|d| d.message)
        .collect()
}

fn profile() -> Value {
    json!({"username":"Steve_1","uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f",
        "texturesValue":"dGV4dHVyZXM=","texturesSignature":"c2lnbmF0dXJl"})
}

fn xmc(settings: Value) -> String {
    tcp(json!([{"type":"XMC","settings":settings}]))
}

#[test]
fn settings_read_as_xmc_build_reads_them() {
    let parsed = parse_xray_json(&xmc(json!({"hostname":"mc.example.com",
        "password":"secret","profiles":[profile(), brace_profile()]})))
    .unwrap();
    let mask = parsed.config.outbounds[0].stream.tcp_xmc.clone().unwrap();
    assert_eq!(mask.hostname, "mc.example.com");
    assert_eq!(mask.password.as_str(), "secret");
    assert_eq!(mask.profiles.len(), 2);
    let steve = &mask.profiles[0];
    assert_eq!(steve.username, "Steve_1");
    assert_eq!(steve.uuid, core::array::from_fn(|i| i as u8));
    assert_eq!(steve.textures_value, "dGV4dHVyZXM=");
    assert_eq!(steve.textures_signature, "c2lnbmF0dXJl");
    assert_eq!(mask.profiles[1].uuid, [0xab; 16]);
    assert!(!format!("{mask:?}").contains("secret"));
    // A null host name is empty: the handshake then names the server's IP.
    let parsed = parse_xray_json(&xmc(
        json!({"hostname":null,"password":"secret","profiles":[profile()]}),
    ))
    .unwrap();
    assert_eq!(
        parsed.config.outbounds[0]
            .stream
            .tcp_xmc
            .as_ref()
            .unwrap()
            .hostname,
        ""
    );
}

fn brace_profile() -> Value {
    json!({"username":"abc","uuid":"{abababab-abab-abab-abab-abababababab}",
        "texturesValue":"v","texturesSignature":"s"})
}

#[test]
fn uuids_read_as_google_uuid_reads_them() {
    let id: [u8; 16] = core::array::from_fn(|i| i as u8);
    for uuid in [
        "00010203-0405-0607-0809-0a0b0c0d0e0f",
        "000102030405060708090A0B0C0D0E0F",
        "urn:uuid:00010203-0405-0607-0809-0a0b0c0d0e0f",
        "(00010203-0405-0607-0809-0a0b0c0d0e0f)",
    ] {
        let mut steve = profile();
        steve["uuid"] = json!(uuid);
        let parsed =
            parse_xray_json(&xmc(json!({"password":"secret","profiles":[steve]}))).unwrap();
        let mask = parsed.config.outbounds[0].stream.tcp_xmc.clone().unwrap();
        assert_eq!(mask.profiles[0].uuid, id, "{uuid}");
    }
}

#[test]
fn incomplete_settings_are_refused_as_xray_core_refuses_them() {
    let with = |key: &str, value: Value| {
        let mut steve = profile();
        steve[key] = value;
        json!({"password":"secret","profiles":[steve]})
    };
    for (settings, expected) in [
        (json!(null), "minecraft profiles are required"),
        (
            json!({"password":"secret"}),
            "minecraft profiles are required",
        ),
        (
            json!({"password":"secret","profiles":[]}),
            "minecraft profiles are required",
        ),
        (json!({"profiles":[profile()]}), "empty password"),
        (
            json!({"password":"secret","profiles":[null]}),
            "invalid minecraft profile username",
        ),
        (
            with("username", json!("ab")),
            "invalid minecraft profile username",
        ),
        (
            with("username", json!("abcdefghijklmnopq")),
            "invalid minecraft profile username",
        ),
        (
            with("username", json!("Stéve")),
            "invalid minecraft profile username",
        ),
        (
            with("uuid", json!("my-short-id")),
            "invalid minecraft profile UUID",
        ),
        (with("uuid", json!(null)), "invalid minecraft profile UUID"),
        (
            with("texturesValue", json!("")),
            "incomplete minecraft profile textures",
        ),
        (
            with("texturesSignature", json!(null)),
            "incomplete minecraft profile textures",
        ),
        (with("username", json!(5)), "must be a string or null"),
        (
            json!({"password":"secret","profiles":{}}),
            "must be an array or null",
        ),
        (
            json!({"password":"secret","profiles":["Steve"]}),
            "must be an object or null",
        ),
        (json!("xmc"), "xmc settings must be an object or null"),
        (with("skin", json!("x")), "unsupported field `skin`"),
        (
            json!({"password":"secret","profiles":[profile()],"seed":1}),
            "unsupported field `seed`",
        ),
    ] {
        let errors = errors(&xmc(settings.clone()));
        assert!(
            errors.iter().any(|e| e.contains(expected)),
            "{settings}: {errors:?}"
        );
    }
}

#[test]
fn a_password_too_long_to_send_is_refused() {
    let longest = "p".repeat(113);
    assert!(parse_xray_json(&xmc(json!({"password":longest,"profiles":[profile()]}))).is_ok());
    // 113 bytes in Cyrillic letters of two bytes each is 56 letters and one byte too many.
    let too_long = "п".repeat(57);
    assert!(
        errors(&xmc(json!({"password":too_long,"profiles":[profile()]})))
            .iter()
            .any(|e| e.contains("at most 113 bytes"))
    );
}

#[test]
fn xmc_is_the_last_tcp_mask() {
    let header = json!({"type":"header-custom","settings":{"clients":[[{"packet":[1]}]]}});
    let fragment = json!({"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}});
    let xmc = json!({"type":"xmc","settings":{"password":"secret","profiles":[profile()]}});
    let sudoku = json!({"type":"sudoku","settings":{"password":"secret"}});
    let parsed = parse_xray_json(&tcp(json!([fragment, header, xmc]))).unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    assert!(stream.tcp_fragment.is_some());
    assert!(stream.tcp_header_custom.is_some());
    assert!(stream.tcp_xmc.is_some());
    for (masks, expected) in [
        (json!([xmc, header]), "xmc must be the last TCP mask"),
        (json!([xmc, xmc]), "xmc must be the last TCP mask"),
        (json!([xmc, sudoku]), "xmc must be the last TCP mask"),
        (json!([sudoku, xmc]), "sudoku must be the last TCP mask"),
    ] {
        assert!(
            errors(&tcp(masks.clone()))
                .iter()
                .any(|e| e.contains(expected)),
            "{masks}"
        );
    }
}

#[test]
fn reality_cannot_run_over_xmc() {
    let xmc = json!({"type":"xmc","settings":{"password":"secret","profiles":[profile()]}});
    let reality = config(json!({"network":"raw","security":"reality",
        "realitySettings":{"serverName":"server.example","fingerprint":"chrome",
            "publicKey":"E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM","shortId":"0123"},
        "finalmask":{"tcp":[xmc]}}));
    assert!(errors(&reality)
        .iter()
        .any(|e| e.contains("REALITY cannot run over an xmc mask")));
}
