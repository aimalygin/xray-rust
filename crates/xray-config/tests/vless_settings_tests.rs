//! VLESS and VMess outbound settings, read as Xray-core v26.10.31 reads them.
use serde_json::{json, Value};
use uuid::Uuid;
use xray_config::{parse_xray_json, OutboundSettings, TargetAddr, VlessOutboundSettings};

const ID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";

fn vless(settings: Value) -> Value {
    json!({"outbounds": [{"tag": "proxy", "protocol": "vless", "settings": settings,
        "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "example.com"}}}]})
}

fn parsed_vless(settings: Value) -> VlessOutboundSettings {
    let config = vless(settings);
    let parsed = parse_xray_json(&config.to_string())
        .unwrap_or_else(|error| panic!("{config}: {:?}", error.diagnostics));
    let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
        panic!("vless");
    };
    vless.clone()
}

fn error_paths(config: &Value) -> Vec<String> {
    parse_xray_json(&config.to_string())
        .map(|_| Vec::new())
        .unwrap_or_else(|error| {
            error
                .diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.path.clone())
                .collect()
        })
}

#[test]
fn the_simplified_form_holds_the_server_and_its_user() {
    let settings = parsed_vless(json!({
        "address": "example.com", "port": 8443, "id": ID, "encryption": "none",
        "flow": "xtls-rprx-vision", "level": 2, "email": "a@example.com", "seed": "ignored",
        "testpre": 0, "testseed": [100, 200, 300, 400, 500]
    }));
    assert_eq!(
        settings.server,
        TargetAddr::Domain("example.com".to_owned())
    );
    assert_eq!(settings.port, 8443);
    let [user] = settings.users.as_slice() else {
        panic!("one user");
    };
    assert_eq!(user.id, Uuid::parse_str(ID).unwrap());
    assert_eq!(user.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(user.level, 2);
    assert_eq!(user.vision_seed, [100, 200, 300, 400]);
}

#[test]
fn a_non_null_address_wins_over_vnext_and_a_null_one_leaves_it() {
    let vnext = json!([{"address": "vnext.example", "port": 443, "users": [{"id": ID, "encryption": "none"}]},
                       {"address": "second.example", "port": 443, "users": []}]);
    let settings = parsed_vless(json!({"address": "flat.example", "port": 443, "id": ID,
                                       "encryption": "none", "vnext": vnext}));
    assert_eq!(
        settings.server,
        TargetAddr::Domain("flat.example".to_owned())
    );
    let settings =
        parsed_vless(json!({"address": null, "id": "not read", "vnext": [vnext[0].clone()]}));
    assert_eq!(
        settings.server,
        TargetAddr::Domain("vnext.example".to_owned())
    );
    // vnext still decodes when the simplified form is read.
    for (vnext, path) in [
        (json!("x"), "$.outbounds[0].settings.vnext"),
        (json!([5]), "$.outbounds[0].settings.vnext[0]"),
        (
            json!([{"users": "x"}]),
            "$.outbounds[0].settings.vnext[0].users",
        ),
    ] {
        let config = vless(json!({"address": "flat.example", "port": 443, "id": ID,
                                  "encryption": "none", "vnext": vnext}));
        assert!(error_paths(&config).iter().any(|p| p == path), "{config}");
    }
    // And the simplified fields decode when vnext is read.
    let config = vless(json!({"id": 5, "vnext": [vnext[0].clone()]}));
    assert!(error_paths(&config)
        .iter()
        .any(|p| p == "$.outbounds[0].settings.id"));
}

#[test]
fn ids_read_as_xray_cores_uuid_parse_string() {
    for (id, expected) in [
        (ID, ID),
        ("278487397e6241389fd3098a63964b6b", ID),
        // From Xray-core v26.10.31's `uuid.ParseString`.
        ("my-short-id", "ed39ef4a-c613-54b3-9b2a-2a6cf18cc74f"),
    ] {
        let flat = parsed_vless(
            json!({"address": "example.com", "port": 443, "id": id, "encryption": "none"}),
        );
        assert_eq!(flat.users[0].id.to_string(), expected, "{id}");
        let vnext = parsed_vless(json!({"vnext": [{"address": "example.com", "port": 443,
                                                   "users": [{"id": id, "encryption": "none"}]}]}));
        assert_eq!(vnext.users[0].id.to_string(), expected, "{id}");
    }
    for id in [
        "",
        "278487397e6241389fd3098a63964b6",
        "{27848739-7e62-4138-9fd3-098a63964b6b}",
    ] {
        let config =
            vless(json!({"address": "example.com", "port": 443, "id": id, "encryption": "none"}));
        assert!(
            error_paths(&config)
                .iter()
                .any(|p| p == "$.outbounds[0].settings.id"),
            "{id}"
        );
    }
}

/// An id is a credential: a refused one is not repeated in the diagnostics.
#[test]
fn a_refused_id_is_not_repeated() {
    for id in [
        "synthetic-secret-id-of-31-bytes",
        "{synthetic-secret-27848739-7e62-41}",
    ] {
        for config in [
            vless(json!({"address": "example.com", "port": 443, "id": id, "encryption": "none"})),
            vless(json!({"vnext": [{"address": "example.com", "port": 443,
                                    "users": [{"id": id, "encryption": "none"}]}]})),
        ] {
            let error = parse_xray_json(&config.to_string()).unwrap_err();
            assert!(
                !format!("{error:?} {error}").contains("synthetic-secret"),
                "{id}"
            );
        }
    }
}

#[test]
fn testseed_takes_four_numbers_or_keeps_the_defaults() {
    for (seed, expected) in [
        (json!(null), [900, 500, 900, 256]),
        (json!([1, 2, 3]), [900, 500, 900, 256]),
        (json!([1, 2, 3, 4]), [1, 2, 3, 4]),
        (json!([0, 0, 0, 0, 9]), [0, 0, 0, 0]),
    ] {
        let flat = parsed_vless(json!({"address": "example.com", "port": 443, "id": ID,
                                       "encryption": "none", "testseed": seed}));
        assert_eq!(flat.users[0].vision_seed, expected, "{seed}");
        let vnext = parsed_vless(json!({"vnext": [{"address": "example.com", "port": 443,
            "users": [{"id": ID, "encryption": "none", "testseed": seed}]}]}));
        assert_eq!(vnext.users[0].vision_seed, expected, "{seed}");
    }
    for seed in [
        json!("1,2,3,4"),
        json!([1, -2, 3, 4]),
        json!([1, 2.5, 3, 4]),
        json!([1, 2, 3, 4294967296_u64]),
    ] {
        let config = vless(json!({"address": "example.com", "port": 443, "id": ID,
                                  "encryption": "none", "testseed": seed}));
        assert!(!error_paths(&config).is_empty(), "{seed}");
    }
}

/// `reverse` is refused. `testpre` is read in either form, up to 64 here.
#[test]
fn reverse_is_refused_and_testpre_is_read() {
    let flat = |extra: Value| {
        let mut settings =
            json!({"address": "example.com", "port": 443, "id": ID, "encryption": "none"});
        settings
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        settings
    };
    let vnext = |user: Value| {
        let mut base = json!({"id": ID, "encryption": "none"});
        base.as_object_mut()
            .unwrap()
            .extend(user.as_object().unwrap().clone());
        json!({"vnext": [{"address": "example.com", "port": 443, "users": [base]}]})
    };
    for (settings, path) in [
        (
            flat(json!({"reverse": {"tag": ""}})),
            "$.outbounds[0].settings.reverse.tag",
        ),
        (
            vnext(json!({"reverse": {"tag": "r"}})),
            "$.outbounds[0].settings.vnext[0].users[0].reverse",
        ),
        (
            flat(json!({"testpre": 65})),
            "$.outbounds[0].settings.testpre",
        ),
        (
            vnext(json!({"testpre": 65})),
            "$.outbounds[0].settings.vnext[0].users[0].testpre",
        ),
        (
            flat(json!({"testpre": "2"})),
            "$.outbounds[0].settings.testpre",
        ),
        (
            flat(json!({"testpre": -1})),
            "$.outbounds[0].settings.testpre",
        ),
    ] {
        let config = vless(settings);
        assert!(error_paths(&config).iter().any(|p| p == path), "{config}");
    }
    for (settings, expected) in [
        (flat(json!({"testpre": 2})), 2),
        (flat(json!({"testpre": 64})), 64),
        (flat(json!({"testpre": 0, "reverse": null})), 0),
        (flat(json!({"testpre": null})), 0),
        (flat(json!({})), 0),
        (vnext(json!({"testpre": 1})), 1),
        // Xray-core keeps no connections ahead for a reverse outbound.
        (flat(json!({"testpre": 4, "reverse": {"tag": "r"}})), 0),
    ] {
        assert_eq!(
            parsed_vless(settings.clone()).users[0].pre_connections,
            expected,
            "{settings}"
        );
    }
}

#[test]
fn vmess_reads_a_non_null_address_over_vnext_and_xray_ids() {
    let config = |settings: Value| {
        json!({"outbounds": [{"protocol": "vmess", "settings": settings,
            "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "example.com"}}}]})
    };
    let parse = |settings: Value| {
        let config = config(settings);
        let parsed = parse_xray_json(&config.to_string())
            .unwrap_or_else(|error| panic!("{config}: {:?}", error.diagnostics));
        let OutboundSettings::Vmess(vmess) = &parsed.config.outbounds[0].settings else {
            panic!("vmess");
        };
        vmess.clone()
    };
    let vnext = json!([{"address": "vnext.example", "port": 443, "users": [{"id": ID}]}]);
    let flat =
        parse(json!({"address": "flat.example", "port": 443, "id": "my-short-id", "vnext": vnext}));
    assert_eq!(flat.server, TargetAddr::Domain("flat.example".to_owned()));
    assert_eq!(
        Uuid::from_bytes(*flat.user_id).to_string(),
        "ed39ef4a-c613-54b3-9b2a-2a6cf18cc74f"
    );
    let from_vnext = parse(json!({"address": null, "vnext": vnext}));
    assert_eq!(
        from_vnext.server,
        TargetAddr::Domain("vnext.example".to_owned())
    );
    assert!(!error_paths(&config(
        json!({"address": "flat.example", "port": 443, "id": ID, "vnext": "x"})
    ))
    .is_empty());
}
