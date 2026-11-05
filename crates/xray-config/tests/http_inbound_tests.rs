//! HTTP inbound settings read as Xray-core v26.10.31 reads them.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, HttpInboundSettings, InboundProtocol};

fn config(settings: Value) -> String {
    json!({
        "inbounds": [{
            "tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 1081,
            "settings": settings
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    })
    .to_string()
}

fn settings(settings: Value) -> HttpInboundSettings {
    let raw = config(settings);
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    match &parsed.config.inbounds[0].protocol {
        InboundProtocol::Http(settings) => settings.clone(),
        other => panic!("not an HTTP inbound: {other:?}"),
    }
}

fn rejection(settings: Value) -> String {
    let raw = config(settings);
    let error = parse_xray_json(&raw).expect_err(&format!("{raw} should be rejected"));
    error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .and_then(|diagnostic| diagnostic.path.clone())
        .unwrap_or_default()
}

/// Whether a request with `user` and `pass` as Basic credentials gets in.
fn admits(settings: &HttpInboundSettings, user: &str, pass: &str) -> bool {
    use base64::Engine as _;
    let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    settings
        .accounts
        .basic_user(Some(format!("Basic {credentials}").as_bytes()))
        .is_some()
}

#[test]
fn accounts_or_users_name_the_credentials() {
    let account = json!([{"user": "alice", "pass": "secret"}]);
    for list in ["accounts", "users"] {
        let parsed = settings(json!({ list: account }));
        assert!(admits(&parsed, "alice", "secret"), "{list}");
        assert!(!admits(&parsed, "alice", "wrong"), "{list}");
    }
    // `accounts` replaces `users` unless it is absent or `null`, so an empty
    // `accounts` needs no credentials at all.
    let open = settings(json!({"accounts": [], "users": account}));
    assert!(open.accounts.is_empty());
    let users = settings(json!({"accounts": null, "users": account}));
    assert!(admits(&users, "alice", "secret"));
    assert!(settings(json!({})).accounts.is_empty());
    assert!(settings(Value::Null).accounts.is_empty());
    // A `null` entry harms only the list in use.
    assert!(settings(json!({"accounts": [], "users": [null]}))
        .accounts
        .is_empty());
}

#[test]
fn accounts_read_as_xray_core_reads_them() {
    // A later account replaces an earlier one of the same name, and absent
    // or `null` fields read as empty.
    let parsed = settings(json!({"accounts": [
        {"user": "alice", "pass": "old"},
        {"user": "alice", "pass": "new"},
        {"user": null},
    ]}));
    assert!(!admits(&parsed, "alice", "old"));
    assert!(admits(&parsed, "alice", "new"));
    assert!(admits(&parsed, "", ""));
    // Credentials are not shown.
    assert_eq!(
        format!("{:?}", parsed.accounts),
        "HttpInboundAccounts { accounts: 2 }"
    );

    for (settings, path) in [
        (
            json!({"accounts": "alice"}),
            "$.inbounds[0].settings.accounts",
        ),
        (json!({"accounts": {}}), "$.inbounds[0].settings.accounts"),
        // Xray-core panics on a `null` entry.
        (
            json!({"accounts": [null]}),
            "$.inbounds[0].settings.accounts[0]",
        ),
        (
            json!({"accounts": ["alice"]}),
            "$.inbounds[0].settings.accounts[0]",
        ),
        (
            json!({"accounts": [{"user": 5, "pass": "x"}]}),
            "$.inbounds[0].settings.accounts[0].user",
        ),
        (
            json!({"accounts": [{"user": "a", "pass": "b", "email": "x"}]}),
            "$.inbounds[0].settings.accounts[0].email",
        ),
        (json!({"users": [null]}), "$.inbounds[0].settings.users[0]"),
        // Both lists must parse, though `accounts` wins.
        (
            json!({"accounts": [], "users": 5}),
            "$.inbounds[0].settings.users",
        ),
    ] {
        assert_eq!(rejection(settings.clone()), path, "{settings}");
    }
    let many: Vec<Value> = (0..65)
        .map(|index| json!({"user": format!("user-{index}"), "pass": "x"}))
        .collect();
    assert_eq!(
        rejection(json!({ "accounts": many })),
        "$.inbounds[0].settings.accounts"
    );
}
