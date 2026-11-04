//! Xray's `localOS` routing condition and the `direct` freedom alias.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, OutboundProtocol, RoutingRule, LOCAL_OS};

fn rule(local_os: Value) -> Result<RoutingRule, Vec<(Option<String>, String)>> {
    let raw = json!({
        "outbounds": [{"tag": "direct", "protocol": "direct"}],
        "routing": {"rules": [
            {"type": "field", "localOS": local_os, "outboundTag": "direct"}
        ]}
    });
    match parse_xray_json(&raw.to_string()) {
        Ok(parsed) => {
            assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
            assert_eq!(
                parsed.config.outbounds[0].settings.protocol(),
                OutboundProtocol::Freedom
            );
            Ok(parsed.config.routing.rules[0].clone())
        }
        Err(error) => Err(error
            .diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .map(|diagnostic| (diagnostic.path, diagnostic.message))
            .collect()),
    }
}

#[test]
fn local_os_is_a_go_string_list() {
    // An array, or one string split at commas without trimming.
    for (raw, names) in [
        (json!(["android", "ios"]), vec!["android", "ios"]),
        (json!("linux,darwin"), vec!["linux", "darwin"]),
        (json!("linux, darwin"), vec!["linux", " darwin"]),
        (json!(""), vec![""]),
        (json!([]), vec![]),
        (json!(null), vec![]),
    ] {
        assert_eq!(rule(raw.clone()).unwrap().local_os, names, "{raw}");
    }
}

#[test]
fn local_os_matches_runtime_goos_case_insensitively() {
    let apple_and_android = rule(json!(["Android", "iOS", "darwin"])).unwrap();
    for os in ["android", "ios", "IOS", "darwin"] {
        assert!(apple_and_android.matches_local_os_on(os), "{os}");
    }
    // `macos` is not a Go GOOS, and a padded name matches nothing.
    for os in ["linux", "windows", "macos", " ios"] {
        assert!(!apple_and_android.matches_local_os_on(os), "{os}");
    }
    assert!(!rule(json!("")).unwrap().matches_local_os());
    assert!(rule(json!(null)).unwrap().matches_local_os_on("plan9"));
    assert!(rule(json!([LOCAL_OS])).unwrap().matches_local_os());
    assert!(["darwin", "ios", "android", "linux", "windows", "freebsd"].contains(&LOCAL_OS));
}

#[test]
fn malformed_local_os_fails_with_its_path() {
    for (raw, path) in [
        (json!(1), "$.routing.rules[0].localOS"),
        (json!({"os": "linux"}), "$.routing.rules[0].localOS"),
        (json!(["linux", 7]), "$.routing.rules[0].localOS[1]"),
    ] {
        let errors = rule(raw.clone()).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|(error_path, _)| error_path.as_deref() == Some(path)),
            "{raw}: {errors:?}"
        );
    }
}
