use serde_json::{json, Value};
use xray_config::{parse_xray_json, MuxUdp443};
fn profile(mux: Value) -> Value {
    let mut config: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/configs/vmess.json")).unwrap();
    config["outbounds"][0]["mux"] = mux;
    config
}
#[test]
fn mux_pinned_defaults_separate_udp_policy_and_explicit_disabling() {
    let config = parse_xray_json(&profile(json!({"enabled":true})).to_string())
        .unwrap()
        .config;
    let mux = config.outbounds[0].mux.as_ref().unwrap();
    assert_eq!(mux.concurrency, 8);
    assert_eq!(mux.xudp_concurrency, 0);
    assert_eq!(mux.udp443, MuxUdp443::Reject);
    for policy in ["skip", "allow", "reject"] {
        let config=parse_xray_json(&profile(json!({"enabled":true,"concurrency":-1,"xudpConcurrency":64,"xudpProxyUDP443":policy})).to_string()).unwrap().config;
        let mux = config.outbounds[0].mux.as_ref().unwrap();
        assert_eq!(mux.concurrency, -1);
        assert_eq!(mux.xudp_concurrency, 64);
    }
    for enabled in [
        json!({}),
        json!({"enabled":false,"concurrency":8,"xudpConcurrency":-1}),
    ] {
        assert!(parse_xray_json(&profile(enabled).to_string())
            .unwrap()
            .config
            .outbounds[0]
            .mux
            .is_none());
    }
}
#[test]
fn mux_type_limits_and_unsupported_protocols_fail_with_paths() {
    for (key, value) in [
        ("enabled", json!(1)),
        ("concurrency", json!(65)),
        ("concurrency", json!(-32769)),
        ("concurrency", json!("8")),
        ("xudpConcurrency", json!(65)),
        ("xudpConcurrency", json!(false)),
        ("xudpProxyUDP443", json!(true)),
        ("xudpProxyUDP443", json!("unknown")),
    ] {
        let mut mux = json!({"enabled":true});
        mux[key] = value;
        let error = parse_xray_json(&profile(mux).to_string()).unwrap_err();
        assert!(error
            .diagnostics
            .iter()
            .any(|d| d.path.as_deref() == Some(format!("$.outbounds[0].mux.{key}").as_str())));
    }
    let mut config = profile(json!({"enabled":true}));
    config["outbounds"][0] = json!({"protocol":"freedom","mux":{"enabled":true}});
    assert!(parse_xray_json(&config.to_string()).is_err());
}

#[test]
fn xhttp_only_allows_udp_mux_as_required_by_pinned_server() {
    for concurrency in [None, Some(0), Some(8), Some(-1)] {
        let mut config = profile(json!({"enabled":true,"xudpConcurrency":8}));
        if let Some(n) = concurrency {
            config["outbounds"][0]["mux"]["concurrency"] = json!(n);
        }
        config["outbounds"][0]["streamSettings"] =
            json!({"network":"xhttp","xhttpSettings":{"path":"/test","mode":"stream-one"}});
        let result = parse_xray_json(&config.to_string());
        if concurrency == Some(-1) {
            assert!(result.is_ok());
        } else {
            assert!(result
                .unwrap_err()
                .diagnostics
                .iter()
                .any(|d| d.path.as_deref() == Some("$.outbounds[0].mux.concurrency")));
        }
    }
}
