use serde_json::{json, Value};
use xray_config::{parse_xray_json, InboundProtocol, TproxySettings};
fn profile() -> Value {
    json!({"inbounds":[{"protocol":"dokodemo-door","listen":"0.0.0.0","port":12345,
    "settings":{"network":"tcp,udp","followRedirect":true},"streamSettings":{"sockopt":{"tproxy":"tproxy","mark":255}}}],"outbounds":[{"protocol":"freedom"}]})
}
#[test]
fn xray_transparent_inbound_and_network_alias() {
    let mut p = profile();
    assert_eq!(
        parse_xray_json(&p.to_string()).unwrap().config.inbounds[0].protocol,
        InboundProtocol::Tproxy(TproxySettings {
            tcp: true,
            udp: true,
            mark: 255
        })
    );
    p["inbounds"][0]["settings"] = json!({"allowedNetwork":["udp"],"followRedirect":true});
    assert_eq!(
        parse_xray_json(&p.to_string()).unwrap().config.inbounds[0].protocol,
        InboundProtocol::Tproxy(TproxySettings {
            tcp: false,
            udp: true,
            mark: 255
        })
    );
}
#[test]
fn ambiguous_or_unsupported_transparent_modes_fail_closed() {
    for (path, value) in [
        ("/inbounds/0/settings/followRedirect", json!(false)),
        ("/inbounds/0/settings/network", json!("icmp")),
        ("/inbounds/0/settings/network", json!([])),
        (
            "/inbounds/0/streamSettings/sockopt/tproxy",
            json!("redirect"),
        ),
        ("/inbounds/0/streamSettings/sockopt/mark", json!(-1)),
        ("/inbounds/0/listen", json!("localhost")),
        (
            "/inbounds/0/streamSettings",
            json!({"network":"ws","sockopt":{"tproxy":"tproxy"}}),
        ),
        (
            "/inbounds/0/settings",
            json!({"followRedirect":true,"address":"example.com"}),
        ),
    ] {
        let mut p = profile();
        *p.pointer_mut(path).unwrap() = value;
        assert!(parse_xray_json(&p.to_string()).is_err(), "{p}");
    }
    let mut p = profile();
    p["inbounds"][0]["protocol"] = json!("socks");
    assert!(parse_xray_json(&p.to_string()).is_err());
}
