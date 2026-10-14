use serde_json::{json, Value};
use xray_config::{parse_xray_json, FragmentRange};
fn profile(noise: Value) -> Value {
    json!({"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"example.com","port":443},
        "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com"},
            "hysteriaSettings":{"version":2,"auth":"synthetic"},"finalmask":{"udp":[{"type":"noise","settings":noise}]}}}]})
}
#[test]
fn encodings_ranges_and_order_match_pinned_xray() {
    let mut p = profile(
        json!({"reset":"20-10","noise":[{"rand":"24-16","randRange":"9-7","delay":"2-1"},
        {"type":"str","packet":" hi "}, {"type":"base64","packet":"AAEC"}, {"type":"hex","packet":"00ff"}, {"packet":[0,128,255]}]}),
    );
    let n = parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
        .stream
        .udp_noise
        .clone()
        .unwrap();
    assert_eq!(n.reset_secs, FragmentRange { from: 10, to: 20 });
    assert_eq!(n.items[0].random_length, FragmentRange { from: 16, to: 24 });
    assert_eq!(n.items[0].random_bytes, FragmentRange { from: 7, to: 9 });
    assert_eq!(n.items[1].packet, b" hi ");
    assert_eq!(n.items[2].packet, [0, 1, 2]);
    assert_eq!(n.items[3].packet, [0, 255]);
    assert_eq!(n.items[4].packet, [0, 128, 255]);
    let masks = p["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array_mut()
        .unwrap();
    masks.push(json!({"type":"salamander","settings":{"password":"synthetic"}}));
    assert!(
        parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
            .stream
            .udp_noise
            .as_ref()
            .unwrap()
            .before_salamander
    );
    p["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(
        !parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
            .stream
            .udp_noise
            .as_ref()
            .unwrap()
            .before_salamander
    );
}
#[test]
fn malformed_and_unbounded_noise_is_rejected() {
    for n in [
        json!({"reset":-1}),
        json!({"noise":vec![json!({"rand":1});17]}),
        json!({"noise":[{"rand":4097}]}),
        json!({"noise":[{"rand":1,"packet":null}]}),
        json!({"noise":[{"randRange":256}]}),
        json!({"noise":[{"delay":1001}]}),
        json!({"noise":vec![json!({"delay":1000});11]}),
        json!({"noise":[{"type":"base64","packet":"??"}]}),
        json!({"noise":[{"type":"str","packet":"a".repeat(4097)}]}),
        json!({"noise":[{"packet":[256]}]}),
        json!({"noise":[{"type":"rand","packet":"4-8"}]}),
        json!({"unknown":true}),
    ] {
        assert!(
            parse_xray_json(&profile(n.clone()).to_string()).is_err(),
            "{n}"
        );
    }
}
#[test]
fn exact_h3_only_and_no_change_when_absent() {
    let mut p = profile(json!({"noise":[{"rand":16}]}));
    p["outbounds"][0] = json!({"protocol":"freedom", "streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.com","alpn":["h3"]},"finalmask":p["outbounds"][0]["streamSettings"]["finalmask"]}});
    assert!(parse_xray_json(&p.to_string()).is_ok());
    p["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = json!(["h2"]);
    assert!(parse_xray_json(&p.to_string()).is_err());
    p["outbounds"][0]["streamSettings"]["finalmask"] = Value::Null;
    assert!(parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
        .stream
        .udp_noise
        .is_none());
}
