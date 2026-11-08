use serde_json::{json, Value};
use xray_config::{parse_xray_json, KcpMask, StreamTransport};

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

#[test]
fn settings_read_camel_case_or_their_snake_case_names() {
    let parsed = parse_xray_json(&tcp(json!([{"type":"Sudoku","settings":{
        "password":"secret","ascii":"Prefer_Entropy","customTables":["xppvvvvx"],
        "custom_table":"vvxpvxpv","paddingMin":0,"padding_min":7,"paddingMax":30}}])))
    .unwrap();
    let mask = parsed.config.outbounds[0]
        .stream
        .tcp_sudoku
        .clone()
        .unwrap();
    assert_eq!(mask.password.as_str(), "secret");
    assert_eq!(mask.ascii, "Prefer_Entropy");
    assert_eq!(mask.custom_table, "vvxpvxpv");
    assert_eq!(mask.custom_tables, ["xppvvvvx"]);
    assert_eq!((mask.padding_min, mask.padding_max), (7, 30));
    assert!(!format!("{mask:?}").contains("secret"));
    // Set both ways, the camelCase field wins.
    let parsed = parse_xray_json(&tcp(json!([{"type":"sudoku","settings":{
        "customTable":"xppvvvvx","custom_table":"vvxpvxpv",
        "customTables":["xppvvvvx"],"custom_tables":["vvxpvxpv"],
        "paddingMax":30,"padding_max":40}}])))
    .unwrap();
    let mask = parsed.config.outbounds[0]
        .stream
        .tcp_sudoku
        .clone()
        .unwrap();
    assert_eq!(mask.custom_table, "xppvvvvx");
    assert_eq!(mask.custom_tables, ["xppvvvvx"]);
    assert_eq!(mask.padding_max, 30);
    // Null or absent settings are the zero settings.
    for settings in [json!(null), json!({})] {
        let parsed = parse_xray_json(&tcp(json!([{"type":"sudoku","settings":settings}]))).unwrap();
        assert!(parsed.config.outbounds[0].stream.tcp_sudoku.is_some());
    }
}

#[test]
fn unknown_modes_tables_and_fields_are_refused() {
    for (settings, expected) in [
        (json!({"ascii":"text"}), "sudoku ascii is"),
        (json!({"customTable":"xxppvvvv-"}), "sudoku custom table"),
        (
            json!({"customTables":["xppvvvvx","xxxpvvvv"]}),
            "sudoku custom table",
        ),
        (json!({"customTables":"xppvvvvx"}), "array of strings"),
        (json!({"paddingMin":-1}), "fit in u32"),
        (json!({"seed":"x"}), "unsupported field `seed`"),
    ] {
        let errors = errors(&tcp(json!([{"type":"sudoku","settings":settings}])));
        assert!(
            errors.iter().any(|e| e.contains(expected)),
            "{settings}: {errors:?}"
        );
    }
    // ASCII mode never reads the custom tables, as in Xray-core.
    assert!(parse_xray_json(&tcp(json!([{"type":"sudoku","settings":{
        "ascii":"ascii","customTable":"bad"}}])))
    .is_ok());
}

#[test]
fn sudoku_is_the_last_tcp_mask() {
    let header = json!({"type":"header-custom","settings":{"clients":[[{"packet":[1]}]]}});
    let fragment = json!({"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}});
    let sudoku = json!({"type":"sudoku","settings":{"password":"secret"}});
    let parsed = parse_xray_json(&tcp(json!([fragment, header, sudoku]))).unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    assert!(stream.tcp_fragment.is_some());
    assert!(stream.tcp_header_custom.is_some());
    assert!(stream.tcp_sudoku.is_some());
    for masks in [json!([sudoku, header]), json!([sudoku, sudoku])] {
        assert!(
            errors(&tcp(masks.clone()))
                .iter()
                .any(|e| e.contains("sudoku must be the last TCP mask")),
            "{masks}"
        );
    }
}

#[test]
fn the_udp_mask_takes_its_place_on_udp_carriers() {
    let sudoku = json!({"type":"sudoku","settings":{"password":"secret"}});
    let legacy = json!({"type":"mkcp-legacy","settings":{"header":"srtp"}});
    let parsed = parse_xray_json(&config(json!({"network":"kcp",
        "finalmask":{"udp":[legacy, sudoku]}})))
    .unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    assert_eq!(
        stream.udp_sudoku.as_ref().unwrap().mask.password.as_str(),
        "secret"
    );
    let StreamTransport::Kcp(kcp) = &stream.transport else {
        panic!("not kcp")
    };
    assert_eq!(kcp.masks[1], KcpMask::Sudoku);
    // On Hysteria, its place among the other QUIC masks.
    let hysteria = |masks: Value| {
        json!({"outbounds":[{"protocol":"hysteria",
            "settings":{"version":2,"address":"192.0.2.1","port":443},
            "streamSettings":{"network":"hysteria","security":"tls",
                "tlsSettings":{"serverName":"server.example","alpn":["h3"]},
                "hysteriaSettings":{"version":2,"auth":"synthetic"},
                "finalmask":{"udp":masks,"quicParams":{"disableChromeParrot":true}}}}]})
        .to_string()
    };
    let salamander = json!({"type":"salamander","settings":{"password":"synthetic-password"}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"n"}]}});
    let header =
        json!({"type":"header-custom","settings":{"client":[{"type":"str","packet":"h"}]}});
    for (masks, places) in [
        (json!([sudoku, salamander]), (true, false, false)),
        (json!([salamander, sudoku]), (false, false, false)),
        (
            json!([noise, sudoku, header, salamander]),
            (true, false, true),
        ),
        (
            json!([header, salamander, noise, sudoku]),
            (false, false, false),
        ),
    ] {
        let parsed = parse_xray_json(&hysteria(masks.clone())).unwrap();
        let sudoku = parsed.config.outbounds[0]
            .stream
            .udp_sudoku
            .clone()
            .unwrap();
        assert_eq!(
            (
                sudoku.before_salamander,
                sudoku.before_noise,
                sudoku.before_header_custom
            ),
            places,
            "{masks}"
        );
    }
    // A carrier without UDP takes none.
    assert!(errors(&config(
        json!({"network":"raw","finalmask":{"udp":[sudoku]}})
    ))
    .iter()
    .any(|e| e.contains("a sudoku UDP mask requires mKCP, Hysteria or XHTTP")));
}
