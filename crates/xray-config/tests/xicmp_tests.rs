//! The `xicmp` mask's settings against what Xray-core's `Xicmp.Build` does
//! with them, from `tests/fixtures/xicmp/vectors.json`, which
//! `tools/xicmp-oracle` records in the pinned checkout.
use serde_json::{json, Value};
use xray_config::parse_xray_json;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../tests/fixtures/xicmp/vectors.json")).unwrap()
}

fn config(stream: Value) -> String {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"10.0.0.9","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":stream}]})
    .to_string()
}

fn kcp(masks: Value) -> String {
    config(json!({"network":"kcp","finalmask":{"udp":masks}}))
}

fn parse_xicmp(settings: Value) -> Result<xray_config::XicmpMask, Vec<String>> {
    match parse_xray_json(&kcp(json!([{"type":"xicmp","settings":settings}]))) {
        Ok(parsed) => Ok(parsed.config.outbounds[0].stream.udp_xicmp.clone().unwrap()),
        Err(error) => Err(error.diagnostics.into_iter().map(|d| d.message).collect()),
    }
}

fn refused(text: &str, expected: &str) {
    let errors: Vec<String> = parse_xray_json(text)
        .unwrap_err()
        .diagnostics
        .into_iter()
        .map(|d| d.message)
        .collect();
    assert!(
        errors.iter().any(|error| error.contains(expected)),
        "{expected:?} not in {errors:?}"
    );
}

#[test]
fn addresses_read_as_xicmp_build_reads_them() {
    for case in vectors()["ips"].as_array().unwrap() {
        let ip = case["ip"].as_str().unwrap();
        let parsed = parse_xicmp(json!({"ips": [ip]}));
        assert_eq!(
            parsed.is_ok(),
            case.get("error").is_none(),
            "{ip:?}: {parsed:?}"
        );
        if let Ok(mask) = parsed {
            // Kept as AsSlice keeps it: no zone, IPv4-mapped as IPv4.
            let expected: std::net::IpAddr = ip
                .split('%')
                .next()
                .unwrap()
                .parse::<std::net::IpAddr>()
                .unwrap()
                .to_canonical();
            assert_eq!(mask.ips, vec![expected], "{ip:?}");
        }
    }
}

#[test]
fn settings_read_as_xicmp_build_reads_them() {
    for case in vectors()["settings"].as_array().unwrap() {
        let settings = &case["settings"];
        let parsed = parse_xicmp(settings.clone());
        if case.get("error").is_some() {
            assert!(parsed.is_err(), "{settings} is refused by Xray-core");
            continue;
        }
        let mask = parsed.unwrap_or_else(|errors| panic!("{settings}: {errors:?}"));
        assert_eq!(mask.dgram, case["dgram"].as_bool().unwrap(), "{settings}");
        let ips: Vec<std::net::IpAddr> = case["ips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ip| ip.as_str().unwrap().parse().unwrap())
            .collect();
        assert_eq!(mask.ips, ips, "{settings}");
    }
    // Absent settings read as `{}`.
    let parsed = parse_xray_json(&kcp(json!([{"type":"xicmp"}]))).unwrap();
    assert_eq!(
        parsed.config.outbounds[0].stream.udp_xicmp,
        Some(xray_config::XicmpMask::default())
    );
}

#[test]
fn xicmp_is_the_last_mask_and_runs_only_where_it_can() {
    let xicmp = json!({"type":"xicmp","settings":{"dgram":true}});
    let noise = json!({"type":"noise","settings":{"noise":[{"rand":"10-20"}]}});
    parse_xray_json(&kcp(json!([
        {"type":"mkcp-legacy","settings":{"value":"seed"}},
        noise.clone(),
        xicmp.clone()
    ])))
    .unwrap();
    refused(
        &kcp(json!([xicmp.clone(), noise])),
        "xicmp must be the last UDP mask",
    );
    refused(
        &kcp(
            json!([{"type":"header-custom","settings":{"client":[{"packet":[1]}],"server":[{"packet":[2]}]}}, xicmp.clone()]),
        ),
        "cannot be combined with xicmp",
    );
    refused(
        &kcp(
            json!([{"type":"realm","settings":{"url":"realm://t@rendezvous.example/x","stunServers":["stun.example.net:3478"]}}, xicmp.clone()]),
        ),
        "cannot be combined with realm",
    );
    refused(
        &config(json!({"network":"raw","finalmask":{"udp":[xicmp.clone()]}})),
        "requires mKCP, Hysteria or XHTTP",
    );
    refused(
        &config(json!({"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"server.example","alpn":["h3"]},
            "finalmask":{"udp":[{"type":"sudoku","settings":{"password":"synthetic"}}, xicmp],
                "quicParams":{"disableChromeParrot":true}}})),
        "cannot run under xicmp on QUIC",
    );
}
