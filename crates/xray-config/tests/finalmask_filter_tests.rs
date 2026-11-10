//! The FinalMask `filter`, which Xray-core v26.11.9's client validates and
//! then ignores: its `WrapConnClient` and `WrapPacketConnClient` return the
//! connection unchanged. `tests/fixtures/filter/config-verdicts.json` records
//! what `xray run -test` says of each case.
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, parse_xray_json_with_exclusive_geodata_dirs, DiagnosticSeverity,
};

fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/filter/config-verdicts.json"
    ))
    .unwrap()
}

fn config(outbound: &Value) -> String {
    json!({"outbounds": [outbound]}).to_string()
}

fn raw_tls(finalmask: Value) -> Value {
    json!({"tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "server.example", "port": 443,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
        "streamSettings": {"network": "raw", "security": "tls",
            "tlsSettings": {"serverName": "server.example"}, "finalmask": finalmask}})
}

fn errors_of(
    parsed: Result<xray_config::ParsedConfig, xray_config::ConfigParseError>,
) -> Vec<(String, String)> {
    parsed
        .err()
        .map(|error| {
            error
                .diagnostics
                .into_iter()
                .filter(|d| d.severity == DiagnosticSeverity::Error)
                .map(|d| (d.path.unwrap_or_default(), d.message))
                .collect()
        })
        .unwrap_or_default()
}

fn errors(outbound: &Value) -> Vec<(String, String)> {
    errors_of(parse_xray_json(&config(outbound)))
}

/// Every case of the corpus gets Xray-core's verdict, except the
/// deliberate differences, which get theirs.
#[test]
fn config_verdicts_match_xray_core() {
    let mut mismatches = Vec::new();
    for case in corpus()["cases"].as_array().unwrap() {
        let parsed = parse_xray_json(&config(&case["outbound"]));
        let expected_ok = match case.get("ours").and_then(Value::as_str) {
            Some(ours) => ours == "ok",
            None => case["xray"] == "ok",
        };
        if parsed.is_ok() != expected_ok {
            mismatches.push(format!(
                "{}: expected {}, got {:?}",
                case["name"],
                if expected_ok { "ok" } else { "an error" },
                errors_of(parsed)
            ));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

fn is_filter(mask: &Value) -> bool {
    mask["type"]
        .as_str()
        .is_some_and(|kind| kind.to_lowercase() == "filter")
}

/// Drops the filters from every `finalmask` list, an XHTTP download
/// stream's included.
fn without_filters(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if let Some(finalmask) = object.get_mut("finalmask").and_then(Value::as_object_mut) {
                for key in ["tcp", "udp"] {
                    if let Some(masks) = finalmask.get_mut(key).and_then(Value::as_array_mut) {
                        masks.retain(|mask| !is_filter(mask));
                    }
                }
            }
            object.values_mut().for_each(without_filters);
        }
        Value::Array(items) => items.iter_mut().for_each(without_filters),
        _ => {}
    }
}

/// Whatever carrier and wherever they stand, the filters leave the parsed
/// configuration, which is all the core reads, as it is without them: every
/// carrier sends what it sends without them, and no warning is added.
#[test]
fn filters_leave_the_parsed_configuration_as_it_is_without_them() {
    let mut compared = 0;
    for case in corpus()["cases"].as_array().unwrap() {
        let name = &case["name"];
        let Ok(with) = parse_xray_json(&config(&case["outbound"])) else {
            continue;
        };
        let mut stripped = case["outbound"].clone();
        without_filters(&mut stripped);
        assert_ne!(stripped, case["outbound"], "{name} holds no filter");
        let without = parse_xray_json(&config(&stripped))
            .unwrap_or_else(|error| panic!("{name} without its filters: {error:?}"));
        assert_eq!(with.config, without.config, "{name}");
        assert_eq!(with.diagnostics, without.diagnostics, "{name}");
        compared += 1;
    }
    assert!(compared >= 50, "only {compared} cases compared");
}

#[test]
fn a_refused_rule_is_named_as_xray_core_names_it() {
    let base = "$.outbounds[0].streamSettings.finalmask";
    let filter = |settings: Value| json!({"type": "filter", "settings": settings});
    assert_eq!(
        errors(&raw_tls(json!({"tcp": [filter(
            json!({"blockedSourceIPs": ["10.0.0.0/8", "10.0.0.0/33"]})
        )]}))),
        [(
            format!("{base}.tcp[0].settings.blockedSourceIPs[1]"),
            r#"invalid "blockedSourceIPs": illegal ip rule: 10.0.0.0/33: CIDR prefix length 33 exceeds max 32"#
                .to_owned()
        )]
    );
    // Another spelling of the field keeps its own in the path.
    assert_eq!(
        errors(&raw_tls(json!({"udp": [
            {"type": "filter"},
            {"type": "Filter", "settings": {"ALLOWEDSOURCEIPS": ["example.com"]}}
        ]}))),
        [(
            format!("{base}.udp[1].settings.ALLOWEDSOURCEIPS[0]"),
            r#"invalid "allowedSourceIPs": illegal ip rule: example.com: unsupported address family"#
                .to_owned()
        )]
    );
    assert_eq!(
        errors(&raw_tls(json!({"tcp": [filter(json!({"blockedSourceIPs": ["ext::cn"],
            "allowedSourceIPs": ["10.0.0.0/+8"]}))]}))),
        [
            (
                format!("{base}.tcp[0].settings.blockedSourceIPs[0]"),
                r#"invalid "blockedSourceIPs": illegal ip rule: ext::cn: empty file"#.to_owned()
            ),
            (
                format!("{base}.tcp[0].settings.allowedSourceIPs[0]"),
                r#"invalid "allowedSourceIPs": illegal ip rule: 10.0.0.0/+8: invalid CIDR prefix length: +8"#
                    .to_owned()
            )
        ]
    );
    assert_eq!(
        errors(&raw_tls(json!({"tcp": [filter(json!(5))]}))),
        [(
            format!("{base}.tcp[0].settings"),
            "filter settings must be an object or null".to_owned()
        )]
    );
    assert_eq!(
        errors(&raw_tls(
            json!({"tcp": [filter(json!({"blockedSourceIPs": "10.0.0.0/8",
            "allowedSourceIPs": [null, 7]}))]})
        )),
        [
            (
                format!("{base}.tcp[0].settings.blockedSourceIPs"),
                "field `blockedSourceIPs` must be an array of strings or null".to_owned()
            ),
            (
                format!("{base}.tcp[0].settings.allowedSourceIPs[0]"),
                r#"invalid "allowedSourceIPs": illegal ip rule: : unsupported address family"#
                    .to_owned()
            ),
            (
                format!("{base}.tcp[0].settings.allowedSourceIPs[1]"),
                "field `allowedSourceIPs` must hold strings".to_owned()
            )
        ]
    );
}

/// The masks that must stay outermost ignore a filter after them only
/// where Xray-core's dial does.
#[test]
fn a_filter_after_udphop_or_xicmp_is_refused_as_any_mask_there() {
    let hysteria = |udp: Value| {
        json!({"protocol": "hysteria", "settings": {"version": 2, "address": "hysteria.example", "port": 443},
            "streamSettings": {"network": "hysteria", "security": "tls",
                "tlsSettings": {"serverName": "hysteria.example", "alpn": ["h3"]},
                "hysteriaSettings": {"version": 2, "auth": "filter"}, "finalmask": {"udp": udp}}})
    };
    let udphop =
        json!({"type": "udphop", "settings": {"mode": "intervalLocal", "remotePorts": "443,8443"}});
    let xicmp = json!({"type": "xicmp", "settings": {"dgram": true, "ips": ["192.0.2.1"]}});
    let filter = json!({"type": "filter"});
    assert!(errors(&hysteria(json!([filter, udphop]))).is_empty());
    assert_eq!(
        errors(&hysteria(json!([udphop, filter]))),
        [(
            "$.outbounds[0].streamSettings.finalmask.udp[0].settings".to_owned(),
            "udphop requires Hysteria or XHTTP with exact h3 ALPN and must be the last UDP mask"
                .to_owned()
        )]
    );
    assert!(errors(&hysteria(json!([filter, xicmp]))).is_empty());
    assert_eq!(
        errors(&hysteria(json!([xicmp, filter]))),
        [(
            "$.outbounds[0].streamSettings.finalmask.udp[0]".to_owned(),
            "xicmp must be the last UDP mask: Xray-core fails every dial with it anywhere else"
                .to_owned()
        )]
    );
}

/// A uniquely named directory under the system's temporary one.
fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "xray-config-filter-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn varint(mut value: usize, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push(value as u8 | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

/// A `GeoIPList` of entries holding only their codes, as protobuf writes it.
fn write_geoip_dat(path: &Path, codes: &[&str]) {
    let mut bytes = Vec::new();
    for code in codes {
        let mut entry = vec![0x0a];
        varint(code.len(), &mut entry);
        entry.extend_from_slice(code.as_bytes());
        bytes.push(0x0a);
        varint(entry.len(), &mut bytes);
        bytes.extend_from_slice(&entry);
    }
    std::fs::write(path, bytes).unwrap();
}

/// `geoip:`, `ext:` and `ext-ip:` rules name a code their file must hold,
/// as Xray-core's `checkFile` asks; `geoip:private` is not built in.
/// The verdicts are those of the pinned `xray run -test` with the same
/// files under `XRAY_LOCATION_ASSET`.
#[test]
fn geodata_rules_need_their_file_and_code() {
    let dir = temp_dir("geodata");
    write_geoip_dat(&dir.join("geoip.dat"), &["CN", "TEST"]);
    write_geoip_dat(&dir.join("custom.dat"), &["XX"]);
    let parse = |rule: &str| {
        let outbound = raw_tls(json!({"tcp": [{"type": "filter",
            "settings": {"blockedSourceIPs": [rule]}}]}));
        errors_of(parse_xray_json_with_exclusive_geodata_dirs(
            &config(&outbound),
            &[&dir],
        ))
    };
    for rule in [
        "geoip:cn",
        "geoip:CN",
        "!geoip:!test",
        "ext:custom.dat:xx",
        "ext-ip:custom.dat:XX",
    ] {
        assert_eq!(parse(rule), [], "{rule}");
    }
    for (rule, cause) in [
        (
            "geoip:private",
            "geodata file `geoip.dat` does not contain code `PRIVATE`",
        ),
        (
            "geoip:us",
            "geodata file `geoip.dat` does not contain code `US`",
        ),
        (
            "ext:custom.dat:cn",
            "geodata file `custom.dat` does not contain code `CN`",
        ),
        (
            "ext:missing.dat:cn",
            "geodata file `missing.dat` was not found",
        ),
    ] {
        let errors = parse(rule);
        assert_eq!(errors.len(), 1, "{rule}: {errors:?}");
        let expected = format!(r#"invalid "blockedSourceIPs": illegal ip rule: {rule}: {cause}"#);
        assert!(errors[0].1.starts_with(&expected), "{rule}: {errors:?}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}
