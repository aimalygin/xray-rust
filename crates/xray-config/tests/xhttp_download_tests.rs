use serde_json::{json, Value};
use xray_config::{parse_xray_json, StreamTransport, TargetAddr};

#[test]
fn pinned_download_configuration_contract_and_fail_closed_boundaries() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/xhttp-download/config.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let raw = json!({"outbounds":[{"protocol":"vless", "settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},"streamSettings":case["stream"]}]}).to_string();
        let parsed = parse_xray_json(&raw);
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            parsed.is_ok(),
            case["rustAccept"].as_bool().unwrap(),
            "{name}: {parsed:?}"
        );
        if let Err(error) = parsed {
            let suffix = case["errorSuffix"].as_str().unwrap();
            assert!(
                error
                    .diagnostics
                    .iter()
                    .any(|d| d.path.as_deref().is_some_and(|p| p.ends_with(suffix))),
                "{name}: missing {suffix}: {error:?}"
            );
            continue;
        }
        let parsed = parsed.unwrap();
        let StreamTransport::Xhttp(up) = &parsed.config.outbounds[0].stream.transport else {
            panic!("{name}")
        };
        let expected = &case["download"];
        if expected.is_null() {
            assert!(up.download.is_none(), "{name}");
            continue;
        }
        let down = up.download.as_ref().unwrap();
        let address = match &down.address {
            TargetAddr::Ip(ip) => ip.to_string(),
            TargetAddr::Domain(name) => name.clone(),
        };
        assert_eq!(address, expected["address"].as_str().unwrap(), "{name}");
        assert_eq!(
            down.port as u64,
            expected["port"].as_u64().unwrap(),
            "{name}"
        );
        let StreamTransport::Xhttp(settings) = &down.stream.transport else {
            panic!("{name}")
        };
        assert_eq!(settings.path, expected["path"].as_str().unwrap(), "{name}");
        assert_eq!(
            settings.host.as_deref().unwrap_or(""),
            expected["host"].as_str().unwrap(),
            "{name}"
        );
        assert!(settings.download.is_none(), "{name}");
    }
}
