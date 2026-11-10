//! `disableChromeParrot` read as Xray-core reads it.
//!
//! `tests/fixtures/chrome-parrot/config-verdicts.json` records what
//! Xray-core v26.11.9's `xray run -test` says about each case
//! (`scripts/check-chrome-parrot-interop.sh` rechecks it): a Go bool, null
//! for false, on any transport, and nothing else.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, StreamTransport};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/chrome-parrot/config-verdicts.json"
    ))
    .unwrap()
}

#[test]
fn every_xray_verdict_is_ours() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 25);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let raw = json!({"outbounds":[case["outbound"]]}).to_string();
        let parsed = parse_xray_json(&raw);
        let xray_accepts = case["xray"] == "ok";
        match parsed {
            Ok(parsed) => {
                assert!(xray_accepts, "{name}: Xray refuses it, we took it");
                assert!(
                    parsed
                        .diagnostics
                        .iter()
                        .all(|d| !d.message.contains("ChromeParrot")),
                    "{name}: {:?}",
                    parsed.diagnostics
                );
                let outbound = &parsed.config.outbounds[0];
                let disabled = outbound
                    .stream
                    .quic_params
                    .as_ref()
                    .is_some_and(|quic| quic.disable_chrome_parrot);
                let raw_disabled = case["outbound"]
                    .pointer("/streamSettings/finalmask/quicParams/disableChromeParrot")
                    == Some(&Value::Bool(true));
                assert_eq!(disabled, raw_disabled, "{name}");
                if let Some(chrome_parrot) = case["chromeParrot"].as_bool() {
                    if !matches!(outbound.stream.transport, StreamTransport::Masque(_)) {
                        assert_eq!(chrome_parrot, !disabled, "{name}");
                    }
                }
            }
            Err(error) => {
                assert!(
                    !xray_accepts,
                    "{name}: Xray takes it, we refused: {error:?}"
                );
                assert!(
                    error.diagnostics.iter().any(|d| d
                        .path
                        .as_deref()
                        .is_some_and(|path| path.ends_with(".quicParams.disableChromeParrot"))),
                    "{name}: {error:?}"
                );
            }
        }
    }
}
