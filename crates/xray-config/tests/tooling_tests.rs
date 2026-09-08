use std::collections::BTreeSet;

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json_with_exclusive_geodata_dirs,
    tooling::{
        configuration_contract, configuration_examples,
        validate_xray_json_with_exclusive_geodata_dirs,
    },
    DiagnosticSeverity,
};

#[path = "../../../tests/support/config_tooling.rs"]
mod fixtures;

fn check(raw: &str) -> xray_config::tooling::ValidationReport {
    validate_xray_json_with_exclusive_geodata_dirs::<&str>(raw, &[])
}

#[test]
fn published_contract_is_current_and_examples_are_accepted() {
    let contract = configuration_contract();
    assert_eq!(
        include_str!("../../../docs/config-contract.json"),
        serde_json::to_string_pretty(&contract).unwrap() + "\n",
        "regenerate with cargo run -p xray-config --example config_contract > docs/config-contract.json"
    );
    assert_eq!(contract["kind"], "xray-rust-executable-config-contract");
    assert!(
        contract.get("$schema").is_none(),
        "must not masquerade as standalone JSON Schema"
    );
    for (name, config) in configuration_examples().as_object().unwrap() {
        let report = check(&config.to_string());
        assert!(report.valid, "{name}: {report:?}");
        assert!(
            report.diagnostics.is_empty(),
            "canonical example {name} warns: {report:?}"
        );
    }
}

#[test]
fn canonical_and_rejection_fixtures_match_parser_and_tooling() {
    for case in fixtures::cases() {
        let name = case["name"].as_str().unwrap();
        let raw = case["config"].to_string();
        let report = check(&raw);
        let parsed = parse_xray_json_with_exclusive_geodata_dirs::<&str>(&raw, &[]);
        assert_eq!(
            report.valid,
            case["accepted"].as_bool().unwrap(),
            "{name}: {report:?}"
        );
        assert_eq!(report.valid, parsed.is_ok(), "{name}");
        let diagnostics = match parsed {
            Ok(parsed) => parsed.diagnostics,
            Err(error) => error.diagnostics,
        };
        assert_eq!(report.diagnostics, diagnostics, "{name}");
        for (key, severity) in [
            ("errorPath", DiagnosticSeverity::Error),
            ("warningPath", DiagnosticSeverity::Warning),
        ] {
            if let Some(path) = case[key].as_str() {
                assert!(
                    report
                        .diagnostics
                        .iter()
                        .any(|d| d.path.as_deref() == Some(path) && d.severity == severity),
                    "{name}: missing {key} {path}: {report:?}"
                );
            }
        }
        if name == "encryption-key-redaction" {
            assert!(!serde_json::to_string(&report)
                .unwrap()
                .contains("private-fixture-value-must-not-be-echoed"));
        }
    }
    assert!(!check("{").valid);
}

#[test]
fn every_registered_object_has_a_reached_fail_closed_fixture() {
    let contract = configuration_contract();
    let mut reached = BTreeSet::new();
    for case in fixtures::cases() {
        let Some(objects) = case["objects"].as_object() else {
            continue;
        };
        for (id, pointer) in objects {
            let pointer = pointer.as_str().unwrap();
            let spec = contract["objects"]
                .as_array()
                .unwrap()
                .iter()
                .find(|spec| spec["id"] == *id)
                .unwrap();
            let mut config = case["config"].clone();
            let object = config
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap();
            // Recognized-key coverage and an unknown mutation exercise the real grammar node.
            assert!(
                object
                    .keys()
                    .all(|key| spec["fields"].as_array().unwrap().contains(&json!(key))),
                "{id}"
            );
            object.insert("milestoneEUnknownField".to_owned(), Value::Null);
            let report = check(&config.to_string());
            assert!(!report.valid, "{id} was advertised but never validated");
            assert!(
                report.diagnostics.iter().any(|d| d
                    .path
                    .as_deref()
                    .is_some_and(|p| p.ends_with(".milestoneEUnknownField"))),
                "{id}: {report:?}"
            );
            reached.insert(id.clone());
        }
    }
    let declared = contract["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|spec| {
            let fields = spec["fields"].as_array().unwrap();
            assert_eq!(
                fields.len(),
                fields
                    .iter()
                    .map(|f| f.as_str().unwrap())
                    .collect::<BTreeSet<_>>()
                    .len()
            );
            spec["id"].as_str().unwrap().to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        reached, declared,
        "add a canonical/mutation fixture for every grammar node"
    );
}

#[test]
fn existing_xhttp_download_and_encryption_oracles_agree_with_tooling() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/xhttp-download/config.json"
    ))
    .unwrap();
    let mut config = configuration_examples()["vless-tls"].clone();
    config["outbounds"][0]["settings"]["vnext"][0]["address"] = json!("127.0.0.1");
    for case in fixture["cases"].as_array().unwrap() {
        config["outbounds"][0]["streamSettings"] = case["stream"].clone();
        let report = check(&config.to_string());
        assert_eq!(
            report.valid,
            case["rustAccept"].as_bool().unwrap(),
            "{}: {report:?}",
            case["name"]
        );
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/vless-encryption/imports.json"
    ))
    .unwrap();
    config = configuration_examples()["vless-tls"].clone();
    for case in fixture["keys"].as_array().unwrap() {
        config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"] =
            case["encryption"].clone();
        let report = check(&config.to_string());
        assert_eq!(
            report.valid,
            case["accepted"].as_bool().unwrap(),
            "{}: {report:?}",
            case["name"]
        );
    }
    for case in fixture["profiles"].as_array().unwrap() {
        let report = check(&json!({"outbounds": [case["outbound"]]}).to_string());
        assert_eq!(
            report.valid,
            case["rustAccepted"].as_bool().unwrap(),
            "{}: {report:?}",
            case["name"]
        );
    }
}
