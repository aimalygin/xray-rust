use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{json, Value};
use xray_config::tooling::{
    configuration_contract, configuration_examples, validate_xray_json_with_exclusive_geodata_dirs,
};

#[path = "../../../tests/support/config_tooling.rs"]
mod fixtures;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "xray-config-tooling-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run(args: &[&str], input: &str, cwd: &Directory) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_xray-rust"))
        .args(args)
        .current_dir(&cwd.0)
        // Both would fail startup. Config tooling must never enter that path.
        .env("XRAY_TUN_FD", "invalid-for-startup")
        .env("XRAY_TUN_PROFILE", "invalid-for-startup")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn report(output: &Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr: {}; stdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must contain exactly one JSON document")
}

#[test]
fn contract_and_examples_are_available_without_startup() {
    let cwd = Directory::new();
    assert_eq!(
        report(&run(&["config", "contract"], "", &cwd), 0),
        configuration_contract()
    );
    for (name, example) in configuration_examples().as_object().unwrap() {
        assert_eq!(
            report(&run(&["config", "example", name], "", &cwd), 0),
            *example
        );
    }
}

#[test]
fn fixture_reports_match_the_linked_parser_over_stdio() {
    let cwd = Directory::new();
    for case in fixtures::cases() {
        let raw = case["config"].to_string();
        let expected = validate_xray_json_with_exclusive_geodata_dirs(&raw, &[&cwd.0]);
        assert_eq!(
            expected.valid,
            case["accepted"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        let output = run(
            &[
                "config",
                "check",
                "--config",
                "-",
                "--json",
                "--geodata-dir",
                cwd.0.to_str().unwrap(),
            ],
            &raw,
            &cwd,
        );
        let actual = report(&output, i32::from(!expected.valid));
        assert_eq!(
            actual,
            serde_json::to_value(expected).unwrap(),
            "{}",
            case["name"]
        );
        assert!(!String::from_utf8_lossy(&output.stdout)
            .contains("private-fixture-value-must-not-be-echoed"));
    }
    let output = run(&["config", "check", "-config", "-", "--json"], "{", &cwd);
    assert_eq!(report(&output, 1)["diagnostics"][0]["path"], "$");
}

#[test]
fn file_and_stdin_checks_report_errors_warnings_and_io_failures() {
    let cwd = Directory::new();
    let raw = configuration_examples()["socks-direct"].to_string();
    fs::write(cwd.0.join("client.json"), &raw).unwrap();
    let file = run(
        &["config", "check", "-config", "client.json", "--json"],
        "",
        &cwd,
    );
    let stdin = run(&["config", "check", "--json", "--config", "-"], &raw, &cwd);
    assert_eq!(report(&file, 0), report(&stdin, 0));
    // No profile or credential echo on a successful check.
    assert!(!String::from_utf8_lossy(&file.stdout).contains("socks-in"));
    for name in ["missing.json", "invalid-utf8.json"] {
        if name == "invalid-utf8.json" {
            fs::write(cwd.0.join(name), [0xff]).unwrap();
        }
        let output = run(&["config", "check", "--config", name, "--json"], "", &cwd);
        assert_eq!(report(&output, 2)["scope"], "input");
    }
    let warning = json!({"outbounds":[{"protocol":"freedom","streamSettings":{"network":"xhttp","xhttpSettings":{"scMaxConcurrentPosts":4}}}]});
    let output = run(
        &["config", "check", "--config", "-"],
        &warning.to_string(),
        &cwd,
    );
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("configuration accepted by parser"));
    assert!(
        text.contains("warning: $.outbounds[0].streamSettings.xhttpSettings.scMaxConcurrentPosts")
    );
}

#[test]
fn geodata_search_matches_run_and_explicit_directories_are_exclusive() {
    let cwd = Directory::new();
    let config_dir = cwd.0.join("profiles");
    fs::create_dir(&config_dir).unwrap();
    // GeoSiteList with TEST containing the full-domain matcher example.test.
    fs::write(
        config_dir.join("geosite.dat"),
        b"\x0a\x18\x0a\x04TEST\x12\x10\x08\x03\x12\x0cexample.test",
    )
    .unwrap();
    let raw = json!({"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["geosite:test"],"outboundTag":"direct"}]}}).to_string();
    fs::write(config_dir.join("client.json"), &raw).unwrap();
    let args = [
        "config",
        "check",
        "--config",
        "profiles/client.json",
        "--json",
    ];
    assert_eq!(report(&run(&args, "", &cwd), 0)["valid"], true);
    let mut explicit = args.to_vec();
    explicit.extend(["--geodata-dir", cwd.0.to_str().unwrap()]);
    assert_eq!(
        report(&run(&explicit, "", &cwd), 1)["valid"],
        false,
        "must not fall back to the config directory"
    );
    explicit.extend(["--geodata-dir", config_dir.to_str().unwrap()]);
    assert_eq!(report(&run(&explicit, "", &cwd), 0)["valid"], true);
    // stdin has no config directory, so only an explicit resource list reaches it.
    assert_eq!(
        report(
            &run(&["config", "check", "--config", "-", "--json"], &raw, &cwd),
            1
        )["valid"],
        false
    );
}

#[test]
fn malformed_options_fail_without_reading_stdin() {
    let cwd = Directory::new();
    for args in [
        vec!["config", "check"],
        vec!["config", "check", "--config", "--json"],
        vec!["config", "check", "--config", "-", "--config", "-"],
        vec!["config", "check", "--config", "-", "--json", "--json"],
        vec!["config", "check", "--config", "-", "--geodata-dir"],
        vec!["config", "contract", "--typo"],
        vec!["config", "example", "unknown"],
    ] {
        let output = run(&args, "", &cwd);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
    }
}
