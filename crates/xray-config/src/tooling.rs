//! Machine-readable configuration discovery and exact, parser-backed validation.
//!
//! The contract is intentionally an executable grammar, not a JSON Schema
//! approximation of context-dependent aliases, crypto keys and external geodata.
//! Validation does not start a core, bind listeners or perform network I/O.

use std::path::Path;

use serde::Serialize;
use serde_json::{json, Value};

use crate::{ConfigParseError, Diagnostic, ParsedConfig};

/// Version of the tooling document and diagnostic envelope, independent of C ABI.
pub const CONFIG_TOOLING_VERSION: u32 = 1;

/// A report contains diagnostics only, never the parsed configuration or keys.
/// Diagnostic messages are human-readable parser output, not stable error codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub schema_version: u32,
    pub core_version: &'static str,
    pub scope: &'static str,
    pub valid: bool,
    pub diagnostics: Vec<Diagnostic>,
}

impl From<Result<ParsedConfig, ConfigParseError>> for ValidationReport {
    fn from(result: Result<ParsedConfig, ConfigParseError>) -> Self {
        let valid = result.is_ok();
        let diagnostics = match result {
            Ok(parsed) => parsed.diagnostics,
            Err(error) => error.diagnostics,
        };
        Self {
            schema_version: CONFIG_TOOLING_VERSION,
            core_version: crate::version(),
            scope: "parser",
            valid,
            diagnostics,
        }
    }
}

/// Validate with the same default resource lookup as `parse_xray_json`.
pub fn validate_xray_json(raw: &str) -> ValidationReport {
    crate::parse_xray_json(raw).into()
}

/// Prepend resource directories to the parser's default lookup order.
pub fn validate_xray_json_with_geodata_dirs<P: AsRef<Path>>(
    raw: &str,
    dirs: &[P],
) -> ValidationReport {
    crate::parse_xray_json_with_geodata_dirs(raw, dirs).into()
}

/// Use only the supplied resource directories, including an empty list.
/// Useful for reproducible editor/CI validation without ambient geodata.
pub fn validate_xray_json_with_exclusive_geodata_dirs<P: AsRef<Path>>(
    raw: &str,
    dirs: &[P],
) -> ValidationReport {
    crate::parse_xray_json_with_exclusive_geodata_dirs(raw, dirs).into()
}

/// Generate the versioned discovery document from the parser's field registry.
///
/// `objects[].fields` are recognized keys, including restricted/ignored input.
/// They are not independently valid values or an unconditional allowlist.
/// Only the executable validator decides acceptance of a complete input.
pub fn configuration_contract() -> Value {
    json!({
        "schemaVersion": CONFIG_TOOLING_VERSION,
        "coreVersion": crate::version(),
        "kind": "xray-rust-executable-config-contract",
        "validation": {
            "scope": "parser",
            "command": ["xray-rust", "config", "check", "--config", "-", "--json"],
            "rustFunction": "xray_config::tooling::validate_xray_json",
            "acceptance": "Exactly the linked xray-config parser with the same geodata search paths. Warnings do not invalidate an input.",
            "fieldSemantics": "Recognized keys include compatibility-only and restricted fields. Unknown keys fail when their grammar node is parsed. Activation, value types, aliases, cross-field constraints and budgets are enforced by the executable validator.",
            "notChecked": ["core outbound graph/carrier compilation", "listener binding", "platform host policy", "network reachability"],
            "geodata": "Local files are read only when referenced; no downloads. CLI defaults match run (config directory, working directory, executable directory). --geodata-dir selects an exclusive ordered search list.",
            "exitCodes": {"0": "accepted, possibly with warnings", "1": "parser rejected", "2": "arguments, input or output failure"}
        },
        "objects": crate::surface::OBJECTS,
        "additionalSurfaces": [
            {"context": "$.log", "semantics": "Accepted and ignored, including unknown fields; runtime logging belongs to the embedding API."},
            {"context": "$.inbounds[].settings (tun)", "fields": ["userLevel"], "semantics": "Only userLevel is consumed. Other input is ignored, not a supported interface/route configuration."},
            {"context": "streamSettings.realitySettings", "fields": ["serverName", "fingerprint", "publicKey", "shortId", "spiderX", "mldsa65Verify"], "semantics": "Validated by the dedicated REALITY parser when selected. Additional fields are currently ignored, not advertised as runtime features."},
            {"context": "$.dns.hosts", "semantics": "Dynamic domain-matcher keys map to an IP, domain alias or nonempty IP array; parser budgets and geodata expansion apply."},
            {"context": "$.policy.levels", "semantics": "Dynamic u32 level keys map to POLICY_LEVEL."},
            {"context": "wsSettings.headers; httpupgradeSettings.headers; xhttpSettings.headers", "semantics": "Dynamic header names with string/null values and carrier-specific Host rules."},
            {"context": "xhttpSettings.downloadSettings; splithttpSettings.downloadSettings; effective extra.downloadSettings", "fields": ["address", "port"], "extends": "STREAM", "semantics": "Requires address, port 1..65535 and explicit XHTTP method/network. A separate bounded stream is parsed with paths remapped to downloadSettings; recursive downloads, stream-one and chaining are unsupported."}
        ],
        "examples": configuration_examples(),
        "documentation": "docs/config-tooling.md"
    })
}

/// Synthetic canonical starting points, checked against the parser in CI.
pub fn configuration_examples() -> Value {
    let socks = json!({
        "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1080,
        "settings": {"auth": "noauth", "udp": true}
    });
    let vless = json!({
        "tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "server.example", "port": 443,
            "users": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none"}]}]},
        "streamSettings": {"network": "raw", "security": "tls",
            "tlsSettings": {"serverName": "server.example", "fingerprint": "chrome"}}
    });
    let mut download = vless.clone();
    download["streamSettings"] = json!({
        "network": "xhttp", "security": "tls",
        "tlsSettings": {"serverName": "server.example", "alpn": ["h2"]},
        "xhttpSettings": {"path": "/up", "mode": "packet-up", "downloadSettings": {
            "address": "download.example", "port": 443, "network": "xhttp", "security": "tls",
            "tlsSettings": {"serverName": "download.example", "alpn": ["h2"]},
            "xhttpSettings": {"path": "/down"}
        }}
    });
    json!({
        "socks-direct": {"inbounds": [socks], "outbounds": [{"tag": "direct", "protocol": "freedom"}]},
        "vless-tls": {"inbounds": [socks], "outbounds": [vless]},
        "xhttp-download": {"inbounds": [socks], "outbounds": [download]},
        "dns-routing": {
            "inbounds": [socks],
            "outbounds": [{"tag": "direct", "protocol": "freedom"},
                {"tag": "dns-out", "protocol": "dns", "settings": {
                    "rewriteNetwork": "tcp", "rewriteAddress": "192.0.2.53", "rewritePort": 53,
                    "rules": [{"action": "return", "qType": "64-65", "rCode": 3}]}}],
            "dns": {"servers": ["192.0.2.53"], "hosts": {"service.example": "192.0.2.80"}, "queryStrategy": "UseIPv4"},
            "routing": {"domainStrategy": "IPOnDemand", "rules": [
                {"type": "field", "network": "udp,tcp", "port": 53, "outboundTag": "dns-out"},
                {"type": "field", "ip": ["192.0.2.0/24"], "outboundTag": "direct"}
            ]}
        }
    })
}
