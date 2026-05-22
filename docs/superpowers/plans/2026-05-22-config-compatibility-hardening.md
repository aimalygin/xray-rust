# Config Compatibility Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Xray JSON parser safer for practical VLESS REALITY/Vision client configs by accepting the supported subset explicitly and rejecting behavior-changing fields that are not implemented yet.

**Architecture:** Keep hardening inside `xray-config`; do not change runtime behavior in this slice. Add small parser validation helpers for object field allowlists, optional booleans, routing validation, inbound settings validation, and outbound stream validation. Use parser tests as the contract.

**Tech Stack:** Rust, serde_json, existing `Diagnostic` model, Cargo tests.

---

## Files

- Modify: `crates/xray-config/src/parser.rs`
  - Add compatibility validation helpers.
  - Parse default outbound tag from the first configured outbound tag.
  - Validate `routing`, inbound settings, outbound settings, and stream settings.
- Modify: `crates/xray-config/tests/parser_tests.rs`
  - Add red tests for routing, default outbound, inbound settings, mux, `sendThrough`, TLS fingerprint, TLS `allowInsecure`, and TCP header settings.
- Verify: `crates/xray-config/tests/model_tests.rs`
  - Existing model tests should keep passing without changes.

## Task 1: Routing And Default Outbound

**Files:**
- Modify: `crates/xray-config/tests/parser_tests.rs`
- Modify: `crates/xray-config/src/parser.rs`

- [x] **Step 1: Write failing parser tests**

Add tests with this behavior:

```rust
#[test]
fn sets_default_outbound_tag_to_first_outbound_tag() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.default_outbound_tag.as_deref(), Some("proxy"));
}

#[test]
fn rejects_non_as_is_routing_domain_strategy_with_path() {
    let raw = raw_with_routing(r#""domainStrategy": "IPIfNonMatch""#);

    assert_parse_error_path(&raw, "$.routing.domainStrategy");
}

#[test]
fn rejects_non_empty_routing_rules_with_path() {
    let raw = raw_with_routing(r#""rules": [{ "type": "field", "outboundTag": "proxy" }]"#);

    assert_parse_error_path(&raw, "$.routing.rules");
}
```

- [x] **Step 2: Run the red tests**

Run:

```bash
cargo test -p xray-config --test parser_tests
```

Expected: tests fail because `default_outbound_tag` is not set and routing is not validated.

- [x] **Step 3: Implement routing validation**

Implement:

```rust
fn parse_config(&mut self) -> CoreConfig {
    self.validate_top_level_fields();
    let inbounds = self.parse_inbounds();
    let outbounds = self.parse_outbounds();
    self.validate_routing();
    let default_outbound_tag = outbounds.first().and_then(|outbound| outbound.tag.clone());

    CoreConfig {
        inbounds,
        outbounds,
        default_outbound_tag,
    }
}
```

Add helpers that accept missing `routing`, accept `domainStrategy: "AsIs"`, accept empty `rules`, and reject unsupported routing behavior with exact JSON paths.

- [x] **Step 4: Run the routing tests green**

Run:

```bash
cargo test -p xray-config --test parser_tests
```

Expected: all parser tests pass.

## Task 2: Inbound Settings Compatibility

**Files:**
- Modify: `crates/xray-config/tests/parser_tests.rs`
- Modify: `crates/xray-config/src/parser.rs`

- [x] **Step 1: Write failing parser tests**

Add tests with this behavior:

```rust
#[test]
fn rejects_enabled_inbound_sniffing_with_path() {
    let raw = raw_with_inbound_extra(r#""sniffing": { "enabled": true }"#);

    assert_parse_error_path(&raw, "$.inbounds[0].sniffing.enabled");
}

#[test]
fn rejects_socks_password_auth_with_path() {
    let raw = raw_with_socks_settings(r#""auth": "password""#);

    assert_parse_error_path(&raw, "$.inbounds[0].settings.auth");
}

#[test]
fn rejects_socks_udp_enabled_with_path() {
    let raw = raw_with_socks_settings(r#""udp": true"#);

    assert_parse_error_path(&raw, "$.inbounds[0].settings.udp");
}
```

- [x] **Step 2: Run the red tests**

Run:

```bash
cargo test -p xray-config --test parser_tests
```

Expected: tests fail because the parser currently ignores these fields.

- [x] **Step 3: Implement inbound validation**

Validate SOCKS and HTTP settings without changing the normalized `InboundConfig` shape:

- `sniffing.enabled: true` is an error.
- SOCKS `auth` must be missing or `"noauth"`.
- SOCKS `udp: true` is an error.
- SOCKS `accounts` must be missing or empty.
- Unknown inbound top-level fields are errors.

- [x] **Step 4: Run the inbound tests green**

Run:

```bash
cargo test -p xray-config --test parser_tests
```

Expected: all parser tests pass.

## Task 3: Outbound And Stream Compatibility

**Files:**
- Modify: `crates/xray-config/tests/parser_tests.rs`
- Modify: `crates/xray-config/src/parser.rs`

- [x] **Step 1: Write failing parser tests**

Add tests with this behavior:

```rust
#[test]
fn rejects_enabled_mux_with_path() {
    let raw = raw_with_outbound_extra(r#""mux": { "enabled": true }"#);

    assert_parse_error_path(&raw, "$.outbounds[0].mux.enabled");
}

#[test]
fn rejects_send_through_with_path() {
    let raw = raw_with_outbound_extra(r#""sendThrough": "127.0.0.2""#);

    assert_parse_error_path(&raw, "$.outbounds[0].sendThrough");
}

#[test]
fn rejects_tls_allow_insecure_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "allowInsecure": true"#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.tlsSettings.allowInsecure");
}

#[test]
fn rejects_tls_fingerprint_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "fingerprint": "chrome""#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.tlsSettings.fingerprint");
}

#[test]
fn rejects_tcp_header_type_with_path() {
    let raw = raw_with_tcp_settings(r#""header": { "type": "http" }"#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.tcpSettings.header.type");
}
```

- [x] **Step 2: Run the red tests**

Run:

```bash
cargo test -p xray-config --test parser_tests
```

Expected: tests fail because these fields are currently ignored or deferred to runtime.

- [x] **Step 3: Implement outbound validation**

Validate:

- `mux.enabled: true` is an error.
- `sendThrough` is an error.
- `proxySettings` is an error.
- TLS `allowInsecure: true` is an error.
- TLS `fingerprint` is an error in this parser slice.
- TCP header type must be missing, empty, or `"none"`.
- Unknown outbound and stream fields are errors.

- [x] **Step 4: Run the outbound tests green**

Run:

```bash
cargo test -p xray-config --test parser_tests
```

Expected: all parser tests pass.

## Task 4: Full Verification And Commit

**Files:**
- Verify all modified files.

- [x] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit code 0.

- [x] **Step 2: Test config crate**

Run:

```bash
cargo test -p xray-config --all-targets
```

Expected: all tests pass.

- [x] **Step 3: Run focused downstream core tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests
```

Expected: all selected tests pass.

- [x] **Step 4: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-config-compatibility-hardening.md crates/xray-config/src/parser.rs crates/xray-config/tests/parser_tests.rs
git commit -m "feat(config): harden xray compatibility diagnostics"
```

Expected: one commit containing the plan and parser hardening.
