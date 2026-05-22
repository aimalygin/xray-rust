# Routing IP/CIDR And Config Corpus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first mobile-relevant IP routing subset: literal IP, CIDR, and built-in `geoip:private` matching for `routing.rules[].ip`.

**Architecture:** Keep routing matchers in `xray-config` as typed, allocation-light model code. Extend the JSON parser to accept only the supported IP matcher subset and reject unsupported `geoip:`/`ext:` families explicitly. Extend `xray-core-rs` outbound selection to pass target IPs into `RoutingRule::matches`, so SOCKS/HTTP/TUN-ready sessions can bypass/proxy by IP without DNS policy coupling.

**Tech Stack:** Rust 2021, std `IpAddr`/`Ipv4Addr`/`Ipv6Addr`, Tokio runtime tests, existing `xray-config`, `xray-core-rs`, and `xray-cli` test harnesses.

---

### Task 1: Add IP Matcher Model Tests

**Files:**
- Modify: `crates/xray-config/tests/model_tests.rs`
- Modify: `crates/xray-config/src/model.rs`
- Modify: `crates/xray-config/src/lib.rs`

- [x] **Step 1: Write failing tests**

Add tests proving:

```rust
IpMatcher::Cidr(IpCidr::new("10.0.0.0".parse().unwrap(), 8).unwrap())
    .matches(&"10.42.0.1".parse().unwrap());
IpMatcher::Private.matches(&"192.168.1.1".parse().unwrap());
!IpMatcher::Private.matches(&"8.8.8.8".parse().unwrap());
```

Also add `ip_matchers: Vec<IpMatcher>` to existing `RoutingRule` test fixtures.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p xray-config --test model_tests ip_routing
```

Expected: compile failure because `IpMatcher`, `IpCidr`, and `ip_matchers` do not exist.

- [x] **Step 3: Implement model**

Add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpMatcher {
    Cidr(IpCidr),
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: std::net::IpAddr,
    prefix: u8,
}
```

Add `matches_ip`, `matches`, and private range checks for IPv4 and IPv6 local/private ranges needed by mobile bypass.

- [x] **Step 4: Verify green**

Run:

```bash
cargo test -p xray-config --test model_tests ip_routing
```

Expected: IP routing model tests pass.

### Task 2: Parse `routing.rules[].ip`

**Files:**
- Modify: `crates/xray-config/tests/parser_tests.rs`
- Modify: `crates/xray-config/src/parser.rs`

- [x] **Step 1: Write failing parser tests**

Add tests for:

```json
{ "type": "field", "ip": ["10.0.0.0/8", "192.168.1.1", "geoip:private"], "outboundTag": "direct" }
```

and rejection for:

```json
{ "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }
{ "type": "field", "ip": ["10.0.0.0/33"], "outboundTag": "direct" }
```

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p xray-config --test parser_tests routing_ip
```

Expected: compile failure or parse failure because `ip` is not allowed/parsed yet.

- [x] **Step 3: Implement parser**

Allow the `ip` field in field rules. Parse each string as:

- `geoip:private` -> `IpMatcher::Private`
- literal IP -> full-length CIDR
- CIDR -> `IpMatcher::Cidr`

Reject other `geoip:` values, `ext:` values, malformed IPs, and invalid prefixes with exact JSON paths.

- [x] **Step 4: Verify green**

Run:

```bash
cargo test -p xray-config --test parser_tests routing_ip
```

Expected: parser IP tests pass.

### Task 3: Use IP Matchers In Runtime Selection

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [x] **Step 1: Write failing runtime test**

Add a SOCKS runtime scenario where:

- default outbound is an intentionally unreachable VLESS proxy;
- a routing rule with `ip: ["127.0.0.0/8"]` selects `direct`;
- SOCKS connects to a local echo server by IPv4 address.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_uses_ip_routing_rule_to_reach_freedom_outbound
```

Expected: SOCKS failure until target IP is passed into routing.

- [x] **Step 3: Implement runtime selection**

Change `select_tcp_outbound_for_session` to pass `target_ip(target)` into `select_configured_outbound`, and make rule matching require all non-empty matcher groups to match.

- [x] **Step 4: Verify green**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_uses_ip_routing_rule_to_reach_freedom_outbound
```

Expected: test passes and echo payload is returned.

### Task 4: Full Verification And Commit

**Files:**
- All modified files.

- [x] **Step 1: Format/check**

Run:

```bash
cargo fmt --all -- --check
git diff --check
```

- [x] **Step 2: Full tests**

Run:

```bash
cargo test -p xray-config --all-targets
cargo test -p xray-core-rs --all-targets
cargo test -p xray-cli --all-targets
```

- [x] **Step 3: Clippy**

Run:

```bash
cargo clippy -p xray-config -p xray-core-rs -p xray-cli --all-targets --locked -- -D warnings
```

- [x] **Step 4: Process interop regression**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-cli --test process_interop_tests -- --ignored --nocapture
```

- [ ] **Step 5: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-routing-ip-cidr-config-corpus.md crates/xray-config/src/lib.rs crates/xray-config/src/model.rs crates/xray-config/src/parser.rs crates/xray-config/tests/model_tests.rs crates/xray-config/tests/parser_tests.rs crates/xray-core-rs/src/outbound.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs
git commit -m "feat(core): route by ip matcher"
```
