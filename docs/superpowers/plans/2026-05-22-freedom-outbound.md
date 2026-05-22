# Freedom Outbound Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first non-VLESS outbound: Xray-compatible `freedom` for direct TCP connects.

**Architecture:** Extend `xray-config` with a `Freedom` outbound settings variant and keep unsupported Freedom settings rejected. In `xray-core-rs`, introduce a small `TcpOutbound` enum so SOCKS/HTTP handlers can dispatch either direct Freedom TCP or existing VLESS TCP without duplicating proxy code.

**Tech Stack:** Rust, existing config parser, Tokio TCP transport, existing DNS resolver abstraction.

---

## Task 1: Config Support

- [x] **Step 1: Write failing parser tests**

Add tests that parse:

```json
{ "outbounds": [{ "tag": "direct", "protocol": "freedom" }] }
```

and reject behavior-changing Freedom settings such as `redirect`.

- [x] **Step 2: Run red tests**

Run:

```bash
cargo test -p xray-config --test parser_tests freedom
```

Expected: tests fail because `freedom` is unsupported.

- [x] **Step 3: Implement model and parser**

Add `OutboundProtocol::Freedom`, `OutboundSettings::Freedom`, and strict parser support for missing/empty Freedom settings.

- [x] **Step 4: Run config tests green**

Run:

```bash
cargo test -p xray-config --test parser_tests
```

Expected: parser tests pass.

## Task 2: Runtime Direct TCP

- [x] **Step 1: Write failing runtime test**

Add a SOCKS runtime test proving a client reaches a local echo server through a Freedom outbound, without a fake VLESS server.

- [x] **Step 2: Run red test**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_freedom_outbound
```

Expected: test fails because runtime only selects VLESS outbounds.

- [x] **Step 3: Implement TCP outbound dispatch**

Add `TcpOutbound::{Freedom, Vless}` and `open_tcp_stream_with_resolver_and_dialer`. Freedom resolves domain targets through the injected resolver and connects with `ConnectorConfig::Tcp`.

- [x] **Step 4: Wire SOCKS and HTTP handlers**

Replace VLESS-only selection in SOCKS and HTTP handlers with the new TCP outbound selector/open function.

- [x] **Step 5: Run runtime tests green**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests
```

Expected: all runtime data path tests pass when loopback sockets are permitted.

## Task 3: Verification And Commit

- [x] **Step 1: Format and test**

Run:

```bash
cargo fmt --all -- --check
cargo test -p xray-config --all-targets
cargo test -p xray-core-rs --test runtime_data_path_tests
```

- [x] **Step 2: Clippy**

Run:

```bash
cargo clippy -p xray-config -p xray-core-rs -p xray-cli --all-targets --locked -- -D warnings
```

- [x] **Step 3: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-freedom-outbound.md crates/xray-config/src/model.rs crates/xray-config/src/parser.rs crates/xray-config/src/lib.rs crates/xray-config/tests/parser_tests.rs crates/xray-config/tests/model_tests.rs crates/xray-core-rs/src/outbound.rs crates/xray-core-rs/src/socks.rs crates/xray-core-rs/src/http.rs crates/xray-core-rs/src/lib.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs
git commit -m "feat(core): support freedom outbound"
```
