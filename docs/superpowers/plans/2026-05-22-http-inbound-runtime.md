# HTTP Inbound Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Start configured HTTP proxy inbounds and tunnel HTTP CONNECT traffic through the existing VLESS outbound runtime path.

**Architecture:** Keep HTTP parsing in `xray-proxy` and listener/runtime orchestration in `xray-core-rs`. The HTTP runtime mirrors the SOCKS runtime: parse an inbound target, open the selected VLESS TCP outbound, send a protocol success response, then stream with `copy_bidirectional`.

**Tech Stack:** Rust, Tokio TCP listeners, existing `xray_proxy::inbound::parse_http_connect`, existing VLESS outbound helpers.

---

## Files

- Modify: `crates/xray-proxy/src/inbound/http.rs`
  - Consume HTTP CONNECT headers through the blank line before returning the target.
- Modify: `crates/xray-proxy/tests/inbound_parser_tests.rs`
  - Add parser regression coverage that headers are consumed and payload bytes remain unread.
- Create: `crates/xray-core-rs/src/http.rs`
  - Add HTTP listener accept loop and connection handler.
- Modify: `crates/xray-core-rs/src/lib.rs`
  - Start HTTP listeners from `InboundProtocol::Http`.
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`
  - Add HTTP CONNECT end-to-end runtime coverage through the fake VLESS server.

## Task 1: HTTP Parser Header Consumption

**Files:**
- Modify: `crates/xray-proxy/tests/inbound_parser_tests.rs`
- Modify: `crates/xray-proxy/src/inbound/http.rs`

- [x] **Step 1: Write failing parser test**

Add:

```rust
#[tokio::test]
async fn parses_http_connect_consumes_headers_before_payload() {
    let mut input = Cursor::new(
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\npayload".to_vec(),
    );

    let target = parse_http_connect(&mut input).await.unwrap();
    let mut remaining = Vec::new();
    input.read_to_end(&mut remaining).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(remaining, b"payload");
}
```

- [x] **Step 2: Run red test**

Run:

```bash
cargo test -p xray-proxy --test inbound_parser_tests parses_http_connect_consumes_headers_before_payload
```

Expected: test fails because headers remain unread.

- [x] **Step 3: Implement header consumption**

Read CRLF-terminated lines after the CONNECT request line until an empty line is found. Reuse the existing line length limit for each header line.

- [x] **Step 4: Run parser tests green**

Run:

```bash
cargo test -p xray-proxy --test inbound_parser_tests
```

Expected: all inbound parser tests pass.

## Task 2: HTTP Runtime Listener

**Files:**
- Create: `crates/xray-core-rs/src/http.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [x] **Step 1: Write failing runtime test**

Add:

```rust
#[tokio::test]
async fn http_client_reaches_echo_target_through_vless_tcp_outbound() {
    timeout(Duration::from_secs(2), run_http_to_vless_echo_scenario())
        .await
        .unwrap();
}
```

The helper starts an HTTP inbound on port `0`, sends a real `CONNECT host:port HTTP/1.1` request, expects `HTTP/1.1 200 Connection Established`, then verifies echoed payload bytes.

- [x] **Step 2: Run red test**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests http_client_reaches_echo_target_through_vless_tcp_outbound
```

Expected: test fails because `Core::start` does not bind HTTP inbounds.

- [x] **Step 3: Implement HTTP listener**

Create `http.rs` with a `serve_http_listener` function that:

- accepts TCP connections until shutdown;
- parses CONNECT targets with `parse_http_connect`;
- opens the configured VLESS TCP outbound;
- writes `HTTP/1.1 200 Connection Established\r\n\r\n` on success;
- writes a minimal `502 Bad Gateway` or `400 Bad Request` response on failure;
- streams via `tokio::io::copy_bidirectional`.

- [x] **Step 4: Wire Core::start**

In `Core::start`, bind both SOCKS and HTTP inbounds, preserve bound inbound reporting, and spawn the correct listener task for each protocol.

- [x] **Step 5: Run runtime test green**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests http_client_reaches_echo_target_through_vless_tcp_outbound
```

Expected: test passes when loopback sockets are permitted.

## Task 3: Verification And Commit

**Files:**
- Verify all modified files.

- [x] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit code 0.

- [x] **Step 2: Test changed crates**

Run:

```bash
cargo test -p xray-proxy --test inbound_parser_tests
cargo test -p xray-core-rs --test runtime_data_path_tests
```

Expected: all selected tests pass when loopback sockets are permitted.

- [x] **Step 3: Clippy**

Run:

```bash
cargo clippy -p xray-proxy -p xray-core-rs --all-targets --locked -- -D warnings
```

Expected: exit code 0.

- [x] **Step 4: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-http-inbound-runtime.md crates/xray-proxy/src/inbound/http.rs crates/xray-proxy/tests/inbound_parser_tests.rs crates/xray-core-rs/src/http.rs crates/xray-core-rs/src/lib.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs
git commit -m "feat(core): run http inbound"
```

Expected: one commit containing HTTP inbound runtime support.
