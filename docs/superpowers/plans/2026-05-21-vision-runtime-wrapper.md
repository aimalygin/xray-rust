# Vision Runtime Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Vision stream wrapper and adjust runtime gating so `VLESS + REALITY + xtls-rprx-vision` reaches the protected transport boundary without opening live REALITY connect yet.

**Architecture:** `xray-proxy::vless` owns Vision framing through a new `VisionStream<S>` wrapper. `xray-core-rs` allows Vision only for selected REALITY outbounds and keeps raw TCP/TLS Vision rejected. The existing transport dialer still rejects `ConnectorConfig::Reality(_)`, preserving the no-partial-live-launch rule.

**Tech Stack:** Rust 2021, Tokio `AsyncRead`/`AsyncWrite`, `bytes::BytesMut`, existing `VisionPadding` and `unpad_vision_block`, existing `xray-core-rs` runtime tests.

---

### Task 1: Add Vision Stream Wrapper Tests

**Files:**
- Test: `crates/xray-proxy/tests/vision_stream_tests.rs`

- [ ] **Step 1: Write failing tests**

Create `crates/xray-proxy/tests/vision_stream_tests.rs`:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_proxy::vless::{unpad_vision_block, VisionCommand, VisionStream};

const USER_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[tokio::test]
async fn vision_stream_write_emits_padded_blocks() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);

    stream.write_all(b"hello vision").await.unwrap();
    stream.flush().await.unwrap();

    let mut padded = vec![0; 16 + 5 + "hello vision".len()];
    server.read_exact(&mut padded).await.unwrap();
    let unpadded = unpad_vision_block(&padded, &USER_ID).unwrap();

    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(&unpadded.payload[..], b"hello vision");
}

#[tokio::test]
async fn vision_stream_read_returns_unpadded_payload() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut sender = VisionStream::new(server, USER_ID, [0, 0, 0, 0]);
    let mut receiver = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);

    sender.write_all(b"reply bytes").await.unwrap();
    sender.shutdown().await.unwrap();

    let mut received = Vec::new();
    receiver.read_to_end(&mut received).await.unwrap();

    assert_eq!(received, b"reply bytes");
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```sh
cargo test -p xray-proxy --test vision_stream_tests
```

Expected: compile failure because `VisionStream` is not defined/exported yet.

### Task 2: Implement VisionStream

**Files:**
- Create: `crates/xray-proxy/src/vless/vision_stream.rs`
- Modify: `crates/xray-proxy/src/vless/mod.rs`
- Test: `crates/xray-proxy/tests/vision_stream_tests.rs`

- [ ] **Step 1: Export module shape**

Update `crates/xray-proxy/src/vless/mod.rs`:

```rust
mod vision;
mod vision_stream;
mod wire;

pub use vision::{
    unpad_vision_block, UnpaddedVisionBlock, VisionCommand, VisionError, VisionPadding,
};
pub use vision_stream::VisionStream;
pub use wire::{encode_request_header, VlessCommand, VlessRequest, WireError};
```

- [ ] **Step 2: Implement minimal async wrapper**

Create `crates/xray-proxy/src/vless/vision_stream.rs` with a `VisionStream<S>` that implements `AsyncRead`, `AsyncWrite`, and `Unpin` when `S: AsyncRead + AsyncWrite + Unpin`. It should:

- hold `inner: S`;
- hold `user_id: [u8; 16]`;
- hold `padding: VisionPadding`;
- buffer pending encoded writes in `BytesMut`;
- buffer raw inbound frame bytes and decoded payload bytes in `BytesMut`;
- encode each `poll_write` input chunk with `VisionCommand::Continue`;
- decode complete inbound Vision frames before yielding raw payload.

- [ ] **Step 3: Run GREEN tests**

Run:

```sh
cargo test -p xray-proxy --test vision_stream_tests
cargo test -p xray-proxy --test vision_tests
```

Expected: all Vision stream and existing Vision block tests pass.

### Task 3: Adjust Core Flow Gating

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write failing core tests**

Change `rejects_vision_flow_for_reality_until_vision_wrapper_exists` to expect selected REALITY transport with the Vision user flow preserved. Add or keep a guard test proving raw TCP Vision still returns `CoreError::UnsupportedOutboundFlow`.

- [ ] **Step 2: Run test to verify RED**

Run:

```sh
cargo test -p xray-core-rs --test runtime_data_path_tests vision
```

Expected: the REALITY+Vision selection test fails because `select_vless_tcp_outbound` still rejects all flows.

- [ ] **Step 3: Implement selection rule**

In `select_vless_tcp_outbound`, reject non-empty flow only unless the flow is exactly `xtls-rprx-vision` and stream security is REALITY. Build `ConnectorConfig::Reality` only after this decision to avoid unnecessary `short_id` cloning for rejected configs.

- [ ] **Step 4: Run focused tests**

Run:

```sh
cargo test -p xray-core-rs --test runtime_data_path_tests vision
cargo test -p xray-transport --test transport_tests transport_dialer_rejects_reality_configs_without_plaintext_downgrade
```

Expected: REALITY+Vision selection passes, raw TCP/TLS Vision guards pass, and the live REALITY dialer gate remains closed.

### Task 4: Integrate Wrapper Boundary In Open Path

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Test: `crates/xray-core-rs/src/outbound.rs`

- [ ] **Step 1: Add focused unit coverage**

Update the existing outbound unit test so raw flow still fails before connecting, and add a helper assertion that `xtls-rprx-vision` with REALITY does not fail before transport dialing. The latter should still return transport `UnsupportedConnectorConfig("reality")` with the current dialer.

- [ ] **Step 2: Wrap post-header stream for Vision**

After writing the VLESS request header, if `outbound.user.flow.as_deref() == Some("xtls-rprx-vision")`, return `Box::new(VisionStream::new(stream, *outbound.user.id.as_bytes(), [0, 0, 0, 0]))`. This code path will become active once REALITY connect is implemented.

- [ ] **Step 3: Run focused tests**

Run:

```sh
cargo test -p xray-core-rs outbound::tests
```

Expected: outbound flow gate tests pass and REALITY live connect remains closed by transport.

### Task 5: Documentation And Full Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/verification.md`

- [ ] **Step 1: Update status text**

Document that Vision wrapper exists and REALITY+Vision selection reaches the protected transport boundary, while live REALITY connector and local Xray-core interoperability remain future work.

- [ ] **Step 2: Run final verification**

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

Expected: all checks pass.

- [ ] **Step 3: Commit**

Run:

```sh
git add README.md docs/verification.md crates/xray-core-rs crates/xray-proxy
git commit -m "feat(proxy): add vision runtime wrapper"
```
