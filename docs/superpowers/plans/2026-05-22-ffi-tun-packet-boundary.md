# FFI TUN Packet Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the existing bounded TUN packet endpoint through the C ABI so mobile VPN adapters can push packets into the core, poll emitted packets, and read packet counters.

**Architecture:** Keep queueing and packet accounting in `xray-tun`. Add nonblocking poll helpers to avoid blocking mobile host threads. Keep FFI as a thin conversion layer from raw pointers to `bytes::Bytes`, with stable status codes and `XrayTunStats`.

**Tech Stack:** Rust, C ABI (`extern "C"`), Tokio runtime owned by `XrayCoreHandle`, `bytes::Bytes`, existing `xray-tun` endpoint.

---

## Files

- Modify: `crates/xray-tun/src/lib.rs`
  - Add `try_poll_inbound` and `try_poll_outbound`.
- Modify: `crates/xray-tun/tests/tun_tests.rs`
  - Add nonblocking poll tests.
- Modify: `crates/xray-ffi/Cargo.toml`
  - Add direct `bytes` dependency.
- Modify: `crates/xray-ffi/src/lib.rs`
  - Add TUN status codes, stats struct, push, poll, and stats ABI functions.
- Modify: `crates/xray-ffi/tests/ffi_tests.rs`
  - Add FFI TUN push, no-packet poll, and stats tests.

## Task 1: Nonblocking TUN Poll

**Files:**
- Modify: `crates/xray-tun/tests/tun_tests.rs`
- Modify: `crates/xray-tun/src/lib.rs`

- [x] **Step 1: Write failing tests**

Add tests for:

```rust
#[tokio::test]
async fn tun_endpoint_try_poll_returns_none_when_queue_is_empty() {
    let tun = TunEndpoint::new(TunConfig { mtu: 1500, queue_depth: 1 });

    assert_eq!(tun.try_poll_outbound().await.unwrap(), None);
}

#[tokio::test]
async fn tun_endpoint_try_poll_returns_queued_packet() {
    let tun = TunEndpoint::new(TunConfig { mtu: 1500, queue_depth: 1 });

    tun.push_outbound(Bytes::from_static(&[1, 2, 3])).await.unwrap();

    assert_eq!(tun.try_poll_outbound().await.unwrap(), Some(Bytes::from_static(&[1, 2, 3])));
}
```

- [x] **Step 2: Run red tests**

Run:

```bash
cargo test -p xray-tun --test tun_tests
```

Expected: compilation fails because `try_poll_outbound` does not exist.

- [x] **Step 3: Implement try poll**

Add async `try_poll_inbound` and `try_poll_outbound` methods that lock the corresponding receiver and return `Ok(None)` when the queue is empty.

- [x] **Step 4: Run TUN tests green**

Run:

```bash
cargo test -p xray-tun --test tun_tests
```

Expected: all TUN tests pass.

## Task 2: FFI TUN ABI

**Files:**
- Modify: `crates/xray-ffi/Cargo.toml`
- Modify: `crates/xray-ffi/src/lib.rs`
- Modify: `crates/xray-ffi/tests/ffi_tests.rs`

- [x] **Step 1: Write failing FFI tests**

Add tests for:

```rust
#[test]
fn ffi_tun_push_packet_updates_stats() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let packet = [0x45, 0, 0, 20];

    assert_eq!(unsafe { xray_tun_push_packet(core, packet.as_ptr(), packet.len(), &mut err) }, XrayStatus::Ok);

    let mut stats = XrayTunStats::default();
    assert_eq!(unsafe { xray_tun_stats(core, &mut stats, &mut err) }, XrayStatus::Ok);
    assert_eq!(stats.inbound_packets, 1);

    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_tun_poll_packet_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut written = 0usize;
    let mut buffer = [0u8; 1500];

    assert_eq!(
        unsafe { xray_tun_poll_packet(core, buffer.as_mut_ptr(), buffer.len(), &mut written, &mut err) },
        XrayStatus::NoPacket
    );
    assert_eq!(written, 0);

    unsafe { xray_core_free(core) };
}
```

- [x] **Step 2: Run red tests**

Run:

```bash
cargo test -p xray-ffi --test ffi_tests
```

Expected: compilation fails because the TUN FFI symbols and status codes do not exist.

- [x] **Step 3: Implement TUN FFI**

Implement:

- `xray_tun_push_packet(handle, data, len, error) -> XrayStatus`
- `xray_tun_poll_packet(handle, buffer, buffer_len, written, error) -> XrayStatus`
- `xray_tun_stats(handle, stats, error) -> XrayStatus`
- `XrayTunStats`
- `NoPacket`, `BufferTooSmall`, and `TunError` statuses.

- [x] **Step 4: Run FFI tests green**

Run:

```bash
cargo test -p xray-ffi --test ffi_tests
```

Expected: all FFI tests pass.

## Task 3: Verification And Commit

**Files:**
- Verify all modified files.

- [x] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit code 0.

- [x] **Step 2: Test crates**

Run:

```bash
cargo test -p xray-tun --all-targets
cargo test -p xray-ffi --all-targets
```

Expected: all tests pass.

- [x] **Step 3: Clippy**

Run:

```bash
cargo clippy -p xray-tun -p xray-ffi --all-targets --locked -- -D warnings
```

Expected: exit code 0.

- [x] **Step 4: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-ffi-tun-packet-boundary.md crates/xray-tun/src/lib.rs crates/xray-tun/tests/tun_tests.rs crates/xray-ffi/Cargo.toml crates/xray-ffi/src/lib.rs crates/xray-ffi/tests/ffi_tests.rs Cargo.lock
git commit -m "feat(ffi): expose tun packet boundary"
```

Expected: one commit containing the nonblocking TUN poll helper and C ABI packet functions.
