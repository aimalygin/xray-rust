# TUN Pump Resilience and iOS Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a single transient TUN I/O error from silently killing all packet flow, make that failure visible when it does happen, and close the four confirmed configuration/diagnostic defects found while investigating a report of "connects on cellular but nothing loads".

**Architecture:** Two layers. In the Rust engine, the fd-backed TUN pump gains an explicit error-disposition classifier so transient errors retry instead of terminating the read/write loops, plus counters that make a terminated loop observable. In the Apple platform layer, utun discovery moves to the hardened WireGuard technique, the selected interface is logged, `XrayCoreError` starts carrying its message across the NSError bridge, and the generated VLESS config gains `sniffing` and an explicit IPv4-only DNS strategy while the tunnel stops advertising IPv6.

**Tech Stack:** Rust 2021 (`xray-tun`, `xray-core-rs`), Swift 5.9 (`platform/apple`, SwiftPM), Tokio, XCTest.

---

## Background — why each task exists

The investigation that produced this plan is summarised here so tasks are not executed blind.

An iOS user on a cellular network reported the tunnel connecting successfully while no application traffic worked, including traffic that routing sends **direct** (bypassing the proxy entirely). The Diagnostics screen showed `Status: Connected`, `Inbound packets: 6`, `Outbound packets: 5`, `Active TCP flows: 0`. The startup probe passing proves the engine's own sockets, DNS bootstrap, VLESS, REALITY and Vision all work on that network, because a probe failure aborts tunnel start outright (`crates/xray-core-rs/src/lib.rs:726-730`).

**The root cause is not proven.** The `inbound=6` reading has an innocent explanation — the screenshot may have been taken on a freshly connected, idle tunnel. Every task below fixes a defect that was independently verified by reading code; none of them depends on the root cause being confirmed. Task 1 addresses the strongest candidate.

Ruled out during the investigation, recorded so nobody re-litigates them:

- **DPI / TLS fingerprint.** Direct (non-proxied) traffic fails too, and it never touches REALITY. Separately, REALITY hides the inner destination, so DPI cannot selectively break one site inside a working tunnel.
- **Stale fd after a tunnel restart.** `setTunnelNetworkSettings` is called from exactly one site and the fd is discovered inside its completion handler; there is no re-apply path, so the documented "new utun on re-apply" mechanism is unreachable in this code.
- **Darwin utun framing.** The 4-byte address-family header is added on write and stripped on read correctly (`crates/xray-core-rs/src/tun_fd.rs:300-345`).

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `crates/xray-core-rs/src/tun_fd.rs` | fd-backed TUN pump: error classification, read/write loops | 1, 2 |
| `crates/xray-tun/src/lib.rs` | `TunStats` counters and their atomics | 2 |
| `platform/apple/Sources/XrayMobileAdapter/XrayDarwinTunFileDescriptor.swift` | utun discovery | 3 |
| `platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift` | packet-I/O backend logging; tunnel network settings | 4, 7 |
| `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift` | `XrayCoreError` NSError bridging | 5 |
| `platform/apple/Sources/XrayAppleShared/XrayVlessURLImporter.swift` | generated VLESS config | 6 |

Test files, all existing:

- `crates/xray-core-rs/src/tun_fd.rs` — inline `mod tests` at line 405
- `platform/apple/Tests/XrayMobileAdapterTests/` — new file in Task 3
- `platform/apple/Tests/XrayAppleTunnelTests/XrayPacketTunnelProviderTests.swift`
- `platform/apple/Tests/XrayAppleSharedTests/XrayClientProfileTests.swift`

**Commands used throughout:**

- Rust: `cargo test -p xray-core-rs --lib` and `cargo test -p xray-tun`
- Swift: `swift test --disable-sandbox --package-path platform/apple`

---

### Task 1: The TUN read and write loops survive transient I/O errors

Today both loops in `crates/xray-core-rs/src/tun_fd.rs` terminate on any error that is not `Interrupted`:

```rust
Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
Err(_) => break,
```

Nothing supervises the spawned tasks — `TunFdRuntime` only awaits them in `stop()` — so a terminated loop means packet ingestion stops permanently while the provider still reports `Connected`. `ENOBUFS`, `ENETDOWN` and friends are ordinary transient conditions on a utun during a network transition.

**Files:**
- Modify: `crates/xray-core-rs/src/tun_fd.rs` (add classifier; rewrite loop bodies at 146-208)
- Test: `crates/xray-core-rs/src/tun_fd.rs` inline `mod tests`

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `crates/xray-core-rs/src/tun_fd.rs` (after `darwin_utun_encoded_packet_borrows_payload_and_adds_family_header`):

```rust
        #[test]
        fn transient_tun_fd_errors_are_retried_not_fatal() {
            for errno in [
                libc::ENOBUFS,
                libc::ENOMEM,
                libc::ENETDOWN,
                libc::ENETUNREACH,
                libc::EHOSTDOWN,
                libc::EHOSTUNREACH,
                libc::ETIMEDOUT,
                libc::EIO,
            ] {
                assert_eq!(
                    io_disposition(&io::Error::from_raw_os_error(errno)),
                    TunFdIoDisposition::Retry,
                    "errno {errno} must be retried"
                );
            }
        }

        #[test]
        fn a_closed_descriptor_is_fatal() {
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::EBADF)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::ENXIO)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
                TunFdIoDisposition::Fatal
            );
        }

        #[test]
        fn interrupts_are_retried_without_counting_as_failures() {
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::EINTR)),
                TunFdIoDisposition::Retry
            );
        }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p xray-core-rs --lib tun_fd`

Expected: FAIL to compile — `cannot find function 'io_disposition' in this scope` and `cannot find type 'TunFdIoDisposition' in this scope`.

- [ ] **Step 3: Add the classifier**

In `crates/xray-core-rs/src/tun_fd.rs`, inside `mod platform` (the `#[cfg(unix)]` one), immediately above `async fn read_loop`:

```rust
    /// Bounds how many consecutive transient failures a pump loop tolerates
    /// before it gives up. A utun that errors this many times in a row is not
    /// recovering, and spinning forever would hide the failure completely.
    const MAX_CONSECUTIVE_TUN_FD_IO_ERRORS: u32 = 64;

    /// Backoff between retries so a persistently failing descriptor cannot spin
    /// the executor at full speed.
    const TUN_FD_IO_RETRY_BACKOFF: Duration = Duration::from_millis(10);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TunFdIoDisposition {
        Retry,
        Fatal,
    }

    /// Classifies a pump I/O error. Everything is retryable except conditions
    /// that mean the descriptor itself is gone, because a tunnel that stops
    /// moving packets is far worse than one that retries a doomed read.
    fn io_disposition(error: &io::Error) -> TunFdIoDisposition {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return TunFdIoDisposition::Fatal;
        }
        match error.raw_os_error() {
            Some(libc::EBADF) | Some(libc::ENXIO) | Some(libc::ENOTCONN) => {
                TunFdIoDisposition::Fatal
            }
            _ => TunFdIoDisposition::Retry,
        }
    }
```

Add `use std::time::Duration;` to the `mod platform` imports if it is not already present.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p xray-core-rs --lib tun_fd`

Expected: PASS — 6 tests (3 new, 3 pre-existing).

- [ ] **Step 5: Commit**

```bash
git add crates/xray-core-rs/src/tun_fd.rs
git commit -m "feat(tun): classify tun fd io errors as retryable or fatal"
```

- [ ] **Step 6: Wire the classifier into the read loop**

Replace the body of `read_loop` in `crates/xray-core-rs/src/tun_fd.rs` (currently lines 146-174) with:

```rust
    async fn read_loop(
        fd: Arc<AsyncFd<TunFd>>,
        tun: Arc<TunEndpoint>,
        mut shutdown: watch::Receiver<bool>,
        packet_format: TunFdPacketFormat,
    ) {
        let mut buffer = vec![0_u8; read_buffer_len(packet_format)];
        let mut consecutive_errors: u32 = 0;

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                packet = read_packet(&fd, packet_format, &mut buffer) => {
                    match packet {
                        Ok(Some(packet)) => {
                            consecutive_errors = 0;
                            match tun.push_inbound(packet).await {
                                Ok(())
                                | Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {}
                                Err(TunError::QueueClosed) => break,
                            }
                        }
                        Ok(None) => {
                            consecutive_errors = 0;
                        }
                        Err(err) => {
                            if io_disposition(&err) == TunFdIoDisposition::Fatal {
                                break;
                            }
                            consecutive_errors += 1;
                            if consecutive_errors >= MAX_CONSECUTIVE_TUN_FD_IO_ERRORS {
                                break;
                            }
                            tokio::time::sleep(TUN_FD_IO_RETRY_BACKOFF).await;
                        }
                    }
                }
            }
        }
    }
```

- [ ] **Step 7: Wire the classifier into the write loop**

Replace the body of `write_loop` in `crates/xray-core-rs/src/tun_fd.rs` (currently lines 176-208) with:

```rust
    async fn write_loop(
        fd: Arc<AsyncFd<TunFd>>,
        tun: Arc<TunEndpoint>,
        mut shutdown: watch::Receiver<bool>,
        packet_format: TunFdPacketFormat,
    ) {
        let mut batch = Vec::with_capacity(TUN_FD_WRITE_BATCH_MAX_PACKETS);
        let mut consecutive_errors: u32 = 0;

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                result = tun.poll_outbound_batch_into(
                    TUN_FD_WRITE_BATCH_MAX_PACKETS,
                    &mut batch,
                ) => {
                    match result {
                        Ok(()) => {
                            match write_packet_batch(&fd, packet_format, &batch).await {
                                Ok(()) => {
                                    consecutive_errors = 0;
                                    tun.record_tun_fd_write_batch(batch.len());
                                }
                                Err(err) => {
                                    if io_disposition(&err) == TunFdIoDisposition::Fatal {
                                        break;
                                    }
                                    consecutive_errors += 1;
                                    if consecutive_errors >= MAX_CONSECUTIVE_TUN_FD_IO_ERRORS {
                                        break;
                                    }
                                    tokio::time::sleep(TUN_FD_IO_RETRY_BACKOFF).await;
                                }
                            }
                        }
                        Err(TunError::QueueClosed) => break,
                        Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {}
                    }
                }
            }
        }
    }
```

Note the behaviour change beyond error handling: `record_tun_fd_write_batch` now runs only when the batch actually reached the descriptor. Previously it was recorded even when `write_packet_batch` had failed, which inflated `tunFdWriteBatches`.

- [ ] **Step 8: Verify the crate still builds and its tests pass**

Run: `cargo test -p xray-core-rs --lib tun_fd`

Expected: PASS. The loops now retry transient failures; the counters that make a give-up visible arrive in Task 2.

- [ ] **Step 9: Commit**

```bash
git add crates/xray-core-rs/src/tun_fd.rs
git commit -m "fix(tun): keep the tun pump alive across transient io errors"
```

---

### Task 2: A terminated pump loop is visible in the stats

Three counters, following the existing `TunStats` pattern exactly.

**Files:**
- Modify: `crates/xray-tun/src/lib.rs` (struct fields, atomics, constructor, snapshot, recorders)
- Test: `crates/xray-tun/tests/tun_tests.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/xray-tun/tests/tun_tests.rs`:

```rust
#[test]
fn tun_fd_pump_failure_counters_start_at_zero_and_increment() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 4,
    });

    let initial = tun.stats();
    assert_eq!(initial.tun_fd_read_loop_exits, 0);
    assert_eq!(initial.tun_fd_write_loop_exits, 0);
    assert_eq!(initial.tun_fd_transient_io_errors, 0);

    tun.record_tun_fd_read_loop_exit();
    tun.record_tun_fd_write_loop_exit();
    tun.record_tun_fd_transient_io_error();
    tun.record_tun_fd_transient_io_error();

    let stats = tun.stats();
    assert_eq!(stats.tun_fd_read_loop_exits, 1);
    assert_eq!(stats.tun_fd_write_loop_exits, 1);
    assert_eq!(stats.tun_fd_transient_io_errors, 2);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p xray-tun tun_fd_pump_failure_counters`

Expected: FAIL to compile — `no field 'tun_fd_read_loop_exits' on type 'TunStats'`.

- [ ] **Step 3: Add the three fields to `TunStats`**

In `crates/xray-tun/src/lib.rs`, in `pub struct TunStats`, immediately after `pub tun_fd_write_batch_max_packets: u64,`:

```rust
    pub tun_fd_read_loop_exits: u64,
    pub tun_fd_write_loop_exits: u64,
    pub tun_fd_transient_io_errors: u64,
```

- [ ] **Step 4: Add the three atomics to `TunEndpoint`**

In `pub struct TunEndpoint`, immediately after `tun_fd_write_batch_max_packets: AtomicU64,`:

```rust
    tun_fd_read_loop_exits: AtomicU64,
    tun_fd_write_loop_exits: AtomicU64,
    tun_fd_transient_io_errors: AtomicU64,
```

In the constructor (the block initialising `tun_fd_write_batch_max_packets: AtomicU64::new(0),`), add immediately after it:

```rust
            tun_fd_read_loop_exits: AtomicU64::new(0),
            tun_fd_write_loop_exits: AtomicU64::new(0),
            tun_fd_transient_io_errors: AtomicU64::new(0),
```

In the `stats()` snapshot (the block reading `tun_fd_write_batch_max_packets: self.tun_fd_write_batch_max_packets.load(Ordering::Relaxed),`), add immediately after it:

```rust
            tun_fd_read_loop_exits: self.tun_fd_read_loop_exits.load(Ordering::Relaxed),
            tun_fd_write_loop_exits: self.tun_fd_write_loop_exits.load(Ordering::Relaxed),
            tun_fd_transient_io_errors: self
                .tun_fd_transient_io_errors
                .load(Ordering::Relaxed),
```

- [ ] **Step 5: Add the three recorders**

In `impl TunEndpoint`, immediately after `pub fn record_tun_fd_write_batch(&self, packets: usize)`:

```rust
    /// Records that the fd-backed read pump gave up. A non-zero value means the
    /// tunnel has stopped ingesting packets while still reporting as connected.
    pub fn record_tun_fd_read_loop_exit(&self) {
        self.tun_fd_read_loop_exits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that the fd-backed write pump gave up.
    pub fn record_tun_fd_write_loop_exit(&self) {
        self.tun_fd_write_loop_exits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a retried pump I/O error. Steady growth here without a loop exit
    /// means the descriptor is unhealthy but still recovering.
    pub fn record_tun_fd_transient_io_error(&self) {
        self.tun_fd_transient_io_errors
            .fetch_add(1, Ordering::Relaxed);
    }
```

- [ ] **Step 6: Record the events from the pump loops**

In `crates/xray-core-rs/src/tun_fd.rs`, in `read_loop`, replace the `Err(err)` arm written in Task 1 with:

```rust
                        Err(err) => {
                            if io_disposition(&err) == TunFdIoDisposition::Fatal {
                                tun.record_tun_fd_read_loop_exit();
                                break;
                            }
                            consecutive_errors += 1;
                            tun.record_tun_fd_transient_io_error();
                            if consecutive_errors >= MAX_CONSECUTIVE_TUN_FD_IO_ERRORS {
                                tun.record_tun_fd_read_loop_exit();
                                break;
                            }
                            tokio::time::sleep(TUN_FD_IO_RETRY_BACKOFF).await;
                        }
```

In `write_loop`, replace its `Err(err)` arm with:

```rust
                                Err(err) => {
                                    if io_disposition(&err) == TunFdIoDisposition::Fatal {
                                        tun.record_tun_fd_write_loop_exit();
                                        break;
                                    }
                                    consecutive_errors += 1;
                                    tun.record_tun_fd_transient_io_error();
                                    if consecutive_errors >= MAX_CONSECUTIVE_TUN_FD_IO_ERRORS {
                                        tun.record_tun_fd_write_loop_exit();
                                        break;
                                    }
                                    tokio::time::sleep(TUN_FD_IO_RETRY_BACKOFF).await;
                                }
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p xray-tun && cargo test -p xray-core-rs --lib tun_fd`

Expected: PASS for both.

- [ ] **Step 8: Run the whole workspace to catch exhaustive-match breakage**

Run: `cargo test --workspace`

Expected: PASS. If a struct-literal construction of `TunStats` fails to compile anywhere, add the three fields there with `0`.

- [ ] **Step 9: Commit**

```bash
git add crates/xray-tun/src/lib.rs crates/xray-tun/tests/tun_tests.rs crates/xray-core-rs/src/tun_fd.rs
git commit -m "feat(tun): count pump loop exits and retried io errors"
```

---

### Task 3: utun discovery uses the hardened technique

`platform/apple/Sources/XrayMobileAdapter/XrayDarwinTunFileDescriptor.swift` currently accepts the first descriptor whose `UTUN_OPT_IFNAME` lookup succeeds and whose name starts with `utun`. WireGuard shipped exactly this and replaced it 73 minutes later (commit `23bf3cfc`), because option 2 on a different `AF_SYSTEM` socket type can mean something else entirely. The replacement — confirming the socket is connected to the `com.apple.net.utun_control` kernel control — is what WireGuardKit, sing-box's `libbox`, and Tun2SocksKit all use today.

The `ioctl` deliberately reuses the candidate socket rather than opening a fresh `AF_SYSTEM` socket, because the Network Extension sandbox forbids creating one.

**Files:**
- Modify: `platform/apple/Sources/XrayMobileAdapter/XrayDarwinTunFileDescriptor.swift`
- Create: `platform/apple/Tests/XrayMobileAdapterTests/XrayDarwinTunFileDescriptorTests.swift`

- [ ] **Step 1: Write the failing test**

Create `platform/apple/Tests/XrayMobileAdapterTests/XrayDarwinTunFileDescriptorTests.swift`:

```swift
#if canImport(Darwin)
import Darwin
import XCTest
@testable import XrayMobileAdapter

final class XrayDarwinTunFileDescriptorTests: XCTestCase {
    func testReturnsNilWhenNoUtunControlSocketIsOpen() {
        // A unit-test process holds no utun control socket, so discovery must
        // decline rather than latch onto an unrelated descriptor.
        XCTAssertNil(XrayDarwinTunFileDescriptor.discoverUtunFileDescriptor())
    }

    func testIgnoresAnOrdinaryConnectedSocket() throws {
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer {
            close(pair[0])
            close(pair[1])
        }

        // Both ends are connected, so getpeername succeeds on them. Discovery
        // must still reject them because sc_family is not AF_SYSTEM.
        XCTAssertNil(XrayDarwinTunFileDescriptor.discoverUtunFileDescriptor())
    }
}
#endif
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `swift test --disable-sandbox --package-path platform/apple --filter XrayDarwinTunFileDescriptorTests`

Expected: `testIgnoresAnOrdinaryConnectedSocket` FAILS — the current implementation may return a descriptor because `getsockopt` on an unrelated socket is not reliably filtered. If both pass by luck on this machine, proceed anyway; the implementation change is still required and Step 5 re-runs them.

- [ ] **Step 3: Replace the implementation**

Replace the entire contents of `platform/apple/Sources/XrayMobileAdapter/XrayDarwinTunFileDescriptor.swift`:

```swift
import Darwin
import Foundation

public enum XrayDarwinTunFileDescriptor {
    private static let utunControlName = "com.apple.net.utun_control"
    private static let sysprotoControl: Int32 = 2
    private static let utunOptionInterfaceName: Int32 = 2

    /// Locates the descriptor of the utun device the Network Extension opened
    /// for this provider.
    ///
    /// A descriptor qualifies only when it is a connected `AF_SYSTEM` socket
    /// whose control id matches `com.apple.net.utun_control`. Matching on the
    /// interface name alone is not sufficient: option 2 is defined per control,
    /// so another `AF_SYSTEM` socket type can answer it with unrelated bytes.
    ///
    /// The control id is resolved through the candidate socket itself because
    /// the extension sandbox does not permit opening a fresh `AF_SYSTEM` socket.
    public static func discoverUtunFileDescriptor(maximum: Int32 = 1024) -> Int32? {
        var controlInfo = ctl_info()
        withUnsafeMutablePointer(to: &controlInfo.ctl_name) { namePointer in
            namePointer.withMemoryRebound(
                to: CChar.self,
                capacity: MemoryLayout.size(ofValue: namePointer.pointee)
            ) { characters in
                _ = strcpy(characters, utunControlName)
            }
        }

        for fileDescriptor in 0 ... maximum {
            var address = sockaddr_ctl()
            var length = socklen_t(MemoryLayout.size(ofValue: address))
            var result: Int32 = -1
            withUnsafeMutablePointer(to: &address) { addressPointer in
                addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
                    result = getpeername(fileDescriptor, generic, &length)
                }
            }
            guard result == 0, address.sc_family == AF_SYSTEM else {
                continue
            }
            if controlInfo.ctl_id == 0 {
                guard ioctl(fileDescriptor, CTLIOCGINFO, &controlInfo) == 0 else {
                    continue
                }
            }
            if address.sc_id == controlInfo.ctl_id {
                return fileDescriptor
            }
        }

        return nil
    }

    /// Reports the interface name behind an already-identified utun descriptor,
    /// for diagnostics. Returns nil when the descriptor is not a utun.
    public static func interfaceName(for fileDescriptor: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var length = socklen_t(buffer.count)
        let result = buffer.withUnsafeMutableBufferPointer { pointer in
            getsockopt(
                fileDescriptor,
                sysprotoControl,
                utunOptionInterfaceName,
                pointer.baseAddress,
                &length
            )
        }
        guard result == 0 else {
            return nil
        }
        return String(cString: buffer)
    }
}
```

- [ ] **Step 4: Add the interface-name test**

Append to `XrayDarwinTunFileDescriptorTests.swift`, inside the class:

```swift
    func testInterfaceNameIsNilForANonUtunDescriptor() throws {
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer {
            close(pair[0])
            close(pair[1])
        }

        XCTAssertNil(XrayDarwinTunFileDescriptor.interfaceName(for: pair[0]))
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `swift test --disable-sandbox --package-path platform/apple --filter XrayDarwinTunFileDescriptorTests`

Expected: PASS — 3 tests.

- [ ] **Step 6: Commit**

```bash
git add platform/apple/Sources/XrayMobileAdapter/XrayDarwinTunFileDescriptor.swift platform/apple/Tests/XrayMobileAdapterTests/XrayDarwinTunFileDescriptorTests.swift
git commit -m "fix(apple): identify the utun by control id instead of name prefix"
```

---

### Task 4: Log which descriptor and interface the pump bound to

`XrayPacketTunnelProvider.swift:2475-2478` logs that the fd backend was chosen but not which fd or which interface, so a mis-bound pump is invisible even with debug logging on.

**Files:**
- Modify: `platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift` (the `case let .darwinUtunFileDescriptor(fd):` arm in `makeRuntime`)

- [ ] **Step 1: Replace the log line**

Find this block in `makeRuntime`:

```swift
        case let .darwinUtunFileDescriptor(fd):
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Using Darwin utun file descriptor for packet I/O"
            )
```

Replace the `XrayAppleLog.info` call with:

```swift
        case let .darwinUtunFileDescriptor(fd):
            let interfaceName = XrayDarwinTunFileDescriptor.interfaceName(for: fd) ?? "unknown"
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Using Darwin utun file descriptor for packet I/O fd=\(fd) interface=\(interfaceName)"
            )
```

The interface name is `utunN`, which carries no user data, so `XrayLogSanitizer` leaves it intact.

- [ ] **Step 2: Verify the package builds**

Run: `swift build --package-path platform/apple`

Expected: build succeeds.

- [ ] **Step 3: Run the Apple test suite**

Run: `swift test --disable-sandbox --package-path platform/apple`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift
git commit -m "feat(apple): log the utun descriptor and interface the pump binds to"
```

---

### Task 5: `XrayCoreError` carries its message across the NSError bridge

`XrayCoreError` conforms to `Error, CustomStringConvertible`. Swift bridges such an enum to `NSError` using only the type name and case index, so `.status(code:message:)` reaches the UI as `The operation couldn't be completed. (XrayMobileAdapter.XrayCoreError error 0.)` and the engine's message — the only thing that says what actually failed — is discarded. `XrayPacketTunnelProviderError` in the same SDK already implements `CustomNSError`; this brings `XrayCoreError` in line.

**Files:**
- Modify: `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift` (the `XrayCoreError` enum)
- Test: `platform/apple/Tests/XrayMobileAdapterTests/XrayCoreErrorTests.swift` (create)

- [ ] **Step 1: Write the failing test**

Create `platform/apple/Tests/XrayMobileAdapterTests/XrayCoreErrorTests.swift`:

```swift
import XCTest
@testable import XrayMobileAdapter

final class XrayCoreErrorTests: XCTestCase {
    func testStatusErrorSurvivesTheNSErrorBridge() {
        let error = XrayCoreError.status(code: XRAY_STATUS_PANIC, message: "config rejected")
        let bridged = error as NSError

        XCTAssertEqual(bridged.domain, XrayCoreError.errorDomain)
        XCTAssertTrue(
            bridged.localizedDescription.contains("config rejected"),
            "expected the engine message, got \(bridged.localizedDescription)"
        )
    }

    func testEveryCaseHasADistinctErrorCode() {
        let codes = [
            XrayCoreError.status(code: XRAY_STATUS_PANIC, message: "x").errorCode,
            XrayCoreError.incompatibleFFIMajorVersion(expected: 1, actual: 2).errorCode,
            XrayCoreError.missingHandle.errorCode,
            XrayCoreError.notRunning.errorCode,
            XrayCoreError.invalidUtf8.errorCode,
        ]
        XCTAssertEqual(Set(codes).count, codes.count)
    }
}
```

`XrayStatus` is a C enum imported from the FFI header, so its values are the
`XRAY_STATUS_*` constants — `XRAY_STATUS_OK`, `XRAY_STATUS_PANIC`,
`XRAY_STATUS_NO_PACKET`, `XRAY_STATUS_BUFFER_TOO_SMALL`. It has no
`init(rawValue:)`; use a constant.

- [ ] **Step 2: Run the test to verify it fails**

Run: `swift test --disable-sandbox --package-path platform/apple --filter XrayCoreErrorTests`

Expected: `testStatusErrorSurvivesTheNSErrorBridge` FAILS — `localizedDescription` is the generic "operation couldn't be completed" string.

- [ ] **Step 3: Conform to `CustomNSError` and `LocalizedError`**

In `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift`, change the declaration:

```swift
public enum XrayCoreError: Error, CustomStringConvertible {
```

to:

```swift
public enum XrayCoreError: Error, CustomStringConvertible, CustomNSError, LocalizedError {
```

Then add, inside the enum and after the existing `description` property:

```swift
    public static let errorDomain = "XrayMobileAdapter.XrayCoreError"

    public var errorCode: Int {
        switch self {
        case .status:
            return 0
        case .incompatibleFFIMajorVersion:
            return 1
        case .invalidPacketPollSize:
            return 2
        case .invalidPacketBatchLimits:
            return 3
        case .packetBatchSizeOverflow:
            return 4
        case .packetBatchTooLarge:
            return 5
        case .missingHandle:
            return 6
        case .notRunning:
            return 7
        case .invalidUtf8:
            return 8
        }
    }

    public var errorUserInfo: [String: Any] {
        [NSLocalizedDescriptionKey: description]
    }

    public var errorDescription: String? {
        description
    }
```

`description` already renders every case, including `"xray status \(code): \(message)"`, so both conformances reuse it rather than duplicating the strings.

- [ ] **Step 4: Run the test to verify it passes**

Run: `swift test --disable-sandbox --package-path platform/apple --filter XrayCoreErrorTests`

Expected: PASS — 2 tests.

- [ ] **Step 5: Run the full Apple suite**

Run: `swift test --disable-sandbox --package-path platform/apple`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add platform/apple/Sources/XrayMobileAdapter/XrayCore.swift platform/apple/Tests/XrayMobileAdapterTests/XrayCoreErrorTests.swift
git commit -m "fix(apple): surface the engine message through the XrayCoreError bridge"
```

---

### Task 6: The generated config enables sniffing and pins DNS to IPv4

`XrayVlessURLImporter.mobileConfigJSON()` emits an inbound with no `sniffing` block. Sniffing is the only recovery path when a fake-IP address arrives without a live mapping — `should_sniff_tun_tcp` requires `provenance == InPoolUnmapped` **and** a sniffing config, and `should_sniff_tcp(None)` is `false`. Without it, a stale fake IP is dialled literally as `198.19.x.y`, which is unroutable. FoXray's exported config enables `http`, `tls` and `quic` sniffing, and the same config sets `queryStrategy: UseIPv4`.

`enabled`, `destOverride`, `metadataOnly`, `routeOnly`, `domainsExcluded` and `excludedDomains` are the accepted sniffing keys (`crates/xray-config/src/parser.rs:1667-1678`); `http`, `tls` and `quic` are the accepted `destOverride` values (`parser.rs:1735-1737`). Unknown keys are a hard config error, so do not invent others.

**Files:**
- Modify: `platform/apple/Sources/XrayAppleShared/XrayVlessURLImporter.swift` (`mobileConfigJSON()`)
- Test: `platform/apple/Tests/XrayAppleSharedTests/XrayClientProfileTests.swift`

- [ ] **Step 1: Write the failing test**

Append to the test class in `platform/apple/Tests/XrayAppleSharedTests/XrayClientProfileTests.swift`:

```swift
    func testImportedConfigEnablesSniffingAndPinsDnsToIPv4() throws {
        let url = "vless://49c1a053-d257-466d-a900-048ff5173866@203.0.113.7:443"
            + "?flow=xtls-rprx-vision&type=tcp&security=reality&fp=chrome"
            + "&sni=example.com&pbk=3jNx5A3WTFKhvCj3IPljaxbcBjCxhH2dVCNobKv_X1c&sid=1c5694e878"

        let profile = try XrayVlessURLImporter.profile(
            from: url,
            providerBundleIdentifier: "com.example.tunnel",
            hostBundleIdentifier: "com.example"
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )

        let inbounds = try XCTUnwrap(root["inbounds"] as? [[String: Any]])
        let sniffing = try XCTUnwrap(inbounds.first?["sniffing"] as? [String: Any])
        XCTAssertEqual(sniffing["enabled"] as? Bool, true)
        XCTAssertEqual(sniffing["destOverride"] as? [String], ["http", "tls", "quic"])
        XCTAssertEqual(sniffing["metadataOnly"] as? Bool, false)

        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        XCTAssertEqual(dns["queryStrategy"] as? String, "UseIPv4")
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `swift test --disable-sandbox --package-path platform/apple --filter testImportedConfigEnablesSniffingAndPinsDnsToIPv4`

Expected: FAIL — `XCTUnwrap` on `inbounds.first?["sniffing"]` returns nil.

- [ ] **Step 3: Add sniffing and the query strategy**

In `platform/apple/Sources/XrayAppleShared/XrayVlessURLImporter.swift`, inside `mobileConfigJSON()`, replace the `"inbounds"` entry of `root`:

```swift
            "inbounds": [
                [
                    "tag": "tun-in",
                    "protocol": "tun",
                    "listen": "127.0.0.1",
                    "port": 0,
                    "settings": [:],
                ],
            ],
```

with:

```swift
            "inbounds": [
                [
                    "tag": "tun-in",
                    "protocol": "tun",
                    "listen": "127.0.0.1",
                    "port": 0,
                    "settings": [:],
                    // Sniffing is the only way a flow recovers its domain when
                    // the fake-IP mapping is missing — after a tunnel restart the
                    // table is empty while clients still hold cached fake IPs.
                    "sniffing": [
                        "enabled": true,
                        "destOverride": ["http", "tls", "quic"],
                        "metadataOnly": false,
                    ],
                ],
            ],
```

and replace the `"dns"` entry:

```swift
            "dns": [
                "fakeIp": [
                    "enabled": true,
                    "ipv4Pool": "198.19.0.0/16",
                    "poolSize": 32768,
                    "ttl": 60,
                ],
            ],
```

with:

```swift
            "dns": [
                "queryStrategy": "UseIPv4",
                "fakeIp": [
                    "enabled": true,
                    "ipv4Pool": "198.19.0.0/16",
                    "poolSize": 32768,
                    "ttl": 60,
                ],
            ],
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `swift test --disable-sandbox --package-path platform/apple --filter testImportedConfigEnablesSniffingAndPinsDnsToIPv4`

Expected: PASS.

- [ ] **Step 5: Run the full Apple suite**

Run: `swift test --disable-sandbox --package-path platform/apple`

Expected: PASS. `XrayMobileDNSPreflightTests` and `XrayClientProfileTests` assert on generated config shape; if a golden-config assertion now fails, update it to include the two new blocks.

- [ ] **Step 6: Verify the engine accepts the new config**

Run: `cargo test -p xray-config`

Expected: PASS — confirms `sniffing` and `queryStrategy` parse. If you want a direct check, add the generated JSON to an existing parser test fixture rather than writing a new harness.

- [ ] **Step 7: Commit**

```bash
git add platform/apple/Sources/XrayAppleShared/XrayVlessURLImporter.swift platform/apple/Tests/XrayAppleSharedTests/XrayClientProfileTests.swift
git commit -m "feat(apple): enable sniffing and pin imported configs to IPv4 DNS"
```

**Note for whoever ships this:** existing profiles are frozen at import time in `XraySecureConfigStore`, so they keep the old config. Users must re-import their VLESS URL to pick this up, or the app needs a migration that regenerates stored configs. That migration is out of scope here and should be tracked separately.

---

### Task 7: The tunnel stops advertising IPv6

`networkSettings` installs `NEIPv6Settings` with a `::/0` default route, so the tunnel captures all IPv6. The engine cannot serve it: the fake-IP pool is IPv4-only by construction, and `restore_client_target` returns `Outside` for anything that is not `IpAddr::V4` (`crates/xray-core-rs/src/dns_outbound_runtime.rs:764-768`), so an IPv6 destination is dialled as a literal through a server that most likely has no IPv6. No ICMP unreachable is emitted for that failure, so the flow hangs rather than failing over.

**Read this before implementing — it is a deliberate trade-off, not a free win.** Removing `ipv6Settings` means iOS no longer routes IPv6 into the tunnel. Traffic to genuine IPv6 literals will then leave over the physical interface instead of the VPN. For a privacy product that is a real regression, and it is the reason the alternative below exists.

The alternative, if the leak is judged unacceptable: keep capturing `::/0` and make the engine reject IPv6 client targets immediately so Happy Eyeballs falls back to IPv4 within milliseconds. That is more work and lands in the Rust flow-open path. Whoever executes this task should confirm the choice with the maintainer before starting.

Also correcting a claim made while planning: this is **not** verified to be "exactly what FoXray does". FoXray's exported Xray config sets `queryStrategy: UseIPv4`, which is covered by Task 6. Its NetworkExtension settings are not visible in that export, so nothing is known about whether it declares IPv6.

**Files:**
- Modify: `platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift` (`networkSettings`, lines 1914-1927)
- Test: `platform/apple/Tests/XrayAppleTunnelTests/XrayPacketTunnelProviderTests.swift`

- [ ] **Step 1: Write the failing test**

Append to the test class in `platform/apple/Tests/XrayAppleTunnelTests/XrayPacketTunnelProviderTests.swift`:

```swift
    func testNetworkSettingsDoNotAdvertiseIPv6() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            resolvedDNSConfiguration: .localDNSAnchor
        )

        // The fake-IP pool is IPv4-only and no IPv6 destination can be restored
        // to a domain, so capturing ::/0 would only produce hanging flows.
        XCTAssertNil(settings.ipv6Settings)
        XCTAssertNotNil(settings.ipv4Settings)
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `swift test --disable-sandbox --package-path platform/apple --filter testNetworkSettingsDoNotAdvertiseIPv6`

Expected: FAIL — `XCTAssertNil(settings.ipv6Settings)` fails because IPv6 settings are installed.

- [ ] **Step 3: Remove the IPv6 settings**

In `networkSettings`, delete this block:

```swift
        let ipv6Settings = NEIPv6Settings(
            addresses: [tunnelLocalIPv6Address],
            networkPrefixLengths: [128]
        )
        ipv6Settings.includedRoutes = [NEIPv6Route.default()]
        let ipv6ExcludedRoutes = ipv6ExcludedRoutes(for: serverAddresses)
        if !ipv6ExcludedRoutes.isEmpty {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Excluding \(ipv6ExcludedRoutes.count) bootstrap IPv6 /128 route(s) from tunnel"
            )
            ipv6Settings.excludedRoutes = ipv6ExcludedRoutes
        }
        settings.ipv6Settings = ipv6Settings
```

and replace it with:

```swift
        // IPv6 is deliberately not advertised. The fake-IP pool is IPv4-only, so
        // an IPv6 destination can never be restored to a domain and would be
        // dialled as a literal through a server that may have no IPv6 at all —
        // a flow that hangs instead of failing over to IPv4. Traffic to IPv6
        // literals therefore leaves outside the tunnel; capturing ::/0 and
        // rejecting it in the engine is the fix that removes that trade-off.
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `swift test --disable-sandbox --package-path platform/apple --filter testNetworkSettingsDoNotAdvertiseIPv6`

Expected: PASS.

- [ ] **Step 5: Run the full Apple suite and remove now-dead code**

Run: `swift test --disable-sandbox --package-path platform/apple`

Expected: existing tests asserting on `ipv6Settings` FAIL. Delete or invert them to match the new contract — do not weaken them into no-ops.

`ipv6ExcludedRoutes(for:)` and `tunnelLocalIPv6Address` now have no callers. Check with:

```bash
grep -rn "ipv6ExcludedRoutes\|tunnelLocalIPv6Address" platform/apple/Sources platform/apple/Tests
```

Delete whatever is genuinely unreferenced, including its tests.

- [ ] **Step 6: Commit**

```bash
git add platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift platform/apple/Tests/XrayAppleTunnelTests/XrayPacketTunnelProviderTests.swift
git commit -m "fix(apple): stop advertising IPv6 the engine cannot route"
```

---

### Task 8: Full verification

- [ ] **Step 1: Rust workspace**

Run: `cargo test --workspace`

Expected: PASS.

- [ ] **Step 2: Lints**

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Expected: no warnings.

- [ ] **Step 3: Apple package**

Run: `swift test --disable-sandbox --package-path platform/apple`

Expected: PASS.

- [ ] **Step 4: Record the new counters in the changelog**

Add to the Unreleased section of `CHANGELOG.md`:

```markdown
### Fixed
- The fd-backed TUN pump no longer stops permanently after a single transient
  read or write error; transient failures retry with backoff and only a closed
  descriptor ends the loop.
- utun discovery now identifies the interface by its kernel control id rather
  than by an interface-name prefix.
- `XrayCoreError` carries its status code and message through the NSError
  bridge instead of surfacing as "error 0".

### Added
- `tunFdReadLoopExits`, `tunFdWriteLoopExits` and `tunFdTransientIoErrors`
  counters in `TunStats`.
- Imported VLESS configs enable TCP/UDP sniffing and set `queryStrategy` to
  `UseIPv4`.

### Changed
- The Apple tunnel no longer advertises IPv6. Traffic to IPv6 literals now
  leaves outside the tunnel.
```

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: record the tun pump and iOS diagnostics changes"
```

---

## Out of scope, tracked elsewhere

- **Startup probe as a hard gate.** A failed probe aborts tunnel start (`crates/xray-core-rs/src/lib.rs:726-730`) with a 10 s budget against `cp.cloudflare.com`. On a weak cellular link this refuses a tunnel that would otherwise work. Explicitly excluded from this plan by the maintainer.
- **A real IPv6 fake-IP pool.** Go Xray-core allocates both `198.18.0.0/15` and `fc00::/18` by default and answers AAAA with a fake IPv6. Reaching parity means an IPv6 pool, an `ipv6Pool` config key, IPv6 reverse mapping, and `restore_client_target` handling `IpAddr::V6`.
- **Malformed ECH GREASE payload** in the uTLS shaping path — already filed as its own task.
- **Surfacing more counters to the app.** `XrayClientRuntimeStats` omits `tcpOpenErrors`, `tcpRemoteReadBytes` and the whole buffer block, and the Vane UI shows only five numbers. The three counters added in Task 2 should join them.
- **`udp_quic_blocked_packets` is dead.** It has no production call site; `udpVisionUDP443Rejections` is the real QUIC-block signal.
- **Config migration for existing profiles.** Stored configs are frozen at import, so Task 6 only affects newly imported profiles.
