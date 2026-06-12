# Performance & Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the performance bottlenecks (iPhone speedtest throughput/ping gap vs xray-core/sing-box) and security findings from the 2026-06-10 audit, except the UserDefaults→Keychain migration (explicitly deferred by owner).

**Architecture:** Keep the existing packetFlow-pump architecture but make the outbound path event-driven and batched: a new blocking batch-poll FFI (`xray_tun_poll_packets`) replaces the 5ms sleep-poll loop; data-path FFI entry points switch to shared (`&`) handle access so push and poll can run concurrently; the Swift pump writes batches and joins its poll loop before core shutdown. Independent quick wins (TCP_NODELAY, DNS cache, Vision buffer reuse, budget bumps, parser warnings, Kotlin locking) land as isolated tasks.

**Tech Stack:** Rust (tokio, smoltcp-based TUN, rustls), Swift (NetworkExtension), Kotlin (JNI wrapper).

**IMPORTANT — no git commits in this run:** the working tree already contains pre-existing uncommitted changes by the owner (tun diagnostics work). Committing files like `tun.rs` or `lib.rs` would sweep that work into mixed commits. All tasks therefore end with test runs, not commits; the owner integrates/commits afterwards.

**Dropped findings (verified already fixed or mitigated):**
- `TunFdConfig::close_if_owned` already guards `fd >= 0` (tun_fd.rs:50 and Drop at :137).
- Double-start is rejected by `Core::start` (`CoreError::AlreadyRunning`).
- UserDefaults secret storage — deferred by owner.

---

### Task 1: TCP_NODELAY on all outbound TCP sockets

**Files:**
- Modify: `crates/xray-transport/src/lib.rs:347-367` (`connect_tcp_stream`)
- Test: `crates/xray-transport/tests/transport_tests.rs`

All TCP connects (plain, TLS, REALITY, socks freedom) funnel through `connect_tcp_stream`, so one change covers every call site.

- [x] **Step 1: Write the failing test** in `crates/xray-transport/tests/transport_tests.rs`:

```rust
#[tokio::test]
async fn connect_tcp_stream_enables_nodelay() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    let stream = xray_transport::connect_tcp_stream(addr, None)
        .await
        .expect("connect");

    assert!(stream.nodelay().expect("query nodelay"));
}
```

- [x] **Step 2: Run** `cargo test -p xray-transport --test transport_tests connect_tcp_stream_enables_nodelay` — expect FAIL (`assertion failed`).

- [x] **Step 3: Implement** — replace the body of `connect_tcp_stream`:

```rust
pub async fn connect_tcp_stream(
    addr: SocketAddr,
    socket_protector: Option<&dyn SocketProtector>,
) -> Result<TcpStream, TransportError> {
    let stream = match socket_protector {
        None => TcpStream::connect(addr).await.map_err(TransportError::Tcp)?,
        Some(socket_protector) => {
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .map_err(TransportError::Tcp)?;

            socket_protector
                .protect(SocketHandle::from_tcp_socket(&socket))
                .map_err(TransportError::SocketProtection)?;

            socket.connect(addr).await.map_err(TransportError::Tcp)?
        }
    };

    // The relay writes many latency-sensitive small frames (VLESS headers,
    // Vision blocks, TLS records); Nagle would delay them behind ACKs.
    stream.set_nodelay(true).map_err(TransportError::Tcp)?;
    Ok(stream)
}
```

- [x] **Step 4: Run** the test again — expect PASS. Run `cargo test -p xray-transport` for regressions.

---

### Task 2: DNS cache for outbound server resolution

**Files:**
- Modify: `crates/xray-transport/src/lib.rs` (add `CachingDnsResolver` next to `SystemDnsResolver`)
- Modify: `crates/xray-core-rs/src/lib.rs:151-176` (wrap `SystemDnsResolver` in `Core::new` / `with_tun_runtime_options`)
- Modify: `crates/xray-ffi/src/lib.rs:421` (wrap resolver passed to core)
- Test: `crates/xray-transport/tests/dns_tests.rs`

- [x] **Step 1: Write failing tests** in `crates/xray-transport/tests/dns_tests.rs`:

```rust
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use xray_transport::{CachingDnsResolver, DnsResolver, TransportError};

#[derive(Default)]
struct CountingResolver {
    calls: AtomicUsize,
}

#[async_trait]
impl DnsResolver for CountingResolver {
    async fn resolve(&self, _domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SocketAddr::from(([192, 0, 2, 1], port)))
    }
}

#[tokio::test]
async fn caching_resolver_reuses_fresh_entries() {
    let inner = std::sync::Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::from_secs(60));

    let first = resolver.resolve("example.com", 443).await.unwrap();
    let second = resolver.resolve("example.com", 443).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn caching_resolver_expires_entries() {
    let inner = std::sync::Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::ZERO);

    resolver.resolve("example.com", 443).await.unwrap();
    resolver.resolve("example.com", 443).await.unwrap();

    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn caching_resolver_keys_by_domain_and_port() {
    let inner = std::sync::Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::from_secs(60));

    resolver.resolve("example.com", 443).await.unwrap();
    resolver.resolve("example.com", 80).await.unwrap();

    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
}
```

- [x] **Step 2: Run** `cargo test -p xray-transport --test dns_tests` — expect FAIL (type not found).

- [x] **Step 3: Implement** in `crates/xray-transport/src/lib.rs` (after `SystemDnsResolver`):

```rust
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const DNS_CACHE_MAX_ENTRIES: usize = 256;

/// TTL cache over another resolver. Proxy clients open a new connection per
/// session; resolving the (usually single) server domain on every connect adds
/// tens of milliseconds on mobile networks.
pub struct CachingDnsResolver {
    inner: Arc<dyn DnsResolver>,
    ttl: std::time::Duration,
    cache: std::sync::Mutex<
        std::collections::HashMap<(String, u16), (SocketAddr, std::time::Instant)>,
    >,
}

impl CachingDnsResolver {
    pub fn new(inner: Arc<dyn DnsResolver>) -> Self {
        Self::with_ttl(inner, DNS_CACHE_TTL)
    }

    pub fn with_ttl(inner: Arc<dyn DnsResolver>, ttl: std::time::Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl DnsResolver for CachingDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        let key = (domain.to_owned(), port);
        let now = std::time::Instant::now();
        {
            let cache = self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((addr, stored_at)) = cache.get(&key) {
                if now.duration_since(*stored_at) < self.ttl {
                    return Ok(*addr);
                }
            }
        }

        let addr = self.inner.resolve(domain, port).await?;

        let mut cache = self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.retain(|_, (_, stored_at)| now.duration_since(*stored_at) < self.ttl);
        }
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.clear();
        }
        cache.insert(key, (addr, now));
        Ok(addr)
    }
}
```

- [x] **Step 4: Wire it up.** In `crates/xray-core-rs/src/lib.rs` import `CachingDnsResolver` and change both default-resolver construction sites:

```rust
use xray_transport::{CachingDnsResolver, DnsResolver, SystemDnsResolver, TransportDialer};
// Core::new:
Self::with_dns_resolver(
    config,
    Arc::new(CachingDnsResolver::new(Arc::new(SystemDnsResolver))),
)
// with_tun_runtime_options:
Arc::new(CachingDnsResolver::new(Arc::new(SystemDnsResolver))),
```

In `crates/xray-ffi/src/lib.rs` (line ~421) replace `Arc::new(SystemDnsResolver)` with `Arc::new(CachingDnsResolver::new(Arc::new(SystemDnsResolver)))` and update the import.

- [x] **Step 5: Run** `cargo test -p xray-transport --test dns_tests` (PASS) and `cargo test -p xray-core-rs -p xray-ffi` for regressions.

---

### Task 3: `TunEndpoint::poll_outbound_batch` + `mtu()` accessor

**Files:**
- Modify: `crates/xray-tun/src/lib.rs`
- Test: `crates/xray-tun/tests/tun_tests.rs`

- [x] **Step 1: Write failing tests** in `crates/xray-tun/tests/tun_tests.rs`:

```rust
#[tokio::test]
async fn poll_outbound_batch_drains_up_to_limit() {
    let tun = TunEndpoint::new(TunConfig { mtu: 1500, queue_depth: 8 });
    for byte in 0..5u8 {
        tun.push_outbound(Bytes::from(vec![byte; 4])).await.unwrap();
    }

    let batch = tun.poll_outbound_batch(3).await.unwrap();
    assert_eq!(batch.len(), 3);
    assert_eq!(batch[0][0], 0);
    assert_eq!(batch[2][0], 2);

    let rest = tun.poll_outbound_batch(8).await.unwrap();
    assert_eq!(rest.len(), 2);
}

#[tokio::test]
async fn poll_outbound_batch_waits_for_first_packet() {
    let tun = std::sync::Arc::new(TunEndpoint::new(TunConfig { mtu: 1500, queue_depth: 8 }));
    let pusher = std::sync::Arc::clone(&tun);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        pusher.push_outbound(Bytes::from_static(b"late")).await.unwrap();
    });

    let batch = tun.poll_outbound_batch(4).await.unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(&batch[0][..], b"late");
}

#[tokio::test]
async fn poll_outbound_batch_reports_queue_closed() {
    let tun = TunEndpoint::new(TunConfig { mtu: 1500, queue_depth: 8 });
    tun.close();
    assert_eq!(tun.poll_outbound_batch(4).await, Err(TunError::QueueClosed));
}

#[test]
fn tun_endpoint_reports_configured_mtu() {
    let tun = TunEndpoint::new(TunConfig { mtu: 1400, queue_depth: 8 });
    assert_eq!(tun.mtu(), 1400);
}
```

- [x] **Step 2: Run** `cargo test -p xray-tun --test tun_tests poll_outbound_batch` — expect FAIL (method missing).

- [x] **Step 3: Implement** in `crates/xray-tun/src/lib.rs` (next to `poll_outbound`):

```rust
pub fn mtu(&self) -> usize {
    self.config.mtu
}

/// Waits for at least one outbound packet (or queue close), then drains up
/// to `max_packets` without further waiting. Holding the receiver lock for
/// the whole batch keeps per-packet locking off the host packet pump path.
pub async fn poll_outbound_batch(&self, max_packets: usize) -> Result<Vec<Bytes>, TunError> {
    let max_packets = max_packets.max(1);
    let mut rx = self.outbound_rx.lock().await;
    let mut packets = Vec::with_capacity(max_packets.min(64));

    loop {
        let closed = self.closed_notify.notified();

        if self.closed.load(Ordering::Acquire) {
            match rx.try_recv() {
                Ok(packet) => {
                    packets.push(packet);
                    break;
                }
                Err(_) => return Err(TunError::QueueClosed),
            }
        }

        tokio::select! {
            packet = rx.recv() => match packet {
                Some(packet) => {
                    packets.push(packet);
                    break;
                }
                None => return Err(TunError::QueueClosed),
            },
            () = closed => {}
        }
    }

    while packets.len() < max_packets {
        match rx.try_recv() {
            Ok(packet) => packets.push(packet),
            Err(_) => break,
        }
    }

    Ok(packets)
}
```

- [x] **Step 4: Run** `cargo test -p xray-tun` — expect PASS.

---

### Task 4: FFI batch poll `xray_tun_poll_packets` + shared-access data path

**Files:**
- Modify: `crates/xray-ffi/src/lib.rs` (new function after `xray_tun_poll_packet_inner`; switch data-path inners to `&*handle`)
- Modify: `crates/xray-ffi/include/xray_ffi.h` (declaration + thread-safety note)
- Test: `crates/xray-ffi/tests/ffi_tests.rs`

Semantics: blocks up to `wait_ms` for the first packet (0 → non-blocking), then drains without waiting. Packets are packed back-to-back into `buffer`; `packet_lengths[i]` receives each length; `packet_count` the number written. `effective_max = min(max_packets, buffer_len / mtu)` guarantees every drained packet fits because `push_packet` enforces `len <= mtu`. Returns `NO_PACKET` on timeout, `TUN_ERROR` once the queue is closed.

Concurrency: `xray_tun_push_packet`, `xray_tun_poll_packet`, `xray_tun_poll_packets`, and `xray_tun_stats` switch from `&mut *handle` to `&*handle` — they only need shared access (`Option::as_ref` + `Runtime::block_on(&self)`). This makes push/poll/stats safe to call concurrently from different threads, which the Swift pump now relies on. Lifecycle functions (`load_config`, `start`, `stop`, `set_*`, `free`) keep `&mut` and must not overlap data-path calls — documented in the header.

- [x] **Step 1: Write failing test** in `crates/xray-ffi/tests/ffi_tests.rs`, mirroring the existing ICMP echo poll test (push an ICMPv4 echo request, which the TUN loop answers synchronously on the outbound queue):

```rust
#[test]
fn tun_poll_packets_returns_batched_echo_replies() {
    // Reuse the same handle/config setup and icmp echo request packet builder
    // as the existing xray_tun_poll_packet test in this file.
    // Push 3 echo requests, then:
    let mut buffer = vec![0u8; 3 * 1500];
    let mut lengths = vec![0usize; 3];
    let mut count = 0usize;
    let status = unsafe {
        xray_tun_poll_packets(
            handle,
            buffer.as_mut_ptr(),
            buffer.len(),
            lengths.as_mut_ptr(),
            3,
            &mut count,
            1_000,
            &mut error,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(count >= 1 && count <= 3);
    assert!(lengths[..count].iter().all(|len| *len > 0));
}

#[test]
fn tun_poll_packets_times_out_with_no_packet() {
    // Same setup, no pushed packets:
    let status = unsafe { xray_tun_poll_packets(handle, buffer.as_mut_ptr(), buffer.len(), lengths.as_mut_ptr(), 3, &mut count, 0, &mut error) };
    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(count, 0);
}
```

(Adapt setup boilerplate from the existing tests in that file; assert `BufferTooSmall` when `buffer_len < mtu` as a third case.)

- [x] **Step 2: Run** `cargo test -p xray-ffi --test ffi_tests tun_poll_packets` — expect FAIL (function missing).

- [x] **Step 3: Implement** in `crates/xray-ffi/src/lib.rs`:

```rust
/// Polls a batch of raw IP packets emitted by the core for the host TUN adapter.
///
/// Waits up to `wait_ms` milliseconds for the first packet (`0` polls without
/// waiting), then drains additional ready packets without waiting. Packets are
/// written back-to-back into `buffer`; `packet_lengths[i]` receives the length
/// of packet `i` and `*packet_count` the number of packets written. At most
/// `min(max_packets, buffer_len / mtu)` packets are returned per call.
///
/// Returns `XRAY_STATUS_NO_PACKET` if no packet arrived within `wait_ms`.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `buffer` must point to `buffer_len` writable bytes.
/// `packet_lengths` must point to `max_packets` writable `usize` values.
/// `packet_count` must point to one writable `usize`. If `error` is non-null,
/// it must point to an initialized `*mut XrayError` value that is either null
/// or a live error pointer returned by this library.
///
/// This function may be called concurrently with `xray_tun_push_packet`,
/// `xray_tun_poll_packet`, and `xray_tun_stats` on the same handle, but not
/// concurrently with lifecycle functions (`xray_core_load_config_json`,
/// `xray_core_start`, `xray_core_stop`, `xray_core_set_*`, `xray_core_free`).
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_packets(
    handle: *mut XrayCoreHandle,
    buffer: *mut u8,
    buffer_len: usize,
    packet_lengths: *mut usize,
    max_packets: usize,
    packet_count: *mut usize,
    wait_ms: u32,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_packets_inner(
                handle,
                buffer,
                buffer_len,
                packet_lengths,
                max_packets,
                packet_count,
                wait_ms,
                error,
            )
        })
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn xray_tun_poll_packets_inner(
    handle: *mut XrayCoreHandle,
    buffer: *mut u8,
    buffer_len: usize,
    packet_lengths: *mut usize,
    max_packets: usize,
    packet_count: *mut usize,
    wait_ms: u32,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !packet_count.is_null() {
        unsafe {
            *packet_count = 0;
        }
    }

    if handle.is_null() {
        unsafe { set_error(error, XrayStatus::NullArgument, "core handle is null") };
        return XrayStatus::NullArgument;
    }
    if buffer.is_null() {
        unsafe { set_error(error, XrayStatus::NullArgument, "packet buffer is null") };
        return XrayStatus::NullArgument;
    }
    if packet_lengths.is_null() {
        unsafe { set_error(error, XrayStatus::NullArgument, "packet lengths pointer is null") };
        return XrayStatus::NullArgument;
    }
    if packet_count.is_null() {
        unsafe { set_error(error, XrayStatus::NullArgument, "packet count pointer is null") };
        return XrayStatus::NullArgument;
    }
    if max_packets == 0 {
        unsafe { set_error(error, XrayStatus::NullArgument, "max_packets must be nonzero") };
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &*handle };
    let Some(core) = handle.core.as_ref() else {
        unsafe { set_error(error, XrayStatus::CoreNotLoaded, "core config is not loaded") };
        return XrayStatus::CoreNotLoaded;
    };

    let tun = core.tun();
    let effective_max = max_packets.min(buffer_len / tun.mtu().max(1));
    if effective_max == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                format!("buffer length {buffer_len} is below the tun mtu {}", tun.mtu()),
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    let wait = Duration::from_millis(u64::from(wait_ms));
    let batch = handle.runtime.block_on(async {
        tokio::time::timeout(wait, tun.poll_outbound_batch(effective_max)).await
    });

    match batch {
        Err(_) => XrayStatus::NoPacket,
        Ok(Err(err)) => {
            unsafe { set_error(error, XrayStatus::TunError, err.to_string()) };
            XrayStatus::TunError
        }
        Ok(Ok(packets)) if packets.is_empty() => XrayStatus::NoPacket,
        Ok(Ok(packets)) => {
            let mut offset = 0usize;
            let mut written = 0usize;
            for packet in &packets {
                if offset + packet.len() > buffer_len || written >= max_packets {
                    break;
                }
                unsafe {
                    ptr::copy_nonoverlapping(packet.as_ptr(), buffer.add(offset), packet.len());
                    *packet_lengths.add(written) = packet.len();
                }
                offset += packet.len();
                written += 1;
            }
            unsafe {
                *packet_count = written;
            }
            XrayStatus::Ok
        }
    }
}
```

Also add `use std::time::Duration;` if missing.

- [x] **Step 4: Switch data-path inners to shared access.** In `xray_tun_push_packet_inner` (line ~936), `xray_tun_poll_packet_inner` (line ~1030), and the stats inner, replace `let handle = unsafe { &mut *handle };` with `let handle = unsafe { &*handle };` (their bodies only use `as_ref()`/`block_on`). Update each function's `# Safety` doc with the concurrency contract sentence from Step 3.

- [x] **Step 5: Header.** In `crates/xray-ffi/include/xray_ffi.h` after `xray_tun_poll_packet` add:

```c
/* May be called concurrently with xray_tun_push_packet / xray_tun_poll_packet /
 * xray_tun_stats on the same handle. Must not overlap lifecycle calls
 * (load_config / start / stop / set_* / free). */
XrayStatus xray_tun_poll_packets(
    XrayCoreHandle *handle,
    uint8_t *buffer,
    size_t buffer_len,
    size_t *packet_lengths,
    size_t max_packets,
    size_t *packet_count,
    uint32_t wait_ms,
    XrayError **error);
```

- [x] **Step 6: Run** `cargo test -p xray-ffi` — expect PASS (including the header-sync test in mobile_artifacts_tests if it checks declarations).

---

### Task 5: Tokio worker clamp 2..4 → 2..6 on mobile

**Files:**
- Modify: `crates/xray-ffi/src/lib.rs:2327-2342`

- [x] **Step 1: Update the test** (TDD on behavior change):

```rust
#[test]
fn runtime_worker_threads_use_available_parallelism_with_mobile_bounds() {
    assert_eq!(runtime_worker_threads_for_available_parallelism(1), 2);
    assert_eq!(runtime_worker_threads_for_available_parallelism(2), 2);
    assert_eq!(runtime_worker_threads_for_available_parallelism(3), 3);
    assert_eq!(runtime_worker_threads_for_available_parallelism(4), 4);
    assert_eq!(runtime_worker_threads_for_available_parallelism(6), 6);
    assert_eq!(runtime_worker_threads_for_available_parallelism(8), 6);
}
```

- [x] **Step 2: Run** — expect FAIL on the `6` cases.

- [x] **Step 3: Implement** — `available.clamp(2, 6)` (modern iPhones have 6 cores; 4 left 2 idle under parallel speedtest flows).

- [x] **Step 4: Run** `cargo test -p xray-ffi runtime_worker_threads` — PASS.

---

### Task 6: Mobile flow-budget bump (UDP 256→512, TCP per-flow 2→4 MB)

**Files:**
- Modify: `crates/xray-core-rs/src/tun.rs:75-107`
- Test: existing tests in `crates/xray-core-rs/src/tun.rs` + `crates/xray-core-rs/tests/core_lifecycle_tests.rs` (grep for `256`/`2 * 1024 * 1024` assertions and update)

- [x] **Step 1: Change the constants:**

```rust
const MOBILE_TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = TcpRemoteBufferPolicy {
    // Per-flow ceiling matches desktop so a single speedtest stream is not
    // capped, while totals stay inside NetworkExtension memory limits.
    normal_per_flow_bytes: 4 * 1024 * 1024,
    pressure_per_flow_bytes: 2 * 1024 * 1024,
    pressure_start_total_bytes: 24 * 1024 * 1024,
    pressure_release_total_bytes: 16 * 1024 * 1024,
    hard_total_bytes: 40 * 1024 * 1024,
};

const MOBILE_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: MOBILE_TCP_REMOTE_BUFFER_POLICY,
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 512,
    },
};
```

- [x] **Step 2: Run** `cargo test -p xray-core-rs` and fix any test assertions that pin the old values (search `max_active_flows`, `2 * 1024 * 1024`, `udp_flow_limit` in tun.rs tests and core_lifecycle_tests.rs).

---

### Task 7: UDP channel depths 64 → 256

**Files:**
- Modify: `crates/xray-core-rs/src/socks.rs:31` (`SOCKS_UDP_FLOW_QUEUE`)
- Modify: `crates/xray-core-rs/src/tun.rs:48` (`UDP_BRIDGE_CHANNEL_DEPTH`)

- [x] **Step 1: Change both constants to `256`.** Burst DNS/QUIC-fallback traffic overflows a 64-deep bounded channel and counts as `udp_channel_dropped_packets`.

- [x] **Step 2: Run** `cargo test -p xray-core-rs` — PASS.

---

### Task 8: Vision padding writes without intermediate allocations

**Files:**
- Modify: `crates/xray-proxy/src/vless/vision.rs` (add `pad_into`, reimplement `pad` on top)
- Modify: `crates/xray-proxy/src/vless/vision_stream.rs:173-181` (`queue_padded_write`)
- Test: `crates/xray-proxy/tests/vision_tests.rs`

- [x] **Step 1: Write failing test** in `crates/xray-proxy/tests/vision_tests.rs`:

```rust
#[test]
fn pad_into_appends_identical_frames_to_pad() {
    let user_id = [7u8; 16];
    let mut reference = VisionPadding::new(user_id, [0, 0, 0, 0]);
    let mut streaming = VisionPadding::new(user_id, [0, 0, 0, 0]);

    let mut expected = BytesMut::new();
    let mut actual = BytesMut::new();
    for payload in [&b"hello"[..], &b"world!"[..]] {
        let frame = reference
            .pad(BytesMut::from(payload), VisionCommand::Continue, 3)
            .unwrap();
        expected.extend_from_slice(&frame);
        streaming
            .pad_into(payload, VisionCommand::Continue, 3, &mut actual)
            .unwrap();
    }

    assert_eq!(actual, expected);
}
```

- [x] **Step 2: Run** `cargo test -p xray-proxy --test vision_tests pad_into` — FAIL (method missing).

- [x] **Step 3: Implement** in `vision.rs`:

```rust
pub fn pad(
    &mut self,
    payload: BytesMut,
    command: VisionCommand,
    deterministic_extra_padding: u16,
) -> Result<BytesMut, VisionError> {
    let mut padded = BytesMut::new();
    self.pad_into(&payload, command, deterministic_extra_padding, &mut padded)?;
    Ok(padded)
}

/// Appends one padded frame directly to `output`, avoiding the per-write
/// temporary buffers `pad` needs on the hot relay path.
pub fn pad_into(
    &mut self,
    payload: &[u8],
    command: VisionCommand,
    deterministic_extra_padding: u16,
    output: &mut BytesMut,
) -> Result<(), VisionError> {
    let content_len = payload.len();
    if content_len > MAX_CONTENT_LEN {
        return Err(VisionError::PayloadTooLarge { len: content_len });
    }

    let padding_len = self.padding_len(content_len, deterministic_extra_padding);
    let user_prefix_len = if self.user_id_emitted { 0 } else { USER_ID_LEN };
    output.reserve(user_prefix_len + HEADER_LEN + content_len + padding_len);

    if !self.user_id_emitted {
        output.extend_from_slice(&self.user_id);
        self.user_id_emitted = true;
    }

    output.put_u8(command as u8);
    output.put_u16(content_len as u16);
    output.put_u16(padding_len as u16);
    output.extend_from_slice(payload);
    output.resize(output.len() + padding_len, 0);

    Ok(())
}
```

And in `vision_stream.rs`:

```rust
fn queue_padded_write(&mut self, input: &[u8], command: VisionCommand) -> io::Result<()> {
    self.padding
        .pad_into(input, command, 0, &mut self.pending_write)
        .map_err(vision_to_io)
}
```

- [x] **Step 4: Run** `cargo test -p xray-proxy` — PASS (vision_stream_tests cover relay behavior).

---

### Task 9: Parser warnings — `allowInsecure` and wildcard listen

**Files:**
- Modify: `crates/xray-config/src/parser.rs` (add `warning` helper; warn in `parse_security` and `parse_inbound`)
- Test: `crates/xray-config/tests/parser_tests.rs`

- [x] **Step 1: Write failing tests** (match existing parser_tests style for building configs/diagnostics):

```rust
#[test]
fn allow_insecure_tls_produces_warning_diagnostic() {
    // outbound with security=tls, tlsSettings.allowInsecure=true
    // expect: parse succeeds, diagnostics contain a Warning whose path is
    // "$.outbounds[0].streamSettings.tlsSettings.allowInsecure"
}

#[test]
fn wildcard_listen_produces_warning_diagnostic() {
    // inbound socks with "listen": "0.0.0.0"
    // expect: parse succeeds, diagnostics contain a Warning whose path is
    // "$.inbounds[0].listen"
}
```

- [x] **Step 2: Run** — FAIL (no warnings emitted).

- [x] **Step 3: Implement.** Add next to `fn error` (parser.rs:1150):

```rust
fn warning(&mut self, path: impl Into<String>, message: impl Into<String>) {
    self.diagnostics.push(Diagnostic::warning(path, message));
}
```

In `parse_security`, bind `allow_insecure` before constructing `TlsSettings` and warn:

```rust
let allow_insecure = tls_settings
    .and_then(|settings| {
        self.optional_bool_at(
            settings,
            "allowInsecure",
            format!("$.outbounds[{index}].streamSettings.tlsSettings.allowInsecure"),
        )
    })
    .unwrap_or(false);
if allow_insecure {
    self.warning(
        format!("$.outbounds[{index}].streamSettings.tlsSettings.allowInsecure"),
        "allowInsecure=true disables TLS certificate verification; the proxy connection can be intercepted",
    );
}
```

In `parse_inbound`, bind `listen` before constructing `InboundConfig` and warn:

```rust
let listen = self
    .string_at(inbound, "listen")
    .unwrap_or("127.0.0.1")
    .to_owned();
if matches!(listen.as_str(), "0.0.0.0" | "::") {
    self.warning(
        format!("$.inbounds[{index}].listen"),
        "wildcard listen address exposes this inbound to other devices on the network; use 127.0.0.1 unless LAN sharing is intended",
    );
}
```

- [x] **Step 4: Run** `cargo test -p xray-config` — PASS, and verify no existing fixture relies on zero diagnostics with these features.

---

### Task 10: Swift `XrayCore.pollPackets` + lock-free data path + log redaction

**Files:**
- Modify: `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift`

- [x] **Step 1: Add an unlocked handle accessor** (below `withHandle`). Safe because `handle` is only freed in `deinit` (callers hold a strong reference) and `stop()` does not free:

```swift
/// Reads the handle under the lock but runs `body` outside it, so blocking
/// data-path calls (pollPackets) do not stall pushPacket/stats. Safe because
/// the handle is only freed in deinit, which cannot run while the caller
/// holds a strong reference.
private func withDataPathHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
    lock.lock()
    let handle = self.handle
    lock.unlock()

    guard let handle else {
        throw XrayCoreError.missingHandle
    }
    return try body(handle)
}
```

- [x] **Step 2: Switch `pushPacket` and `pollPacket` to `withDataPathHandle`** (bodies unchanged otherwise).

- [x] **Step 3: Add the batch poll:**

```swift
/// Polls a batch of outbound packets, waiting up to `waitMilliseconds` for
/// the first one. Returns an empty array on timeout.
public func pollPackets(
    maxPackets: Int = 64,
    maxPacketBytes: Int = 1_500,
    waitMilliseconds: UInt32 = 0
) throws -> [Data] {
    try withDataPathHandle { handle in
        var error: OpaquePointer?
        var buffer = [UInt8](repeating: 0, count: maxPackets * maxPacketBytes)
        var lengths = [Int](repeating: 0, count: maxPackets)
        var packetCount = 0
        let status = buffer.withUnsafeMutableBufferPointer { bufferPointer in
            lengths.withUnsafeMutableBufferPointer { lengthsPointer in
                xray_tun_poll_packets(
                    handle,
                    bufferPointer.baseAddress,
                    bufferPointer.count,
                    lengthsPointer.baseAddress,
                    maxPackets,
                    &packetCount,
                    waitMilliseconds,
                    &error
                )
            }
        }

        if status == XRAY_STATUS_NO_PACKET {
            return []
        }

        try check(status, error: error)
        var packets = [Data]()
        packets.reserveCapacity(packetCount)
        var offset = 0
        for index in 0..<packetCount {
            let length = lengths[index]
            packets.append(Data(buffer[offset..<(offset + length)]))
            offset += length
        }
        return packets
    }
}
```

- [x] **Step 4: Redact the tun fd in the init log** (line ~275): replace `tunFd=\(tunFileDescriptor.map(String.init) ?? "none")` with `tunFd=\(tunFileDescriptor != nil ? "present" : "none")`.

- [x] **Step 5: Build/test:** `cd platform/apple && swift build && swift test` (XrayMobileAdapter target compiles against the regenerated module; requires the Rust staticlib header from Task 4).

---

### Task 11: Pump rework — event-driven batch loop, single QUIC filter, joined stop

**Files:**
- Modify: `platform/apple/Sources/XrayMobileAdapter/XrayPacketTunnelPump.swift`
- Modify: `platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift` (fd log line only)
- Test: `platform/apple/Tests/XrayMobileAdapterTests/XrayPacketTunnelPumpTests.swift`

Changes:
1. Poll loop: replace the sleep-tuned `pollPackets()` loop with a blocking batch loop (`waitMilliseconds: 250`); write each batch with one `writePackets` call. No sleeps in the happy path — Rust wakes the call the moment a packet is queued.
2. Remove the Swift-side QUIC parsing/ICMP generation (`quicRejectPacket`, `udpPayload`, `icmpPortUnreachableReply`, checksum helpers, `UDPPacketPayload`) — the Rust core performs the same check and already pushes ICMP port-unreachable replies to the outbound queue (`tun.rs:712-720`); filtering twice burned CPU on every UDP packet. `XrayPacketTunnelPumpOptions.blockQUIC` stays for API stability; the pump just logs it.
3. `stop()` joins the poll loop (semaphore, 1s timeout = 4× poll wait) so `xray_core_stop` (which takes exclusive handle access) can never overlap an in-flight poll.

- [x] **Step 1: Update tests first.** In `XrayPacketTunnelPumpTests.swift` delete the five `testQuicBlocking*` tests and the now-unused packet/checksum helpers (`ipv4UDPPacket`, `ipv6UDPPacket`, `ipv4TCPPacket`, `quicInitialPayload`, `assertIPv4ICMPPortUnreachable`, `assertIPv6ICMPPortUnreachable`, `ipv6TransportChecksum`, `internetChecksum`). Rust keeps equivalent coverage in `crates/xray-core-rs/src/tun.rs` QUIC tests.

- [x] **Step 2: Rewrite the pump.** Replace `maxPacketsPerPollPass`, `pollPackets()`, `pollAndWritePacket()` and the QUIC helpers with:

```swift
private static let maxPacketsPerPoll = 64
private static let pollWaitMilliseconds: UInt32 = 250
private static let pollErrorBackoffSeconds: TimeInterval = 0.05
private let pollLoopExited = DispatchSemaphore(value: 0)

public func stop() {
    lock.lock()
    let wasRunning = running
    running = false
    lock.unlock()
    XrayMobileLog.info("PacketPump", "Stopping packet pump")
    guard wasRunning else {
        return
    }
    // Join the poll loop so the provider can stop the core without a poll
    // call still holding the FFI data path.
    let deadline = DispatchTime.now() + .milliseconds(Int(Self.pollWaitMilliseconds) * 4)
    if pollLoopExited.wait(timeout: deadline) == .timedOut {
        XrayMobileLog.error("PacketPump", "Poll loop did not exit before stop deadline")
    }
}

private func pollPackets() {
    queue.async { [weak self] in
        guard let self else {
            return
        }

        while self.isRunning {
            autoreleasepool {
                self.pollAndWriteBatch()
            }
            self.logStatsIfNeeded()
        }
        self.pollLoopExited.signal()
        XrayMobileLog.info("PacketPump", "Packet pump poll loop exited")
    }
}

private func pollAndWriteBatch() {
    let packets: [Data]
    do {
        packets = try core.pollPackets(
            maxPackets: Self.maxPacketsPerPoll,
            waitMilliseconds: Self.pollWaitMilliseconds
        )
    } catch {
        let count = incrementPollPacketErrorCount()
        if Self.shouldLogPacketError(count) {
            XrayMobileLog.error("PacketPump", "pollPackets failed count=\(count) error=\(error)")
        }
        Thread.sleep(forTimeInterval: Self.pollErrorBackoffSeconds)
        return
    }

    guard !packets.isEmpty else {
        return
    }

    let protocols = packets.map { NSNumber(value: Self.protocolFamily(for: $0)) }
    let didWrite = provider.packetFlow.writePackets(packets, withProtocols: protocols)
    let byteCount = packets.reduce(0) { $0 + $1.count }
    if let snapshot = recordWrittenBatch(
        packetCount: packets.count,
        byteCount: byteCount,
        didWrite: didWrite
    ) {
        XrayMobileLog.info(
            "PacketPump",
            "Wrote packet batch packets=\(packets.count) bytes=\(byteCount) didWrite=\(didWrite) totals writtenPackets=\(snapshot.writtenPacketCount) writtenBytes=\(snapshot.writtenByteCount) writeErrors=\(snapshot.writePacketErrorCount)"
        )
    }
    if !didWrite {
        let count = currentWritePacketErrorCount()
        if Self.shouldLogPacketError(count) {
            XrayMobileLog.error(
                "PacketPump",
                "writePackets returned false count=\(count) packets=\(packets.count)"
            )
        }
    }
}

private func recordWrittenBatch(
    packetCount: Int,
    byteCount: Int,
    didWrite: Bool
) -> PacketPumpSnapshot? {
    lock.lock()
    defer { lock.unlock() }

    if didWrite {
        writtenPacketCount += UInt64(packetCount)
        writtenByteCount += UInt64(byteCount)
    } else {
        writePacketErrorCount += 1
    }

    guard !didWrite || Self.shouldLogPacketEvent(writtenPacketCount) else {
        return nil
    }
    return snapshotLocked()
}
```

In `readPackets`, delete the whole `if let rejectPacket = Self.quicRejectPacket(...)` block (keep `pushPacket`); delete `recordWrittenPacket`, `incrementBlockedQUICPacketCount` if now unused; keep `blockedQUICPacketCount` in the snapshot (always 0) or drop it from snapshot + stats log line consistently. In `start()` keep the `blockQUIC` log line: QUIC filtering is now done solely by the Rust core.

- [x] **Step 3: Provider log redaction.** In `XrayPacketTunnelProvider.swift:85-88` replace `"Using Darwin utun fd=\(fd) for packet I/O"` with `"Using Darwin utun file descriptor for packet I/O"`.

- [x] **Step 4: Build & test:** `cd platform/apple && swift build && swift test`. Expect all remaining tests green.

---

### Task 12: Kotlin `XrayCore` thread safety

**Files:**
- Modify: `platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt`

- [x] **Step 1: Implement.** Guard every native call and the handle with one lock; `close()` zeroes the handle under the lock so no thread can observe a freed handle:

```kotlin
class XrayCore private constructor(handle: Long) : Closeable {
    private val lock = Any()
    private var nativeHandle: Long = handle
    ...
    fun start() = withHandle { nativeStart(it) }
    fun stop() = withHandle { nativeStop(it) }
    fun pushPacket(packet: ByteArray) = withHandle { nativePushPacket(it, packet) }
    fun pollPacket(maxBytes: Int = 65_535): ByteArray? = withHandle { nativePollPacket(it, maxBytes) }
    fun stats(): XrayTunStats { val raw = withHandle { nativeStats(it) }; ... }

    override fun close() {
        val handle = synchronized(lock) {
            val current = nativeHandle
            nativeHandle = 0L
            current
        }
        if (handle != 0L) {
            nativeFree(handle)
        }
    }

    private inline fun <T> withHandle(block: (Long) -> T): T = synchronized(lock) {
        check(nativeHandle != 0L) { "xray core is closed" }
        block(nativeHandle)
    }
}
```

(private setters `loadConfig`/`setTunFd`/etc. also route through `withHandle`; `requireHandle` is removed.)

- [x] **Step 2: Verify** — no Gradle wrapper in repo; rely on `ktlint`-style review + the Rust FFI tests. Note in summary that an Android build wasn't run.

---

### Task 13: Full verification

- [x] `cargo test --workspace`
- [x] `cargo clippy --workspace --all-targets` (fix new warnings in touched code only)
- [x] `cd platform/apple && swift test`
- [x] Re-run `cargo fmt` on touched Rust files (`cargo fmt -p xray-transport -p xray-tun -p xray-ffi -p xray-core-rs -p xray-proxy -p xray-config`)

## Self-Review Notes

- Spec coverage: TCP_NODELAY (T1), DNS cache (T2), sleep-poll & FFI batching (T3+T4+T10+T11), worker clamp (T5), flow budgets (T6), UDP channel depth (T7), Vision allocs (T8), allowInsecure + wildcard listen (T9), NSLog redaction (T10/T11), Kotlin handle race (T12). Deferred/dropped items listed in header.
- Type consistency: `poll_outbound_batch(max_packets) -> Result<Vec<Bytes>, TunError>` used by T4; `pollPackets(maxPackets:maxPacketBytes:waitMilliseconds:)` used by T11; `pad_into(&[u8], VisionCommand, u16, &mut BytesMut)` used by T8.
- Known risk: switching FFI data-path to `&*handle` while lifecycle keeps `&mut` requires the host contract "no lifecycle call overlaps data-path call" — enforced in Swift by pump-join-before-stop (T11) and documented in the header (T4).
