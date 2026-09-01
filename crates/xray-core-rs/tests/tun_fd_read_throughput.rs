//! Read-path throughput harness for the direct-fd TUN bridge.
//!
//! Ignored by default: it is a measurement, not an assertion. Run with
//!
//! ```text
//! cargo test --release -p xray-core-rs --test tun_fd_read_throughput -- --ignored --nocapture
//! ```
//!
//! A `socketpair(AF_UNIX, SOCK_DGRAM)` stands in for the platform descriptor:
//! it has the same datagram read semantics as a Darwin utun fd (one packet per
//! `read`, a short read discards the rest), so the loop under test is exercised
//! unchanged and no elevated privileges are needed.

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xray_core_rs::{TunFdClosePolicy, TunFdConfig, TunFdPacketFormat, TunFdRuntime};
use xray_tun::{TunConfig, TunEndpoint};

/// Counts allocations so the harness can report allocator traffic, which is
/// what the read path actually changes — throughput here is dominated by the
/// descriptor syscall.
struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every method forwards to `System` unchanged.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Overridable so one harness covers both a realistic MTU and a payload large
/// enough to make the per-packet copy dominate: `TUN_BENCH_MTU`,
/// `TUN_BENCH_PACKET_LEN`, `TUN_BENCH_PACKETS`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn socketpair(buffer_bytes: usize) -> (RawFd, RawFd) {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array the call fills in.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(
        rc,
        0,
        "socketpair failed: {}",
        std::io::Error::last_os_error()
    );
    // The default datagram buffer is far below a jumbo payload, so a single
    // write would fail with EMSGSIZE before the read path is exercised.
    for fd in fds {
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            let size = buffer_bytes as libc::c_int;
            // SAFETY: `size` is a live `c_int` of the length passed in.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::addr_of!(size).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }
    (fds[0], fds[1])
}

/// Peak resident set size of this process, in bytes.
fn peak_rss_bytes() -> u64 {
    // SAFETY: `usage` is a live, correctly sized `rusage`.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    // SAFETY: the call only writes into `usage`.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let max_rss = usage.ru_maxrss as u64;
    // Darwin reports bytes, Linux kilobytes.
    if cfg!(target_os = "macos") {
        max_rss
    } else {
        max_rss * 1024
    }
}

fn ipv4_packet(len: usize, seed: u8) -> Vec<u8> {
    let mut packet = vec![seed; len];
    packet[0] = 0x45;
    packet
}

#[test]
#[ignore = "throughput measurement, run explicitly"]
fn direct_fd_read_path_throughput() {
    let mtu = env_usize("TUN_BENCH_MTU", 1500);
    let packet_len = env_usize("TUN_BENCH_PACKET_LEN", 1400);
    let packets = env_usize("TUN_BENCH_PACKETS", 200_000);
    let queue_depth = env_usize("TUN_BENCH_QUEUE_DEPTH", 1024);
    assert!(packet_len <= mtu, "payload must fit the mtu");

    let (host_fd, tun_fd) = socketpair((packet_len * 64).max(256 * 1024));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    let tun = Arc::new(TunEndpoint::new_with_queue_depths(
        TunConfig { mtu, queue_depth },
        queue_depth,
        queue_depth,
    ));

    let bridge = runtime
        .block_on(async {
            TunFdRuntime::start(
                TunFdConfig::new(tun_fd, TunFdPacketFormat::RawIp, TunFdClosePolicy::Owned),
                Arc::clone(&tun),
            )
        })
        .expect("fd bridge");

    let packet = ipv4_packet(packet_len, 0xAB);
    let producer = std::thread::spawn(move || {
        let mut sent = 0_usize;
        while sent < packets {
            // SAFETY: `packet` outlives the call and `host_fd` is open.
            let written = unsafe { libc::write(host_fd, packet.as_ptr().cast(), packet.len()) };
            if written < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    // A datagram socketpair reports a full buffer instead of
                    // blocking, so the producer paces itself against the
                    // reader rather than dropping the packet.
                    Some(libc::EINTR | libc::ENOBUFS | libc::EAGAIN) => {
                        std::thread::yield_now();
                        continue;
                    }
                    _ => panic!("write failed: {err}"),
                }
            }
            sent += 1;
        }
        // SAFETY: the producer owns `host_fd` and is done with it.
        unsafe { libc::close(host_fd) };
    });

    let allocations_before = ALLOCATIONS.load(Ordering::Relaxed);
    let started = Instant::now();
    let received = runtime.block_on(async {
        let mut received = 0_usize;
        while received < packets {
            match tokio::time::timeout(Duration::from_secs(5), tun.poll_inbound()).await {
                Ok(Ok(packet)) => {
                    assert_eq!(packet.len(), packet_len);
                    received += 1;
                }
                Ok(Err(err)) => panic!("queue closed after {received} packets: {err}"),
                Err(_) => break,
            }
        }
        received
    });
    let elapsed = started.elapsed();

    producer.join().expect("producer");
    runtime.block_on(bridge.stop());

    let stats = runtime.block_on(tun.stats());
    let per_packet = elapsed.as_secs_f64() / received.max(1) as f64;
    println!(
        "mtu {mtu} payload {packet_len}: received {received}/{packets} ({} dropped) in {:.3} s — {:.1} ns/packet, {:.2} Mpps, {:.1} MB/s",
        stats.dropped_packets,
        elapsed.as_secs_f64(),
        per_packet * 1e9,
        1.0 / per_packet / 1e6,
        (received * packet_len) as f64 / elapsed.as_secs_f64() / 1e6,
    );
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - allocations_before;
    println!(
        "{allocations} allocations — {:.2} per packet",
        allocations as f64 / received.max(1) as f64
    );
    println!(
        "peak rss {:.1} MiB",
        peak_rss_bytes() as f64 / (1024.0 * 1024.0)
    );
}
