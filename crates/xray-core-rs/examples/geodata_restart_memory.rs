//! Physical footprint of repeated core starts with geodata routing rules, the
//! way a mobile host restarts the core on every server switch.
//!
//! ```sh
//! cargo run --release -p xray-core-rs --example geodata_restart_memory -- \
//!     <geodata-dir> <config.json> [restarts] [stop-first|overlap]
//! ```
//!
//! The config is parsed with the directory as the only geodata search
//! directory, then a core is created and started. `stop-first` (the default)
//! stops and drops the running core before the next one is parsed;
//! `overlap` starts the next core before stopping the previous one. Each line
//! reports the footprint after the phase, the footprint peak inside it, the
//! bytes held in live allocations and the geodata cache counters. A stopped
//! core is dropped and the cache trimmed, as `xray_core_free` does.
//! Footprint counts dirty and compressed pages, the measure iOS jetsam
//! limits apply to. macOS only.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use xray_config::{
    geodata_cache_stats, parse_xray_json_with_exclusive_geodata_dirs, trim_geodata_cache,
};
use xray_core_rs::Core;

/// Counts the bytes the program holds in live allocations, so a footprint
/// that grows with freed memory can be told apart from one that grows with
/// retained memory.
struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to the system allocator unchanged and only
// updates a counter.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE_BYTES.fetch_add(new_size, Ordering::Relaxed);
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live_kib() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed) / 1024
}

#[cfg(target_os = "macos")]
fn footprint_kib() -> (u64, u64) {
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::uninit();
    // SAFETY: the buffer is a writable rusage_info_v4, the layout the V4
    // flavor fills; it is read only after the call reports success.
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    };
    assert_eq!(rc, 0, "proc_pid_rusage failed");
    // SAFETY: the call above reported success.
    let info = unsafe { info.assume_init() };
    (
        info.ri_phys_footprint / 1024,
        info.ri_interval_max_phys_footprint / 1024,
    )
}

#[cfg(target_os = "macos")]
fn reset_peak() {
    extern "C" {
        fn proc_reset_footprint_interval(pid: libc::c_int) -> libc::c_int;
    }
    // SAFETY: the call only resets this process's interval footprint peak.
    unsafe {
        proc_reset_footprint_interval(libc::getpid());
    }
}

#[cfg(not(target_os = "macos"))]
fn footprint_kib() -> (u64, u64) {
    (0, 0)
}

#[cfg(not(target_os = "macos"))]
fn reset_peak() {}

struct Phase {
    base: u64,
    live: usize,
    started: Instant,
}

impl Phase {
    fn begin() -> Self {
        reset_peak();
        Self {
            base: footprint_kib().0,
            live: live_kib(),
            started: Instant::now(),
        }
    }

    fn end(self, label: &str, baseline: u64) {
        let elapsed = self.started.elapsed();
        let (now, peak) = footprint_kib();
        let live = live_kib();
        let cache = geodata_cache_stats();
        println!(
            "{label:<10} footprint={now:>6} KiB (+{:>6} vs idle) delta={:>+6} KiB peak=+{:>6} KiB live_heap={live:>6} KiB ({:>+6}) time={:>7.2} ms cache: {} entries, {} hits, {} misses, {} KiB unused",
            now.saturating_sub(baseline),
            now as i64 - self.base as i64,
            peak.saturating_sub(self.base),
            live as i64 - self.live as i64,
            elapsed.as_secs_f64() * 1000.0,
            cache.entries,
            cache.hits,
            cache.misses,
            cache.unused_bytes / 1024,
        );
    }
}

async fn start_core(raw: &str, geodata_dir: &str) -> Core {
    let parsed = parse_xray_json_with_exclusive_geodata_dirs(raw, &[geodata_dir])
        .unwrap_or_else(|error| panic!("config failed to parse: {:?}", error.diagnostics));
    let mut core = Core::new(parsed.config).expect("core builds");
    core.start().await.expect("core starts");
    core
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [geodata_dir, config_path, rest @ ..] = args.as_slice() else {
        eprintln!(
            "usage: geodata_restart_memory <geodata-dir> <config.json> [restarts] [stop-first|overlap]"
        );
        std::process::exit(2);
    };
    let restarts = rest
        .first()
        .map(|value| value.parse::<usize>().expect("restarts is a number"))
        .unwrap_or(5);
    let overlap = match rest.get(1).map(String::as_str) {
        None | Some("stop-first") => false,
        Some("overlap") => true,
        Some(other) => panic!("unknown mode `{other}`"),
    };
    let raw = std::fs::read_to_string(config_path).expect("config is readable");

    // A first core without the geodata rules warms the runtime, listeners and
    // allocator so the following deltas belong to the routing rules.
    let warmup_raw = r#"{"inbounds":[{"tag":"in","protocol":"socks","listen":"127.0.0.1","port":0}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}"#;
    let mut warmup = start_core(warmup_raw, geodata_dir).await;
    warmup.stop().await.expect("warm-up core stops");
    drop(warmup);
    let idle = footprint_kib().0;
    println!(
        "mode={} restarts={restarts} idle footprint={idle} KiB live_heap={} KiB",
        if overlap { "overlap" } else { "stop-first" },
        live_kib()
    );

    let mut running: Option<Core> = None;
    for start in 1..=restarts {
        if !overlap {
            if let Some(mut core) = running.take() {
                let phase = Phase::begin();
                core.stop().await.expect("core stops");
                drop(core);
                trim_geodata_cache();
                phase.end(&format!("stop #{}", start - 1), idle);
            }
        }
        let phase = Phase::begin();
        let core = start_core(&raw, geodata_dir).await;
        phase.end(&format!("start #{start}"), idle);
        if let Some(mut previous) = running.replace(core) {
            let phase = Phase::begin();
            previous.stop().await.expect("core stops");
            drop(previous);
            trim_geodata_cache();
            phase.end(&format!("stop #{}", start - 1), idle);
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (steady, _) = footprint_kib();
    println!(
        "steady with one core: footprint={steady} KiB (+{} vs idle) live_heap={} KiB",
        steady.saturating_sub(idle),
        live_kib()
    );
    if let Some(mut core) = running.take() {
        core.stop().await.expect("core stops");
    }
    trim_geodata_cache();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (after, _) = footprint_kib();
    println!(
        "after last stop:      footprint={after} KiB (+{} vs idle) live_heap={} KiB",
        after.saturating_sub(idle),
        live_kib()
    );
}
