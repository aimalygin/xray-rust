//! Growing a connection's stream windows from what the link delivers, as
//! grpc-go does.
//!
//! Under Xray's default `grpcSettings` grpc-go's BDP estimator is live: only
//! `WithInitialWindowSize`, which Xray attaches for an `initialWindowsSize`
//! above zero, sets `StaticWindowSize` and turns it off
//! (`Xray-core/transport/internet/grpc/dial.go:169-171`,
//! `grpc@v1.84.0/dialoptions.go`, `internal/transport/http2_client.go:393-398`).
//! A DATA frame that arrives while no estimate is in flight sends a PING
//! (`handleData`, `http2_client.go:1207-1240`). The bytes that land before its
//! ACK are one sample, and a sample that fills two thirds of the estimate at
//! the highest bandwidth seen so far doubles it, up to 16 MiB
//! (`internal/transport/bdp_estimator.go`). Each growth reaches the peer as
//! `SETTINGS_INITIAL_WINDOW_SIZE` for every stream (`updateFlowControl`,
//! `http2_client.go:1186-1205`).
//!
//! Without it every stream keeps HTTP/2's 65,535-byte window, which is a
//! flow's entire downlink per round trip: about 10 Mbit/s at 50 ms and 5 at
//! 100 ms, however fast the link.
//!
//! Nothing is sent before data arrives, so the opening burst is unchanged.
//! Two differences from grpc-go remain:
//!
//! - grpc-go returns connection credit as frames arrive; h2 returns it only as
//!   streams are read. The connection window therefore grows with the stream
//!   window to sixteen of them (see [`connection_window_for`]), so that a flow
//!   that stops reading with a full window blocks the others only when fifteen
//!   more have done the same.
//! - On mobile targets the estimate stops at [`BDP_LIMIT`] = 1 MiB. Sixteen
//!   such windows fit in the 16 MiB connection window the transport opens
//!   with, so the memory a stalled reader can pin stays where it was.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Waker;

use futures_util::task::AtomicWaker;
use h2::{Ping, PingPong};
use tokio::sync::{Mutex, Notify};
use tokio::time::{Duration, Instant};

/// grpc-go's `bdpLimit`, the largest window its estimator grows to.
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
pub(super) const BDP_LIMIT: u32 = 16 * 1024 * 1024;

/// 1 MiB is 84 Mbit/s per flow at 100 ms, against 5 at the static window, and
/// keeps the memory sixteen stalled flows can pin inside the connection window
/// mobile clients already had.
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
pub(super) const BDP_LIMIT: u32 = 1024 * 1024;

/// How many full stream windows the connection window holds.
const STREAMS_PER_CONNECTION_WINDOW: u32 = 16;

/// grpc-go's `alpha`, `beta` and `gamma` (`bdp_estimator.go`).
const ALPHA: f64 = 0.9;
const BETA: f64 = 0.66;
const GAMMA: f64 = 2.0;

/// A loopback round trip can measure as zero; one microsecond keeps the
/// bandwidth finite without changing any real estimate.
const MIN_RTT_SECS: f64 = 1e-6;

/// The connection window that goes with a stream window of `stream_window`.
pub(super) fn connection_window_for(stream_window: u32, opening_window: u32) -> u32 {
    stream_window
        .saturating_mul(STREAMS_PER_CONNECTION_WINDOW)
        .max(opening_window)
}

/// grpc-go's `bdpEstimator`, without the bookkeeping of when a sample starts,
/// which [`BdpSampler`] keeps instead.
#[derive(Debug)]
pub(super) struct BdpEstimator {
    bdp: u32,
    limit: u32,
    max_bandwidth: f64,
    rtt: f64,
    samples: u64,
}

impl BdpEstimator {
    pub(super) fn new(initial_window: u32, limit: u32) -> Self {
        Self {
            bdp: initial_window,
            limit,
            max_bandwidth: 0.0,
            rtt: 0.0,
            samples: 0,
        }
    }

    pub(super) fn at_limit(&self) -> bool {
        self.bdp >= self.limit
    }

    /// Takes one sample, `bytes` received between a PING and its ACK `rtt`
    /// apart, and returns the new window if it grows.
    pub(super) fn calculate(&mut self, bytes: u64, rtt: Duration) -> Option<u32> {
        self.samples += 1;
        let rtt_sample = rtt.as_secs_f64().max(MIN_RTT_SECS);
        if self.samples < 10 {
            // The first ten round trips bootstrap a plain average.
            self.rtt += (rtt_sample - self.rtt) / self.samples as f64;
        } else {
            self.rtt += (rtt_sample - self.rtt) * ALPHA;
        }

        // A saturated link delivers at most 1.5 BDP before the ACK returns.
        let sample = bytes.min(u64::from(u32::MAX)) as f64;
        let bandwidth = sample / (self.rtt * 1.5);
        let fastest = bandwidth >= self.max_bandwidth;
        if fastest {
            self.max_bandwidth = bandwidth;
        }

        if fastest && sample >= BETA * f64::from(self.bdp) && !self.at_limit() {
            self.bdp = (GAMMA * sample).min(f64::from(self.limit)) as u32;
            return Some(self.bdp);
        }
        None
    }
}

/// What a connection's streams and its driver share: the bytes the streams
/// read, and a grown window on its way to the driver.
#[derive(Debug, Default)]
pub(crate) struct BdpSampler {
    /// Bytes read since the last sample ended.
    bytes: AtomicU64,
    /// Whether a PING is out, during which data extends its sample instead of
    /// starting another.
    sampling: AtomicBool,
    /// Set once the estimate reaches its limit, after which nothing counts.
    finished: AtomicBool,
    data: Notify,
    /// A grown window the driver has not applied yet, or zero.
    pending_window: AtomicU32,
    driver: AtomicWaker,
}

impl BdpSampler {
    /// Counts `len` bytes of DATA, and starts a sample unless one is running.
    ///
    /// grpc-go counts frames as they arrive; this counts them as a stream
    /// reads them. For a reader that keeps up the two are the same, and a
    /// reader that has stopped has no use for a larger window.
    pub(crate) fn record_data(&self, len: usize) {
        if self.finished.load(Ordering::Relaxed) {
            return;
        }
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        if !self.sampling.load(Ordering::Relaxed) {
            self.data.notify_one();
        }
    }

    /// Called by the driver on every poll: remembers its waker and hands over
    /// a window waiting to be applied.
    pub(super) fn take_window(&self, waker: &Waker) -> Option<u32> {
        self.driver.register(waker);
        match self.pending_window.swap(0, Ordering::Relaxed) {
            0 => None,
            window => Some(window),
        }
    }

    /// Puts back a window the driver could not apply yet. The driver's next
    /// poll retries, so this deliberately does not wake it.
    pub(super) fn defer_window(&self, window: u32) {
        self.pending_window.fetch_max(window, Ordering::Relaxed);
    }

    fn offer_window(&self, window: u32) {
        self.pending_window.fetch_max(window, Ordering::Relaxed);
        self.driver.wake();
    }
}

/// One connection's BDP ping loop.
pub(super) struct BdpPings {
    pub(super) sampler: Arc<BdpSampler>,
    /// Shared with the keepalive: h2 allows one user PING in flight.
    pub(super) ping_pong: Arc<Mutex<PingPong>>,
    pub(super) estimator: BdpEstimator,
}

impl BdpPings {
    /// Samples until the estimate reaches its limit, then idles.
    ///
    /// It never finishes, because finishing would end the connection it is
    /// driven beside.
    pub(super) async fn run(mut self) {
        while !self.estimator.at_limit() {
            self.sampler.data.notified().await;
            // A keepalive PING holds the handle for at most its timeout; the
            // data that arrived meanwhile is simply not sampled.
            let Ok(mut ping_pong) = self.ping_pong.try_lock() else {
                self.sampler.bytes.store(0, Ordering::Relaxed);
                continue;
            };
            self.sampler.sampling.store(true, Ordering::Relaxed);
            let sent = Instant::now();
            let acknowledged = ping_pong.ping(Ping::opaque()).await.is_ok();
            drop(ping_pong);
            self.sampler.sampling.store(false, Ordering::Relaxed);
            let bytes = self.sampler.bytes.swap(0, Ordering::Relaxed);
            if !acknowledged {
                break;
            }
            if let Some(window) = self.estimator.calculate(bytes, sent.elapsed()) {
                self.sampler.offer_window(window);
            }
        }
        self.sampler.finished.store(true, Ordering::Relaxed);
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt;

    use super::*;

    const RTT: Duration = Duration::from_millis(40);

    #[test]
    fn a_sample_that_fills_two_thirds_of_the_window_doubles_it() {
        let mut estimator = BdpEstimator::new(65_535, 16 << 20);

        assert_eq!(estimator.calculate(65_535, RTT), Some(131_070));
        assert_eq!(estimator.calculate(131_070, RTT), Some(262_140));
    }

    #[test]
    fn a_sample_below_two_thirds_of_the_window_leaves_it() {
        let mut estimator = BdpEstimator::new(65_535, 16 << 20);

        assert_eq!(estimator.calculate(40_000, RTT), None);
    }

    #[test]
    fn a_slower_sample_leaves_the_window_even_when_it_is_large_enough() {
        let mut estimator = BdpEstimator::new(65_535, 16 << 20);
        assert_eq!(estimator.calculate(65_535, RTT), Some(131_070));

        // Five times the round trip with the same bytes is a lower bandwidth.
        assert_eq!(estimator.calculate(131_070, RTT * 5), None);
    }

    #[test]
    fn the_window_stops_at_the_limit() {
        let mut estimator = BdpEstimator::new(65_535, 1 << 20);

        let mut window = 65_535;
        while let Some(grown) = estimator.calculate(u64::from(window), RTT) {
            window = grown;
        }

        assert_eq!(window, 1 << 20);
        assert!(estimator.at_limit());
        assert_eq!(estimator.calculate(u64::from(window) * 4, RTT), None);
    }

    #[test]
    fn the_connection_window_holds_sixteen_stream_windows_and_never_shrinks() {
        assert_eq!(connection_window_for(65_535, 16 << 20), 16 << 20);
        assert_eq!(connection_window_for(1 << 20, 16 << 20), 16 << 20);
        assert_eq!(connection_window_for(4 << 20, 16 << 20), 64 << 20);
        assert_eq!(connection_window_for(16 << 20, 16 << 20), 256 << 20);
    }

    #[test]
    fn a_running_sample_absorbs_data_without_starting_another() {
        let sampler = BdpSampler::default();
        sampler.sampling.store(true, Ordering::Relaxed);

        sampler.record_data(1000);
        sampler.record_data(500);

        assert_eq!(sampler.bytes.load(Ordering::Relaxed), 1500);
        assert!(sampler.data.notified().now_or_never().is_none());
    }

    #[test]
    fn a_finished_sampler_counts_nothing() {
        let sampler = BdpSampler::default();
        sampler.finished.store(true, Ordering::Relaxed);

        sampler.record_data(1000);

        assert_eq!(sampler.bytes.load(Ordering::Relaxed), 0);
    }
}
