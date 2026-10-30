//! Growing HTTP/2 stream windows from what the link delivers, as grpc-go's BDP
//! estimator does.
//!
//! Under Xray's default `grpcSettings` grpc-go's estimator is live: only
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
//! Without it every gRPC stream keeps HTTP/2's 65,535-byte window, which is a
//! flow's entire downlink per round trip: about 10 Mbit/s at 50 ms and 5 at
//! 100 ms, however fast the link.
//!
//! gRPC counts DATA as it arrives, where grpc-go does — see [`DataArrivals`]
//! for the server policy that depends on it.
//!
//! XHTTP uses the same estimator on a [`MemoryClass::Constrained`] host, where
//! it opens with a smaller window than Go's 4 MiB and grows to it only for a
//! reader that keeps up (see `super::xhttp::h2`). That is why XHTTP counts what
//! its reader takes instead; Go's HTTP/2 server, unlike grpc-go's, has no ping
//! policy to trip.
//!
//! Nothing is sent before data arrives, so an opening burst is unchanged.
//! Two differences from grpc-go remain:
//!
//! - grpc-go returns connection credit as frames arrive; h2 returns it only as
//!   streams are read. The gRPC connection window therefore grows with the
//!   stream window to sixteen of them (see [`connection_window_for`]), so that
//!   a flow that stops reading with a full window blocks the others only when
//!   fifteen more have done the same.
//! - On a constrained host gRPC stops at 1 MiB (see [`grpc_bdp_limit`]).
//!   Sixteen such windows fit in the 16 MiB connection window the transport
//!   opens with, so the memory stalled readers can pin stays where it was.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Waker;

use futures_util::task::AtomicWaker;
use h2::{Ping, PingPong};
use tokio::sync::{Mutex, Notify};
use tokio::time::{Duration, Instant};

use crate::MemoryClass;

/// grpc-go's `bdpLimit`, the largest window its estimator grows to.
const GRPC_BDP_LIMIT: u32 = 16 * 1024 * 1024;

/// 1 MiB is 84 Mbit/s per flow at 100 ms, against 5 at the static window.
const CONSTRAINED_GRPC_BDP_LIMIT: u32 = 1024 * 1024;

/// How many full stream windows the gRPC connection window holds.
const STREAMS_PER_CONNECTION_WINDOW: u32 = 16;

/// grpc-go's `alpha`, `beta` and `gamma` (`bdp_estimator.go`).
const ALPHA: f64 = 0.9;
const BETA: f64 = 0.66;
const GAMMA: f64 = 2.0;

/// A loopback round trip can measure as zero; one microsecond keeps the
/// bandwidth finite without changing any real estimate.
const MIN_RTT_SECS: f64 = 1e-6;

/// The largest window gRPC's estimator grows to on a host of `class`.
pub(crate) fn grpc_bdp_limit(class: MemoryClass) -> u32 {
    match class {
        MemoryClass::Standard => GRPC_BDP_LIMIT,
        MemoryClass::Constrained => CONSTRAINED_GRPC_BDP_LIMIT,
    }
}

/// The gRPC connection window that goes with a stream window of
/// `stream_window`.
pub(crate) fn connection_window_for(stream_window: u32, opening_window: u32) -> u32 {
    stream_window
        .saturating_mul(STREAMS_PER_CONNECTION_WINDOW)
        .max(opening_window)
}

/// grpc-go's `bdpEstimator`, without the bookkeeping of when a sample starts,
/// which [`BdpSampler`] keeps instead.
#[derive(Debug)]
pub(crate) struct BdpEstimator {
    bdp: u32,
    limit: u32,
    max_bandwidth: f64,
    rtt: f64,
    samples: u64,
}

impl BdpEstimator {
    pub(crate) fn new(initial_window: u32, limit: u32) -> Self {
        Self {
            bdp: initial_window,
            limit,
            max_bandwidth: 0.0,
            rtt: 0.0,
            samples: 0,
        }
    }

    pub(crate) fn at_limit(&self) -> bool {
        self.bdp >= self.limit
    }

    /// Takes one sample, `bytes` received between a PING and its ACK `rtt`
    /// apart, and returns the new window if it grows.
    pub(crate) fn calculate(&mut self, bytes: u64, rtt: Duration) -> Option<u32> {
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

/// What a connection's DATA and its driver share: the bytes of the running
/// sample, and a grown window on its way to the driver.
#[derive(Debug, Default)]
pub(crate) struct BdpSampler {
    /// Bytes counted since the running sample started.
    bytes: AtomicU64,
    /// Whether a sample is running, from the DATA that started it until its
    /// PING is answered. Data meanwhile extends it instead of starting another.
    sampling: AtomicBool,
    /// Set once sampling stops, after which nothing counts.
    finished: AtomicBool,
    data: Notify,
    /// A grown window the driver has not applied yet, or zero.
    pending_window: AtomicU32,
    driver: AtomicWaker,
}

impl BdpSampler {
    /// Counts `len` bytes of DATA, starting a sample unless one is running.
    ///
    /// The DATA that starts a sample claims it on the spot, as grpc-go's
    /// `bdpEstimator.add` sets `isSent`: the ping loop may not run before more
    /// DATA arrives, and if starting were left to it, that DATA would start a
    /// second sample, to be pinged for after the first one's ACK with nothing
    /// written since.
    pub(crate) fn record_data(&self, len: usize) {
        if self.finished.load(Ordering::Relaxed) {
            return;
        }
        if self.sampling.swap(true, Ordering::AcqRel) {
            self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        } else {
            self.bytes.store(len as u64, Ordering::Relaxed);
            self.data.notify_one();
        }
    }

    /// Ends the running sample and returns its bytes.
    fn end_sample(&self) -> u64 {
        let bytes = self.bytes.swap(0, Ordering::Relaxed);
        self.sampling.store(false, Ordering::Release);
        bytes
    }

    /// Called by the driver on every poll: remembers its waker and hands over
    /// a window waiting to be applied.
    pub(crate) fn take_window(&self, waker: &Waker) -> Option<u32> {
        self.driver.register(waker);
        match self.pending_window.swap(0, Ordering::Relaxed) {
            0 => None,
            window => Some(window),
        }
    }

    /// Puts back a window the driver could not apply yet. The driver's next
    /// poll retries, so this deliberately does not wake it.
    pub(crate) fn defer_window(&self, window: u32) {
        self.pending_window.fetch_max(window, Ordering::Relaxed);
    }

    fn offer_window(&self, window: u32) {
        self.pending_window.fetch_max(window, Ordering::Relaxed);
        self.driver.wake();
    }

    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }
}

/// An HTTP/2 frame header: a 24-bit length, a type, flags and a stream id
/// (RFC 9113 4.1).
const FRAME_HEADER_LEN: usize = 9;
const DATA_FRAME: u8 = 0x0;

/// Counts DATA frames into a [`BdpSampler`] as they come off the socket, which
/// is where grpc-go's `handleData` counts them.
///
/// The timing is what grpc-go's server relies on. More than two PINGs with no
/// DATA or HEADERS written in between is `GOAWAY` `too_many_pings`, which ends
/// every call on the connection (`handlePing`,
/// `grpc@v1.84.0/internal/transport/http2_server.go:882-933`). A frame that
/// arrives after a PING's ACK was written after the server answered that PING,
/// so a sample started by its arrival always follows fresh DATA. A sample
/// started when a call *reads* does not: draining data h2 buffered earlier
/// pings again and again after the server has stopped writing, which is how a
/// full-duplex flow lost its connection while its upload was still running.
pub(crate) struct DataArrivals {
    sampler: Arc<BdpSampler>,
    header: [u8; FRAME_HEADER_LEN],
    header_len: usize,
    payload_left: usize,
}

impl DataArrivals {
    pub(crate) fn new(sampler: Arc<BdpSampler>) -> Self {
        Self {
            sampler,
            header: [0; FRAME_HEADER_LEN],
            header_len: 0,
            payload_left: 0,
        }
    }

    /// Scans the next bytes the server sent. Its side of the connection is
    /// frames from the first byte: a server's preface is a SETTINGS frame with
    /// nothing before it (RFC 9113 3.4).
    pub(crate) fn observe(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.payload_left > 0 {
                let skipped = self.payload_left.min(bytes.len());
                self.payload_left -= skipped;
                bytes = &bytes[skipped..];
                continue;
            }
            let taken = (FRAME_HEADER_LEN - self.header_len).min(bytes.len());
            self.header[self.header_len..][..taken].copy_from_slice(&bytes[..taken]);
            self.header_len += taken;
            bytes = &bytes[taken..];
            if self.header_len == FRAME_HEADER_LEN {
                self.header_len = 0;
                let [high, middle, low, kind, ..] = self.header;
                self.payload_left = u32::from_be_bytes([0, high, middle, low]) as usize;
                if kind == DATA_FRAME {
                    self.sampler.record_data(self.payload_left);
                }
            }
        }
    }

    /// Whether the estimate has stopped, after which there is nothing to count.
    pub(crate) fn is_finished(&self) -> bool {
        self.sampler.is_finished()
    }
}

/// One connection's BDP ping loop.
pub(crate) struct BdpPings {
    pub(crate) sampler: Arc<BdpSampler>,
    /// Shared with the keepalive: h2 allows one user PING in flight.
    pub(crate) ping_pong: Arc<Mutex<PingPong>>,
    pub(crate) estimator: BdpEstimator,
    /// Stops after this many samples in a row leave the window unchanged.
    /// grpc-go keeps sampling until its limit, so gRPC passes `None`.
    pub(crate) idle_limit: Option<u32>,
}

impl BdpPings {
    /// Samples until the estimate reaches its limit or settles, then idles.
    ///
    /// It never finishes, because finishing would end the connection it is
    /// driven beside.
    pub(crate) async fn run(mut self) {
        let mut unchanged = 0;
        while !self.estimator.at_limit() && self.idle_limit.is_none_or(|limit| unchanged < limit) {
            self.sampler.data.notified().await;
            // A keepalive PING holds the handle for at most its timeout; the
            // data that arrived meanwhile is simply not sampled.
            let Ok(mut ping_pong) = self.ping_pong.try_lock() else {
                self.sampler.end_sample();
                continue;
            };
            let sent = Instant::now();
            let acknowledged = ping_pong.ping(Ping::opaque()).await.is_ok();
            drop(ping_pong);
            let bytes = self.sampler.end_sample();
            if !acknowledged {
                break;
            }
            match self.estimator.calculate(bytes, sent.elapsed()) {
                Some(window) => {
                    unchanged = 0;
                    self.sampler.offer_window(window);
                }
                None => unchanged += 1,
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
    fn grpc_grows_to_grpc_gos_limit_except_on_a_constrained_host() {
        assert_eq!(grpc_bdp_limit(MemoryClass::Standard), 16 << 20);
        assert_eq!(grpc_bdp_limit(MemoryClass::Constrained), 1 << 20);
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

    fn frame(kind: u8, payload_len: usize) -> Vec<u8> {
        let len = u32::try_from(payload_len)
            .expect("a frame length")
            .to_be_bytes();
        let mut frame = vec![len[1], len[2], len[3], kind, 0, 0, 0, 0, 1];
        frame.resize(FRAME_HEADER_LEN + payload_len, 0xa5);
        frame
    }

    #[test]
    fn only_data_frames_are_counted_however_the_reads_split_them() {
        const SETTINGS: u8 = 0x4;
        const WINDOW_UPDATE: u8 = 0x8;
        let wire = [
            frame(SETTINGS, 18),
            frame(DATA_FRAME, 16_384),
            frame(WINDOW_UPDATE, 4),
            frame(DATA_FRAME, 0),
            frame(DATA_FRAME, 5),
        ]
        .concat();

        for read_len in [1, 7, 9, 10, 4096, wire.len()] {
            let sampler = Arc::new(BdpSampler::default());
            sampler.sampling.store(true, Ordering::Relaxed);
            let mut arrivals = DataArrivals::new(Arc::clone(&sampler));
            for read in wire.chunks(read_len) {
                arrivals.observe(read);
            }
            assert_eq!(
                sampler.bytes.load(Ordering::Relaxed),
                16_389,
                "reads of {read_len}"
            );
        }
    }

    #[test]
    fn the_data_that_starts_a_sample_claims_it_for_the_data_behind_it() {
        let sampler = Arc::new(BdpSampler::default());
        let mut arrivals = DataArrivals::new(Arc::clone(&sampler));

        arrivals.observe(&frame(DATA_FRAME, 100));
        assert!(sampler.data.notified().now_or_never().is_some());
        arrivals.observe(&frame(DATA_FRAME, 50));

        assert!(
            sampler.data.notified().now_or_never().is_none(),
            "a second sample was started inside the first"
        );
        assert_eq!(sampler.end_sample(), 150);
    }

    /// A stream reading on another task can add to a sample just as it ends;
    /// those bytes belong to neither sample.
    #[test]
    fn a_new_sample_drops_bytes_left_over_from_the_last() {
        let sampler = BdpSampler::default();
        sampler.bytes.store(30, Ordering::Relaxed);

        sampler.record_data(70);

        assert!(sampler.data.notified().now_or_never().is_some());
        assert_eq!(sampler.end_sample(), 70);
    }

    #[test]
    fn a_finished_sampler_counts_nothing() {
        let sampler = BdpSampler::default();
        sampler.finished.store(true, Ordering::Relaxed);

        sampler.record_data(1000);

        assert_eq!(sampler.bytes.load(Ordering::Relaxed), 0);
    }
}
