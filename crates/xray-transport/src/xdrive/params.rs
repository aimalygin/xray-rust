//! The tuning of a session, as Xray-core v26.11.9's `params.go` derives it
//! from the configured numbers.

use std::time::Duration;

const DEFAULT_SEGMENT_BYTES: usize = 512 * 1024;
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(20);
const DEFAULT_MIN_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DEFAULT_MAX_POLL_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_EAGER_WINDOW: Duration = Duration::from_secs(2);
const DEFAULT_HOLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_CONCURRENCY: usize = 8;

const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_CONCURRENCY: usize = 256;

/// The numbers of `xdriveSettings`, as configured; zero takes the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdriveTuning {
    pub segment_bytes: u32,
    pub flush_interval_ms: u32,
    pub poll_interval_ms: u32,
    pub max_poll_interval_ms: u32,
    pub session_ttl_seconds: u32,
    pub concurrency: u32,
    pub eager_window_ms: u32,
    pub hole_timeout_ms: u32,
}

/// `params`: what the session's writer and reader work with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Params {
    /// The most bytes one segment carries.
    pub segment_bytes: usize,
    /// How often a writer looks whether its buffer stopped growing.
    pub flush_interval: Duration,
    /// How often a reader polls while data moves.
    pub min_poll_interval: Duration,
    /// How seldom a reader polls at most once nothing moves.
    pub max_poll_interval: Duration,
    /// How long after data moved a reader keeps polling often.
    pub eager_window: Duration,
    /// How long a reader waits for a segment that later ones overtook.
    pub hole_timeout: Duration,
    /// How long a server keeps a session nobody uses; unused by a client.
    pub session_ttl: Duration,
    /// How many requests a direction keeps in flight.
    pub concurrency: usize,
}

fn millis(value: u32, fallback: Duration) -> Duration {
    if value == 0 {
        fallback
    } else {
        Duration::from_millis(u64::from(value))
    }
}

fn seconds(value: u32, fallback: Duration) -> Duration {
    if value == 0 {
        fallback
    } else {
        Duration::from_secs(u64::from(value))
    }
}

fn capped(value: u32, fallback: usize, limit: usize) -> usize {
    match value {
        0 => fallback,
        value => (value as usize).min(limit),
    }
}

impl Params {
    /// `paramsFromConfig`.
    pub(crate) fn from_tuning(tuning: &XdriveTuning) -> Self {
        let mut params = Self {
            segment_bytes: capped(
                tuning.segment_bytes,
                DEFAULT_SEGMENT_BYTES,
                MAX_SEGMENT_BYTES,
            ),
            flush_interval: millis(tuning.flush_interval_ms, DEFAULT_FLUSH_INTERVAL),
            min_poll_interval: millis(tuning.poll_interval_ms, DEFAULT_MIN_POLL_INTERVAL),
            max_poll_interval: millis(tuning.max_poll_interval_ms, DEFAULT_MAX_POLL_INTERVAL),
            eager_window: millis(tuning.eager_window_ms, DEFAULT_EAGER_WINDOW),
            hole_timeout: millis(tuning.hole_timeout_ms, DEFAULT_HOLE_TIMEOUT),
            session_ttl: seconds(tuning.session_ttl_seconds, DEFAULT_SESSION_TTL),
            concurrency: capped(tuning.concurrency, DEFAULT_CONCURRENCY, MAX_CONCURRENCY),
        };
        if params.max_poll_interval < params.min_poll_interval {
            params.max_poll_interval = params.min_poll_interval;
        }
        params
    }
}

/// `paramsForStorage`: a storage of slots (Google Drive) takes defaults of
/// its own for the numbers the configuration leaves at zero -- 64 slots a
/// way, a 10 ms flush and polls of at most 200 ms -- since its concurrency
/// and flush mean other things than the segment storages'.
pub(crate) fn for_slot_store(tuning: &XdriveTuning) -> Params {
    let mut tuning = *tuning;
    if tuning.concurrency == 0 {
        tuning.concurrency = 64;
    }
    if tuning.flush_interval_ms == 0 {
        tuning.flush_interval_ms = 10;
    }
    if tuning.max_poll_interval_ms == 0 {
        tuning.max_poll_interval_ms = 200;
    }
    Params::from_tuning(&tuning)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_takes_xrays_defaults() {
        assert_eq!(
            Params::from_tuning(&XdriveTuning::default()),
            Params {
                segment_bytes: 512 * 1024,
                flush_interval: Duration::from_millis(20),
                min_poll_interval: Duration::from_millis(50),
                max_poll_interval: Duration::from_millis(500),
                eager_window: Duration::from_secs(2),
                hole_timeout: Duration::from_secs(30),
                session_ttl: Duration::from_secs(300),
                concurrency: 8,
            }
        );
    }

    #[test]
    fn slot_stores_take_their_own_defaults_for_zero_only() {
        let params = for_slot_store(&XdriveTuning::default());
        assert_eq!(params.concurrency, 64);
        assert_eq!(params.flush_interval, Duration::from_millis(10));
        assert_eq!(params.max_poll_interval, Duration::from_millis(200));
        assert_eq!(params.min_poll_interval, Duration::from_millis(50));
        let params = for_slot_store(&XdriveTuning {
            concurrency: 3,
            flush_interval_ms: 7,
            max_poll_interval_ms: 900,
            ..XdriveTuning::default()
        });
        assert_eq!(params.concurrency, 3);
        assert_eq!(params.flush_interval, Duration::from_millis(7));
        assert_eq!(params.max_poll_interval, Duration::from_millis(900));
    }

    #[test]
    fn caps_and_the_poll_floor_apply() {
        let params = Params::from_tuning(&XdriveTuning {
            segment_bytes: u32::MAX,
            concurrency: 1_000,
            poll_interval_ms: 300,
            max_poll_interval_ms: 100,
            ..XdriveTuning::default()
        });
        assert_eq!(params.segment_bytes, 16 * 1024 * 1024);
        assert_eq!(params.concurrency, 256);
        assert_eq!(params.max_poll_interval, Duration::from_millis(300));
        let params = Params::from_tuning(&XdriveTuning {
            segment_bytes: 1,
            concurrency: 1,
            session_ttl_seconds: 7,
            ..XdriveTuning::default()
        });
        assert_eq!((params.segment_bytes, params.concurrency), (1, 1));
        assert_eq!(params.session_ttl, Duration::from_secs(7));
    }
}
