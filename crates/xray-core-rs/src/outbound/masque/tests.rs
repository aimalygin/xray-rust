use super::*;
use std::sync::atomic::AtomicBool;

fn range(from: i32, to: i32) -> xray_config::XhttpRange {
    xray_config::XhttpRange { from, to }
}

#[derive(Default)]
struct Fake {
    closed: AtomicBool,
}

impl Pooled for Fake {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

fn pool(xmux: XhttpXmuxSettings) -> Pool<Fake> {
    let mut rng = rand::thread_rng();
    Pool {
        xmux,
        concurrency: draw_range(xmux.max_concurrency, &mut rng),
        connections: draw_range(xmux.max_connections, &mut rng),
        entries: Vec::new(),
        last_error: None,
    }
}

fn zero() -> XhttpXmuxSettings {
    XhttpXmuxSettings {
        max_concurrency: range(0, 0),
        max_connections: range(0, 0),
        c_max_reuse_times: range(0, 0),
        h_max_request_times: range(0, 0),
        h_max_reusable_secs: range(0, 0),
        h_keep_alive_period_secs: 0,
    }
}

fn refused() -> CoreError {
    MasqueError::Status(401).into()
}

/// A flow's next step, dialing with `dial` when the pool asks.
fn flow(
    pool: &mut Pool<Fake>,
    dials: &mut usize,
    dial: impl FnOnce() -> Result<Arc<Fake>, CoreError>,
) -> Result<Lease<Fake>, String> {
    match pool.take() {
        Take::Lease(lease) => Ok(lease),
        Take::Failed(error) => Err(error),
        Take::Dial => {
            *dials += 1;
            pool.dialed(dial()).map_err(|error| error.to_string())
        }
    }
}

/// Xray's `TestGetTunnelFallsBack`: with room for three tunnels, a refused
/// dial falls back to the healthy one and is not retried within a second.
#[test]
fn a_refused_dial_falls_back_to_the_healthy_tunnel() {
    let mut pool = pool(XhttpXmuxSettings {
        max_connections: range(3, 3),
        ..zero()
    });
    let healthy = Arc::new(Fake::default());
    let mut dials = 0;
    let first = flow(&mut pool, &mut dials, || Ok(Arc::clone(&healthy))).unwrap();
    let mut held = vec![first];
    for _ in 0..5 {
        let lease = flow(&mut pool, &mut dials, || Err(refused())).unwrap();
        assert!(Arc::ptr_eq(&lease.0.tunnel, &healthy));
        held.push(lease);
    }
    assert_eq!(
        dials, 2,
        "a failed tunnel must not be redialed within the retry interval"
    );
}

/// Xray's `TestGetTunnelFailsWithoutTunnels`.
#[test]
fn a_refused_dial_without_tunnels_fails_every_flow_for_a_second() {
    let mut pool = pool(XhttpXmuxSettings {
        max_connections: range(3, 3),
        ..zero()
    });
    let mut dials = 0;
    for _ in 0..2 {
        let Err(error) = flow(&mut pool, &mut dials, || Err(refused())) else {
            panic!("a refused dial without tunnels must fail");
        };
        assert!(error.contains("401"), "{error}");
    }
    assert_eq!(dials, 1);
    pool.last_error.as_mut().unwrap().1 -= RETRY_INTERVAL;
    let _ = flow(&mut pool, &mut dials, || Err(refused()));
    assert_eq!(dials, 2, "after a second the next flow dials again");
}

#[test]
fn the_default_is_one_tunnel_for_every_flow() {
    let mut pool = pool(MASQUE_DEFAULT_XMUX_FOR_TESTS);
    let mut dials = 0;
    let leases: Vec<_> = (0..10)
        .map(|_| flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap())
        .collect();
    assert_eq!(dials, 1);
    assert!(leases
        .iter()
        .all(|lease| Arc::ptr_eq(&lease.0, &leases[0].0)));
    assert_eq!(leases[0].0.running.load(Ordering::Acquire), 10);
    let unreusable = leases[0].0.unreusable_at.unwrap();
    let left = unreusable.saturating_duration_since(Instant::now());
    assert!(left > Duration::from_secs(1790) && left <= Duration::from_secs(3000));
}

#[test]
fn concurrency_opens_a_tunnel_once_every_tunnel_is_full() {
    let mut pool = pool(XhttpXmuxSettings {
        max_concurrency: range(2, 2),
        ..zero()
    });
    let mut dials = 0;
    let leases: Vec<_> = (0..5)
        .map(|_| flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap())
        .collect();
    assert_eq!(dials, 3);
    assert!(pool
        .entries
        .iter()
        .all(|entry| entry.running.load(Ordering::Acquire) <= 2));
    drop(leases);
    let _lease = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert_eq!(dials, 3, "a tunnel with room takes the next flow");
}

#[test]
fn a_used_up_tunnel_retires_and_closes_with_its_last_flow() {
    let mut pool = pool(XhttpXmuxSettings {
        c_max_reuse_times: range(2, 2),
        ..zero()
    });
    let mut dials = 0;
    let first = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    let second = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert!(Arc::ptr_eq(&first.0, &second.0));
    let tunnel = Arc::clone(&first.0.tunnel);
    let third = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert_eq!(dials, 2, "two uses spend the first tunnel");
    assert!(!Arc::ptr_eq(&third.0, &first.0));
    assert!(!tunnel.is_closed(), "flows still hold the retired tunnel");
    drop(first);
    assert!(!tunnel.is_closed());
    drop(second);
    assert!(tunnel.is_closed(), "the last flow closes a retired tunnel");
}

#[test]
fn an_old_or_closed_tunnel_is_not_reused() {
    let mut pool = pool(zero());
    let mut dials = 0;
    let lease = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    let old = Arc::clone(&lease.0.tunnel);
    // Past its reusable time.
    let entry = Arc::clone(&lease.0);
    drop(lease);
    pool.entries[0] = Arc::new(Entry {
        tunnel: Arc::clone(&entry.tunnel),
        running: AtomicI32::new(0),
        left_usage: AtomicI32::new(-1),
        unreusable_at: Some(Instant::now() - Duration::from_secs(1)),
        not_used: AtomicBool::new(false),
    });
    let fresh = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert_eq!(dials, 2);
    assert!(old.is_closed(), "an expired tunnel without flows closes");
    fresh.0.tunnel.close();
    let _next = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert_eq!(dials, 3, "a closed tunnel is dropped from the pool");
}

#[test]
fn ranges_draw_within_their_bounds() {
    let mut rng = rand::thread_rng();
    for _ in 0..200 {
        let value = draw_range(range(1800, 3000), &mut rng);
        assert!(
            (1800..3000).contains(&value),
            "RandBetween excludes the upper bound"
        );
    }
    let draws: std::collections::BTreeSet<_> = (0..200)
        .map(|_| draw_range(range(0, 2), &mut rng))
        .collect();
    assert_eq!(
        draws,
        [0, 1].into(),
        "every value below the upper bound, never it"
    );
    assert_eq!(draw_range(range(1, 1), &mut rng), 1);
    assert_eq!(draw_range(range(2, 3), &mut rng), 2);
    assert_eq!(draw_range(range(0, 0), &mut rng), 0);
}

#[test]
fn open_timeout_adds_the_tunnel_dial() {
    assert_eq!(
        open_timeout(Duration::from_secs(4)),
        Duration::from_secs(14)
    );
    assert_eq!(open_timeout(Duration::ZERO), Duration::ZERO);
}

const MASQUE_DEFAULT_XMUX_FOR_TESTS: XhttpXmuxSettings = xray_config::MASQUE_DEFAULT_XMUX;
