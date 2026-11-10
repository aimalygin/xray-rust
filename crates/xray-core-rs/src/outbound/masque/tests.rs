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
        established: Instant::now(),
    });
    let fresh = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert_eq!(dials, 2);
    assert!(old.is_closed(), "an expired tunnel without flows closes");
    // Closed after it had been up for a while.
    pool.entries[0] = Arc::new(Entry {
        tunnel: Arc::clone(&fresh.0.tunnel),
        running: AtomicI32::new(0),
        left_usage: AtomicI32::new(-1),
        unreusable_at: None,
        not_used: AtomicBool::new(false),
        established: Instant::now() - SHORT_LIVED,
    });
    fresh.0.tunnel.close();
    let _next = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert_eq!(dials, 3, "a closed tunnel is dropped from the pool");
}

/// A proxy that answers and then hangs up: the tunnel that closed right
/// after it was established is a failed dial, so the next flows fail for a
/// second instead of each paying for a handshake.
#[test]
fn a_tunnel_closed_right_after_it_was_established_is_not_redialed_at_once() {
    let mut pool = pool(zero());
    let mut dials = 0;
    let lease = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    lease.0.tunnel.close();
    drop(lease);
    for _ in 0..3 {
        let Err(error) = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))) else {
            panic!("no dial within a second of a tunnel that closed at once");
        };
        assert!(error.contains("closed right after"), "{error}");
    }
    assert_eq!(dials, 1);
    pool.last_error.as_mut().unwrap().1 -= RETRY_INTERVAL;
    let _next = flow(&mut pool, &mut dials, || Ok(Arc::new(Fake::default()))).unwrap();
    assert_eq!(dials, 2, "after a second the next flow dials again");
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

#[test]
fn http2_takes_only_h2_without_h3() {
    let alpn = |list: &[&str]| list.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    assert!(uses_http2(&alpn(&["h2"])));
    assert!(uses_http2(&alpn(&["http/1.1", "h2"])));
    assert!(!uses_http2(&alpn(&["h3", "h2"])));
    assert!(!uses_http2(&alpn(&[])));
    assert!(!uses_http2(&alpn(&["http/1.1"])));
}

#[test]
fn the_http2_carrier_must_negotiate_h2() {
    assert!(negotiated_h2(Some(b"h2")).is_ok());
    assert_eq!(
        negotiated_h2(Some(b"http/1.1")).unwrap_err().to_string(),
        r#"MASQUE dial failed: the server negotiated "http/1.1" instead of h2"#
    );
    assert_eq!(
        negotiated_h2(None).unwrap_err().to_string(),
        r#"MASQUE dial failed: the server negotiated "" instead of h2"#
    );
}

#[test]
fn http2_keepalive_follows_xmux() {
    assert_eq!(h2_keep_alive(0), Some(Duration::from_secs(45)));
    assert_eq!(h2_keep_alive(20), Some(Duration::from_secs(20)));
    assert_eq!(h2_keep_alive(-1), None);
}

/// The QUIC configuration a MASQUE outbound with `quic_params` dials with.
fn quic_for(quic_params: serde_json::Value) -> H3QuicConfig {
    let config = serde_json::json!({"outbounds": [{"protocol": "masque",
        "settings": {"address": "masque.example", "port": 443},
        "streamSettings": {"network": "masque", "security": "tls",
            "tlsSettings": {"serverName": "masque.example"},
            "finalmask": {"quicParams": quic_params}}}]});
    let parsed = xray_config::parse_xray_json(&config.to_string()).unwrap();
    let outbound = &parsed.config.outbounds[0];
    let StreamTransport::Masque(transport) = &outbound.stream.transport else {
        panic!("not a MASQUE transport");
    };
    masque_quic_config(&outbound.stream, transport).unwrap()
}

/// Xray's MASQUE dial never parrots Chrome, whatever `disableChromeParrot`
/// says.
#[test]
fn quic_never_parrots_chrome() {
    use serde_json::json;
    for quic_params in [
        json!({}),
        json!({"disableChromeParrot": false}),
        json!({"disableChromeParrot": true}),
    ] {
        assert!(
            !quic_for(quic_params.clone()).chrome_parrot,
            "{quic_params}"
        );
    }
}

#[test]
fn quic_runs_xrays_congestion_choices_and_bbr_profiles() {
    use serde_json::json;
    assert_eq!(quic_for(json!({})).congestion, H3Congestion::BbrStandard);
    assert_eq!(
        quic_for(json!({"bbrProfile": "conservative"})).congestion,
        H3Congestion::BbrConservative
    );
    // Xray's dial runs BBR with the profile for `brutal`: nothing announces
    // a rate.
    assert_eq!(
        quic_for(
            json!({"congestion": "brutal", "brutalUp": "100 mbps", "bbrProfile": "aggressive"})
        )
        .congestion,
        H3Congestion::BbrAggressive
    );
    assert_eq!(
        quic_for(json!({"congestion": "reno"})).congestion,
        H3Congestion::Reno
    );
    assert!(matches!(
        quic_for(json!({"congestion": "force-brutal", "brutalUp": "100 mbps"})).congestion,
        H3Congestion::ForceBrutal { .. }
    ));
}

/// A MASQUE outbound to `address` over HTTP/3 with `udp` as its UDP masks.
fn masque_with_masks(address: &str, udp: serde_json::Value) -> OutboundConfig {
    let config = serde_json::json!({"outbounds": [{"protocol": "masque",
        "settings": {"address": address, "port": 443},
        "streamSettings": {"network": "masque", "security": "tls",
            "tlsSettings": {"serverName": "masque.example"},
            "finalmask": {"udp": udp}}}]});
    xray_config::parse_xray_json(&config.to_string())
        .unwrap()
        .config
        .outbounds
        .remove(0)
}

/// Xray's MASQUE dial opens its UDP socket through `FinalMask.DialUDP`, as
/// XHTTP over HTTP/3 does: every UDP mask rides it, realm and xicmp too.
#[test]
fn every_udp_mask_rides_masque_over_http3() {
    use serde_json::json;
    let masks = [
        (
            "noise",
            json!({"type": "noise", "settings": {"noise": [{"rand": "10-20"}]}}),
        ),
        (
            "header-custom",
            json!({"type": "header-custom", "settings": {
                "client": [{"type": "str", "packet": "hi"}],
                "server": [{"type": "str", "packet": "ok"}]}}),
        ),
        (
            "sudoku",
            json!({"type": "sudoku", "settings": {"password": "synthetic-sudoku"}}),
        ),
        (
            "xdns",
            json!({"type": "xdns", "settings": {
                "domains": [{"names": ["t.example"], "types": [1, 5, 16, 28], "edns0": 4096}],
                "resolvers": [{"addrs": ["192.0.2.53:53"]}]}}),
        ),
        (
            "realm",
            json!({"type": "realm", "settings": {
                "url": "realm+http://synthetic-token@192.0.2.80:8080/masque",
                "stunServers": ["192.0.2.3:3478"]}}),
        ),
        ("xicmp", json!({"type": "xicmp"})),
    ];
    for (name, mask) in masks {
        let outbound = masque_with_masks("192.0.2.1", json!([mask]));
        super::super::validate_udp_noise(&outbound.stream)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let masque =
            MasqueOutbound::new(&outbound).unwrap_or_else(|error| panic!("{name}: {error}"));
        let Dial::H3 { quic, .. } = &masque.0.dial else {
            panic!("{name}: not HTTP/3");
        };
        let set = match name {
            "noise" => quic.udp_noise.is_some(),
            "header-custom" => quic.udp_header_custom.is_some(),
            "sudoku" => quic.udp_sudoku.is_some(),
            "xdns" => quic.udp_xdns.is_some(),
            "realm" => quic.udp_realm.is_some(),
            _ => quic.udp_xicmp.is_some(),
        };
        assert!(set, "{name} must reach the QUIC carrier");

        // Over HTTP/2 the carrier is TCP: the core refuses what the
        // configuration would.
        let with_alpn = |alpn: &[&str]| {
            let mut stream = outbound.stream.clone();
            let StreamSecurity::Tls(tls) = &mut stream.security else {
                unreachable!()
            };
            tls.alpn = alpn.iter().map(|p| p.to_string()).collect();
            super::super::validate_udp_noise(&stream)
        };
        assert!(with_alpn(&["h2"]).is_err(), "{name} over HTTP/2");
        assert!(
            with_alpn(&["h2", "h3"]).is_ok(),
            "{name} over h2 and h3 runs HTTP/3"
        );
    }
}

/// Xray's xicmp client sends to its `ips`, else to the outbound's address,
/// which it never resolves; a name without `ips` fails at start, as on
/// every other carrier.
#[test]
fn xicmp_to_a_named_server_needs_its_ips() {
    use serde_json::json;
    let refused = MasqueOutbound::new(&masque_with_masks(
        "masque.example",
        json!([{"type": "xicmp"}]),
    ));
    assert!(
        matches!(refused, Err(CoreError::UnsupportedOutboundNetwork)),
        "{refused:?}"
    );
    MasqueOutbound::new(&masque_with_masks(
        "masque.example",
        json!([{"type": "xicmp", "settings": {"ips": ["192.0.2.1"]}}]),
    ))
    .unwrap();
    MasqueOutbound::new(&masque_with_masks("192.0.2.1", json!([{"type": "xicmp"}]))).unwrap();
}
