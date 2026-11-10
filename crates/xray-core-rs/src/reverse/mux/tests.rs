use super::*;
use tokio::io::{duplex, DuplexStream};
use xray_proxy::reverse::{encode_control, ControlState};

/// A portal's frame, as Xray-core's Mux client writes it.
struct PortalFrame<'a> {
    id: u16,
    status: Status,
    target: Option<Target>,
    source: Option<Target>,
    local: Option<Target>,
    payload: Option<&'a [u8]>,
}

fn endpoint_bytes(target: &Target, out: &mut Vec<u8>) {
    out.push(match target.network {
        Network::Tcp => 1,
        Network::Udp => 2,
    });
    out.extend(target.port.to_be_bytes());
    match &target.addr {
        TargetAddr::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(3);
            out.extend(ip.octets());
        }
        TargetAddr::Domain(name) => {
            out.extend([2, name.len() as u8]);
            out.extend(name.as_bytes());
        }
    }
}

fn portal_frame(frame: PortalFrame<'_>) -> Vec<u8> {
    let mut meta = frame.id.to_be_bytes().to_vec();
    meta.push(frame.status as u8);
    meta.push(u8::from(frame.payload.is_some()));
    if let Some(target) = &frame.target {
        endpoint_bytes(target, &mut meta);
    }
    if let Some(source) = &frame.source {
        endpoint_bytes(source, &mut meta);
    }
    if let Some(local) = &frame.local {
        endpoint_bytes(local, &mut meta);
    }
    let mut wire = (meta.len() as u16).to_be_bytes().to_vec();
    wire.extend(meta);
    if let Some(payload) = frame.payload {
        wire.extend((payload.len() as u16).to_be_bytes());
        wire.extend(payload);
    }
    wire
}

/// Fails a test that would otherwise hang on a regression.
async fn within<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("timed out")
}

fn tcp(addr: &str, port: u16) -> Target {
    Target::new(TargetAddr::Ip(addr.parse().unwrap()), port, Network::Tcp)
}

fn udp(addr: &str, port: u16) -> Target {
    Target::new(TargetAddr::Ip(addr.parse().unwrap()), port, Network::Udp)
}

fn control_target() -> Target {
    Target::new(TargetAddr::Domain("reverse".into()), 0, Network::Udp)
}

fn new_frame(id: u16, target: Target, payload: Option<&[u8]>) -> Vec<u8> {
    portal_frame(PortalFrame {
        id,
        status: Status::New,
        target: Some(target),
        source: Some(tcp("198.51.100.7", 40000)),
        local: Some(tcp("203.0.113.1", 443)),
        payload,
    })
}

fn keep(id: u16, address: Option<Target>, payload: &[u8]) -> Vec<u8> {
    portal_frame(PortalFrame {
        id,
        status: Status::Keep,
        target: address,
        source: None,
        local: None,
        payload: Some(payload),
    })
}

fn end(id: u16) -> Vec<u8> {
    portal_frame(PortalFrame {
        id,
        status: Status::End,
        target: None,
        source: None,
        local: None,
        payload: None,
    })
}

/// A bridge's reverse Mux server on one end of an in-memory tunnel, the
/// portal's end returned.
struct Harness {
    shared: Arc<Shared>,
    tunnel: Arc<TunnelState>,
    portal: DuplexStream,
    opened: mpsc::Receiver<NewSession>,
    tasks: tokio::task::JoinSet<()>,
    buffer: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        let tunnel = Arc::new(TunnelState::default());
        let shared = Shared::new(Arc::clone(&tunnel));
        let (bridge, portal) = duplex(1 << 20);
        let (read, write) = tokio::io::split(bridge);
        let (sessions, opened) = mpsc::channel(64);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn({
            let shared = Arc::clone(&shared);
            async move {
                let _ = read_loop(shared, read, sessions).await;
            }
        });
        tasks.spawn({
            let shared = Arc::clone(&shared);
            async move {
                let _ = write_loop(shared, write).await;
            }
        });
        Self {
            shared,
            tunnel,
            portal,
            opened,
            tasks,
            buffer: Vec::new(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.portal.write_all(bytes).await.unwrap();
    }

    async fn opened(&mut self) -> NewSession {
        tokio::time::timeout(Duration::from_secs(5), self.opened.recv())
            .await
            .expect("a session opens")
            .expect("the reader runs")
    }

    /// The next frame the bridge sent, decoded as the portal's client
    /// worker reads it.
    async fn frame(&mut self) -> (u16, Status, bool, Option<Target>, Vec<u8>) {
        loop {
            if let Some((frame, n)) = wire::decode(&self.buffer).unwrap() {
                let decoded = (
                    frame.session_id,
                    frame.status,
                    frame.error,
                    frame.target.clone(),
                    frame.payload.unwrap_or_default().to_vec(),
                );
                self.buffer.drain(..n);
                return decoded;
            }
            let mut chunk = [0; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), self.portal.read(&mut chunk))
                .await
                .expect("the bridge sends a frame")
                .unwrap();
            assert_ne!(n, 0, "the bridge closed the tunnel");
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }

    fn held(&self) -> usize {
        self.tunnel.sessions()
    }
}

#[tokio::test]
async fn a_stream_session_carries_both_ways_and_ends_with_the_bridge() {
    let mut harness = Harness::new();
    harness
        .send(&new_frame(1, tcp("127.0.0.1", 8080), Some(b"GET /")))
        .await;
    let new = harness.opened().await;
    assert_eq!(new.target, tcp("127.0.0.1", 8080));
    assert_eq!(new.source, Some("198.51.100.7:40000".parse().unwrap()));
    assert_eq!(new.local, Some("203.0.113.1:443".parse().unwrap()));
    let mut session = new.session;
    harness.send(&keep(1, None, b" HTTP/1.1")).await;
    let mut read = [0; 64];
    let n = within(session.read(&mut read)).await.unwrap();
    assert_eq!(&read[..n], b"GET /");
    let n = within(session.read(&mut read)).await.unwrap();
    assert_eq!(&read[..n], b" HTTP/1.1");

    // A long answer goes in frames of at most 8 KiB.
    let answer = vec![7; wire::MAX_PAYLOAD + 10];
    session.write_all(&answer).await.unwrap();
    session.shutdown().await.unwrap();
    let mut received = Vec::new();
    loop {
        let (id, status, error, target, payload) = harness.frame().await;
        assert_eq!(id, 1);
        match status {
            Status::Keep => {
                assert!(target.is_none());
                assert!(payload.len() <= wire::MAX_PAYLOAD);
                received.extend(payload);
            }
            Status::End => {
                assert!(!error);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(received, answer);
    // Its End sent, the bridge reads nothing more on it.
    assert_eq!(within(session.read(&mut read)).await.unwrap(), 0);
    drop(session);
    tokio::task::yield_now().await;
    assert_eq!(harness.held(), 0);
}

#[tokio::test]
async fn the_portals_end_ends_the_session_both_ways() {
    let mut harness = Harness::new();
    harness
        .send(&new_frame(3, tcp("127.0.0.1", 22), None))
        .await;
    let mut session = harness.opened().await.session;
    harness.send(&keep(3, None, b"left over")).await;
    harness.send(&end(3)).await;
    let mut read = [0; 64];
    let n = within(session.read(&mut read)).await.unwrap();
    assert_eq!(&read[..n], b"left over");
    assert_eq!(within(session.read(&mut read)).await.unwrap(), 0);
    assert!(within(session.write_all(b"too late")).await.is_err());
    drop(session);
    tokio::task::yield_now().await;
    assert_eq!(harness.held(), 0);
}

#[tokio::test]
async fn a_dropped_session_ends_with_the_error_flag() {
    let mut harness = Harness::new();
    harness
        .send(&new_frame(5, tcp("127.0.0.1", 22), None))
        .await;
    let session = harness.opened().await.session;
    drop(session);
    let (id, status, error, _, _) = harness.frame().await;
    assert_eq!((id, status, error), (5, Status::End, true));

    harness
        .send(&new_frame(6, tcp("127.0.0.1", 22), None))
        .await;
    let session = harness.opened().await.session;
    session.finish(true);
    let (id, status, error, _, _) = harness.frame().await;
    assert_eq!((id, status, error), (6, Status::End, true));
}

#[tokio::test]
async fn data_for_an_unknown_session_gets_an_end() {
    let mut harness = Harness::new();
    harness.send(&keep(9, None, b"stray")).await;
    let (id, status, error, _, _) = harness.frame().await;
    assert_eq!((id, status, error), (9, Status::End, false));
    // An End or keepalive for it needs no answer, and the tunnel goes on.
    harness.send(&end(9)).await;
    harness
        .send(&new_frame(10, tcp("127.0.0.1", 22), None))
        .await;
    assert_eq!(harness.opened().await.target, tcp("127.0.0.1", 22));
}

#[tokio::test]
async fn a_datagram_session_keeps_each_address() {
    let mut harness = Harness::new();
    harness
        .send(&new_frame(2, udp("127.0.0.1", 53), Some(b"first")))
        .await;
    let session = harness.opened().await.session;
    harness
        .send(&keep(2, Some(udp("192.0.2.9", 5353)), b"second"))
        .await;
    harness.send(&keep(2, None, b"third")).await;
    assert_eq!(
        within(session.recv_datagram()).await,
        Some((None, Bytes::from_static(b"first")))
    );
    assert_eq!(
        within(session.recv_datagram()).await,
        Some((Some(udp("192.0.2.9", 5353)), Bytes::from_static(b"second")))
    );
    assert_eq!(
        within(session.recv_datagram()).await,
        Some((None, Bytes::from_static(b"third")))
    );

    session
        .send_datagram(&udp("192.0.2.9", 5353), b"answer")
        .await
        .unwrap();
    let (id, status, _, target, payload) = harness.frame().await;
    assert_eq!((id, status), (2, Status::Keep));
    assert_eq!(target, Some(udp("192.0.2.9", 5353)));
    assert_eq!(payload, b"answer");
    assert!(session
        .send_datagram(&udp("192.0.2.9", 5353), &[0; wire::MAX_PAYLOAD + 1])
        .await
        .is_err());

    harness.send(&end(2)).await;
    assert_eq!(within(session.recv_datagram()).await, None);
    assert!(session
        .send_datagram(&udp("192.0.2.9", 5353), b"late")
        .await
        .is_err());
}

#[tokio::test]
async fn the_control_session_drains_the_tunnel_and_is_never_answered() {
    let mut harness = Harness::new();
    harness.send(&new_frame(1, control_target(), None)).await;
    harness
        .send(&keep(
            1,
            None,
            &encode_control(ControlState::Active, &[1; 9]),
        ))
        .await;
    // The control session is held but never handed out.
    harness
        .send(&new_frame(2, tcp("127.0.0.1", 22), None))
        .await;
    let _session = harness.opened().await;
    assert_eq!(harness.held(), 2);
    assert!(harness.tunnel.is_active());
    harness
        .send(&keep(
            1,
            None,
            &encode_control(ControlState::Drain, &[2; 64]),
        ))
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while harness.tunnel.is_active() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the tunnel drains");
    harness.send(&end(1)).await;
    harness
        .send(&new_frame(3, tcp("127.0.0.1", 22), None))
        .await;
    let _third = harness.opened().await;
    assert_eq!(harness.held(), 2);
}

#[tokio::test]
async fn a_control_message_that_does_not_parse_stops_the_reading() {
    let mut harness = Harness::new();
    harness
        .send(&new_frame(1, control_target(), Some(&[0x08])))
        .await;
    harness
        .send(&keep(1, None, &encode_control(ControlState::Drain, &[])))
        .await;
    harness
        .send(&new_frame(2, tcp("127.0.0.1", 22), None))
        .await;
    let _session = harness.opened().await;
    assert!(harness.tunnel.is_active());
}

#[tokio::test]
async fn a_session_past_the_bound_is_refused_and_a_reused_id_fails_the_tunnel() {
    let mut harness = Harness::new();
    let mut sessions = Vec::new();
    for id in 1..=MAX_SESSIONS as u16 {
        harness
            .send(&new_frame(id, tcp("127.0.0.1", 22), None))
            .await;
        sessions.push(harness.opened().await);
    }
    let refused = MAX_SESSIONS as u16 + 1;
    harness
        .send(&new_frame(refused, tcp("127.0.0.1", 22), Some(b"x")))
        .await;
    let (id, status, error, _, _) = harness.frame().await;
    assert_eq!((id, status, error), (refused, Status::End, true));
    assert_eq!(harness.held(), MAX_SESSIONS);

    harness
        .send(&new_frame(1, tcp("127.0.0.1", 22), None))
        .await;
    let joined = tokio::time::timeout(Duration::from_secs(5), harness.tasks.join_next())
        .await
        .expect("the reader stops");
    assert!(joined.is_some());
}

#[tokio::test]
async fn a_full_session_pauses_the_reader_without_losing_frames() {
    let mut harness = Harness::new();
    harness
        .send(&new_frame(1, tcp("127.0.0.1", 22), None))
        .await;
    let mut slow = harness.opened().await.session;
    for index in 0..SESSION_QUEUE + 4 {
        harness.send(&keep(1, None, &[index as u8; 100])).await;
    }
    // Queued behind the slow session's frames.
    harness
        .send(&new_frame(2, tcp("127.0.0.1", 23), None))
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(harness.opened.try_recv().is_err(), "the reader waits");
    let mut received = Vec::new();
    while received.len() < (SESSION_QUEUE + 4) * 100 {
        let mut read = [0; 1000];
        let n = within(slow.read(&mut read)).await.unwrap();
        received.extend_from_slice(&read[..n]);
    }
    for (index, chunk) in received.chunks(100).enumerate() {
        assert!(chunk.iter().all(|&b| b == index as u8));
    }
    assert_eq!(harness.opened().await.target, tcp("127.0.0.1", 23));
}

#[tokio::test(start_paused = true)]
async fn an_idle_tunnel_closes_after_a_whole_check() {
    let tunnel = Arc::new(TunnelState::default());
    let shared = Shared::new(tunnel);
    let idle = tokio::spawn(idle_loop(Arc::clone(&shared)));
    tokio::time::sleep(IDLE_CHECK + Duration::from_secs(1)).await;
    assert!(idle.is_finished());

    // A session opened and closed within the check keeps it open.
    let tunnel = Arc::new(TunnelState::default());
    let shared = Shared::new(tunnel);
    let idle = tokio::spawn(idle_loop(Arc::clone(&shared)));
    tokio::time::sleep(Duration::from_secs(30)).await;
    lock(&shared.state).opened += 1;
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert!(!idle.is_finished());
    tokio::time::sleep(IDLE_CHECK).await;
    assert!(idle.is_finished());
}

#[tokio::test(start_paused = true)]
async fn a_silent_tunnel_ends_after_conn_idle() {
    let shared = Shared::new(Arc::new(TunnelState::default()));
    let inactive = tokio::spawn(inactivity_loop(
        Arc::clone(&shared),
        Duration::from_secs(300),
    ));
    tokio::time::sleep(Duration::from_secs(200)).await;
    shared.touch();
    tokio::time::sleep(Duration::from_secs(200)).await;
    assert!(!inactive.is_finished());
    tokio::time::sleep(Duration::from_secs(101)).await;
    assert!(inactive.is_finished());
}

#[tokio::test]
async fn closing_fails_every_session() {
    let mut harness = Harness::new();
    harness
        .send(&new_frame(1, tcp("127.0.0.1", 22), None))
        .await;
    let mut session = harness.opened().await.session;
    harness.shared.close();
    let mut read = [0; 8];
    assert!(within(session.read(&mut read)).await.is_err());
    assert!(within(session.write_all(b"x")).await.is_err());
}

#[tokio::test]
async fn reads_and_writes_count_as_activity() {
    let mut harness = Harness::new();
    let start = *lock(&harness.shared.activity);
    tokio::time::sleep(Duration::from_millis(20)).await;
    harness
        .send(&new_frame(1, tcp("127.0.0.1", 22), None))
        .await;
    let session = harness.opened().await.session;
    let read = *lock(&harness.shared.activity);
    assert!(read > start, "a read counts");
    tokio::time::sleep(Duration::from_millis(20)).await;
    session.finish(false);
    let _ = harness.frame().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(*lock(&harness.shared.activity) > read, "a write counts");
}

/// A portal that floods frames for sessions the bridge does not hold and
/// reads none of the Ends it gets back: the tunnel fails once they back up.
#[tokio::test]
async fn ends_the_portal_never_reads_fail_the_tunnel() {
    let mut harness = Harness::new();
    let flood = keep(9, None, b"x").repeat(400_000);
    let Harness { portal, tasks, .. } = &mut harness;
    let stopped = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::select! {
            joined = tasks.join_next() => joined,
            _ = async {
                let _ = portal.write_all(&flood).await;
                std::future::pending::<()>().await
            } => unreachable!(),
        }
    })
    .await
    .expect("the reader stops");
    assert!(stopped.is_some());
}
