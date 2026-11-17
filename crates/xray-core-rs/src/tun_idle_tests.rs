//! The TUN loop sleeps until something is due: with no flows, or only idle
//! ones, nothing wakes it.

use super::*;
use std::cell::Cell;
use std::net::SocketAddrV4;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::time::timeout;

thread_local! {
    /// Turns of the TUN loops running on this thread. A `#[tokio::test]`
    /// runtime runs its tasks on the test's own thread.
    static LOOP_TURNS: Cell<u64> = const { Cell::new(0) };
}

pub(super) fn count_loop_turn() {
    LOOP_TURNS.with(|turns| turns.set(turns.get() + 1));
}

fn loop_turns() -> u64 {
    LOOP_TURNS.with(Cell::get)
}

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 2);
const CLIENT_PORT: u16 = 49_152;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

async fn started_core(outbound: &str) -> crate::Core {
    let raw =
        format!(r#"{{"inbounds":[{{"tag":"tun-in","protocol":"tun"}}],"outbounds":[{outbound}]}}"#);
    let config = xray_config::parse_xray_json(&raw)
        .expect("TUN config parses")
        .config;
    let mut core = crate::Core::new(config).expect("core builds");
    core.start().await.expect("core starts");
    core
}

/// Hands each outbound TCP dial the next stream, so that a test sees the
/// other end of every connection and paused time sees no socket.
struct DuplexConnector(Mutex<Vec<DuplexStream>>);

#[async_trait::async_trait]
impl xray_transport::ResolvedTcpConnector for DuplexConnector {
    async fn connect_resolved(
        &self,
        _: &Target,
        _: &[SocketAddr],
        _: Option<&xray_transport::HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let stream = self.0.lock().unwrap().pop().ok_or_else(|| {
            TransportError::Tcp(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
        })?;
        Ok(Box::new(stream))
    }
}

/// A started core with a freedom outbound, whose first outbound TCP
/// connection is `stream`, and `extra` JSON fields.
async fn core_dialing(
    stream: DuplexStream,
    extra: &str,
    profile: TunRuntimeProfile,
) -> crate::Core {
    let raw = format!(
        r#"{{{extra}"inbounds":[{{"tag":"tun-in","protocol":"tun"}}],"outbounds":[{{"protocol":"freedom","tag":"direct"}}]}}"#
    );
    let config = xray_config::parse_xray_json(&raw)
        .expect("TUN config parses")
        .config;
    let dialer = TransportDialer::system()
        .expect("system dialer")
        .with_resolved_tcp_connector(Arc::new(DuplexConnector(Mutex::new(vec![stream]))));
    let mut core = crate::Core::with_transport_dialer_and_tun_options(
        config,
        Arc::new(dialer),
        TunRuntimeOptions {
            profile,
            ..Default::default()
        },
    )
    .expect("core builds");
    core.start().await.expect("core starts");
    core
}

#[test]
fn housekeeping_needs_no_timer_until_something_happens() {
    let start = TokioInstant::now();
    let mut housekeeping = TunHousekeeping::new(start);
    assert_eq!(housekeeping.next_run(false), None);
    assert!(!housekeeping.is_due(start));

    // Activity has the next turn see it, a second after the last one.
    housekeeping.record_activity();
    let next = start + TUN_FLOW_STATS_INTERVAL;
    assert_eq!(housekeeping.next_run(false), Some(next));
    assert!(housekeeping.is_due(next));

    // A turn that saw everything leaves nothing to wake for...
    housekeeping.ran(next, None);
    assert_eq!(housekeeping.next_run(false), None);
    // ...unless bytes wait in the TUN buffers, whose release wakes nothing.
    assert_eq!(
        housekeeping.next_run(true),
        Some(next + TUN_FLOW_STATS_INTERVAL)
    );
}

#[test]
fn housekeeping_wakes_for_the_earliest_expiry_it_left() {
    let start = TokioInstant::now();
    let mut housekeeping = TunHousekeeping::new(start);

    let linger = start + TUN_TCP_LINGER;
    housekeeping.ran(start, Some(linger));
    assert_eq!(housekeeping.next_run(false), Some(linger));

    // Never sooner than a turn may run.
    let soon = start + Duration::from_millis(10);
    housekeeping.ran(start, Some(soon));
    assert_eq!(
        housekeeping.next_run(false),
        Some(start + TUN_FLOW_STATS_INTERVAL)
    );
}

/// The measured cause of 45 to 50 wakeups a minute of an idle VPN: a
/// one-second statistics tick with nothing to count.
#[tokio::test(start_paused = true)]
async fn idle_tun_loop_is_never_woken() {
    let mut core = started_core(r#"{"protocol":"blackhole","tag":"block"}"#).await;
    let before = loop_turns();

    tokio::time::sleep(Duration::from_secs(600)).await;

    assert_eq!(loop_turns() - before, 0);
    // The statistics a turn would have recorded are there all the same.
    let stats = core.tun().stats().await;
    assert_eq!((stats.active_tcp_flows, stats.active_udp_flows), (0, 0));
    assert!(stats.udp_flow_limit > 0);
    core.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn udp_flow_is_evicted_when_idle_and_the_loop_then_sleeps() {
    let mut core = started_core(r#"{"protocol":"blackhole","tag":"block"}"#).await;
    let before = loop_turns();

    let packet = build_ipv4_udp_packet(
        CLIENT,
        CLIENT_PORT,
        Ipv4Addr::new(192, 0, 2, 10),
        9_999,
        b"datagram",
    )
    .unwrap();
    core.tun().push_inbound(packet).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(core.tun().stats().await.active_udp_flows, 1);

    tokio::time::sleep(UDP_IDLE_TIMEOUT - Duration::from_secs(1)).await;
    assert_eq!(core.tun().stats().await.active_udp_flows, 1);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        core.tun().stats().await.active_udp_flows,
        0,
        "the idle UDP flow was not evicted"
    );
    // The datagram, one turn to see it, the flow's end and one turn after
    // it, where a tick would have woken the loop sixty times.
    let woken = loop_turns() - before;
    assert!(woken <= 8, "the TUN loop woke {woken} times");

    let evicted = loop_turns();
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(loop_turns() - evicted, 0);
    core.stop().await.unwrap();
}

fn tcp_segment(
    server: SocketAddrV4,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Bytes {
    Bytes::from(super::tests::build_ipv4_tcp_packet(
        CLIENT,
        CLIENT_PORT,
        *server.ip(),
        server.port(),
        sequence,
        acknowledgement,
        flags,
        payload,
    ))
}

/// The flags, sequence number and payload of a TCP segment to the client.
fn received_segment(packet: &[u8]) -> Option<(u8, u32, Vec<u8>)> {
    if packet.len() < 40 || packet[0] != 0x45 || packet[9] != TCP_PROTOCOL {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let tcp = packet.get(20..total)?;
    if u16::from_be_bytes([tcp[2], tcp[3]]) != CLIENT_PORT {
        return None;
    }
    let header = usize::from(tcp[12] >> 4) * 4;
    let sequence = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    Some((tcp[13], sequence, tcp.get(header..)?.to_vec()))
}

/// Polls the TUN until a segment matches, and returns it.
async fn receive_segment(
    tun: &TunEndpoint,
    mut matches: impl FnMut(u8, &[u8]) -> bool,
) -> (u8, u32, Vec<u8>) {
    loop {
        let packet = tun.poll_outbound().await.unwrap();
        if let Some((flags, sequence, payload)) = received_segment(&packet) {
            if matches(flags, &payload) {
                return (flags, sequence, payload);
            }
        }
    }
}

/// An established TCP flow nobody uses wakes the loop no more than no flow
/// does; smoltcp's own timers and the flow's next segment still do.
#[tokio::test]
async fn idle_tcp_flow_leaves_the_loop_asleep_until_its_next_segment() {
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let SocketAddr::V4(server) = echo.local_addr().unwrap() else {
        unreachable!("bound to IPv4");
    };
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut buffer = [0; 64];
        loop {
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                return;
            }
        }
    });
    let mut core = started_core(r#"{"protocol":"freedom","tag":"direct"}"#).await;
    let tun = core.tun();

    timeout(Duration::from_secs(10), async {
        let mut sequence = 1_000u32;
        tun.push_inbound(tcp_segment(server, sequence, 0, TCP_SYN, &[]))
            .await
            .unwrap();
        sequence += 1;
        let (_, server_syn, _) = receive_segment(tun, |flags, _| {
            flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK
        })
        .await;
        // The retransmission timer of the SYN-ACK, a second away, drives
        // the stack with no tick to run it.
        let (_, retransmitted, _) = receive_segment(tun, |flags, _| flags & TCP_SYN != 0).await;
        assert_eq!(retransmitted, server_syn);
        let mut acknowledged = server_syn.wrapping_add(1);
        tun.push_inbound(tcp_segment(server, sequence, acknowledged, TCP_ACK, &[]))
            .await
            .unwrap();

        for payload in [&b"ping"[..], b"pong"] {
            tun.push_inbound(tcp_segment(
                server,
                sequence,
                acknowledged,
                TCP_PSH | TCP_ACK,
                payload,
            ))
            .await
            .unwrap();
            sequence += payload.len() as u32;
            let (_, echoed_at, echoed) =
                receive_segment(tun, |flags, data| flags & TCP_FIN == 0 && !data.is_empty()).await;
            assert_eq!(echoed, payload);
            acknowledged = echoed_at.wrapping_add(payload.len() as u32);
            tun.push_inbound(tcp_segment(server, sequence, acknowledged, TCP_ACK, &[]))
                .await
                .unwrap();
            if payload == b"pong" {
                break;
            }

            // A turn follows the last activity within a second; after it
            // the established flow wakes nothing, where a tick woke the loop
            // every second.
            tokio::time::sleep(Duration::from_millis(2_000)).await;
            let settled = loop_turns();
            tokio::time::sleep(Duration::from_millis(2_500)).await;
            assert_eq!(loop_turns() - settled, 0, "an idle TCP flow woke the loop");
            assert_eq!(tun.stats().await.active_tcp_flows, 1);
        }
    })
    .await
    .expect("the TCP flow works across an idle loop");

    core.stop().await.unwrap();
    echo_task.abort();
}

/// Opens a TCP flow from the app to `server`. Returns the app's next
/// sequence number and the stack's, which the app acknowledged.
async fn open_tcp_flow(tun: &TunEndpoint, server: SocketAddrV4) -> (u32, u32) {
    let sequence = 1_000u32;
    tun.push_inbound(tcp_segment(server, sequence, 0, TCP_SYN, &[]))
        .await
        .unwrap();
    let (_, server_syn, _) = receive_segment(tun, |flags, _| {
        flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK
    })
    .await;
    let acknowledged = server_syn.wrapping_add(1);
    tun.push_inbound(tcp_segment(
        server,
        sequence + 1,
        acknowledged,
        TCP_ACK,
        &[],
    ))
    .await
    .unwrap();
    (sequence + 1, acknowledged)
}

/// Takes every packet the TUN holds for the app; true if a reset was among
/// them.
async fn drain_reset(tun: &TunEndpoint) -> bool {
    let mut reset = false;
    while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
        reset |= received_segment(&packet).is_some_and(|(flags, _, _)| flags & TCP_RST != 0);
    }
    reset
}

/// A flow the remote closed and the app keeps half open in FIN-WAIT-2 has
/// nothing but the close-wait deadline to end it: with no other input, the
/// loop sleeps through the linger and wakes at its end to reset the flow.
#[tokio::test]
async fn fin_wait_2_flow_is_reset_at_the_linger_with_no_other_input() {
    let (stream, peer) = tokio::io::duplex(1_024);
    let mut core = core_dialing(stream, "", TunRuntimeProfile::Default).await;
    let tun = core.tun();
    let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 20), 443);

    // In real time: smoltcp's timers run on the system clock.
    timeout(Duration::from_secs(10), async {
        let (sequence, _) = open_tcp_flow(tun, server).await;
        // The remote closes. The stack sends its FIN, and the app
        // acknowledges it without closing its own side.
        drop(peer);
        let (_, fin, _) = receive_segment(tun, |flags, _| flags & TCP_FIN != 0).await;
        tun.push_inbound(tcp_segment(
            server,
            sequence,
            fin.wrapping_add(1),
            TCP_ACK,
            &[],
        ))
        .await
        .unwrap();
    })
    .await
    .expect("the flow reaches FIN-WAIT-2");

    // Nothing else happens from here on.
    tokio::time::pause();
    let start = TokioInstant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let settled = loop_turns();
    tokio::time::sleep_until(start + TUN_TCP_LINGER - Duration::from_secs(1)).await;
    assert_eq!(loop_turns() - settled, 0, "the loop woke during the linger");
    assert!(
        !drain_reset(tun).await,
        "the flow was reset before the linger ran out"
    );
    assert_eq!(tun.stats().await.active_tcp_flows, 1);

    // The turn that saw FIN-WAIT-2 ran within a second of the app's ACK.
    tokio::time::sleep_until(start + TUN_TCP_LINGER + Duration::from_secs(2)).await;
    assert!(
        drain_reset(tun).await,
        "the app was not told the flow is gone"
    );
    assert_eq!(tun.stats().await.active_tcp_flows, 0);
    core.stop().await.unwrap();
}

/// Upload bytes waiting for their outbound show in the statistics, and their
/// release by the outbound wakes nothing: the loop looks every second while
/// bytes wait, records them gone, and then sleeps.
#[tokio::test]
async fn released_upload_bytes_leave_the_statistics_with_no_other_input() {
    let (stream, mut peer) = tokio::io::duplex(32);
    let mut core = core_dialing(stream, "", TunRuntimeProfile::Default).await;
    let tun = core.tun();
    let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 21), 443);
    let upload = [0x55; 1_000];

    timeout(Duration::from_secs(10), async {
        let (sequence, acknowledged) = open_tcp_flow(tun, server).await;
        tun.push_inbound(tcp_segment(
            server,
            sequence,
            acknowledged,
            TCP_PSH | TCP_ACK,
            &upload,
        ))
        .await
        .unwrap();
        // The stack acknowledges the bytes, so that no smoltcp timer is left,
        // and the outbound takes what fits its 32-byte pipe.
        receive_segment(tun, |flags, data| flags & TCP_ACK != 0 && data.is_empty()).await;
        let mut first = [0; 32];
        peer.read_exact(&mut first).await.unwrap();
    })
    .await
    .expect("the upload reaches the outbound");

    tokio::time::pause();
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(
        tun.stats().await.tcp_pending_upload_bytes > 0,
        "the waiting bytes did not reach the statistics"
    );

    // The outbound takes the rest, which tells the loop nothing.
    let mut rest = [0; 1_000 - 32];
    peer.read_exact(&mut rest).await.unwrap();
    tokio::time::sleep(TUN_FLOW_STATS_INTERVAL + Duration::from_millis(100)).await;
    assert_eq!(
        tun.stats().await.tcp_pending_upload_bytes,
        0,
        "the released bytes stayed in the statistics"
    );

    let settled = loop_turns();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(loop_turns() - settled, 0, "the loop kept looking");
    core.stop().await.unwrap();
}

/// A DNS query for the HTTPS records (type 65) of `name`. The TUN relays it
/// through its DNS-over-TCP pool; A and AAAA go to the core's resolver.
fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 65, 0, 1]);
    query
}

/// A DNS-over-TCP connection the pool keeps idle has nothing but its expiry
/// to close it: with no other input, the loop sleeps until then.
#[tokio::test(start_paused = true)]
async fn pooled_dns_connection_is_closed_at_its_expiry_with_no_other_input() {
    // The pool's idle TTL of the low-memory profile.
    const IDLE_TTL: Duration = Duration::from_secs(15);
    let (stream, mut upstream) = tokio::io::duplex(1_024);
    let mut core = core_dialing(
        stream,
        r#""dns":{"servers":["tcp+local://192.0.2.53"]},"#,
        TunRuntimeProfile::LowMemory,
    )
    .await;
    let upstream = tokio::spawn(async move {
        let len = upstream.read_u16().await.unwrap();
        let mut message = vec![0; usize::from(len)];
        upstream.read_exact(&mut message).await.unwrap();
        message[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        upstream.write_u16(len).await.unwrap();
        upstream.write_all(&message).await.unwrap();
        // The pool keeps the connection open until it expires.
        let mut more = [0; 1];
        assert_eq!(upstream.read(&mut more).await.unwrap(), 0);
        TokioInstant::now()
    });

    let query = dns_query(0x5151, "pool.example");
    let packet = build_ipv4_udp_packet(CLIENT, CLIENT_PORT, TUN_DNS_ANCHOR, 53, &query).unwrap();
    core.tun().push_inbound(packet).await.unwrap();
    let reply = core.tun().poll_outbound().await.unwrap();
    assert_eq!(reply.get(28..30), Some(&query[..2]), "not the DNS answer");
    let answered = TokioInstant::now();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let settled = loop_turns();
    tokio::time::sleep_until(answered + IDLE_TTL - Duration::from_secs(1)).await;
    assert_eq!(
        loop_turns() - settled,
        0,
        "the loop woke while the connection idled"
    );
    assert!(
        !upstream.is_finished(),
        "the connection closed before it expired"
    );

    let closed = timeout(Duration::from_secs(5), upstream)
        .await
        .expect("the pool did not close its expired connection")
        .unwrap();
    assert!(
        closed <= answered + IDLE_TTL + TUN_FLOW_STATS_INTERVAL,
        "closed {:?} after the answer",
        closed - answered
    );
    core.stop().await.unwrap();
}
