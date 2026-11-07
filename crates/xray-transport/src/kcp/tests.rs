//! The stream and its driver over loopback, against a peer built from the
//! same engine that echoes what it reads.
use super::*;
use segment::{read_segments, Segment, CMD_TERMINATE, OPTION_CLOSE};
use std::sync::Mutex as StdMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(masks: Vec<KcpMask>) -> KcpConfig {
    KcpConfig {
        mtu: 1350,
        tti: 20,
        uplink_capacity: 5,
        downlink_capacity: 20,
        cwnd_multiplier: 1,
        max_sending_window: 2 * 1024 * 1024,
        masks,
        noise: None,
    }
}

/// What the echo peer saw, datagram by datagram, after its masks.
#[derive(Default)]
struct Seen {
    raw: Vec<Vec<u8>>,
    segments: Vec<Segment>,
}

/// An echo peer on loopback: one engine for the first conversation.
async fn echo_peer(masks: Vec<KcpMask>) -> (SocketAddr, Arc<StdMutex<Seen>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let seen = Arc::new(StdMutex::new(Seen::default()));
    let record = Arc::clone(&seen);
    let mut masks = Masks::new(&masks, None).unwrap();
    tokio::spawn(async move {
        let since = Instant::now();
        let mut engine: Option<Engine> = None;
        let mut client = None;
        let mut buf = vec![0; 8192];
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                received = socket.recv_from(&mut buf) => {
                    let Ok((length, from)) = received else { return };
                    client = Some(from);
                    let datagram = &mut buf[..length];
                    record.lock().unwrap().raw.push(datagram.to_vec());
                    let Some(range) = masks.open(datagram, from, Instant::now()) else { continue };
                    let segments = read_segments(&datagram[range]);
                    let Some(first) = segments.first() else { continue };
                    record.lock().unwrap().segments.extend(segments.iter().cloned());
                    let engine = engine.get_or_insert_with(|| {
                        Engine::new(first.conv(), config(Vec::new()).engine_config().unwrap())
                    });
                    engine.input(segments, elapsed(since));
                    let mut data = [0; 8192];
                    while let Some(count) = engine.read(&mut data).filter(|count| *count > 0) {
                        let _ = engine.write(&data[..count]);
                    }
                }
                _ = tick.tick() => {}
            }
            if let (Some(engine), Some(client)) = (engine.as_mut(), client) {
                engine.flush(elapsed(since));
                for datagram in std::mem::take(&mut engine.out) {
                    masks.start(datagram);
                    while let Some(action) = masks.next(Instant::now(), Some(address), client) {
                        if let Action::Send(datagram) = action {
                            let _ = socket.send_to(&datagram, client).await;
                        }
                    }
                }
            }
        }
    });
    (address, seen)
}

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("timed out")
}

async fn eventually(seen: &StdMutex<Seen>, check: impl Fn(&Seen) -> bool) {
    within(async {
        while !check(&seen.lock().unwrap()) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn bytes_come_back_from_an_echo_peer() {
    let (peer, seen) = echo_peer(Vec::new()).await;
    let mut stream = connect(&[peer], None, &config(Vec::new())).await.unwrap();
    let message: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = tokio::io::split(&mut stream);
    let writer = async {
        write.write_all(&message).await.unwrap();
        write.flush().await.unwrap();
    };
    let reader = async {
        let mut echoed = vec![0; message.len()];
        read.read_exact(&mut echoed).await.unwrap();
        echoed
    };
    let ((), echoed) = within(async { tokio::join!(writer, reader) }).await;
    assert_eq!(echoed, message);
    // Every segment carried this connection's conversation.
    let seen = seen.lock().unwrap();
    let conv = seen.segments[0].conv();
    assert!(seen.segments.iter().all(|segment| segment.conv() == conv));
}

#[tokio::test]
async fn nothing_goes_out_until_the_first_write() {
    let (peer, seen) = echo_peer(Vec::new()).await;
    let mut stream = connect(&[peer], None, &config(Vec::new())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(seen.lock().unwrap().raw.is_empty());
    stream.write_all(b"now").await.unwrap();
    eventually(&seen, |seen| !seen.raw.is_empty()).await;
}

#[tokio::test]
async fn masked_bytes_come_back_and_the_wire_carries_the_masks() {
    let masks = vec![
        KcpMask::Aes128Gcm("seed".to_owned().into()),
        KcpMask::Header(KcpHeader::Wechat),
    ];
    let (peer, seen) = echo_peer(masks.clone()).await;
    let mut stream = connect(&[peer], None, &config(masks)).await.unwrap();
    stream.write_all(b"masked").await.unwrap();
    let mut echoed = [0; 6];
    within(stream.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"masked");
    let seen = seen.lock().unwrap();
    // WeChat's header leads; the segments under it are encrypted.
    assert!(seen
        .raw
        .iter()
        .all(|datagram| datagram[..2] == [0xa1, 0x08]));
    assert!(!seen
        .raw
        .iter()
        .any(|datagram| datagram.windows(6).any(|window| window == b"masked")));
}

#[tokio::test]
async fn dropping_the_stream_closes_then_terminates() {
    let (peer, seen) = echo_peer(Vec::new()).await;
    let mut stream = connect(&[peer], None, &config(Vec::new())).await.unwrap();
    stream.write_all(b"bye").await.unwrap();
    let mut echoed = [0; 3];
    within(stream.read_exact(&mut echoed)).await.unwrap();
    stream.write_all(b"last").await.unwrap();
    drop(stream);
    // The data still in flight carries the close flag, and once the peer
    // acknowledges it a terminate follows.
    eventually(&seen, |seen| {
        seen.segments.iter().any(|segment| match segment {
            Segment::Data(data) => data.option == OPTION_CLOSE,
            _ => false,
        })
    })
    .await;
    eventually(&seen, |seen| {
        seen.segments
            .iter()
            .any(|segment| matches!(segment, Segment::Cmd(cmd) if cmd.cmd == CMD_TERMINATE))
    })
    .await;
}

#[tokio::test]
async fn noise_goes_out_ahead_of_the_first_segment() {
    let (peer, seen) = echo_peer(Vec::new()).await;
    let mut config = config(vec![KcpMask::Noise]);
    config.noise = Some(UdpNoiseConfig {
        items: vec![crate::udp_noise::UdpNoiseItem {
            packet: b"noise!".to_vec(),
            random_length: crate::udp_noise::NoiseRange { from: 0, to: 0 },
            random_bytes: crate::udp_noise::NoiseRange { from: 0, to: 0 },
            delay_ms: crate::udp_noise::NoiseRange { from: 30, to: 30 },
        }],
        reset_secs: crate::udp_noise::NoiseRange { from: 0, to: 0 },
        before_salamander: false,
    });
    let mut stream = connect(&[peer], None, &config).await.unwrap();
    stream.write_all(b"after the noise").await.unwrap();
    let mut echoed = [0; 15];
    within(stream.read_exact(&mut echoed)).await.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.raw[0], b"noise!");
    assert!(seen.raw[1..].iter().all(|datagram| datagram != b"noise!"));
}

#[tokio::test]
async fn a_closed_peer_refuses_writes_and_ends_reads() {
    // A peer that answers the first segment with a terminate.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let mut stream = connect(&[peer], None, &config(Vec::new())).await.unwrap();
    stream.write_all(b"hello?").await.unwrap();
    let mut buf = [0; 2048];
    let (length, from) = within(socket.recv_from(&mut buf)).await.unwrap();
    let conv = read_segments(&buf[..length])[0].conv();
    let mut terminate = Vec::new();
    segment::CmdSegment {
        conv,
        cmd: CMD_TERMINATE,
        option: 0,
        sending_next: 0,
        receiving_next: 0,
        peer_rto: 0,
    }
    .encode(&mut terminate);
    socket.send_to(&terminate, from).await.unwrap();
    let mut read = [0; 8];
    assert_eq!(within(stream.read(&mut read)).await.unwrap(), 0);
    let error = stream.write(b"more").await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn a_settings_error_or_no_address_fails_the_dial() {
    let mut bad = config(Vec::new());
    bad.mtu = 20;
    assert!(matches!(
        connect(&["127.0.0.1:1".parse().unwrap()], None, &bad).await,
        Err(TransportError::Kcp(_))
    ));
    assert!(matches!(
        connect(&[], None, &config(Vec::new())).await,
        Err(TransportError::Kcp(_))
    ));
    let long_label = KcpMask::Header(KcpHeader::Dns(format!("{}.b", "a".repeat(64))));
    assert!(matches!(
        connect(
            &["127.0.0.1:1".parse().unwrap()],
            None,
            &config(vec![long_label])
        )
        .await,
        Err(TransportError::Kcp(_))
    ));
}

#[tokio::test]
async fn the_socket_is_protected_before_it_sends() {
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);
    impl crate::SocketProtector for Counting {
        fn protect(&self, _: crate::SocketHandle) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (peer, _) = echo_peer(Vec::new()).await;
    let counting = Counting::default();
    let _stream = connect(&[peer], Some(&counting), &config(Vec::new()))
        .await
        .unwrap();
    assert_eq!(counting.0.load(Ordering::SeqCst), 1);
    // A protector that fails stops the dial.
    struct Refusing;
    impl crate::SocketProtector for Refusing {
        fn protect(&self, _: crate::SocketHandle) -> io::Result<()> {
            Err(io::Error::other("refused"))
        }
    }
    assert!(matches!(
        connect(&[peer], Some(&Refusing), &config(Vec::new())).await,
        Err(TransportError::SocketProtection(_))
    ));
}

/// A peer that floods the client and never acknowledges still sees its
/// segment resent: the timers do not wait for the socket to fall quiet.
#[tokio::test]
async fn resends_go_out_while_datagrams_keep_arriving() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let mut stream = connect(&[peer], None, &config(Vec::new())).await.unwrap();
    stream.write_all(b"resend me").await.unwrap();
    let mut buf = [0; 2048];
    let (_, client) = within(socket.recv_from(&mut buf)).await.unwrap();
    let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut foreign = Vec::new();
    segment::CmdSegment {
        conv: 0,
        cmd: segment::CMD_PING,
        option: 0,
        sending_next: 0,
        receiving_next: 0,
        peer_rto: 0,
    }
    .encode(&mut foreign);
    let flooding = tokio::spawn(async move {
        loop {
            let _ = flood.send_to(&foreign, client).await;
        }
    });
    let mut resent = 0;
    let deadline = Instant::now() + Duration::from_millis(600);
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
    {
        resent += read_segments(&buf[..length])
            .iter()
            .filter(|segment| matches!(segment, Segment::Data(_)))
            .count();
    }
    flooding.abort();
    // The rto stays at 100 ms without an ack.
    assert!(resent >= 3, "{resent} resends");
}

#[test]
fn conversations_count_up_from_the_drawn_number() {
    let counter = AtomicU32::new(0xfffe);
    assert_eq!(count_up(&counter), 0xffff);
    // A Go uint32 counter truncated to 16 bits wraps to zero.
    assert_eq!(count_up(&counter), 0);
    assert_eq!(count_up(&counter), 1);
}

#[tokio::test]
async fn dropping_a_stream_waiting_for_a_standalone_reply_releases_the_driver() {
    use crate::header_custom::HeaderCustomUdpConfig;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let mut stream = connect(
        &[peer],
        None,
        &config(vec![KcpMask::HeaderCustom(Arc::new(
            HeaderCustomUdpConfig {
                standalone: true,
                ..Default::default()
            },
        ))]),
    )
    .await
    .unwrap();
    let weak = Arc::downgrade(&stream.shared);
    stream.write_all(b"pending").await.unwrap();
    let mut buf = [0; 8192];
    assert_eq!(within(socket.recv_from(&mut buf)).await.unwrap().0, 0);
    drop(stream);
    within(async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test]
async fn custom_headers_write_with_go_dual_stack_local_address() {
    use crate::header_custom::{CustomArg, CustomExpr, CustomItem, HeaderCustomUdpConfig};
    let fields = |fields: &[(&str, &str)]| {
        let client = fields
            .iter()
            .map(|(op, name)| CustomItem {
                delay: (0, 0),
                rand: 0,
                rand_range: (0, 255),
                packet: vec![],
                capture: String::new(),
                reuse: String::new(),
                transform: Some(CustomExpr {
                    op: (*op).into(),
                    args: vec![CustomArg::Metadata((*name).into())],
                }),
            })
            .collect();
        config(vec![KcpMask::HeaderCustom(Arc::new(
            HeaderCustomUdpConfig {
                standalone: false,
                client,
                server: vec![],
            },
        ))])
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let mut buf = [0; 8192];
    // Go's wildcard socket has a local port, but no local IPv4 address.
    let mut stream = connect(
        &[peer],
        None,
        &fields(&[("be32", "remote_ip4_u32"), ("be16", "local_port")]),
    )
    .await
    .unwrap();
    stream.write_all(b"port").await.unwrap();
    let (length, from) = within(socket.recv_from(&mut buf)).await.unwrap();
    assert!(length > 6);
    assert_eq!(buf[..4], [127, 0, 0, 1]);
    assert_eq!(buf[4..6], from.port().to_be_bytes());
    // The first stream keeps resending to its unanswering peer.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let mut stream = connect(&[peer], None, &fields(&[("be32", "local_ip4_u32")]))
        .await
        .unwrap();
    stream.write_all(b"dropped").await.unwrap();
    let received =
        tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf)).await;
    assert!(
        received.is_err(),
        "a write without a local IPv4 address went out"
    );
}

#[tokio::test]
async fn an_unanswered_standalone_request_goes_out_again_after_a_second() {
    use crate::header_custom::{CustomItem, HeaderCustomUdpConfig};
    let item = |packet: &[u8]| CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: packet.to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let mut stream = connect(
        &[peer],
        None,
        &config(vec![KcpMask::HeaderCustom(Arc::new(
            HeaderCustomUdpConfig {
                standalone: true,
                client: vec![item(b"REQ")],
                server: vec![item(b"ACK")],
            },
        ))]),
    )
    .await
    .unwrap();
    stream.write_all(b"pending").await.unwrap();
    let mut buf = [0; 8192];
    let (n, from) = within(socket.recv_from(&mut buf)).await.unwrap();
    assert_eq!(&buf[..n], b"REQ");
    let started = Instant::now();
    let (n, _) = within(socket.recv_from(&mut buf)).await.unwrap();
    assert_eq!(&buf[..n], b"REQ");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(3),
        "{waited:?}"
    );
    socket.send_to(b"ACK", from).await.unwrap();
    // The held datagram follows, unmasked: an mKCP segment.
    let (n, _) = within(socket.recv_from(&mut buf)).await.unwrap();
    assert!(n > 24, "{:?}", &buf[..n]);
}
