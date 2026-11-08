use super::*;
use crate::header_custom::{CustomArg, CustomExpr, CustomItem};
use std::{collections::VecDeque, future::poll_fn, task::Poll};

/// An inner socket that records what is sent and hands out what is queued.
#[derive(Debug, Default)]
struct Fake {
    sent: Mutex<Vec<Vec<u8>>>,
    incoming: Mutex<VecDeque<(SocketAddr, Vec<u8>, usize)>>,
    /// Refuses the next send as not ready.
    busy: std::sync::atomic::AtomicBool,
}

#[derive(Debug)]
struct Ready;

impl UdpPoller for Ready {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for Fake {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Ready)
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if self.busy.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.sent.lock().unwrap().push(transmit.contents.to_vec());
        Ok(())
    }

    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some((addr, bytes, stride)) = self.incoming.lock().unwrap().pop_front() else {
            return Poll::Pending;
        };
        bufs[0][..bytes.len()].copy_from_slice(&bytes);
        meta[0] = udp::RecvMeta {
            addr,
            len: bytes.len(),
            stride,
            ..Default::default()
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("0.0.0.0:40000".parse().unwrap())
    }
}

fn item(packet: &[u8]) -> CustomItem {
    CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: packet.to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    }
}

fn metadata(op: &str, name: &str) -> CustomItem {
    CustomItem {
        transform: Some(CustomExpr {
            op: op.into(),
            args: vec![CustomArg::Metadata(name.into())],
        }),
        ..item(b"")
    }
}

fn peer() -> SocketAddr {
    "192.0.2.1:443".parse().unwrap()
}

fn masked(
    standalone: bool,
    client: Vec<CustomItem>,
    server: Vec<CustomItem>,
) -> (Arc<Fake>, Arc<dyn AsyncUdpSocket>, Arc<HeaderCustomState>) {
    let state = HeaderCustomState::new(Arc::new(HeaderCustomUdpConfig {
        standalone,
        client,
        server,
    }))
    .unwrap();
    let fake = Arc::new(Fake::default());
    let socket = wrap(fake.clone(), peer(), peer(), state.clone());
    (fake, socket, state)
}

fn send(socket: &Arc<dyn AsyncUdpSocket>, contents: &[u8]) -> io::Result<()> {
    socket.try_send(&udp::Transmit {
        destination: peer(),
        ecn: None,
        contents,
        segment_size: None,
        src_ip: None,
    })
}

/// One read through the mask: the bytes Quinn sees and their stride.
async fn receive(
    socket: &Arc<dyn AsyncUdpSocket>,
    fake: &Fake,
    from: SocketAddr,
    bytes: &[u8],
    stride: usize,
) -> (Vec<u8>, usize) {
    fake.incoming
        .lock()
        .unwrap()
        .push_back((from, bytes.to_vec(), stride));
    let mut buffer = vec![0; 65_536];
    let mut meta = [udp::RecvMeta::default()];
    let count = poll_fn(|cx| {
        let mut bufs = [IoSliceMut::new(&mut buffer)];
        socket.poll_recv(cx, &mut bufs, &mut meta)
    })
    .await
    .unwrap();
    assert_eq!(count, 1);
    (buffer[..meta[0].len].to_vec(), meta[0].stride)
}

fn sent(fake: &Fake) -> Vec<Vec<u8>> {
    fake.sent.lock().unwrap().clone()
}

#[tokio::test]
async fn prefixes_go_on_every_datagram_and_come_off_each_one_of_a_batch() {
    let (fake, socket, _) = masked(false, vec![item(b"HC")], vec![item(b"SV")]);
    send(&socket, b"quic").unwrap();
    assert_eq!(sent(&fake), [b"HCquic".to_vec()]);
    assert_eq!(socket.max_transmit_segments(), 1);
    let batch = socket.try_send(&udp::Transmit {
        destination: peer(),
        ecn: None,
        contents: b"aaaabbbb",
        segment_size: Some(4),
        src_ip: None,
    });
    assert_eq!(batch.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    // A GRO batch keeps its shape: each datagram loses its prefix.
    assert_eq!(
        receive(&socket, &fake, peer(), b"SVaaaaSVbbbbSVcc", 6).await,
        (b"aaaabbbbcc".to_vec(), 4)
    );
    // A datagram that does not match is dropped from the batch.
    assert_eq!(
        receive(&socket, &fake, peer(), b"SVaaaaXXbbbbSVcc", 6).await,
        (b"aaaacc".to_vec(), 4)
    );
    let other = "192.0.2.2:443".parse().unwrap();
    assert_eq!(
        receive(&socket, &fake, other, b"SVaaaa", 6).await,
        (vec![], 1)
    );
}

#[tokio::test(start_paused = true)]
async fn standalone_holds_quic_until_the_reply_and_asks_again_after_a_second() {
    let (fake, socket, _) = masked(true, vec![item(b"REQ")], vec![item(b"ACK")]);
    let mut poller = socket.clone().create_io_poller();
    let would_block = |result: io::Result<()>| {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    };
    would_block(send(&socket, b"one"));
    assert_eq!(sent(&fake), [b"REQ".to_vec()]);
    let pending = poll_fn(|cx| Poll::Ready(poller.as_mut().poll_writable(cx).is_pending())).await;
    assert!(pending);
    // Other datagrams pass untouched while the reply is awaited.
    assert_eq!(
        receive(&socket, &fake, peer(), b"data", 4).await,
        (b"data".to_vec(), 4)
    );
    // The reply is taken off and wakes the writer.
    assert_eq!(
        receive(&socket, &fake, peer(), b"ACK", 3).await,
        (vec![], 1)
    );
    poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .unwrap();
    send(&socket, b"one").unwrap();
    send(&socket, b"two").unwrap();
    assert_eq!(
        sent(&fake),
        [b"REQ".to_vec(), b"one".to_vec(), b"two".to_vec()]
    );
    // Five seconds after the reply, the next write asks again.
    tokio::time::advance(Duration::from_secs(5) + Duration::from_millis(1)).await;
    would_block(send(&socket, b"three"));
    assert_eq!(sent(&fake).len(), 4);
    // Unanswered, the request goes out again a second later.
    let started = Instant::now();
    poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .unwrap();
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    would_block(send(&socket, b"three"));
    assert_eq!(&sent(&fake)[3..], [b"REQ".to_vec(), b"REQ".to_vec()]);
}

#[tokio::test]
async fn writes_see_the_dual_stack_local_port_and_the_server_address() {
    let (fake, socket, _) = masked(
        false,
        vec![
            metadata("be16", "local_port"),
            metadata("be32", "remote_ip4_u32"),
        ],
        vec![],
    );
    send(&socket, b"q").unwrap();
    let mut expected = 40000u16.to_be_bytes().to_vec();
    expected.extend([192, 0, 2, 1, b'q']);
    assert_eq!(sent(&fake), [expected]);
    // Go's wildcard socket has no local IPv4 address: Xray drops the write.
    let (fake, socket, _) = masked(false, vec![metadata("be32", "local_ip4_u32")], vec![]);
    send(&socket, b"q").unwrap();
    assert!(sent(&fake).is_empty());
}

#[tokio::test]
async fn a_rebound_socket_keeps_the_completed_handshake() {
    let (fake, socket, state) = masked(true, vec![item(b"REQ")], vec![item(b"ACK")]);
    assert!(send(&socket, b"one").is_err());
    receive(&socket, &fake, peer(), b"ACK", 3).await;
    let rebound = Arc::new(Fake::default());
    let socket = wrap(rebound.clone(), peer(), peer(), state);
    send(&socket, b"two").unwrap();
    assert_eq!(sent(&rebound), [b"two".to_vec()]);
}

#[tokio::test(start_paused = true)]
async fn the_reply_wakes_a_waiting_writer_before_the_resend_timer() {
    let (fake, socket, _) = masked(true, vec![item(b"REQ")], vec![item(b"ACK")]);
    assert!(send(&socket, b"one").is_err());
    let mut poller = socket.clone().create_io_poller();
    let started = Instant::now();
    let waiting = tokio::spawn(async move {
        poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        started.elapsed()
    });
    tokio::task::yield_now().await;
    receive(&socket, &fake, peer(), b"ACK", 3).await;
    assert!(waiting.await.unwrap() < Duration::from_secs(1));
}

#[tokio::test]
async fn a_request_that_could_not_go_out_is_not_awaited() {
    let (fake, socket, _) = masked(true, vec![item(b"REQ")], vec![item(b"ACK")]);
    fake.busy.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        send(&socket, b"one").unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(sent(&fake).is_empty());
    // Ready at once, and the next attempt sends the request.
    let mut poller = socket.clone().create_io_poller();
    poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .unwrap();
    assert!(send(&socket, b"one").is_err());
    assert_eq!(sent(&fake), [b"REQ".to_vec()]);
}
