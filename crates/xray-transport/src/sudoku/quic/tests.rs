use super::*;
use std::{future::poll_fn, net::Ipv4Addr};

/// An inner socket that records what is sent and hands out what is queued,
/// each entry one read: its bytes and their GRO stride.
#[derive(Debug, Default)]
struct Fake {
    sent: Mutex<Vec<Vec<u8>>>,
    incoming: Mutex<VecDeque<(Vec<u8>, usize)>>,
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
        self.sent.lock().unwrap().push(transmit.contents.to_vec());
        Ok(())
    }

    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some((bytes, stride)) = self.incoming.lock().unwrap().pop_front() else {
            return Poll::Pending;
        };
        bufs[0][..bytes.len()].copy_from_slice(&bytes);
        meta[0] = udp::RecvMeta {
            addr: peer(),
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

fn peer() -> SocketAddr {
    "192.0.2.1:443".parse().unwrap()
}

fn config() -> SudokuConfig {
    SudokuConfig {
        password: "synthetic".into(),
        padding_min: 5,
        padding_max: 20,
        ..Default::default()
    }
}

fn masked() -> (Arc<Fake>, Arc<dyn AsyncUdpSocket>, DatagramMask) {
    let fake = Arc::new(Fake::default());
    let socket = wrap(fake.clone(), &config()).unwrap();
    (fake, socket, DatagramMask::new(&config()).unwrap())
}

fn send(socket: &dyn AsyncUdpSocket, contents: &[u8]) -> io::Result<()> {
    socket.try_send(&udp::Transmit {
        destination: peer(),
        ecn: None,
        contents,
        segment_size: None,
        src_ip: None,
    })
}

/// Reads with `slots` buffers of `size` bytes, as Quinn does.
async fn receive(socket: &dyn AsyncUdpSocket, slots: usize, size: usize) -> Vec<Vec<u8>> {
    let mut storage = vec![vec![0u8; size]; slots];
    let mut meta = vec![udp::RecvMeta::default(); slots];
    let count = poll_fn(|cx| {
        let mut bufs: Vec<IoSliceMut<'_>> = storage
            .iter_mut()
            .map(|buffer| IoSliceMut::new(buffer))
            .collect();
        socket.poll_recv(cx, &mut bufs, &mut meta)
    })
    .await
    .unwrap();
    (0..count)
        .map(|i| {
            assert_eq!(meta[i].addr, peer());
            assert_eq!(meta[i].stride, meta[i].len);
            storage[i][..meta[i].len].to_vec()
        })
        .collect()
}

#[tokio::test]
async fn packets_go_out_encoded_and_come_back_decoded() {
    let (fake, socket, mask) = masked();
    let packet: Vec<u8> = (0..1200).map(|i| i as u8).collect();
    send(socket.as_ref(), &packet).unwrap();
    let sent = fake.sent.lock().unwrap().pop().unwrap();
    // Four clues per byte, and padding between them.
    assert!(sent.len() >= packet.len() * 4, "{}", sent.len());
    let mut wire = sent.clone();
    let range = mask.decode(&mut wire, 0..sent.len()).unwrap();
    assert_eq!(wire[range], packet[..]);

    // Each packet is encoded afresh, as Xray-core encodes each datagram.
    send(socket.as_ref(), &packet).unwrap();
    assert_ne!(fake.sent.lock().unwrap().pop().unwrap(), sent);

    fake.incoming
        .lock()
        .unwrap()
        .push_back((mask.encode(b"from the server"), usize::MAX));
    assert_eq!(
        receive(socket.as_ref(), 1, 1472).await,
        [b"from the server"]
    );
}

#[tokio::test]
async fn a_datagram_that_does_not_decode_is_dropped() {
    let (fake, socket, mask) = masked();
    let mut cut = mask.encode(b"whole");
    cut.truncate(cut.len() - 1);
    let incoming = [cut, b"plain bytes".to_vec(), mask.encode(b"next")];
    for datagram in incoming {
        let stride = datagram.len();
        fake.incoming.lock().unwrap().push_back((datagram, stride));
    }
    assert_eq!(receive(socket.as_ref(), 4, 1472).await, [b"next"]);
}

#[tokio::test]
async fn a_gro_batch_is_split_at_its_stride_and_what_finds_no_slot_waits() {
    let (fake, socket, mask) = masked();
    // GRO joins datagrams of one length; sudoku's lengths vary, so pad each
    // encoding to a common stride with trailing padding the decoder skips.
    let stride = 200;
    let mut batch = Vec::new();
    for word in [&b"one"[..], b"two", b"three"] {
        let mut datagram = mask.encode(word);
        assert!(datagram.len() <= stride);
        let filler = padding_byte(&mask, &datagram);
        datagram.resize(stride, filler);
        batch.extend_from_slice(&datagram);
    }
    fake.incoming.lock().unwrap().push_back((batch, stride));
    // Two slots: the third datagram waits for the next read.
    assert_eq!(
        receive(socket.as_ref(), 2, 1472).await,
        [&b"one"[..], b"two"]
    );
    assert_eq!(receive(socket.as_ref(), 2, 1472).await, [b"three"]);
    // A datagram too long for Quinn's buffer is dropped.
    fake.incoming
        .lock()
        .unwrap()
        .push_back((mask.encode(&[7; 100]), usize::MAX));
    fake.incoming
        .lock()
        .unwrap()
        .push_back((mask.encode(b"fits"), usize::MAX));
    assert_eq!(receive(socket.as_ref(), 1, 64).await, [b"fits"]);
}

/// A byte the decoder skips: one the sender used as padding.
fn padding_byte(mask: &DatagramMask, datagram: &[u8]) -> u8 {
    (0..=255u8)
        .find(|&byte| {
            let mut probe = datagram.to_vec();
            probe.push(byte);
            let length = probe.len();
            let mut alone = mask.encode(b"x");
            alone.push(byte);
            let alone_length = alone.len();
            mask.decode(&mut probe, 0..length).is_some()
                && mask
                    .decode(&mut alone, 0..alone_length)
                    .as_ref()
                    .map(|r| r.len())
                    == Some(1)
        })
        .expect("a padding byte")
}

#[test]
fn the_socket_takes_and_gives_one_datagram_a_time_and_may_fragment() {
    let (_, socket, _) = masked();
    assert!(socket.may_fragment());
    assert_eq!(socket.max_transmit_segments(), 1);
    assert_eq!(socket.max_receive_segments(), 1);
    assert!(send(socket.as_ref(), &[0; 2400][..]).is_ok());
    let batch = udp::Transmit {
        destination: peer(),
        ecn: None,
        contents: &[0; 2400],
        segment_size: Some(1200),
        src_ip: None,
    };
    assert!(socket.try_send(&batch).is_err(), "no GSO batch");
}

/// Quinn sets the don't-fragment bit; a clone of the socket clears it.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
#[tokio::test]
async fn the_carrier_clears_the_dont_fragment_bit_quinn_sets() {
    use crate::socket_options::sys::get_int;
    use quinn::Runtime as _;
    use std::os::fd::AsRawFd;
    let [v4, v6] = FRAGMENTATION;
    for (bind, (level, name, allowed)) in [
        (std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), v4),
        ("[::1]:0".parse().unwrap(), v6),
    ] {
        let Ok(socket) = std::net::UdpSocket::bind(bind) else {
            continue;
        };
        let clone = socket.try_clone().unwrap();
        let _quinn = quinn::TokioRuntime.wrap_udp_socket(socket).unwrap();
        let fd = clone.as_raw_fd();
        assert_ne!(get_int(fd, level, name).unwrap(), allowed, "{bind}");
        allow_fragmentation(&clone).unwrap();
        assert_eq!(get_int(fd, level, name).unwrap(), allowed, "{bind}");
    }
}
