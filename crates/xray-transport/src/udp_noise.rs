//! Bounded Xray UDP noise. Installed only when configured; no task or packet queue.
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use rand::Rng;
use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};
use tokio::time::{Duration, Instant, Sleep};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoiseRange {
    pub from: u32,
    pub to: u32,
}
impl NoiseRange {
    pub(crate) fn sample(&self) -> u32 {
        rand::thread_rng().gen_range(self.from..=self.to)
    }
    fn valid(&self, max: u32) -> bool {
        self.from <= self.to && self.to <= max
    }
}
/// One segment of an Xray `exp` noise packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoiseSegment {
    /// These bytes.
    Bytes(Vec<u8>),
    /// That many random bytes.
    Random(NoiseRange),
    /// That many random ASCII letters.
    RandomLetters(NoiseRange),
    /// That many random decimal digits.
    RandomDigits(NoiseRange),
    /// The Unix time in seconds, four big-endian bytes.
    Timestamp,
    /// The connection's count of these segments, from one, four big-endian
    /// bytes.
    Counter,
    /// Eight random bytes.
    Nonce,
}
impl NoiseSegment {
    /// The most bytes this segment adds to a packet.
    fn max_len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Random(size) | Self::RandomLetters(size) | Self::RandomDigits(size) => {
                size.to as usize
            }
            Self::Timestamp | Self::Counter => 4,
            Self::Nonce => 8,
        }
    }
}
/// Xray-core's letters for `<rc>`, one drawn as a random byte modulo 52.
const ASCII_LETTERS: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpNoiseItem {
    pub packet: Vec<u8>,
    pub random_length: NoiseRange,
    pub random_bytes: NoiseRange,
    pub delay_ms: NoiseRange,
    /// The segments of an `exp` packet, built anew for every send; `packet`
    /// is then empty and `random_length` zero.
    pub segments: Vec<NoiseSegment>,
}
impl UdpNoiseItem {
    /// One noise packet: the fixed bytes, random ones of a random length, or
    /// the `exp` segments, `counter` counting each `<c>` the connection sends.
    pub(crate) fn build(&self, counter: &mut u32) -> Vec<u8> {
        if !self.segments.is_empty() {
            return self.build_segments(counter);
        }
        if self.random_length.to == 0 {
            return self.packet.clone();
        }
        let mut rng = rand::thread_rng();
        (0..self.random_length.sample())
            .map(|_| rng.gen_range(self.random_bytes.from..=self.random_bytes.to) as u8)
            .collect()
    }

    /// Xray-core's `buildPacket` for `exp` segments, sizes drawn inclusive.
    fn build_segments(&self, counter: &mut u32) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut packet = Vec::with_capacity(self.segments.iter().map(NoiseSegment::max_len).sum());
        for segment in &self.segments {
            match segment {
                NoiseSegment::Bytes(bytes) => packet.extend_from_slice(bytes),
                NoiseSegment::Timestamp => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |since| since.as_secs());
                    // Go's `uint32(time.Now().Unix())`.
                    packet.extend_from_slice(&(now as u32).to_be_bytes());
                }
                NoiseSegment::Counter => {
                    *counter = counter.wrapping_add(1);
                    packet.extend_from_slice(&counter.to_be_bytes());
                }
                NoiseSegment::Nonce => packet.extend((0..8).map(|_| rng.gen::<u8>())),
                NoiseSegment::Random(size)
                | NoiseSegment::RandomLetters(size)
                | NoiseSegment::RandomDigits(size) => {
                    packet.extend((0..size.sample()).map(|_| {
                        let byte = rng.gen::<u8>();
                        match segment {
                            NoiseSegment::RandomLetters(_) => {
                                ASCII_LETTERS[usize::from(byte) % ASCII_LETTERS.len()]
                            }
                            NoiseSegment::RandomDigits(_) => b'0' + byte % 10,
                            _ => byte,
                        }
                    }));
                }
            }
        }
        packet
    }

    fn valid_segments(&self) -> bool {
        self.segments.is_empty()
            || self.packet.is_empty()
                && self.random_length.to == 0
                && self.segments.iter().all(|segment| match segment {
                    NoiseSegment::Random(size)
                    | NoiseSegment::RandomLetters(size)
                    | NoiseSegment::RandomDigits(size) => size.valid(4096),
                    _ => true,
                })
                && self
                    .segments
                    .iter()
                    .map(NoiseSegment::max_len)
                    .sum::<usize>()
                    <= 4096
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpNoiseConfig {
    pub items: Vec<UdpNoiseItem>,
    pub reset_secs: NoiseRange,
    /// FinalMask array order: a noise before Salamander is itself obfuscated.
    pub before_salamander: bool,
}
impl UdpNoiseConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.items.len() > 16
            || !self.reset_secs.valid(i32::MAX as u32)
            || self.items.iter().any(|i| {
                i.packet.len() > 4096
                    || !i.random_length.valid(4096)
                    || !i.random_bytes.valid(255)
                    || !i.delay_ms.valid(1000)
                    || (!i.packet.is_empty() && i.random_length.to != 0)
                    || !i.valid_segments()
            })
            || self.items.iter().map(|i| i.delay_ms.to).sum::<u32>() > 10_000
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP noise exceeds bounded configuration",
            ));
        }
        Ok(())
    }
}

pub(crate) fn wrap(
    inner: Arc<dyn AsyncUdpSocket>,
    peer: SocketAddr,
    config: UdpNoiseConfig,
    session: Option<Arc<UdpNoiseState>>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    config.validate()?;
    if config.items.is_empty() {
        return Ok(inner);
    }
    Ok(Arc::new(NoiseSocket {
        inner,
        peer,
        config,
        session: session.unwrap_or_default(),
    }))
}
/// Xray wraps the logical hopping connection once. Keep noise progress and its
/// idle deadline across protected socket replacements, but not new QUIC sessions.
#[derive(Default)]
pub(crate) struct UdpNoiseState {
    done: AtomicBool,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    index: usize,
    packet: Option<Vec<u8>>,
    delay_until: Option<Instant>,
    expires: Option<Instant>,
    /// The `<c>` segments sent so far, which a reset does not restart.
    counter: u32,
}
struct NoiseSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    peer: SocketAddr,
    config: UdpNoiseConfig,
    session: Arc<UdpNoiseState>,
}
impl fmt::Debug for NoiseSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpNoiseSocket")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
impl AsyncUdpSocket for NoiseSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(NoisePoller {
            inner: self.inner.clone().create_io_poller(),
            socket: self,
            timer: None,
        })
    }
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected UDP noise peer",
            ));
        }
        if self.session.done.load(Ordering::Acquire) {
            return self.inner.try_send(transmit);
        }
        let mut state = self.session.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.expires.is_some_and(|t| Instant::now() > t) {
            state.index = 0;
            state.expires = None;
        }
        loop {
            if let Some(until) = state.delay_until {
                if Instant::now() < until {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                state.delay_until = None;
            }
            let Some(item) = self.config.items.get(state.index) else {
                break;
            };
            let State {
                packet, counter, ..
            } = &mut *state;
            let packet = packet.get_or_insert_with(|| item.build(counter));
            let noise = udp::Transmit {
                destination: self.peer,
                ecn: None,
                contents: packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            // Like Xray, noise send errors do not fail the application packet.
            // Readiness is different: retry the same item, never duplicate earlier items.
            if let Err(error) = self.inner.try_send(&noise) {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Err(error);
                }
            }
            state.packet = None;
            state.index += 1;
            let delay = item.delay_ms.sample();
            if delay != 0 {
                state.delay_until = Some(Instant::now() + Duration::from_millis(delay.into()));
            }
        }
        let result = self.inner.try_send(transmit);
        if result.is_ok() {
            if self.config.reset_secs.to == 0 {
                self.session.done.store(true, Ordering::Release);
            } else {
                state.expires = Some(
                    Instant::now() + Duration::from_secs(self.config.reset_secs.sample().into()),
                );
            }
        }
        result
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}
struct NoisePoller {
    socket: Arc<NoiseSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
    timer: Option<Pin<Box<Sleep>>>,
}
impl fmt::Debug for NoisePoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpNoisePoller").finish_non_exhaustive()
    }
}
impl UdpPoller for NoisePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let until = this
            .socket
            .session
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .delay_until;
        if let Some(until) = until {
            let timer = this
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(until)));
            if timer.deadline() != until {
                timer.as_mut().reset(until);
            }
            if timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        this.timer = None;
        this.inner.as_mut().poll_writable(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::Runtime;
    use std::future::poll_fn;
    fn r(n: u32) -> NoiseRange {
        NoiseRange { from: n, to: n }
    }
    fn config() -> UdpNoiseConfig {
        UdpNoiseConfig {
            items: vec![
                UdpNoiseItem {
                    packet: b"noise".to_vec(),
                    random_length: r(0),
                    random_bytes: r(0),
                    delay_ms: r(40),
                    segments: Vec::new(),
                },
                UdpNoiseItem {
                    packet: vec![],
                    random_length: NoiseRange { from: 16, to: 24 },
                    random_bytes: r(7),
                    delay_ms: r(0),
                    segments: Vec::new(),
                },
            ],
            reset_secs: r(0),
            before_salamander: false,
        }
    }
    async fn send(socket: &Arc<dyn AsyncUdpSocket>, peer: SocketAddr, bytes: &[u8]) {
        let mut poller = socket.clone().create_io_poller();
        let transmit = udp::Transmit {
            destination: peer,
            ecn: None,
            contents: bytes,
            segment_size: None,
            src_ip: None,
        };
        loop {
            match socket.try_send(&transmit) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    poll_fn(|cx| poller.as_mut().poll_writable(cx))
                        .await
                        .unwrap()
                }
                Err(e) => panic!("{e}"),
            }
        }
    }
    #[tokio::test]
    async fn wire_prelude_delays_then_untouched_traffic() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = server.local_addr().unwrap();
            let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            raw.set_nonblocking(true).unwrap();
            let socket = wrap(
                quinn::TokioRuntime.wrap_udp_socket(raw).unwrap(),
                peer,
                config(),
                None,
            )
            .unwrap();
            let started = Instant::now();
            send(&socket, peer, b"first QUIC").await;
            assert!(started.elapsed() >= Duration::from_millis(40));
            send(&socket, peer, b"later QUIC").await;
            let mut b = [0; 128];
            for i in 0..4 {
                let (n, from) = server.recv_from(&mut b).await.unwrap();
                assert_eq!(from, socket.local_addr().unwrap());
                match i {
                    0 => assert_eq!(&b[..n], b"noise"),
                    1 => {
                        assert!((16..=24).contains(&n));
                        assert!(b[..n].iter().all(|v| *v == 7));
                    }
                    2 => assert_eq!(&b[..n], b"first QUIC"),
                    _ => assert_eq!(&b[..n], b"later QUIC"),
                }
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(20), server.recv_from(&mut b))
                    .await
                    .is_err()
            );
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn cancellation_drops_pending_delay_without_sending_payload() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = server.local_addr().unwrap();
        let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.set_nonblocking(true).unwrap();
        let socket = wrap(
            quinn::TokioRuntime.wrap_udp_socket(raw).unwrap(),
            peer,
            config(),
            None,
        )
        .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(5),
            send(&socket, peer, b"must not leak")
        )
        .await
        .is_err());
        drop(socket);
        let mut b = [0; 128];
        let (n, _) = server.recv_from(&mut b).await.unwrap();
        assert_eq!(&b[..n], b"noise");
        assert!(
            tokio::time::timeout(Duration::from_millis(60), server.recv_from(&mut b))
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use std::{future::poll_fn, sync::atomic::AtomicUsize};
    #[derive(Debug, Default)]
    struct RecordingSocket {
        packets: Mutex<Vec<Vec<u8>>>,
        calls: AtomicUsize,
    }
    #[derive(Debug)]
    struct Ready;
    impl UdpPoller for Ready {
        fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncUdpSocket for RecordingSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(Ready)
        }
        fn try_send(&self, t: &udp::Transmit) -> io::Result<()> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.packets.lock().unwrap().push(t.contents.to_vec());
            Ok(())
        }
        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            _: &mut [IoSliceMut<'_>],
            _: &mut [udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
    }
    fn range(n: u32) -> NoiseRange {
        NoiseRange { from: n, to: n }
    }
    #[tokio::test(start_paused = true)]
    async fn socket_replacement_preserves_reset_and_new_connection_restarts_noise() {
        for reset in [0, 1] {
            let recorder = || {
                Arc::new(RecordingSocket {
                    calls: AtomicUsize::new(2), // readiness is exercised separately
                    ..Default::default()
                })
            };
            let config = UdpNoiseConfig {
                items: vec![UdpNoiseItem {
                    packet: b"noise".to_vec(),
                    random_length: range(0),
                    random_bytes: range(0),
                    delay_ms: range(0),
                    segments: Vec::new(),
                }],
                reset_secs: range(reset),
                before_salamander: false,
            };
            let session = Arc::new(UdpNoiseState::default());
            let peer = "127.0.0.1:2".parse().unwrap();
            let send = |socket: &Arc<dyn AsyncUdpSocket>, contents: &[u8]| {
                socket
                    .try_send(&udp::Transmit {
                        destination: peer,
                        contents,
                        ecn: None,
                        segment_size: None,
                        src_ip: None,
                    })
                    .unwrap();
            };
            let first = recorder();
            let socket = wrap(first.clone(), peer, config.clone(), Some(session.clone())).unwrap();
            send(&socket, b"first");
            assert_eq!(
                *first.packets.lock().unwrap(),
                [b"noise".as_slice(), b"first"]
            );
            drop(socket);
            tokio::time::advance(Duration::from_millis(500)).await;
            let next = recorder();
            let socket = wrap(next.clone(), peer, config.clone(), Some(session)).unwrap();
            send(&socket, b"rebound");
            assert_eq!(*next.packets.lock().unwrap(), [b"rebound".as_slice()]);
            tokio::time::advance(Duration::from_millis(1100)).await;
            send(&socket, b"after idle");
            let expected: &[&[u8]] = if reset == 0 {
                &[b"rebound", b"after idle"]
            } else {
                &[b"rebound", b"noise", b"after idle"]
            };
            assert_eq!(*next.packets.lock().unwrap(), expected);
            let fresh = recorder();
            let socket = wrap(fresh.clone(), peer, config, None).unwrap();
            send(&socket, b"new connection");
            assert_eq!(
                *fresh.packets.lock().unwrap(),
                [b"noise".as_slice(), b"new connection"]
            );
        }
    }
    #[tokio::test(start_paused = true)]
    async fn readiness_retry_and_sliding_idle_reset_preserve_sequence() {
        let raw = Arc::new(RecordingSocket::default());
        let peer = "127.0.0.1:2".parse().unwrap();
        let config = UdpNoiseConfig {
            items: [b"noise one", b"noise two"]
                .into_iter()
                .map(|p| UdpNoiseItem {
                    packet: p.to_vec(),
                    random_length: range(0),
                    random_bytes: range(0),
                    delay_ms: range(0),
                    segments: Vec::new(),
                })
                .collect(),
            reset_secs: range(1),
            before_salamander: false,
        };
        let socket = wrap(raw.clone(), peer, config, None).unwrap();
        let mut poller = socket.clone().create_io_poller();
        for (delay, payload) in [
            (0, b"one".as_slice()),
            (500, b"two"),
            (600, b"three"),
            (1100, b"four"),
        ] {
            tokio::time::advance(Duration::from_millis(delay)).await;
            let t = udp::Transmit {
                destination: peer,
                ecn: None,
                contents: payload,
                segment_size: None,
                src_ip: None,
            };
            loop {
                match socket.try_send(&t) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        poll_fn(|cx| poller.as_mut().poll_writable(cx))
                            .await
                            .unwrap()
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        }
        assert_eq!(
            *raw.packets.lock().unwrap(),
            [
                b"noise one".as_slice(),
                b"noise two",
                b"one",
                b"two",
                b"three",
                b"noise one",
                b"noise two",
                b"four"
            ]
        );
    }
}

#[cfg(test)]
mod exp_tests {
    use super::*;

    fn exp(segments: Vec<NoiseSegment>) -> UdpNoiseItem {
        UdpNoiseItem {
            packet: Vec::new(),
            random_length: NoiseRange { from: 0, to: 0 },
            random_bytes: NoiseRange { from: 0, to: 255 },
            delay_ms: NoiseRange { from: 0, to: 0 },
            segments,
        }
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The segments the noise-exp oracle wrote for what Xray-core read.
    fn oracle_segments(item: &serde_json::Value) -> Vec<NoiseSegment> {
        item["segments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|segment| match segment["kind"].as_str().unwrap() {
                "BYTES" => NoiseSegment::Bytes(decode_hex(segment["bytes"].as_str().unwrap())),
                "COUNTER" => NoiseSegment::Counter,
                kind => panic!("the oracle's sends draw nothing at random, not {kind}"),
            })
            .collect()
    }

    /// The packets Xray-core's noise mask sent for each connection, its
    /// counter running across the items in order.
    #[test]
    fn exp_packets_match_what_xray_core_sends() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/noise/exp-vectors.json"
        ))
        .unwrap();
        let sends = vectors["sends"].as_array().unwrap();
        assert!(!sends.is_empty());
        for send in sends {
            let mut counter = 0;
            let built: Vec<String> = send["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    let packet = exp(oracle_segments(item)).build(&mut counter);
                    packet.iter().map(|byte| format!("{byte:02x}")).collect()
                })
                .collect();
            let sent: Vec<&str> = send["sent"]
                .as_array()
                .unwrap()
                .iter()
                .map(|packet| packet.as_str().unwrap())
                .collect();
            assert_eq!(built, sent[..sent.len() - 1], "{send}");
            assert_eq!(sent[sent.len() - 1], send["payload"].as_str().unwrap());
        }
    }

    #[test]
    fn random_segments_draw_inclusive_sizes_from_their_alphabets() {
        let mut counter = 7;
        let item = exp(vec![
            NoiseSegment::RandomLetters(NoiseRange { from: 2, to: 4 }),
            NoiseSegment::Bytes(b"|".to_vec()),
            NoiseSegment::RandomDigits(NoiseRange { from: 3, to: 3 }),
            NoiseSegment::Bytes(b"|".to_vec()),
            NoiseSegment::Nonce,
            NoiseSegment::Random(NoiseRange { from: 0, to: 0 }),
        ]);
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..500 {
            let packet = item.build(&mut counter);
            let letters = packet.iter().position(|byte| *byte == b'|').unwrap();
            lengths.insert(letters);
            assert!(packet[..letters].iter().all(u8::is_ascii_alphabetic));
            let digits = &packet[letters + 1..letters + 4];
            assert!(digits.iter().all(u8::is_ascii_digit), "{packet:?}");
            assert_eq!(packet[letters + 4], b'|');
            assert_eq!(
                packet.len(),
                letters + 5 + 8,
                "eight nonce bytes, no random ones"
            );
        }
        assert_eq!(lengths.into_iter().collect::<Vec<_>>(), [2, 3, 4]);
        assert_eq!(counter, 7, "no counter segment counts");
    }

    #[test]
    fn timestamps_are_unix_seconds_and_counters_run_per_connection() {
        let unix = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32
        };
        let item = exp(vec![NoiseSegment::Timestamp, NoiseSegment::Counter]);
        let mut counter = u32::MAX - 1;
        let before = unix();
        let first = item.build(&mut counter);
        let second = item.build(&mut counter);
        let after = unix();
        let stamp = u32::from_be_bytes(first[..4].try_into().unwrap());
        assert!((before..=after).contains(&stamp));
        assert_eq!(first[4..], u32::MAX.to_be_bytes());
        assert_eq!(second[4..], 0u32.to_be_bytes(), "Go's counter wraps");
    }

    #[test]
    fn exp_items_are_bounded_like_literal_packets() {
        let config = |item: UdpNoiseItem| UdpNoiseConfig {
            items: vec![item],
            reset_secs: NoiseRange { from: 0, to: 0 },
            before_salamander: false,
        };
        let size = |to| NoiseRange { from: 0, to };
        assert!(config(exp(vec![
            NoiseSegment::Random(size(4088)),
            NoiseSegment::Nonce
        ]))
        .validate()
        .is_ok());
        assert!(config(exp(vec![
            NoiseSegment::Random(size(4089)),
            NoiseSegment::Nonce
        ]))
        .validate()
        .is_err());
        assert!(config(exp(vec![NoiseSegment::Random(NoiseRange {
            from: 3,
            to: 2
        })]))
        .validate()
        .is_err());
        let mut mixed = exp(vec![NoiseSegment::Counter]);
        mixed.packet = b"x".to_vec();
        assert!(config(mixed).validate().is_err());
    }
}
