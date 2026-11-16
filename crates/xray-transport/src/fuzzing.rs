//! Entry points for the `cargo-fuzz` targets in `fuzz/`, built only with the
//! `fuzzing` feature. Each feeds bytes that a server, a resolver or anyone on
//! the path controls to a decoder this crate otherwise keeps private, in the
//! form and order the transport would read them.
use std::{
    collections::VecDeque,
    fmt, io,
    io::IoSliceMut,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use quinn::{udp, AsyncUdpSocket, UdpPoller};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::{
    header_custom::{
        CustomArg, CustomExpr, CustomItem, HeaderCustomTcpConfig, HeaderCustomUdpConfig,
    },
    hysteria::{
        carrier::{self, CarrierSession},
        GeckoPacketSize, HeaderCustomCarrier, HysteriaCarrierConfig, SudokuCarrier,
    },
    kcp::{KcpHeader, KcpMask},
    sudoku::{SudokuConfig, SudokuStream},
    TransportStream,
};

const PASSWORD: &str = "fuzz-password";

fn peer() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], 443))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("construct fuzz runtime")
}

/// A DNS server's answer to the resolver's A or AAAA query and to the
/// system resolver's SRV and TXT queries.
pub fn dns_response(data: &[u8]) {
    crate::dns::fuzz_response(data);
    crate::system_records::fuzz_response(data.get(1..).unwrap_or_default());
}

/// A MASQUE proxy's capsule stream over HTTP/2 or the request stream of
/// HTTP/3, with the packets its DATAGRAM capsules carry.
pub fn masque_capsules(data: &[u8]) {
    crate::masque::fuzz_capsules(data);
}

/// The server's mKCP datagrams under one of the masks an mKCP stream takes.
/// The first byte picks the masks and whether the datagrams are sealed by
/// them first; the rest is datagrams, each after a two-byte length.
pub fn kcp(data: &[u8]) {
    let Some((&selector, datagrams)) = data.split_first() else {
        return;
    };
    let stacks = kcp_mask_stacks();
    let masks = &stacks[usize::from(selector & 0x7f) % stacks.len()];
    crate::kcp::fuzz_datagrams(masks, selector & 0x80 != 0, datagrams);
}

fn kcp_mask_stacks() -> Vec<Vec<KcpMask>> {
    let aes = || KcpMask::Aes128Gcm(Zeroizing::new(PASSWORD.to_owned()));
    let salamander = || KcpMask::Salamander(Zeroizing::new(PASSWORD.to_owned()));
    let header = KcpMask::Header;
    vec![
        Vec::new(),
        vec![KcpMask::Original],
        vec![aes()],
        vec![header(KcpHeader::Dns("www.example.com".to_owned()))],
        vec![header(KcpHeader::Dtls)],
        vec![header(KcpHeader::Srtp)],
        vec![header(KcpHeader::Utp)],
        vec![header(KcpHeader::Wechat)],
        vec![header(KcpHeader::Wireguard)],
        vec![salamander()],
        vec![KcpMask::Original, header(KcpHeader::Srtp)],
        vec![aes(), header(KcpHeader::Dtls), salamander()],
        vec![KcpMask::HeaderCustom(header_custom_udp(1))],
        vec![
            KcpMask::HeaderCustom(header_custom_udp(3)),
            KcpMask::Original,
        ],
        vec![KcpMask::Sudoku(sudoku(0))],
        vec![KcpMask::Original, KcpMask::Sudoku(sudoku(2))],
    ]
}

/// What the finalmask UDP masks read. The first byte picks the decoder:
/// the QUIC carrier's stack of Salamander, Gecko, `header-custom` and
/// sudoku over a socket that hands out the rest; an xdns resolver's answer;
/// an xicmp echo reply; or what a realm client hears from STUN servers,
/// peers and the rendezvous.
pub fn finalmask_udp(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 4 {
        0 => carrier_stack(rest),
        1 => crate::xdns::fuzz_response(rest),
        2 => crate::xicmp::fuzz_reply(rest),
        _ => crate::realm::fuzz_answers(rest),
    }
}

/// The carrier's masks as `wrap_masks` stacks them over a socket whose
/// datagrams the input scripts. Two bytes pick the masks and their order;
/// each datagram after them is a GRO stride byte, a two-byte length and its
/// bytes. With bit 7 of the first byte each datagram is Salamander's
/// encoding of those bytes, so the masks inside Salamander read them as
/// written.
fn carrier_stack(data: &[u8]) {
    let [masks, picks, rest @ ..] = data else {
        return;
    };
    let salamander = masks & 1 != 0;
    let mut config = HysteriaCarrierConfig {
        salamander_password: salamander.then(|| Arc::new(Zeroizing::new(PASSWORD.to_owned()))),
        gecko: GeckoPacketSize::new(64, 1200).filter(|_| masks & 2 != 0),
        ..HysteriaCarrierConfig::default()
    };
    let header_pick = usize::from(picks & 0x0f);
    if header_pick < HEADER_CUSTOM_UDP_CONFIGS {
        config.header_custom = Some(HeaderCustomCarrier {
            config: header_custom_udp(header_pick),
            before_salamander: masks & 4 != 0,
            before_noise: false,
        });
    }
    let sudoku_pick = usize::from(picks >> 4);
    if sudoku_pick < SUDOKU_CONFIGS {
        config.sudoku = Some(SudokuCarrier {
            config: sudoku(sudoku_pick),
            before_salamander: masks & 8 != 0,
            before_noise: false,
            before_header_custom: masks & 16 != 0,
        });
    }
    if config.validate().is_err() {
        return;
    }
    let Ok(session) = CarrierSession::new(&config) else {
        return;
    };
    let quinn_buffer = if masks & 32 != 0 { 1452 } else { 64 };
    let foreign = masks & 64 != 0;
    let encode = salamander && masks & 128 != 0;

    let mut incoming = VecDeque::new();
    let mut rest = rest;
    while let [stride, high, low, tail @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        let (datagram, tail) = tail.split_at(length);
        rest = tail;
        let stride = match *stride {
            0 => datagram.len().max(1),
            stride => usize::from(stride) * 8,
        };
        let (datagram, stride) = if encode {
            salamander_encode(datagram, stride)
        } else {
            (datagram.to_vec(), stride)
        };
        let from = if foreign {
            SocketAddr::from(([198, 51, 100, 7], 443))
        } else {
            peer()
        };
        incoming.push_back((from, datagram, stride));
    }

    let inner = Arc::new(ScriptedSocket {
        incoming: Mutex::new(incoming),
    });
    let Ok(socket) = carrier::wrap_masks(inner, peer(), peer(), &config, &session) else {
        return;
    };
    // A first send, which a standalone header-custom answers with its
    // request and a prefix one with the state its reads match against.
    let _ = socket.try_send(&udp::Transmit {
        destination: peer(),
        ecn: None,
        contents: &[0xc3; 48],
        segment_size: None,
        src_ip: None,
    });
    let mut cx = Context::from_waker(Waker::noop());
    let mut first = vec![0; quinn_buffer];
    let mut second = vec![0; quinn_buffer];
    // Each poll takes at least one scripted datagram until none is left.
    for _ in 0..1024 {
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut meta = [udp::RecvMeta::default(); 2];
        match socket.poll_recv(&mut cx, &mut bufs, &mut meta) {
            Poll::Ready(Ok(count)) => {
                for meta in meta.iter().take(count) {
                    assert!(meta.len <= quinn_buffer, "a mask overran Quinn's buffer");
                }
            }
            Poll::Ready(Err(_)) | Poll::Pending => break,
        }
    }
}

/// Salamander's encoding of each of the datagram's GRO segments, under a
/// salt of zeros; the stride grows by the salt.
fn salamander_encode(datagram: &[u8], stride: usize) -> (Vec<u8>, usize) {
    const SALT: [u8; carrier::SALT_LEN] = [0; carrier::SALT_LEN];
    let key = carrier::key(PASSWORD, &SALT);
    let mut wire = Vec::with_capacity(datagram.len() + carrier::SALT_LEN);
    for segment in datagram.chunks(stride.max(1)) {
        wire.extend_from_slice(&SALT);
        wire.extend(
            segment
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ key[i % key.len()]),
        );
    }
    (wire, stride + carrier::SALT_LEN)
}

/// A socket under the masks that hands out the scripted datagrams, each cut
/// to the buffer it is read into, as the system cuts one, and takes every
/// send.
struct ScriptedSocket {
    incoming: Mutex<VecDeque<(SocketAddr, Vec<u8>, usize)>>,
}

impl fmt::Debug for ScriptedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptedSocket").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for ScriptedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }

    fn try_send(&self, _: &udp::Transmit) -> io::Result<()> {
        Ok(())
    }

    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some((addr, datagram, stride)) = self
            .incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
        else {
            return Poll::Pending;
        };
        let len = datagram.len().min(bufs[0].len());
        bufs[0][..len].copy_from_slice(&datagram[..len]);
        meta[0] = udp::RecvMeta {
            addr,
            len,
            stride,
            ..udp::RecvMeta::default()
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([192, 0, 2, 10], 40000)))
    }
}

/// What a server sends back through the finalmask TCP masks. The first
/// byte's low two bits pick a `header-custom` handshake, a sudoku stream or
/// an xmc login and the stream after it, and its other bits the settings;
/// then come the read sizes and the server's bytes.
pub fn finalmask_tcp(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let runtime = runtime();
    match selector & 3 {
        0 => runtime.block_on(async {
            let configs = header_custom_tcp();
            let config = &configs[usize::from(selector >> 2) % configs.len()];
            let (sizes, server) = read_sizes(rest);
            let mut server = Peer::new(server.to_vec(), sizes);
            let local = SocketAddr::from(([192, 0, 2, 10], 40000));
            let _ = crate::header_custom::client_handshake(
                &mut server,
                config,
                Some(local),
                Some(peer()),
            )
            .await;
        }),
        1 => runtime.block_on(async {
            let (sizes, server) = read_sizes(rest);
            let config = sudoku(usize::from(selector >> 2) % SUDOKU_CONFIGS);
            let carrier = Box::new(Peer::new(server.to_vec(), sizes));
            let Ok(mut stream) = SudokuStream::new(carrier, &config) else {
                return;
            };
            let mut plain = Vec::new();
            let _ = stream.read_to_end(&mut plain).await;
        }),
        _ => runtime.block_on(crate::xmc::fuzz_server(rest)),
    }
}

/// Splits off the read sizes a leading count byte says follow it.
pub(crate) fn read_sizes(data: &[u8]) -> (&[u8], &[u8]) {
    let count = usize::from(data.first().copied().unwrap_or_default() & 0x0f);
    let rest = data.get(1..).unwrap_or_default();
    rest.split_at(count.min(rest.len()))
}

/// A server whose bytes arrive in reads of the sizes given, in turn, each
/// one more than its byte; everything written to it is taken and dropped.
pub(crate) struct Peer {
    data: Vec<u8>,
    offset: usize,
    sizes: Vec<u8>,
    next: usize,
}

impl Peer {
    pub(crate) fn new(data: Vec<u8>, sizes: &[u8]) -> Self {
        Self {
            data,
            offset: 0,
            sizes: sizes.to_vec(),
            next: 0,
        }
    }
}

impl AsyncRead for Peer {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let size = match this.sizes.as_slice() {
            [] => usize::MAX,
            sizes => usize::from(sizes[this.next % sizes.len()]) + 1,
        };
        this.next += 1;
        let size = size.min(buf.remaining()).min(this.data.len() - this.offset);
        buf.put_slice(&this.data[this.offset..this.offset + size]);
        this.offset += size;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Peer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TransportStream for Peer {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
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

fn captured(packet: &[u8], name: &str) -> CustomItem {
    CustomItem {
        capture: name.to_owned(),
        ..item(packet)
    }
}

fn reused(name: &str) -> CustomItem {
    CustomItem {
        reuse: name.to_owned(),
        ..item(b"")
    }
}

fn transform(op: &str, args: Vec<CustomArg>) -> CustomItem {
    CustomItem {
        transform: Some(CustomExpr {
            op: op.to_owned(),
            args,
        }),
        ..item(b"")
    }
}

const HEADER_CUSTOM_UDP_CONFIGS: usize = 5;

/// The `header-custom` UDP settings of the recorded vectors: fixed bytes,
/// a capture reused, transforms of captured bytes, and the standalone
/// exchange.
fn header_custom_udp(pick: usize) -> Arc<HeaderCustomUdpConfig> {
    let (standalone, client, server) = match pick % HEADER_CUSTOM_UDP_CONFIGS {
        0 => (false, vec![item(b"hello")], vec![item(&[0xaa, 0xbb])]),
        1 => (
            false,
            vec![captured(b"token", "x"), reused("x")],
            vec![reused("x")],
        ),
        2 => (
            false,
            vec![
                captured(b"ABCD", "x"),
                CustomItem {
                    capture: "slice".to_owned(),
                    ..transform(
                        "slice",
                        vec![
                            CustomArg::Reuse("x".to_owned()),
                            CustomArg::U64(1),
                            CustomArg::U64(2),
                        ],
                    )
                },
            ],
            vec![transform(
                "concat",
                vec![
                    CustomArg::Reuse("slice".to_owned()),
                    CustomArg::Bytes(b"!".to_vec()),
                ],
            )],
        ),
        3 => (true, vec![item(b"hello")], vec![item(&[0xaa, 0xbb])]),
        _ => (
            true,
            vec![captured(b"token", "x"), reused("x")],
            vec![reused("x")],
        ),
    };
    Arc::new(HeaderCustomUdpConfig {
        standalone,
        client,
        server,
    })
}

/// The `header-custom` TCP settings of the recorded vectors, the server's
/// sequences checked against what it sends.
fn header_custom_tcp() -> Vec<HeaderCustomTcpConfig> {
    vec![
        HeaderCustomTcpConfig {
            clients: vec![vec![item(&[1, 2, 3])]],
            servers: vec![vec![item(&[0, 1, 2])]],
        },
        HeaderCustomTcpConfig {
            clients: vec![vec![captured(b"ABCDEFGH", "nonce")]],
            servers: vec![vec![reused("nonce")]],
        },
        HeaderCustomTcpConfig {
            clients: vec![vec![item(b"hi")]],
            servers: vec![vec![
                captured(b"0123", "token"),
                transform(
                    "concat",
                    vec![
                        CustomArg::Reuse("token".to_owned()),
                        CustomArg::Bytes(b"!".to_vec()),
                    ],
                ),
            ]],
        },
        HeaderCustomTcpConfig {
            clients: vec![vec![item(b"c0")], vec![reused("token"), item(b"!")]],
            servers: vec![vec![CustomItem {
                rand: 5,
                rand_range: (0, 255),
                ..captured(b"", "token")
            }]],
        },
        HeaderCustomTcpConfig {
            clients: vec![vec![item(b"c0")]],
            servers: vec![
                vec![item(b"s0")],
                vec![item(b"s1")],
                vec![transform(
                    "pad",
                    vec![
                        CustomArg::Bytes(b"ab".to_vec()),
                        CustomArg::U64(7),
                        CustomArg::Bytes(b"xy".to_vec()),
                    ],
                )],
            ],
        },
    ]
}

const SUDOKU_CONFIGS: usize = 4;

/// The sudoku settings of the recorded vectors: entropy and ASCII layouts,
/// several custom tables, and padding.
fn sudoku(pick: usize) -> Arc<SudokuConfig> {
    let password = |password: &str| SudokuConfig {
        password: password.to_owned(),
        ..SudokuConfig::default()
    };
    Arc::new(match pick % SUDOKU_CONFIGS {
        0 => password("synthetic"),
        1 => SudokuConfig {
            ascii: "prefer_ascii".to_owned(),
            ..password("p@ss")
        },
        2 => SudokuConfig {
            custom_tables: vec!["xppvvvvx".to_owned(), "vvxpvxpv".to_owned(), String::new()],
            ..password("multi")
        },
        _ => SudokuConfig {
            padding_min: 20,
            padding_max: 80,
            ..password("synthetic")
        },
    })
}
