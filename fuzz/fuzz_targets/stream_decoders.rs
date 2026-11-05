#![no_main]

//! Server-to-client stream decoders fed by a hostile or MITM'd peer. The first
//! input byte selects up to 15 read sizes from the bytes after it, so partial
//! reads split frames, records and headers at fuzzer-chosen boundaries.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::runtime::Builder;
use xray_proxy::shadowsocks::{ClientStream, Method};
use xray_proxy::vless::{VisionStream, VisionStreamIo, VlessResponseStream};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::stream::grpc_test_only::{
    encode_hunk, HunkDecoder, HunkMode, MAX_HUNK_PAYLOAD_LEN,
};
use xray_transport::stream::{FrameDecoder, FrameEvent};

// Matches the seed corpus; the fuzzer can still reach other ids.
const VISION_USER_ID: [u8; 16] = [0x11; 16];
const SHADOWSOCKS_METHODS: [(&str, &str); 3] = [
    ("aes-128-gcm", "fuzz-password"),
    ("chacha20-ietf-poly1305", "fuzz-password"),
    ("2022-blake3-aes-128-gcm", "AQEBAQEBAQEBAQEBAQEBAQ=="),
];

fn split_input(data: &[u8]) -> (&[u8], &[u8]) {
    let count = usize::from(data.first().copied().unwrap_or_default() & 0x0f);
    let rest = data.get(1..).unwrap_or_default();
    rest.split_at(count.min(rest.len()))
}

/// Yields the peer bytes in the read sizes chosen by the input.
struct Chunks<'a> {
    data: &'a [u8],
    sizes: &'a [u8],
    next: usize,
}

impl<'a> Chunks<'a> {
    fn new(data: &'a [u8], sizes: &'a [u8]) -> Self {
        Self {
            data,
            sizes,
            next: 0,
        }
    }

    fn next_len(&mut self, limit: usize) -> usize {
        let size = match self.sizes {
            [] => usize::MAX,
            sizes => usize::from(sizes[self.next % sizes.len()]) + 1,
        };
        self.next += 1;
        size.min(limit).min(self.data.len())
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.data.is_empty() {
            return None;
        }
        let (chunk, rest) = self.data.split_at(self.next_len(usize::MAX));
        self.data = rest;
        Some(chunk)
    }
}

/// An in-memory peer: reads follow [`Chunks`], writes are discarded.
struct ChunkedPeer<'a>(Chunks<'a>);

impl AsyncRead for ChunkedPeer<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let chunks = &mut self.get_mut().0;
        let len = chunks.next_len(buf.remaining());
        let (chunk, rest) = chunks.data.split_at(len);
        buf.put_slice(chunk);
        chunks.data = rest;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ChunkedPeer<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl VisionStreamIo for ChunkedPeer<'_> {
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

fn grpc_hunks(sizes: &[u8], wire: &[u8]) {
    for mode in [HunkMode::Single, HunkMode::Multi] {
        let mut decoder = HunkDecoder::new(mode);
        'chunks: for chunk in Chunks::new(wire, sizes) {
            decoder.push(chunk);
            loop {
                match decoder.next_payload() {
                    Ok(Some(payload)) => {
                        assert!(payload.len() <= MAX_HUNK_PAYLOAD_LEN);
                        if mode == HunkMode::Single {
                            let mut round_trip = HunkDecoder::new(HunkMode::Single);
                            round_trip.push(&encode_hunk(&payload));
                            assert_eq!(round_trip.next_payload(), Ok(Some(payload)));
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break 'chunks,
                }
            }
        }
    }
}

fn websocket_frames(sizes: &[u8], wire: &[u8]) {
    let mut decoder = FrameDecoder::new();
    'chunks: for chunk in Chunks::new(wire, sizes) {
        decoder.extend(chunk);
        loop {
            match decoder.next_event() {
                Ok(Some(FrameEvent::Payload(payload))) => assert!(!payload.is_empty()),
                Ok(Some(FrameEvent::Pong(_))) => {}
                Ok(Some(FrameEvent::Close)) | Err(_) => break 'chunks,
                Ok(None) => break,
            }
        }
    }
}

async fn read_all(mut reader: impl AsyncRead + Unpin) {
    let mut decoded = Vec::new();
    let _ = reader.read_to_end(&mut decoded).await;
}

async fn shadowsocks_responses(sizes: &[u8], wire: &[u8]) {
    let target = Target::new(
        TargetAddr::Domain("example.com".to_owned()),
        443,
        Network::Tcp,
    );
    for (name, password) in SHADOWSOCKS_METHODS {
        let method = Method::new(name, password).expect("fuzz Shadowsocks method");
        let peer = ChunkedPeer(Chunks::new(wire, sizes));
        if let Ok(stream) = ClientStream::new(peer, &method, &target) {
            read_all(stream).await;
        }
    }
}

async fn vless_responses(sizes: &[u8], wire: &[u8]) {
    read_all(VlessResponseStream::new(ChunkedPeer(Chunks::new(
        wire, sizes,
    ))))
    .await;
    let response = VlessResponseStream::new(ChunkedPeer(Chunks::new(wire, sizes)));
    read_all(VisionStream::new(response, VISION_USER_ID, [1, 2, 3, 4])).await;
}

fuzz_target!(|data: &[u8]| {
    let (sizes, wire) = split_input(data);
    grpc_hunks(sizes, wire);
    websocket_frames(sizes, wire);
    if let Some(hello) = xray_transport::extract_server_hello_for_fuzzing(wire) {
        assert_eq!(hello.first(), Some(&0x02));
    }
    let runtime = Builder::new_current_thread()
        .build()
        .expect("construct fuzz runtime");
    runtime.block_on(async {
        shadowsocks_responses(sizes, wire).await;
        vless_responses(sizes, wire).await;
    });
});
