//! The byte stream on top of one gRPC call.
//!
//! Xray's `HunkReaderWriter` turns a bidirectional `Hunk` stream into a
//! `net.Conn` (`Xray-core/transport/internet/grpc/encoding/hunkconn.go:
//! 28-141`), and this is the same adapter over h2: every write becomes one
//! `Hunk`, every read is served out of whatever `Hunk`s have arrived.
//!
//! It is separate from `h2client.rs` because the two have different lifetimes.
//! Everything here runs on every read and every write for the life of a
//! tunnel; the handshake and request next door run once and will be replaced
//! wholesale when connections start being pooled.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use h2::client::ResponseFuture;
use h2::{RecvStream, SendStream};
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::framing::{encode_hunk, HunkDecoder};
use super::h2client::H2ConnectionDriver;
use crate::{TransportError, TransportStream};

/// The downlink before and after the server's HEADERS arrive.
enum Downlink {
    /// The response is still outstanding, because the dial did not wait for
    /// it. Polled on the first read.
    Awaiting(ResponseFuture),
    Reading(RecvStream),
}

/// One gRPC call as an `AsyncRead + AsyncWrite`.
///
/// Both halves of the h2 stream live here, and that is load-bearing rather
/// than tidy: h2 emits `RST_STREAM` only once *every* reference to a stream is
/// gone, so dropping the `SendStream` while something else still holds the
/// `RecvStream` sends nothing at all. Owning the pair is what makes dropping
/// this struct tell the peer the call is over.
pub struct GrpcStream {
    downlink: Downlink,
    uplink: SendStream<Bytes>,
    decoder: HunkDecoder,
    /// A decoded `Hunk` payload part-way through being handed to the caller.
    pending_read: Vec<u8>,
    pending_read_pos: usize,
    /// The encoded `Hunk` that has not been handed to h2 in full yet, because
    /// the flow-control window ran out mid-frame.
    pending_write: Bytes,
    /// Set once `data()` has yielded `None` and the trailers have been read.
    eof: bool,
    send_closed: bool,
    /// Declared last so it is dropped last: the two stream halves above have to
    /// go first for the `RST_STREAM` they queue to have a live driver to flush
    /// it.
    driver: H2ConnectionDriver,
}

impl GrpcStream {
    pub(super) fn new(
        response: ResponseFuture,
        uplink: SendStream<Bytes>,
        driver: H2ConnectionDriver,
    ) -> Self {
        Self {
            downlink: Downlink::Awaiting(response),
            uplink,
            decoder: HunkDecoder::new(),
            pending_read: Vec::new(),
            pending_read_pos: 0,
            pending_write: Bytes::new(),
            eof: false,
            send_closed: false,
            driver,
        }
    }

    /// Whether the connection underneath has ended — a graceful `GOAWAY`
    /// included. See [`H2ConnectionDriver`].
    pub fn connection_is_finished(&self) -> bool {
        self.driver.is_finished()
    }

    fn deliver(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let remaining = &self.pending_read[self.pending_read_pos..];
        let take = remaining.len().min(output.remaining());
        if take == 0 {
            return false;
        }

        output.put_slice(&remaining[..take]);
        self.pending_read_pos += take;
        if self.pending_read_pos == self.pending_read.len() {
            self.pending_read = Vec::new();
            self.pending_read_pos = 0;
        }
        true
    }

    /// Hands whatever is left of the current frame to h2, a window's worth at
    /// a time.
    ///
    /// The order matters. `reserve_capacity` states the *total* still wanted
    /// and is decremented as data goes out, so it is restated every pass
    /// rather than once up front. `poll_capacity` is edge-triggered — it
    /// returns `Pending` unless the connection has assigned capacity since the
    /// last call (`h2-0.4.15/src/proto/streams/send.rs:363-389`), which is why
    /// the reservation has to come first — and it never grants zero. And
    /// nothing is ever handed over unreserved: `send_data` would buffer it
    /// without bound, which is the same as having no backpressure at all.
    fn poll_drain_uplink(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_write.is_empty() {
            self.uplink.reserve_capacity(self.pending_write.len());
            let granted = match ready!(self.uplink.poll_capacity(cx)) {
                Some(Ok(granted)) => granted,
                Some(Err(error)) => return Poll::Ready(Err(h2_io_error("uplink stalled", &error))),
                // The send half stopped streaming: END_STREAM has gone out, or
                // the peer reset us.
                None => {
                    return Poll::Ready(Err(protocol_io_error(
                        "the gRPC uplink is closed".to_owned(),
                    )))
                }
            };

            let take = granted.min(self.pending_write.len());
            self.uplink
                .send_data(self.pending_write.split_to(take), false)
                .map_err(|error| h2_io_error("could not send a Hunk", &error))?;
        }

        Poll::Ready(Ok(()))
    }

    /// Turns the end of the h2 stream into either EOF or an error.
    ///
    /// Xray's reader draws that line by what `Recv` returns: `io.EOF` — which
    /// grpc-go produces for `grpc-status: 0` — ends the read cleanly, and
    /// anything else becomes "failed to fetch hunk from gRPC tunnel"
    /// (`hunkconn.go:75-89`). A failed call reported as EOF would truncate a
    /// tunnel with no trace.
    ///
    /// A stream that simply ends with no trailers at all is treated as EOF.
    /// That is a bare half-close rather than a completed RPC, and the sibling
    /// WebSocket adapter takes the same view of a socket that closes without a
    /// close frame: a half-closed relay is ordinary.
    fn poll_finish_downlink(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Checked first because it is the more precise complaint: grpc-go
        // turns an EOF inside a message into `io.ErrUnexpectedEOF` rather than
        // letting it pass as the end of the stream
        // (`grpc@v1.81.0/internal/transport/transport.go:360-380`).
        let buffered = self.decoder.buffered_len();
        if buffered != 0 {
            return Poll::Ready(Err(protocol_io_error(format!(
                "the gRPC stream ended {buffered} bytes into a Hunk"
            ))));
        }

        let Downlink::Reading(recv) = &mut self.downlink else {
            // Unreachable: only the reading arm can report the end of data.
            // `eof` is still set rather than left alone, because the caller
            // treats `Ok(())` with nothing delivered as end of stream and
            // would otherwise spin on this branch forever.
            self.eof = true;
            return Poll::Ready(Ok(()));
        };
        let trailers = ready!(recv.poll_trailers(cx))
            .map_err(|error| h2_io_error("could not read the gRPC trailers", &error))?;

        if let Some(status) = trailers.as_ref().and_then(grpc_status) {
            if status != "0" {
                let message = trailers
                    .as_ref()
                    .and_then(|trailers| trailers.get("grpc-message"))
                    .and_then(|message| message.to_str().ok())
                    .unwrap_or("no message");
                return Poll::Ready(Err(protocol_io_error(format!(
                    "the gRPC call failed with status {status}: {message}"
                ))));
            }
        }

        self.eof = true;
        Poll::Ready(Ok(()))
    }
}

fn grpc_status(trailers: &HeaderMap) -> Option<&str> {
    trailers.get("grpc-status")?.to_str().ok()
}

fn protocol_io_error(reason: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, TransportError::Grpc(reason))
}

fn h2_io_error(context: &str, error: &h2::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        TransportError::Grpc(format!("{context}: {error}")),
    )
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.deliver(output) {
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }

            match this.decoder.next_payload().map_err(protocol_io_error)? {
                // A zero-length `Hunk` is a legal zero-byte write, not the end
                // of anything: Xray's own reader copies nothing out of it and
                // returns `(0, nil)` (`hunkconn.go:91-105`). `Ok(0)` from an
                // `AsyncRead` means EOF, so it must never reach the caller —
                // ask for the next message instead.
                Some(payload) if payload.is_empty() => continue,
                Some(payload) => {
                    this.pending_read = payload;
                    this.pending_read_pos = 0;
                    continue;
                }
                None => {}
            }

            let recv = match &mut this.downlink {
                // Nothing about the response HEADERS is inspected. grpc-go
                // only evaluates `:status` for a response that is *not*
                // gRPC-shaped — a valid `content-type` puts it in gRPC mode
                // and the HTTP status stops mattering
                // (`grpc@v1.81.0/internal/transport/http2_client.go:
                // 1529-1573`) — so getting this right means reading
                // content-type as well, which belongs with the rest of the
                // header work. Until then a non-gRPC body is caught one layer
                // down, where its first byte fails `HunkDecoder`'s
                // payload-format check.
                Downlink::Awaiting(response) => {
                    let response = ready!(Pin::new(response).poll(cx))
                        .map_err(|error| h2_io_error("no gRPC response", &error))?;
                    this.downlink = Downlink::Reading(response.into_body());
                    continue;
                }
                Downlink::Reading(recv) => recv,
            };

            match ready!(recv.poll_data(cx)) {
                Some(Ok(chunk)) => {
                    // The window has to be handed back explicitly or the peer
                    // stalls the moment it has sent 65535 bytes, which is the
                    // connection and stream default. h2 releases the stream
                    // and connection windows together here.
                    recv.flow_control()
                        .release_capacity(chunk.len())
                        .map_err(|error| h2_io_error("could not release the window", &error))?;
                    this.decoder.push(&chunk);
                }
                Some(Err(error)) => {
                    return Poll::Ready(Err(h2_io_error("downlink failed", &error)))
                }
                // Not `is_end_stream()`: a gRPC call ends with a trailing
                // HEADERS frame, and h2 leaves `is_end_stream()` false until
                // those trailers have been taken. `data()` yielding `None` is
                // the only end there is.
                None => {
                    ready!(this.poll_finish_downlink(cx))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Anything left over goes first, so two `Hunk`s are never interleaved
        // on the wire. Returning `Pending` here has accepted nothing yet.
        match this.poll_drain_uplink(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // One write, one `Hunk`: `HunkReaderWriter.Write` hands the whole
        // buffer to a single `Send` (`hunkconn.go:131-141`), so the peer's
        // reads see the same boundaries ours did.
        this.pending_write = Bytes::from(encode_hunk(input));
        if let Poll::Ready(Err(error)) = this.poll_drain_uplink(cx) {
            return Poll::Ready(Err(error));
        }

        // The frame is ours now; whatever the window would not take drains on
        // the next poll.
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_drain_uplink(cx)
    }

    /// Half-closes the call: an empty DATA frame with END_STREAM, and no
    /// reset.
    ///
    /// That is what `CloseSend` puts on the wire, and `HunkReaderWriter.Close`
    /// reaches it with nothing else attached — Xray builds its hunk connection
    /// with a nil cancel function (`dial.go:74`), so the `h.cancel()` branch at
    /// `hunkconn.go:143-146` is dead on the client and the call is never
    /// cancelled, only half-closed.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_uplink(cx))?;

        if !this.send_closed {
            this.uplink
                .send_data(Bytes::new(), true)
                .map_err(|error| h2_io_error("could not half-close the gRPC call", &error))?;
            this.send_closed = true;
        }

        Poll::Ready(Ok(()))
    }
}

/// The direct-mode methods forward to the plain ones, as they do for the
/// WebSocket and HTTPUpgrade adapters: record alignment exists only for
/// Vision, which the compatibility matrix keeps off this transport.
impl TransportStream for GrpcStream {
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
