//! The byte stream on top of one gRPC call.
//!
//! Xray's `HunkReaderWriter` turns a bidirectional `Hunk` stream into a
//! `net.Conn` (`Xray-core/transport/internet/grpc/encoding/hunkconn.go:
//! 28-141`), and this is the same adapter over h2: every write becomes one
//! `Hunk`, every read is served out of whatever `Hunk`s have arrived.
//!
//! It is separate from `h2client.rs` because the two have different lifetimes.
//! Everything here runs on every read and every write for the life of a
//! tunnel; next door the handshake runs once per connection and the request
//! once per call, which is the seam the pool splits on — it keeps the
//! connection and repeats the call.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use h2::client::ResponseFuture;
use h2::{RecvStream, SendStream};
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::framing::{encode_hunk, HunkDecoder, HunkMode, MAX_HUNK_PAYLOAD_LEN};
use super::h2client::H2ConnectionDriver;
use super::keepalive::OpenCall;
use crate::{TransportError, TransportStream};

/// Where [`GrpcStream::poll_drain_uplink`] stopped.
enum Uplink {
    /// Everything queued is h2's now.
    Drained,
    /// h2 will take no more. `poll_capacity` reports that only for a send half
    /// that has stopped streaming (`h2-0.4.15/src/proto/streams/send.rs:
    /// 366-369`), and the request went out with `end_of_stream: false`, so
    /// past its HEADERS the only ways there are our own END_STREAM — which
    /// cannot be it while bytes are still queued, since the half-close comes
    /// after the drain — and the stream being gone: reset by the peer, or
    /// taken down with the connection under it.
    Closed,
}

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
    ///
    /// A payload reaches the caller in three copies: h2's `Bytes` into
    /// `HunkDecoder`'s buffer (`framing.rs`, `push`), that buffer into the
    /// `Vec` `parse_hunk` returns, and this into the caller's `ReadBuf`. Two
    /// of the three are avoidable — a decoder holding `Bytes` could slice a
    /// payload that arrived inside a single DATA frame instead of copying it,
    /// and a payload that fits the caller's buffer whole never needs to land
    /// here at all — but both are decoder API changes, and the uplink is the
    /// side a relay's cost sits on. Deferred until there is a benchmark number
    /// to move.
    pending_read: Vec<u8>,
    pending_read_pos: usize,
    /// The encoded `Hunk` that has not been handed to h2 in full yet, because
    /// the flow-control window ran out mid-frame.
    pending_write: Bytes,
    /// The caller's write [`Self::pending_write`] was encoded from, held from
    /// the moment it is encoded until the whole frame is h2's.
    ///
    /// It exists so that [`AsyncWrite::poll_write`] can return `Pending` on a
    /// frame the window will not take yet and still be idempotent when the
    /// caller retries: the retry finds the frame already built and finishes
    /// handing *it* over rather than encoding a second copy of the same bytes.
    ///
    /// h2 grants stream capacity from the connection task, so the grant lands
    /// after the write that reserved it has returned. Reporting such a write
    /// as accepted and leaving its frame queued — which is what this replaced —
    /// is invisible to a caller that writes again, because the next write
    /// drains it, and fatal to one that writes once and then waits for a reply:
    /// nothing else polls the uplink, so the peer never receives the write it
    /// is being waited on for. Every tunnel whose far end speaks first is that
    /// caller, and so is the VLESS request header that
    /// `open_vless_tcp_stream_with_resolver_and_dialer` writes before handing
    /// the stream to the relay (`crates/xray-core-rs/src/outbound.rs`), off
    /// which an Xray inbound dials the target.
    ///
    /// Keeping the count here rather than draining from the read path is what
    /// leaves both halves usable from separate tasks: h2 holds one capacity
    /// waker per send half, so a reader that reserved capacity would overwrite
    /// a writer's and strand it.
    accepted: Option<usize>,
    /// The response HEADERS, held from the moment they arrive.
    ///
    /// h2 hands the block over as the response head and keeps nothing of it,
    /// so by the time the downlink ends there is no way back to it — and for
    /// gRPC's Trailers-Only response this is the block the call's status lives
    /// in. See [`Self::finish_downlink`].
    response_head: Option<HeaderMap>,
    /// The trailing HEADERS, held from the moment they arrive, for the reason
    /// [`Self::response_head`] is: h2 yields the block from `poll_trailers`
    /// once and `None` for ever after (`h2-0.4.15/src/share.rs:425-436`).
    ///
    /// A failed call leaves [`Self::eof`] unset so that a caller which reads
    /// again comes back through [`Self::finish_downlink`], which is only worth
    /// doing if the verdict survives the trip. Without this the second read
    /// finds no ending block at all and reports the peer as having closed the
    /// stream without trailers — a different fault, about a peer that did
    /// nothing of the kind, in place of the `grpc-status` it actually sent.
    trailers: Option<HeaderMap>,
    /// Whether [`Self::response_head`] is the block that *ended* the call: one
    /// header block carrying `:status`, `content-type` and the `grpc-status`,
    /// with no DATA and no trailers behind it.
    ///
    /// Set from `is_end_stream()` when the response arrives, and again from
    /// the reset branch of [`AsyncRead::poll_read`] when a reset got there
    /// first and erased that answer — see
    /// [`Self::the_reset_behind_a_trailers_only_response`].
    head_ended_the_call: bool,
    /// Whether any DATA has arrived on the downlink.
    ///
    /// Read only by [`Self::the_reset_behind_a_trailers_only_response`], which
    /// may stand in for an END_STREAM h2 destroyed evidence of, but only where
    /// the response head is all the peer ever sent.
    downlink_carried_data: bool,
    /// Set once `data()` has yielded `None` and the trailers have said the call
    /// succeeded. Every other way a downlink can end is an error, not this.
    eof: bool,
    send_closed: bool,
    /// Keeps the connection task alive for as long as the call is: h2 reads
    /// and writes nothing unless that task is polled.
    ///
    /// Shared rather than owned, because a pooled connection carries many
    /// calls at once and the last of them to go is not knowable from here.
    driver: Arc<H2ConnectionDriver>,
    /// Keeps the connection's keepalive out of dormancy for as long as this
    /// call is open — see [`super::keepalive`].
    ///
    /// Nothing reads it. It is held because dropping it is the event: every
    /// way a call can end, a peer's reset and a relay dropping the tunnel
    /// mid-transfer included, ends at this struct's own drop.
    _open_call: OpenCall,
}

impl GrpcStream {
    /// `mode` arrives from [`GrpcCall`](super::h2client::GrpcCall) rather than
    /// from the config, so the decoder below is necessarily reading the message
    /// the `:path` in that same call asked for.
    pub(super) fn new(
        response: ResponseFuture,
        uplink: SendStream<Bytes>,
        mode: HunkMode,
        driver: Arc<H2ConnectionDriver>,
        open_call: OpenCall,
    ) -> Self {
        Self {
            downlink: Downlink::Awaiting(response),
            uplink,
            decoder: HunkDecoder::new(mode),
            pending_read: Vec::new(),
            pending_read_pos: 0,
            pending_write: Bytes::new(),
            accepted: None,
            response_head: None,
            trailers: None,
            head_ended_the_call: false,
            downlink_carried_data: false,
            eof: false,
            send_closed: false,
            driver,
            _open_call: open_call,
        }
    }

    /// Whether the connection underneath has ended — a graceful `GOAWAY`
    /// included.
    ///
    /// **A test-only accessor**, like `GrpcTransport::holds_a_live_connection`
    /// next door. Nothing in the crate calls it: the pool asks
    /// `H2Connection::is_live`, which is the same question of the same
    /// `JoinHandle`. It exists because `H2ConnectionDriver` is `pub(crate)`
    /// and the integration tests need some window onto it, and the unpooled
    /// `open_grpc_h2_stream` hands back a `GrpcStream` and nothing
    /// else — which is the only shape in which a peer that answers no ping,
    /// or none at all, can be put in front of the driver.
    ///
    /// Completion is not success, which is why the question is "finished"
    /// rather than "failed": h2 resolves its connection future as `Ok(())`
    /// after a `GOAWAY(NO_ERROR)`
    /// (`h2-0.4.15/src/proto/connection.rs:216-235`), so a pool that retired a
    /// connection only on `Err` would go on handing out a dead one.
    ///
    /// `pub` only because those tests are integration tests and cannot reach a
    /// `pub(crate)`; hidden for the reason its sibling is.
    #[doc(hidden)]
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
    ///
    /// It reports rather than judges a send half that will take no more,
    /// because the two callers answer for it differently: see
    /// [`Self::poll_drain_uplink_for_write`] and
    /// [`Self::poll_drain_uplink_for_end_of_call`].
    fn poll_drain_uplink(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Uplink>> {
        while !self.pending_write.is_empty() {
            self.uplink.reserve_capacity(self.pending_write.len());
            let granted = match ready!(self.uplink.poll_capacity(cx)) {
                Some(Ok(granted)) => granted,
                Some(Err(error)) => return Poll::Ready(Err(h2_io_error("uplink stalled", &error))),
                None => return Poll::Ready(Ok(Uplink::Closed)),
            };

            let take = granted.min(self.pending_write.len());
            self.uplink
                .send_data(self.pending_write.split_to(take), false)
                .map_err(|error| h2_io_error("could not send a Hunk", &error))?;
        }

        Poll::Ready(Ok(Uplink::Drained))
    }

    /// The drain for a caller that still has bytes to deliver.
    ///
    /// A stream that will take no more fails the write, as `hc.Send` does on
    /// Xray's side. Accepting bytes no peer will ever read would lose them
    /// with nothing said, and the relay would go on pumping its source into
    /// the void until the downlink noticed.
    fn poll_drain_uplink_for_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(self.poll_drain_uplink(cx))? {
            Uplink::Drained => Poll::Ready(Ok(())),
            Uplink::Closed => Poll::Ready(Err(protocol_io_error(
                "the gRPC uplink is closed".to_owned(),
            ))),
        }
    }

    /// The drain for the two calls that end the tunnel, where a stream the
    /// peer already took away is the normal end of a call — see
    /// [`AsyncWrite::poll_shutdown`]'s doc for whose end that is and why.
    ///
    /// Both of them reach it: `copy_direction` answers EOF with
    /// `writer.flush()` and then `writer.shutdown()` and propagates either
    /// (`crates/xray-core-rs/src/policy.rs:196-200`), and every path through
    /// this adapter runs the drain before it gets anywhere near the half-close
    /// itself. Exempting only the empty END_STREAM DATA frame would leave the
    /// exemption unreachable for any call whose peer stopped reading first —
    /// which is every call an Xray inbound ends, since a peer that has
    /// finished the RPC has long since stopped opening the window.
    ///
    /// Flush is not only an end-of-call caller, so the discard has to hold
    /// mid-relay too: `copy_direction` also flushes at 64 KiB unflushed and
    /// every 2 ms (`policy.rs:212-220`). It does, for a different reason —
    /// mid-stream a send half that will take no more means the stream is gone,
    /// and the very next `poll_write` says so rather than swallowing bytes.
    fn poll_drain_uplink_for_end_of_call(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(self.poll_drain_uplink(cx))? {
            Uplink::Drained => Poll::Ready(Ok(())),
            Uplink::Closed => {
                // Dropped rather than kept: nothing will ever carry them, and
                // a relay's last frame can be a megabyte.
                //
                // **This is the one place a frame leaves the queue unsent, so
                // it is the one place [`Self::accepted`] is void.** The count
                // is cleared here rather than inferred from the emptied queue
                // in `poll_write`, because the queue empties two ways that
                // must not be confused: everything went to h2 — which is what
                // the other drain and the success arm above mean, and which
                // the retry has to *report* — or it was discarded here, which
                // the retry has to re-encode and be refused for. Inferring
                // treats the first as the second and puts a second copy of the
                // caller's bytes on the wire.
                self.pending_write = Bytes::new();
                self.accepted = None;
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Waits for the trailers the end of the h2 stream may have behind it, and
    /// hands them to [`Self::finish_downlink`].
    fn poll_finish_downlink(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Downlink::Reading(recv) = &mut self.downlink else {
            // Unreachable: only the reading arm can report the end of data.
            // `eof` is still set rather than left alone, because the caller
            // treats `Ok(())` with nothing delivered as end of stream and
            // would otherwise spin on this branch forever.
            self.eof = true;
            return Poll::Ready(Ok(()));
        };
        // `poll_trailers` is `#[doc(hidden)]` (`h2-0.4.15/src/share.rs:
        // 425-436`), so an h2 bump can drop it with no deprecation cycle and
        // this will fail to compile rather than misbehave. It is still the
        // only option: the supported `RecvStream::trailers` is `async`, and
        // this is a manual `poll` impl with nowhere to hold the future. If it
        // does go, the replacement is to store a boxed `trailers()` future in
        // `Downlink`.
        let trailers = ready!(recv.poll_trailers(cx))
            .map_err(|error| h2_io_error("could not read the gRPC trailers", &error))?;

        // Kept rather than passed straight on, because this call is the only
        // one that ever yields them — see [`Self::trailers`]. Guarded so that a
        // second pass through here, which finds `None`, cannot erase what the
        // first one took.
        if trailers.is_some() {
            self.trailers = trailers;
        }
        Poll::Ready(self.finish_downlink())
    }

    /// Turns the end of the h2 stream into either EOF or an error.
    ///
    /// Xray's reader draws that line by what `Recv` returns: `io.EOF` — which
    /// grpc-go produces for `grpc-status: 0` — ends the read cleanly, and
    /// anything else becomes "failed to fetch hunk from gRPC tunnel"
    /// (`hunkconn.go:75-89`). A failed call reported as EOF would truncate a
    /// tunnel with no trace.
    ///
    /// **The status comes from whichever header block ended the call.**
    /// Usually that is the trailers, but a call the server ends having sent no
    /// message has no trailers: `writeStatus` finds no headers sent, so it puts
    /// `:status 200`, `content-type` and the `grpc-status` into a single
    /// END_STREAM header block with no DATA behind it — gRPC's Trailers-Only
    /// response (`grpc@v1.81.0/internal/transport/http2_server.go:1082-1093`).
    /// h2 hands that block over as the response head and `poll_trailers` then
    /// yields `None`, which is why [`Self::response_head`] is kept: without it
    /// a `grpc-status: 0` there would read as a call that never said how it
    /// went. An Xray inbound answers this way whenever `Tun` returns having
    /// written nothing — a tunnel whose remote closed without a byte — and,
    /// with `grpc-status: 12`, whenever the `serviceName` does not match the
    /// one it serves.
    ///
    /// grpc-go reads it the same way round, and only that way round:
    /// `operateHeaders` parses `grpc-status` into a block-local variable and
    /// builds the call's status from it only once the block it is holding
    /// carried END_STREAM (`http2_client.go:1499-1506,1618-1627`). A status in
    /// a header block that did *not* end the call is dropped on the `if
    /// !endStream { return }` above it, so the head's status is consulted here
    /// only when the head was the end.
    ///
    /// **A block carrying no status at all is not a clean end.** grpc-go opens
    /// each one at `grpcStatusCode = codes.Unknown` (`http2_client.go:1481`)
    /// and builds the final status from whatever it still holds, so a
    /// status-less end is a non-OK status, and `RecvMsg` hands it to the caller
    /// in place of `io.EOF` (`grpc@v1.81.0/stream.go:1174-1184`).
    ///
    /// **Nor is END_STREAM on a DATA frame with no trailers behind it.**
    /// grpc-go closes such a stream with `codes.Internal`, "server closed the
    /// stream without sending trailers" (`http2_client.go:1244`). A grpc-go
    /// server always sends trailers — `writeStatus` is the only way it ends an
    /// RPC — so this is the pathological path, reached by a peer that is not
    /// one or by one that died mid-response. It is still worth the divergence
    /// from the sibling WebSocket adapter, which does treat a socket closed
    /// without a close frame as an ordinary half-close: a truncated response
    /// that we call success and xray-core calls an error is the kind of
    /// disagreement that gets debugged on someone else's server.
    fn finish_downlink(&mut self) -> io::Result<()> {
        // Checked before the status because it is the more precise complaint:
        // grpc-go turns an EOF inside a message into `io.ErrUnexpectedEOF`
        // rather than letting it pass as the end of the stream
        // (`grpc@v1.81.0/internal/transport/transport.go:360-380`).
        let buffered = self.decoder.buffered_len();
        if buffered != 0 {
            return Err(protocol_io_error(format!(
                "the gRPC stream ended {buffered} bytes into a Hunk"
            )));
        }

        // Both blocks are borrowed out of `self` rather than taken or passed
        // in: an error below leaves `eof` unset, so a caller that reads again
        // comes back through here, and it has to reach the same verdict the
        // second time instead of decaying into the missing-trailers complaint.
        // That holds for an ordinary trailing block only because
        // `poll_finish_downlink` kept it — see [`Self::trailers`].
        let head = self
            .response_head
            .as_ref()
            .filter(|_| self.head_ended_the_call);
        let Some(ending) = self.trailers.as_ref().or(head) else {
            return Err(protocol_io_error(
                "the gRPC server closed the stream without sending trailers".to_owned(),
            ));
        };

        let Some(status) = grpc_status(ending) else {
            return Err(protocol_io_error(
                "the gRPC call ended with no grpc-status".to_owned(),
            ));
        };

        if status != "0" {
            let message = ending
                .get("grpc-message")
                .and_then(|message| message.to_str().ok())
                .unwrap_or("no message");
            return Err(protocol_io_error(format!(
                "the gRPC call failed with status {status}: {message}"
            )));
        }

        self.eof = true;
        Ok(())
    }

    /// Whether this h2 error is the `RST_STREAM` a gRPC server puts *behind* a
    /// Trailers-Only response, rather than a peer taking the stream away
    /// mid-call.
    ///
    /// grpc-go's server sends one whenever it ends an RPC the client has not
    /// half-closed — `rst := s.getState() == streamActive` in `writeStatus`
    /// (`grpc@v1.81.0/internal/transport/http2_server.go:1127-1129`) — and a
    /// relay's uplink stays open for the whole call, so this is the *ordinary*
    /// shape of a Trailers-Only response reaching us, not a rare one. Both the
    /// `serviceName` typo and the remote that closed without a byte arrive
    /// this way.
    ///
    /// The error *code* is deliberately not part of the test, even though
    /// `writeStatus` always uses `ErrCodeNo` and h2 picks NO_ERROR for the
    /// same situation (`h2-0.4.15/src/proto/streams/streams.rs:1601-1619`):
    /// grpc-go ignores it too once the call is over, and answers the same
    /// frames with `io.EOF` whether the reset says NO_ERROR or CANCEL.
    ///
    /// It has to be inferred, because h2 destroys the evidence. The END_STREAM
    /// header block leaves the stream `HalfClosedRemote`; `recv_reset` then
    /// overwrites that with `Closed(Cause::Error(..))`
    /// (`h2-0.4.15/src/proto/streams/state.rs:258-289`). Both frames arrive in
    /// one read, so by the time the response future resolves,
    /// `is_end_stream()` — which is exactly `HalfClosedRemote` with an empty
    /// queue (`recv.rs:633-638`) — already reads false, and the next
    /// `poll_data` fails out of `ensure_recv_open` (`state.rs:433-441`) with
    /// the reset in place of the end of the stream. (When the two frames do
    /// *not* land together, `is_end_stream()` catches the response first and
    /// this never fires.)
    ///
    /// grpc-go loses nothing here because it is frame-driven: `operateHeaders`
    /// has already closed the stream with `io.EOF` and the block's status by
    /// the time the RST_STREAM is parsed (`http2_client.go:1618-1627`), and
    /// `handleRSTStream` then finds either no stream at all or one
    /// `closeStream` returns early on — `swapState(streamDone) == streamDone`
    /// (`http2_client.go:1248-1252`, `:939-946`). Its verdict is whatever the
    /// header block said. Verified against a real grpc-go client fed these
    /// exact frames: `grpc-status: 0` behind a reset is a plain `io.EOF`, and
    /// `grpc-status: 12` is `Unimplemented` with its message.
    ///
    /// **`grpc-status` in the head is the marker, because it is the only thing
    /// that can distinguish the two blocks after the fact.** `writeStatus` is
    /// the sole place grpc-go emits that header and it always ends the stream
    /// there, so a response head carrying one is a trailers block. Without it,
    /// this is a peer that answered and then took the stream away — grpc-go
    /// calls that `codes.Internal`, "stream terminated by RST_STREAM"
    /// (`handleRSTStream`, `http2_client.go:1248-1273`), confirmed against the
    /// same client — and reporting the reset is both the right verdict and the
    /// more useful message. The one shape left over is a peer that puts a
    /// `grpc-status` in a block that did *not* end the call and then resets:
    /// grpc-go fails it, we would read the status, and h2 leaves us no way to
    /// tell it apart. It takes two framing violations at once to get there.
    fn the_reset_behind_a_trailers_only_response(&self, error: &h2::Error) -> bool {
        error.is_reset()
            && error.is_remote()
            && !self.downlink_carried_data
            && self
                .response_head
                .as_ref()
                .is_some_and(|head| grpc_status(head).is_some())
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
                    let (head, body) = response.into_parts();
                    // `is_end_stream()` is exactly "this header block carried
                    // END_STREAM" at this one moment and nowhere later: it is
                    // the recv half being closed *and* nothing queued behind it
                    // (`h2-0.4.15/src/proto/streams/recv.rs:633-638`), and
                    // resolving the response is what took the block off that
                    // queue (`recv.rs:336-346`). A DATA or trailers frame that
                    // has already arrived is still sitting on it, so a head
                    // that did not end the call reads as false even when the
                    // rest of the call is in hand. A `RST_STREAM` that got
                    // here first also reads as false, which is what
                    // `the_reset_behind_a_trailers_only_response` is for.
                    this.head_ended_the_call = body.is_end_stream();
                    this.response_head = Some(head.headers);
                    this.downlink = Downlink::Reading(body);
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
                    this.downlink_carried_data = true;
                }
                Some(Err(error)) => {
                    if !this.the_reset_behind_a_trailers_only_response(&error) {
                        return Poll::Ready(Err(h2_io_error("downlink failed", &error)));
                    }
                    // The reset is all that is left of the peer's END_STREAM,
                    // so it stands in for the `is_end_stream()` it erased.
                    this.head_ended_the_call = true;
                    return Poll::Ready(this.finish_downlink());
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
        // A frame an earlier poll encoded but could not finish handing over
        // goes out before anything else — two `Hunk`s are never interleaved on
        // the wire — and is then reported as the write it was encoded from.
        //
        // `input` is not consulted on this path and does not need to be:
        // `AsyncWrite` callers retry a `Pending` write with the same buffer,
        // and the count that comes back is the one taken from it. Reading the
        // retry's buffer instead would let a caller be told a different number
        // than the frame already on its way carries. A caller that *abandons* a
        // `Pending` write and then writes something else is told the abandoned
        // length — which is inside the unspecified state tokio already
        // documents for a cancelled `write_all`, and is why nothing in this
        // workspace cancels one.
        //
        // The count outlives its frame whenever a flush or a half-close drains
        // it first, and that is precisely when it has to be reported rather
        // than dropped: the drain below then finds nothing to do and this
        // returns the write the flush already sent. An emptied queue is *not*
        // grounds to forget the count and start again — see
        // [`Self::poll_drain_uplink_for_end_of_call`], which clears it on the
        // one path that empties the queue without sending.
        if let Some(accepted) = this.accepted {
            ready!(this.poll_drain_uplink_for_write(cx))?;
            this.accepted = None;
            return Poll::Ready(Ok(accepted));
        }

        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Clamped, not refused and not panicked on: a short write is what
        // `AsyncWrite` is for, `write_all` loops until the tail follows, and
        // nothing has to thread a `Result` back out of the framing. What it
        // keeps off the wire is a `Hunk` past the 4 MiB a stock grpc-go peer
        // will receive — and past what our own decoder accepts — see
        // `MAX_HUNK_PAYLOAD_LEN`. No caller in this crate reaches it, since the
        // relay caps a single write at 1 MiB
        // (`crates/xray-core-rs/src/policy.rs:15`), but that is a property of
        // today's callers rather than of this transport. One that did would see
        // its write split across two `Hunk`s, which is the only framing a peer
        // capped at 4 MiB per message could have taken in the first place.
        let input = &input[..input.len().min(MAX_HUNK_PAYLOAD_LEN)];

        // One write, one `Hunk`: `HunkReaderWriter.Write` hands the whole
        // buffer to a single `Send` (`hunkconn.go:131-141`), so the peer's
        // reads see the same boundaries ours did.
        this.pending_write = Bytes::from(encode_hunk(input));
        this.accepted = Some(input.len());
        // Not reported until the whole frame is h2's. A `Pending` here is the
        // ordinary case rather than the rare one — the connection task assigns
        // the capacity this just reserved, so the grant cannot arrive inside
        // this poll — and returning `Ready` on it would hand the caller a write
        // that is still sitting in this struct. See [`Self::accepted`] for what
        // that costs; the retry lands on the branch above.
        ready!(this.poll_drain_uplink_for_write(cx))?;
        this.accepted = None;
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_drain_uplink_for_end_of_call(cx)
    }

    /// Half-closes the call: an empty DATA frame with END_STREAM, and no
    /// reset.
    ///
    /// That is what `CloseSend` puts on the wire, and `HunkReaderWriter.Close`
    /// reaches it with nothing else attached — Xray builds its hunk connection
    /// with a nil cancel function (`dial.go:74`), so the `h.cancel()` branch at
    /// `hunkconn.go:143-146` is dead on the client and the call is never
    /// cancelled, only half-closed.
    ///
    /// **A stream the peer already reset is a success here, not a failure.**
    /// grpc-go's server sends `RST_STREAM(NO_ERROR)` right behind its trailers
    /// whenever the client has not half-closed first — `rst := s.getState() ==
    /// streamActive` in `writeStatus` (`grpc@v1.81.0/internal/transport/
    /// http2_server.go:1127-1129`) — so every call an Xray inbound ends before
    /// we do leaves nothing to half-close, and h2 answers `send_data` on it
    /// with `UserError::InactiveStreamId`. Xray's own client cannot fail here:
    /// `CloseSend` returns nil unconditionally, "Always return nil" and all
    /// (`grpc@v1.81.0/stream.go:1039-1052`), so `HunkReaderWriter.Close` has no
    /// error to report on this path. Reporting one would fail a completed
    /// tunnel — `relay_bidirectional` propagates a shutdown error and aborts
    /// its select, dropping a downlink still draining into the local socket.
    /// That covers the drain this starts with as much as the half-close it
    /// ends with — `poll_drain_uplink_for_end_of_call` is where a call that
    /// stalled mid-frame is let through.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_uplink_for_end_of_call(cx))?;

        if !this.send_closed {
            if let Err(error) = this.uplink.send_data(Bytes::new(), true) {
                // Which failure this was is asked of the stream, not of the
                // error: h2 keeps `Error::Kind` private and offers no accessor
                // for the `UserError` inside it, while `reason`, `is_reset`
                // and `is_io` all answer for a *received frame* rather than a
                // user error (`h2-0.4.15/src/error.rs:20-64`). `poll_reset`
                // asks the question directly — it yields the reason a closed
                // stream carries and stays `Pending` while the stream is still
                // streaming (`h2-0.4.15/src/proto/streams/state.rs:446-461`) —
                // which is exactly the line between "the peer took the stream
                // away", the normal end of a call, and "we asked for something
                // illegal", which must keep surfacing. The pre-check is the
                // wrong way round on purpose: it would register a waker on
                // every clean shutdown to catch a case that never happened.
                if this.uplink.poll_reset(cx).is_pending() {
                    return Poll::Ready(Err(h2_io_error(
                        "could not half-close the gRPC call",
                        &error,
                    )));
                }
            }
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
