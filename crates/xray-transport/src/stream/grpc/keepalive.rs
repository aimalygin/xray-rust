//! The ping loop, and the two pieces of connection state it reads.
//!
//! grpc-go's keepalive goroutine
//! (`grpc@v1.81.0/internal/transport/http2_client.go:1723-1800`) does not ping
//! on a timer. It pings only a connection that is *both* carrying a call and
//! hearing nothing back, and the two suppressions that make that true are the
//! reason this module exists at all: h2 exposes neither the count of open
//! streams nor the time of the last read, so both have to be kept here.
//!
//! Reproducing them matters more for us than it would for an ordinary client.
//! [`super::pool`] deliberately holds one connection open with no call on it
//! between flows, so "no active streams" is the steady state rather than an
//! edge case, and `permitWithoutStream` defaults to false — which means the
//! likeliest keepalive a config asks for, `idleTimeout` on its own, would have
//! us emitting a PING every ten seconds on an idle connection where xray-core
//! emits none. A periodic heartbeat no member of the population sends is
//! exactly the shape a censor watching a link is looking for, and the same
//! goes the other way round for [`LastRead`]: a heartbeat that appears only on
//! a *quiet* connection is a sharper signal than one that appears always.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use h2::Ping;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::{Duration, Instant};

use super::config::GrpcKeepalive;
use crate::BoxedTransportStream;

/// When the peer last put anything on the connection.
///
/// grpc-go keeps the same thing as `t.lastRead` and stamps it on every frame
/// the reader takes off the socket, whatever the frame is — including the ACK
/// to its own ping (`http2_client.go:1663,1671`). That is the whole of how
/// `outstandingPing` is ever cleared: `handlePing` does nothing for an ACK
/// beyond the BDP estimate, so a ping counts as answered because reading the
/// answer counted as activity.
///
/// Held as nanoseconds from the connection's own start rather than as an
/// [`Instant`], because the read path writes it and the ping loop reads it
/// from another task and an `Instant` is not atomic. The origin makes the
/// range a non-question: u64 nanoseconds is 584 years of connection.
///
/// The clock is [`tokio::time::Instant`] rather than [`std::time::Instant`] so
/// that a paused clock moves it, which is what lets the keepalive tests reach
/// a ten-second interval without waiting ten seconds.
#[derive(Debug)]
pub(super) struct LastRead {
    opened: Instant,
    nanos_since_opened: AtomicU64,
}

impl LastRead {
    fn new() -> Self {
        Self {
            opened: Instant::now(),
            nanos_since_opened: AtomicU64::new(0),
        }
    }

    /// Records that the peer has just spoken.
    ///
    /// `Relaxed` because the ping loop wants the value and nothing else: there
    /// is no other write it has to be ordered against, and a stamp one poll
    /// stale can only delay a ping by the length of one read.
    fn mark(&self) {
        let elapsed = self.opened.elapsed().as_nanos();
        self.nanos_since_opened.store(
            u64::try_from(elapsed).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn at(&self) -> Instant {
        self.opened + Duration::from_nanos(self.nanos_since_opened.load(Ordering::Relaxed))
    }
}

/// The socket, with a stamp taken every time the peer is heard from.
///
/// Wrapping is the only way to see the reads: h2 owns the socket from the
/// handshake onwards and reports nothing about them. `LastRead` is optional so
/// that a connection dialled without keepalive — Xray's default, all three
/// settings off — pays neither the clock read nor the store, which is the same
/// gate grpc-go puts on the two `atomic.StoreInt64` calls
/// (`if t.keepaliveEnabled`).
pub(super) struct WatchedIo {
    io: BoxedTransportStream,
    last_read: Option<Arc<LastRead>>,
}

impl WatchedIo {
    /// Wraps `io`, watching it only if `keepalive` is configured.
    ///
    /// Returns the clock the ping loop reads, or `None` when there is no ping
    /// loop to read it.
    pub(super) fn new(
        io: BoxedTransportStream,
        keepalive: Option<GrpcKeepalive>,
    ) -> (Self, Option<Arc<LastRead>>) {
        let last_read = keepalive.map(|_| Arc::new(LastRead::new()));
        let watched = Self {
            io,
            last_read: last_read.clone(),
        };
        (watched, last_read)
    }
}

impl AsyncRead for WatchedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = output.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, output);
        // Only bytes count. A `Ready(Ok(()))` that filled nothing is the end of
        // the socket, which is the opposite of the peer being alive, and
        // stamping it would hold a dead connection off the ping that is
        // supposed to notice.
        if matches!(polled, Poll::Ready(Ok(()))) && output.filled().len() > before {
            if let Some(last_read) = &self.last_read {
                last_read.mark();
            }
        }
        polled
    }
}

impl AsyncWrite for WatchedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

/// How many gRPC calls are open on one connection.
///
/// grpc-go reads `len(t.activeStreams)` under the transport's mutex and
/// signals `kpDormancyCond` from `initStream` when a stream is created
/// (`http2_client.go:818-821`). The count is kept here for the same reason
/// [`LastRead`] is: h2 tracks its streams but tells nobody how many there are.
#[derive(Debug)]
pub(super) struct OpenCalls {
    state: Mutex<OpenCallsState>,
    opened: Notify,
    changed: Notify,
}

#[derive(Debug)]
struct OpenCallsState {
    open: usize,
    /// `Some` exactly while no call is open. It starts at connection creation
    /// so a successful dial whose callers are all cancelled is retired too.
    idle_since: Option<Instant>,
}

impl Default for OpenCalls {
    fn default() -> Self {
        Self {
            state: Mutex::new(OpenCallsState {
                open: 0,
                idle_since: Some(Instant::now()),
            }),
            opened: Notify::new(),
            changed: Notify::new(),
        }
    }
}

impl OpenCalls {
    fn state(&self) -> MutexGuard<'_, OpenCallsState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Counts one call in until the returned guard is dropped.
    ///
    /// A guard rather than a pair of calls because the decrement has to happen
    /// on every way out of a call, and a `GrpcStream` has several — a peer's
    /// reset, a relay dropping it mid-transfer, and the ordinary half-close
    /// all end at the same `drop`.
    pub(super) fn open(self: &Arc<Self>) -> OpenCall {
        {
            let mut state = self.state();
            state.open += 1;
            state.idle_since = None;
        }
        // `notify_one` rather than `notify_waiters` so that a call opening in
        // the gap between the loop's count check and its park is not lost: a
        // permit with no waiter is kept, and the park consumes it.
        self.opened.notify_one();
        // The idle waiter may be sleeping until the old idle deadline. A call
        // invalidates that deadline immediately.
        self.changed.notify_one();
        OpenCall(Arc::clone(self))
    }

    fn close(&self) {
        {
            let mut state = self.state();
            state.open = state
                .open
                .checked_sub(1)
                .expect("every closed gRPC call was opened");
            if state.open == 0 {
                state.idle_since = Some(Instant::now());
            }
        }
        self.changed.notify_one();
    }

    pub(super) fn has_been_idle_for(&self, duration: Duration) -> bool {
        self.state()
            .idle_since
            .is_some_and(|since| Instant::now() >= since + duration)
    }

    /// Waits until the connection has continuously carried no calls for
    /// `duration`. Every transition wakes the waiter so a new call cancels an
    /// old deadline, and the deadline is derived from the recorded transition
    /// rather than from when this task happens to be scheduled.
    pub(super) async fn wait_until_idle_for(&self, duration: Duration) {
        loop {
            // Create the waiter first. `notify_one` retains a permit, so a
            // transition between the state read and the await cannot be lost.
            let changed = self.changed.notified();
            let deadline = self.state().idle_since.map(|since| since + duration);
            let Some(deadline) = deadline else {
                changed.await;
                continue;
            };

            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    if self.has_been_idle_for(duration) {
                        return;
                    }
                }
                () = changed => {}
            }
        }
    }

    /// Parks until at least one call is open.
    ///
    /// The count is re-read after every wake, where grpc-go pings
    /// unconditionally on the far side of its `Wait()`. That is deliberate:
    /// `notify_one` leaves a permit behind when nobody was parked, so a wake
    /// here does not prove a call is open the way a `Signal` under grpc-go's
    /// mutex does, and the failure it would buy is the one this whole module
    /// exists to avoid — a PING on a connection with nothing on it. What it
    /// costs is a ping for a call that opened and closed inside the scheduler's
    /// own latency, which grpc-go would have sent.
    async fn wait_for_one(&self) {
        while self.state().open == 0 {
            self.opened.notified().await;
        }
    }
}

/// One open call, counted for as long as it lives.
#[derive(Debug)]
pub(super) struct OpenCall(Arc<OpenCalls>);

impl Drop for OpenCall {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Everything one connection's ping loop needs.
pub(super) struct Pings {
    pub(super) ping_pong: h2::PingPong,
    pub(super) keepalive: GrpcKeepalive,
    pub(super) last_read: Arc<LastRead>,
    pub(super) calls: Arc<OpenCalls>,
}

impl Pings {
    /// Pings until one goes unacknowledged for longer than `timeout`.
    ///
    /// The body is grpc-go's `case <-timer.C` in its own order, and the order
    /// is load-bearing: a connection the peer is talking on is let off before
    /// the dormancy is even considered, and both come before the send.
    ///
    /// **The wait is until `lastRead + time`, not `time` from here.** grpc-go
    /// rearms its timer for exactly that (`http2_client.go:1750`), so a peer
    /// that spoke one second into a ten-second interval buys nine more seconds
    /// and not nineteen. Sleeping a whole fresh interval instead would let the
    /// heartbeat drift up to twice as far from where grpc-go puts it.
    ///
    /// **A ping is sent the moment dormancy lifts**, without waiting out
    /// another interval: grpc-go's send sits directly under the `Wait()` and
    /// the comment between them says both ways in mean the same thing
    /// (`http2_client.go:1779-1792`). So a flow arriving on a connection that
    /// has been idle takes a PING out alongside its HEADERS.
    ///
    /// **One divergence is left, and it is in the acknowledgement.** grpc-go
    /// clears `outstandingPing` from the *read* stamp rather than from the ACK
    /// itself, so a peer that answers no ping but is otherwise still sending
    /// frames keeps its connection; awaiting the pong under a timeout, as this
    /// does, ends it. Closing that gap means driving `send_ping` and
    /// `poll_pong` — both `#[doc(hidden)]` in h2 — by hand for a peer that is
    /// alive and specifically refuses to answer pings, which is not a peer
    /// anything in the population is.
    pub(super) async fn run(mut self) {
        // grpc-go opens with `prevNano = time.Now()`. The stamp is the same
        // instant on a connection nothing has been read on yet, and on one
        // where the server's SETTINGS have already landed it reaches the same
        // first ping — the rearm below targets `lastRead + time` either way.
        let mut previous_read = self.last_read.at();
        loop {
            tokio::time::sleep_until(previous_read + self.keepalive.time).await;

            let last_read = self.last_read.at();
            if last_read > previous_read {
                previous_read = last_read;
                continue;
            }

            if !self.keepalive.permit_without_stream {
                self.calls.wait_for_one().await;
            }

            let pong =
                tokio::time::timeout(self.keepalive.timeout, self.ping_pong.ping(Ping::opaque()));
            if !matches!(pong.await, Ok(Ok(_))) {
                return;
            }
            // The ACK was a read, so this is at least a full interval on from
            // where the loop started: grpc-go reaches the same place in two
            // passes, waking on `min(kp.Time, timeoutLeft)` and then rearming
            // for `lastRead + kp.Time` off the ACK it read in the meantime.
            previous_read = self.last_read.at();
        }
    }
}
