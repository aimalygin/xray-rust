//! `header-custom` UDP masks on a QUIC carrier's socket: Hysteria and XHTTP
//! over HTTP/3.
//!
//! Xray-core wraps the packet conn quic-go writes to, one datagram at a
//! time, so this socket sends no GSO batch either. A standalone write holds
//! the datagram back until the reply arrives, as Xray's write blocks; Quinn
//! retries it once the poller wakes.
use super::{
    udp::{UdpHeader, Write},
    HeaderCustomUdpConfig,
};
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};
use tokio::time::{Duration, Instant, Sleep};

#[cfg(test)]
mod tests;

/// A standalone request unanswered this long goes out again. Xray-core's
/// write waits for its reply for good, which would hold every QUIC packet.
pub(crate) const RESEND: Duration = Duration::from_secs(1);

/// One QUIC connection's mask state. A rebound socket keeps it, as Xray's
/// conn sits above the socket.
pub(crate) struct HeaderCustomState {
    inner: Mutex<State>,
}

struct State {
    header: UdpHeader,
    /// When the standalone request being awaited went out.
    requested: Option<Instant>,
    /// The pollers waiting for its reply.
    wakers: Vec<Waker>,
}

impl fmt::Debug for HeaderCustomState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderCustomState").finish_non_exhaustive()
    }
}

impl HeaderCustomState {
    pub(crate) fn new(config: Arc<HeaderCustomUdpConfig>) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            inner: Mutex::new(State {
                header: UdpHeader::new(config)?,
                requested: None,
                wakers: Vec::new(),
            }),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl State {
    fn answered(&mut self) {
        self.requested = None;
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }
}

/// Wraps `inner` for datagrams to and from `peer`. `remote` is the address
/// Xray-core writes to, which the metadata and the state use.
pub(crate) fn wrap(
    inner: Arc<dyn AsyncUdpSocket>,
    peer: SocketAddr,
    remote: SocketAddr,
    state: Arc<HeaderCustomState>,
) -> Arc<dyn AsyncUdpSocket> {
    // Go listens on the IPv6 wildcard for either family: a port, and no
    // IPv4 address.
    let local = inner
        .local_addr()
        .ok()
        .map(|local| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), local.port()));
    Arc::new(HeaderSocket {
        inner,
        peer,
        remote,
        local,
        state,
    })
}

struct HeaderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    peer: SocketAddr,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    state: Arc<HeaderCustomState>,
}

impl fmt::Debug for HeaderSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderCustomSocket")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl HeaderSocket {
    /// Takes the prefix off each datagram in place, or the reply a
    /// standalone write awaits, dropping what does not match. A GRO batch
    /// is opened datagram by datagram at its stride.
    fn open(&self, state: &mut State, buffer: &mut [u8], meta: &mut udp::RecvMeta, now: Instant) {
        if meta.addr != self.peer || meta.len > buffer.len() {
            meta.len = 0;
            meta.stride = 1;
            return;
        }
        let stride = meta.stride.max(1);
        let (mut offset, mut written, mut first) = (0, 0, None);
        while offset < meta.len {
            let end = (offset + stride).min(meta.len);
            let limit = end.min(offset.saturating_add(state.header.receive_limit()));
            let waiting = state.header.waiting();
            match state.header.read(&buffer[offset..limit], self.remote, now) {
                Some(start) => {
                    let length = limit - offset - start;
                    buffer.copy_within(offset + start..limit, written);
                    first.get_or_insert(length);
                    written += length;
                }
                None if waiting && !state.header.waiting() => state.answered(),
                None => {}
            }
            offset = end;
        }
        meta.len = written;
        meta.stride = first.unwrap_or(1).max(1);
    }
}

impl AsyncUdpSocket for HeaderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HeaderPoller {
            inner: self.inner.clone().create_io_poller(),
            state: self.state.clone(),
            timer: None,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected header-custom peer",
            ));
        }
        if transmit
            .segment_size
            .is_some_and(|size| transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "header-custom sends one datagram at a time",
            ));
        }
        let now = Instant::now();
        let mut state = self.state.lock();
        if state.requested.is_some_and(|at| now >= at + RESEND) {
            state.header.abandon();
            state.requested = None;
        }
        match state
            .header
            .write(transmit.contents, self.local, self.remote, now)
        {
            Write::Packet(datagram) => self.inner.try_send(&udp::Transmit {
                contents: &datagram,
                segment_size: None,
                ..*transmit
            }),
            Write::Handshake(request) => {
                let sent = self.inner.try_send(&udp::Transmit {
                    destination: transmit.destination,
                    ecn: None,
                    contents: &request,
                    segment_size: None,
                    src_ip: transmit.src_ip,
                });
                if let Err(error) = sent {
                    // Nothing went out, so nothing is awaited.
                    state.header.abandon();
                    return Err(error);
                }
                state.requested = Some(now);
                Err(io::ErrorKind::WouldBlock.into())
            }
            Write::Waiting => Err(io::ErrorKind::WouldBlock.into()),
            // Xray-core drops what it cannot mask; QUIC recovers the loss.
            Write::Drop => Ok(()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
        let now = Instant::now();
        let mut state = self.state.lock();
        for (buffer, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(count) {
            self.open(&mut state, buffer, meta, now);
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

struct HeaderPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    state: Arc<HeaderCustomState>,
    timer: Option<Pin<Box<Sleep>>>,
}

impl fmt::Debug for HeaderPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderCustomPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for HeaderPoller {
    /// Pending while a standalone reply is awaited, until it arrives or the
    /// request is due to go out again.
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let resend = {
            let mut state = this.state.lock();
            let resend = state.requested.map(|at| at + RESEND);
            if resend.is_some() && !state.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                state.wakers.push(cx.waker().clone());
            }
            resend
        };
        if let Some(resend) = resend {
            let timer = this
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(resend)));
            if timer.deadline() != resend {
                timer.as_mut().reset(resend);
            }
            if timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        this.timer = None;
        this.inner.as_mut().poll_writable(cx)
    }
}
