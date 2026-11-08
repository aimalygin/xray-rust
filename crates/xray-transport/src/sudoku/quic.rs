//! The sudoku mask on a QUIC carrier's socket: Hysteria and XHTTP over
//! HTTP/3.
//!
//! Each QUIC packet is encoded on its own and grows at least fourfold, which
//! only IP fragmentation carries past the path MTU. quic-go writes to the
//! masked conn Xray-core gives it, whose don't-fragment bit it cannot set,
//! so the system fragments. Quinn sets that bit on its sockets, so the
//! carrier clears it again. The socket then reports that datagrams may
//! fragment, which turns Quinn's path MTU discovery off, as quic-go's is
//! off on a masked conn.
use super::{datagram::DatagramMask, SudokuConfig};
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use std::{
    collections::VecDeque,
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
};

#[cfg(test)]
mod tests;

/// Xray's `readBuf`: the most one read brings.
const RECEIVE_BUFFER: usize = 65_535;

/// Wraps `inner`, which carries datagrams four or more times the size of
/// the QUIC packets above.
pub(crate) fn wrap(
    inner: Arc<dyn AsyncUdpSocket>,
    config: &SudokuConfig,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    Ok(Arc::new(SudokuSocket {
        inner,
        mask: DatagramMask::new(config)?,
        receive: Mutex::new(Receive {
            buffer: vec![0; RECEIVE_BUFFER].into_boxed_slice(),
            decoded: VecDeque::new(),
        }),
    }))
}

struct SudokuSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    mask: DatagramMask,
    receive: Mutex<Receive>,
}

struct Receive {
    buffer: Box<[u8]>,
    /// Datagrams of a GRO batch that found no free slot in Quinn's.
    decoded: VecDeque<(udp::RecvMeta, Vec<u8>)>,
}

impl fmt::Debug for SudokuSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SudokuQuicSocket").finish_non_exhaustive()
    }
}

/// Puts `datagram` in Quinn's next slot, or queues it. One too long for
/// Quinn's buffer is dropped, as a truncated read would be.
fn deliver(
    datagram: &[u8],
    from: udp::RecvMeta,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [udp::RecvMeta],
    count: &mut usize,
    queue: &mut VecDeque<(udp::RecvMeta, Vec<u8>)>,
) {
    let slots = bufs.len().min(meta.len());
    if *count < slots {
        if datagram.len() <= bufs[*count].len() {
            bufs[*count][..datagram.len()].copy_from_slice(datagram);
            meta[*count] = udp::RecvMeta {
                len: datagram.len(),
                stride: datagram.len().max(1),
                ..from
            };
            *count += 1;
        }
    } else {
        queue.push_back((from, datagram.to_vec()));
    }
}

impl AsyncUdpSocket for SudokuSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    /// Encodes one QUIC packet afresh, as Xray's `udpConn.WriteTo` does.
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|size| transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sudoku sends one datagram at a time",
            ));
        }
        let datagram = self.mask.encode(transmit.contents);
        self.inner.try_send(&udp::Transmit {
            contents: &datagram,
            segment_size: None,
            ..*transmit
        })
    }

    /// Decodes each datagram the carrier brings, a GRO batch datagram by
    /// datagram, and drops one that does not decode whole.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut receive = self.receive.lock().unwrap_or_else(|e| e.into_inner());
        let Receive { buffer, decoded } = &mut *receive;
        loop {
            let mut count = 0;
            let mut queued = std::mem::take(decoded);
            while let Some((from, datagram)) = queued.pop_front() {
                deliver(&datagram, from, bufs, meta, &mut count, decoded);
            }
            if count > 0 {
                return Poll::Ready(Ok(count));
            }
            let mut raw = [udp::RecvMeta::default()];
            let received = ready!(self.inner.poll_recv(
                cx,
                &mut [IoSliceMut::new(&mut buffer[..])],
                &mut raw
            ))?;
            if received == 0 {
                return Poll::Ready(Ok(0));
            }
            let from = raw[0];
            let stride = from.stride.max(1);
            let mut offset = 0;
            while offset < from.len.min(buffer.len()) {
                let end = (offset + stride).min(from.len).min(buffer.len());
                if let Some(plain) = self.mask.decode(buffer, offset..end) {
                    deliver(&buffer[plain], from, bufs, meta, &mut count, decoded);
                }
                offset = end;
            }
            if count > 0 {
                return Poll::Ready(Ok(count));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// The carrier cleared the don't-fragment bit for this mask.
    fn may_fragment(&self) -> bool {
        true
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// The don't-fragment options: the level, the name and the value that lets
/// the system fragment, for IPv4 and then IPv6.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const FRAGMENTATION: [(libc::c_int, libc::c_int, libc::c_int); 2] = [
    (
        libc::IPPROTO_IP,
        libc::IP_MTU_DISCOVER,
        libc::IP_PMTUDISC_DONT,
    ),
    (
        libc::IPPROTO_IPV6,
        libc::IPV6_MTU_DISCOVER,
        libc::IPV6_PMTUDISC_DONT,
    ),
];
/// Darwin's `IPV6_DONTFRAG` is 62, which `libc` does not name.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) const FRAGMENTATION: [(libc::c_int, libc::c_int, libc::c_int); 2] = [
    (libc::IPPROTO_IP, libc::IP_DONTFRAG, 0),
    (libc::IPPROTO_IPV6, 62, 0),
];

/// Clears the don't-fragment bit Quinn set on `socket`, so the system
/// fragments a datagram longer than the path MTU. `socket` may be a clone of
/// Quinn's: the option belongs to the socket, not to the descriptor.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) fn allow_fragmentation(socket: &std::net::UdpSocket) -> io::Result<()> {
    use crate::socket_options::sys::set_int;
    use std::os::fd::AsRawFd;
    let [v4, v6] = FRAGMENTATION;
    let fd = socket.as_raw_fd();
    if socket.local_addr()?.is_ipv6() {
        set_int(fd, v6.0, v6.1, v6.2)?;
        // A dual-stack socket also carries IPv4, where the option may not
        // apply; Quinn tolerates that the same way.
        let _ = set_int(fd, v4.0, v4.1, v4.2);
        Ok(())
    } else {
        set_int(fd, v4.0, v4.1, v4.2)
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub(crate) fn allow_fragmentation(_: &std::net::UdpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the sudoku UDP mask on QUIC needs IP fragmentation, which this platform cannot allow",
    ))
}
