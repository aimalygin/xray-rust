//! The xdns client as a QUIC carrier's socket: Hysteria and XHTTP over
//! HTTP/3.
//!
//! quic-go sees a masked conn whose don't-fragment bit it cannot set, so
//! its path MTU discovery stays off; the socket reports that datagrams may
//! fragment, which keeps Quinn's off too. Fragmenting is xdns's own: a
//! packet larger than a query's name goes out in several queries.
use super::XdnsClient;
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// A socket over `client` whose packets report `peer` as their source, the
/// address the carrier above it expects.
pub(crate) fn socket(client: Arc<XdnsClient>, peer: SocketAddr) -> Arc<dyn AsyncUdpSocket> {
    Arc::new(XdnsSocket { client, peer })
}

struct XdnsSocket {
    client: Arc<XdnsClient>,
    peer: SocketAddr,
}

impl fmt::Debug for XdnsSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdnsQuicSocket")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Queries never wait: a resolver that cannot take one drops it.
#[derive(Debug)]
struct Ready;

impl UdpPoller for Ready {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for XdnsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Ready)
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|size| transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xdns sends one packet at a time",
            ));
        }
        self.client.send(transmit.contents)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let slots = bufs.len().min(meta.len());
        let mut count = 0;
        let mut next = match self.client.poll_recv(cx) {
            Poll::Ready(Some(packet)) => Some(packet),
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the xdns client stopped",
                )))
            }
            Poll::Pending => return Poll::Pending,
        };
        while let Some(packet) = next.take() {
            // One longer than Quinn's buffer is dropped, as a truncated
            // datagram would be.
            if packet.data.len() <= bufs[count].len() {
                bufs[count][..packet.data.len()].copy_from_slice(&packet.data);
                meta[count] = udp::RecvMeta {
                    addr: self.peer,
                    len: packet.data.len(),
                    stride: packet.data.len().max(1),
                    ecn: None,
                    dst_ip: None,
                };
                count += 1;
            }
            if count < slots {
                next = self.client.try_recv();
            }
        }
        if count == 0 {
            // Everything ready was dropped; wait for more.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(if self.peer.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        })
    }

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

#[cfg(test)]
mod tests;
