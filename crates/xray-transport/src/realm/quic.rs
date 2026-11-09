//! The realm socket under a QUIC carrier. It may be dual-stack, its peer
//! of another family than the server's address the connection is dialed
//! to, so Quinn sees it as a socket of the server address's family: IPv4
//! destinations go out IPv4-mapped where the socket is IPv6, and sources
//! come back in their canonical form for the carrier socket to match.
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// `inner`, a quinn-wrapped realm socket, for a connection to
/// `logical_peer`.
pub(crate) fn wrap(
    inner: Arc<dyn AsyncUdpSocket>,
    logical_peer: SocketAddr,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let local = inner.local_addr()?;
    Ok(Arc::new(RealmQuicSocket {
        inner,
        socket_ipv6: local.is_ipv6(),
        report_ipv6: logical_peer.is_ipv6(),
    }))
}

struct RealmQuicSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    socket_ipv6: bool,
    report_ipv6: bool,
}

impl fmt::Debug for RealmQuicSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealmQuicSocket")
            .field("socket_ipv6", &self.socket_ipv6)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for RealmQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        match transmit.destination {
            SocketAddr::V4(v4) if self.socket_ipv6 => self.inner.try_send(&udp::Transmit {
                destination: SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
                src_ip: None,
                ..*transmit
            }),
            _ => self.inner.try_send(transmit),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for meta in &mut meta[..count] {
            meta.addr = crate::canonicalize_socket_addr(meta.addr);
            meta.dst_ip = meta.dst_ip.map(|ip| ip.to_canonical());
        }
        Poll::Ready(Ok(count))
    }

    /// The local port in the server address's family, so Quinn neither
    /// maps nor refuses that address.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let port = self.inner.local_addr()?.port();
        Ok(if self.report_ipv6 {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)
        })
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

#[cfg(test)]
mod tests;
