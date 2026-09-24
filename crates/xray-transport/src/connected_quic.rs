//! Connected UDP for a single QUIC peer on macOS.
//!
//! The connected send path avoids per-packet destination processing. Quinn's
//! UDP receive state still handles ECN, packet metadata, and path MTU discovery.
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::Interest;

pub(crate) fn wrap(socket: UdpSocket, peer: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    // The caller protects the descriptor before opening its route to the peer.
    socket.connect(peer)?;
    let inner = udp::UdpSocketState::new((&socket).into())?;
    let options = socket2::SockRef::from(&socket);
    let traffic_class = if peer.is_ipv6() {
        options.tclass_v6()?
    } else {
        options.tos_v4()?
    };
    Ok(Arc::new(ConnectedSocket {
        io: tokio::net::UdpSocket::from_std(socket)?,
        inner,
        peer,
        traffic_class: Mutex::new(traffic_class),
        last_send_error: Mutex::new(None),
    }))
}

#[derive(Debug)]
struct ConnectedSocket {
    io: tokio::net::UdpSocket,
    inner: udp::UdpSocketState,
    peer: SocketAddr,
    // Serialize the cached ECN option and its send; concurrent callers cannot
    // change a packet's marking between setsockopt and send. Preserve DSCP bits.
    traffic_class: Mutex<u32>,
    last_send_error: Mutex<Option<Instant>>,
}

impl AsyncUdpSocket for ConnectedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller {
            socket: self,
            ready: None,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.peer
            || transmit
                .segment_size
                .is_some_and(|size| size == 0 || transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "single-peer socket requires one datagram to its connected peer",
            ));
        }
        if let Some(source) = transmit.src_ip {
            if source != self.io.local_addr()?.ip() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "source address differs from connected UDP route",
                ));
            }
        }
        let mut traffic_class = self.traffic_class.lock().unwrap_or_else(|e| e.into_inner());
        self.io.try_io(Interest::WRITABLE, || {
            let marking = transmit.ecn.map_or(0, |ecn| ecn as u32);
            let desired = (*traffic_class & !3) | marking;
            let socket = socket2::SockRef::from(&self.io);
            if desired != *traffic_class {
                if self.peer.is_ipv6() {
                    socket.set_tclass_v6(desired)?;
                } else {
                    socket.set_tos_v4(desired)?;
                }
                *traffic_class = desired;
            }
            // Match Quinn UDP: failed datagrams are loss, not a connection
            // failure. In particular a PMTU probe may exceed the route's MTU.
            // WouldBlock still clears Tokio readiness and schedules a retry.
            loop {
                match socket.send(transmit.contents) {
                    Ok(sent) if sent == transmit.contents.len() => return Ok(()),
                    Ok(_) => return Ok(()), // A partial datagram is lost.
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
                    Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => return Ok(()),
                    Err(error) => {
                        let now = Instant::now();
                        let mut last = self.last_send_error.lock().unwrap_or_else(|e| e.into_inner());
                        if last.is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(60)) {
                            tracing::warn!(%error, peer = %self.peer, "connected QUIC UDP send failed");
                            *last = Some(now);
                        }
                        return Ok(());
                    }
                }
            }
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::HostUnreachable
                            | io::ErrorKind::NetworkUnreachable
                    ) =>
                {
                    continue
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

type Writable = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;
struct Poller {
    socket: Arc<ConnectedSocket>,
    ready: Option<Writable>,
}
impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectedUdpPoller")
            .field("peer", &self.socket.peer)
            .finish_non_exhaustive()
    }
}
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.ready.is_none() {
            let socket = this.socket.clone();
            this.ready = Some(Box::pin(async move { socket.io.writable().await }));
        }
        match this.ready.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.ready = None;
                Poll::Ready(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::Runtime;
    use std::future::poll_fn;

    #[tokio::test]
    async fn rejected_mtu_probe_does_not_close_connected_socket() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = peer_socket.local_addr().unwrap();
            let local = UdpSocket::bind("127.0.0.1:0").unwrap();
            local.set_nonblocking(true).unwrap();
            let socket = wrap(local, peer).unwrap();
            let mut poller = socket.clone().create_io_poller();
            let oversized = vec![0; 65_536];
            for payload in [oversized.as_slice(), b"after MTU rejection".as_slice()] {
                let transmit = udp::Transmit {
                    destination: peer,
                    ecn: None,
                    contents: payload,
                    segment_size: None,
                    src_ip: None,
                };
                loop {
                    match socket.try_send(&transmit) {
                        Ok(()) => break,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            poll_fn(|cx| poller.as_mut().poll_writable(cx))
                                .await
                                .unwrap();
                        }
                        Err(error) => panic!("a rejected UDP probe must remain nonfatal: {error}"),
                    }
                }
            }
            let mut bytes = [0; 128];
            let (n, from) = peer_socket.recv_from(&mut bytes).await.unwrap();
            assert_eq!(from, socket.local_addr().unwrap());
            assert_eq!(&bytes[..n], b"after MTU rejection");
        })
        .await
        .unwrap();
    }

    async fn marking_roundtrip(bind: &str) {
        let server = UdpSocket::bind(bind).unwrap();
        server.set_nonblocking(true).unwrap();
        let peer = server.local_addr().unwrap();
        let server = quinn::TokioRuntime.wrap_udp_socket(server).unwrap();
        let client = UdpSocket::bind(bind).unwrap();
        client.set_nonblocking(true).unwrap();
        let inspect = client.try_clone().unwrap();
        let options = socket2::SockRef::from(&inspect);
        if peer.is_ipv6() {
            options.set_tclass_v6(0x28).unwrap();
        } else {
            options.set_tos_v4(0x28).unwrap();
        }
        let client = wrap(client, peer).unwrap();
        assert_eq!(client.max_transmit_segments(), 1);
        assert!(!client.local_addr().unwrap().ip().is_unspecified());
        let mut poller = client.clone().create_io_poller();
        for marking in [
            Some(udp::EcnCodepoint::Ect0),
            None,
            Some(udp::EcnCodepoint::Ect1),
            Some(udp::EcnCodepoint::Ce),
            None,
        ] {
            let transmit = udp::Transmit {
                destination: peer,
                ecn: marking,
                contents: b"verified connected UDP",
                segment_size: None,
                src_ip: Some(client.local_addr().unwrap().ip()),
            };
            loop {
                match client.try_send(&transmit) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        poll_fn(|cx| poller.as_mut().poll_writable(cx))
                            .await
                            .unwrap()
                    }
                    Err(e) => panic!("connected send failed: {e}"),
                }
            }
            let mut bytes = [0; 2048];
            let mut bufs = [IoSliceMut::new(&mut bytes)];
            let mut meta = [udp::RecvMeta::default()];
            let count = poll_fn(|cx| server.poll_recv(cx, &mut bufs, &mut meta))
                .await
                .unwrap();
            assert_eq!(count, 1);
            assert_eq!(&bufs[0][..meta[0].len], transmit.contents);
            assert_eq!(meta[0].addr, client.local_addr().unwrap());
            assert_eq!(
                meta[0].ecn, marking,
                "per-packet ECN survives connected send"
            );
            let actual = if peer.is_ipv6() {
                options.tclass_v6().unwrap()
            } else {
                options.tos_v4().unwrap()
            };
            assert_eq!(
                actual,
                0x28 | marking.map_or(0, |value| value as u32),
                "DSCP bits survive ECN updates"
            );
        }
        let wrong_peer = SocketAddr::new(peer.ip(), peer.port().wrapping_add(1));
        let mut invalid = udp::Transmit {
            destination: wrong_peer,
            ecn: None,
            contents: b"data",
            segment_size: None,
            src_ip: None,
        };
        assert_eq!(
            client.try_send(&invalid).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        invalid.destination = peer;
        invalid.segment_size = Some(2);
        assert_eq!(
            client.try_send(&invalid).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn connected_ipv4_preserves_payload_ecn_and_dscp() {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            marking_roundtrip("127.0.0.1:0"),
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn connected_ipv6_preserves_payload_ecn_and_dscp() {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            marking_roundtrip("[::1]:0"),
        )
        .await
        .unwrap();
    }
}
