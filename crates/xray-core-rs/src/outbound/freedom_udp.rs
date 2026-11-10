//! The socket of a freedom UDP flow: plain, or under `finalmask.udp` as
//! Xray-core's freedom dials it through `FinalMask.DialUDP`.
use std::{io, net::SocketAddr};

/// A freedom UDP flow's socket. Under masks it sends only to the flow's
/// destination, the address the masks were opened for, and takes replies
/// only from it.
#[derive(Debug)]
pub(crate) enum FreedomUdpSocket {
    Plain(tokio::net::UdpSocket),
    Masked(xray_transport::MaskedUdpSocket),
}

impl FreedomUdpSocket {
    /// Sends `payload` to `target`, through the masks when there are any.
    pub(crate) async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Plain(socket) => socket.send_to(payload, target).await,
            Self::Masked(socket) if socket.peer() == target => {
                socket.send(payload).await.map(|()| payload.len())
            }
            Self::Masked(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a masked freedom flow sends only to its destination",
            )),
        }
    }

    /// Receives the next datagram with its sender, unmasked when there are
    /// masks. Cancel-safe, as a socket's receive is.
    pub(crate) async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Plain(socket) => socket.recv_from(buf).await,
            Self::Masked(socket) => socket.recv(buf).await,
        }
    }
}
