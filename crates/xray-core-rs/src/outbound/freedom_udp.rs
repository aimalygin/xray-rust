//! The socket of a freedom UDP flow: plain, or under `finalmask.udp` as
//! Xray-core's freedom dials it through `FinalMask.DialUDP`.
use std::mem::MaybeUninit;
use std::task::{ready, Poll};
use std::{io, net::SocketAddr};

use bytes::Bytes;
use tokio::io::ReadBuf;

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

    /// [`Self::recv_from`] into an allocation of the datagram's own size, cut
    /// at `MAX` bytes. A plain socket reads into the stack, so a flow that
    /// waits for its next datagram keeps no buffer; masks read into
    /// `masked_buffer`, allocated on their first datagram.
    pub(crate) async fn recv_datagram<const MAX: usize>(
        &self,
        masked_buffer: &mut Vec<u8>,
    ) -> io::Result<(Bytes, SocketAddr)> {
        match self {
            Self::Plain(socket) => {
                std::future::poll_fn(|cx| {
                    let mut storage = [MaybeUninit::<u8>::uninit(); MAX];
                    let mut buf = ReadBuf::uninit(&mut storage);
                    let source = ready!(socket.poll_recv_from(cx, &mut buf))?;
                    Poll::Ready(Ok((Bytes::copy_from_slice(buf.filled()), source)))
                })
                .await
            }
            Self::Masked(socket) => {
                masked_buffer.resize(MAX, 0);
                let (len, source) = socket.recv(masked_buffer).await?;
                Ok((Bytes::copy_from_slice(&masked_buffer[..len]), source))
            }
        }
    }
}
