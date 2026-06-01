use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::VisionStreamIo;

const VLESS_VERSION: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseHeaderState {
    Version,
    AddonsLength,
    Addons,
    Done,
}

pub struct VlessResponseStream<S> {
    inner: S,
    state: ResponseHeaderState,
    addons_remaining: usize,
}

impl<S> VlessResponseStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: ResponseHeaderState::Version,
            addons_remaining: 0,
        }
    }

    fn poll_read_one(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let mut byte = [0];
        let mut buffer = ReadBuf::new(&mut byte);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buffer))?;

        if buffer.filled().is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "vless response header ended early",
            )));
        }

        Poll::Ready(Ok(byte[0]))
    }

    fn poll_discard_addons(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        let mut scratch = [0; 64];
        let to_read = self.addons_remaining.min(scratch.len());
        let mut buffer = ReadBuf::new(&mut scratch[..to_read]);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buffer))?;
        let read = buffer.filled().len();

        if read == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "vless response addons ended early",
            )));
        }

        self.addons_remaining -= read;
        if self.addons_remaining == 0 {
            self.state = ResponseHeaderState::Done;
        }

        Poll::Ready(Ok(()))
    }

    fn poll_discard_response_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            match self.state {
                ResponseHeaderState::Version => {
                    let version = ready!(self.poll_read_one(cx))?;
                    if version != VLESS_VERSION {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected vless response version {version}"),
                        )));
                    }
                    self.state = ResponseHeaderState::AddonsLength;
                }
                ResponseHeaderState::AddonsLength => {
                    self.addons_remaining = usize::from(ready!(self.poll_read_one(cx))?);
                    self.state = if self.addons_remaining == 0 {
                        ResponseHeaderState::Done
                    } else {
                        ResponseHeaderState::Addons
                    };
                }
                ResponseHeaderState::Addons => ready!(self.poll_discard_addons(cx))?,
                ResponseHeaderState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S> AsyncRead for VlessResponseStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_discard_response_header(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S> AsyncWrite for VlessResponseStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S> VisionStreamIo for VlessResponseStream<S>
where
    S: VisionStreamIo,
{
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_discard_response_header(cx))?;
        Pin::new(&mut this.inner).poll_read_direct(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown_direct(cx)
    }
}
