//! Owned codec halves sharing no mutable cryptographic state or record buffers.
use super::stream::{ReadState, WriteState};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Response codec and its read carrier. Cancel the writer if this half fails.
pub struct ClientReadHalf<S> {
    pub(super) inner: S,
    pub(super) state: ReadState,
}
/// Request codec and its write carrier. Shutdown permits the reader to continue.
pub struct ClientWriteHalf<S> {
    pub(super) inner: S,
    pub(super) state: WriteState,
}
impl<S: AsyncRead + Unpin> AsyncRead for ClientReadHalf<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state
            .poll_read(&mut this.inner, cx, out, |_, _| Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ClientWriteHalf<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.state.poll_write(&mut this.inner, cx, data, true)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.poll_flush(&mut this.inner, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.poll_shutdown(&mut this.inner, cx)
    }
}
