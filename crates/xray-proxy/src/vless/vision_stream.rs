use std::cmp;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{unpad_vision_block, VisionCommand, VisionError, VisionPadding};

const HEADER_LEN: usize = 5;
const USER_ID_LEN: usize = 16;
const MAX_CONTENT_LEN: usize = u16::MAX as usize;
const READ_CHUNK_LEN: usize = 8 * 1024;

pub struct VisionStream<S> {
    inner: S,
    user_id: [u8; USER_ID_LEN],
    padding: VisionPadding,
    pending_write: BytesMut,
    pending_write_len: usize,
    raw_read: BytesMut,
    decoded_read: BytesMut,
    inbound_user_id_seen: bool,
    inner_eof: bool,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S, user_id: [u8; USER_ID_LEN], seed: [u32; 4]) -> Self {
        Self {
            inner,
            user_id,
            padding: VisionPadding::new(user_id, seed),
            pending_write: BytesMut::new(),
            pending_write_len: 0,
            raw_read: BytesMut::new(),
            decoded_read: BytesMut::new(),
            inbound_user_id_seen: false,
            inner_eof: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    fn fill_output(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let len = cmp::min(output.remaining(), self.decoded_read.len());
        if len == 0 {
            return false;
        }

        output.put_slice(&self.decoded_read.split_to(len));
        true
    }

    fn decode_next_frame(&mut self) -> io::Result<bool> {
        let Some(frame_len) = self.next_frame_len()? else {
            return Ok(false);
        };

        let frame = self.raw_read.split_to(frame_len);
        let unpadded = unpad_vision_block(&frame, &self.user_id).map_err(vision_to_io)?;
        self.inbound_user_id_seen = true;
        self.decoded_read.extend_from_slice(&unpadded.payload);

        Ok(true)
    }

    fn next_frame_len(&self) -> io::Result<Option<usize>> {
        let Some(offset) = self.next_frame_offset() else {
            return Ok(None);
        };

        if self.raw_read.len() < offset + HEADER_LEN {
            return Ok(None);
        }

        VisionCommand::try_from(self.raw_read[offset]).map_err(vision_to_io)?;
        let content_len =
            u16::from_be_bytes([self.raw_read[offset + 1], self.raw_read[offset + 2]]) as usize;
        let padding_len =
            u16::from_be_bytes([self.raw_read[offset + 3], self.raw_read[offset + 4]]) as usize;
        let frame_len = offset + HEADER_LEN + content_len + padding_len;

        if self.raw_read.len() < frame_len {
            return Ok(None);
        }

        Ok(Some(frame_len))
    }

    fn next_frame_offset(&self) -> Option<usize> {
        if self.raw_read.is_empty() {
            return None;
        }

        if self.inbound_user_id_seen {
            return Some(0);
        }

        if self.raw_read.len() < USER_ID_LEN {
            if self.user_id.starts_with(&self.raw_read) {
                return None;
            }

            return Some(0);
        }

        if self.raw_read[..USER_ID_LEN] == self.user_id {
            Some(USER_ID_LEN)
        } else {
            Some(0)
        }
    }
}

impl<S> VisionStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_write.is_empty() {
            let written =
                std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending_write))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write vision frame",
                )));
            }

            self.pending_write.advance(written);
        }

        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for VisionStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fill_output(output) || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.decode_next_frame()? {
                if this.fill_output(output) || output.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            if this.inner_eof {
                return Poll::Ready(Ok(()));
            }

            let mut bytes = [0; READ_CHUNK_LEN];
            let mut read_buf = ReadBuf::new(&mut bytes);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        this.inner_eof = true;
                        if this.raw_read.is_empty() {
                            return Poll::Ready(Ok(()));
                        }

                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete vision frame",
                        )));
                    }

                    this.raw_read.extend_from_slice(filled);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for VisionStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.pending_write.is_empty() {
            std::task::ready!(this.poll_drain_pending(cx))?;
        }

        if this.pending_write_len != 0 {
            let accepted_len = this.pending_write_len;
            this.pending_write_len = 0;
            return Poll::Ready(Ok(accepted_len));
        }

        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let accepted_len = cmp::min(input.len(), MAX_CONTENT_LEN);
        let payload = BytesMut::from(&input[..accepted_len]);
        let padded = this
            .padding
            .pad(payload, VisionCommand::Continue, 0)
            .map_err(vision_to_io)?;
        this.pending_write.extend_from_slice(&padded);
        this.pending_write_len = accepted_len;

        std::task::ready!(this.poll_drain_pending(cx))?;

        let accepted_len = this.pending_write_len;
        this.pending_write_len = 0;
        Poll::Ready(Ok(accepted_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn vision_to_io(error: VisionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
