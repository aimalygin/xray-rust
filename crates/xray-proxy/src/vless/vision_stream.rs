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
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS_13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

pub trait VisionStreamIo: AsyncRead + AsyncWrite + Unpin {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

impl VisionStreamIo for tokio::io::DuplexStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

impl<T> VisionStreamIo for std::io::Cursor<T>
where
    std::io::Cursor<T>: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

pub struct VisionStream<S> {
    inner: S,
    user_id: [u8; USER_ID_LEN],
    padding: VisionPadding,
    pending_write: BytesMut,
    pending_write_len: usize,
    pending_direct_write_mode: bool,
    pending_end_write_mode: bool,
    raw_read: BytesMut,
    decoded_read: BytesMut,
    inbound_user_id_seen: bool,
    padding_write_mode: bool,
    direct_write_mode: bool,
    padding_read_mode: bool,
    direct_read_mode: bool,
    inner_eof: bool,
    packets_to_filter: usize,
    enable_xtls: bool,
    is_tls12_or_above: bool,
    is_tls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S, user_id: [u8; USER_ID_LEN], seed: [u32; 4]) -> Self {
        Self {
            inner,
            user_id,
            padding: VisionPadding::new(user_id, seed),
            pending_write: BytesMut::new(),
            pending_write_len: 0,
            pending_direct_write_mode: false,
            pending_end_write_mode: false,
            raw_read: BytesMut::new(),
            decoded_read: BytesMut::new(),
            inbound_user_id_seen: false,
            padding_write_mode: true,
            direct_write_mode: false,
            padding_read_mode: true,
            direct_read_mode: false,
            inner_eof: false,
            packets_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
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
        let command = unpadded.command;
        self.filter_tls_packet(&unpadded.payload);
        self.decoded_read.extend_from_slice(&unpadded.payload);
        if matches!(command, VisionCommand::End | VisionCommand::Direct) {
            self.padding_read_mode = false;
            self.direct_read_mode = command == VisionCommand::Direct;
            self.decoded_read.extend_from_slice(&self.raw_read.split());
        }

        Ok(true)
    }

    fn queue_padded_write(&mut self, input: &[u8], command: VisionCommand) -> io::Result<()> {
        let payload = BytesMut::from(input);
        let padded = self
            .padding
            .pad(payload, command, 0)
            .map_err(vision_to_io)?;
        self.pending_write.extend_from_slice(&padded);
        Ok(())
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

    fn filter_tls_packet(&mut self, packet: &[u8]) {
        if self.packets_to_filter == 0 || packet.is_empty() {
            return;
        }

        self.packets_to_filter -= 1;
        if packet.len() >= 6 {
            if packet[..TLS_SERVER_HANDSHAKE_START.len()] == TLS_SERVER_HANDSHAKE_START
                && packet[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
            {
                self.remaining_server_hello =
                    (i32::from(packet[3]) << 8 | i32::from(packet[4])) + HEADER_LEN as i32;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if packet.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = packet[43] as usize;
                    let cipher_offset = 43 + session_id_len + 1;
                    if packet.len() >= cipher_offset + 2 {
                        self.cipher =
                            u16::from_be_bytes([packet[cipher_offset], packet[cipher_offset + 1]]);
                    }
                }
            } else if packet[..TLS_CLIENT_HANDSHAKE_START.len()] == TLS_CLIENT_HANDSHAKE_START
                && packet[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
            {
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let end = cmp::min(self.remaining_server_hello as usize, packet.len());
            self.remaining_server_hello -= packet.len() as i32;
            if packet[..end]
                .windows(TLS_13_SUPPORTED_VERSIONS.len())
                .any(|window| window == TLS_13_SUPPORTED_VERSIONS)
            {
                if self.cipher != 0 && self.cipher != TLS_AES_128_CCM_8_SHA256 {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

impl<S> VisionStream<S>
where
    S: VisionStreamIo,
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

        if self.pending_direct_write_mode {
            std::task::ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.padding_write_mode = false;
            self.direct_write_mode = true;
            self.pending_direct_write_mode = false;
        } else if self.pending_end_write_mode {
            self.padding_write_mode = false;
            self.pending_end_write_mode = false;
        }

        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for VisionStream<S>
where
    S: VisionStreamIo,
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
        if this.direct_read_mode {
            return Pin::new(&mut this.inner).poll_read_direct(cx, output);
        }
        if !this.padding_read_mode {
            return Pin::new(&mut this.inner).poll_read(cx, output);
        }

        loop {
            if this.decode_next_frame()? {
                if this.fill_output(output) || output.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                if this.direct_read_mode {
                    return Pin::new(&mut this.inner).poll_read_direct(cx, output);
                }
                if !this.padding_read_mode {
                    return Pin::new(&mut this.inner).poll_read(cx, output);
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
    S: VisionStreamIo,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.pending_write.is_empty()
            || this.pending_direct_write_mode
            || this.pending_end_write_mode
        {
            std::task::ready!(this.poll_drain_pending(cx))?;
        }

        if this.pending_write_len != 0 {
            let accepted_len = this.pending_write_len;
            this.pending_write_len = 0;
            return Poll::Ready(Ok(accepted_len));
        }

        if this.direct_write_mode {
            return Pin::new(&mut this.inner).poll_write_direct(cx, input);
        }
        if !this.padding_write_mode {
            return Pin::new(&mut this.inner).poll_write(cx, input);
        }

        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let accepted_len = cmp::min(input.len(), MAX_CONTENT_LEN);
        let input = &input[..accepted_len];
        this.filter_tls_packet(input);
        if this.is_tls && is_complete_tls_application_data_records(input) {
            if this.enable_xtls {
                this.queue_padded_write(input, VisionCommand::Direct)?;
                this.pending_direct_write_mode = true;
            } else {
                this.queue_padded_write(input, VisionCommand::End)?;
                this.pending_end_write_mode = true;
            }
        } else if !this.is_tls12_or_above && this.packets_to_filter <= 1 {
            this.queue_padded_write(input, VisionCommand::End)?;
            this.pending_end_write_mode = true;
        } else {
            this.queue_padded_write(input, VisionCommand::Continue)?;
        }
        this.pending_write_len = accepted_len;

        std::task::ready!(this.poll_drain_pending(cx))?;

        let accepted_len = this.pending_write_len;
        this.pending_write_len = 0;
        Poll::Ready(Ok(accepted_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain_pending(cx))?;
        if this.direct_write_mode {
            Pin::new(&mut this.inner).poll_flush_direct(cx)
        } else {
            Pin::new(&mut this.inner).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain_pending(cx))?;
        if this.direct_write_mode {
            Pin::new(&mut this.inner).poll_shutdown_direct(cx)
        } else {
            Pin::new(&mut this.inner).poll_shutdown(cx)
        }
    }
}

fn vision_to_io(error: VisionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn is_complete_tls_application_data_records(input: &[u8]) -> bool {
    let mut offset = 0;
    while offset < input.len() {
        if input.len() - offset < HEADER_LEN {
            return false;
        }
        if input[offset..offset + TLS_APPLICATION_DATA_START.len()] != TLS_APPLICATION_DATA_START {
            return false;
        }

        let record_len = u16::from_be_bytes([input[offset + 3], input[offset + 4]]) as usize;
        offset += HEADER_LEN;
        if input.len() - offset < record_len {
            return false;
        }
        offset += record_len;
    }

    !input.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const USER_ID: [u8; USER_ID_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[tokio::test]
    async fn reads_raw_bytes_after_direct_block() {
        let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
        let direct = padding
            .pad(BytesMut::from(&b"padded"[..]), VisionCommand::Direct, 0)
            .unwrap();
        let mut stream = VisionStream::new(
            std::io::Cursor::new([direct.to_vec(), b"raw".to_vec()].concat()),
            USER_ID,
            [0, 0, 0, 0],
        );
        let mut output = Vec::new();

        stream.read_to_end(&mut output).await.unwrap();

        assert_eq!(output, b"paddedraw");
    }
}
