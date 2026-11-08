//! A TCP carrier under the sudoku mask, as Xray-core's client wraps it:
//! classic sudoku on the way up, packed on the way down. Every byte passes
//! through it, so Vision's direct mode reads and writes it too.
use super::{
    codec::{Encoder, PackedDecoder},
    table::Table,
    SudokuConfig,
};
use crate::{BoxedTransportStream, TransportStream};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Xray's `ioBufferSize`.
const READ_BUFFER: usize = 32 * 1024;

pub struct SudokuStream {
    inner: BoxedTransportStream,
    tables: Arc<Vec<Table>>,
    encoder: Encoder,
    decoder: PackedDecoder,
    /// One write's encoding, and how much of it went out.
    out: Vec<u8>,
    written: usize,
    /// Decoded bytes, and how many were read.
    pending: Vec<u8>,
    consumed: usize,
    raw: Box<[u8]>,
    eof: bool,
}

impl SudokuStream {
    /// Wraps `inner`, or fails when the settings give no table.
    pub fn new(inner: BoxedTransportStream, config: &SudokuConfig) -> io::Result<Self> {
        let tables = config.tables()?;
        Ok(Self {
            encoder: Encoder::new(tables.clone(), config.padding()),
            tables,
            inner,
            decoder: PackedDecoder::default(),
            out: Vec::new(),
            written: 0,
            pending: Vec::new(),
            consumed: 0,
            raw: vec![0; READ_BUFFER].into_boxed_slice(),
            eof: false,
        })
    }

    /// Writes out what an earlier write encoded.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.out.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SudokuStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.consumed < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.consumed);
                buf.put_slice(&this.pending[this.consumed..this.consumed + n]);
                this.consumed += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            let mut raw = ReadBuf::new(&mut this.raw);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut raw))?;
            let filled = raw.filled().len();
            this.pending.clear();
            this.consumed = 0;
            if filled == 0 {
                this.eof = true;
                this.decoder.reset();
                continue;
            }
            this.decoder
                .decode(&this.tables, &this.raw[..filled], &mut this.pending)?;
        }
    }
}

impl AsyncWrite for SudokuStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.encoder.encode(buf, &mut this.out);
        // The bytes are taken; what the socket cannot take yet goes out on
        // the next write or flush.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl TransportStream for SudokuStream {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

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

#[cfg(test)]
mod tests;
