//! One XDRIVE session as a byte stream: Xray-core v26.10.31's `Conn`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::params::Params;
use super::storage::Storage;
use super::wal::{Cancel, ReaderShared, WalReader, WalWriter};
use crate::TransportStream;

/// How long a stream dropped without a shutdown keeps storing what it had
/// buffered and its end mark. Xray-core's `Close` blocks for as long as
/// that takes; a drop cannot block, so the work goes on in the background,
/// for this long at most.
const BACKGROUND_CLOSE: Duration = Duration::from_secs(120);

type CloseFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// A session: what is written goes to the storage under one prefix, what is
/// read comes from under the other.
pub(crate) struct XdriveStream {
    writer: WalWriter,
    writer_cancel: Cancel,
    chunks: mpsc::Receiver<Bytes>,
    reader: Arc<ReaderShared>,
    reader_cancel: Cancel,
    read_buf: Bytes,
    /// The shutdown under way, until it is done.
    closing: Option<CloseFuture>,
    shut: bool,
}

impl XdriveStream {
    /// `newConn`: a session that writes `write_prefix` and reads `read_prefix`.
    pub(crate) fn new(
        storage: Arc<dyn Storage>,
        write_prefix: String,
        read_prefix: String,
        params: Params,
    ) -> Self {
        let writer_cancel = Cancel::default();
        let reader_cancel = Cancel::default();
        let writer = WalWriter::new(
            Arc::clone(&storage),
            write_prefix,
            params,
            writer_cancel.clone(),
        );
        let (chunks, reader) =
            WalReader::spawn(storage, read_prefix, params, reader_cancel.clone());
        Self {
            writer,
            writer_cancel,
            chunks,
            reader,
            reader_cancel,
            read_buf: Bytes::new(),
            closing: None,
            shut: false,
        }
    }
}

impl AsyncRead for XdriveStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.read_buf.is_empty() {
            match this.chunks.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => this.read_buf = chunk,
                Poll::Ready(None) => {
                    return Poll::Ready(match this.reader.error() {
                        Some(error) => Err(error),
                        None => Ok(()),
                    });
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let size = this.read_buf.len().min(output.remaining());
        output.put_slice(&this.read_buf[..size]);
        this.read_buf.advance(size);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for XdriveStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = this.writer.poll_write(cx, data);
        if let Poll::Ready(Ok(_)) = written {
            this.reader.wake();
        }
        written
    }

    /// Segments go out as the writer's flush loop cuts them, as in
    /// Xray-core, whose connection has no flush either.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Ends the written direction: stores the rest and the end mark. The
    /// read direction goes on until the peer ends its own.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shut {
            return Poll::Ready(Ok(()));
        }
        let writer = this.writer.clone();
        let result = std::task::ready!(this
            .closing
            .get_or_insert_with(|| Box::pin(async move { writer.close().await }))
            .as_mut()
            .poll(cx));
        this.closing = None;
        this.shut = true;
        Poll::Ready(result)
    }
}

impl Drop for XdriveStream {
    fn drop(&mut self) {
        self.reader_cancel.cancel();
        if self.shut {
            self.writer_cancel.cancel();
            return;
        }
        let writer = self.writer.clone();
        let cancel = self.writer_cancel.clone();
        let closing = self.closing.take();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    let close = async move {
                        match closing {
                            Some(closing) => closing.await,
                            None => writer.close().await,
                        }
                    };
                    let _ = tokio::time::timeout(BACKGROUND_CLOSE, close).await;
                    cancel.cancel();
                });
            }
            Err(_) => cancel.cancel(),
        }
    }
}

impl TransportStream for XdriveStream {
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
