//! One XDRIVE session as a byte stream: Xray-core v26.10.31's `Conn`, in
//! segments or in slots.

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
use super::slots::{SlotReader, SlotReaderShared, SlotStore, SlotTable, SlotWriter};
use super::storage::Storage;
use super::wal::{Cancel, ReaderShared, WalReader, WalWriter};
use crate::TransportStream;

/// How long a stream dropped without a shutdown keeps storing what it had
/// buffered and its end mark. Xray-core's `Close` blocks for as long as
/// that takes; a drop cannot block, so the work goes on in the background,
/// for this long at most.
const BACKGROUND_CLOSE: Duration = Duration::from_secs(120);

type CloseFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// The written direction: `walWriter` or `slotWriter`.
#[derive(Clone, Debug)]
enum SessionWriter {
    Segments(WalWriter),
    Slots(SlotWriter),
}

impl SessionWriter {
    fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            Self::Segments(writer) => writer.poll_write(cx, data),
            Self::Slots(writer) => writer.poll_write(cx, data),
        }
    }

    async fn close(&self) -> io::Result<()> {
        match self {
            Self::Segments(writer) => writer.close().await,
            Self::Slots(writer) => writer.close().await,
        }
    }
}

/// The read direction's error and wake: `walReader`'s or `slotReader`'s.
#[derive(Debug)]
enum SessionReader {
    Segments(Arc<ReaderShared>),
    Slots(Arc<SlotReaderShared>),
}

impl SessionReader {
    fn error(&self) -> Option<io::Error> {
        match self {
            Self::Segments(reader) => reader.error(),
            Self::Slots(reader) => reader.error(),
        }
    }

    fn wake(&self) {
        match self {
            Self::Segments(reader) => reader.wake(),
            Self::Slots(reader) => reader.wake(),
        }
    }
}

/// What a dial needs of a session in slots to announce it after the fact,
/// as Xray-core v26.11.9 does: the first segment, and both directions to fail.
pub(crate) struct Announcer {
    pub first: tokio::sync::oneshot::Receiver<Bytes>,
    writer: SlotWriter,
    reader: Arc<SlotReaderShared>,
}

impl Announcer {
    /// The announcement failed: writes and reads report `error` from now on.
    pub(crate) fn fail(&self, error: String) {
        self.writer.fail(error.clone());
        self.reader.fail(error);
    }
}

/// A session: what is written goes to the storage under one prefix or into
/// one ring, what is read comes from the other.
pub(crate) struct XdriveStream {
    writer: SessionWriter,
    writer_cancel: Cancel,
    chunks: mpsc::Receiver<Bytes>,
    reader: SessionReader,
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
            writer: SessionWriter::Segments(writer),
            writer_cancel,
            chunks,
            reader: SessionReader::Segments(reader),
            reader_cancel,
            read_buf: Bytes::new(),
            closing: None,
            shut: false,
        }
    }

    /// `newSlotConn`: a session that writes the ring `write` and reads `read`.
    #[cfg(test)]
    pub(crate) fn slots(
        store: Arc<dyn SlotStore>,
        write: SlotTable,
        read: SlotTable,
        params: Params,
    ) -> Self {
        Self::slots_announced(store, write, read, params).0
    }

    /// A session in slots whose announcement is still to be stored: the
    /// stream, and what the dial announces it with -- its first segment once
    /// cut, and a way to fail the session should the announcement fail.
    pub(crate) fn slots_announced(
        store: Arc<dyn SlotStore>,
        write: SlotTable,
        read: SlotTable,
        params: Params,
    ) -> (Self, Announcer) {
        let writer_cancel = Cancel::default();
        let reader_cancel = Cancel::default();
        let writer = SlotWriter::new(Arc::clone(&store), write, params, writer_cancel.clone());
        let (chunks, reader) = SlotReader::spawn(store, read, params, reader_cancel.clone());
        let announcer = Announcer {
            first: writer.first_segment(),
            writer: writer.clone(),
            reader: Arc::clone(&reader),
        };
        let stream = Self {
            writer: SessionWriter::Slots(writer),
            writer_cancel,
            chunks,
            reader: SessionReader::Slots(reader),
            reader_cancel,
            read_buf: Bytes::new(),
            closing: None,
            shut: false,
        };
        (stream, announcer)
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
