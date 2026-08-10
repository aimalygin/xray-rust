//! Bounded HTTP/1.1 wire engine for XHTTP.
//!
//! The high-level XHTTP modes decide request targets, metadata, padding, and
//! connection reuse. This module owns only HTTP/1.1 framing. Its APIs consume
//! a stream while an operation is in flight: cancelling a fixed request or a
//! response-head read therefore drops that connection instead of exposing a
//! partially advanced socket for unsafe reuse. A chunked exchange is split
//! after its complete request head is flushed, allowing upload and response
//! download to progress independently for `stream-up` and `stream-one`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use futures_util::task::AtomicWaker;
use thiserror::Error;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf,
};
use tokio::task::JoinHandle;

use super::super::http_headers::{serialize_request_with_framing, H1BodyFraming, HeaderMap};

/// Go's default `http.Transport` response-head limit.
pub const DEFAULT_MAX_RESPONSE_HEAD_BYTES: usize = 10 << 20;

const IO_BUFFER_BYTES: usize = 8 * 1024;
const MAX_UPLOAD_CHUNK_BYTES: usize = 16 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 4096;
const MAX_TRAILER_BYTES: usize = 64 * 1024;

/// A fully composed XHTTP request head.
///
/// `target` is already escaped and includes any raw query. This engine does
/// not reinterpret it, so metadata and padding placement remain the
/// composer's responsibility.
#[derive(Debug, Clone, Copy)]
pub struct H1Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub host: &'a str,
    pub headers: &'a HeaderMap,
}

/// HTTP/1.1 protocol and I/O failures detected by the XHTTP engine.
#[derive(Debug, Error)]
pub enum H1Error {
    #[error("HTTP/1.1 I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP/1.1 request write failed after {bytes_written} bytes: {source}")]
    RequestWrite {
        bytes_written: usize,
        #[source]
        source: io::Error,
    },
    #[error("invalid HTTP/1.1 response: {0}")]
    InvalidResponse(String),
    #[error("HTTP/1.1 response head exceeded {limit} bytes")]
    ResponseHeadTooLarge { limit: usize },
    #[error("XHTTP HTTP/1.1 server returned status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("HTTP/1.1 response-head limit must be non-zero")]
    ZeroResponseHeadLimit,
}

/// Writes and flushes a fixed-length request without waiting for its response.
///
/// Returning a [`PendingResponse`] lets XHTTP expose a deferred downlink as
/// soon as the request is on the wire. The stream stays owned throughout: if
/// this future is cancelled during a partial write, the connection is dropped
/// rather than becoming eligible for reuse in an ambiguous state.
pub async fn start_fixed_request<S>(
    mut stream: S,
    request: &H1Request<'_>,
    body: &[u8],
) -> Result<PendingResponse<S>, H1Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Go's transferWriter sends an explicit zero Content-Length for every
    // empty identity request except GET and HEAD. XHTTP permits arbitrary
    // uplink methods, so limiting this to the usual body-carrying methods
    // changes DELETE/OPTIONS/custom requests on the wire.
    let framing = if body.is_empty() && matches!(request.method, "GET" | "HEAD") {
        H1BodyFraming::None
    } else {
        H1BodyFraming::ContentLength(body.len() as u64)
    };
    let head = serialize_request_with_framing(
        request.method,
        request.target,
        request.host,
        request.headers,
        framing,
    );
    let mut bytes_written = 0;
    write_all_counted(&mut stream, &head, &mut bytes_written)
        .await
        .map_err(|source| H1Error::RequestWrite {
            bytes_written,
            source,
        })?;
    write_all_counted(&mut stream, body, &mut bytes_written)
        .await
        .map_err(|source| H1Error::RequestWrite {
            bytes_written,
            source,
        })?;
    stream
        .flush()
        .await
        .map_err(|source| H1Error::RequestWrite {
            bytes_written,
            source,
        })?;

    Ok(PendingResponse::new(stream)
        .for_request_method(request.method)
        .allow_reuse(request_allows_reuse(request.headers)))
}

async fn write_all_counted<W>(
    writer: &mut W,
    mut input: &[u8],
    bytes_written: &mut usize,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while !input.is_empty() {
        let written = writer.write(input).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write the complete HTTP/1.1 request",
            ));
        }
        *bytes_written = bytes_written.checked_add(written).ok_or_else(|| {
            io::Error::other("HTTP/1.1 request write progress counter overflowed")
        })?;
        input = &input[written..];
    }
    Ok(())
}

/// Writes a fixed-length request and opens its status-200 response body.
///
/// The stream is owned by the future. If the future is cancelled during a
/// partial write or response-head read, the stream is dropped and cannot be
/// accidentally returned to a packet-upload pool in an ambiguous state.
pub async fn send_fixed_request<S>(
    stream: S,
    request: &H1Request<'_>,
    body: &[u8],
) -> Result<H1ResponseBody<S>, H1Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    start_fixed_request(stream, request, body)
        .await?
        .open()
        .await
}

/// Starts a chunked request and returns independently pollable upload and
/// response halves.
///
/// The request head is completely written and flushed before the split. The
/// response may therefore be opened while [`ChunkedUpload`] is still sending,
/// which is required for a genuinely full-duplex `stream-one` exchange.
pub async fn start_chunked_request<S>(
    mut stream: S,
    request: &H1Request<'_>,
) -> Result<(ChunkedUpload, PendingResponse<ReadHalf<S>>), H1Error>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let head = serialize_request_with_framing(
        request.method,
        request.target,
        request.host,
        request.headers,
        H1BodyFraming::Chunked,
    );
    stream.write_all(&head).await?;
    stream.flush().await?;

    let (reader, writer) = tokio::io::split(stream);
    Ok((
        ChunkedUpload::spawn(writer),
        PendingResponse::new(reader)
            .for_request_method(request.method)
            .allow_reuse(request_allows_reuse(request.headers)),
    ))
}

/// Bounded, cancellation-safe encoder for an HTTP/1.1 chunked request body.
///
/// A bounded duplex pipe transfers accepted bytes to one dedicated encoder
/// task. The task owns the network write half and is never cancelled between
/// partial writes, so cancelling a caller's `write` or `flush` cannot duplicate
/// a chunk prefix or payload. The pipe capacity bounds queued application data
/// to one 16 KiB chunk and preserves normal `AsyncWrite` backpressure.
pub struct ChunkedUpload {
    input: DuplexStream,
    worker: Option<JoinHandle<io::Result<()>>>,
    status: Arc<ChunkWorkerStatus>,
    accepted: u64,
    shutdown_started: bool,
}

impl ChunkedUpload {
    fn spawn<W>(writer: W) -> Self
    where
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (input, worker_input) = tokio::io::duplex(MAX_UPLOAD_CHUNK_BYTES);
        let status = Arc::new(ChunkWorkerStatus::new());
        let worker_status = status.clone();
        let worker = tokio::spawn(async move {
            let result = run_chunk_worker(worker_input, writer, &worker_status).await;
            if let Err(error) = &result {
                worker_status.fail(error);
            }
            worker_status.done.store(true, Ordering::Release);
            worker_status.waker.wake();
            result
        });

        Self {
            input,
            worker: Some(worker),
            status,
            accepted: 0,
            shutdown_started: false,
        }
    }

    fn worker_error(&self) -> Option<io::Error> {
        lock_unpoisoned(&self.status.failure)
            .as_ref()
            .map(ChunkWorkerFailure::to_io_error)
    }

    fn poll_delivery(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.worker_error() {
            return Poll::Ready(Err(error));
        }
        if self.status.delivered.load(Ordering::Acquire) >= self.accepted {
            return Poll::Ready(Ok(()));
        }
        if self.status.done.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/1.1 chunk worker stopped before delivering accepted bytes",
            )));
        }

        self.status.waker.register(cx.waker());
        if let Some(error) = self.worker_error() {
            return Poll::Ready(Err(error));
        }
        if self.status.delivered.load(Ordering::Acquire) >= self.accepted {
            Poll::Ready(Ok(()))
        } else if self.status.done.load(Ordering::Acquire) {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/1.1 chunk worker stopped before delivering accepted bytes",
            )))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for ChunkedUpload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/1.1 chunked upload is shutting down",
            )));
        }
        if let Some(error) = this.worker_error() {
            return Poll::Ready(Err(error));
        }

        match Pin::new(&mut this.input).poll_write(cx, input) {
            Poll::Ready(Ok(written)) => {
                this.accepted = this.accepted.saturating_add(written as u64);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.input).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        this.poll_delivery(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shutdown_started {
            match Pin::new(&mut this.input).poll_shutdown(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => this.shutdown_started = true,
            }
        }

        let Some(worker) = this.worker.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let worker_result = Pin::new(worker).poll(cx);
        match worker_result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                this.worker = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(error)) => {
                this.worker = None;
                Poll::Ready(Err(io::Error::other(format!(
                    "HTTP/1.1 chunk worker failed: {error}"
                ))))
            }
        }
    }
}

impl Drop for ChunkedUpload {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

struct ChunkWorkerStatus {
    delivered: AtomicU64,
    done: AtomicBool,
    failure: Mutex<Option<ChunkWorkerFailure>>,
    waker: AtomicWaker,
}

impl ChunkWorkerStatus {
    fn new() -> Self {
        Self {
            delivered: AtomicU64::new(0),
            done: AtomicBool::new(false),
            failure: Mutex::new(None),
            waker: AtomicWaker::new(),
        }
    }

    fn fail(&self, error: &io::Error) {
        *lock_unpoisoned(&self.failure) = Some(ChunkWorkerFailure {
            kind: error.kind(),
            message: error.to_string(),
        });
    }
}

struct ChunkWorkerFailure {
    kind: io::ErrorKind,
    message: String,
}

impl ChunkWorkerFailure {
    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

async fn run_chunk_worker<W>(
    mut input: DuplexStream,
    mut writer: W,
    status: &ChunkWorkerStatus,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; MAX_UPLOAD_CHUNK_BYTES];
    loop {
        let read = input.read(&mut buffer).await?;
        if read == 0 {
            break;
        }

        let prefix = format!("{read:x}\r\n");
        writer.write_all(prefix.as_bytes()).await?;
        writer.write_all(&buffer[..read]).await?;
        writer.write_all(b"\r\n").await?;
        // Go's Transport wraps request chunks in FlushAfterChunkWriter so a
        // slowly produced upload is visible to the server immediately.
        writer.flush().await?;
        status.delivered.fetch_add(read as u64, Ordering::Release);
        status.waker.wake();
    }

    writer.write_all(b"0\r\n\r\n").await?;
    writer.flush().await?;
    // The terminal chunk closes the HTTP request body, but stream-one still
    // needs the same connection's response half. Go's HTTP transport does not
    // send a TCP FIN after reaching EOF on a request body. Calling
    // `AsyncWrite::shutdown` here did: a Go HTTP/1 server observes that FIN in
    // its background reader, cancels Request.Context, and XHTTP's hub closes
    // the proxied connection while the response is still streaming.
    Ok(())
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// An HTTP/1.1 response whose head has not yet been read.
#[derive(Debug)]
pub struct PendingResponse<R> {
    reader: R,
    max_head_bytes: usize,
    response_to_head: bool,
    request_allows_reuse: bool,
}

impl<R> PendingResponse<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            max_head_bytes: DEFAULT_MAX_RESPONSE_HEAD_BYTES,
            response_to_head: false,
            request_allows_reuse: true,
        }
    }

    /// Overrides the defensive client-side response-head limit.
    ///
    /// XHTTP's `serverMaxHeaderBytes` is deliberately not wired here: that is
    /// an inbound server setting in Xray. Production callers use the Go
    /// Transport-compatible 10 MiB default; this hook also permits focused
    /// low-memory tests and embedding policies.
    pub fn with_response_head_limit(mut self, limit: usize) -> Result<Self, H1Error> {
        if limit == 0 {
            return Err(H1Error::ZeroResponseHeadLimit);
        }
        self.max_head_bytes = limit;
        Ok(self)
    }

    /// Applies request-method response semantics. In particular, a response
    /// to `HEAD` never exposes a body even if the server sends framing fields.
    pub fn for_request_method(mut self, method: &str) -> Self {
        self.response_to_head = method == "HEAD";
        self
    }

    fn allow_reuse(mut self, allow: bool) -> Self {
        self.request_allows_reuse = allow;
        self
    }
}

impl<R> PendingResponse<R>
where
    R: AsyncRead + Unpin,
{
    /// Parses and validates a status-200 response, retaining bytes read past
    /// the header terminator for the body decoder.
    pub async fn open(mut self) -> Result<H1ResponseBody<R>, H1Error> {
        let mut received = Vec::with_capacity(1024);
        let mut consumed_head_bytes = 0usize;
        loop {
            if let Some(position) = find_header_end(&received) {
                let head_bytes = position + 4;
                if consumed_head_bytes
                    .checked_add(head_bytes)
                    .is_none_or(|total| total > self.max_head_bytes)
                {
                    return Err(H1Error::ResponseHeadTooLarge {
                        limit: self.max_head_bytes,
                    });
                }

                let parsed = parse_response_head(&received[..position], self.response_to_head)?;
                if (100..=199).contains(&parsed.status) && parsed.status != 101 {
                    consumed_head_bytes += head_bytes;
                    received.drain(..head_bytes);
                    continue;
                }
                if parsed.status != 200 {
                    return Err(H1Error::UnexpectedStatus {
                        status: parsed.status,
                    });
                }

                let body = received.split_off(head_bytes);
                return Ok(H1ResponseBody::new(
                    self.reader,
                    body,
                    parsed.framing,
                    parsed.reusable && self.request_allows_reuse,
                    parsed.content_encoding,
                ));
            }
            if consumed_head_bytes
                .checked_add(received.len())
                .is_none_or(|total| total >= self.max_head_bytes)
            {
                return Err(H1Error::ResponseHeadTooLarge {
                    limit: self.max_head_bytes,
                });
            }

            let mut chunk = [0u8; IO_BUFFER_BYTES];
            let read = self.reader.read(&mut chunk).await?;
            if read == 0 {
                return Err(H1Error::InvalidResponse(
                    "connection closed before response headers completed".to_owned(),
                ));
            }
            received.extend_from_slice(&chunk[..read]);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedResponseHead {
    status: u16,
    framing: ResponseFraming,
    reusable: bool,
    content_encoding: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseFraming {
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    Size,
    Data { remaining: u64 },
    DataTerminator { matched: u8 },
    Trailers { total: usize, saw_field: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyState {
    ContentLength(u64),
    Chunked(ChunkState),
    CloseDelimited,
    Done { reusable: bool },
}

/// A decoded response body that owns its reader and all over-read bytes.
#[derive(Debug)]
pub struct H1ResponseBody<R> {
    reader: R,
    buffer: Vec<u8>,
    buffer_offset: usize,
    line_buffer: Vec<u8>,
    state: BodyState,
    reusable_when_framed: bool,
    content_encoding: Option<Vec<u8>>,
}

impl<R> H1ResponseBody<R> {
    fn new(
        reader: R,
        buffer: Vec<u8>,
        framing: ResponseFraming,
        reusable_when_framed: bool,
        content_encoding: Option<Vec<u8>>,
    ) -> Self {
        let state = match framing {
            ResponseFraming::ContentLength(0) => BodyState::Done {
                reusable: reusable_when_framed,
            },
            ResponseFraming::ContentLength(length) => BodyState::ContentLength(length),
            ResponseFraming::Chunked => BodyState::Chunked(ChunkState::Size),
            ResponseFraming::CloseDelimited => BodyState::CloseDelimited,
        };
        Self {
            reader,
            buffer,
            buffer_offset: 0,
            line_buffer: Vec::new(),
            state,
            reusable_when_framed,
            content_encoding,
        }
    }

    /// Returns the final response's Content-Encoding value, if present.
    ///
    /// XHTTP only needs this narrow metadata seam to reproduce Go's
    /// transport-controlled gzip decoding. Framing remains owned by this
    /// reader so decoding cannot accidentally expose or reuse the raw socket.
    pub(crate) fn content_encoding(&self) -> Option<&[u8]> {
        self.content_encoding.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, BodyState::Done { .. })
    }

    /// Returns the reader and every byte already read beyond a completely
    /// decoded framed body. The returned buffer precedes the reader and must
    /// be consumed first. A close-delimited response is intentionally never
    /// reusable.
    pub fn into_reusable(mut self) -> Result<(R, Vec<u8>), Self> {
        if self.state != (BodyState::Done { reusable: true }) {
            return Err(self);
        }

        if self.buffer_offset > 0 {
            self.buffer.drain(..self.buffer_offset);
        }
        Ok((self.reader, self.buffer))
    }
}

impl<R> H1ResponseBody<R>
where
    R: AsyncRead + Unpin,
{
    fn unread_buffer(&self) -> &[u8] {
        &self.buffer[self.buffer_offset..]
    }

    fn consume_buffer(&mut self, amount: usize) {
        self.buffer_offset += amount;
        if self.buffer_offset == self.buffer.len() {
            self.buffer.clear();
            self.buffer_offset = 0;
        }
    }

    fn copy_buffered(&mut self, output: &mut ReadBuf<'_>, limit: usize) -> usize {
        let copied = self
            .unread_buffer()
            .len()
            .min(output.remaining())
            .min(limit);
        if copied > 0 {
            output.put_slice(&self.unread_buffer()[..copied]);
            self.consume_buffer(copied);
        }
        copied
    }

    fn poll_fill_buffer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !self.unread_buffer().is_empty() {
            return Poll::Ready(Ok(true));
        }

        let mut scratch = [0u8; IO_BUFFER_BYTES];
        let mut read_buffer = ReadBuf::new(&mut scratch);
        match Pin::new(&mut self.reader).poll_read(cx, &mut read_buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let read = read_buffer.filled().len();
                if read == 0 {
                    return Poll::Ready(Ok(false));
                }
                self.buffer.extend_from_slice(read_buffer.filled());
                Poll::Ready(Ok(true))
            }
        }
    }

    fn poll_line(&mut self, cx: &mut Context<'_>, limit: usize) -> Poll<io::Result<Vec<u8>>> {
        loop {
            while !self.unread_buffer().is_empty() {
                let byte = self.unread_buffer()[0];
                self.consume_buffer(1);
                self.line_buffer.push(byte);

                if self.line_buffer.ends_with(b"\r\n") {
                    if self.line_buffer.len() >= limit {
                        return Poll::Ready(Err(invalid_data("HTTP/1.1 line is too long")));
                    }
                    self.line_buffer.truncate(self.line_buffer.len() - 2);
                    return Poll::Ready(Ok(std::mem::take(&mut self.line_buffer)));
                }
                if self.line_buffer.len() >= limit {
                    return Poll::Ready(Err(invalid_data("HTTP/1.1 line is too long")));
                }
            }

            match self.poll_fill_buffer(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HTTP/1.1 response ended in the middle of a line",
                    )));
                }
                Poll::Ready(Ok(true)) => {}
            }
        }
    }

    fn poll_content_length(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
        remaining: u64,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let copied = self.copy_buffered(output, usize_from_u64(remaining));
        if copied > 0 {
            let remaining = remaining - copied as u64;
            self.state = if remaining == 0 {
                BodyState::Done {
                    reusable: self.reusable_when_framed,
                }
            } else {
                BodyState::ContentLength(remaining)
            };
            return Poll::Ready(Ok(()));
        }

        let wanted = output
            .remaining()
            .min(usize_from_u64(remaining))
            .min(IO_BUFFER_BYTES);
        let mut scratch = [0u8; IO_BUFFER_BYTES];
        let mut read_buffer = ReadBuf::new(&mut scratch[..wanted]);
        match Pin::new(&mut self.reader).poll_read(cx, &mut read_buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let read = read_buffer.filled().len();
                if read == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HTTP/1.1 response body ended before Content-Length",
                    )));
                }
                output.put_slice(read_buffer.filled());
                let remaining = remaining - read as u64;
                self.state = if remaining == 0 {
                    BodyState::Done {
                        reusable: self.reusable_when_framed,
                    }
                } else {
                    BodyState::ContentLength(remaining)
                };
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_close_delimited(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.copy_buffered(output, usize::MAX) > 0 {
            return Poll::Ready(Ok(()));
        }

        let filled_before = output.filled().len();
        match Pin::new(&mut self.reader).poll_read(cx, output) {
            Poll::Ready(Ok(())) if output.filled().len() == filled_before => {
                self.state = BodyState::Done { reusable: false };
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }

    fn poll_chunked(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
        mut chunk_state: ChunkState,
    ) -> Poll<io::Result<()>> {
        loop {
            match chunk_state {
                ChunkState::Size => {
                    let line = match self.poll_line(cx, MAX_CHUNK_LINE_BYTES) {
                        Poll::Pending => {
                            self.state = BodyState::Chunked(chunk_state);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(line)) => line,
                    };
                    let size = parse_chunk_size(&line)?;
                    chunk_state = if size == 0 {
                        ChunkState::Trailers {
                            total: 0,
                            saw_field: false,
                        }
                    } else {
                        ChunkState::Data { remaining: size }
                    };
                }
                ChunkState::Data { remaining } => {
                    if output.remaining() == 0 {
                        self.state = BodyState::Chunked(chunk_state);
                        return Poll::Ready(Ok(()));
                    }

                    let copied = self.copy_buffered(output, usize_from_u64(remaining));
                    if copied > 0 {
                        let remaining = remaining - copied as u64;
                        self.state = if remaining == 0 {
                            BodyState::Chunked(ChunkState::DataTerminator { matched: 0 })
                        } else {
                            BodyState::Chunked(ChunkState::Data { remaining })
                        };
                        return Poll::Ready(Ok(()));
                    }

                    match self.poll_fill_buffer(cx) {
                        Poll::Pending => {
                            self.state = BodyState::Chunked(chunk_state);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "HTTP/1.1 chunk ended before its declared size",
                            )));
                        }
                        Poll::Ready(Ok(true)) => {}
                    }
                }
                ChunkState::DataTerminator { mut matched } => {
                    while matched < 2 {
                        if self.unread_buffer().is_empty() {
                            match self.poll_fill_buffer(cx) {
                                Poll::Pending => {
                                    self.state =
                                        BodyState::Chunked(ChunkState::DataTerminator { matched });
                                    return Poll::Pending;
                                }
                                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                Poll::Ready(Ok(false)) => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "HTTP/1.1 chunk is missing its terminator",
                                    )));
                                }
                                Poll::Ready(Ok(true)) => {}
                            }
                        }

                        let expected = b"\r\n"[matched as usize];
                        let actual = self.unread_buffer()[0];
                        self.consume_buffer(1);
                        if actual != expected {
                            return Poll::Ready(Err(invalid_data(
                                "malformed HTTP/1.1 chunk terminator",
                            )));
                        }
                        matched += 1;
                    }
                    chunk_state = ChunkState::Size;
                }
                ChunkState::Trailers {
                    total,
                    mut saw_field,
                } => {
                    let line = match self.poll_line(cx, MAX_TRAILER_BYTES) {
                        Poll::Pending => {
                            self.state = BodyState::Chunked(chunk_state);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(line)) => line,
                    };
                    let total = total
                        .checked_add(line.len() + 2)
                        .ok_or_else(|| invalid_data("HTTP/1.1 trailers are too large"))?;
                    if total > MAX_TRAILER_BYTES {
                        return Poll::Ready(Err(invalid_data("HTTP/1.1 trailers are too large")));
                    }
                    if line.is_empty() {
                        self.state = BodyState::Done {
                            reusable: self.reusable_when_framed,
                        };
                        return Poll::Ready(Ok(()));
                    }
                    validate_trailer_line(&line, saw_field)?;
                    if !matches!(line.first(), Some(b' ' | b'\t')) {
                        saw_field = true;
                    }
                    chunk_state = ChunkState::Trailers { total, saw_field };
                }
            }
        }
    }
}

impl<R> AsyncRead for H1ResponseBody<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.state {
            BodyState::ContentLength(remaining) => this.poll_content_length(cx, output, remaining),
            BodyState::Chunked(state) => this.poll_chunked(cx, output, state),
            BodyState::CloseDelimited => this.poll_close_delimited(cx, output),
            BodyState::Done { .. } => Poll::Ready(Ok(())),
        }
    }
}

fn parse_response_head(head: &[u8], response_to_head: bool) -> Result<ParsedResponseHead, H1Error> {
    let mut lines = ResponseLines::new(head);
    let status_line = lines
        .next()
        .ok_or_else(|| H1Error::InvalidResponse("missing status line".to_owned()))??;
    let (http_minor, status) = parse_status_line(status_line)?;

    let mut content_lengths: Vec<Vec<u8>> = Vec::new();
    let mut transfer_encodings: Vec<Vec<u8>> = Vec::new();
    let mut connection_values: Vec<Vec<u8>> = Vec::new();
    let mut content_encoding: Option<Vec<u8>> = None;
    let mut current_header: Option<(Vec<u8>, Vec<u8>)> = None;

    for line in lines {
        let line = line?;
        if matches!(line.first(), Some(b' ' | b'\t')) {
            let Some((_, value)) = current_header.as_mut() else {
                return Err(H1Error::InvalidResponse(
                    "header continuation appeared before a field".to_owned(),
                ));
            };
            value.push(b' ');
            let continuation = trim_ascii_whitespace(line);
            if continuation
                .iter()
                .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
            {
                return Err(H1Error::InvalidResponse(
                    "response contains an invalid folded header value".to_owned(),
                ));
            }
            value.extend_from_slice(continuation);
            continue;
        }

        if let Some((name, value)) = current_header.take() {
            collect_framing_header(
                &name,
                &value,
                &mut content_lengths,
                &mut transfer_encodings,
                &mut connection_values,
                &mut content_encoding,
            );
        }
        current_header = Some(parse_header_line(line)?);
    }

    if let Some((name, value)) = current_header {
        collect_framing_header(
            &name,
            &value,
            &mut content_lengths,
            &mut transfer_encodings,
            &mut connection_values,
            &mut content_encoding,
        );
    }

    let content_length = parse_content_lengths(&content_lengths)?;
    let chunked = if http_minor == 0 || transfer_encodings.is_empty() {
        false
    } else {
        if transfer_encodings.len() != 1 || !transfer_encodings[0].eq_ignore_ascii_case(b"chunked")
        {
            return Err(H1Error::InvalidResponse(
                "unsupported Transfer-Encoding in response".to_owned(),
            ));
        }
        true
    };

    let framing = if response_to_head || (100..=199).contains(&status) {
        ResponseFraming::ContentLength(0)
    } else if chunked {
        ResponseFraming::Chunked
    } else if let Some(length) = content_length {
        ResponseFraming::ContentLength(length)
    } else {
        ResponseFraming::CloseDelimited
    };

    let has_close = header_values_contain_token(&connection_values, b"close");
    let has_keep_alive = header_values_contain_token(&connection_values, b"keep-alive");
    let reusable = !matches!(framing, ResponseFraming::CloseDelimited)
        && !has_close
        && (http_minor == 1 || has_keep_alive);

    Ok(ParsedResponseHead {
        status,
        framing,
        reusable,
        content_encoding,
    })
}

fn parse_status_line(line: &[u8]) -> Result<(u8, u16), H1Error> {
    let Some(rest) = line.strip_prefix(b"HTTP/1.") else {
        return Err(H1Error::InvalidResponse(
            "response is not HTTP/1.x".to_owned(),
        ));
    };
    let Some((&minor, rest)) = rest.split_first() else {
        return Err(H1Error::InvalidResponse(
            "truncated HTTP version".to_owned(),
        ));
    };
    if !matches!(minor, b'0' | b'1') || rest.first() != Some(&b' ') {
        return Err(H1Error::InvalidResponse(
            "unsupported HTTP version or malformed status line".to_owned(),
        ));
    }
    let code = rest[1..]
        .split(|byte| *byte == b' ' || *byte == b'\t')
        .next()
        .unwrap_or_default();
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(H1Error::InvalidResponse(
            "status code is not three decimal digits".to_owned(),
        ));
    }
    let status =
        ((code[0] - b'0') as u16) * 100 + ((code[1] - b'0') as u16) * 10 + (code[2] - b'0') as u16;
    Ok((minor - b'0', status))
}

fn parse_header_line(line: &[u8]) -> Result<(Vec<u8>, Vec<u8>), H1Error> {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(H1Error::InvalidResponse(
            "response header is missing `:`".to_owned(),
        ));
    };
    let name = &line[..colon];
    if name.is_empty() || !name.iter().copied().all(valid_header_name_byte) {
        return Err(H1Error::InvalidResponse(
            "response contains an invalid header name".to_owned(),
        ));
    }
    let value = trim_ascii_whitespace(&line[colon + 1..]);
    if value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(H1Error::InvalidResponse(
            "response contains an invalid header value".to_owned(),
        ));
    }
    Ok((name.to_vec(), value.to_vec()))
}

fn collect_framing_header(
    name: &[u8],
    value: &[u8],
    content_lengths: &mut Vec<Vec<u8>>,
    transfer_encodings: &mut Vec<Vec<u8>>,
    connection_values: &mut Vec<Vec<u8>>,
    content_encoding: &mut Option<Vec<u8>>,
) {
    if name.eq_ignore_ascii_case(b"Content-Length") {
        content_lengths.push(trim_ascii_whitespace(value).to_vec());
    } else if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
        transfer_encodings.push(trim_ascii_whitespace(value).to_vec());
    } else if name.eq_ignore_ascii_case(b"Connection") {
        connection_values.push(trim_ascii_whitespace(value).to_vec());
    } else if name.eq_ignore_ascii_case(b"Content-Encoding") && content_encoding.is_none() {
        *content_encoding = Some(trim_ascii_whitespace(value).to_vec());
    }
}

fn header_values_contain_token(values: &[Vec<u8>], wanted: &[u8]) -> bool {
    values.iter().any(|value| {
        value
            .split(|byte| *byte == b',')
            .map(trim_ascii_whitespace)
            .any(|token| token.eq_ignore_ascii_case(wanted))
    })
}

fn request_allows_reuse(headers: &HeaderMap) -> bool {
    !headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case("close"))
}

fn parse_content_lengths(values: &[Vec<u8>]) -> Result<Option<u64>, H1Error> {
    let Some(first) = values.first() else {
        return Ok(None);
    };
    if values.iter().skip(1).any(|value| value != first) {
        return Err(H1Error::InvalidResponse(
            "response contains conflicting Content-Length fields".to_owned(),
        ));
    }
    if first.is_empty() || !first.iter().all(u8::is_ascii_digit) {
        return Err(H1Error::InvalidResponse(
            "response contains an invalid Content-Length".to_owned(),
        ));
    }

    let mut length = 0u64;
    for &digit in first {
        length = length
            .checked_mul(10)
            .and_then(|value| value.checked_add((digit - b'0') as u64))
            .ok_or_else(|| {
                H1Error::InvalidResponse("response Content-Length overflows".to_owned())
            })?;
    }
    if length > i64::MAX as u64 {
        return Err(H1Error::InvalidResponse(
            "response Content-Length exceeds Go's int64 range".to_owned(),
        ));
    }
    Ok(Some(length))
}

fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    let line = trim_trailing_ascii_whitespace(line);
    let size = line.split(|byte| *byte == b';').next().unwrap_or_default();
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_data("invalid HTTP/1.1 chunk size"));
    }

    let mut parsed = 0u64;
    for &digit in size {
        let value = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return Err(invalid_data("invalid HTTP/1.1 chunk size")),
        };
        parsed = parsed
            .checked_mul(16)
            .and_then(|current| current.checked_add(value as u64))
            .ok_or_else(|| invalid_data("HTTP/1.1 chunk size overflows"))?;
    }
    Ok(parsed)
}

fn validate_trailer_line(line: &[u8], saw_field: bool) -> io::Result<()> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        let value = trim_ascii_whitespace(line);
        let valid = !value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f);
        return if saw_field && valid {
            Ok(())
        } else {
            Err(invalid_data("invalid HTTP/1.1 trailer continuation"))
        };
    }

    parse_header_line(line)
        .map(|_| ())
        .map_err(|error| invalid_data(error.to_string()))
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn trim_trailing_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn valid_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

struct ResponseLines<'a> {
    remaining: &'a [u8],
    finished: bool,
}

impl<'a> ResponseLines<'a> {
    fn new(head: &'a [u8]) -> Self {
        Self {
            remaining: head,
            finished: false,
        }
    }
}

impl<'a> Iterator for ResponseLines<'a> {
    type Item = Result<&'a [u8], H1Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if let Some(position) = self
            .remaining
            .windows(2)
            .position(|window| window == b"\r\n")
        {
            let line = &self.remaining[..position];
            self.remaining = &self.remaining[position + 2..];
            return Some(validate_response_line(line));
        }

        self.finished = true;
        let line = self.remaining;
        self.remaining = &[];
        Some(validate_response_line(line))
    }
}

fn validate_response_line(line: &[u8]) -> Result<&[u8], H1Error> {
    if line.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(H1Error::InvalidResponse(
            "response head contains a bare CR or LF".to_owned(),
        ));
    }
    Ok(line)
}
