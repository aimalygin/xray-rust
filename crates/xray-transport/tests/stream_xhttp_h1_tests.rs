use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use xray_transport::stream::{
    xhttp_h1_test_only::{
        send_fixed_request, start_chunked_request, start_fixed_request, H1Error, H1Request,
        PendingResponse,
    },
    HeaderMap,
};

#[tokio::test]
async fn fixed_request_error_reports_exact_partial_wire_progress() {
    let headers = HeaderMap::new();
    let request = H1Request {
        method: "POST",
        target: "/upload",
        host: "example.com",
        headers: &headers,
    };
    let error = start_fixed_request(PartialThenFailIo::new(7), &request, b"payload")
        .await
        .expect_err("the scripted write must fail");

    match error {
        H1Error::RequestWrite {
            bytes_written,
            source,
        } => {
            assert_eq!(bytes_written, 7);
            assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
        }
        error => panic!("unexpected error: {error}"),
    }
}

#[tokio::test]
async fn fixed_request_keeps_go_framing_header_order_under_partial_io() {
    let (client, server) = tokio::io::duplex(16);
    let server = tokio::spawn(async move {
        let mut server = OneByteIo::new(server);
        let mut wire = read_request_head(&mut server).await?;
        let mut body = [0u8; 3];
        server.read_exact(&mut body).await?;
        wire.extend_from_slice(&body);
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok::<_, io::Error>(wire)
    });

    let mut headers = HeaderMap::new();
    headers.set("Zed", "last");
    headers.set("Accept", "first");
    headers.set("Content-Length", "999");
    headers.set("Transfer-Encoding", "identity");
    let request = H1Request {
        method: "POST",
        target: "/x?sid=1",
        host: "example.com",
        headers: &headers,
    };
    let response = send_fixed_request(OneByteIo::new(client), &request, b"abc")
        .await
        .expect("fixed request should succeed");
    assert!(response.is_complete());

    let wire = server.await.expect("server task should finish").unwrap();
    assert_eq!(
        wire,
        b"POST /x?sid=1 HTTP/1.1\r\n\
          Host: example.com\r\n\
          User-Agent: Go-http-client/1.1\r\n\
          Content-Length: 3\r\n\
          Accept: first\r\n\
          Zed: last\r\n\
          \r\n\
          abc"
    );
}

#[tokio::test]
async fn empty_get_omits_content_length_like_go_request_write() {
    for method in ["GET", "HEAD"] {
        let head = capture_empty_fixed_request(method).await;
        assert!(
            !head.windows(15).any(|window| window == b"Content-Length:"),
            "{method} must omit Content-Length for an empty body"
        );
    }
}

#[tokio::test]
async fn empty_post_writes_content_length_zero_like_go_request_write() {
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PURGE"] {
        let head = capture_empty_fixed_request(method).await;
        assert!(
            head.windows(b"Content-Length: 0\r\n".len())
                .any(|window| window == b"Content-Length: 0\r\n"),
            "{method} must carry Content-Length: 0 for an empty body"
        );
    }
}

#[tokio::test]
async fn chunked_exchange_downloads_response_before_upload_finishes() {
    let (client, mut server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move {
        let head = read_request_head(&mut server).await?;
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
            .await?;
        let mut upload_wire = Vec::new();
        server.read_to_end(&mut upload_wire).await?;
        Ok::<_, io::Error>((head, upload_wire))
    });

    let headers = HeaderMap::new();
    let request = H1Request {
        method: "POST",
        target: "/stream",
        host: "example.com",
        headers: &headers,
    };
    let (mut upload, pending) = start_chunked_request(client, &request)
        .await
        .expect("chunked request head should succeed");

    let upload_task = async {
        upload.write_all(b"ping").await?;
        upload.shutdown().await
    };
    let response_task = async {
        let mut response = pending.open().await.map_err(h1_to_io)?;
        let mut body = Vec::new();
        response.read_to_end(&mut body).await?;
        Ok::<_, io::Error>(body)
    };
    let (upload_result, response_result) = tokio::join!(upload_task, response_task);
    upload_result.expect("upload should finish");
    assert_eq!(response_result.unwrap(), b"pong");

    let (head, upload_wire) = server_task.await.unwrap().unwrap();
    assert!(head
        .windows(b"Transfer-Encoding: chunked\r\n".len())
        .any(|window| window == b"Transfer-Encoding: chunked\r\n"));
    assert_eq!(upload_wire, b"4\r\nping\r\n0\r\n\r\n");
}

#[tokio::test]
async fn cancelled_flush_resumes_partially_written_chunk_without_duplication() {
    let (io, gate) = GatedIo::new();
    let headers = HeaderMap::new();
    let request = H1Request {
        method: "POST",
        target: "/cancel",
        host: "example.com",
        headers: &headers,
    };
    let (mut upload, pending) = start_chunked_request(io, &request).await.unwrap();
    drop(pending);

    upload.write_all(b"abcdef").await.unwrap();
    gate.wait_for_partial_chunk().await;
    poll_fn(|cx| match Pin::new(&mut upload).poll_flush(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => panic!("flush unexpectedly completed: {result:?}"),
    })
    .await;
    gate.release();
    upload.shutdown().await.unwrap();

    let wire = gate.written();
    assert!(wire.ends_with(b"6\r\nabcdef\r\n0\r\n\r\n"), "wire={wire:?}");
    assert_eq!(count_subslice(&wire, b"abcdef"), 1);
    assert_eq!(
        gate.shutdown_calls(),
        0,
        "finishing a chunked HTTP body must not half-close the shared connection"
    );
}

#[tokio::test]
async fn content_length_body_preserves_overread_for_reuse() {
    let reader =
        ScriptedReader::all_at_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloNEXT");
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();
    let (_, tail) = response
        .into_reusable()
        .expect("HTTP/1.1 framed response should be reusable");

    assert_eq!((body, tail), (b"hello".to_vec(), b"NEXT".to_vec()));
}

#[tokio::test]
async fn chunk_extensions_and_trailers_decode_without_losing_overread() {
    let reader = ScriptedReader::one_byte_at_a_time(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: yes\r\n folded\r\n\r\nNEXT",
    );
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();
    let (mut reader, mut tail) = response.into_reusable().unwrap();
    reader.read_to_end(&mut tail).await.unwrap();

    assert_eq!((body, tail), (b"Wikipedia".to_vec(), b"NEXT".to_vec()));
}

#[tokio::test]
async fn transfer_encoding_overrides_valid_content_length() {
    let reader = ScriptedReader::all_at_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n\
          2\r\nok\r\n0\r\n\r\nTAIL",
    );
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();
    let (_, tail) = response.into_reusable().unwrap();

    assert_eq!((body, tail), (b"ok".to_vec(), b"TAIL".to_vec()));
}

#[tokio::test]
async fn conflicting_duplicate_content_lengths_are_rejected() {
    let error =
        open_error(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx").await;
    assert!(matches!(error, H1Error::InvalidResponse(_)));
}

#[tokio::test]
async fn equal_duplicate_content_lengths_are_accepted() {
    let reader = ScriptedReader::all_at_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
    );
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"x");
}

#[tokio::test]
async fn malformed_content_length_is_rejected_even_with_chunked_encoding() {
    let error = open_error(
        b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\nTransfer-Encoding: chunked\r\n\r\n\
          0\r\n\r\n",
    )
    .await;
    assert!(matches!(error, H1Error::InvalidResponse(_)));
}

#[tokio::test]
async fn duplicate_transfer_encoding_is_rejected() {
    let error = open_error(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\
          Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    .await;
    assert!(matches!(error, H1Error::InvalidResponse(_)));
}

#[tokio::test]
async fn close_delimited_body_completes_only_at_eof_and_is_not_reusable() {
    let reader = ScriptedReader::one_byte_at_a_time(b"HTTP/1.1 200 OK\r\n\r\nbody");
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();

    assert_eq!(body, b"body");
    assert!(response.into_reusable().is_err());
}

#[tokio::test]
async fn connection_close_prevents_reuse_of_framed_response() {
    let reader = ScriptedReader::all_at_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let response = PendingResponse::new(reader).open().await.unwrap();
    assert!(response.into_reusable().is_err());
}

#[tokio::test]
async fn request_connection_close_prevents_reuse_of_framed_response() {
    let (client, mut server) = tokio::io::duplex(256);
    let server_task = tokio::spawn(async move {
        read_request_head(&mut server).await.unwrap();
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut headers = HeaderMap::new();
    headers.set("connection", "keep-alive, close");
    let request = H1Request {
        method: "GET",
        target: "/",
        host: "example.com",
        headers: &headers,
    };
    let response = send_fixed_request(client, &request, b"").await.unwrap();
    assert!(response.into_reusable().is_err());
    server_task.await.unwrap();
}

#[tokio::test]
async fn http_1_0_requires_keep_alive_for_reuse() {
    let reader = ScriptedReader::all_at_once(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    let response = PendingResponse::new(reader).open().await.unwrap();
    assert!(response.into_reusable().is_err());

    let reader = ScriptedReader::all_at_once(
        b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    );
    let response = PendingResponse::new(reader).open().await.unwrap();
    assert!(response.into_reusable().is_ok());
}

#[tokio::test]
async fn head_response_exposes_no_body_and_preserves_following_bytes() {
    let reader = ScriptedReader::all_at_once(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nNEXT");
    let mut response = PendingResponse::new(reader)
        .for_request_method("HEAD")
        .open()
        .await
        .unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();
    let (_, tail) = response.into_reusable().unwrap();

    assert_eq!((body, tail), (Vec::new(), b"NEXT".to_vec()));
}

#[tokio::test]
async fn informational_responses_are_skipped_before_final_200() {
    let reader = ScriptedReader::one_byte_at_a_time(
        b"HTTP/1.1 100 Continue\r\n\r\n\
          HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n\
          HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn status_101_is_terminal_and_rejected() {
    let error = open_error(b"HTTP/1.1 101 Switching Protocols\r\n\r\n").await;
    assert!(matches!(error, H1Error::UnexpectedStatus { status: 101 }));
}

#[tokio::test]
async fn response_head_limit_counts_informational_and_final_heads() {
    let reader = ScriptedReader::all_at_once(
        b"HTTP/1.1 100 Continue\r\nX: 1234567890\r\n\r\n\
          HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let pending = PendingResponse::new(reader)
        .with_response_head_limit(64)
        .unwrap();
    let result = pending.open().await;
    assert!(matches!(
        result,
        Err(H1Error::ResponseHeadTooLarge { limit: 64 })
    ));
}

#[tokio::test]
async fn eof_inside_chunk_data_is_reported() {
    let reader = ScriptedReader::one_byte_at_a_time(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc",
    );
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let error = response.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn eof_inside_chunk_trailer_is_reported() {
    let reader = ScriptedReader::one_byte_at_a_time(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          1\r\na\r\n0\r\nX-Trailer: incomplete",
    );
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let error = response.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn malformed_chunk_terminator_is_rejected() {
    let reader = ScriptedReader::one_byte_at_a_time(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naXX",
    );
    let mut response = PendingResponse::new(reader).open().await.unwrap();
    let error = response.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn dropping_incomplete_framed_body_drops_owned_reader() {
    let drops = Arc::new(AtomicUsize::new(0));
    let reader = ScriptedReader::with_drop_probe(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab",
        drops.clone(),
    );
    let response = PendingResponse::new(reader).open().await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(response);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

async fn capture_empty_fixed_request(method: &str) -> Vec<u8> {
    let (client, mut server) = tokio::io::duplex(256);
    let server_task = tokio::spawn(async move {
        let head = read_request_head(&mut server).await.unwrap();
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        head
    });
    let headers = HeaderMap::new();
    let request = H1Request {
        method,
        target: "/",
        host: "example.com",
        headers: &headers,
    };
    let _response = send_fixed_request(client, &request, b"").await.unwrap();
    server_task.await.unwrap()
}

async fn open_error(response: &'static [u8]) -> H1Error {
    match PendingResponse::new(ScriptedReader::all_at_once(response))
        .open()
        .await
    {
        Ok(_) => panic!("response unexpectedly succeeded"),
        Err(error) => error,
    }
}

async fn read_request_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test request head exceeded limit",
            ));
        }
    }
    Ok(head)
}

fn h1_to_io(error: H1Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn count_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

struct OneByteIo {
    inner: DuplexStream,
}

impl OneByteIo {
    fn new(inner: DuplexStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for OneByteIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut byte = [0u8; 1];
        let mut limited = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                output.put_slice(limited.filled());
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for OneByteIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let limit = input.len().min(1);
        Pin::new(&mut self.inner).poll_write(cx, &input[..limit])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct PartialThenFailIo {
    remaining_before_failure: usize,
}

impl PartialThenFailIo {
    fn new(remaining_before_failure: usize) -> Self {
        Self {
            remaining_before_failure,
        }
    }
}

impl AsyncRead for PartialThenFailIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PartialThenFailIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.remaining_before_failure == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "scripted write failure",
            )));
        }
        let written = input.len().min(self.remaining_before_failure);
        self.remaining_before_failure -= written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
struct ScriptedReader {
    bytes: Vec<u8>,
    offset: usize,
    max_read: usize,
    drops: Option<Arc<AtomicUsize>>,
}

impl ScriptedReader {
    fn all_at_once(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            offset: 0,
            max_read: usize::MAX,
            drops: None,
        }
    }

    fn one_byte_at_a_time(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            offset: 0,
            max_read: 1,
            drops: None,
        }
    }

    fn with_drop_probe(bytes: &[u8], drops: Arc<AtomicUsize>) -> Self {
        Self {
            bytes: bytes.to_vec(),
            offset: 0,
            max_read: usize::MAX,
            drops: Some(drops),
        }
    }
}

impl Drop for ScriptedReader {
    fn drop(&mut self) {
        if let Some(drops) = &self.drops {
            drops.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = self.bytes.len().saturating_sub(self.offset);
        let copied = available.min(output.remaining()).min(self.max_read);
        if copied > 0 {
            let end = self.offset + copied;
            output.put_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct GateHandle {
    state: Arc<Mutex<GateState>>,
}

impl GateHandle {
    async fn wait_for_partial_chunk(&self) {
        poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();
            if state.partial_chunk_done {
                Poll::Ready(())
            } else {
                state.partial_observer = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    fn release(&self) {
        let waker = {
            let mut state = self.state.lock().unwrap();
            state.released = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn written(&self) -> Vec<u8> {
        self.state.lock().unwrap().written.clone()
    }

    fn shutdown_calls(&self) -> usize {
        self.state.lock().unwrap().shutdown_calls
    }
}

struct GateState {
    written: Vec<u8>,
    request_head_done: bool,
    partial_chunk_done: bool,
    released: bool,
    waker: Option<Waker>,
    partial_observer: Option<Waker>,
    shutdown_calls: usize,
}

struct GatedIo {
    response: &'static [u8],
    response_offset: usize,
    state: Arc<Mutex<GateState>>,
}

impl GatedIo {
    fn new() -> (Self, GateHandle) {
        let state = Arc::new(Mutex::new(GateState {
            written: Vec::new(),
            request_head_done: false,
            partial_chunk_done: false,
            released: false,
            waker: None,
            partial_observer: None,
            shutdown_calls: 0,
        }));
        (
            Self {
                response: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                response_offset: 0,
                state: state.clone(),
            },
            GateHandle { state },
        )
    }
}

impl AsyncRead for GatedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let copied = (self.response.len() - self.response_offset).min(output.remaining());
        if copied > 0 {
            let end = self.response_offset + copied;
            output.put_slice(&self.response[self.response_offset..end]);
            self.response_offset = end;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.lock().unwrap();
        if !state.request_head_done {
            state.written.extend_from_slice(input);
            state.request_head_done = state.written.ends_with(b"\r\n\r\n");
            return Poll::Ready(Ok(input.len()));
        }
        if !state.partial_chunk_done {
            let written = input.len().min(2);
            state.written.extend_from_slice(&input[..written]);
            state.partial_chunk_done = true;
            if let Some(observer) = state.partial_observer.take() {
                observer.wake();
            }
            return Poll::Ready(Ok(written));
        }
        if !state.released {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        state.written.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().shutdown_calls += 1;
        Poll::Ready(Ok(()))
    }
}
