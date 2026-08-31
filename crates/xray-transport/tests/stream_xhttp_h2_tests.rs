use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::server;
use h2::{Reason, RecvStream};
use http::{Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

use xray_transport::stream::xhttp_h2_test_only::{
    connect_h2, connect_h2_with_keepalive, H2Client, H2Error,
};
use xray_transport::{BoxedTransportStream, TransportStream};

const DEADLINE: Duration = Duration::from_secs(3);

type Exchange = (Request<RecvStream>, server::SendResponse<Bytes>);

const CLIENT_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct RecordingIo {
    io: DuplexStream,
    writes: Arc<Mutex<Vec<u8>>>,
}

impl RecordingIo {
    fn new(io: DuplexStream) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                io,
                writes: Arc::clone(&writes),
            },
            writes,
        )
    }
}

impl tokio::io::AsyncRead for RecordingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, output)
    }
}

impl tokio::io::AsyncWrite for RecordingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = match Pin::new(&mut self.io).poll_write(cx, input) {
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        self.writes
            .lock()
            .expect("recorded client writes lock")
            .extend_from_slice(&input[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl TransportStream for RecordingIo {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        tokio::io::AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(self, cx, input)
    }
}

fn client_frame_counts(writes: &Arc<Mutex<Vec<u8>>>) -> (usize, usize, usize) {
    let writes = writes.lock().expect("recorded client writes lock");
    let mut offset = if writes.starts_with(CLIENT_CONNECTION_PREFACE) {
        CLIENT_CONNECTION_PREFACE.len()
    } else {
        0
    };
    let mut pings = 0;
    let mut ping_acknowledgements = 0;
    let mut settings_acknowledgements = 0;

    while offset + 9 <= writes.len() {
        let payload_len = usize::from(writes[offset]) << 16
            | usize::from(writes[offset + 1]) << 8
            | usize::from(writes[offset + 2]);
        let frame_end = offset + 9 + payload_len;
        if frame_end > writes.len() {
            break;
        }
        if writes[offset + 3] == 0x6 {
            if writes[offset + 4] & 0x1 == 0 {
                pings += 1;
            } else {
                ping_acknowledgements += 1;
            }
        } else if writes[offset + 3] == 0x4 && writes[offset + 4] & 0x1 != 0 {
            settings_acknowledgements += 1;
        }
        offset = frame_end;
    }

    (pings, ping_acknowledgements, settings_acknowledgements)
}

async fn wait_for_client_pings(writes: &Arc<Mutex<Vec<u8>>>, expected: usize) {
    for _ in 0..128 {
        if client_frame_counts(writes).0 >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("client did not write {expected} PING frames");
}

async fn settle_client_settings_exchange(writes: &Arc<Mutex<Vec<u8>>>) {
    for _ in 0..128 {
        if client_frame_counts(writes).2 >= 1 {
            // Let the connection driver's select poll its keepalive branch and
            // arm the first idle deadline at the same paused instant.
            tokio::task::yield_now().await;
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("client did not acknowledge the server SETTINGS frame");
}

enum ServerCommand {
    GracefulShutdown(oneshot::Sender<()>),
    Close(oneshot::Sender<()>),
}

struct TestServer {
    requests: mpsc::UnboundedReceiver<Result<Exchange, h2::Error>>,
    commands: Option<mpsc::UnboundedSender<ServerCommand>>,
    driver: Option<JoinHandle<()>>,
}

impl TestServer {
    async fn accept(&mut self) -> Option<Result<Exchange, h2::Error>> {
        self.requests.recv().await
    }

    async fn graceful_shutdown(&self) {
        let (done, wait) = oneshot::channel();
        self.commands
            .as_ref()
            .expect("server command channel")
            .send(ServerCommand::GracefulShutdown(done))
            .expect("server driver is alive");
        wait.await.expect("graceful shutdown accepted");
    }

    async fn close(&self) {
        let (done, wait) = oneshot::channel();
        self.commands
            .as_ref()
            .expect("server command channel")
            .send(ServerCommand::Close(done))
            .expect("server driver is alive");
        wait.await.expect("connection close accepted");
    }

    async fn wait_closed(mut self) {
        self.commands = None;
        if let Some(driver) = self.driver.take() {
            driver.await.expect("server driver task");
        }
    }
}

enum ServerEvent {
    Request(Option<Result<Box<Exchange>, h2::Error>>),
    Command(Option<ServerCommand>),
}

async fn drive_server(
    mut connection: server::Connection<DuplexStream, Bytes>,
    requests: mpsc::UnboundedSender<Result<Exchange, h2::Error>>,
    mut commands: mpsc::UnboundedReceiver<ServerCommand>,
) {
    let mut commands_open = true;
    loop {
        let event = if commands_open {
            tokio::select! {
                request = connection.accept() => {
                    ServerEvent::Request(request.map(|result| result.map(Box::new)))
                },
                command = commands.recv() => ServerEvent::Command(command),
            }
        } else {
            ServerEvent::Request(connection.accept().await.map(|result| result.map(Box::new)))
        };

        match event {
            ServerEvent::Request(Some(Ok(exchange))) => {
                let _ = requests.send(Ok(*exchange));
            }
            ServerEvent::Request(Some(Err(error))) => {
                let _ = requests.send(Err(error));
                break;
            }
            ServerEvent::Request(None) => break,
            ServerEvent::Command(Some(ServerCommand::GracefulShutdown(done))) => {
                connection.graceful_shutdown();
                let _ = done.send(());
            }
            ServerEvent::Command(Some(ServerCommand::Close(done))) => {
                let _ = done.send(());
                break;
            }
            ServerEvent::Command(None) => commands_open = false,
        }
    }
}

async fn pair() -> (H2Client, TestServer) {
    pair_with(server::Builder::new()).await
}

async fn pair_with(builder: server::Builder) -> (H2Client, TestServer) {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let client = connect_h2(Box::new(client_io) as BoxedTransportStream);
    let server = builder.handshake::<_, Bytes>(server_io);
    let (client, server) = tokio::join!(client, server);
    let server = server.expect("server HTTP/2 handshake");
    let (request_tx, requests) = mpsc::unbounded_channel();
    let (commands, command_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(drive_server(server, request_tx, command_rx));
    let server = TestServer {
        requests,
        commands: Some(commands),
        driver: Some(driver),
    };
    (client.expect("client HTTP/2 handshake"), server)
}

async fn recording_pair(
    read_idle: Option<Duration>,
) -> (H2Client, TestServer, Arc<Mutex<Vec<u8>>>) {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (client_io, writes) = RecordingIo::new(client_io);
    let client = connect_h2_with_keepalive(Box::new(client_io) as BoxedTransportStream, read_idle);
    let server = server::handshake(server_io);
    let (client, server) = tokio::join!(client, server);
    let (request_tx, requests) = mpsc::unbounded_channel();
    let (commands, command_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(drive_server(
        server.expect("server HTTP/2 handshake"),
        request_tx,
        command_rx,
    ));
    let server = TestServer {
        requests,
        commands: Some(commands),
        driver: Some(driver),
    };
    (client.expect("client HTTP/2 handshake"), server, writes)
}

async fn frozen_recording_pair(
    read_idle: Option<Duration>,
) -> (
    H2Client,
    server::Connection<DuplexStream, Bytes>,
    Arc<Mutex<Vec<u8>>>,
) {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (client_io, writes) = RecordingIo::new(client_io);
    let client = connect_h2_with_keepalive(Box::new(client_io) as BoxedTransportStream, read_idle);
    let server = server::handshake(server_io);
    let (client, server) = tokio::join!(client, server);
    (
        client.expect("client HTTP/2 handshake"),
        server.expect("server HTTP/2 handshake"),
        writes,
    )
}

fn request(method: Method, uri: &str) -> Request<()> {
    Request::builder()
        .version(Version::HTTP_2)
        .method(method)
        .uri(uri)
        .body(())
        .expect("valid test request")
}

fn response(status: StatusCode) -> Response<()> {
    Response::builder()
        .status(status)
        .body(())
        .expect("valid test response")
}

async fn drain_request(mut body: RecvStream) -> Vec<u8> {
    let mut output = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("request DATA");
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("release request capacity");
        output.extend_from_slice(&chunk);
    }
    output
}

#[tokio::test]
async fn empty_get_ends_on_headers_without_a_zero_length_data_frame() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let shape = (request.method().clone(), request.body().is_end_stream());
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send response");
        shape
    });

    let mut body = timeout(
        DEADLINE,
        client.send_fixed(
            request(Method::GET, "http://example.test/empty"),
            Bytes::new(),
        ),
    )
    .await
    .expect("request deadline")
    .expect("status 200");
    let mut output = Vec::new();
    body.read_to_end(&mut output).await.expect("empty response");

    assert_eq!(server_task.await.expect("server task"), (Method::GET, true));
}

#[tokio::test]
async fn start_fixed_empty_returns_before_delayed_response_with_headers_end_stream() {
    let (client, mut server) = pair().await;
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (respond_tx, respond_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        accepted_tx
            .send(request.body().is_end_stream())
            .expect("report request shape");
        respond_rx.await.expect("release delayed response");
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send response");
    });

    let pending = timeout(
        DEADLINE,
        client.start_fixed(
            request(Method::GET, "http://example.test/start-fixed-empty"),
            Bytes::new(),
        ),
    )
    .await
    .expect("start_fixed must not wait for response")
    .expect("send empty fixed request");
    assert!(accepted_rx.await.expect("request shape"));

    respond_tx.send(()).expect("release response");
    let _body = pending.open().await.expect("status 200");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn start_fixed_nonempty_finishes_data_before_returning_without_waiting_for_response() {
    let (client, mut server) = pair().await;
    let (received_tx, received_rx) = oneshot::channel();
    let (respond_tx, respond_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let body = drain_request(request.into_body()).await;
        received_tx
            .send(body)
            .expect("report complete request body");
        respond_rx.await.expect("release delayed response");
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send response");
    });

    let payload = Bytes::from_static(b"complete-fixed-body");
    let pending = timeout(
        DEADLINE,
        client.start_fixed(
            request(Method::POST, "http://example.test/start-fixed-body"),
            payload.clone(),
        ),
    )
    .await
    .expect("complete upload must not wait for response")
    .expect("send fixed request body");
    assert_eq!(received_rx.await.expect("complete request body"), payload);

    respond_tx.send(()).expect("release response");
    let _body = pending.open().await.expect("status 200");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn cancelling_flow_controlled_start_fixed_upload_resets_its_stream() {
    let mut builder = server::Builder::new();
    builder.initial_window_size(8);
    let (client, mut server) = pair_with(builder).await;
    let (first_tx, first_rx) = oneshot::channel();
    let (reset_tx, reset_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let first = request
            .body_mut()
            .data()
            .await
            .expect("first DATA")
            .expect("valid first DATA");
        first_tx.send(first.len()).ok();
        let reason = poll_fn(|cx| respond.poll_reset(cx))
            .await
            .expect("client reset");
        reset_tx.send(reason).ok();
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let upload = tokio::spawn(async move {
        client
            .start_fixed(
                request(Method::POST, "http://example.test/cancel-fixed-upload"),
                Bytes::from(vec![0x5a; 64]),
            )
            .await
    });
    assert_eq!(
        timeout(DEADLINE, first_rx)
            .await
            .expect("first DATA deadline")
            .expect("first DATA length"),
        8
    );
    upload.abort();
    let _ = upload.await;

    assert_eq!(
        timeout(DEADLINE, reset_rx)
            .await
            .expect("reset deadline")
            .expect("reset reason"),
        Reason::CANCEL
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn dropping_start_fixed_pending_response_resets_its_stream() {
    let (client, mut server) = pair().await;
    let (reset_tx, reset_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let reason = poll_fn(|cx| respond.poll_reset(cx))
            .await
            .expect("client reset");
        reset_tx.send(reason).ok();
    });

    let pending = client
        .start_fixed(
            request(Method::GET, "http://example.test/drop-fixed-pending"),
            Bytes::new(),
        )
        .await
        .expect("send empty fixed request");
    drop(pending);

    assert_eq!(
        timeout(DEADLINE, reset_rx)
            .await
            .expect("reset deadline")
            .expect("reset reason"),
        Reason::CANCEL
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn empty_post_preserves_composer_owned_headers() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let content_length = request
            .headers()
            .get("content-length")
            .expect("caller supplied content-length")
            .to_str()
            .expect("ASCII content-length")
            .to_owned();
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send response");
        content_length
    });

    let mut request = request(Method::POST, "http://example.test/post");
    request
        .headers_mut()
        .insert("content-length", "0".parse().expect("header value"));
    let _body = client
        .send_fixed(request, Bytes::new())
        .await
        .expect("status 200");

    assert_eq!(server_task.await.expect("server task"), "0");
}

#[tokio::test]
async fn relative_uri_is_rejected_without_poisoning_the_connection() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (request, mut respond) = server
            .accept()
            .await
            .expect("valid request arrives")
            .expect("valid request");
        let path = request.uri().path().to_owned();
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send response");
        path
    });

    let invalid = client
        .send_fixed(request(Method::GET, "/relative"), Bytes::new())
        .await
        .expect_err("HTTP/2 request needs scheme and authority");
    assert!(
        invalid.to_string().contains("scheme") || invalid.to_string().contains("authority"),
        "unexpected error: {invalid}"
    );

    let _body = client
        .send_fixed(
            request(Method::GET, "http://example.test/absolute"),
            Bytes::new(),
        )
        .await
        .expect("connection remains usable");
    assert_eq!(server_task.await.expect("server task"), "/absolute");
}

#[tokio::test]
async fn arbitrary_valid_method_is_preserved() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let method = request.method().clone();
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send response");
        method
    });
    let method = Method::from_bytes(b"BREW").expect("valid extension method");

    let _body = client
        .send_fixed(
            request(method.clone(), "http://example.test/custom"),
            Bytes::new(),
        )
        .await
        .expect("status 200");

    assert_eq!(server_task.await.expect("server task"), method);
}

#[tokio::test]
async fn head_response_is_logically_bodyless_even_if_peer_sends_data() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut body = respond
            .send_response(response(StatusCode::OK), false)
            .expect("send response HEADERS");
        body.send_data(Bytes::from_static(b"illegal-for-head"), true)
            .expect("queue illegal response DATA");
    });

    let mut body = client
        .send_fixed(
            request(Method::HEAD, "http://example.test/head"),
            Bytes::new(),
        )
        .await
        .expect("status 200");
    let mut output = Vec::new();
    timeout(DEADLINE, body.read_to_end(&mut output))
        .await
        .expect("HEAD read must not wait")
        .expect("logical EOF");

    assert!(output.is_empty());
    server_task.await.expect("server task");
}

#[tokio::test]
async fn non_200_response_resets_only_that_stream() {
    let (client, mut server) = pair().await;
    let (reset_tx, reset_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut body = respond
            .send_response(response(StatusCode::FORBIDDEN), false)
            .expect("send rejected response");
        let reason = poll_fn(|cx| body.poll_reset(cx))
            .await
            .expect("client reset");
        reset_tx.send(reason).ok();

        let (_request, mut respond) = server
            .accept()
            .await
            .expect("second request before connection end")
            .expect("valid second request");
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send second response");
    });

    let error = timeout(
        DEADLINE,
        client.send_fixed(
            request(Method::POST, "http://example.test/rejected"),
            Bytes::from(vec![0x5a; 256 * 1024]),
        ),
    )
    .await
    .expect("early rejection must stop a backpressured fixed upload")
    .expect_err("non-200 must fail");
    assert!(matches!(
        error,
        H2Error::UnexpectedStatus {
            status: StatusCode::FORBIDDEN
        }
    ));
    assert_eq!(
        timeout(DEADLINE, reset_rx)
            .await
            .expect("reset deadline")
            .expect("reset reason"),
        Reason::CANCEL
    );

    let _body = client
        .send_fixed(
            request(Method::GET, "http://example.test/still-live"),
            Bytes::new(),
        )
        .await
        .expect("connection survives stream rejection");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn cancelling_before_response_headers_sends_cancel_reset() {
    let (client, mut server) = pair().await;
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (reset_tx, reset_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        accepted_tx.send(()).ok();
        let reason = poll_fn(|cx| respond.poll_reset(cx))
            .await
            .expect("client reset");
        reset_tx.send(reason).ok();
    });

    let (_upload, response) = client
        .start_streaming(request(
            Method::POST,
            "http://example.test/cancel-before-headers",
        ))
        .await
        .expect("start request");
    accepted_rx.await.expect("server accepted request");
    let open = tokio::spawn(response.open());
    open.abort();
    let _ = open.await;

    assert_eq!(
        timeout(DEADLINE, reset_rx)
            .await
            .expect("reset deadline")
            .expect("reset reason"),
        Reason::CANCEL
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn streaming_upload_and_download_progress_full_duplex() {
    let (client, mut server) = pair().await;
    let (received_tx, received_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut response_body = respond
            .send_response(response(StatusCode::OK), false)
            .expect("send response HEADERS");
        response_body
            .send_data(Bytes::from_static(b"ready:"), false)
            .expect("send early response DATA");
        let received = drain_request(request.into_body()).await;
        received_tx.send(received).ok();
        response_body
            .send_data(Bytes::from_static(b"done"), true)
            .expect("finish response");
    });

    let (mut upload, response) = client
        .start_streaming(request(Method::POST, "http://example.test/full-duplex"))
        .await
        .expect("start streaming request");
    let mut body = response.open().await.expect("early status 200");
    let mut early = [0_u8; 6];
    body.read_exact(&mut early).await.expect("early response");
    upload.write_all(b"payload").await.expect("upload payload");
    upload.shutdown().await.expect("upload END_STREAM");
    let mut late = Vec::new();
    body.read_to_end(&mut late).await.expect("finish response");

    assert_eq!((&early, late.as_slice()), (b"ready:", &b"done"[..]));
    assert_eq!(received_rx.await.expect("received upload"), b"payload");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn dropping_upload_without_shutdown_resets_the_response_half() {
    let (client, mut server) = pair().await;
    let (reset_tx, reset_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut response_body = respond
            .send_response(response(StatusCode::OK), false)
            .expect("send response HEADERS");
        let reason = poll_fn(|cx| response_body.poll_reset(cx))
            .await
            .expect("client reset");
        reset_tx.send(reason).ok();
    });

    let (upload, response) = client
        .start_streaming(request(Method::POST, "http://example.test/drop-upload"))
        .await
        .expect("start streaming request");
    let mut body = response.open().await.expect("status 200");
    drop(upload);
    let mut byte = [0_u8; 1];
    let error = timeout(DEADLINE, body.read(&mut byte))
        .await
        .expect("response reset deadline")
        .expect_err("response sibling must observe cancellation");

    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert_eq!(
        reset_rx.await.expect("server reset observation"),
        Reason::CANCEL
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn dropping_response_before_eof_resets_the_upload_half() {
    let (client, mut server) = pair().await;
    let (reset_tx, reset_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut response_body = respond
            .send_response(response(StatusCode::OK), false)
            .expect("send response HEADERS");
        let reason = poll_fn(|cx| response_body.poll_reset(cx))
            .await
            .expect("client reset");
        reset_tx.send(reason).ok();
    });

    let (mut upload, response) = client
        .start_streaming(request(Method::POST, "http://example.test/drop-response"))
        .await
        .expect("start streaming request");
    let body = response.open().await.expect("status 200");
    drop(body);
    let error = upload
        .write(b"must-not-be-accepted")
        .await
        .expect_err("upload sibling must observe cancellation");

    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert_eq!(
        reset_rx.await.expect("server reset observation"),
        Reason::CANCEL
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn response_trailers_are_consumed_before_eof() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut response_body = respond
            .send_response(response(StatusCode::OK), false)
            .expect("send response HEADERS");
        response_body
            .send_data(Bytes::from_static(b"body"), false)
            .expect("send response DATA");
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-finished", "yes".parse().expect("trailer value"));
        response_body
            .send_trailers(trailers)
            .expect("send response trailers");
    });

    let mut body = client
        .send_fixed(
            request(Method::GET, "http://example.test/trailers"),
            Bytes::new(),
        )
        .await
        .expect("status 200");
    let mut output = Vec::new();
    body.read_to_end(&mut output).await.expect("response EOF");

    assert_eq!(output, b"body");
    assert_eq!(
        body.trailers()
            .and_then(|trailers| trailers.get("x-finished"))
            .and_then(|value| value.to_str().ok()),
        Some("yes")
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn response_releases_flow_control_across_small_partial_reads() {
    let (client, mut server) = pair().await;
    let expected: Vec<u8> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
    let server_payload = Bytes::copy_from_slice(&expected);
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut response_body = respond
            .send_response(response(StatusCode::OK), false)
            .expect("send response HEADERS");
        response_body
            .send_data(server_payload, true)
            .expect("queue response larger than one stream window");
    });

    let mut body = client
        .send_fixed(
            request(Method::GET, "http://example.test/partial-response"),
            Bytes::new(),
        )
        .await
        .expect("status 200");
    let mut actual = Vec::new();
    let mut small = [0_u8; 7];
    loop {
        let read = timeout(DEADLINE, body.read(&mut small))
            .await
            .expect("response progress deadline")
            .expect("response read");
        if read == 0 {
            break;
        }
        actual.extend_from_slice(&small[..read]);
    }

    assert_eq!(actual, expected);
    server_task.await.expect("server task");
}

#[tokio::test]
async fn upload_obeys_partial_flow_control_and_cancel_returns_the_stream() {
    let mut builder = server::Builder::new();
    builder.initial_window_size(8);
    let (client, mut server) = pair_with(builder).await;
    let (reset_tx, reset_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let first = request
            .body_mut()
            .data()
            .await
            .expect("first DATA")
            .expect("valid first DATA");
        let reason = poll_fn(|cx| respond.poll_reset(cx))
            .await
            .expect("client reset");
        reset_tx.send((first.len(), reason)).ok();
    });

    // h2's client handshake intentionally does not wait for peer SETTINGS.
    // Give the connection driver a turn to apply the server's eight-byte
    // stream window before opening this request.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (mut upload, _response) = client
        .start_streaming(request(Method::POST, "http://example.test/backpressure"))
        .await
        .expect("start streaming request");
    let accepted = upload.write(&[7_u8; 64]).await.expect("partial write");
    assert_eq!(accepted, 8);

    let blocked = timeout(Duration::from_millis(25), upload.write(&[9_u8; 8])).await;
    assert!(blocked.is_err(), "second write should wait for capacity");
    drop(upload);

    assert_eq!(
        timeout(DEADLINE, reset_rx)
            .await
            .expect("reset deadline")
            .expect("reset details"),
        (8, Reason::CANCEL)
    );
    server_task.await.expect("server task");
}

#[tokio::test]
async fn streaming_upload_reuses_released_flow_control_beyond_initial_windows() {
    const UPLOAD_BYTES: usize = 8 * 1024 * 1024;

    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (mut request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut received = 0;
        while let Some(chunk) = request.body_mut().data().await {
            let chunk = chunk.expect("valid upload DATA");
            received += chunk.len();
            request
                .body_mut()
                .flow_control()
                .release_capacity(chunk.len())
                .expect("release upload flow control");
        }
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send upload response");
        received
    });

    let (mut upload, response) = client
        .start_streaming(request(
            Method::POST,
            "http://example.test/sustained-upload",
        ))
        .await
        .expect("start streaming request");
    timeout(DEADLINE, async {
        upload
            .write_all(&vec![0x5a; UPLOAD_BYTES])
            .await
            .expect("write sustained upload");
        upload.shutdown().await.expect("finish sustained upload");
    })
    .await
    .expect("sustained upload progress deadline");
    let mut body = response.open().await.expect("status 200");
    assert_eq!(body.read(&mut [0_u8; 1]).await.expect("response EOF"), 0);
    assert_eq!(server_task.await.expect("server task"), UPLOAD_BYTES);
}

#[tokio::test]
async fn cloned_client_opens_concurrent_streams_without_serializing_headers() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let mut exchanges = Vec::new();
        for _ in 0..2 {
            let (request, respond) = server
                .accept()
                .await
                .expect("request before connection end")
                .expect("valid request");
            exchanges.push((request.uri().path().to_owned(), respond));
        }
        exchanges.sort_by(|left, right| left.0.cmp(&right.0));
        for (path, mut respond) in exchanges {
            let mut body = respond
                .send_response(response(StatusCode::OK), false)
                .expect("send response HEADERS");
            body.send_data(Bytes::from(path), true)
                .expect("send response DATA");
        }
    });

    let first = client.send_fixed(request(Method::GET, "http://example.test/a"), Bytes::new());
    let second_client = client.clone();
    let second =
        second_client.send_fixed(request(Method::GET, "http://example.test/b"), Bytes::new());
    let (first, second) = timeout(DEADLINE, async { tokio::join!(first, second) })
        .await
        .expect("both request HEADERS must arrive");
    let mut first = first.expect("first status 200");
    let mut second = second.expect("second status 200");
    let mut first_body = Vec::new();
    let mut second_body = Vec::new();
    first
        .read_to_end(&mut first_body)
        .await
        .expect("first response body");
    second
        .read_to_end(&mut second_body)
        .await
        .expect("second response body");

    assert_eq!((first_body, second_body), (b"/a".to_vec(), b"/b".to_vec()));
    server_task.await.expect("server task");
}

#[tokio::test]
async fn remote_reset_after_headers_is_reported_by_response_reader() {
    let (client, mut server) = pair().await;
    let (opened_tx, opened_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        let mut body = respond
            .send_response(response(StatusCode::OK), false)
            .expect("send response HEADERS");
        opened_rx.await.expect("client opened response");
        body.send_reset(Reason::CANCEL);
    });

    let (_upload, response) = client
        .start_streaming(request(Method::POST, "http://example.test/reset"))
        .await
        .expect("start request");
    let mut body = response.open().await.expect("status 200");
    opened_tx.send(()).expect("signal response open");
    let mut byte = [0_u8; 1];
    let error = timeout(DEADLINE, body.read(&mut byte))
        .await
        .expect("reset deadline")
        .expect_err("remote reset must be visible");

    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    server_task.await.expect("server task");
}

#[tokio::test]
async fn connection_close_fails_a_pending_response_and_retires_the_client() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let _exchange = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        // Stop the driver and drop its I/O with no response HEADERS.
        server.close().await;
    });

    let (_upload, response) = client
        .start_streaming(request(
            Method::POST,
            "http://example.test/connection-close",
        ))
        .await
        .expect("start request");
    let error = timeout(DEADLINE, response.open())
        .await
        .expect("connection-close deadline")
        .expect_err("closed connection must fail response");
    timeout(DEADLINE, async {
        while client.is_live() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed connection retires driver");

    assert!(matches!(error, H2Error::Protocol { .. }));
    server_task.await.expect("server task");
}

#[tokio::test]
async fn graceful_goaway_marks_the_client_dead_and_rejects_new_streams() {
    let (client, mut server) = pair().await;
    let server_task = tokio::spawn(async move {
        let (_request, mut respond) = server
            .accept()
            .await
            .expect("request before connection end")
            .expect("valid request");
        respond
            .send_response(response(StatusCode::OK), true)
            .expect("send response");
        server.graceful_shutdown().await;
        server.wait_closed().await;
    });

    let mut body = client
        .send_fixed(
            request(Method::GET, "http://example.test/before-goaway"),
            Bytes::new(),
        )
        .await
        .expect("first response");
    let mut sink = Vec::new();
    body.read_to_end(&mut sink)
        .await
        .expect("first response EOF");
    drop(body);

    timeout(DEADLINE, async {
        while client.is_live() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("GOAWAY retires driver");
    let error = client
        .send_fixed(
            request(Method::GET, "http://example.test/after-goaway"),
            Bytes::new(),
        )
        .await
        .expect_err("dead connection rejects streams");

    assert!(matches!(error, H2Error::Protocol { .. }));
    server_task.await.expect("server task");
}

#[tokio::test(start_paused = true)]
async fn keepalive_read_idle_deadline_moves_after_response_data() {
    let (client, mut server, writes) = recording_pair(Some(Duration::from_secs(10))).await;
    settle_client_settings_exchange(&writes).await;
    let pending = client
        .start_fixed(
            request(Method::GET, "http://example.test/keepalive-read"),
            Bytes::new(),
        )
        .await
        .expect("send request");
    let (_request, mut respond) = server
        .accept()
        .await
        .expect("request before connection end")
        .expect("valid request");
    let mut response_send = respond
        .send_response(response(StatusCode::OK), false)
        .expect("send response HEADERS");
    let mut response = pending.open().await.expect("status 200");

    tokio::time::advance(Duration::from_secs(9)).await;
    response_send
        .send_data(Bytes::from_static(b"x"), false)
        .expect("send response DATA");
    let mut byte = [0_u8; 1];
    response
        .read_exact(&mut byte)
        .await
        .expect("read activity reaches client");

    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert_eq!(client_frame_counts(&writes).0, 0);

    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_client_pings(&writes, 1).await;
    assert!(client.is_live());

    response_send
        .send_data(Bytes::new(), true)
        .expect("finish response DATA");
    let mut tail = Vec::new();
    response.read_to_end(&mut tail).await.expect("response EOF");
    server.close().await;
    server.wait_closed().await;
}

#[tokio::test(start_paused = true)]
async fn acknowledged_idle_pings_keep_the_connection_live() {
    let (client, server, writes) = recording_pair(Some(Duration::from_secs(1))).await;
    settle_client_settings_exchange(&writes).await;

    for expected in 1..=3 {
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_client_pings(&writes, expected).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(client.is_live());
    }

    server.close().await;
    server.wait_closed().await;
}

#[tokio::test(start_paused = true)]
async fn unacknowledged_ping_retires_the_connection_after_timeout() {
    let (client, _frozen_server, writes) =
        frozen_recording_pair(Some(Duration::from_secs(1))).await;
    settle_client_settings_exchange(&writes).await;

    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_client_pings(&writes, 1).await;
    tokio::time::advance(Duration::from_secs(15) + Duration::from_millis(1)).await;
    for _ in 0..32 {
        if !client.is_live() {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(!client.is_live());
}

#[tokio::test(start_paused = true)]
async fn disabled_keepalive_sends_no_ping_to_an_idle_peer() {
    let (client, _frozen_server, writes) = frozen_recording_pair(None).await;
    settle_client_settings_exchange(&writes).await;

    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    assert_eq!(client_frame_counts(&writes).0, 0);
    assert!(client.is_live());
}
