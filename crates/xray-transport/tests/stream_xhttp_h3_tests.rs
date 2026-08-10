use std::future::{poll_fn, Future};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::error::Code;
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rand::rngs::mock::StepRng;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use xray_routing::{Network, Target, TargetAddr};

use xray_transport::stream::xhttp_composer_test_only::{
    NormalizedRange, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpModeSelection, XhttpRange,
    XhttpScheme,
};
use xray_transport::stream::xhttp_h3_test_only::{
    connect_h3, H3Client, H3Congestion, H3ConnectConfig, H3Error, H3QuicConfig, H3QuicVersion,
    H3UdpHopConfig,
};
use xray_transport::stream::xhttp_transport_test_only::{
    XhttpClock, XhttpH3Dial, XhttpHttpVersion, XhttpTransport, XhttpXmuxPolicy,
};
use xray_transport::stream::{HeaderMap as XhttpHeaderMap, TransportLayer};
use xray_transport::{
    ConnectorConfig, HappyEyeballsConfig, SocketHandle, SocketProtector, TlsClientConfig,
    TlsConnector, TransportDialer,
};

const DEADLINE: Duration = Duration::from_secs(5);
const GZIP_PONG: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x2b, 0xc8, 0xcf, 0x4b, 0x07, 0x00,
    0x4f, 0x41, 0x58, 0x21, 0x04, 0x00, 0x00, 0x00,
];

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type Exchange = (Request<()>, ServerStream);

#[derive(Clone)]
struct TestServer {
    inner: Arc<TestServerInner>,
    requests: Arc<Mutex<mpsc::UnboundedReceiver<Exchange>>>,
}

struct TestServerInner {
    endpoint: quinn::Endpoint,
    driver: JoinHandle<()>,
}

impl Drop for TestServerInner {
    fn drop(&mut self) {
        self.endpoint.close(
            quinn::VarInt::from_u32(Code::H3_NO_ERROR.value() as u32),
            b"test complete",
        );
        self.driver.abort();
    }
}

impl TestServer {
    async fn accept(&self) -> Exchange {
        timeout(DEADLINE, self.requests.lock().await.recv())
            .await
            .expect("server request deadline")
            .expect("server request before connection close")
    }

    fn close_connection(&self) {
        self.inner.endpoint.close(
            quinn::VarInt::from_u32(Code::H3_NO_ERROR.value() as u32),
            b"server close",
        );
    }
}

async fn pair() -> (H3Client, TestServer) {
    pair_with_options(None, None).await
}

async fn pair_with_protector(
    socket_protector: Option<Arc<dyn SocketProtector>>,
) -> (H3Client, TestServer) {
    pair_with_options(socket_protector, None).await
}

async fn pair_with_server_stream_window(window: u32) -> (H3Client, TestServer) {
    pair_with_options(None, Some(window)).await
}

async fn pair_with_options(
    socket_protector: Option<Arc<dyn SocketProtector>>,
    server_stream_receive_window: Option<u32>,
) -> (H3Client, TestServer) {
    let (client_tls, server_addr, server) = server_with_options(server_stream_receive_window).await;
    let client = connect_h3(H3ConnectConfig {
        remote_addr: server_addr,
        server_name: "localhost".to_owned(),
        tls_config: client_tls,
        socket_protector,
        quic: H3QuicConfig::default(),
    })
    .await
    .expect("connect HTTP/3 client");
    (client, server)
}

async fn server_with_options(
    server_stream_receive_window: Option<u32>,
) -> (Arc<rustls::ClientConfig>, SocketAddr, TestServer) {
    server_with_transport_options(server_stream_receive_window, None).await
}

async fn server_with_transport_options(
    server_stream_receive_window: Option<u32>,
    max_concurrent_bidi_streams: Option<u32>,
) -> (Arc<rustls::ClientConfig>, SocketAddr, TestServer) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate test certificate");
    let certificate = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("server certificate");
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_crypto = QuicServerConfig::try_from(server_tls).expect("QUIC server TLS");
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    if server_stream_receive_window.is_some() || max_concurrent_bidi_streams.is_some() {
        let mut transport = quinn::TransportConfig::default();
        if let Some(window) = server_stream_receive_window {
            transport.stream_receive_window(quinn::VarInt::from_u32(window));
        }
        if let Some(limit) = max_concurrent_bidi_streams {
            transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(limit));
        }
        server_config.transport_config(Arc::new(transport));
    }
    let endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind QUIC server");
    let server_addr = endpoint.local_addr().expect("QUIC server address");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("add test root");
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];

    let (request_tx, request_rx) = mpsc::unbounded_channel();
    let server_endpoint = endpoint.clone();
    let driver = tokio::spawn(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            let request_tx = request_tx.clone();
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(_) => return,
                };
                let mut connection = match h3::server::Connection::new(h3_quinn::Connection::new(
                    connection,
                ))
                .await
                {
                    Ok(connection) => connection,
                    Err(_) => return,
                };

                loop {
                    let resolver = match connection.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) | Err(_) => return,
                    };
                    let exchange = match resolver.resolve_request().await {
                        Ok(exchange) => exchange,
                        Err(_) => continue,
                    };
                    if request_tx.send(exchange).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let server = TestServer {
        inner: Arc::new(TestServerInner { endpoint, driver }),
        requests: Arc::new(Mutex::new(request_rx)),
    };

    (Arc::new(client_tls), server_addr, server)
}

fn request(method: Method, path: &str) -> Request<()> {
    Request::builder()
        .version(Version::HTTP_3)
        .method(method)
        .uri(format!("https://localhost{path}"))
        .body(())
        .expect("valid HTTP/3 request")
}

fn response(status: StatusCode) -> Response<()> {
    Response::builder()
        .version(Version::HTTP_3)
        .status(status)
        .body(())
        .expect("valid HTTP/3 response")
}

async fn drain_request(stream: &mut ServerStream) -> Result<Vec<u8>, h3::error::StreamError> {
    let mut output = Vec::new();
    while let Some(mut data) = stream.recv_data().await? {
        while data.has_remaining() {
            let chunk = data.chunk();
            output.extend_from_slice(chunk);
            let consumed = chunk.len();
            data.advance(consumed);
        }
    }
    let _ = stream.recv_trailers().await?;
    Ok(output)
}

fn xhttp_config(mode: XhttpModeSelection, max_post: i32) -> (XhttpConfig, XhttpEndpoint) {
    xhttp_config_with_headers(mode, max_post, XhttpHeaderMap::new())
}

fn xhttp_config_with_headers(
    mode: XhttpModeSelection,
    max_post: i32,
    headers: XhttpHeaderMap,
) -> (XhttpConfig, XhttpEndpoint) {
    let input = XhttpConfigInput {
        mode,
        path: "/api".to_owned(),
        headers,
        x_padding_bytes: XhttpRange::exact(1),
        sc_max_each_post_bytes: XhttpRange::exact(max_post),
        sc_min_posts_interval_ms: XhttpRange::exact(1),
        sc_max_buffered_posts: 4,
        ..XhttpConfigInput::default()
    };
    let mut config = XhttpConfig::normalize(input).expect("normalize XHTTP test config");
    config.min_posts_interval_ms = NormalizedRange::exact(0);
    let endpoint =
        XhttpEndpoint::new(XhttpScheme::Https, "localhost").expect("valid XHTTP test endpoint");
    (config, endpoint)
}

fn unlimited_xmux() -> XhttpXmuxPolicy {
    XhttpXmuxPolicy {
        max_concurrency: XhttpRange::exact(0),
        max_connections: XhttpRange::exact(0),
        c_max_reuse_times: XhttpRange::exact(0),
        h_max_request_times: XhttpRange::exact(0),
        h_max_reusable_secs: XhttpRange::exact(0),
        h_keep_alive_period_secs: 0,
    }
}

fn xhttp_h3_transport(
    mode: XhttpModeSelection,
    xmux: XhttpXmuxPolicy,
    max_post: i32,
) -> XhttpTransport {
    let (config, endpoint) = xhttp_config(mode, max_post);
    XhttpTransport::new(config, endpoint, XhttpHttpVersion::Http3, xmux)
        .expect("build H3 XHTTP transport")
        .with_rng(Box::new(StepRng::new(0x0102_0304_0506_0708, 1)))
        .expect("inject deterministic XHTTP random source")
}

fn xhttp_h3_transport_with_headers(
    mode: XhttpModeSelection,
    xmux: XhttpXmuxPolicy,
    max_post: i32,
    headers: XhttpHeaderMap,
) -> XhttpTransport {
    let (config, endpoint) = xhttp_config_with_headers(mode, max_post, headers);
    XhttpTransport::new(config, endpoint, XhttpHttpVersion::Http3, xmux)
        .expect("build H3 XHTTP transport")
        .with_rng(Box::new(StepRng::new(0x0102_0304_0506_0708, 1)))
        .expect("inject deterministic XHTTP random source")
}

fn h3_dial(client: H3Client, dials: Arc<AtomicUsize>) -> XhttpH3Dial {
    Arc::new(move || {
        dials.fetch_add(1, Ordering::AcqRel);
        let client = client.clone();
        Box::pin(async move { Ok(client) })
    })
}

fn h3_network_dial(
    client_tls: Arc<rustls::ClientConfig>,
    server_addr: SocketAddr,
    dials: Arc<AtomicUsize>,
) -> XhttpH3Dial {
    Arc::new(move || {
        dials.fetch_add(1, Ordering::AcqRel);
        let client_tls = Arc::clone(&client_tls);
        Box::pin(async move {
            connect_h3(H3ConnectConfig {
                remote_addr: server_addr,
                server_name: "localhost".to_owned(),
                tls_config: client_tls,
                socket_protector: None,
                quic: H3QuicConfig::default(),
            })
            .await
        })
    })
}

async fn serve_clean_exchange(server: &TestServer) -> (Method, String, Vec<u8>) {
    let (request, mut stream) = server.accept().await;
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let body = drain_request(&mut stream).await.expect("request body");
    stream
        .send_response(response(StatusCode::OK))
        .await
        .expect("response headers");
    stream.finish().await.expect("response finish");
    (method, path, body)
}

#[tokio::test]
async fn empty_fixed_request_preserves_method_and_has_no_data_frame() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (request, mut stream) = server.accept().await;
            let body = drain_request(&mut stream).await.expect("request body");
            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("response headers");
            stream
                .send_data(Bytes::from_static(b"ok"))
                .await
                .expect("response data");
            stream.finish().await.expect("response finish");
            (
                request.method().clone(),
                request.uri().path().to_owned(),
                body,
            )
        }
    });

    let mut body = client
        .send_fixed(request(Method::PATCH, "/empty-fixed"), Bytes::new())
        .await
        .expect("status 200");
    let mut output = Vec::new();
    body.read_to_end(&mut output).await.expect("response body");

    assert_eq!(output, b"ok");
    assert_eq!(
        handler.await.expect("server handler"),
        (Method::PATCH, "/empty-fixed".to_owned(), Vec::new())
    );
}

#[tokio::test]
async fn fixed_request_and_response_trailers_survive_partial_reads() {
    let (client, server) = pair().await;
    let payload: Vec<u8> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
    let response_payload = payload.clone();
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_request, mut stream) = server.accept().await;
            let request_body = drain_request(&mut stream).await.expect("request body");
            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("response headers");
            stream
                .send_data(Bytes::from(response_payload))
                .await
                .expect("response data");
            let mut trailers = HeaderMap::new();
            trailers.insert("x-finished", "yes".parse().expect("trailer value"));
            stream
                .send_trailers(trailers)
                .await
                .expect("response trailers");
            stream.finish().await.expect("response finish");
            request_body
        }
    });

    let mut body = client
        .send_fixed(
            request(Method::POST, "/trailers"),
            Bytes::from_static(b"upload"),
        )
        .await
        .expect("status 200");
    let mut actual = Vec::new();
    let mut small = [0_u8; 7];
    loop {
        let read = body.read(&mut small).await.expect("partial response read");
        if read == 0 {
            break;
        }
        actual.extend_from_slice(&small[..read]);
    }

    assert_eq!(actual, payload);
    assert_eq!(handler.await.expect("server handler"), b"upload");
    assert_eq!(
        body.trailers()
            .and_then(|trailers| trailers.get("x-finished"))
            .and_then(|value| value.to_str().ok()),
        Some("yes")
    );
}

#[tokio::test]
async fn start_fixed_completes_upload_before_delayed_response_headers() {
    let (client, server) = pair().await;
    let (release, wait) = tokio::sync::oneshot::channel();
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_request, mut stream) = server.accept().await;
            let body = drain_request(&mut stream).await.expect("request body");
            wait.await.expect("release response");
            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("response headers");
            stream.finish().await.expect("response finish");
            body
        }
    });

    let pending = timeout(
        DEADLINE,
        client.start_fixed(
            request(Method::POST, "/start-fixed"),
            Bytes::from_static(b"complete upload"),
        ),
    )
    .await
    .expect("start_fixed must not await response")
    .expect("fixed upload");
    release.send(()).expect("release response");
    let mut response = pending.open().await.expect("status 200");
    let mut sink = Vec::new();
    response.read_to_end(&mut sink).await.expect("response EOF");

    assert_eq!(handler.await.expect("server handler"), b"complete upload");
}

#[tokio::test]
async fn streaming_upload_and_download_progress_full_duplex() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_request, mut stream) = server.accept().await;
            let mut first = stream
                .recv_data()
                .await
                .expect("first request data")
                .expect("request data before FIN");
            let first = first.copy_to_bytes(first.remaining());
            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("response headers");
            stream
                .send_data(Bytes::from_static(b"reply-before-fin"))
                .await
                .expect("early response data");
            let mut rest = drain_request(&mut stream)
                .await
                .expect("remaining request body");
            stream.finish().await.expect("response finish");
            let mut whole = first.to_vec();
            whole.append(&mut rest);
            whole
        }
    });

    let (mut upload, pending) = client
        .start_streaming(request(Method::POST, "/full-duplex"))
        .await
        .expect("open streaming request");
    upload.write_all(b"first-").await.expect("first upload");
    let mut response = pending.open().await.expect("status 200");
    let mut early = vec![0_u8; b"reply-before-fin".len()];
    response
        .read_exact(&mut early)
        .await
        .expect("early response before request FIN");
    upload.write_all(b"second").await.expect("second upload");
    upload.shutdown().await.expect("request FIN");
    let mut tail = Vec::new();
    response.read_to_end(&mut tail).await.expect("response EOF");

    assert_eq!(early, b"reply-before-fin");
    assert!(tail.is_empty());
    assert_eq!(handler.await.expect("server handler"), b"first-second");
}

#[tokio::test]
async fn flush_delivers_request_data_without_half_closing_upload() {
    const SERVER_STREAM_WINDOW: u32 = 1024;
    const PAYLOAD_BYTES: usize = 8 * 1024;

    let (client, server) = pair_with_server_stream_window(SERVER_STREAM_WINDOW).await;
    let (accepted, request_accepted) = tokio::sync::oneshot::channel();
    let (release_reads, reads_released) = tokio::sync::oneshot::channel();
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_request, mut stream) = server.accept().await;
            accepted.send(()).expect("observe accepted request");
            reads_released.await.expect("release request reads");
            let mut received = Vec::new();
            while received.len() < PAYLOAD_BYTES {
                let mut data = stream
                    .recv_data()
                    .await
                    .expect("flushed request data")
                    .expect("request stays open after flush");
                received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }

            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("response after flushed data");
            stream
                .send_data(Bytes::from_static(b"ack"))
                .await
                .expect("response data");
            stream.finish().await.expect("response finish");
            let rest = drain_request(&mut stream).await.expect("request FIN");
            (received, rest)
        }
    });

    let (mut upload, pending) = client
        .start_streaming(request(Method::POST, "/flush"))
        .await
        .expect("open streaming request");
    request_accepted.await.expect("server accepted request");
    let payload = vec![0x5a; PAYLOAD_BYTES];
    upload.write_all(&payload).await.expect("write request");

    let mut flush = Box::pin(upload.flush());
    assert!(
        timeout(Duration::from_millis(100), &mut flush)
            .await
            .is_err(),
        "flush must wait while QUIC stream flow control is blocked"
    );
    release_reads.send(()).expect("release request reads");
    timeout(DEADLINE, &mut flush)
        .await
        .expect("flush after flow-control release")
        .expect("flush request DATA to QUIC");
    drop(flush);

    let mut response = timeout(DEADLINE, pending.open())
        .await
        .expect("response before request shutdown")
        .expect("status 200");
    let mut ack = [0_u8; 3];
    response
        .read_exact(&mut ack)
        .await
        .expect("response to flushed request data");
    upload.shutdown().await.expect("request FIN");
    let mut tail = Vec::new();
    response.read_to_end(&mut tail).await.expect("response EOF");

    assert_eq!(ack, *b"ack");
    assert!(tail.is_empty());
    assert_eq!(
        handler.await.expect("server handler"),
        (payload, Vec::new())
    );
}

#[tokio::test]
async fn h3_quinn_recv_stream_remains_stoppable_after_a_pending_read() {
    let (client_tls, server_addr, server) = server_with_options(None).await;
    let (response_sent, response_ready) = tokio::sync::oneshot::channel();
    let (observe_cancel, cancel_requested) = tokio::sync::oneshot::channel();
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_request, mut stream) = server.accept().await;
            drain_request(&mut stream).await.expect("request body");
            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("response headers");
            response_sent.send(()).expect("publish response headers");
            cancel_requested.await.expect("release cancellation probe");

            timeout(DEADLINE, async {
                loop {
                    match stream.send_data(Bytes::from_static(b"x")).await {
                        Ok(()) => tokio::task::yield_now().await,
                        Err(error) => break error,
                    }
                }
            })
            .await
            .expect("server observes STOP_SENDING")
        }
    });

    let mut endpoint = quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind direct QUIC client");
    let crypto = QuicClientConfig::try_from(client_tls).expect("QUIC client TLS");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = endpoint
        .connect(server_addr, "localhost")
        .expect("start direct QUIC connection")
        .await
        .expect("connect direct QUIC client");
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("start direct H3 client");
    let driver = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

    let stream = sender
        .send_request(request(Method::GET, "/adapter-cancel"))
        .await
        .expect("send direct H3 request");
    let (mut send, mut recv) = stream.split();
    send.finish().await.expect("request FIN");
    response_ready.await.expect("server response headers");
    recv.recv_response()
        .await
        .expect("receive response headers");

    // Poll exactly once into Pending, then cancel the future. h3-quinn 0.0.10
    // used to move its raw RecvStream into that future and panic here because
    // stop_sending subsequently unwrapped an empty Option.
    let mut pending_read = Box::pin(recv.recv_data());
    poll_fn(|cx| match pending_read.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("idle response read unexpectedly completed"),
    })
    .await;
    drop(pending_read);
    recv.stop_sending(Code::H3_REQUEST_CANCELLED);
    observe_cancel.send(()).expect("probe STOP_SENDING");

    let error = handler.await.expect("server handler");
    assert!(
        matches!(
            &error,
            h3::error::StreamError::RemoteTerminate { code, .. }
                if *code == Code::H3_REQUEST_CANCELLED
        ),
        "unexpected server stream error: {error:?}"
    );

    endpoint.close(
        quinn::VarInt::from_u32(Code::H3_NO_ERROR.value() as u32),
        b"adapter regression complete",
    );
    driver.abort();
}

#[tokio::test]
async fn response_drop_after_upload_fin_cancels_stream_and_reuses_connection() {
    let (client, server) = pair().await;
    let (response_sent, response_ready) = tokio::sync::oneshot::channel();
    let (observe_cancel, cancel_requested) = tokio::sync::oneshot::channel();
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_first_request, mut first) = server.accept().await;
            let upload = drain_request(&mut first).await.expect("completed upload");
            first
                .send_response(response(StatusCode::OK))
                .await
                .expect("first response headers");
            first
                .send_data(Bytes::from_static(b"ready"))
                .await
                .expect("first response data");
            response_sent.send(()).expect("publish first response");
            cancel_requested.await.expect("release cancellation probe");

            let cancellation = timeout(DEADLINE, async {
                loop {
                    match first.send_data(Bytes::from_static(b"x")).await {
                        Ok(()) => tokio::task::yield_now().await,
                        Err(error) => break error,
                    }
                }
            })
            .await
            .expect("server observes response cancellation");

            let (_second_request, mut second) = server.accept().await;
            drain_request(&mut second)
                .await
                .expect("second request body");
            second
                .send_response(response(StatusCode::OK))
                .await
                .expect("second response headers");
            second.finish().await.expect("second response FIN");
            (upload, cancellation)
        }
    });

    let (mut upload, pending) = client
        .start_streaming(request(Method::POST, "/completed-upload-cancel"))
        .await
        .expect("open first request");
    upload
        .write_all(b"complete before cancellation")
        .await
        .expect("first upload");
    upload.shutdown().await.expect("first upload FIN");
    let mut body = pending.open().await.expect("first response headers");
    response_ready.await.expect("first response DATA sent");
    let mut ready = [0_u8; 5];
    body.read_exact(&mut ready)
        .await
        .expect("first response data");
    assert_eq!(&ready, b"ready");

    // Let the response worker enter its next idle recv_data poll, which is the
    // state that triggered h3-quinn's detached cancellation panic.
    tokio::task::yield_now().await;
    drop(body);
    observe_cancel
        .send(())
        .expect("probe response cancellation");
    assert!(client.is_live(), "one cancelled stream must not kill H3");

    let mut second = client
        .send_fixed(request(Method::GET, "/after-body-drop"), Bytes::new())
        .await
        .expect("same H3 connection remains reusable");
    let mut sink = Vec::new();
    second
        .read_to_end(&mut sink)
        .await
        .expect("second response EOF");

    let (received, cancellation) = handler.await.expect("server handler");
    assert_eq!(received, b"complete before cancellation");
    assert!(
        matches!(
            &cancellation,
            h3::error::StreamError::RemoteTerminate { code, .. }
                if *code == Code::H3_REQUEST_CANCELLED
        ),
        "unexpected cancellation: {cancellation:?}"
    );
}

#[tokio::test]
async fn non_200_cancels_only_its_stream_and_connection_stays_reusable() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_first, mut first) = server.accept().await;
            drain_request(&mut first).await.expect("first request body");
            first
                .send_response(response(StatusCode::NOT_FOUND))
                .await
                .expect("404 response");
            first.finish().await.expect("404 finish");

            let (_second, mut second) = server.accept().await;
            drain_request(&mut second)
                .await
                .expect("second request body");
            second
                .send_response(response(StatusCode::OK))
                .await
                .expect("second response");
            second.finish().await.expect("second finish");
        }
    });

    let error = client
        .send_fixed(request(Method::GET, "/not-found"), Bytes::new())
        .await
        .expect_err("non-200 must fail");
    assert!(matches!(
        error,
        H3Error::UnexpectedStatus {
            status: StatusCode::NOT_FOUND
        }
    ));
    assert!(client.is_live());

    let mut body = client
        .send_fixed(request(Method::GET, "/after-404"), Bytes::new())
        .await
        .expect("connection remains reusable");
    let mut sink = Vec::new();
    body.read_to_end(&mut sink).await.expect("second EOF");
    handler.await.expect("server handler");
}

#[tokio::test]
async fn dropping_pending_response_resets_exchange_without_killing_connection() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_first, mut first) = server.accept().await;
            let first_result = first.recv_data().await;

            let (_second, mut second) = server.accept().await;
            drain_request(&mut second)
                .await
                .expect("second request body");
            second
                .send_response(response(StatusCode::OK))
                .await
                .expect("second response");
            second.finish().await.expect("second finish");
            first_result
        }
    });

    let (mut upload, pending) = client
        .start_streaming(request(Method::POST, "/cancel"))
        .await
        .expect("open first stream");
    drop(pending);
    let error = timeout(DEADLINE, upload.shutdown())
        .await
        .expect("cancelled upload deadline")
        .expect_err("sibling upload must fail");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert!(client.is_live());

    let mut body = client
        .send_fixed(request(Method::GET, "/after-cancel"), Bytes::new())
        .await
        .expect("connection remains reusable");
    let mut sink = Vec::new();
    body.read_to_end(&mut sink).await.expect("second EOF");
    assert!(handler.await.expect("server handler").is_err());
}

#[tokio::test]
async fn cloned_client_opens_concurrent_streams() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let mut exchanges = vec![server.accept().await, server.accept().await];
            exchanges.sort_by(|left, right| left.0.uri().path().cmp(right.0.uri().path()));
            for (request, mut stream) in exchanges {
                drain_request(&mut stream).await.expect("request body");
                stream
                    .send_response(response(StatusCode::OK))
                    .await
                    .expect("response headers");
                stream
                    .send_data(Bytes::from(request.uri().path().to_owned()))
                    .await
                    .expect("response data");
                stream.finish().await.expect("response finish");
            }
        }
    });

    let first = client.send_fixed(request(Method::GET, "/a"), Bytes::new());
    let second_client = client.clone();
    let second = second_client.send_fixed(request(Method::GET, "/b"), Bytes::new());
    let (mut first, mut second) = tokio::try_join!(first, second).expect("concurrent requests");
    let mut first_body = Vec::new();
    let mut second_body = Vec::new();
    first
        .read_to_end(&mut first_body)
        .await
        .expect("first body");
    second
        .read_to_end(&mut second_body)
        .await
        .expect("second body");

    assert_eq!((first_body, second_body), (b"/a".to_vec(), b"/b".to_vec()));
    handler.await.expect("server handler");
}

#[tokio::test]
async fn head_response_is_logically_bodyless_even_if_peer_sends_data() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (_request, mut stream) = server.accept().await;
            drain_request(&mut stream).await.expect("HEAD request body");
            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("response headers");
            let _ = stream.send_data(Bytes::from_static(b"illegal")).await;
            let _ = stream.finish().await;
        }
    });

    let mut body = client
        .send_fixed(request(Method::HEAD, "/head"), Bytes::new())
        .await
        .expect("HEAD status 200");
    let mut byte = [0_u8; 1];
    let read = timeout(DEADLINE, body.read(&mut byte))
        .await
        .expect("HEAD EOF deadline")
        .expect("HEAD read");

    assert_eq!(read, 0);
    handler.await.expect("server handler");
}

#[tokio::test]
async fn server_connection_close_retires_client_driver() {
    let (client, server) = pair().await;
    server.close_connection();

    timeout(DEADLINE, async {
        while client.is_live() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection-close retirement");
}

#[tokio::test]
async fn xhttp_h3_stream_one_is_full_duplex() {
    let (client, server) = pair().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (request, mut stream) = server.accept().await;
            let mut first = stream
                .recv_data()
                .await
                .expect("first request DATA")
                .expect("stream-one upload before FIN");
            let mut upload = first.copy_to_bytes(first.remaining()).to_vec();
            stream
                .send_response(response(StatusCode::OK))
                .await
                .expect("stream-one response headers");
            stream
                .send_data(Bytes::from_static(b"pong"))
                .await
                .expect("stream-one response DATA");
            stream.finish().await.expect("stream-one response FIN");
            upload.extend_from_slice(
                &drain_request(&mut stream)
                    .await
                    .expect("remaining stream-one upload"),
            );
            (request.method().clone(), upload)
        }
    });
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamOne, unlimited_xmux(), 4);
    let mut stream = transport
        .open_stream_with_h3_dial(h3_dial(client, Arc::clone(&dials)))
        .await
        .expect("open H3 stream-one");

    stream.write_all(b"ping").await.expect("write uplink");
    stream.flush().await.expect("flush uplink before FIN");
    let mut response_body = Vec::new();
    stream
        .read_to_end(&mut response_body)
        .await
        .expect("read response before upload FIN");
    stream.shutdown().await.expect("finish uplink");

    assert_eq!(response_body, b"pong");
    assert_eq!(
        handler.await.expect("server handler"),
        (Method::POST, b"ping".to_vec())
    );
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn h3_auto_gzip_decodes_only_exact_lowercase_content_encoding() {
    let (client, server) = pair().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h3_dial(client, Arc::clone(&dials));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            for encoding in ["gzip", "GZiP"] {
                let (request, mut stream) = server.accept().await;
                assert_eq!(request.headers()[http::header::ACCEPT_ENCODING], "gzip");
                drain_request(&mut stream)
                    .await
                    .expect("stream-one request body");
                let response = Response::builder()
                    .version(Version::HTTP_3)
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_ENCODING, encoding)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(Bytes::from_static(GZIP_PONG))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
        }
    });
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamOne, unlimited_xmux(), 4);

    for expected in [b"pong".as_slice(), GZIP_PONG] {
        let mut stream = transport
            .open_stream_with_h3_dial(Arc::clone(&dial))
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, expected);
        drop(stream);
    }

    handler.await.unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn explicit_accept_encoding_keeps_h3_gzip_response_compressed() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (request, mut stream) = server.accept().await;
            assert_eq!(request.headers()[http::header::ACCEPT_ENCODING], "gzip");
            drain_request(&mut stream).await.unwrap();
            let response = Response::builder()
                .version(Version::HTTP_3)
                .status(StatusCode::OK)
                .header(http::header::CONTENT_ENCODING, "gzip")
                .body(())
                .unwrap();
            stream.send_response(response).await.unwrap();
            stream
                .send_data(Bytes::from_static(GZIP_PONG))
                .await
                .unwrap();
            stream.finish().await.unwrap();
        }
    });
    let mut headers = XhttpHeaderMap::new();
    headers.set("Accept-Encoding", "gzip");
    let transport = xhttp_h3_transport_with_headers(
        XhttpModeSelection::StreamOne,
        unlimited_xmux(),
        4,
        headers,
    );
    let mut stream = transport
        .open_stream_with_h3_dial(h3_dial(client, Arc::new(AtomicUsize::new(0))))
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    assert_eq!(response, GZIP_PONG);
    handler.await.unwrap();
}

#[tokio::test]
async fn malformed_h3_auto_gzip_does_not_retire_the_pooled_connection() {
    let (client, server) = pair().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h3_dial(client, Arc::clone(&dials));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            for malformed in [true, false] {
                let (request, mut stream) = server.accept().await;
                assert_eq!(request.headers()[http::header::ACCEPT_ENCODING], "gzip");
                drain_request(&mut stream).await.unwrap();
                let mut response = Response::builder()
                    .version(Version::HTTP_3)
                    .status(StatusCode::OK);
                if malformed {
                    response = response.header(http::header::CONTENT_ENCODING, "gzip");
                }
                stream
                    .send_response(response.body(()).unwrap())
                    .await
                    .unwrap();
                stream
                    .send_data(if malformed {
                        Bytes::from_static(b"not-gzip")
                    } else {
                        Bytes::from_static(b"healthy")
                    })
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
        }
    });
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamOne, unlimited_xmux(), 4);

    let mut malformed = transport
        .open_stream_with_h3_dial(Arc::clone(&dial))
        .await
        .unwrap();
    malformed.shutdown().await.unwrap();
    let mut ignored = Vec::new();
    let error = malformed
        .read_to_end(&mut ignored)
        .await
        .expect_err("malformed gzip must reach the caller");
    assert!(error.to_string().contains("gzip response decode failed"));
    drop(malformed);

    let mut healthy = transport.open_stream_with_h3_dial(dial).await.unwrap();
    healthy.shutdown().await.unwrap();
    let mut response = Vec::new();
    healthy.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"healthy");

    handler.await.unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn xhttp_h3_stream_up_uses_one_session_for_get_and_post() {
    let (client, server) = pair().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (download_request, mut download) = server.accept().await;
            assert_eq!(
                download_request.headers()[http::header::ACCEPT_ENCODING],
                "gzip"
            );
            let download_body = drain_request(&mut download)
                .await
                .expect("empty download request body");
            download
                .send_response(response(StatusCode::OK))
                .await
                .expect("download response headers");
            download
                .send_data(Bytes::from_static(b"pong"))
                .await
                .expect("download response DATA");
            download.finish().await.expect("download response FIN");

            let (upload_request, mut upload) = server.accept().await;
            assert_eq!(
                upload_request.headers()[http::header::ACCEPT_ENCODING],
                "gzip"
            );
            let upload_body = drain_request(&mut upload).await.expect("stream-up body");
            let upload_response = Response::builder()
                .version(Version::HTTP_3)
                .status(StatusCode::OK)
                .header(http::header::CONTENT_ENCODING, "gzip")
                .body(())
                .unwrap();
            upload
                .send_response(upload_response)
                .await
                .expect("upload response headers");
            upload
                .send_data(Bytes::from_static(GZIP_PONG))
                .await
                .expect("compressed upload response body");
            upload.finish().await.expect("upload response FIN");
            (
                download_request.method().clone(),
                download_request.uri().path().to_owned(),
                download_body,
                upload_request.method().clone(),
                upload_request.uri().path().to_owned(),
                upload_body,
            )
        }
    });
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamUp, unlimited_xmux(), 4);
    let mut stream = transport
        .open_stream_with_h3_dial(h3_dial(client, Arc::clone(&dials)))
        .await
        .expect("open H3 stream-up");

    stream.write_all(b"ping").await.expect("write upload");
    stream.shutdown().await.expect("finish upload");
    let mut response_body = Vec::new();
    stream
        .read_to_end(&mut response_body)
        .await
        .expect("read download");

    let (down_method, down_path, down_body, up_method, up_path, up_body) =
        handler.await.expect("server handler");
    assert_eq!(response_body, b"pong");
    assert_eq!(down_method, Method::GET);
    assert_eq!(up_method, Method::POST);
    assert!(down_body.is_empty());
    assert_eq!(up_body, b"ping");
    assert_eq!(down_path, up_path);
    assert_eq!(
        dials.load(Ordering::Acquire),
        2,
        "the conservative H3 pool gives persistent GET and POST separate connections"
    );
}

#[tokio::test]
async fn xhttp_h3_packet_503_wakes_pending_downlink_with_the_same_error() {
    let (client, server) = pair().await;
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let (download_request, mut download) = server.accept().await;
            assert_eq!(download_request.method(), Method::GET);
            drain_request(&mut download)
                .await
                .expect("empty packet downlink request");
            download
                .send_response(response(StatusCode::OK))
                .await
                .expect("pending downlink headers");

            let (upload_request, mut upload) = server.accept().await;
            assert_ne!(upload_request.method(), Method::GET);
            let body = drain_request(&mut upload)
                .await
                .expect("packet upload body");
            upload
                .send_response(response(StatusCode::SERVICE_UNAVAILABLE))
                .await
                .expect("packet rejection headers");
            let _ = upload.finish().await;
            body
        }
    });
    let transport = xhttp_h3_transport(XhttpModeSelection::PacketUp, unlimited_xmux(), 4);
    let mut stream = transport
        .open_stream_with_h3_dial(h3_dial(client, Arc::new(AtomicUsize::new(0))))
        .await
        .expect("open H3 packet-up");
    stream.write_all(b"boom").await.expect("queue packet");

    let mut byte = [0_u8; 1];
    let read_error = timeout(DEADLINE, stream.read(&mut byte))
        .await
        .expect("blocked H3 downlink was not woken")
        .expect_err("upload 503 must fail the logical stream");
    let write_error = stream
        .write_all(b"after-error")
        .await
        .expect_err("same shared failure must reach writes");
    assert_eq!(handler.await.expect("server handler"), b"boom");
    assert_eq!(read_error.to_string(), write_error.to_string());
    assert_eq!(
        read_error.to_string(),
        "XHTTP HTTP/3 server returned status 503 Service Unavailable"
    );
}

#[tokio::test]
async fn xhttp_h3_pool_reuses_one_dial_for_sequential_streams() {
    let (client, server) = pair().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h3_dial(client, Arc::clone(&dials));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let first = serve_clean_exchange(&server).await;
            let second = serve_clean_exchange(&server).await;
            (first, second)
        }
    });
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamOne, unlimited_xmux(), 4);

    for _ in 0..2 {
        let mut stream = transport
            .open_stream_with_h3_dial(Arc::clone(&dial))
            .await
            .expect("open pooled H3 stream");
        stream.shutdown().await.expect("finish pooled request");
        let mut sink = Vec::new();
        stream
            .read_to_end(&mut sink)
            .await
            .expect("pooled response");
    }

    let ((first_method, _, first_body), (second_method, _, second_body)) =
        handler.await.expect("server handler");
    assert_eq!((first_method, second_method), (Method::POST, Method::POST));
    assert!(first_body.is_empty());
    assert!(second_body.is_empty());
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn h3_pool_fans_out_at_peer_stream_limit_one_then_reuses_connections() {
    let (client_tls, server_addr, server) = server_with_transport_options(None, Some(1)).await;
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h3_network_dial(client_tls, server_addr, Arc::clone(&dials));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let mut uploads = Vec::new();
            for expected_body in [b"first".as_slice(), b"second".as_slice()] {
                let first = server.accept().await;
                let second = server.accept().await;
                let ((download_request, mut download), (upload_request, mut upload)) =
                    if first.0.method() == Method::GET {
                        (first, second)
                    } else {
                        (second, first)
                    };
                assert_eq!(download_request.method(), Method::GET);
                assert!(drain_request(&mut download).await.unwrap().is_empty());
                download
                    .send_response(response(StatusCode::OK))
                    .await
                    .expect("download response headers");

                assert_eq!(upload_request.method(), Method::POST);
                let body = drain_request(&mut upload).await.expect("upload body");
                assert_eq!(body, expected_body);
                uploads.push(body);
                upload
                    .send_response(response(StatusCode::OK))
                    .await
                    .expect("upload response headers");
                upload.finish().await.expect("upload response finish");

                download
                    .send_data(Bytes::from_static(b"pong"))
                    .await
                    .expect("download response body");
                download.finish().await.expect("download response finish");
            }
            uploads
        }
    });
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamUp, unlimited_xmux(), 4);

    for payload in [b"first".as_slice(), b"second".as_slice()] {
        let mut stream = timeout(
            DEADLINE,
            transport.open_stream_with_h3_dial(Arc::clone(&dial)),
        )
        .await
        .expect("peer MAX_STREAMS_BIDI=1 must not deadlock stream-up")
        .expect("open H3 stream-up");
        assert_eq!(
            dials.load(Ordering::Acquire),
            2,
            "persistent download and upload need two connections, then reuse them"
        );
        stream.write_all(payload).await.expect("write upload");
        stream.shutdown().await.expect("finish upload");
        let mut response_body = Vec::new();
        stream
            .read_to_end(&mut response_body)
            .await
            .expect("read download response");
        assert_eq!(response_body, b"pong");
    }

    assert_eq!(
        handler.await.expect("server handler"),
        vec![b"first".to_vec(), b"second".to_vec()]
    );
    assert_eq!(
        dials.load(Ordering::Acquire),
        2,
        "released low-capacity connections must be reused without a third dial"
    );
}

#[tokio::test]
async fn xhttp_h3_xmux_fans_out_concurrent_logical_streams() {
    let (client, server) = pair().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h3_dial(client, Arc::clone(&dials));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            let first = serve_clean_exchange(&server).await;
            let second = serve_clean_exchange(&server).await;
            (first, second)
        }
    });
    let mut xmux = unlimited_xmux();
    xmux.max_concurrency = XhttpRange::exact(1);
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamOne, xmux, 4);

    let mut first = transport
        .open_stream_with_h3_dial(Arc::clone(&dial))
        .await
        .expect("open first H3 logical stream");
    let mut second = transport
        .open_stream_with_h3_dial(dial)
        .await
        .expect("open second H3 logical stream");
    first.shutdown().await.expect("finish first upload");
    second.shutdown().await.expect("finish second upload");
    let mut first_response = Vec::new();
    let mut second_response = Vec::new();
    first
        .read_to_end(&mut first_response)
        .await
        .expect("first response");
    second
        .read_to_end(&mut second_response)
        .await
        .expect("second response");

    handler.await.expect("server handler");
    assert_eq!(dials.load(Ordering::Acquire), 2);
    assert_eq!(transport.xmux_client_count().await, 2);
}

#[tokio::test]
async fn xhttp_h3_idle_connection_is_retired_before_the_next_checkout() {
    let (client, server) = pair().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h3_dial(client, Arc::clone(&dials));
    let handler = tokio::spawn({
        let server = server.clone();
        async move {
            serve_clean_exchange(&server).await;
            serve_clean_exchange(&server).await;
        }
    });
    let elapsed = Arc::new(AtomicU64::new(0));
    let anchor = Instant::now();
    let clock: XhttpClock = {
        let elapsed = Arc::clone(&elapsed);
        Arc::new(move || anchor + Duration::from_secs(elapsed.load(Ordering::Acquire)))
    };
    let transport = xhttp_h3_transport(XhttpModeSelection::StreamOne, unlimited_xmux(), 4)
        .with_clock(clock)
        .expect("inject clock")
        .with_h3_idle_timeout(Duration::from_secs(3))
        .expect("inject H3 idle timeout");

    let mut first = transport
        .open_stream_with_h3_dial(Arc::clone(&dial))
        .await
        .expect("first H3 stream");
    first.shutdown().await.expect("first upload FIN");
    let mut sink = Vec::new();
    first.read_to_end(&mut sink).await.expect("first response");
    drop(first);
    elapsed.store(4, Ordering::Release);

    let mut second = transport
        .open_stream_with_h3_dial(dial)
        .await
        .expect("second H3 stream");
    second.shutdown().await.expect("second upload FIN");
    second
        .read_to_end(&mut sink)
        .await
        .expect("second response");

    handler.await.expect("server handler");
    assert_eq!(dials.load(Ordering::Acquire), 2);
}

#[test]
fn xhttp_h3_keepalive_defaults_only_for_zero_xmux_policy() {
    let (config, endpoint) = xhttp_config(XhttpModeSelection::StreamOne, 4);
    let transport = XhttpTransport::new(
        config.clone(),
        endpoint.clone(),
        XhttpHttpVersion::Http3,
        unlimited_xmux(),
    )
    .expect("default H3 transport");
    assert_eq!(
        transport.h3_quic_config().keep_alive_interval,
        Some(Duration::from_secs(10))
    );

    for h_keep_alive_period_secs in [-1, 7] {
        let mut xmux = unlimited_xmux();
        xmux.h_keep_alive_period_secs = h_keep_alive_period_secs;
        let transport = XhttpTransport::new(
            config.clone(),
            endpoint.clone(),
            XhttpHttpVersion::Http3,
            xmux,
        )
        .expect("explicit xmux keepalive policy");
        assert_eq!(transport.h3_quic_config().keep_alive_interval, None);
    }

    let quic = H3QuicConfig {
        keep_alive_interval: Some(Duration::from_secs(3)),
        ..H3QuicConfig::default()
    };
    let transport = XhttpTransport::new_with_h3_quic(
        config,
        endpoint,
        XhttpHttpVersion::Http3,
        unlimited_xmux(),
        quic,
    )
    .expect("explicit QUIC keepalive");
    assert_eq!(
        transport.h3_quic_config().keep_alive_interval,
        Some(Duration::from_secs(3))
    );
}

#[derive(Default)]
struct RecordingProtector {
    calls: AtomicUsize,
}

impl SocketProtector for RecordingProtector {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        assert!(socket.raw() >= 0);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn udp_socket_is_protected_before_quinn_takes_ownership() {
    let protector = Arc::new(RecordingProtector::default());
    let protector_dyn: Arc<dyn SocketProtector> = protector.clone();
    let (client, _server) = pair_with_protector(Some(protector_dyn)).await;

    assert!(client.is_live());
    assert_eq!(protector.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn preprotected_tls_connector_protects_every_production_h3_candidate() {
    let (client_tls, server_addr, server) = server_with_options(None).await;
    let protector = Arc::new(RecordingProtector::default());
    let protector_dyn: Arc<dyn SocketProtector> = protector.clone();
    let dialer = TransportDialer::with_tls_connector(
        TlsConnector::with_pinned_client_config(client_tls).with_socket_protector(protector_dyn),
    );
    let connector = ConnectorConfig::Tls(TlsClientConfig {
        server_name: "localhost".to_owned(),
        allow_insecure: false,
        alpn: vec!["http/1.1".to_owned()],
        fingerprint: Some("fingerprint-is-ignored-by-h3".to_owned()),
    });
    let target = Target::new(
        TargetAddr::Ip(server_addr.ip()),
        server_addr.port(),
        Network::Tcp,
    );
    let unused_socket =
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve unused UDP candidate");
    let unused_addr = unused_socket.local_addr().expect("unused UDP address");
    drop(unused_socket);
    let happy_eyeballs = HappyEyeballsConfig {
        prioritize_ipv6: false,
        interleave: 1,
        try_delay: Duration::from_millis(5),
        max_concurrent: NonZeroUsize::new(2).expect("nonzero test concurrency"),
    };
    let layer = TransportLayer::Xhttp(xhttp_h3_transport(
        XhttpModeSelection::StreamOne,
        unlimited_xmux(),
        4,
    ));
    let handler = tokio::spawn({
        let server = server.clone();
        async move { serve_clean_exchange(&server).await }
    });

    let mut stream = timeout(
        DEADLINE,
        dialer.connect_stream(
            &connector,
            &layer,
            &target,
            &[unused_addr, server_addr],
            Some(&happy_eyeballs),
        ),
    )
    .await
    .expect("production H3 Happy Eyeballs deadline")
    .expect("production H3 dial through preprotected connector");
    stream.shutdown().await.expect("finish production upload");
    let mut sink = Vec::new();
    stream
        .read_to_end(&mut sink)
        .await
        .expect("production H3 response");

    handler.await.expect("server handler");
    assert_eq!(
        protector.calls.load(Ordering::SeqCst),
        2,
        "both the losing and winning UDP sockets must be protected"
    );
}

#[tokio::test]
async fn production_h3_rejects_tcp_and_reality_security_without_downgrade() {
    let dialer = TransportDialer::system().expect("system dialer");
    let target = Target::new(
        TargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
        443,
        Network::Tcp,
    );
    let layer = TransportLayer::Xhttp(xhttp_h3_transport(
        XhttpModeSelection::StreamOne,
        unlimited_xmux(),
        4,
    ));
    let reality = xray_transport::RealityClientConfig {
        server_name: "example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [0; 32],
        short_id: Vec::new(),
        spider_x: "/".to_owned(),
        mldsa65_verify: None,
    };

    for (connector, expected) in [
        (ConnectorConfig::Tcp, "TCP"),
        (ConnectorConfig::Reality(reality), "REALITY"),
    ] {
        let result = dialer
            .connect_stream(
                &connector,
                &layer,
                &target,
                &[SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9)],
                None,
            )
            .await;
        let error = match result {
            Ok(_) => panic!("H3 must require stock TLS"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected),
            "unexpected error for {expected}: {error}"
        );
    }
}

struct FailingProtector {
    calls: AtomicUsize,
}

impl SocketProtector for FailingProtector {
    fn protect(&self, _socket: SocketHandle) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deliberate protection failure",
        ))
    }
}

#[tokio::test]
async fn invalid_sni_precedes_socket_protection_and_protection_failure_stops_candidate_race() {
    let (client_tls, server_addr, _server) = server_with_options(None).await;
    let recording = Arc::new(RecordingProtector::default());
    let error = connect_h3(H3ConnectConfig {
        remote_addr: server_addr,
        server_name: "invalid server name".to_owned(),
        tls_config: Arc::clone(&client_tls),
        socket_protector: Some(recording.clone()),
        quic: H3QuicConfig::default(),
    })
    .await
    .expect_err("invalid SNI must fail before UDP bind/protection");
    assert!(matches!(
        error,
        H3Error::Transport(xray_transport::TransportError::InvalidTlsServerName(_))
    ));
    assert_eq!(recording.calls.load(Ordering::SeqCst), 0);

    let failing = Arc::new(FailingProtector {
        calls: AtomicUsize::new(0),
    });
    let policy = HappyEyeballsConfig {
        prioritize_ipv6: false,
        interleave: 1,
        try_delay: Duration::from_millis(1),
        max_concurrent: NonZeroUsize::new(2).expect("nonzero test concurrency"),
    };
    let error = xray_transport::stream::xhttp_h3_test_only::connect_h3_candidates(
        H3ConnectConfig {
            remote_addr: server_addr,
            server_name: "localhost".to_owned(),
            tls_config: client_tls,
            socket_protector: Some(failing.clone()),
            quic: H3QuicConfig::default(),
        },
        &[server_addr, server_addr],
        Some(&policy),
    )
    .await
    .expect_err("protection failure must be fatal to the whole candidate race");
    assert!(matches!(
        error,
        H3Error::Transport(xray_transport::TransportError::SocketProtection(_))
    ));
    assert_eq!(
        failing.calls.load(Ordering::SeqCst),
        1,
        "a protection failure must not try another candidate"
    );
}

#[test]
fn default_quic_diagnostics_expose_static_window_approximation() {
    let config = H3QuicConfig::default();
    let diagnostics = config
        .diagnostics()
        .expect("the supported default must remain usable");

    assert_eq!(config.initial_stream_receive_window, 2 * 1024 * 1024);
    assert_eq!(config.max_stream_receive_window, None);
    assert_eq!(config.initial_connection_receive_window, 3 * 1024 * 1024);
    assert_eq!(config.max_connection_receive_window, None);
    assert_eq!(diagnostics.stream_receive_window, 2 * 1024 * 1024);
    assert_eq!(diagnostics.connection_receive_window, 3 * 1024 * 1024);
    assert!(!diagnostics.adaptive_receive_windows);
}

#[test]
fn unsupported_quic_parity_modes_fail_closed() {
    let mut config = H3QuicConfig {
        version: H3QuicVersion::V2,
        ..H3QuicConfig::default()
    };
    assert!(matches!(
        config.diagnostics(),
        Err(H3Error::UnsupportedQuicVersion {
            requested: H3QuicVersion::V2
        })
    ));
    let (xhttp, endpoint) = xhttp_config(XhttpModeSelection::StreamOne, 4);
    assert!(XhttpTransport::new_with_h3_quic(
        xhttp,
        endpoint,
        XhttpHttpVersion::Http3,
        unlimited_xmux(),
        config.clone(),
    )
    .is_err());

    config.version = H3QuicVersion::V1;
    config.max_stream_receive_window = Some(6 * 1024 * 1024);
    assert!(matches!(
        config.diagnostics(),
        Err(H3Error::UnsupportedAdaptiveReceiveWindows { .. })
    ));

    config.max_stream_receive_window = None;
    config.congestion = H3Congestion::ForceBrutal {
        bytes_per_second: 65_536,
    };
    assert!(matches!(
        config.diagnostics(),
        Err(H3Error::UnsupportedCongestion {
            requested: H3Congestion::ForceBrutal { .. }
        })
    ));

    config.congestion = H3Congestion::BbrStandard;
    config.udp_hop = H3UdpHopConfig {
        ports: vec![443, 8443],
        interval_min: Duration::from_secs(5),
        interval_max: Duration::from_secs(10),
    };
    assert!(matches!(
        config.diagnostics(),
        Err(H3Error::UnsupportedUdpHop { port_count: 2, .. })
    ));

    config.udp_hop = H3UdpHopConfig::default();
    config.debug = true;
    assert!(matches!(
        config.diagnostics(),
        Err(H3Error::UnsupportedDebugLogging)
    ));
}
