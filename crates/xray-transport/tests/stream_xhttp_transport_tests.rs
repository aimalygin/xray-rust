use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::{client, server, Ping, Reason, RecvStream};
use http::{header, Method, Response, StatusCode};
use rand::rngs::mock::StepRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Instant};

use xray_transport::stream::xhttp_composer_test_only::{
    NormalizedRange, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpMetadataPlacement,
    XhttpModeSelection, XhttpRange, XhttpScheme,
};
use xray_transport::stream::xhttp_transport_test_only::{
    XhttpClock, XhttpDial, XhttpHttpVersion, XhttpTransport, XhttpXmuxPolicy,
};
use xray_transport::stream::HeaderMap;
use xray_transport::{BoxedTransportStream, TransportError, TransportStream};

const DEADLINE: Duration = Duration::from_secs(3);
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_FRAME_HEADER_LEN: usize = 9;
const H2_RST_STREAM_FRAME: u8 = 0x3;
const H2_SETTINGS_FRAME: u8 = 0x4;
const H2_PING_FRAME: u8 = 0x6;
const H2_ACK_FLAG: u8 = 0x1;
const GZIP_PONG: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x2b, 0xc8, 0xcf, 0x4b, 0x07, 0x00,
    0x4f, 0x41, 0x58, 0x21, 0x04, 0x00, 0x00, 0x00,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedH2Reset {
    stream_id: u32,
    reason: Reason,
}

struct FrameObservedStream {
    inner: DuplexStream,
    writes: Vec<u8>,
    preface_observed: bool,
    settings_ack: Option<oneshot::Sender<()>>,
    ping_ack: Option<oneshot::Sender<()>>,
    resets: Option<mpsc::UnboundedSender<ObservedH2Reset>>,
}

impl FrameObservedStream {
    fn new(inner: DuplexStream) -> (Self, oneshot::Receiver<()>, oneshot::Receiver<()>) {
        let (settings_ack, settings_observed) = oneshot::channel();
        let (ping_ack, ping_observed) = oneshot::channel();
        (
            Self {
                inner,
                writes: Vec::new(),
                preface_observed: false,
                settings_ack: Some(settings_ack),
                ping_ack: Some(ping_ack),
                resets: None,
            },
            settings_observed,
            ping_observed,
        )
    }

    fn new_with_reset_observation(
        inner: DuplexStream,
    ) -> (
        Self,
        oneshot::Receiver<()>,
        oneshot::Receiver<()>,
        mpsc::UnboundedReceiver<ObservedH2Reset>,
    ) {
        let (mut stream, settings_ack, ping_ack) = Self::new(inner);
        let (resets, observed_resets) = mpsc::unbounded_channel();
        stream.resets = Some(resets);
        (stream, settings_ack, ping_ack, observed_resets)
    }

    fn observe_complete_frames(&mut self) {
        if !self.preface_observed {
            if self.writes.len() < H2_PREFACE.len() {
                return;
            }
            assert!(
                self.writes.starts_with(H2_PREFACE),
                "observed client write did not start with the HTTP/2 preface"
            );
            self.writes.drain(..H2_PREFACE.len());
            self.preface_observed = true;
        }

        while self.writes.len() >= H2_FRAME_HEADER_LEN {
            let payload_len = usize::from(self.writes[0]) << 16
                | usize::from(self.writes[1]) << 8
                | usize::from(self.writes[2]);
            let frame_len = H2_FRAME_HEADER_LEN + payload_len;
            if self.writes.len() < frame_len {
                return;
            }

            let frame_type = self.writes[3];
            let flags = self.writes[4];
            if frame_type == H2_RST_STREAM_FRAME {
                assert_eq!(payload_len, 4, "outbound RST_STREAM payload length");
                let stream_id = u32::from_be_bytes([
                    self.writes[5],
                    self.writes[6],
                    self.writes[7],
                    self.writes[8],
                ]) & 0x7fff_ffff;
                let reason = Reason::from(u32::from_be_bytes([
                    self.writes[9],
                    self.writes[10],
                    self.writes[11],
                    self.writes[12],
                ]));
                if let Some(resets) = &self.resets {
                    let _ = resets.send(ObservedH2Reset { stream_id, reason });
                }
            }
            if flags & H2_ACK_FLAG != 0 {
                let notification = match frame_type {
                    H2_SETTINGS_FRAME => &mut self.settings_ack,
                    H2_PING_FRAME => &mut self.ping_ack,
                    _ => {
                        self.writes.drain(..frame_len);
                        continue;
                    }
                };
                if let Some(notification) = notification.take() {
                    let _ = notification.send(());
                }
            }
            self.writes.drain(..frame_len);
        }
    }
}

impl AsyncRead for FrameObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for FrameObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = match Pin::new(&mut self.inner).poll_write(cx, input) {
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        self.writes.extend_from_slice(&input[..written]);
        self.observe_complete_frames();
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TransportStream for FrameObservedStream {
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

#[tokio::test]
async fn h2_frame_observer_reports_settings_and_ping_ack_once() {
    let (client_io, server_io) = tokio::io::duplex(16);
    let (client_io, settings_ack, ping_ack) = FrameObservedStream::new(client_io);
    let (client, server) = tokio::join!(client::handshake(client_io), server::handshake(server_io));
    let (send_request, client_connection) = client.expect("client HTTP/2 handshake");
    let mut server_connection = server.expect("server HTTP/2 handshake");
    let client_driver = tokio::spawn(client_connection);

    let mut ping_pong = server_connection
        .ping_pong()
        .expect("server connection PingPong");
    let ping = ping_pong.ping(Ping::opaque());
    tokio::pin!(ping);
    let drive_server_until_pong = async {
        tokio::select! {
            result = &mut ping => result,
            exchange = server_connection.accept() => {
                match exchange {
                    Some(Ok((request, _))) => {
                        panic!("unexpected request while awaiting PING ACK: {}", request.uri());
                    }
                    Some(Err(error)) => {
                        panic!("server connection failed while awaiting PING ACK: {error}");
                    }
                    None => panic!("server connection closed before PING ACK"),
                }
            }
        }
    };

    let (settings_result, ping_result, pong_result) = timeout(DEADLINE, async {
        tokio::join!(settings_ack, ping_ack, drive_server_until_pong)
    })
    .await
    .expect("client SETTINGS and PING acknowledgements");
    settings_result.expect("SETTINGS ACK observation sender");
    ping_result.expect("PING ACK observation sender");
    pong_result.expect("server consumed PING ACK");

    drop(server_connection);
    drop(send_request);
    client_driver.abort();
    let _ = client_driver.await;
}

#[tokio::test]
async fn h2_frame_observer_reports_one_fragmented_rst_stream() {
    let (client_io, _server_io) = tokio::io::duplex(64);
    let (mut client_io, _settings_ack, _ping_ack, mut resets) =
        FrameObservedStream::new_with_reset_observation(client_io);
    let reset = [
        0, 0, 4, 0x3, 0, // four-byte RST_STREAM payload
        0, 0, 0, 7, // stream ID 7
        0, 0, 0, 8, // CANCEL
    ];

    client_io.write_all(H2_PREFACE).await.unwrap();
    client_io.write_all(&reset[..5]).await.unwrap();
    assert!(matches!(
        resets.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    client_io.write_all(&reset[5..11]).await.unwrap();
    assert!(matches!(
        resets.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    client_io.write_all(&reset[11..]).await.unwrap();

    assert_eq!(
        resets.recv().await,
        Some(ObservedH2Reset {
            stream_id: 7,
            reason: Reason::CANCEL,
        })
    );
    assert!(matches!(
        resets.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn scripted_h2_dial_uses_fifo_and_reports_exhaustion() {
    let (first_client, mut first_server_io) = tokio::io::duplex(64);
    let first_server = tokio::spawn(async move {
        let mut request = [0_u8; 1];
        first_server_io.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [1]);
        first_server_io.write_all(&[11]).await.unwrap();
    });
    let (second_client, mut second_server_io) = tokio::io::duplex(64);
    let second_server = tokio::spawn(async move {
        let mut request = [0_u8; 1];
        second_server_io.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [2]);
        second_server_io.write_all(&[22]).await.unwrap();
    });
    let (dial, dials) = scripted_h2_dial([
        (Box::new(first_client) as BoxedTransportStream, first_server),
        (
            Box::new(second_client) as BoxedTransportStream,
            second_server,
        ),
    ]);

    timeout(DEADLINE, async {
        for (request, expected_response) in [(1, 11), (2, 22)] {
            let mut stream = dial().await.unwrap();
            stream.write_all(&[request]).await.unwrap();
            let mut response = [0_u8; 1];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [expected_response]);
        }
    })
    .await
    .expect("scripted H2 dial entries");
    assert_eq!(dials.load(Ordering::Acquire), 2);

    let error = match dial().await {
        Ok(_) => panic!("exhausted scripted H2 dial must fail"),
        Err(error) => error,
    };
    match error {
        TransportError::Tcp(error) => assert_eq!(error.kind(), io::ErrorKind::NotConnected),
        other => panic!("unexpected exhausted dial error: {other}"),
    }
    assert_eq!(dials.load(Ordering::Acquire), 3);
}

#[tokio::test]
async fn h1_stream_one_is_full_duplex_and_uses_only_the_supplied_dial() {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let head = read_h1_head(&mut server).await?;
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
            .await?;
        let upload = read_h1_chunked(&mut server).await?;
        Ok::<_, io::Error>((head, upload))
    });

    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport
        .open_stream_with_dial(queued_dial([client]))
        .await
        .expect("stream-one should open after its request head is flushed");
    stream.write_all(b"ping").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"pong");

    let (head, upload) = timeout(DEADLINE, server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(head.starts_with(b"POST /api/ HTTP/1.1\r\n"));
    assert!(contains(&head, b"Transfer-Encoding: chunked\r\n"));
    assert!(contains(&head, b"Connection: close\r\n"));
    assert_eq!(upload, b"ping");
}

#[tokio::test]
async fn h1_stream_auto_gzip_is_injected_and_mixed_case_encoding_is_decoded() {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let head = read_h1_head(&mut server).await?;
        server
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Encoding: GZiP\r\nContent-Length: {}\r\n\r\n",
                    GZIP_PONG.len()
                )
                .as_bytes(),
            )
            .await?;
        server.write_all(GZIP_PONG).await?;
        let _ = read_h1_chunked(&mut server).await?;
        Ok::<_, io::Error>(head)
    });

    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport
        .open_stream_with_dial(queued_dial([client]))
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    assert_eq!(response, b"pong");
    let head = server_task.await.unwrap().unwrap();
    assert!(contains(&head, b"Accept-Encoding: gzip\r\n"));
}

#[tokio::test]
async fn explicit_accept_encoding_keeps_h1_gzip_response_compressed() {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let head = read_h1_head(&mut server).await?;
        server
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                    GZIP_PONG.len()
                )
                .as_bytes(),
            )
            .await?;
        server.write_all(GZIP_PONG).await?;
        let _ = read_h1_chunked(&mut server).await?;
        Ok::<_, io::Error>(head)
    });
    let mut headers = HeaderMap::new();
    headers.set("Accept-Encoding", "gzip");
    let transport = transport_with_headers(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        4,
        headers,
    );
    let mut stream = transport
        .open_stream_with_dial(queued_dial([client]))
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    assert_eq!(response, GZIP_PONG);
    let head = server_task.await.unwrap().unwrap();
    assert!(contains(&head, b"Accept-Encoding: gzip\r\n"));
}

#[tokio::test]
async fn h1_stream_up_uses_separate_downlink_and_uplink_sockets_with_one_session() {
    let (down_client, mut down_server) = tokio::io::duplex(64 * 1024);
    let (up_client, mut up_server) = tokio::io::duplex(64 * 1024);
    let down = tokio::spawn(async move {
        let head = read_h1_head(&mut down_server).await?;
        down_server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
            .await?;
        Ok::<_, io::Error>(head)
    });
    let up = tokio::spawn(async move {
        let head = read_h1_head(&mut up_server).await?;
        let body = read_h1_chunked(&mut up_server).await?;
        up_server
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                    GZIP_PONG.len()
                )
                .as_bytes(),
            )
            .await?;
        up_server.write_all(GZIP_PONG).await?;
        Ok::<_, io::Error>((head, body))
    });

    let transport = transport(
        XhttpModeSelection::StreamUp,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport
        .open_stream_with_dial(queued_dial([down_client, up_client]))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"pong");

    let down_head = down.await.unwrap().unwrap();
    let (up_head, upload) = up.await.unwrap().unwrap();
    assert!(down_head.starts_with(b"GET "));
    assert!(up_head.starts_with(b"POST "));
    assert!(contains(&down_head, b"Connection: close\r\n"));
    assert!(contains(&up_head, b"Connection: close\r\n"));
    assert!(contains(&down_head, b"Accept-Encoding: gzip\r\n"));
    assert!(contains(&up_head, b"Accept-Encoding: gzip\r\n"));
    assert_eq!(h1_path(&down_head), h1_path(&up_head));
    assert_eq!(upload, b"ping");
}

#[tokio::test]
async fn h1_custom_session_ids_share_one_flow_then_refresh_for_the_next_flow() {
    let (first_down_client, first_down_server) = tokio::io::duplex(64 * 1024);
    let (first_up_client, first_up_server) = tokio::io::duplex(64 * 1024);
    let first_server = tokio::spawn(serve_h1_stream_up_session(
        first_down_server,
        first_up_server,
    ));
    let (second_down_client, second_down_server) = tokio::io::duplex(64 * 1024);
    let (second_up_client, second_up_server) = tokio::io::duplex(64 * 1024);
    let second_server = tokio::spawn(serve_h1_stream_up_session(
        second_down_server,
        second_up_server,
    ));

    let config = XhttpConfig::normalize(XhttpConfigInput {
        mode: XhttpModeSelection::StreamUp,
        path: "/api".to_owned(),
        x_padding_bytes: XhttpRange::exact(1),
        session_placement: XhttpMetadataPlacement::Header,
        session_key: "X-Custom-Session".to_owned(),
        session_id_table: "Base62".to_owned(),
        session_id_length: XhttpRange::exact(6),
        ..XhttpConfigInput::default()
    })
    .unwrap();
    let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.com").unwrap();
    let transport =
        XhttpTransport::new(config, endpoint, XhttpHttpVersion::Http1, unlimited_xmux())
            .unwrap()
            .with_rng(Box::new(StepRng::new(0, 1)))
            .unwrap();
    let dial = queued_dial([
        first_down_client,
        first_up_client,
        second_down_client,
        second_up_client,
    ]);

    for payload in [b"first".as_slice(), b"second".as_slice()] {
        let mut stream = transport
            .open_stream_with_dial(Arc::clone(&dial))
            .await
            .unwrap();
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
    }

    let (first_down, first_up, first_body) = first_server.await.unwrap().unwrap();
    let (second_down, second_up, second_body) = second_server.await.unwrap().unwrap();
    let first_id = h1_header_value(&first_down, "X-Custom-Session").unwrap();
    let second_id = h1_header_value(&second_down, "X-Custom-Session").unwrap();

    assert_eq!(
        h1_header_value(&first_up, "X-Custom-Session"),
        Some(first_id)
    );
    assert_eq!(
        h1_header_value(&second_up, "X-Custom-Session"),
        Some(second_id)
    );
    assert_eq!(first_id.len(), 6);
    assert_eq!(second_id.len(), 6);
    assert!(first_id.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(second_id.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert_ne!(first_id, second_id);
    assert_eq!(first_body, b"first");
    assert_eq!(second_body, b"second");
}

#[tokio::test]
async fn h1_packet_up_batches_and_reuses_only_a_fully_drained_upload_socket() {
    let (down_client, mut down_server) = tokio::io::duplex(64 * 1024);
    let (up_client, mut up_server) = tokio::io::duplex(64 * 1024);
    let down = tokio::spawn(async move {
        let head = read_h1_head(&mut down_server).await?;
        down_server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok::<_, io::Error>(head)
    });
    let up = tokio::spawn(async move {
        let mut exchanges = Vec::new();
        for _ in 0..2 {
            let head = read_h1_head(&mut up_server).await?;
            let length = h1_content_length(&head)?;
            let mut body = vec![0; length];
            up_server.read_exact(&mut body).await?;
            up_server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 8\r\n\r\nnot-gzip",
                )
                .await?;
            exchanges.push((head, body));
        }
        Ok::<_, io::Error>(exchanges)
    });

    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport
        .open_stream_with_dial(queued_dial([down_client, up_client]))
        .await
        .unwrap();
    stream.write_all(b"abcdefgh").await.unwrap();
    stream.shutdown().await.unwrap();

    let exchanges = timeout(DEADLINE, up).await.unwrap().unwrap().unwrap();
    assert_eq!(exchanges[0].1, b"abcd");
    assert_eq!(exchanges[1].1, b"efgh");
    assert!(h1_path(&exchanges[0].0).ends_with("/0"));
    assert!(h1_path(&exchanges[1].0).ends_with("/1"));
    assert!(!contains(&exchanges[0].0, b"Connection: close\r\n"));
    assert!(!contains(&exchanges[1].0, b"Connection: close\r\n"));
    assert!(!contains(&exchanges[0].0, b"Accept-Encoding:"));
    assert!(!contains(&exchanges[1].0, b"Accept-Encoding:"));
    let down_head = down.await.unwrap().unwrap();
    assert!(down_head.starts_with(b"GET "));
    assert!(contains(&down_head, b"Connection: close\r\n"));
    assert!(contains(&down_head, b"Accept-Encoding: gzip\r\n"));
}

#[tokio::test]
async fn h1_packet_up_idle_flush_and_shutdown_do_not_dial_an_uploader() {
    let (down_client, mut down_server) = tokio::io::duplex(64 * 1024);
    let down = tokio::spawn(async move {
        let head = read_h1_head(&mut down_server).await?;
        down_server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok::<_, io::Error>(head)
    });

    let dials = Arc::new(AtomicUsize::new(0));
    let mut stream = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        500_000,
    )
    .open_stream_with_dial(counted_queued_dial([down_client], Arc::clone(&dials)))
    .await
    .unwrap();

    stream.flush().await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(dials.load(Ordering::Acquire), 1);

    timeout(DEADLINE, stream.shutdown())
        .await
        .expect("idle packet uploader shutdown hung")
        .unwrap();
    let mut response = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut response))
        .await
        .expect("idle packet-up downlink did not finish")
        .unwrap();
    assert!(response.is_empty());
    assert_eq!(dials.load(Ordering::Acquire), 1);

    let down_head = down.await.unwrap().unwrap();
    assert!(down_head.starts_with(b"GET "));
}

#[tokio::test]
async fn h1_packet_up_exact_500k_limit_splits_without_corrupting_payload() {
    const MAX_PACKET: usize = 500_000;

    let (down_client, mut down_server) = tokio::io::duplex(64 * 1024);
    let (up_client, mut up_server) = tokio::io::duplex(64 * 1024);
    let down = tokio::spawn(async move {
        let _ = read_h1_head(&mut down_server).await?;
        down_server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
    });
    let up = tokio::spawn(async move {
        let mut packets = Vec::new();
        for _ in 0..2 {
            let head = read_h1_head(&mut up_server).await?;
            let mut body = vec![0; h1_content_length(&head)?];
            up_server.read_exact(&mut body).await?;
            up_server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await?;
            packets.push((h1_path(&head).to_owned(), body));
        }
        Ok::<_, io::Error>(packets)
    });

    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        MAX_PACKET as i32,
    );
    let mut stream = transport
        .open_stream_with_dial(queued_dial([down_client, up_client]))
        .await
        .unwrap();
    let payload = vec![0x5a; MAX_PACKET + 1];
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();

    let packets = timeout(DEADLINE, up).await.unwrap().unwrap().unwrap();
    assert_eq!(packets[0].0.split('/').next_back(), Some("0"));
    assert_eq!(packets[1].0.split('/').next_back(), Some("1"));
    assert_eq!(packets[0].1, payload[..MAX_PACKET]);
    assert_eq!(packets[1].1, payload[MAX_PACKET..]);
    down.await.unwrap().unwrap();
}

#[tokio::test]
async fn h1_pooled_packet_partial_write_is_not_replayed_on_a_fresh_connection() {
    let (down_client, mut down_server) = tokio::io::duplex(64 * 1024);
    let down = tokio::spawn(async move {
        let _ = read_h1_head(&mut down_server).await?;
        down_server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
    });

    let (pooled_inner, mut pooled_server) = tokio::io::duplex(64 * 1024);
    let (pooled_client, partial_write) = ArmablePartialWriteStream::new(pooled_inner, 8);
    let pooled = tokio::spawn(async move {
        let first_head = read_h1_head(&mut pooled_server).await?;
        let mut first_body = vec![0; h1_content_length(&first_head)?];
        pooled_server.read_exact(&mut first_body).await?;
        partial_write.arm();
        pooled_server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;

        let mut second_prefix = Vec::new();
        pooled_server.read_to_end(&mut second_prefix).await?;
        Ok::<_, io::Error>((first_body, second_prefix))
    });

    // This connection is a replay detector. A partial pooled write must fail
    // the packet instead of consuming this third dial and sending the same
    // `(session, seq)` request again.
    let (replay_client, _replay_server) = tokio::io::duplex(64 * 1024);
    let dials = Arc::new(AtomicUsize::new(0));
    let queue = Arc::new(Mutex::new(VecDeque::from([
        Box::new(down_client) as BoxedTransportStream,
        Box::new(pooled_client) as BoxedTransportStream,
        Box::new(replay_client) as BoxedTransportStream,
    ])));
    let dial: XhttpDial = {
        let queue = Arc::clone(&queue);
        let dials = Arc::clone(&dials);
        Arc::new(move || {
            dials.fetch_add(1, Ordering::AcqRel);
            let stream = queue.lock().unwrap().pop_front();
            Box::pin(async move {
                stream.ok_or_else(|| {
                    TransportError::Tcp(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "test dial queue is empty",
                    ))
                })
            })
        })
    };

    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        5,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    // A five-byte packet establishes and pools the upload connection. The
    // second packet then gets exactly eight request-head bytes onto that same
    // socket before its scripted write failure.
    stream.write_all(b"firstagain").await.unwrap();

    let (first_body, second_prefix) = timeout(DEADLINE, pooled)
        .await
        .expect("partial pooled request did not terminate")
        .unwrap()
        .unwrap();
    assert_eq!(first_body, b"first");
    assert_eq!(second_prefix.len(), 8);
    assert!(b"POST /api/".starts_with(second_prefix.as_slice()));
    assert_eq!(
        dials.load(Ordering::Acquire),
        2,
        "a partially written POST must not be replayed on the spare connection"
    );

    let error = stream
        .write_all(b"after-partial-write")
        .await
        .expect_err("the packet-worker failure must reach the logical stream");
    assert!(error
        .to_string()
        .contains("request write failed after 8 bytes"));
    down.await.unwrap().unwrap();
}

#[tokio::test]
async fn h2_packet_up_retries_once_when_goaway_refuses_uncommitted_pooled_request() {
    let stale_post_count = Arc::new(AtomicUsize::new(0));
    let (stale_client, stale_server_io) = tokio::io::duplex(1024 * 1024);
    let (stale_client, _settings_ack, goaway_ping_ack) = FrameObservedStream::new(stale_client);
    let (downlink_ready, downlink_ready_rx) = oneshot::channel();
    let (start_goaway, start_goaway_rx) = oneshot::channel();
    let stale_server = tokio::spawn({
        let stale_post_count = Arc::clone(&stale_post_count);
        async move {
            let mut connection = server::handshake::<_>(stale_server_io)
                .await
                .expect("stale server HTTP/2 handshake");
            let (download, mut respond) = connection
                .accept()
                .await
                .expect("stale connection closed before GET")
                .expect("stale connection failed before GET");
            assert_eq!(download.method(), http::Method::GET);
            let _held_downlink = respond
                .send_response(ok_response(), false)
                .expect("send persistent stale downlink headers");
            let _ = downlink_ready.send(());

            start_goaway_rx
                .await
                .expect("GOAWAY controller was dropped");
            connection.graceful_shutdown();

            // `accept` polls the connection driver through `poll_closed`, so
            // the graceful-shutdown PING can be acknowledged while any
            // request which slipped past GOAWAY is still recorded.
            while let Some(exchange) = connection.accept().await {
                let (request, mut respond) =
                    exchange.expect("stale connection failed after GOAWAY");
                stale_post_count.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async move {
                    drain_h2_request(request.into_body()).await;
                    let _ = respond.send_response(ok_response(), true);
                });
            }
        }
    });

    let (fresh_client, fresh_server_io) = tokio::io::duplex(1024 * 1024);
    let (fresh_record, mut fresh_record_rx) = mpsc::unbounded_channel();
    let fresh_server = tokio::spawn(async move {
        let Ok(mut connection) = server::handshake::<_>(fresh_server_io).await else {
            return;
        };
        let mut accepted = VecDeque::new();
        loop {
            let (request, mut respond) = match accepted.pop_front() {
                Some(exchange) => exchange,
                None => connection
                    .accept()
                    .await
                    .expect("fresh connection closed while awaiting packet")
                    .expect("fresh connection failed while awaiting packet"),
            };
            assert_eq!(request.method(), http::Method::POST);
            let path = request.uri().path().to_owned();
            let drain = drain_h2_request(request.into_body());
            tokio::pin!(drain);
            let body = loop {
                tokio::select! {
                    body = &mut drain => break body,
                    exchange = connection.accept() => {
                        let exchange = exchange
                            .expect("fresh connection closed while draining packet")
                            .expect("fresh connection failed while draining packet");
                        accepted.push_back(exchange);
                    }
                }
            };
            respond
                .send_response(ok_response(), true)
                .expect("send fresh packet response");
            fresh_record
                .send((path, body))
                .expect("fresh packet record receiver");
        }
    });

    let (dial, dials) = scripted_h2_dial([
        (Box::new(stale_client) as BoxedTransportStream, stale_server),
        (Box::new(fresh_client) as BoxedTransportStream, fresh_server),
    ]);
    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        5,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    timeout(DEADLINE, downlink_ready_rx)
        .await
        .expect("stale server did not accept the persistent GET")
        .expect("stale GET readiness sender");
    start_goaway
        .send(())
        .expect("stale GOAWAY controller receiver");
    timeout(DEADLINE, goaway_ping_ack)
        .await
        .expect("client did not acknowledge graceful-shutdown PING")
        .expect("GOAWAY PING observation sender");

    stream
        .write_all(b"firstsecon")
        .await
        .unwrap_or_else(|error| {
            panic!(
                "pre-commit GOAWAY was not retried on a fresh H2 connection: {error}; dials={}, stale_posts={}",
                dials.load(Ordering::Acquire),
                stale_post_count.load(Ordering::Acquire)
            )
        });
    let first_two = timeout(DEADLINE, async {
        let first = fresh_record_rx
            .recv()
            .await
            .expect("fresh server stopped before sequence 0");
        let second = fresh_record_rx
            .recv()
            .await
            .expect("fresh server stopped before sequence 1");
        [first, second]
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "fresh server did not receive both refused packets; dials={}, stale_posts={}",
            dials.load(Ordering::Acquire),
            stale_post_count.load(Ordering::Acquire)
        )
    });
    let fresh_packets = Arc::new(Mutex::new(Vec::new()));
    for (expected_sequence, (path, body)) in ["0", "1"].into_iter().zip(first_two) {
        assert_eq!(path.split('/').next_back(), Some(expected_sequence));
        fresh_packets.lock().unwrap().push(body);
    }
    assert_eq!(dials.load(Ordering::Acquire), 2);
    assert_eq!(stale_post_count.load(Ordering::Acquire), 0);
    assert_eq!(
        fresh_packets.lock().unwrap().as_slice(),
        [b"first", b"secon"]
    );

    stream.write_all(b"d").await.unwrap();
    stream.shutdown().await.unwrap();
    let (third_path, third_body) = timeout(DEADLINE, fresh_record_rx.recv())
        .await
        .expect("fresh server did not receive sequence 2")
        .expect("fresh server stopped before sequence 2");
    assert_eq!(third_path.split('/').next_back(), Some("2"));
    assert_eq!(third_body, b"d");
    assert_eq!(dials.load(Ordering::Acquire), 2);
    assert_eq!(stale_post_count.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn h2_packet_up_does_not_replay_when_goaway_follows_request_data() {
    const MAX_PACKET: usize = 16;
    const PAYLOAD: &[u8] = b"0123456789abcdef0123456789abcdefx";

    let (first_client, first_server_io) = tokio::io::duplex(1024 * 1024);
    let (first_client, settings_ack, _ping_ack) = FrameObservedStream::new(first_client);
    let (downlink_ready, downlink_ready_rx) = oneshot::channel();
    let (body_seen, body_seen_rx) = oneshot::channel();
    let (goaway_flushed, goaway_flushed_rx) = oneshot::channel();
    let first_server = tokio::spawn(async move {
        let mut builder = server::Builder::new();
        builder.initial_window_size(8);
        let mut connection = builder
            .handshake::<_, Bytes>(first_server_io)
            .await
            .expect("post-commit server HTTP/2 handshake");
        let (download, mut download_response) = connection
            .accept()
            .await
            .expect("post-commit connection closed before GET")
            .expect("post-commit connection failed before GET");
        assert_eq!(download.method(), http::Method::GET);
        let _held_downlink = download_response
            .send_response(ok_response(), false)
            .expect("send persistent post-commit downlink headers");
        let _ = downlink_ready.send(());

        let (upload, _upload_response) = connection
            .accept()
            .await
            .expect("post-commit connection closed before POST")
            .expect("post-commit connection failed before POST");
        assert_eq!(upload.method(), http::Method::POST);
        let path = upload.uri().path().to_owned();
        let mut body = upload.into_body();
        let bytes = tokio::select! {
            data = body.data() => data
                .expect("POST ended before its first DATA frame")
                .expect("POST first DATA frame failed"),
            exchange = connection.accept() => {
                match exchange {
                    Some(Ok((request, _))) => {
                        panic!("unexpected request before post-commit GOAWAY: {}", request.uri());
                    }
                    Some(Err(error)) => {
                        panic!("post-commit connection failed before DATA: {error}");
                    }
                    None => panic!("post-commit connection closed before DATA"),
                }
            }
        };
        body_seen
            .send((path, bytes.to_vec()))
            .expect("post-commit body record receiver");

        connection.abrupt_shutdown(Reason::NO_ERROR);
        std::future::poll_fn(|cx| connection.poll_closed(cx))
            .await
            .expect("flush post-commit GOAWAY");
        let _ = goaway_flushed.send(());
    });

    let replay_seen = Arc::new(AtomicBool::new(false));
    let (replay_client, replay_server_io) = tokio::io::duplex(1024 * 1024);
    let replay_server = tokio::spawn({
        let replay_seen = Arc::clone(&replay_seen);
        async move {
            let Ok(mut connection) = server::handshake::<_>(replay_server_io).await else {
                return;
            };
            if let Some(Ok((_request, _respond))) = connection.accept().await {
                replay_seen.store(true, Ordering::Release);
                connection.abrupt_shutdown(Reason::NO_ERROR);
                let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
            }
        }
    });

    let (dial, dials) = scripted_h2_dial([
        (Box::new(first_client) as BoxedTransportStream, first_server),
        (
            Box::new(replay_client) as BoxedTransportStream,
            replay_server,
        ),
    ]);
    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        MAX_PACKET as i32,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    timeout(DEADLINE, async {
        downlink_ready_rx
            .await
            .expect("post-commit GET readiness sender");
        settings_ack.await.expect("SETTINGS ACK observation sender");
    })
    .await
    .expect("post-commit server was not ready for the bounded upload");

    // More than two pipe capacities keeps this public write pending until the
    // first packet either commits or fails. Its terminal error therefore also
    // proves the packet worker has settled before replay is ruled out.
    let writer = tokio::spawn(async move {
        stream
            .write_all(PAYLOAD)
            .await
            .expect_err("post-commit packet worker must fail the public write")
    });
    let (path, first_data) = timeout(DEADLINE, body_seen_rx)
        .await
        .expect("post-commit server did not observe POST DATA")
        .expect("post-commit body record sender");
    assert_eq!(path.split('/').next_back(), Some("0"));
    assert!(!first_data.is_empty());
    assert!(first_data.len() <= 8);
    assert!(PAYLOAD.starts_with(&first_data));
    timeout(DEADLINE, goaway_flushed_rx)
        .await
        .expect("post-commit GOAWAY did not flush")
        .expect("post-commit GOAWAY flush sender");

    let error = timeout(DEADLINE, writer)
        .await
        .expect("post-commit terminal error did not reach the public stream")
        .expect("post-commit public writer task");
    assert!(matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    ));
    assert_eq!(dials.load(Ordering::Acquire), 1);
    assert!(!replay_seen.load(Ordering::Acquire));
}

#[tokio::test]
async fn dropping_h2_packet_up_while_upload_is_flow_controlled_cancels_once_and_releases_pool() {
    const MAX_PACKET: usize = 16;
    const BLOCKED_UPLOAD: [u8; 64] = [0x5a; 64];
    const REPLACEMENT_UPLOAD: &[u8] = b"replacement";
    const REPLACEMENT_DOWNLINK: &[u8] = b"reused";

    #[derive(Debug)]
    enum PublicHalfTerminal {
        Io(io::Result<()>),
        Cancelled,
    }

    fn expect_cancelled(direction: &str, result: PublicHalfTerminal) {
        match result {
            PublicHalfTerminal::Cancelled => {}
            PublicHalfTerminal::Io(result) => {
                panic!("{direction} completed I/O before cancellation: {result:?}")
            }
        }
    }

    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (client_io, settings_ack, _ping_ack, mut outbound_resets) =
        FrameObservedStream::new_with_reset_observation(client_io);
    let (post_blocked, post_blocked_rx) = oneshot::channel();
    let (replacement_post, replacement_post_rx) = oneshot::channel();
    let (reset_tx, mut reset_rx) = mpsc::unbounded_channel::<(Method, Reason)>();
    let server_task = tokio::spawn(async move {
        let mut builder = server::Builder::new();
        builder.initial_window_size(8);
        let mut connection = builder
            .handshake::<_, Bytes>(server_io)
            .await
            .expect("flow-controlled server HTTP/2 handshake");
        let mut reset_observers = Vec::new();
        let mut post_blocked = Some(post_blocked);
        let mut replacement_post = Some(replacement_post);
        let mut accepted = 0_usize;

        while let Some(exchange) = connection.accept().await {
            let (request, mut respond) =
                exchange.expect("flow-controlled server connection failed");
            match accepted {
                0 => {
                    assert_eq!(request.method(), Method::GET);
                    let mut response = respond
                        .send_response(ok_response(), false)
                        .expect("send persistent original downlink headers");
                    let reset_tx = reset_tx.clone();
                    reset_observers.push(tokio::spawn(async move {
                        let reason = std::future::poll_fn(|cx| response.poll_reset(cx))
                            .await
                            .expect("observe original GET reset");
                        reset_tx
                            .send((Method::GET, reason))
                            .expect("original GET reset receiver");
                    }));
                }
                1 => {
                    assert_eq!(request.method(), Method::POST);
                    let post_blocked = post_blocked
                        .take()
                        .expect("original POST is accepted only once");
                    let reset_tx = reset_tx.clone();
                    reset_observers.push(tokio::spawn(async move {
                        let mut body = request.into_body();
                        let first_data = body
                            .data()
                            .await
                            .expect("original POST ended before DATA")
                            .expect("read original POST DATA");
                        assert_eq!(first_data.as_ref(), &[0x5a; 8]);
                        post_blocked
                            .send(())
                            .expect("original POST blocked receiver");

                        // Retain both the DATA and its RecvStream without
                        // releasing capacity. The client's remaining eight
                        // bytes therefore stay flow-controlled until drop.
                        let reason = std::future::poll_fn(|cx| respond.poll_reset(cx))
                            .await
                            .expect("observe original POST reset");
                        reset_tx
                            .send((Method::POST, reason))
                            .expect("original POST reset receiver");
                        drop((first_data, body));
                    }));
                }
                2 => {
                    assert_eq!(request.method(), Method::GET);
                    let mut response = respond
                        .send_response(ok_response(), false)
                        .expect("send replacement downlink headers");
                    response
                        .send_data(Bytes::from_static(REPLACEMENT_DOWNLINK), true)
                        .expect("send replacement downlink body");
                }
                3 => {
                    assert_eq!(request.method(), Method::POST);
                    let replacement_post = replacement_post
                        .take()
                        .expect("replacement POST is accepted only once");
                    reset_observers.push(tokio::spawn(async move {
                        let body = drain_h2_request(request.into_body()).await;
                        respond
                            .send_response(ok_response(), true)
                            .expect("send replacement POST response");
                        replacement_post
                            .send(body)
                            .expect("replacement POST body receiver");
                    }));
                }
                _ => panic!("unexpected fifth request on reused H2 connection"),
            }
            accepted += 1;
        }

        assert_eq!(accepted, 4);
        for observer in reset_observers {
            observer.await.expect("server stream observer task");
        }
    });

    let client_io = Arc::new(Mutex::new(
        Some(Box::new(client_io) as BoxedTransportStream),
    ));
    let dials = Arc::new(AtomicUsize::new(0));
    let dial: XhttpDial = {
        let client_io = Arc::clone(&client_io);
        let dials = Arc::clone(&dials);
        Arc::new(move || {
            dials.fetch_add(1, Ordering::AcqRel);
            let stream = client_io.lock().unwrap().take();
            Box::pin(async move {
                stream.ok_or_else(|| {
                    TransportError::Tcp(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "flow-controlled test dial is exhausted",
                    ))
                })
            })
        })
    };
    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        MAX_PACKET as i32,
    );
    let stream = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .expect("open original packet-up flow");

    timeout(DEADLINE, settings_ack)
        .await
        .expect("client did not acknowledge the eight-byte receive window")
        .expect("SETTINGS ACK observation sender");

    let (mut public_reader, mut public_writer) = tokio::io::split(stream);
    let (read_cancel, mut read_cancel_rx) = oneshot::channel();
    let reader_task = tokio::spawn(async move {
        let mut byte = [0_u8; 1];
        let terminal = tokio::select! {
            biased;
            cancel = &mut read_cancel_rx => {
                cancel.expect("read cancellation sender");
                PublicHalfTerminal::Cancelled
            }
            result = public_reader.read(&mut byte) => {
                PublicHalfTerminal::Io(result.map(|_| ()))
            }
        };
        drop(public_reader);
        terminal
    });

    let (write_cancel, mut write_cancel_rx) = oneshot::channel();
    let (writer_started, writer_started_rx) = oneshot::channel();
    let (writer_done, mut writer_done_rx) = oneshot::channel();
    let writer_task = tokio::spawn(async move {
        writer_started.send(()).expect("writer-started receiver");
        let terminal = tokio::select! {
            biased;
            cancel = &mut write_cancel_rx => {
                cancel.expect("write cancellation sender");
                PublicHalfTerminal::Cancelled
            }
            result = public_writer.write_all(&BLOCKED_UPLOAD) => {
                PublicHalfTerminal::Io(result)
            }
        };
        drop(public_writer);
        let _ = writer_done.send(());
        terminal
    });

    timeout(DEADLINE, async {
        writer_started_rx
            .await
            .expect("writer-started observation sender");
        post_blocked_rx
            .await
            .expect("original POST blocked observation sender");
    })
    .await
    .expect("public writer did not reach deterministic H2 flow control");
    assert!(matches!(
        writer_done_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    read_cancel.send(()).expect("read cancellation receiver");
    write_cancel.send(()).expect("write cancellation receiver");
    let (reader_result, writer_result) =
        timeout(DEADLINE, async { tokio::join!(reader_task, writer_task) })
            .await
            .expect("public split halves did not stop after cancellation");
    expect_cancelled(
        "read half",
        reader_result.expect("public reader task panicked"),
    );
    expect_cancelled(
        "write half",
        writer_result.expect("public writer task panicked"),
    );
    writer_done_rx
        .await
        .expect("writer completion observation sender");

    let resets = timeout(DEADLINE, async {
        [
            reset_rx.recv().await.expect("first reset event"),
            reset_rx.recv().await.expect("second reset event"),
        ]
    })
    .await
    .expect("server did not observe both original stream resets");
    assert_eq!(
        resets
            .iter()
            .filter(|event| **event == (Method::GET, Reason::CANCEL))
            .count(),
        1
    );
    assert_eq!(
        resets
            .iter()
            .filter(|event| **event == (Method::POST, Reason::CANCEL))
            .count(),
        1
    );
    assert!(matches!(
        reset_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    timeout(DEADLINE, async {
        loop {
            if transport.h2_connection_activity_counts().await == vec![0] {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled packet-up flow did not release H2 reservations");

    let wire_resets = timeout(DEADLINE, async {
        [
            outbound_resets.recv().await.expect("first outbound reset"),
            outbound_resets.recv().await.expect("second outbound reset"),
        ]
    })
    .await
    .expect("client did not emit both original stream resets");
    assert!(wire_resets
        .iter()
        .all(|reset| reset.reason == Reason::CANCEL));
    assert_ne!(wire_resets[0].stream_id, wire_resets[1].stream_id);
    assert!(matches!(
        outbound_resets.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let mut replacement = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .expect("reuse healthy H2 connection for replacement flow");
    replacement
        .write_all(REPLACEMENT_UPLOAD)
        .await
        .expect("write replacement packet");
    replacement
        .shutdown()
        .await
        .expect("finish replacement uplink");
    let mut downlink = Vec::new();
    replacement
        .read_to_end(&mut downlink)
        .await
        .expect("read replacement downlink to EOF");
    assert_eq!(downlink, REPLACEMENT_DOWNLINK);
    let replacement_body = timeout(DEADLINE, replacement_post_rx)
        .await
        .expect("replacement POST did not complete")
        .expect("replacement POST body sender");
    assert_eq!(replacement_body, REPLACEMENT_UPLOAD);
    drop(replacement);

    timeout(DEADLINE, async {
        loop {
            if transport.h2_connection_activity_counts().await == vec![0] {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement packet-up flow did not release H2 reservations");
    assert!(matches!(
        outbound_resets.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        dials.load(Ordering::Acquire),
        1,
        "local cancellation must preserve the healthy H2 connection"
    );

    drop(transport);
    drop(dial);
    timeout(DEADLINE, server_task)
        .await
        .expect("flow-controlled server did not stop")
        .expect("flow-controlled server task panicked");
}

#[tokio::test]
async fn h2_stream_up_is_full_duplex_and_pools_both_requests_on_one_connection() {
    let dials = Arc::new(AtomicUsize::new(0));
    let uploads = Arc::new(Mutex::new(Vec::new()));
    let dial = h2_dial(Arc::clone(&dials), {
        let uploads = Arc::clone(&uploads);
        move |request, mut respond| {
            let uploads = Arc::clone(&uploads);
            async move {
                assert_eq!(request.headers()[header::ACCEPT_ENCODING], "gzip");
                if request.method() == http::Method::GET {
                    let mut send = respond
                        .send_response(ok_response(), false)
                        .expect("send downlink headers");
                    send.send_data(Bytes::from_static(b"pong"), true)
                        .expect("send downlink body");
                    drain_h2_request(request.into_body()).await;
                } else {
                    let body = drain_h2_request(request.into_body()).await;
                    uploads.lock().unwrap().push(body);
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_ENCODING, "gzip")
                        .body(())
                        .unwrap();
                    let mut send = respond
                        .send_response(response, false)
                        .expect("send upload response");
                    send.send_data(Bytes::from_static(GZIP_PONG), true)
                        .expect("send compressed upload response body");
                }
            }
        }
    });
    let transport = transport(
        XhttpModeSelection::StreamUp,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"pong");
    wait_until(|| !uploads.lock().unwrap().is_empty()).await;
    assert_eq!(*uploads.lock().unwrap(), vec![b"ping".to_vec()]);
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn h2_stream_up_read_flush_does_not_strand_flow_controlled_writer() {
    const READY: u8 = 0x41;
    const COMPLETE: u8 = 0x42;
    const UPLOAD_BYTES: usize = 2 * 1024 * 1024;

    let dials = Arc::new(AtomicUsize::new(0));
    let upload_done = Arc::new(AtomicBool::new(false));
    let upload_notify = Arc::new(tokio::sync::Notify::new());
    let dial = h2_dial(Arc::clone(&dials), {
        let upload_done = Arc::clone(&upload_done);
        let upload_notify = Arc::clone(&upload_notify);
        move |request, mut respond| {
            let upload_done = Arc::clone(&upload_done);
            let upload_notify = Arc::clone(&upload_notify);
            async move {
                if request.method() == http::Method::GET {
                    let mut send = respond
                        .send_response(ok_response(), false)
                        .expect("send downlink headers");
                    send.send_data(Bytes::from_static(&[READY]), false)
                        .expect("send ready marker");
                    while !upload_done.load(Ordering::Acquire) {
                        let notified = upload_notify.notified();
                        if upload_done.load(Ordering::Acquire) {
                            break;
                        }
                        notified.await;
                    }
                    send.send_data(Bytes::from_static(&[COMPLETE]), true)
                        .expect("send completion marker");
                    drain_h2_request(request.into_body()).await;
                } else {
                    let body = drain_h2_request(request.into_body()).await;
                    assert_eq!(body, vec![0x5a; UPLOAD_BYTES]);
                    upload_done.store(true, Ordering::Release);
                    upload_notify.notify_waiters();
                    respond
                        .send_response(ok_response(), true)
                        .expect("send upload response");
                }
            }
        }
    });
    let transport = transport(
        XhttpModeSelection::StreamUp,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    let mut ready = [0; 1];
    stream
        .read_exact(&mut ready)
        .await
        .expect("read ready marker");
    assert_eq!(ready, [READY]);

    let (mut reader, mut writer) = tokio::io::split(stream);
    timeout(DEADLINE, async {
        tokio::try_join!(
            async {
                writer.write_all(&vec![0x5a; UPLOAD_BYTES]).await?;
                writer.shutdown().await
            },
            async {
                let mut complete = [0; 1];
                reader.read_exact(&mut complete).await?;
                assert_eq!(complete, [COMPLETE]);
                Ok::<(), io::Error>(())
            }
        )
    })
    .await
    .expect("concurrent H2 stream-up transfer must make flow-control progress")
    .expect("concurrent H2 stream-up transfer");
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn h2_auto_gzip_decodes_mixed_case_content_encoding() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h2_dial(Arc::clone(&dials), |request, mut respond| async move {
        assert_eq!(request.headers()[header::ACCEPT_ENCODING], "gzip");
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_ENCODING, "GZiP")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from_static(GZIP_PONG), true).unwrap();
        drain_h2_request(request.into_body()).await;
    });
    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    assert_eq!(response, b"pong");
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn explicit_accept_encoding_keeps_h2_gzip_response_compressed() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = h2_dial(Arc::clone(&dials), |request, mut respond| async move {
        assert_eq!(request.headers()[header::ACCEPT_ENCODING], "gzip");
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_ENCODING, "gzip")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from_static(GZIP_PONG), true).unwrap();
        drain_h2_request(request.into_body()).await;
    });
    let mut headers = HeaderMap::new();
    headers.set("Accept-Encoding", "gzip");
    let transport = transport_with_headers(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
        headers,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    assert_eq!(response, GZIP_PONG);
}

#[tokio::test]
async fn malformed_h2_auto_gzip_does_not_retire_the_pooled_connection() {
    let dials = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let dial = h2_dial(Arc::clone(&dials), {
        let requests = Arc::clone(&requests);
        move |request, mut respond| {
            let request_index = requests.fetch_add(1, Ordering::AcqRel);
            async move {
                assert_eq!(request.headers()[header::ACCEPT_ENCODING], "gzip");
                if request_index == 0 {
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_ENCODING, "gzip")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(Bytes::from_static(b"not-gzip"), true)
                        .unwrap();
                } else {
                    let mut send = respond.send_response(ok_response(), false).unwrap();
                    send.send_data(Bytes::from_static(b"healthy"), true)
                        .unwrap();
                }
                drain_h2_request(request.into_body()).await;
            }
        }
    });
    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
    );

    let mut malformed = transport
        .open_stream_with_dial(Arc::clone(&dial))
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

    let mut healthy = transport.open_stream_with_dial(dial).await.unwrap();
    healthy.shutdown().await.unwrap();
    let mut response = Vec::new();
    healthy.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"healthy");
    assert_eq!(dials.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn h2_pool_fans_out_when_peer_stream_limit_is_exhausted_then_reuses_connections() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial: XhttpDial = {
        let dials = Arc::clone(&dials);
        Arc::new(move || {
            dials.fetch_add(1, Ordering::AcqRel);
            let (client, server_io) = tokio::io::duplex(1024 * 1024);
            tokio::spawn(async move {
                let mut builder = server::Builder::new();
                builder.max_concurrent_streams(1);
                let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
                while let Some(exchange) = connection.accept().await {
                    let Ok((request, mut respond)) = exchange else {
                        break;
                    };
                    tokio::spawn(async move {
                        if request.method() == http::Method::GET {
                            let _held_response = respond
                                .send_response(ok_response(), false)
                                .expect("send persistent downlink headers");
                            drain_h2_request(request.into_body()).await;
                            std::future::pending::<()>().await;
                        } else {
                            drain_h2_request(request.into_body()).await;
                            respond
                                .send_response(ok_response(), true)
                                .expect("send upload response");
                        }
                    });
                }
            });
            Box::pin(async move { Ok(Box::new(client) as BoxedTransportStream) })
        })
    };
    let transport = transport(
        XhttpModeSelection::StreamUp,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
    );

    let mut first = timeout(DEADLINE, transport.open_stream_with_dial(Arc::clone(&dial)))
        .await
        .expect("saturated H2 pool deadlocked")
        .unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 2);
    first.write_all(b"first").await.unwrap();
    first.shutdown().await.unwrap();
    drop(first);
    timeout(DEADLINE, async {
        loop {
            let activity = transport.h2_connection_activity_counts().await;
            if activity.len() == 2 && activity.iter().all(|count| *count == 0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped flow did not release both H2 request reservations");

    let second = timeout(DEADLINE, transport.open_stream_with_dial(dial))
        .await
        .expect("released H2 connections were not reusable")
        .unwrap();
    assert_eq!(
        dials.load(Ordering::Acquire),
        2,
        "released capacity must be reused without a third dial"
    );
    drop(second);
}

#[tokio::test]
async fn delayed_get_response_does_not_block_open_stream() {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let (head_seen, head_wait) = tokio::sync::oneshot::channel();
    let (release, release_wait) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let head = read_h1_head(&mut server).await?;
        let _ = head_seen.send(head);
        let _ = release_wait.await;
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
    });
    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        4,
    );
    let opening =
        tokio::spawn(async move { transport.open_stream_with_dial(queued_dial([client])).await });
    let head = timeout(DEADLINE, head_wait).await.unwrap().unwrap();
    assert!(head.starts_with(b"GET "));
    let stream = timeout(DEADLINE, opening)
        .await
        .expect("open_stream waited for delayed response")
        .unwrap()
        .unwrap();
    let _ = release.send(());
    server_task.await.unwrap().unwrap();
    drop(stream);
}

#[tokio::test]
async fn default_xmux_fans_out_three_clients_then_reuses_a_released_slot() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = success_h2_dial(Arc::clone(&dials));
    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        XhttpXmuxPolicy::default(),
        4,
    );

    let first = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    let second = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 2);
    assert_eq!(transport.xmux_open_usages().await, vec![1, 1]);

    drop(first);
    let third = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 3);
    assert_eq!(transport.xmux_client_count().await, 3);

    let fourth = transport.open_stream_with_dial(dial).await.unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 3);
    assert_eq!(transport.xmux_open_usages().await, vec![1, 1, 1]);
    drop((second, third, fourth));
    assert_eq!(transport.xmux_open_usages().await, vec![0, 0, 0]);
}

#[tokio::test]
async fn max_connections_fans_out_before_reusing_an_eligible_client() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = success_h2_dial(Arc::clone(&dials));
    let mut policy = unlimited_xmux();
    policy.max_connections = XhttpRange::exact(2);
    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        policy,
        4,
    );
    for _ in 0..3 {
        let stream = transport
            .open_stream_with_dial(Arc::clone(&dial))
            .await
            .unwrap();
        drop(stream);
    }
    assert_eq!(transport.xmux_client_count().await, 2);
    assert_eq!(dials.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn c_max_reuse_times_retires_a_client_after_exactly_two_selections() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = success_h2_dial(Arc::clone(&dials));
    let mut policy = unlimited_xmux();
    policy.c_max_reuse_times = XhttpRange::exact(2);
    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        policy,
        4,
    );
    for expected in [1, 1, 2] {
        let stream = transport
            .open_stream_with_dial(Arc::clone(&dial))
            .await
            .unwrap();
        drop(stream);
        assert_eq!(dials.load(Ordering::Acquire), expected);
    }
}

#[tokio::test]
async fn h_max_request_times_rotates_packet_uploader_after_downlink_budget() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = success_h2_dial(Arc::clone(&dials));
    let mut policy = unlimited_xmux();
    policy.h_max_request_times = XhttpRange::exact(2);
    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http2,
        policy,
        4,
    );
    let mut stream = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 1);
    stream.write_all(b"x").await.unwrap();
    wait_until(|| dials.load(Ordering::Acquire) == 2).await;
    assert_eq!(
        transport.xmux_open_usages().await,
        vec![1],
        "the retired downlink client is removed from the manager, while the rotated packet uploader must retain its own xmux reservation"
    );
    stream.shutdown().await.unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn reusable_deadline_and_h2_idle_timeout_use_the_injected_clock() {
    let base = Instant::now();
    let seconds = Arc::new(AtomicU64::new(0));
    let clock: XhttpClock = {
        let seconds = Arc::clone(&seconds);
        Arc::new(move || base + Duration::from_secs(seconds.load(Ordering::Acquire)))
    };
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = success_h2_dial(Arc::clone(&dials));
    let mut policy = unlimited_xmux();
    policy.h_max_reusable_secs = XhttpRange::exact(1);
    let expiring_transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        policy,
        4,
    )
    .with_clock(Arc::clone(&clock))
    .unwrap();
    let first = expiring_transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    drop(first);
    seconds.store(2, Ordering::Release);
    let second = expiring_transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    drop(second);
    assert_eq!(dials.load(Ordering::Acquire), 2, "xmux expiry must redial");

    let idle_dials = Arc::new(AtomicUsize::new(0));
    let idle_dial = success_h2_dial(Arc::clone(&idle_dials));
    let idle_transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
    )
    .with_clock(clock)
    .unwrap()
    .with_h2_idle_timeout(Duration::from_secs(3))
    .unwrap();
    let first = idle_transport
        .open_stream_with_dial(Arc::clone(&idle_dial))
        .await
        .unwrap();
    drop(first);
    seconds.store(6, Ordering::Release);
    let second = idle_transport
        .open_stream_with_dial(idle_dial)
        .await
        .unwrap();
    drop(second);
    assert_eq!(
        idle_dials.load(Ordering::Acquire),
        2,
        "idle pool must redial"
    );
}

#[tokio::test]
async fn h2_idle_timeout_never_retires_a_connection_with_an_active_flow() {
    let base = Instant::now();
    let seconds = Arc::new(AtomicU64::new(0));
    let clock: XhttpClock = {
        let seconds = Arc::clone(&seconds);
        Arc::new(move || base + Duration::from_secs(seconds.load(Ordering::Acquire)))
    };
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = success_h2_dial(Arc::clone(&dials));
    let mut policy = unlimited_xmux();
    policy.max_concurrency = XhttpRange::exact(2);
    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http2,
        policy,
        4,
    )
    .with_clock(clock)
    .unwrap()
    .with_h2_idle_timeout(Duration::from_secs(3))
    .unwrap();

    let first = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    seconds.store(10, Ordering::Release);
    let second = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 1);

    drop((first, second));
    seconds.store(14, Ordering::Release);
    let third = transport.open_stream_with_dial(dial).await.unwrap();
    drop(third);
    assert_eq!(dials.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn usage_lease_decrements_on_successful_drop_and_open_error() {
    let transport = transport(
        XhttpModeSelection::StreamOne,
        XhttpHttpVersion::Http1,
        unlimited_xmux(),
        4,
    );
    let failing: XhttpDial = Arc::new(|| {
        Box::pin(async {
            Err(TransportError::Tcp(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "deliberate test failure",
            )))
        })
    });
    assert!(transport.open_stream_with_dial(failing).await.is_err());
    assert_eq!(transport.xmux_open_usages().await, vec![0]);

    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let _ = read_h1_head(&mut server).await?;
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
    });
    let stream = transport
        .open_stream_with_dial(queued_dial([client]))
        .await
        .unwrap();
    assert!(transport.xmux_open_usages().await.contains(&1));
    server.await.unwrap().unwrap();
    drop(stream);
    assert!(transport
        .xmux_open_usages()
        .await
        .iter()
        .all(|usage| *usage == 0));
}

#[test]
fn keepalive_negative_zero_and_positive_normalize_without_silent_drop() {
    let make = |value| {
        let mut policy = unlimited_xmux();
        policy.h_keep_alive_period_secs = value;
        transport(
            XhttpModeSelection::StreamOne,
            XhttpHttpVersion::Http2,
            policy,
            4,
        )
    };
    assert_eq!(make(-1).h2_keep_alive_period(), None);
    assert_eq!(
        make(0).h2_keep_alive_period(),
        Some(Duration::from_secs(45))
    );
    assert_eq!(make(7).h2_keep_alive_period(), Some(Duration::from_secs(7)));
}

#[tokio::test]
async fn packet_uploader_error_wakes_pending_downlink_with_the_same_error() {
    let dials = Arc::new(AtomicUsize::new(0));
    let dial: XhttpDial = Arc::new(move || {
        dials.fetch_add(1, Ordering::AcqRel);
        let (client, server_io) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let mut connection = server::handshake::<_>(server_io).await.unwrap();
            let (download, mut download_response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(download.method(), http::Method::GET);
            let _held_downlink = download_response
                .send_response(ok_response(), false)
                .unwrap();
            drain_h2_request(download.into_body()).await;

            let (upload, mut upload_response) = connection.accept().await.unwrap().unwrap();
            assert_ne!(upload.method(), http::Method::GET);
            // `Connection::accept` also drives the server connection. Drain
            // DATA in a sibling task while this task keeps polling the driver;
            // awaiting the body inline deadlocks before the 503 can be sent.
            let mut reject_upload = tokio::spawn(async move {
                drain_h2_request(upload.into_body()).await;
                upload_response
                    .send_response(status_response(StatusCode::SERVICE_UNAVAILABLE), true)
                    .expect("send deterministic upload rejection");
            });
            tokio::select! {
                result = &mut reject_upload => {
                    result.expect("upload rejection task panicked");
                }
                exchange = connection.accept() => {
                    match exchange {
                        Some(Ok((request, _))) => {
                            panic!("unexpected extra request while rejecting {:?}", request.method());
                        }
                        Some(Err(error)) => panic!("H2 server failed before rejection: {error}"),
                        None => panic!("H2 connection closed before rejection"),
                    }
                }
            }
            // `Connection::accept` is also the server-side connection driver;
            // keep polling it so the queued 503 reaches the client.
            while connection.accept().await.is_some() {}
        });
        Box::pin(async move { Ok(Box::new(client) as BoxedTransportStream) })
    });
    let transport = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        4,
    );
    let mut stream = transport.open_stream_with_dial(dial).await.unwrap();
    stream.write_all(b"boom").await.unwrap();

    let mut byte = [0_u8; 1];
    let read_error = timeout(DEADLINE, stream.read(&mut byte))
        .await
        .expect("blocked downlink was not woken")
        .expect_err("upload 503 must fail the logical stream");
    let write_error = stream
        .write_all(b"after-error")
        .await
        .expect_err("same shared failure must reach writes");
    assert_eq!(read_error.to_string(), write_error.to_string());
    assert_eq!(
        read_error.to_string(),
        "XHTTP HTTP/2 server returned status 503 Service Unavailable"
    );
}

fn transport(
    mode: XhttpModeSelection,
    version: XhttpHttpVersion,
    xmux: XhttpXmuxPolicy,
    max_post: i32,
) -> XhttpTransport {
    transport_with_headers(mode, version, xmux, max_post, HeaderMap::new())
}

fn transport_with_headers(
    mode: XhttpModeSelection,
    version: XhttpHttpVersion,
    xmux: XhttpXmuxPolicy,
    max_post: i32,
    headers: HeaderMap,
) -> XhttpTransport {
    let mut input = XhttpConfigInput {
        mode,
        path: "/api".to_owned(),
        headers,
        x_padding_bytes: XhttpRange::exact(1),
        sc_max_each_post_bytes: XhttpRange::exact(max_post),
        sc_min_posts_interval_ms: XhttpRange::exact(1),
        sc_max_buffered_posts: 4,
        ..XhttpConfigInput::default()
    };
    input.is_reality = mode == XhttpModeSelection::StreamOne;
    let mut config = XhttpConfig::normalize(input).unwrap();
    config.min_posts_interval_ms = NormalizedRange::exact(0);
    let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.com").unwrap();
    XhttpTransport::new(config, endpoint, version, xmux)
        .unwrap()
        .with_rng(Box::new(StepRng::new(0x0102_0304_0506_0708, 1)))
        .unwrap()
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

fn queued_dial<const N: usize>(streams: [DuplexStream; N]) -> XhttpDial {
    let streams = Arc::new(Mutex::new(VecDeque::from(streams)));
    Arc::new(move || {
        let stream = streams.lock().unwrap().pop_front();
        Box::pin(async move {
            stream
                .map(|stream| Box::new(stream) as BoxedTransportStream)
                .ok_or_else(|| {
                    TransportError::Tcp(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "test dial queue is empty",
                    ))
                })
        })
    })
}

fn counted_queued_dial<const N: usize>(
    streams: [DuplexStream; N],
    dials: Arc<AtomicUsize>,
) -> XhttpDial {
    let streams = Arc::new(Mutex::new(VecDeque::from(streams)));
    Arc::new(move || {
        dials.fetch_add(1, Ordering::AcqRel);
        let stream = streams.lock().unwrap().pop_front();
        Box::pin(async move {
            stream
                .map(|stream| Box::new(stream) as BoxedTransportStream)
                .ok_or_else(|| {
                    TransportError::Tcp(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "test dial queue is empty",
                    ))
                })
        })
    })
}

#[derive(Clone)]
struct PartialWriteArm {
    armed: Arc<AtomicBool>,
}

impl PartialWriteArm {
    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
}

struct ArmablePartialWriteStream {
    inner: DuplexStream,
    armed: Arc<AtomicBool>,
    accepted_after_arm: usize,
    limit: usize,
}

impl ArmablePartialWriteStream {
    fn new(inner: DuplexStream, limit: usize) -> (Self, PartialWriteArm) {
        let armed = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                armed: Arc::clone(&armed),
                accepted_after_arm: 0,
                limit,
            },
            PartialWriteArm { armed },
        )
    }
}

impl AsyncRead for ArmablePartialWriteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for ArmablePartialWriteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let armed = self.armed.load(Ordering::Acquire);
        let remaining = self.limit.saturating_sub(self.accepted_after_arm);
        if armed && remaining == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "scripted partial request-write failure",
            )));
        }
        let allowed = if armed {
            input.len().min(remaining)
        } else {
            input.len()
        };
        let written = match Pin::new(&mut self.inner).poll_write(cx, &input[..allowed]) {
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        if armed {
            self.accepted_after_arm += written;
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TransportStream for ArmablePartialWriteStream {
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

fn success_h2_dial(dials: Arc<AtomicUsize>) -> XhttpDial {
    h2_dial(dials, |request, mut respond| async move {
        // Client-side cancellation can race a detached test responder. It is
        // not a server failure and must not panic after the owning test passed.
        if respond.send_response(ok_response(), true).is_err() {
            return;
        }
        drain_h2_request(request.into_body()).await;
    })
}

fn scripted_h2_dial<const N: usize>(
    connections: [(BoxedTransportStream, tokio::task::JoinHandle<()>); N],
) -> (XhttpDial, Arc<AtomicUsize>) {
    assert!(
        matches!(N, 2 | 3),
        "scripted H2 dial requires two connections and permits one replay detector"
    );
    let connections = Arc::new(Mutex::new(VecDeque::from(connections)));
    let dials = Arc::new(AtomicUsize::new(0));
    let dial: XhttpDial = {
        let connections = Arc::clone(&connections);
        let dials = Arc::clone(&dials);
        Arc::new(move || {
            dials.fetch_add(1, Ordering::AcqRel);
            let connection = connections.lock().unwrap().pop_front();
            Box::pin(async move {
                let (stream, _server_task) = connection.ok_or_else(|| {
                    TransportError::Tcp(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "test dial queue is empty",
                    ))
                })?;
                Ok(stream)
            })
        })
    };
    (dial, dials)
}

fn h2_dial<F, Fut>(dials: Arc<AtomicUsize>, handler: F) -> XhttpDial
where
    F: Fn(http::Request<RecvStream>, server::SendResponse<Bytes>) -> Fut
        + Send
        + Sync
        + Clone
        + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    Arc::new(move || {
        dials.fetch_add(1, Ordering::AcqRel);
        let handler = handler.clone();
        let (client, server_io) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let mut connection = server::handshake::<_>(server_io).await.unwrap();
            while let Some(exchange) = connection.accept().await {
                let Ok((request, respond)) = exchange else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(handler(request, respond));
            }
        });
        Box::pin(async move { Ok(Box::new(client) as BoxedTransportStream) })
    })
}

async fn drain_h2_request(mut body: RecvStream) -> Vec<u8> {
    let mut output = Vec::new();
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(chunk) => {
                body.flow_control().release_capacity(chunk.len()).unwrap();
                output.extend_from_slice(&chunk);
            }
            Err(_) => break,
        }
    }
    output
}

fn ok_response() -> Response<()> {
    status_response(StatusCode::OK)
}

fn status_response(status: StatusCode) -> Response<()> {
    Response::builder().status(status).body(()).unwrap()
}

async fn serve_h1_stream_up_session(
    mut downlink: DuplexStream,
    mut uplink: DuplexStream,
) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let down_head = read_h1_head(&mut downlink).await?;
    downlink
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .await?;

    let up_head = read_h1_head(&mut uplink).await?;
    let body = read_h1_chunked(&mut uplink).await?;
    let _ = uplink
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .await;
    Ok((down_head, up_head, body))
}

async fn read_h1_head<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let byte = reader.read_u8().await?;
        output.push(byte);
        if output.ends_with(b"\r\n\r\n") {
            return Ok(output);
        }
        if output.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test request head is too large",
            ));
        }
    }
}

async fn read_h1_line<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        output.push(reader.read_u8().await?);
        if output.ends_with(b"\r\n") {
            output.truncate(output.len() - 2);
            return Ok(output);
        }
    }
}

async fn read_h1_chunked<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let line = read_h1_line(reader).await?;
        let size = usize::from_str_radix(
            std::str::from_utf8(line.split(|byte| *byte == b';').next().unwrap())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            16,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if size == 0 {
            while !read_h1_line(reader).await?.is_empty() {}
            return Ok(output);
        }
        let offset = output.len();
        output.resize(offset + size, 0);
        reader.read_exact(&mut output[offset..]).await?;
        let mut terminator = [0_u8; 2];
        reader.read_exact(&mut terminator).await?;
        if terminator != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid test chunk terminator",
            ));
        }
    }
}

fn h1_content_length(head: &[u8]) -> io::Result<usize> {
    let text = std::str::from_utf8(head)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    text.lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?
        .trim()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn h1_target(head: &[u8]) -> &str {
    std::str::from_utf8(head)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
}

fn h1_path(head: &[u8]) -> &str {
    h1_target(head).split('?').next().unwrap()
}

fn h1_header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    std::str::from_utf8(head)
        .ok()?
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn wait_until(predicate: impl Fn() -> bool) {
    timeout(DEADLINE, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("condition did not become true");
}
