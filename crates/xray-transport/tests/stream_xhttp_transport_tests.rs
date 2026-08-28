use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::{server, RecvStream};
use http::{header, Response, StatusCode};
use rand::rngs::mock::StepRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::{timeout, Instant};

use xray_transport::stream::xhttp_composer_test_only::{
    NormalizedRange, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpModeSelection, XhttpRange,
    XhttpScheme,
};
use xray_transport::stream::xhttp_transport_test_only::{
    XhttpClock, XhttpDial, XhttpHttpVersion, XhttpTransport, XhttpXmuxPolicy,
};
use xray_transport::stream::HeaderMap;
use xray_transport::{BoxedTransportStream, TransportError, TransportStream};

const DEADLINE: Duration = Duration::from_secs(3);
const GZIP_PONG: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x2b, 0xc8, 0xcf, 0x4b, 0x07, 0x00,
    0x4f, 0x41, 0x58, 0x21, 0x04, 0x00, 0x00, 0x00,
];

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
async fn default_xmux_separates_concurrent_flows_then_reuses_the_released_slot() {
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
    let third = transport.open_stream_with_dial(dial).await.unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 2);
    assert_eq!(transport.xmux_client_count().await, 2);
    drop((second, third));
    assert_eq!(transport.xmux_open_usages().await, vec![0, 0]);
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
