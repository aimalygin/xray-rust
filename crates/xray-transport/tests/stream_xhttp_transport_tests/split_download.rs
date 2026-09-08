use super::*;
use xray_transport::stream::xhttp_transport_test_only::XhttpModeDial;

fn split_transport(
    mode: XhttpModeSelection,
    version: XhttpHttpVersion,
    download: bool,
    policy: XhttpXmuxPolicy,
) -> XhttpTransport {
    let mut headers = HeaderMap::new();
    headers.set(if download { "X-Down" } else { "X-Up" }, "yes");
    let config = XhttpConfig::normalize(XhttpConfigInput {
        mode,
        path: if download { "/download" } else { "/upload" }.to_owned(),
        headers,
        session_placement: if download {
            XhttpMetadataPlacement::Header
        } else {
            XhttpMetadataPlacement::Path
        },
        session_key: if download { "X-Session" } else { "" }.to_owned(),
        x_padding_bytes: XhttpRange::exact(1),
        sc_max_each_post_bytes: XhttpRange::exact(4),
        sc_min_posts_interval_ms: XhttpRange::exact(1),
        ..Default::default()
    })
    .unwrap();
    XhttpTransport::new(
        config,
        XhttpEndpoint::new(
            XhttpScheme::Http,
            if download { "down.test" } else { "up.test" },
        )
        .unwrap(),
        version,
        policy,
    )
    .unwrap()
}

#[derive(Debug)]
struct Seen {
    path: String,
    session: Option<String>,
    body: Vec<u8>,
}

fn observing_dial(
    version: XhttpHttpVersion,
    download: bool,
    seen: mpsc::UnboundedSender<Seen>,
    count: Arc<AtomicUsize>,
) -> XhttpDial {
    if version == XhttpHttpVersion::Http2 {
        return h2_dial(count, move |request, mut respond| {
            let seen = seen.clone();
            async move {
                assert_eq!(
                    request.uri().authority().unwrap().as_str(),
                    if download { "down.test" } else { "up.test" }
                );
                assert!(request
                    .headers()
                    .contains_key(if download { "x-down" } else { "x-up" }));
                assert!(!request
                    .headers()
                    .contains_key(if download { "x-up" } else { "x-down" }));
                assert_eq!(
                    request.method(),
                    if download { Method::GET } else { Method::POST }
                );
                let path = request.uri().path().to_owned();
                let session = request
                    .headers()
                    .get("x-session")
                    .map(|v| v.to_str().unwrap().to_owned());
                if download {
                    let mut response = respond.send_response(ok_response(), false).unwrap();
                    response
                        .send_data(Bytes::from_static(b"pong"), true)
                        .unwrap();
                }
                let body = drain_h2_request(request.into_body()).await;
                if !download {
                    respond.send_response(ok_response(), true).unwrap();
                }
                seen.send(Seen {
                    path,
                    session,
                    body,
                })
                .unwrap();
            }
        });
    }
    Arc::new(move || {
        count.fetch_add(1, Ordering::AcqRel);
        let seen = seen.clone();
        let (client, mut server) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let head = read_h1_head(&mut server).await.unwrap();
            assert_eq!(
                h1_header_value(&head, "Host"),
                Some(if download { "down.test" } else { "up.test" })
            );
            assert_eq!(
                h1_header_value(&head, if download { "X-Down" } else { "X-Up" }),
                Some("yes")
            );
            assert_eq!(
                h1_header_value(&head, if download { "X-Up" } else { "X-Down" }),
                None
            );
            assert!(head.starts_with(if download { b"GET " } else { b"POST " }));
            let path = h1_path(&head).to_owned();
            let session = h1_header_value(&head, "X-Session").map(str::to_owned);
            let body = if download {
                Vec::new()
            } else if h1_header_value(&head, "Transfer-Encoding") == Some("chunked") {
                read_h1_chunked(&mut server).await.unwrap()
            } else {
                let mut body = vec![0; h1_content_length(&head).unwrap()];
                server.read_exact(&mut body).await.unwrap();
                body
            };
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                .await
                .unwrap();
            seen.send(Seen {
                path,
                session,
                body,
            })
            .unwrap();
        });
        Box::pin(async move { Ok(Box::new(client) as BoxedTransportStream) })
    })
}

#[tokio::test]
async fn independent_h1_h2_downloads_share_session_without_sharing_headers_or_pools() {
    for mode in [XhttpModeSelection::PacketUp, XhttpModeSelection::StreamUp] {
        for up_version in [XhttpHttpVersion::Http1, XhttpHttpVersion::Http2] {
            for down_version in [XhttpHttpVersion::Http1, XhttpHttpVersion::Http2] {
                let up = split_transport(mode, up_version, false, unlimited_xmux());
                let down = split_transport(
                    XhttpModeSelection::Auto,
                    down_version,
                    true,
                    unlimited_xmux(),
                );
                let (seen, mut events) = mpsc::unbounded_channel();
                let up_count = Arc::new(AtomicUsize::new(0));
                let down_count = Arc::new(AtomicUsize::new(0));
                let mut stream = timeout(
                    DEADLINE,
                    up.open_split_stream_with_dials(
                        XhttpModeDial::Stream(observing_dial(
                            up_version,
                            false,
                            seen.clone(),
                            up_count.clone(),
                        )),
                        &down,
                        XhttpModeDial::Stream(observing_dial(
                            down_version,
                            true,
                            seen,
                            down_count.clone(),
                        )),
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(!up.shares_xmux_with(&down));
                assert_eq!(up.xmux_open_usages().await, vec![1]);
                assert_eq!(down.xmux_open_usages().await, vec![1]);
                let mut response = [0; 4];
                // Server-first data is readable before sending any upload bytes.
                timeout(DEADLINE, stream.read_exact(&mut response))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&response, b"pong");
                stream.write_all(b"ping").await.unwrap();
                stream.shutdown().await.unwrap();
                let first = timeout(DEADLINE, events.recv()).await.unwrap().unwrap();
                let second = timeout(DEADLINE, events.recv()).await.unwrap().unwrap();
                let (d, u) = if first.session.is_some() {
                    (first, second)
                } else {
                    (second, first)
                };
                assert_eq!(d.path, "/download/");
                assert_eq!(u.path.split('/').nth(2), d.session.as_deref());
                assert_eq!(u.body, b"ping");
                assert!(d.body.is_empty());
                drop(stream);
                assert!(up.xmux_open_usages().await.iter().all(|n| *n == 0));
                assert!(down.xmux_open_usages().await.iter().all(|n| *n == 0));
                assert_eq!(up_count.load(Ordering::Acquire), 1);
                assert_eq!(down_count.load(Ordering::Acquire), 1);
            }
        }
    }
}

#[tokio::test]
async fn cancelling_upload_setup_aborts_download_and_releases_both_leases() {
    let up = split_transport(
        XhttpModeSelection::StreamUp,
        XhttpHttpVersion::Http1,
        false,
        unlimited_xmux(),
    );
    let down = split_transport(
        XhttpModeSelection::Auto,
        XhttpHttpVersion::Http1,
        true,
        unlimited_xmux(),
    );
    let (client, mut server) = tokio::io::duplex(65536);
    let (started, mut started_rx) = mpsc::unbounded_channel();
    let pending_dial: XhttpDial = Arc::new(move || {
        started.send(()).unwrap();
        Box::pin(std::future::pending())
    });
    let read_eof = tokio::spawn(async move {
        let head = read_h1_head(&mut server).await.unwrap();
        assert!(head.starts_with(b"GET "));
        server.read(&mut [0]).await.unwrap()
    });
    let task = tokio::spawn({
        let up = up.clone();
        let down = down.clone();
        async move {
            up.open_split_stream_with_dials(
                XhttpModeDial::Stream(pending_dial),
                &down,
                XhttpModeDial::Stream(queued_dial([client])),
            )
            .await
        }
    });
    timeout(DEADLINE, started_rx.recv()).await.unwrap().unwrap();
    task.abort();
    assert!(matches!(task.await, Err(e) if e.is_cancelled()));
    assert_eq!(timeout(DEADLINE, read_eof).await.unwrap().unwrap(), 0);
    assert_eq!(up.xmux_open_usages().await, vec![0]);
    assert_eq!(down.xmux_open_usages().await, vec![0]);
}

#[tokio::test]
async fn download_failure_fails_both_halves_without_dialing_packet_uploader() {
    let up = split_transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http1,
        false,
        unlimited_xmux(),
    );
    let down = split_transport(
        XhttpModeSelection::Auto,
        XhttpHttpVersion::Http1,
        true,
        unlimited_xmux(),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let up_dial: XhttpDial = {
        let count = count.clone();
        Arc::new(move || {
            count.fetch_add(1, Ordering::AcqRel);
            Box::pin(async {
                Err(TransportError::Xhttp(
                    "must not upload after download failure".to_owned(),
                ))
            })
        })
    };
    let (client, mut server) = tokio::io::duplex(65536);
    let responder = tokio::spawn(async move {
        read_h1_head(&mut server).await.unwrap();
        server
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut stream = up
        .open_split_stream_with_dials(
            XhttpModeDial::Stream(up_dial),
            &down,
            XhttpModeDial::Stream(queued_dial([client])),
        )
        .await
        .unwrap();
    let read = timeout(DEADLINE, stream.read(&mut [0]))
        .await
        .unwrap()
        .unwrap_err();
    let write = stream.write(b"must not send").await.unwrap_err();
    assert_eq!(read.to_string(), write.to_string());
    assert_eq!(count.load(Ordering::Acquire), 0);
    drop(stream);
    responder.await.unwrap();
    assert_eq!(up.xmux_open_usages().await, vec![0]);
    assert_eq!(down.xmux_open_usages().await, vec![0]);
}

#[tokio::test]
async fn packet_rollover_does_not_rotate_the_independent_download_pool() {
    let mut policy = unlimited_xmux();
    policy.h_max_request_times = XhttpRange::exact(2);
    let up = transport(
        XhttpModeSelection::PacketUp,
        XhttpHttpVersion::Http2,
        policy,
        1,
    );
    let down = transport(
        XhttpModeSelection::Auto,
        XhttpHttpVersion::Http2,
        unlimited_xmux(),
        1,
    );
    let up_count = Arc::new(AtomicUsize::new(0));
    let down_count = Arc::new(AtomicUsize::new(0));
    let mut stream = up
        .open_split_stream_with_dials(
            XhttpModeDial::Stream(success_h2_dial(up_count.clone())),
            &down,
            XhttpModeDial::Stream(success_h2_dial(down_count.clone())),
        )
        .await
        .unwrap();
    for _ in 0..4 {
        stream.write_all(b"x").await.unwrap();
    }
    stream.shutdown().await.unwrap();
    assert!(up_count.load(Ordering::Acquire) >= 2);
    assert_eq!(down_count.load(Ordering::Acquire), 1);
    assert_eq!(down.xmux_open_usages().await, vec![1]);
    drop(stream);
    timeout(DEADLINE, async {
        loop {
            if up.xmux_open_usages().await.iter().all(|n| *n == 0)
                && down.xmux_open_usages().await.iter().all(|n| *n == 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
