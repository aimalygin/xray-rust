#[path = "hysteria/support.rs"]
mod support;

use std::future::pending;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use support::{AUTH, DEADLINE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use xray_proxy::hysteria::decode_tcp_request;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::{HysteriaClient, HysteriaConfig, HysteriaError};
use xray_transport::{SocketHandle, SocketProtector, TlsConnector};

#[derive(Clone, Copy)]
enum Mode {
    Good,
    Rejected,
    Malformed,
    AuthStall,
    TcpStall,
    Prefetch,
    HalfClose,
    TcpRejected,
    TcpMalformed,
}

struct Mock {
    endpoint: quinn::Endpoint,
    driver: tokio::task::JoinHandle<()>,
    accepted: mpsc::Receiver<quinn::Connection>,
    tcp_cancelled: Arc<AtomicBool>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
        self.driver.abort();
    }
}

impl Mock {
    fn start(mode: Mode) -> (Self, TlsConnector) {
        let identity = support::identity();
        let endpoint = quinn::Endpoint::server(identity.server, support::localhost()).unwrap();
        let accepting = endpoint.clone();
        let (tx, accepted) = mpsc::channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let tcp_cancelled = Arc::clone(&cancelled);
        let driver = tokio::spawn(async move {
            let Ok(connection) = accepting.accept().await.unwrap().await else {
                return;
            };
            tx.send(connection.clone()).await.unwrap();
            let mut http3: h3::server::Connection<_, Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let Ok(Some(request)) = http3.accept().await else {
                return;
            };
            let Ok((request, mut response)) = request.resolve_request().await else {
                return;
            };
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().authority().unwrap().as_str(), "hysteria");
            assert_eq!(request.uri().path(), "/auth");
            assert_eq!(request.headers()["hysteria-auth"], AUTH);
            assert_eq!(request.headers()["hysteria-cc-rx"], "0");
            let padding = request.headers()["hysteria-padding"].as_bytes();
            assert!((256..2048).contains(&padding.len()));
            if matches!(mode, Mode::AuthStall) {
                pending::<()>().await;
            }
            let status = if matches!(mode, Mode::Rejected) {
                404
            } else {
                233
            };
            let udp = if matches!(mode, Mode::Malformed) {
                "invalid"
            } else {
                "false"
            };
            response
                .send_response(
                    Response::builder()
                        .status(status)
                        .header("hysteria-udp", udp)
                        .header("hysteria-cc-rx", "auto")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            response.finish().await.unwrap();
            if matches!(
                mode,
                Mode::TcpStall
                    | Mode::Prefetch
                    | Mode::HalfClose
                    | Mode::TcpRejected
                    | Mode::TcpMalformed
            ) {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut wire = Vec::new();
                while decode_tcp_request(&wire).is_err() {
                    let mut bytes = [0; 1024];
                    let n = recv.read(&mut bytes).await.unwrap().unwrap();
                    wire.extend_from_slice(&bytes[..n]);
                }
                if matches!(mode, Mode::TcpStall) {
                    let _ = send.stopped().await;
                    cancelled.store(true, Ordering::Release);
                } else if matches!(mode, Mode::HalfClose) {
                    send.write_all(b"\x00\x00\x00").await.unwrap();
                    let data = recv.read_to_end(4096).await.unwrap();
                    send.write_all(&data).await.unwrap();
                    send.finish().unwrap();
                } else if matches!(mode, Mode::TcpRejected) {
                    send.write_all(b"\x07\x06secret\x00").await.unwrap();
                    send.finish().unwrap();
                } else if matches!(mode, Mode::TcpMalformed) {
                    send.write_all(b"\x00\x7f\xff").await.unwrap();
                    send.finish().unwrap();
                } else {
                    send.write_all(b"\x00\x00\x00prefetched-data")
                        .await
                        .unwrap();
                    send.finish().unwrap();
                }
            }
            connection.closed().await;
            drop(http3);
        });
        (
            Self {
                endpoint,
                driver,
                accepted,
                tcp_cancelled,
            },
            identity.connector,
        )
    }
    fn config(&self) -> HysteriaConfig {
        HysteriaConfig::new(
            self.endpoint.local_addr().unwrap(),
            support::tls_settings(),
            AUTH.into(),
        )
    }
    async fn connection(&mut self) -> quinn::Connection {
        timeout(DEADLINE, self.accepted.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn authentication_headers_fail_closed_and_do_not_expose_auth() {
    for (mode, expected) in [
        (Mode::Rejected, HysteriaError::Authentication),
        (Mode::Malformed, HysteriaError::AuthenticationHeaders),
    ] {
        let (mut server, tls) = Mock::start(mode);
        let config = server.config();
        assert!(!format!("{config:?}").contains(AUTH));
        assert_eq!(
            HysteriaClient::connect(config, &tls).await.err(),
            Some(expected)
        );
        assert!(!format!("{expected:?} {expected}").contains(AUTH));
        timeout(DEADLINE, server.connection().await.closed())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn auth_deadline_and_caller_cancellation_close_pending_connection() {
    let (mut server, tls) = Mock::start(Mode::AuthStall);
    let mut config = server.config();
    config.limits.operation_timeout = Duration::from_millis(100);
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Timeout)
    );
    timeout(DEADLINE, server.connection().await.closed())
        .await
        .unwrap();

    let (mut server, tls) = Mock::start(Mode::AuthStall);
    let config = server.config();
    let task = tokio::spawn(async move { HysteriaClient::connect(config, &tls).await });
    let connection = server.connection().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    timeout(DEADLINE, connection.closed()).await.unwrap();
}

#[tokio::test]
async fn disabled_udp_last_clone_and_explicit_close_release_connection() {
    let (mut server, tls) = Mock::start(Mode::Good);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    assert!(!client.udp_enabled());
    assert!(matches!(
        client.open_udp(),
        Err(HysteriaError::UdpUnsupported)
    ));
    let connection = server.connection().await;
    let last = client.clone();
    drop(client);
    assert!(last.is_live());
    drop(last);
    timeout(DEADLINE, connection.closed()).await.unwrap();

    let (mut server, tls) = Mock::start(Mode::Good);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let local = client.local_addr().unwrap();
    client.close();
    assert!(client.local_addr().is_err());
    timeout(DEADLINE, server.connection().await.closed())
        .await
        .unwrap();
    timeout(DEADLINE, async {
        loop {
            if std::net::UdpSocket::bind(local).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed connection releases socket while client handle remains");
}

fn target() -> Target {
    Target::new(TargetAddr::Domain("example.com".into()), 443, Network::Tcp)
}

#[tokio::test]
async fn tcp_response_deadline_resets_stream_and_releases_slot() {
    let (server, tls) = Mock::start(Mode::TcpStall);
    let mut config = server.config();
    config.limits.operation_timeout = Duration::from_millis(150);
    config.limits.max_tcp_streams = 1;
    let client = HysteriaClient::connect(config, &tls).await.unwrap();
    assert!(matches!(
        client.open_tcp(&target()).await,
        Err(HysteriaError::Timeout)
    ));
    timeout(DEADLINE, async {
        while !server.tcp_cancelled.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A second attempt reaches the peer (then times out), rather than leaking
    // the only local slot from the cancelled request.
    assert!(matches!(
        client.open_tcp(&target()).await,
        Err(HysteriaError::Timeout)
    ));
    client.close();
}

#[tokio::test]
async fn tcp_response_preserves_prefetched_application_bytes() {
    let (server, tls) = Mock::start(Mode::Prefetch);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let mut stream = client.open_tcp(&target()).await.unwrap();
    let mut output = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output, b"prefetched-data");
}

#[tokio::test]
async fn tcp_half_close_keeps_the_receive_direction_open() {
    let (server, tls) = Mock::start(Mode::HalfClose);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let mut stream = client.open_tcp(&target()).await.unwrap();
    stream.write_all(b"reply after FIN").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut output = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output, b"reply after FIN");
}

#[tokio::test]
async fn tcp_failure_status_and_malformed_headers_fail_without_server_text() {
    for (mode, expected) in [
        (Mode::TcpRejected, HysteriaError::TcpRejected),
        (Mode::TcpMalformed, HysteriaError::TcpResponse),
    ] {
        let (server, tls) = Mock::start(mode);
        let client = HysteriaClient::connect(server.config(), &tls)
            .await
            .unwrap();
        let error = client.open_tcp(&target()).await.err().unwrap();
        assert_eq!(error, expected);
        assert!(!format!("{error} {error:?}").contains("secret"));
    }
}

struct Protector {
    calls: AtomicUsize,
    reject: bool,
}
impl SocketProtector for Protector {
    fn protect(&self, _socket: SocketHandle) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            Err(io::Error::other("synthetic rejection"))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn socket_protection_precedes_handshake_and_tls_remains_verified() {
    let (server, tls) = Mock::start(Mode::Good);
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        reject: true,
    });
    let protected = tls.with_socket_protector(protector.clone());
    assert_eq!(
        HysteriaClient::connect(server.config(), &protected)
            .await
            .err(),
        Some(HysteriaError::SocketProtection)
    );
    assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
    assert!(!server.driver.is_finished());
    // System trust must reject the generated local self-signed certificate.
    assert_eq!(
        HysteriaClient::connect(server.config(), &TlsConnector::system().unwrap())
            .await
            .err(),
        Some(HysteriaError::Connect)
    );
    let (server, tls) = Mock::start(Mode::Good);
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        reject: false,
    });
    let protected = tls.with_socket_protector(protector.clone());
    let client = HysteriaClient::connect(server.config(), &protected)
        .await
        .unwrap();
    assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
    client.close();
}

#[tokio::test]
async fn config_validation_happens_before_opening_a_socket() {
    let (server, tls) = Mock::start(Mode::Good);
    let mut config = server.config();
    config.limits.udp_queue_bytes = usize::MAX;
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    let mut config = server.config();
    config.auth = zeroize::Zeroizing::new("bad\r\nheader".into());
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    let mut config = server.config();
    config.tls.fingerprint = Some("chrome".into());
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    let mut config = server.config();
    config.tls.alpn = vec!["h2".into()];
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    assert!(!server.driver.is_finished());
}

#[tokio::test]
async fn dedicated_endpoint_advertises_zero_length_local_cid() {
    let (server, tls) = Mock::start(Mode::Good);
    let capture = tokio::net::UdpSocket::bind(support::localhost())
        .await
        .unwrap();
    let mut config = server.config();
    config.remote_addr = capture.local_addr().unwrap();
    let connecting = tokio::spawn(async move { HysteriaClient::connect(config, &tls).await });
    let mut packet = [0u8; 2048];
    let (len, _) = timeout(DEADLINE, capture.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    connecting.abort();
    assert!(len >= 1200, "QUIC Initial minimum datagram size");
    assert_eq!(packet[0] & 0xc0, 0xc0, "QUIC long header");
    assert_eq!(&packet[1..5], &1u32.to_be_bytes(), "QUIC v1");
    let destination_len = packet[5] as usize;
    assert!(destination_len >= 8, "initial server CID remains nonempty");
    assert_eq!(packet[6 + destination_len], 0, "empty client source CID");
}

#[tokio::test]
async fn rebind_from_host_thread_preserves_connection_and_protects_each_socket() {
    #[derive(Default)]
    struct Count(AtomicUsize);
    impl SocketProtector for Count {
        fn protect(&self, _: SocketHandle) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (mut server, tls) = Mock::start(Mode::Good);
    let count = Arc::new(Count::default());
    let tls = tls.with_socket_protector(count.clone());
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let connection = server.connection().await;
    let old = client.local_addr().unwrap();
    // A plain host thread has no Tokio context, as with the Swift/FFI caller.
    let host = client.clone();
    std::thread::spawn(move || {
        for _ in 0..100 {
            assert!(host.rebind());
        }
    })
    .join()
    .unwrap();
    timeout(DEADLINE, async {
        while client.local_addr().unwrap() == old {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 2);
    assert!(client.is_live());
    assert!(connection.close_reason().is_none());
    client.close();
    assert!(!client.rebind());
    timeout(DEADLINE, connection.closed()).await.unwrap();
}

#[tokio::test]
async fn rebind_protection_failure_closes_live_connection() {
    #[derive(Default)]
    struct RejectSecond(AtomicUsize);
    impl SocketProtector for RejectSecond {
        fn protect(&self, _: SocketHandle) -> io::Result<()> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
    }
    let (mut server, tls) = Mock::start(Mode::Good);
    let protector = Arc::new(RejectSecond::default());
    let tls = tls.with_socket_protector(protector.clone());
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let connection = server.connection().await;
    assert!(client.rebind());
    timeout(DEADLINE, connection.closed()).await.unwrap();
    assert!(!client.is_live());
    assert!(client.local_addr().is_err());
    assert!(!client.rebind());
    assert_eq!(protector.0.load(Ordering::SeqCst), 2);
}
