//! Answers under their limit, as Go's transport reads them for Xray-core:
//! a gzip body decoded as it arrives and never read past the limit, over
//! HTTP/1.1, HTTP/2 and HTTP/3 from servers that would send far more. The bodies
//! end somewhere, 32 or 64 MiB on, so that a client reading on shows as
//! bytes counted rather than as memory that only grows.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_compression::tokio::bufread::GzipEncoder;
use bytes::Bytes;
use http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::client::{
    read_body, ChunkedBody, Prepared, Progress, ServiceClient, ServiceDialer, ServiceRequest,
    ServiceUrl,
};
use super::h2::H2Connection;
use crate::{TlsClientConfig, TransportDialer};

/// The most of an answer these tests read: a MiB, and one byte more to
/// tell an answer past the limit.
const LIMIT: usize = (1 << 20) + 1;

/// One gzip member of `bytes`.
async fn member(bytes: &[u8]) -> Bytes {
    let mut encoded = Vec::new();
    GzipEncoder::new(bytes)
        .read_to_end(&mut encoded)
        .await
        .unwrap();
    Bytes::from(encoded)
}

/// 64 KiB that gzip cannot shrink, from xorshift.
fn noise() -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..64 << 10)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// The most bytes a server here sends of a body the client should stop
/// reading after a MiB.
const SERVED: usize = 64 << 20;

/// A body of `chunks` handed out one by one; `served` counts them.
fn chunked(
    chunks: Vec<Bytes>,
    served: Arc<AtomicUsize>,
) -> ChunkedBody<impl FnMut(&mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> + Unpin> {
    let mut chunks = chunks.into_iter();
    ChunkedBody::new(move |_: &mut Context<'_>| {
        served.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(chunks.next().map(Ok))
    })
}

/// `chunk` again and again, `times` times; `served` counts them.
fn repeated(
    chunk: Bytes,
    times: usize,
    served: Arc<AtomicUsize>,
) -> ChunkedBody<impl FnMut(&mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> + Unpin> {
    chunked(vec![chunk; times], served)
}

async fn read_within(
    body: impl tokio::io::AsyncBufRead + Unpin,
    gzip: bool,
) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(10), read_body(body, gzip, LIMIT))
        .await
        .expect("the body ends at the limit")
        .map_err(|error| error.to_string())
}

#[tokio::test]
async fn a_long_gzip_body_ends_at_the_limit_read_as_it_comes() {
    // 512 members of 64 KiB of zeros, one stream to Go's gzip reader:
    // sixteen make the MiB, and the body is read no further.
    let served = Arc::new(AtomicUsize::new(0));
    let zeros = member(&[0; 64 << 10]).await;
    let body = read_within(repeated(zeros, 512, Arc::clone(&served)), true)
        .await
        .unwrap();
    assert_eq!(body.len(), LIMIT);
    assert!(body.iter().all(|&byte| byte == 0));
    let served = served.load(Ordering::Relaxed);
    assert!(served <= 18, "{served} members read for a MiB");
}

#[tokio::test]
async fn a_gzip_bomb_is_read_only_as_far_as_the_limit() {
    // 64 MiB of zeros in one member, fed in 1 KiB pieces: a MiB of it
    // takes about one of them.
    let bomb = member(&vec![0; 64 << 20]).await;
    let pieces: Vec<Bytes> = (0..bomb.len())
        .step_by(1024)
        .map(|at| bomb.slice(at..(at + 1024).min(bomb.len())))
        .collect();
    let total = pieces.len();
    let served = Arc::new(AtomicUsize::new(0));
    let body = read_within(chunked(pieces, Arc::clone(&served)), true)
        .await
        .unwrap();
    assert_eq!(body.len(), LIMIT);
    let served = served.load(Ordering::Relaxed);
    assert!(served * 8 < total, "{served} of {total} pieces read");
}

#[tokio::test]
async fn gzip_bodies_read_as_gos_gzip_reader_reads_them() {
    let served = Arc::new(AtomicUsize::new(0));
    let (abc, def) = (member(b"abc").await, member(b"def").await);
    // Concatenated members are one stream.
    let both = Bytes::from([abc.as_ref(), def.as_ref()].concat());
    let body = read_within(chunked(vec![both], Arc::clone(&served)), true).await;
    assert_eq!(body.unwrap(), b"abcdef");
    // An empty body is nothing, as io.EOF from gzip.NewReader.
    let body = read_within(chunked(Vec::new(), Arc::clone(&served)), true).await;
    assert_eq!(body.unwrap(), b"");
    // What follows a member must be another one; a member cut short fails.
    let trailing = Bytes::from([abc.as_ref(), b"not gzip"].concat());
    assert!(
        read_within(chunked(vec![trailing], Arc::clone(&served)), true)
            .await
            .is_err()
    );
    let cut = abc.slice(..abc.len() - 3);
    assert!(read_within(chunked(vec![cut], Arc::clone(&served)), true)
        .await
        .is_err());
    // A plain body is taken as it is, up to the limit.
    let plain = Bytes::from(noise());
    let plain = read_within(repeated(plain, 32, served), false)
        .await
        .unwrap();
    assert_eq!(plain.len(), LIMIT);
}

/// An HTTP/1.1 server: on its first connection a chunked gzip body of
/// [`SERVED`] bytes, `member` again and again, on later ones `ok`. It
/// counts connections, and the bytes of the long body sent before the
/// client let it go.
struct LongHttp1 {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    sent: Arc<AtomicUsize>,
    gone: Arc<AtomicBool>,
}

async fn long_http1(member: Bytes) -> LongHttp1 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = LongHttp1 {
        addr: listener.local_addr().unwrap(),
        connections: Arc::new(AtomicUsize::new(0)),
        sent: Arc::new(AtomicUsize::new(0)),
        gone: Arc::new(AtomicBool::new(false)),
    };
    let (connections, sent, gone) = (
        Arc::clone(&server.connections),
        Arc::clone(&server.sent),
        Arc::clone(&server.gone),
    );
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let first = connections.fetch_add(1, Ordering::Relaxed) == 0;
            let (member, sent, gone) = (member.clone(), Arc::clone(&sent), Arc::clone(&gone));
            tokio::spawn(async move {
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    if !first {
                        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                        if socket.write_all(ok).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\
                        Transfer-Encoding: chunked\r\n\r\n";
                    if socket.write_all(head).await.is_err() {
                        return;
                    }
                    let chunk = [
                        format!("{:x}\r\n", member.len()).as_bytes(),
                        &member,
                        b"\r\n",
                    ]
                    .concat();
                    while sent.load(Ordering::Relaxed) < SERVED {
                        if socket.write_all(&chunk).await.is_err() {
                            gone.store(true, Ordering::Relaxed);
                            return;
                        }
                        sent.fetch_add(chunk.len(), Ordering::Relaxed);
                    }
                    if socket.write_all(b"0\r\n\r\n").await.is_err() {
                        gone.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });
    server
}

fn request(url: &str) -> ServiceRequest {
    ServiceRequest {
        method: Method::GET,
        url: ServiceUrl::parse(url).unwrap(),
        headers: Vec::new(),
        body: Bytes::new(),
        max_body: LIMIT - 1,
    }
}

#[tokio::test]
async fn http1_stops_a_long_gzip_body_at_the_limit_and_drops_the_connection() {
    let server = long_http1(member(&noise()).await).await;
    let dialer = ServiceDialer {
        dialer: TransportDialer::system().unwrap(),
        tls: TlsClientConfig {
            server_name: String::new(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: None,
        },
        fronting: None,
        keep_alive: None,
        h3: None,
    };
    let client = ServiceClient::new(
        Arc::new(dialer),
        Arc::new(Mutex::new(Default::default())),
        1,
    );
    let url = format!("http://{}/long", server.addr);
    let answer = tokio::time::timeout(Duration::from_secs(10), client.send(&request(&url)))
        .await
        .expect("the long answer ends at the limit")
        .unwrap();
    assert_eq!(answer.body.len(), LIMIT);
    // The connection whose body was left unread is not used again.
    let next = client.send(&request(&url)).await.unwrap();
    assert_eq!(next.body, "ok");
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !server.gone.load(Ordering::Relaxed) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        server.gone.load(Ordering::Relaxed),
        "the server still sends"
    );
    let sent = server.sent.load(Ordering::Relaxed);
    assert!(sent < 16 << 20, "{sent} bytes sent before the client left");
}

#[tokio::test]
async fn http2_stops_a_long_gzip_body_at_the_limit_and_resets_the_stream() {
    let noise = member(&noise()).await;
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (_, mut respond) = connection.accept().await.unwrap().unwrap();
        // Later requests get `ok`, on the same connection.
        tokio::spawn(async move {
            while let Some(Ok((_, mut respond))) = connection.accept().await {
                let ok = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(ok, false).unwrap();
                let _ = send.send_data(Bytes::from_static(b"ok"), true);
            }
        });
        let long = http::Response::builder()
            .status(200)
            .header("content-encoding", "gzip")
            .body(())
            .unwrap();
        let mut send = respond.send_response(long, false).unwrap();
        // The member again and again, cut wherever the window falls, up to
        // SERVED bytes, and then the end of the stream.
        let (mut sent, mut at) = (0usize, 0usize);
        while sent < SERVED {
            send.reserve_capacity(noise.len());
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(granted)) if granted > 0 => {
                    let taken = granted.min(noise.len() - at);
                    if send.send_data(noise.slice(at..at + taken), false).is_err() {
                        break;
                    }
                    at = (at + taken) % noise.len();
                    sent += taken;
                }
                Some(Ok(_)) => {}
                _ => break,
            }
        }
        if sent >= SERVED {
            let _ = send.send_data(Bytes::new(), true);
            return (sent, None);
        }
        let reset = std::future::poll_fn(|cx| send.poll_reset(cx)).await;
        (sent, reset.ok())
    });
    let connection = H2Connection::handshake(Box::new(client_io), None)
        .await
        .unwrap();
    let long = request("https://storage.test/long");
    let answer = tokio::time::timeout(
        Duration::from_secs(10),
        connection.send(&Prepared::new(&long), &Progress::new()),
    )
    .await
    .expect("the long answer ends at the limit")
    .unwrap();
    assert_eq!(answer.body.len(), LIMIT);
    let (sent, reset) = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the server learns the stream is gone")
        .unwrap();
    assert_eq!(reset, Some(h2::Reason::CANCEL));
    assert!(sent < 16 << 20, "{sent} bytes sent before the reset");
    // The connection lives on, as Go's after it resets a stream.
    let next = request("https://storage.test/ok");
    let next = connection
        .send(&Prepared::new(&next), &Progress::new())
        .await
        .unwrap();
    assert_eq!(next.body, "ok");
}

/// An HTTP/3 server on the loopback: its first request answered with a
/// gzip body of [`SERVED`] bytes, `member` again and again, later ones
/// with `ok`. The task gives the bytes of the long body it sent and the
/// code the client stopped it with, if it did.
async fn long_http3(
    member: Bytes,
) -> (
    SocketAddr,
    [u8; 32],
    tokio::task::JoinHandle<(usize, Option<h3::error::Code>)>,
) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
    let certified = rcgen::generate_simple_self_signed(vec!["storage.test".to_owned()]).unwrap();
    let der = certified.cert.der().clone();
    let pin: [u8; 32] = Sha256::digest(&der).into();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let resolver = h3.accept().await.unwrap().unwrap();
        let (_, mut stream) = resolver.resolve_request().await.unwrap();
        // Later requests get `ok`, on the same connection.
        tokio::spawn(async move {
            let _endpoint = endpoint;
            while let Ok(Some(resolver)) = h3.accept().await {
                if let Ok((_, mut stream)) = resolver.resolve_request().await {
                    let ok = http::Response::builder().status(200).body(()).unwrap();
                    let _ = stream.send_response(ok).await;
                    let _ = stream.send_data(Bytes::from_static(b"ok")).await;
                    let _ = stream.finish().await;
                }
            }
        });
        let long = http::Response::builder()
            .status(200)
            .header("content-encoding", "gzip")
            .body(())
            .unwrap();
        stream.send_response(long).await.unwrap();
        let mut sent = 0usize;
        while sent < SERVED {
            if let Err(error) = stream.send_data(member.clone()).await {
                let code = match error {
                    h3::error::StreamError::RemoteTerminate { code, .. } => Some(code),
                    _ => None,
                };
                return (sent, code);
            }
            sent += member.len();
        }
        let _ = stream.finish().await;
        (sent, None)
    });
    (addr, pin, task)
}

#[tokio::test]
async fn http3_stops_a_long_gzip_body_at_the_limit_and_stops_the_stream() {
    let (addr, pin, server) = long_http3(member(&noise()).await).await;
    let dialer = ServiceDialer {
        dialer: TransportDialer::system().unwrap(),
        tls: TlsClientConfig {
            server_name: "storage.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: vec![pin],
            verify_peer_cert_by_name: Vec::new(),
            alpn: vec!["h3".to_owned()],
            fingerprint: None,
        },
        fronting: None,
        keep_alive: None,
        h3: Some(crate::stream::H3QuicConfig::default()),
    };
    let client = ServiceClient::new(
        Arc::new(dialer),
        Arc::new(Mutex::new(Default::default())),
        1,
    );
    let long = request(&format!("https://{addr}/long"));
    let answer = tokio::time::timeout(Duration::from_secs(20), client.send(&long))
        .await
        .expect("the long answer ends at the limit")
        .unwrap();
    assert_eq!(answer.body.len(), LIMIT);
    let (sent, stopped) = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the server learns the stream is stopped")
        .unwrap();
    // Cancelled as quic-go's client cancels a body closed early.
    assert_eq!(stopped, Some(h3::error::Code::H3_REQUEST_CANCELLED));
    assert!(sent < SERVED / 2, "{sent} bytes sent before the stop");
    // The connection lives on, as quic-go's after it cancels a stream.
    let next = client
        .send(&request(&format!("https://{addr}/ok")))
        .await
        .unwrap();
    assert_eq!(next.body, "ok");
}
