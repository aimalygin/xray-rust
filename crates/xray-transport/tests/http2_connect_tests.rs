//! HTTP/2 CONNECT tunnels against an h2 server over an in-memory pipe.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::server::{self, SendResponse};
use h2::RecvStream;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::timeout;
use xray_transport::stream::{Http2ConnectClient, Http2ConnectError};
use xray_transport::{set_memory_class, MemoryClass};

const DEADLINE: Duration = Duration::from_secs(10);

/// The server's end of the pipe, recording every byte the client sent.
struct Recorded {
    io: DuplexStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Recorded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, buf);
        let read = buf.filled()[before..].to_vec();
        self.log.lock().unwrap().extend_from_slice(&read);
        polled
    }
}

impl AsyncWrite for Recorded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// How the server answers each CONNECT, in order; the last one repeats.
#[derive(Clone, Copy)]
enum Answer {
    /// 200, then echo the tunnel.
    Echo,
    /// This status with END_STREAM.
    Refuse(u16),
    /// `RST_STREAM(REFUSED_STREAM)` instead of an answer.
    RefuseStream,
}

/// What the server saw of each request.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    authority: Option<String>,
    scheme: Option<String>,
    path: Option<String>,
    fields: Vec<(String, String)>,
}

struct Server {
    seen: Arc<Mutex<Vec<Seen>>>,
    log: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn pair(max_streams: Option<u32>, answers: Vec<Answer>) -> (Http2ConnectClient, Server) {
    pair_with_goaway(max_streams, answers, None).await
}

/// A pair whose server sends GOAWAY once it has accepted `goaway_after`
/// requests, and keeps serving the ones it accepted.
async fn pair_with_goaway(
    max_streams: Option<u32>,
    answers: Vec<Answer>,
    goaway_after: Option<usize>,
) -> (Http2ConnectClient, Server) {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Recorded {
        io: server_io,
        log: Arc::clone(&log),
    };
    let server_seen = Arc::clone(&seen);
    let task = tokio::spawn(async move {
        let mut builder = server::Builder::new();
        if let Some(max) = max_streams {
            builder.max_concurrent_streams(max);
        }
        let mut connection = builder.handshake::<_, Bytes>(recorded).await.unwrap();
        let mut index = 0;
        while let Some(Ok((request, respond))) = connection.accept().await {
            let answer = answers[index.min(answers.len() - 1)];
            index += 1;
            server_seen.lock().unwrap().push(seen_of(&request));
            tokio::spawn(answer_request(request, respond, answer));
            if goaway_after == Some(index) {
                connection.graceful_shutdown();
            }
        }
    });
    let client = Http2ConnectClient::handshake(Box::new(client_io))
        .await
        .unwrap();
    (client, Server { seen, log, task })
}

fn seen_of(request: &Request<RecvStream>) -> Seen {
    Seen {
        method: request.method().to_string(),
        authority: request.uri().authority().map(ToString::to_string),
        scheme: request.uri().scheme_str().map(str::to_owned),
        path: request.uri().path_and_query().map(ToString::to_string),
        fields: request
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
            .collect(),
    }
}

async fn answer_request(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    answer: Answer,
) {
    match answer {
        Answer::RefuseStream => respond.send_reset(h2::Reason::REFUSED_STREAM),
        Answer::Refuse(status) => {
            let response = Response::builder()
                .status(StatusCode::from_u16(status).unwrap())
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
        }
        Answer::Echo => {
            let mut send = respond.send_response(Response::new(()), false).unwrap();
            let mut body = request.into_body();
            while let Some(Ok(data)) = body.data().await {
                if data.is_empty() {
                    continue;
                }
                let _ = body.flow_control().release_capacity(data.len());
                send.reserve_capacity(data.len());
                let _ = std::future::poll_fn(|cx| send.poll_capacity(cx)).await;
                if send.send_data(data, false).is_err() {
                    return;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        }
    }
}

/// The client's SETTINGS parameters and its connection WINDOW_UPDATE, read
/// from the bytes after the preface.
fn opening_frames(log: &[u8]) -> (Vec<(u16, u32)>, u32) {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(log.starts_with(PREFACE));
    let mut rest = &log[PREFACE.len()..];
    let mut settings = None;
    let mut increment = None;
    while rest.len() >= 9 && (settings.is_none() || increment.is_none()) {
        let len = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]) as usize;
        let (kind, stream) = (rest[3], u32::from_be_bytes(rest[5..9].try_into().unwrap()));
        let payload = &rest[9..9 + len];
        match kind {
            0x4 if settings.is_none() => {
                settings = Some(
                    payload
                        .chunks(6)
                        .map(|p| {
                            (
                                u16::from_be_bytes([p[0], p[1]]),
                                u32::from_be_bytes([p[2], p[3], p[4], p[5]]),
                            )
                        })
                        .collect(),
                );
            }
            0x8 if stream == 0 => {
                increment = Some(u32::from_be_bytes(payload.try_into().unwrap()));
            }
            _ => {}
        }
        rest = &rest[9 + len..];
    }
    (settings.unwrap(), increment.unwrap())
}

#[tokio::test]
async fn a_tunnel_is_a_connect_stream_opened_with_gos_settings() {
    timeout(DEADLINE, async {
        set_memory_class(Some(MemoryClass::Standard));
        let (client, server) = pair(None, vec![Answer::Echo]).await;
        // A constrained host opens at a quarter of Go's window, as XHTTP does.
        set_memory_class(Some(MemoryClass::Constrained));
        let (constrained, constrained_server) = pair(None, vec![Answer::Echo]).await;
        set_memory_class(None);
        // The 200 comes after the server read the client's opening frames.
        let _tunnel = constrained.open("example.com:443", &[]).await.unwrap();
        let (settings, _) = opening_frames(&constrained_server.log.lock().unwrap());
        assert_eq!(
            settings,
            [(0x2, 0), (0x4, 1 << 20), (0x5, 1 << 20), (0x6, 10 << 20)]
        );
        let mut tunnel = client
            .open(
                "example.com:443",
                &[
                    ("proxy-authorization", "Basic dTpw"),
                    ("user-agent", "synthetic-agent"),
                    ("cookie", "a=1"),
                    ("cookie", "b=2"),
                ],
            )
            .await
            .unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        let mut echoed = [0; 4];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        // A shutdown is END_STREAM, which the echo answers with its own.
        tunnel.shutdown().await.unwrap();
        let mut rest = Vec::new();
        tunnel.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());

        let seen = server.seen.lock().unwrap()[0].clone();
        assert_eq!(seen.method, "CONNECT");
        assert_eq!(seen.authority.as_deref(), Some("example.com:443"));
        assert_eq!((seen.scheme, seen.path), (None, None));
        assert_eq!(
            seen.fields,
            [
                ("proxy-authorization".into(), "Basic dTpw".into()),
                ("user-agent".into(), "synthetic-agent".into()),
                ("cookie".into(), "a=1".into()),
                ("cookie".into(), "b=2".into()),
            ]
        );
        // Go's client SETTINGS in Go's order; the connection credit is the
        // engine's 16 MiB, where Go grants 1 GiB.
        let (settings, increment) = opening_frames(&server.log.lock().unwrap());
        assert_eq!(
            settings,
            [(0x2, 0), (0x4, 4 << 20), (0x5, 1 << 20), (0x6, 10 << 20)]
        );
        assert_eq!(increment, (16 << 20) - 65_535);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tunnels_share_the_connection_up_to_the_proxys_stream_limit() {
    timeout(DEADLINE, async {
        let (client, server) = pair(Some(1), vec![Answer::Echo]).await;
        assert!(client.can_take_new_tunnel());
        let tunnel = client.open("example.com:443", &[]).await.unwrap();
        // The proxy's SETTINGS arrived before its 200: one stream is the limit.
        assert!(!client.can_take_new_tunnel());
        // A clone shares the connection and its count.
        assert!(!client.clone().can_take_new_tunnel());
        // Each half keeps the tunnel counted until both are gone, whichever
        // goes first.
        let (read, write) = tunnel.into_io_halves();
        drop(read);
        assert!(!client.can_take_new_tunnel());
        drop(write);
        assert!(client.can_take_new_tunnel());
        let second = client.open("example.com:443", &[]).await.unwrap();
        let (read, write) = second.into_io_halves();
        drop(write);
        assert!(!client.can_take_new_tunnel());
        drop(read);
        assert!(client.can_take_new_tunnel());
        assert_eq!(server.seen.lock().unwrap().len(), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_refused_tunnel_fails_alone() {
    timeout(DEADLINE, async {
        let (client, server) = pair(None, vec![Answer::Refuse(403), Answer::Echo]).await;
        let Err(error) = client.open("example.com:443", &[]).await else {
            panic!("a 403 must not open the tunnel");
        };
        assert!(matches!(error, Http2ConnectError::Rejected(403)), "{error}");
        assert!(!error.connection_unusable());
        // The connection stays up for the next tunnel.
        assert!(client.can_take_new_tunnel());
        let mut tunnel = client.open("example.com:443", &[]).await.unwrap();
        tunnel.write_all(b"ok").await.unwrap();
        let mut echoed = [0; 2];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ok");
        assert_eq!(server.seen.lock().unwrap().len(), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_closed_connection_is_unusable() {
    timeout(DEADLINE, async {
        let (client, server) = pair(None, vec![Answer::Echo]).await;
        drop(server);
        let mut unusable = false;
        for _ in 0..100 {
            if !client.can_take_new_tunnel() {
                unusable = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(unusable, "the driver should end with the connection");
        let Err(error) = client.open("example.com:443", &[]).await else {
            panic!("a closed connection must not open a tunnel");
        };
        assert!(error.connection_unusable(), "{error}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_field_http2_cannot_carry_fails_before_sending() {
    timeout(DEADLINE, async {
        let (client, server) = pair(None, vec![Answer::Echo]).await;
        let Err(error) = client.open("example.com:443", &[("x-line", "a\nb")]).await else {
            panic!("a line break must not reach HTTP/2");
        };
        assert!(matches!(error, Http2ConnectError::InvalidField), "{error}");
        assert!(client.can_take_new_tunnel());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(server.seen.lock().unwrap().is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_refused_stream_or_a_goaway_asks_for_a_new_connection() {
    timeout(DEADLINE, async {
        let (client, _server) = pair(None, vec![Answer::RefuseStream]).await;
        let Err(error) = client.open("example.com:443", &[]).await else {
            panic!("a refused stream must not open the tunnel");
        };
        assert!(error.connection_unusable(), "{error}");

        let (client, server) = pair_with_goaway(None, vec![Answer::Echo], Some(1)).await;
        let mut first = client.open("example.com:443", &[]).await.unwrap();
        // The GOAWAY leaves the open tunnel alone.
        first.write_all(b"a").await.unwrap();
        let mut echoed = [0; 1];
        first.read_exact(&mut echoed).await.unwrap();
        let mut refused = None;
        for _ in 0..100 {
            match client.open("example.com:443", &[]).await {
                Err(error) => {
                    refused = Some(error);
                    break;
                }
                Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        let error = refused.expect("a tunnel after GOAWAY must fail");
        assert!(error.connection_unusable(), "{error}");
        assert!(!server.seen.lock().unwrap().is_empty());
        first.write_all(b"b").await.unwrap();
        first.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"b");
    })
    .await
    .unwrap();
}
