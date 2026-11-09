//! The HTTP/2 tunnel against an in-memory HTTP/2 proxy: the request Xray's
//! client sends, DATAGRAM capsules both ways, its refusals, the 32 KiB
//! buffer that holds a writer back and the keepalive.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicBool;

use bytes::BytesMut;
use http::Response;
use tokio::io::DuplexStream;
use tokio::time::timeout;

use super::*;
use crate::masque::capsule::{self, AssignedAddress, Capsule, CapsuleParser, IpPrefix, Parsed};
use crate::masque::WriteOutcome;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn config() -> MasqueH2Config {
    MasqueH2Config {
        authority: "proxy.example:8443".to_owned(),
        request: MasqueRequest {
            headers: vec![(
                "X-Custom".to_owned(),
                zeroize::Zeroizing::new("1".to_owned()),
            )],
            ..MasqueRequest::default()
        },
        keep_alive: Some(H2_KEEP_ALIVE),
        warp: None,
    }
}

/// An IPv4 UDP packet with `payload`.
fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// What the proxy does once it accepted the request.
#[derive(Clone, Copy, PartialEq)]
enum Proxy {
    /// Assigns addresses and echoes each packet back to its sender.
    Echo,
    /// Assigns addresses and never reads the request stream again.
    Stalled,
}

struct Accepted {
    request: http::request::Parts,
}

/// Serves one CONNECT-IP request over HTTP/2 on `io`.
async fn serve(
    io: DuplexStream,
    connect_protocol: bool,
    status: u16,
    proxy: Proxy,
) -> Option<Accepted> {
    let mut builder = h2::server::Builder::new();
    if connect_protocol {
        builder.enable_connect_protocol();
    }
    let mut connection = builder.handshake::<_, Bytes>(io).await.ok()?;
    let (request, mut respond) = connection.accept().await?.ok()?;
    tokio::spawn(async move { while connection.accept().await.is_some() {} });
    let (parts, mut body) = request.into_parts();
    let mut send = respond
        .send_response(Response::builder().status(status).body(()).unwrap(), false)
        .ok()?;
    if status != 200 {
        return Some(Accepted { request: parts });
    }
    tokio::spawn(async move {
        let mut parser = CapsuleParser::default();
        while let Some(Ok(data)) = body.data().await {
            let _ = body.flow_control().release_capacity(data.len());
            parser.push(data);
            while let Ok(Some(Parsed::Capsule(capsule))) = parser.next() {
                match capsule {
                    Capsule::AddressRequest(entries) => {
                        let assigned: Vec<AssignedAddress> = entries
                            .iter()
                            .map(|entry| AssignedAddress {
                                request_id: entry.request_id,
                                prefix: if entry.prefix.addr.is_ipv4() {
                                    IpPrefix::new(LOCAL.into(), 32)
                                } else {
                                    IpPrefix::new("fd00::2".parse().unwrap(), 128)
                                },
                            })
                            .collect();
                        let _ = send.send_data(capsule::address_assign(&assigned), false);
                        if proxy == Proxy::Stalled {
                            // Keep the stream open without reading it.
                            std::future::pending::<()>().await;
                        }
                    }
                    Capsule::Datagram(value) => {
                        assert_eq!(value[0], 0, "the context ID");
                        let mut packet = value[1..].to_vec();
                        let (src, dst) = (packet[12..16].to_vec(), packet[16..20].to_vec());
                        packet[12..16].copy_from_slice(&dst);
                        packet[16..20].copy_from_slice(&src);
                        let mut echo = BytesMut::new();
                        capsule::put_varint(&mut echo, 0);
                        capsule::put_varint(&mut echo, value.len() as u64);
                        echo.extend_from_slice(&[0]);
                        echo.extend_from_slice(&packet);
                        let _ = send.send_data(echo.freeze(), false);
                    }
                    _ => {}
                }
            }
        }
    });
    Some(Accepted { request: parts })
}

#[tokio::test]
async fn a_tunnel_carries_packets_in_datagram_capsules() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve(server, true, 200, Proxy::Echo));
    let tunnel = timeout(Duration::from_secs(5), dial_h2(client, config()))
        .await
        .unwrap()
        .unwrap();
    let accepted = server.await.unwrap().unwrap();
    let request = accepted.request;
    assert_eq!(request.method, Method::CONNECT);
    assert_eq!(
        request
            .extensions
            .get::<h2::ext::Protocol>()
            .map(|p| p.as_str()),
        Some("connect-ip")
    );
    assert_eq!(
        request.uri.authority().unwrap().as_str(),
        "proxy.example:8443"
    );
    assert_eq!(request.uri.path(), "/.well-known/masque/ip/*/*/");
    // Xray sorts the canonical names; the Chrome preset is the User-Agent.
    let names: Vec<&str> = request.headers.keys().map(|name| name.as_str()).collect();
    assert_eq!(names, ["capsule-protocol", "user-agent", "x-custom"]);
    assert_eq!(request.headers["capsule-protocol"], "?1");
    assert!(request.headers["user-agent"]
        .to_str()
        .unwrap()
        .contains("Chrome/"));

    assert_eq!(
        tunnel.local_addrs(),
        [LOCAL.into(), "fd00::2".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(tunnel.max_packet_size(), 65535);
    let packet = ipv4(LOCAL, REMOTE, 64, b"over http/2");
    assert_eq!(
        tunnel.write_packet(&packet).await.unwrap(),
        WriteOutcome::Sent
    );
    let echoed = timeout(Duration::from_secs(5), tunnel.read_packet())
        .await
        .unwrap()
        .unwrap();
    // The proxy swapped the addresses of what it got: one TTL less.
    assert_eq!(echoed[8], 63);
    assert_eq!(&echoed[12..16], REMOTE.octets());
    assert_eq!(&echoed[16..20], LOCAL.octets());
    assert_eq!(&echoed[28..], b"over http/2");
    // TTL 1 has nowhere to go.
    let expired = ipv4(LOCAL, REMOTE, 1, b"");
    assert_eq!(
        tunnel.write_packet(&expired).await.unwrap(),
        WriteOutcome::Dropped
    );
    tunnel.close();
    assert!(tunnel.read_packet().await.is_err());
}

#[tokio::test]
async fn reading_keeps_the_stream_window_open() {
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve(server, true, 200, Proxy::Echo));
    let tunnel = dial_h2(client, config()).await.unwrap();
    let tunnel = Arc::new(tunnel);
    // Twice the 6 MiB window comes back; it opens as the reader takes it.
    let packet = ipv4(LOCAL, REMOTE, 64, &[0x5a; 1200]);
    let count = 2 * (6 << 20) / packet.len() + 1;
    let writer = tokio::spawn({
        let tunnel = Arc::clone(&tunnel);
        async move {
            for _ in 0..count {
                tunnel.write_packet(&packet).await.unwrap();
            }
        }
    });
    for _ in 0..count {
        timeout(Duration::from_secs(10), tunnel.read_packet())
            .await
            .unwrap()
            .unwrap();
    }
    writer.await.unwrap();
}

#[tokio::test]
async fn http2_needs_extended_connect() {
    let (client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(serve(server, false, 200, Proxy::Echo));
    let error = timeout(Duration::from_secs(5), dial_h2(client, config()))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "CONNECT-IP request failed: connect-ip: failed to send request: http2: the server did not enable extended CONNECT"
    );
}

#[tokio::test]
async fn a_refusal_reports_its_status() {
    let (client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(serve(server, true, 407, Proxy::Echo));
    let error = timeout(Duration::from_secs(5), dial_h2(client, config()))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, MasqueError::Status(407)), "{error}");
}

#[tokio::test(start_paused = true)]
async fn a_spent_window_holds_writers_back_after_32_kib() {
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve(server, true, 200, Proxy::Stalled));
    let tunnel = dial_h2(client, config()).await.unwrap();
    // The proxy's stream window takes 64 KiB less what the address request
    // spent; Xray's buffer then holds 32 KiB more.
    let packet = ipv4(LOCAL, REMOTE, 64, &[0x5a; 1272]);
    let mut accepted = 0;
    while timeout(Duration::from_secs(1), tunnel.write_packet(&packet))
        .await
        .is_ok()
    {
        accepted += 1;
        assert!(accepted < 200, "nothing held the writer back");
    }
    let capsule = 1304;
    let expected: i32 = 65535 / capsule + (32 << 10) / capsule;
    assert!(
        (accepted - expected).abs() <= 2,
        "{accepted} packets went out, about {expected} expected"
    );
}

#[tokio::test(start_paused = true)]
async fn answered_pings_keep_the_connection() {
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve(server, true, 200, Proxy::Echo));
    let mut config = config();
    config.keep_alive = Some(Duration::from_secs(5));
    let tunnel = dial_h2(client, config).await.unwrap();
    // Nothing else crosses the connection: only its PINGs keep it.
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert!(!tunnel.is_closed(), "{:?}", tunnel.close_reason());
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_ping_closes_the_connection() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let answering = Arc::new(AtomicBool::new(true));
    let (server, _relay) = relay(server, Arc::clone(&answering));
    tokio::spawn(serve(server, true, 200, Proxy::Echo));
    let mut config = config();
    config.keep_alive = Some(Duration::from_secs(5));
    let tunnel = dial_h2(client, config).await.unwrap();
    // The proxy falls silent once the tunnel is up.
    answering.store(false, Ordering::Release);
    let started = tokio::time::Instant::now();
    timeout(Duration::from_secs(120), tunnel.closed())
        .await
        .unwrap();
    // Ticks a third of the period apart: a PING at the first one past 5 s
    // of silence, the connection closed at the first one 15 s after it.
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(20) && waited <= Duration::from_secs(24),
        "{waited:?}"
    );
}

/// The proxy's end of the connection behind a relay that passes nothing
/// on once `answering` is cleared, leaving the connection open and silent.
fn relay(
    io: DuplexStream,
    answering: Arc<AtomicBool>,
) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn pass(
        mut from: impl AsyncRead + Unpin,
        mut to: impl AsyncWrite + Unpin,
        answering: Arc<AtomicBool>,
    ) {
        let mut buf = vec![0; 16 << 10];
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if !answering.load(Ordering::Acquire) {
                std::future::pending::<()>().await;
            }
            if to.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
    }
    let (near, far) = tokio::io::duplex(1 << 20);
    let (io_read, io_write) = tokio::io::split(io);
    let (far_read, far_write) = tokio::io::split(far);
    let task = tokio::spawn(async move {
        tokio::join!(
            pass(io_read, far_write, Arc::clone(&answering)),
            pass(far_read, io_write, answering),
        );
    });
    (near, task)
}

/// One frame as the oracle records it.
#[derive(Debug, PartialEq)]
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: String,
}

/// The frames our client writes after its preface, through the request's
/// last header block frame, to a server that enables extended CONNECT once
/// it has the client's SETTINGS.
async fn client_frames(config: MasqueH2Config) -> Vec<Frame> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client, mut server) = tokio::io::duplex(1 << 20);
    let dial = tokio::spawn(dial_h2(client, config));
    let mut preface = [0; 24];
    server.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let mut frames = Vec::new();
    let mut sent = false;
    loop {
        let mut head = [0; 9];
        server.read_exact(&mut head).await.unwrap();
        let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let mut payload = vec![0; len];
        server.read_exact(&mut payload).await.unwrap();
        let frame = Frame {
            kind: head[3],
            flags: head[4],
            stream: u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff,
            payload: payload.iter().map(|b| format!("{b:02x}")).collect(),
        };
        let last = matches!(frame.kind, 1 | 9) && frame.flags & 4 != 0;
        if frame.kind == 4 && frame.flags & 1 == 0 && !sent {
            sent = true;
            server
                .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1])
                .await
                .unwrap();
        }
        frames.push(frame);
        if last {
            break;
        }
    }
    dial.abort();
    frames
}

#[tokio::test]
async fn the_request_is_xrays_frame_for_frame() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/masque/http2-request-vectors.json"
    ))
    .unwrap();
    // Xray acknowledges the server's SETTINGS from its read loop, before or
    // after its request: the acknowledgements are left out.
    let without_acks = |frames: Vec<Frame>| -> Vec<Frame> {
        frames
            .into_iter()
            .filter(|frame| !(frame.kind == 4 && frame.flags & 1 != 0))
            .collect()
    };
    // Xray drew its browser versions for that run; the client sends them.
    let browser = |preset: &str| vectors["userAgents"][preset].as_str().unwrap().to_owned();
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut headers: Vec<(String, String)> = case["canonical"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_owned(),
                    pair[1].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        match headers.iter_mut().find(|(name, _)| name == "User-Agent") {
            None => headers.push(("User-Agent".to_owned(), browser("chrome"))),
            Some((_, value)) if value == "firefox" => *value = browser("firefox"),
            Some(_) => {}
        }
        headers.sort();
        let host = case["host"].as_str().unwrap().to_owned();
        let config = MasqueH2Config {
            authority: crate::masque::authority(
                &host,
                case["serverName"].as_str().unwrap(),
                case["port"].as_u64().unwrap() as u16,
            ),
            request: MasqueRequest {
                host,
                path: case["path"].as_str().unwrap().to_owned(),
                headers: headers
                    .into_iter()
                    .map(|(name, value)| (name, zeroize::Zeroizing::new(value)))
                    .collect(),
            },
            keep_alive: None,
            warp: case["warp"].as_array().map(|addresses| {
                addresses
                    .iter()
                    .map(|prefix| {
                        let (addr, len) = prefix.as_str().unwrap().split_once('/').unwrap();
                        crate::masque::IpPrefix::new(addr.parse().unwrap(), len.parse().unwrap())
                    })
                    .collect()
            }),
        };
        let expected: Vec<Frame> = case["frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|frame| Frame {
                kind: frame["type"].as_u64().unwrap() as u8,
                flags: frame["flags"].as_u64().unwrap() as u8,
                stream: frame["stream"].as_u64().unwrap() as u32,
                payload: frame["payload"].as_str().unwrap().to_owned(),
            })
            .collect();
        let got = timeout(Duration::from_secs(5), client_frames(config))
            .await
            .unwrap();
        assert_eq!(without_acks(got), without_acks(expected), "{name}");
    }
}

#[test]
fn warp_authorities_take_port_443_as_xray_adds_it() {
    for (authority, want) in [
        ("cloudflareaccess.com", "cloudflareaccess.com:443"),
        ("cloudflareaccess.com:8443", "cloudflareaccess.com:8443"),
        ("[2001:db8::1]", "[2001:db8::1]:443"),
        ("[2001:db8::1]:8443", "[2001:db8::1]:8443"),
        ("2001:db8::1", "[2001:db8::1]:443"),
        ("192.0.2.1", "192.0.2.1:443"),
    ] {
        assert_eq!(warp_authority(authority), want, "{authority}");
    }
}
