//! RAW's `http` header obfuscation on the client, against the bytes Xray-core's
//! `transport/internet/headers/http` server reads and writes.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::stream::{RawHttpHeaderConfig, RawHttpHeaderStream, TransportLayer};
use xray_transport::{ConnectorConfig, TransportDialer};

fn config() -> Arc<RawHttpHeaderConfig> {
    Arc::new(RawHttpHeaderConfig {
        method: "GET".to_owned(),
        version: "1.1".to_owned(),
        paths: vec!["/video".to_owned()],
        headers: vec![
            ("Host".to_owned(), vec!["cdn.example".to_owned()]),
            ("Connection".to_owned(), vec!["keep-alive".to_owned()]),
        ],
    })
}

const REQUEST_HEAD: &[u8] =
    b"GET /video HTTP/1.1\r\nHost: cdn.example\r\nConnection: keep-alive\r\n\r\n";
const RESPONSE_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: video/mpeg\r\nTransfer-Encoding: chunked\r\n\r\n";

#[tokio::test]
async fn the_first_write_follows_a_request_head_and_the_response_head_is_dropped() {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let mut stream = RawHttpHeaderStream::client(Box::new(client), &config());

    stream.write_all(b"first").await.unwrap();
    stream.write_all(b"second").await.unwrap();
    stream.flush().await.unwrap();
    let mut sent = vec![0; REQUEST_HEAD.len() + 11];
    server.read_exact(&mut sent).await.unwrap();
    assert_eq!(&sent[..REQUEST_HEAD.len()], REQUEST_HEAD);
    assert_eq!(&sent[REQUEST_HEAD.len()..], b"firstsecond");

    // The head arrives in pieces, split inside its end, and the first bytes
    // after it come with its last piece.
    server.write_all(&RESPONSE_HEAD[..20]).await.unwrap();
    server
        .write_all(&RESPONSE_HEAD[20..RESPONSE_HEAD.len() - 2])
        .await
        .unwrap();
    let mut tail = RESPONSE_HEAD[RESPONSE_HEAD.len() - 2..].to_vec();
    tail.extend_from_slice(b"reply");
    server.write_all(&tail).await.unwrap();
    server.write_all(b" more").await.unwrap();
    drop(server);

    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"reply more");
}

#[tokio::test]
async fn a_head_that_never_ends_or_a_close_inside_it_fails_the_read() {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let mut stream = RawHttpHeaderStream::client(Box::new(client), &config());
    server.write_all(&vec![b'a'; 9000]).await.unwrap();
    let error = stream.read(&mut [0; 16]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let (client, mut server) = tokio::io::duplex(1 << 16);
    let mut stream = RawHttpHeaderStream::client(Box::new(client), &config());
    server.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
    drop(server);
    let error = stream.read(&mut [0; 16]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn each_request_draws_a_path_and_header_values_from_the_lists() {
    let config = RawHttpHeaderConfig {
        method: "POST".to_owned(),
        version: "1.0".to_owned(),
        paths: vec!["/a".to_owned(), "/b".to_owned()],
        headers: vec![
            ("Empty".to_owned(), Vec::new()),
            (
                "X-Pick".to_owned(),
                vec!["one".to_owned(), "two".to_owned()],
            ),
        ],
    };
    let mut paths = std::collections::HashSet::new();
    for _ in 0..64 {
        let head = String::from_utf8(config.request_head()).unwrap();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap();
        assert!(request_line.starts_with("POST /") && request_line.ends_with(" HTTP/1.0"));
        paths.insert(request_line.to_owned());
        assert_eq!(lines.next(), Some("Empty: "));
        assert!(matches!(lines.next(), Some("X-Pick: one" | "X-Pick: two")));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), Some(""));
    }
    assert_eq!(paths.len(), 2, "both paths are drawn");
}

#[test]
fn the_default_headers_are_xrays_chrome_on_windows() {
    let headers = RawHttpHeaderConfig::default_headers();
    let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Host",
            "User-Agent",
            "Sec-CH-UA",
            "Sec-CH-UA-Mobile",
            "Sec-CH-UA-Platform",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Accept-Encoding",
            "Connection",
            "Pragma",
        ]
    );
    assert_eq!(headers[0].1, ["www.baidu.com", "www.bing.com"]);
    assert!(headers[1].1[0].contains("Chrome/"), "{:?}", headers[1].1);
    assert!(
        headers[2].1[0].contains("\"Google Chrome\""),
        "{:?}",
        headers[2].1
    );
    assert_eq!(headers[9].1, ["gzip, deflate"]);
}

#[tokio::test]
async fn the_dialer_wraps_a_raw_connection_in_the_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut sent = vec![0; REQUEST_HEAD.len() + 4];
        socket.read_exact(&mut sent).await.unwrap();
        let mut reply = RESPONSE_HEAD.to_vec();
        reply.extend_from_slice(b"pong");
        socket.write_all(&reply).await.unwrap();
        sent
    });

    let dialer = TransportDialer::system().unwrap();
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
    let mut stream = dialer
        .connect_stream(
            &ConnectorConfig::Tcp,
            &TransportLayer::RawHttpHeader(config()),
            &target,
            &[addr],
            None,
        )
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");

    let sent = server.await.unwrap();
    assert_eq!(&sent[..REQUEST_HEAD.len()], REQUEST_HEAD);
    assert_eq!(&sent[REQUEST_HEAD.len()..], b"ping");
}
