use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_proxy::inbound::{
    negotiate_socks5_no_auth, parse_http_connect, parse_socks5_connect, parse_socks5_request,
    write_socks5_failure, write_socks5_success, HttpParseError, SocksParseError,
};
use xray_routing::{Network, TargetAddr};

#[tokio::test]
async fn socks5_negotiate_no_auth_writes_method_selection() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5_no_auth(server).await });

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0]);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn socks5_negotiate_rejects_when_no_auth_is_absent() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5_no_auth(server).await });

    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0xff]);
    assert_eq!(
        server_task.await.unwrap(),
        Err(SocksParseError::NoAcceptableMethods)
    );
}

#[tokio::test]
async fn socks5_request_parser_reads_connect_after_greeting() {
    let bytes = [
        5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
        0xbb,
    ];

    let target = parse_socks5_request(&bytes[..]).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn socks5_reply_writers_emit_ipv4_success_and_failure() {
    let mut output = Vec::new();

    write_socks5_success(&mut output).await.unwrap();
    write_socks5_failure(&mut output).await.unwrap();

    assert_eq!(
        output,
        vec![
            5, 0, 0, 1, 0, 0, 0, 0, 0, 0, // success
            5, 1, 0, 1, 0, 0, 0, 0, 0, 0, // general failure
        ]
    );
}

#[tokio::test]
async fn parses_socks5_connect_domain_target() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { parse_socks5_connect(server).await });

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);

    client
        .write_all(&[
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ])
        .await
        .unwrap();

    let target = server_task.await.unwrap().unwrap();

    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn parses_socks5_request_ipv4_target() {
    let bytes = [0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x00, 0x50];

    let target = parse_socks5_request(Cursor::new(bytes)).await.unwrap();

    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 80);
    assert_eq!(
        target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
}

#[tokio::test]
async fn parses_socks5_request_ipv6_target() {
    let bytes = [
        0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xbb,
    ];

    let target = parse_socks5_request(Cursor::new(bytes)).await.unwrap();

    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 443);
    assert_eq!(
        target.addr,
        TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
    );
}

#[tokio::test]
async fn rejects_socks5_unsupported_version() {
    let bytes = [0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::UnsupportedVersion(0x04));
}

#[tokio::test]
async fn rejects_socks5_unsupported_command() {
    let bytes = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::UnsupportedCommand(0x02));
}

#[tokio::test]
async fn rejects_socks5_nonzero_reserved_byte() {
    let bytes = [
        0x05, 0x01, 0x01, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', 0x01, 0xbb,
    ];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::InvalidReserved(0x01));
}

#[tokio::test]
async fn rejects_socks5_unsupported_address_type() {
    let bytes = [0x05, 0x01, 0x00, 0x05];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::UnsupportedAddressType(0x05));
}

#[tokio::test]
async fn rejects_socks5_empty_domain() {
    let bytes = [0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xbb];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::InvalidDomain);
}

#[tokio::test]
async fn rejects_socks5_invalid_utf8_domain() {
    let bytes = [0x05, 0x01, 0x00, 0x03, 0x01, 0xff, 0x01, 0xbb];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::InvalidDomain);
}

#[tokio::test]
async fn rejects_socks5_truncated_input_as_io() {
    let bytes = [0x05, 0x01, 0x00, 0x01, 127, 0, 0];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::Io);
}

#[tokio::test]
async fn parses_http_connect_domain_target() {
    let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn parses_http_connect_ipv4_literal_target() {
    let raw = b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 8080);
    assert_eq!(
        target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    );
}

#[tokio::test]
async fn parses_http_connect_bracketed_ipv6_literal_target() {
    let raw = b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[tokio::test]
async fn rejects_http_non_connect_method() {
    let raw = b"GET example.com:443 HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::NotConnect);
}

#[tokio::test]
async fn rejects_http_missing_port() {
    let raw = b"CONNECT example.com HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::MissingPort);
}

#[tokio::test]
async fn rejects_http_invalid_port() {
    let raw = b"CONNECT example.com:https HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::InvalidPort);
}

#[tokio::test]
async fn rejects_http_overlong_request_line() {
    let raw = format!("CONNECT {}:443 HTTP/1.1\r\n\r\n", "a".repeat(8192));

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::LineTooLong);
}

#[tokio::test]
async fn rejects_http_empty_host() {
    let raw = b"CONNECT :443 HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::InvalidAuthority);
}

#[tokio::test]
async fn rejects_http_port_zero() {
    let raw = b"CONNECT example.com:0 HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::InvalidPort);
}
