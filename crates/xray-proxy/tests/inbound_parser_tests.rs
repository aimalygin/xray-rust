use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_proxy::inbound::{
    encode_socks5_udp_datagram, negotiate_socks5_no_auth, parse_http_connect, parse_socks5_connect,
    parse_socks5_request, parse_socks5_request_message, parse_socks5_udp_datagram,
    write_socks5_failure, write_socks5_success, write_socks5_success_with_bind, HttpParseError,
    SocksCommand, SocksParseError,
};
use xray_routing::{Network, Target, TargetAddr};

#[derive(Debug)]
struct CountingIo {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    read_calls: usize,
    write_calls: usize,
}

impl CountingIo {
    fn new(input: impl Into<Vec<u8>>) -> Self {
        Self {
            input: Cursor::new(input.into()),
            output: Vec::new(),
            read_calls: 0,
            write_calls: 0,
        }
    }
}

impl AsyncRead for CountingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_calls += 1;
        let source = self.input.get_ref();
        let start = self.input.position() as usize;
        if start >= source.len() {
            return Poll::Ready(Ok(()));
        }

        let len = buf.remaining().min(source.len() - start);
        buf.put_slice(&source[start..start + len]);
        self.input.set_position((start + len) as u64);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CountingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_calls += 1;
        self.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

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
async fn socks5_negotiate_no_auth_reads_greeting_with_two_io_reads() {
    let mut stream = CountingIo::new([5, 2, 2, 0]);

    negotiate_socks5_no_auth(&mut stream).await.unwrap();

    assert_eq!(stream.read_calls, 2);
    assert_eq!(stream.write_calls, 1);
    assert_eq!(stream.output, [5, 0]);
}

#[tokio::test]
async fn socks5_request_parser_reads_ipv4_request_with_two_io_reads() {
    let mut reader = CountingIo::new([5, 1, 0, 1, 192, 0, 2, 1, 0, 80]);

    let request = parse_socks5_request_message(&mut reader).await.unwrap();

    assert_eq!(request.command, SocksCommand::Connect);
    assert_eq!(request.target.port, 80);
    assert_eq!(
        request.target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    assert_eq!(reader.read_calls, 2);
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
async fn socks5_request_parser_reads_udp_associate_command() {
    let bytes = [5, 3, 0, 1, 0, 0, 0, 0, 0, 0];

    let request = parse_socks5_request_message(&bytes[..]).await.unwrap();

    assert_eq!(request.command, SocksCommand::UdpAssociate);
    assert_eq!(request.target.network, Network::Udp);
    assert_eq!(request.target.port, 0);
    assert_eq!(
        request.target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    );
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
async fn socks5_success_writer_can_emit_bound_udp_address() {
    let mut output = Vec::new();
    let bind = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 53000));

    write_socks5_success_with_bind(&mut output, bind)
        .await
        .unwrap();

    assert_eq!(output, vec![5, 0, 0, 1, 127, 0, 0, 1, 0xcf, 0x08]);
}

#[test]
fn socks5_udp_datagram_round_trips_ipv4_target() {
    let target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        5353,
        Network::Udp,
    );

    let encoded = encode_socks5_udp_datagram(&target, b"dns-ish").unwrap();
    let decoded = parse_socks5_udp_datagram(&encoded).unwrap();

    assert_eq!(decoded.target, target);
    assert_eq!(&decoded.payload[..], b"dns-ish");
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
async fn parses_http_connect_consumes_headers_before_payload() {
    let mut input = Cursor::new(
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\npayload".to_vec(),
    );

    let target = parse_http_connect(&mut input).await.unwrap();
    let mut remaining = Vec::new();
    input.read_to_end(&mut remaining).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
    assert_eq!(remaining, b"payload");
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
