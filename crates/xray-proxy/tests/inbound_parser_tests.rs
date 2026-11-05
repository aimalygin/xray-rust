use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_proxy::inbound::{
    decode_http_basic_credentials, encode_socks5_udp_datagram, negotiate_socks5,
    negotiate_socks5_no_auth, parse_http_connect, parse_http_connect_request, parse_socks4_connect,
    parse_socks5_connect, parse_socks5_request, parse_socks5_request_message,
    parse_socks5_udp_datagram, read_socks5_command, read_socks5_target,
    write_socks5_command_not_supported, write_socks5_failure, write_socks5_success,
    write_socks5_success_with_bind, HttpInboundAccounts, HttpParseError, SocksAccount,
    SocksCommand, SocksInboundAuth, SocksParseError, MAX_SOCKS_CREDENTIAL_LENGTH,
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

fn password_auth() -> SocksInboundAuth {
    SocksInboundAuth::Password(vec![
        SocksAccount::new(b"first-user", b"first-pass").unwrap(),
        SocksAccount::new(b"synthetic-user", b"synthetic-pass").unwrap(),
    ])
}

fn password_request(user: &[u8], pass: &[u8]) -> Vec<u8> {
    let mut request = vec![1, u8::try_from(user.len()).unwrap()];
    request.extend_from_slice(user);
    request.push(u8::try_from(pass.len()).unwrap());
    request.extend_from_slice(pass);
    request
}

#[tokio::test]
async fn socks5_password_auth_accepts_any_configured_account() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

    client.write_all(&[5, 2, 0, 2]).await.unwrap();
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 2]);

    client
        .write_all(&password_request(b"synthetic-user", b"synthetic-pass"))
        .await
        .unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).await.unwrap();

    assert_eq!(status, [1, 0]);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn socks5_password_auth_rejects_wrong_credentials() {
    let attempts: [(&[u8], &[u8]); 3] = [
        (b"synthetic-user", b"wrong-pass"),
        (b"wrong-user", b"synthetic-pass"),
        (b"first-user", b"synthetic-pass"),
    ];
    for (user, pass) in attempts {
        let (mut client, server) = tokio::io::duplex(64);
        let server_task =
            tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selection = [0; 2];
        client.read_exact(&mut selection).await.unwrap();
        client
            .write_all(&password_request(user, pass))
            .await
            .unwrap();
        let mut status = [0; 2];
        client.read_exact(&mut status).await.unwrap();

        // Xray-core answers a failed login with 0xFF.
        assert_eq!(status, [1, 0xff]);
        assert_eq!(
            server_task.await.unwrap(),
            Err(SocksParseError::AuthenticationFailed)
        );
    }
}

#[tokio::test]
async fn socks5_password_auth_never_selects_no_auth() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0xff]);
    assert_eq!(
        server_task.await.unwrap(),
        Err(SocksParseError::NoAcceptableMethods)
    );
}

#[tokio::test]
async fn socks5_password_auth_ignores_the_subnegotiation_version() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await.unwrap();
    // Xray-core does not check the version byte.
    let mut request = password_request(b"synthetic-user", b"synthetic-pass");
    request[0] = 5;
    client.write_all(&request).await.unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).await.unwrap();

    assert_eq!(status, [1, 0]);
    assert!(server_task.await.unwrap().is_ok());
}

#[tokio::test]
async fn socks5_password_auth_fails_on_truncated_credentials() {
    let mut stream = CountingIo::new([5, 1, 2, 1, 14, b's', b'y', b'n']);

    assert_eq!(
        negotiate_socks5(&mut stream, &password_auth()).await,
        Err(SocksParseError::Io)
    );
    assert_eq!(stream.output, [5, 2]);
}

#[test]
fn socks_accounts_enforce_rfc1929_lengths_and_redact_debug() {
    let longest = vec![b'a'; MAX_SOCKS_CREDENTIAL_LENGTH];
    let too_long = vec![b'a'; MAX_SOCKS_CREDENTIAL_LENGTH + 1];
    assert!(SocksAccount::new(&longest, &longest).is_some());
    // Xray-core keeps empty credentials, which the wire can carry.
    assert!(SocksAccount::new(b"", b"").is_some());
    assert!(SocksAccount::new(&too_long, b"synthetic-pass").is_none());
    assert!(SocksAccount::new(b"synthetic-user", &too_long).is_none());

    let debug = format!("{:?}", password_auth());
    assert!(!debug.contains("synthetic"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
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
async fn socks5_request_parser_reads_ipv4_request_with_three_io_reads() {
    let mut reader = CountingIo::new([5, 1, 0, 1, 192, 0, 2, 1, 0, 80]);

    let request = parse_socks5_request_message(&mut reader).await.unwrap();

    assert_eq!(request.command, SocksCommand::Connect);
    assert_eq!(request.target.port, 80);
    assert_eq!(
        request.target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    // The command is read before the address, so it can be refused first.
    assert_eq!(reader.read_calls, 3);
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
    write_socks5_command_not_supported(&mut output)
        .await
        .unwrap();

    assert_eq!(
        output,
        vec![
            5, 0, 0, 1, 0, 0, 0, 0, 0, 0, // success
            5, 1, 0, 1, 0, 0, 0, 0, 0, 0, // general failure
            5, 7, 0, 1, 0, 0, 0, 0, 0, 0, // command not supported, as Xray-core sends it
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
async fn rejects_socks5_unsupported_command() {
    let bytes = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::UnsupportedCommand(0x02));
}

#[tokio::test]
async fn socks5_requests_ignore_their_version_and_reserved_bytes() {
    // Xray-core checks only the command byte.
    let bytes = [
        0x04, 0x01, 0x01, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', 0x01, 0xbb,
    ];

    let target = parse_socks5_request(Cursor::new(bytes)).await.unwrap();

    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
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
async fn keeps_http_port_zero_to_fail_when_dialed() {
    // As in Xray-core, which answers it and then fails to dial it.
    let raw = b"CONNECT example.com:0 HTTP/1.1\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 0);
}

/// A SOCKS 4 request after its version byte.
fn socks4_body(command: u8, port: u16, ip: [u8; 4], user: &[u8], domain: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![command];
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&ip);
    body.extend_from_slice(user);
    body.push(0);
    if let Some(domain) = domain {
        body.extend_from_slice(domain);
        body.push(0);
    }
    body
}

#[tokio::test]
async fn parses_socks4_and_socks4a_connect_like_xray() {
    let target = |body: Vec<u8>| async move { parse_socks4_connect(Cursor::new(body)).await };
    assert_eq!(
        target(socks4_body(1, 443, [192, 0, 2, 7], b"user-id", None)).await,
        Ok(Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
            443,
            Network::Tcp
        ))
    );
    // Any address with a zero first byte announces a 4a domain.
    assert_eq!(
        target(socks4_body(1, 80, [0, 0, 0, 9], b"", Some(b"example.test"))).await,
        Ok(Target::new(
            TargetAddr::Domain("example.test".to_owned()),
            80,
            Network::Tcp
        ))
    );
    // Go's ParseAddress turns a literal into an IP target.
    assert_eq!(
        target(socks4_body(1, 80, [0, 0, 0, 1], b"", Some(b"2001:db8::1"))).await,
        Ok(Target::new(
            TargetAddr::Ip("2001:db8::1".parse().unwrap()),
            80,
            Network::Tcp
        ))
    );
    for (body, error) in [
        (
            socks4_body(2, 80, [192, 0, 2, 7], b"", None),
            SocksParseError::UnsupportedCommand(2),
        ),
        (
            socks4_body(1, 80, [0, 0, 0, 1], b"", Some(b"")),
            SocksParseError::InvalidDomain,
        ),
        (
            socks4_body(1, 80, [0, 0, 0, 1], b"", Some(b"\xff\xfe")),
            SocksParseError::InvalidDomain,
        ),
        (
            socks4_body(1, 80, [192, 0, 2, 7], &[b'u'; 256], None),
            SocksParseError::InvalidDomain,
        ),
        (vec![1, 0, 80, 192, 0, 2, 7, b'u'], SocksParseError::Io),
    ] {
        assert_eq!(target(body.clone()).await, Err(error), "{body:?}");
    }
    assert!(
        target(socks4_body(1, 80, [192, 0, 2, 7], &[b'u'; 255], None))
            .await
            .is_ok()
    );
}

#[test]
fn decodes_http_basic_credentials_like_go() {
    let decoded = |value: &[u8]| {
        decode_http_basic_credentials(value).map(|(user, pass)| (user.to_vec(), pass.to_vec()))
    };
    assert_eq!(
        decoded(b"Basic dXNlcjpwYXNz"),
        Some((b"user".to_vec(), b"pass".to_vec()))
    );
    // Split at the first colon; empty halves are Go's result too.
    assert_eq!(
        decoded(b"Basic dXNlcjpwOmFzcw=="),
        Some((b"user".to_vec(), b"p:ass".to_vec()))
    );
    assert_eq!(decoded(b"Basic Og=="), Some((Vec::new(), Vec::new())));
    for refused in [
        &b"basic dXNlcjpwYXNz"[..],
        b"Bearer dXNlcjpwYXNz",
        b"Basic dXNlcjpwYXNz=",
        b"Basic dXNlcnBhc3M=",
        b"Basic ",
    ] {
        assert_eq!(
            decoded(refused),
            None,
            "{:?}",
            String::from_utf8_lossy(refused)
        );
    }
}

#[tokio::test]
async fn http_connect_keeps_the_first_proxy_authorization() {
    // Go's `Header.Get` returns a header's first value.
    let request = parse_http_connect_request(Cursor::new(
        b"CONNECT example.test:443 HTTP/1.1\r\nProxy-Authorization:\tBasic dXNlcjpwYXNz \r\nPROXY-AUTHORIZATION: Basic Zmlyc3Q6Zmlyc3Q=\r\nHost: example.test:443\r\n\r\n".to_vec(),
    ))
    .await
    .unwrap();
    assert_eq!(
        request.proxy_authorization.as_deref().map(Vec::as_slice),
        Some(&b"Basic dXNlcjpwYXNz"[..])
    );
    let auth = SocksInboundAuth::Password(vec![SocksAccount::new(b"user", b"pass").unwrap()]);
    let accounts = HttpInboundAccounts::from(&auth);
    let user = accounts
        .basic_user(request.proxy_authorization.as_deref().map(Vec::as_slice))
        .expect("the first credentials are admitted")
        .expect("an account names the user");
    assert_eq!(user.as_str(), "user");
    assert!(accounts
        .basic_user(Some(b"Basic Zmlyc3Q6Zmlyc3Q="))
        .is_none());
    assert!(accounts.basic_user(None).is_none());
    let none = HttpInboundAccounts::from(&SocksInboundAuth::NoAuth);
    assert!(matches!(none.basic_user(None), Some(None)));

    let anonymous = parse_http_connect_request(Cursor::new(
        b"CONNECT example.test:443 HTTP/1.1\r\n\r\n".to_vec(),
    ))
    .await
    .unwrap();
    assert_eq!(anonymous.proxy_authorization, None);
}

#[test]
fn http_accounts_keep_one_password_per_name() {
    // As Xray-core's accounts map: the later password replaces the earlier.
    let mut accounts = HttpInboundAccounts::default();
    accounts.insert(b"a", b"old");
    accounts.insert(b"a", b"new");
    accounts.insert(b"", b"");
    assert!(accounts.basic_user(Some(b"Basic YTpvbGQ=")).is_none());
    assert!(accounts.basic_user(Some(b"Basic YTpuZXc=")).is_some());
    // Empty names and passwords are accounts too.
    assert!(accounts.basic_user(Some(b"Basic Og==")).is_some());
    assert_eq!(
        format!("{accounts:?}"),
        "HttpInboundAccounts { accounts: 2 }"
    );
}

#[tokio::test]
async fn http_requests_read_as_go_reads_them() {
    let target = |raw: &'static [u8]| async move {
        parse_http_connect_request(Cursor::new(raw.to_vec()))
            .await
            .map(|request| request.target)
    };
    let domain = |name: &str, port| {
        Ok(Some(Target::new(
            TargetAddr::Domain(name.to_owned()),
            port,
            Network::Tcp,
        )))
    };
    // A missing or empty port is port 80, a long one is cut to 16 bits.
    assert_eq!(
        target(b"CONNECT example.com HTTP/1.1\r\n\r\n").await,
        domain("example.com", 80)
    );
    assert_eq!(
        target(b"CONNECT example.com: HTTP/1.1\r\n\r\n").await,
        domain("example.com", 80)
    );
    assert_eq!(
        target(b"CONNECT [::1] HTTP/1.1\r\n\r\n").await,
        Ok(Some(Target::new(
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            80,
            Network::Tcp
        )))
    );
    assert_eq!(
        target(b"CONNECT example.com:70000 HTTP/1.1\r\n\r\n").await,
        domain("example.com", 4464)
    );
    // Versions Go reads, and headers written with `\n` alone.
    assert_eq!(
        target(b"CONNECT example.com:443 HTTP/2.0\r\n\r\n").await,
        domain("example.com", 443)
    );
    assert_eq!(
        target(b"CONNECT example.com:443 HTTP/1.1\nHost: x\n\n").await,
        domain("example.com", 443)
    );
    // A name with a space before its colon is kept, uncanonicalized.
    assert_eq!(
        target(b"CONNECT example.com:443 HTTP/1.1\r\nHost : x\r\n\r\n").await,
        domain("example.com", 443)
    );
    // Another method has no target here.
    assert_eq!(
        target(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await,
        Ok(None)
    );
    assert_eq!(
        target(b"connect example.com:443 HTTP/1.1\r\n\r\n").await,
        Ok(None)
    );

    for (raw, error) in [
        (
            &b"CONNECT example.com:443\r\n\r\n"[..],
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/10.0\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1 x\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT  example.com:443 HTTP/1.1\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (b"\x01\x02garbage\r\n\r\n", HttpParseError::Malformed),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\nNoColon\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\n: x\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\nBad\x01Name: x\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\n folded\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:+80 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidPort,
        ),
        (
            b"CONNECT example.com:99999999999999999999 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidPort,
        ),
        (
            b"CONNECT ::1:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
        (
            b"CONNECT exa%41mple.com:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
        (
            b"CONNECT exa[mple.com:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
        (
            b"CONNECT [::1]x:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
    ] {
        assert_eq!(
            parse_http_connect_request(Cursor::new(raw.to_vec())).await,
            Err(error),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

/// The target of a SOCKS5 `CONNECT` to the domain `name`.
async fn socks5_domain_target(name: &[u8]) -> Result<Target, SocksParseError> {
    let mut request = vec![5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
    request.extend_from_slice(name);
    request.extend_from_slice(&443_u16.to_be_bytes());
    parse_socks5_request(&request[..]).await
}

fn ip(text: &str) -> Result<TargetAddr, SocksParseError> {
    Ok(TargetAddr::Ip(text.parse().unwrap()))
}

fn domain(text: &str) -> Result<TargetAddr, SocksParseError> {
    Ok(TargetAddr::Domain(text.to_owned()))
}

#[tokio::test]
async fn socks5_domains_read_as_xray_core_reads_them() {
    for (name, expected) in [
        // A name that starts with a digit or `[` and is an IP literal to Go's
        // net.ParseAddress is that IP.
        (b"192.0.2.7".as_slice(), ip("192.0.2.7")),
        (b"[2001:db8::1]", ip("2001:db8::1")),
        (b"[192.0.2.7]", ip("192.0.2.7")),
        (b"2001:db8::1", ip("2001:db8::1")),
        (b"0::ffff:192.0.2.7", ip("192.0.2.7")),
        (b"192.0.2.7 ", ip("192.0.2.7")),
        (b"192.0.2.7\t\n", ip("192.0.2.7")),
        // Other names keep to letters, digits, `-`, `.` and `_`.
        (b"1password.example", domain("1password.example")),
        (b"Under_Score-1.example.", domain("Under_Score-1.example.")),
        (b"192.0.2.256", domain("192.0.2.256")),
        (b"::1", Err(SocksParseError::InvalidDomain)),
        (b" 192.0.2.7", Err(SocksParseError::InvalidDomain)),
        (b"[example.com]", Err(SocksParseError::InvalidDomain)),
        (b"[]", Err(SocksParseError::InvalidDomain)),
        (b"exa mple.com", Err(SocksParseError::InvalidDomain)),
        (b"example.com:443", Err(SocksParseError::InvalidDomain)),
        (b"a/b", Err(SocksParseError::InvalidDomain)),
        (
            "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}".as_bytes(),
            Err(SocksParseError::InvalidDomain),
        ),
        (b"\xff.example", Err(SocksParseError::InvalidDomain)),
    ] {
        let target = socks5_domain_target(name).await.map(|target| target.addr);
        assert_eq!(target, expected, "{}", String::from_utf8_lossy(name));
    }
}

#[tokio::test]
async fn socks5_ipv4_mapped_addresses_read_as_ipv4() {
    let mut request = vec![5, 1, 0, 4];
    request.extend_from_slice(&"::ffff:192.0.2.7".parse::<Ipv6Addr>().unwrap().octets());
    request.extend_from_slice(&80_u16.to_be_bytes());
    let target = parse_socks5_request(&request[..]).await.unwrap();
    assert_eq!(Ok(target.addr), ip("192.0.2.7"));

    let mut datagram = vec![0, 0, 0, 4];
    datagram.extend_from_slice(&"::ffff:192.0.2.7".parse::<Ipv6Addr>().unwrap().octets());
    datagram.extend_from_slice(&53_u16.to_be_bytes());
    datagram.extend_from_slice(b"payload");
    let decoded = parse_socks5_udp_datagram(&datagram).unwrap();
    assert_eq!(Ok(decoded.target.addr), ip("192.0.2.7"));
}

#[tokio::test]
async fn socks5_tor_resolve_commands_read_as_connect() {
    for command in [0xf0, 0xf1] {
        let bytes = [5, command, 0, 1, 192, 0, 2, 7, 0, 80];
        let request = parse_socks5_request_message(&bytes[..]).await.unwrap();
        assert_eq!(request.command, SocksCommand::Connect);
        assert_eq!(request.target.network, Network::Tcp);
    }
}

#[tokio::test]
async fn socks5_commands_are_refused_before_their_address() {
    // BIND and unknown commands fail on the three bytes before the address.
    for command in [2, 4, 0xff] {
        let mut reader = CountingIo::new([5, command, 0]);
        assert_eq!(
            read_socks5_command(&mut reader).await,
            Err(SocksParseError::UnsupportedCommand(command))
        );
    }
    let mut reader = CountingIo::new([5, 3, 0]);
    assert_eq!(
        read_socks5_command(&mut reader).await,
        Ok(SocksCommand::UdpAssociate)
    );
    let mut reader = CountingIo::new([1, 192, 0, 2, 7, 0, 53]);
    let target = read_socks5_target(&mut reader, SocksCommand::UdpAssociate)
        .await
        .unwrap();
    assert_eq!(target.network, Network::Udp);
}

#[test]
fn socks5_udp_datagrams_read_as_xray_core_reads_them() {
    let datagram = |head: [u8; 3], name: &[u8]| {
        let mut datagram = head.to_vec();
        datagram.push(3);
        datagram.push(u8::try_from(name.len()).unwrap());
        datagram.extend_from_slice(name);
        datagram.extend_from_slice(&53_u16.to_be_bytes());
        datagram.extend_from_slice(b"payload");
        parse_socks5_udp_datagram(&datagram).map(|decoded| decoded.target.addr)
    };
    // The reserved bytes are not checked; a fragment is refused.
    assert_eq!(
        datagram([0xff, 0xff, 0], b"example.com"),
        domain("example.com")
    );
    assert_eq!(
        datagram([0, 0, 1], b"example.com"),
        Err(SocksParseError::UnsupportedUdpFragment)
    );
    assert_eq!(datagram([0, 0, 0], b"192.0.2.7"), ip("192.0.2.7"));
    assert_eq!(
        datagram([0, 0, 0], b"exa mple.com"),
        Err(SocksParseError::InvalidDomain)
    );
}

#[tokio::test]
async fn socks4a_domains_read_through_go_parse_address() {
    let socks4a = |name: &[u8]| {
        let mut body = vec![1, 0, 80, 0, 0, 0, 1, 0];
        body.extend_from_slice(name);
        body.push(0);
        body
    };
    for (name, expected) in [
        (b"[2001:db8::1]".as_slice(), ip("2001:db8::1")),
        (b"::ffff:192.0.2.7", ip("192.0.2.7")),
        (b" 192.0.2.7 ", ip("192.0.2.7")),
        // Unlike SOCKS5, the name is not checked, only trimmed.
        (b" exa mple.com ", domain("exa mple.com")),
        (b"[example.com]", domain("example.com")),
        (b" ", Err(SocksParseError::InvalidDomain)),
    ] {
        let target = parse_socks4_connect(&socks4a(name)[..])
            .await
            .map(|target| target.addr);
        assert_eq!(target, expected, "{}", String::from_utf8_lossy(name));
    }
}
