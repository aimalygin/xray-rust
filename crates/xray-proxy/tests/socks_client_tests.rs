use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_proxy::inbound::{
    negotiate_socks5, parse_socks5_request_message, write_socks5_success, SocksAccount,
    SocksCommand, SocksInboundAuth, SocksParseError,
};
use xray_proxy::outbound::{socks5_connect, SocksClientError};
use xray_routing::{Network, Target, TargetAddr};

const USER: &[u8] = b"synthetic-user";
const PASS: &[u8] = b"synthetic-pass";
const PAYLOAD: &[u8] = b"tunnel-bytes";
const SUCCESS_V4: [u8; 10] = [5, 0, 0, 1, 198, 51, 100, 1, 0x1f, 0x90];

/// Replays scripted server bytes and records what the client writes.
#[derive(Debug)]
struct ScriptedIo {
    input: Vec<u8>,
    position: usize,
    output: Vec<u8>,
    write_calls: usize,
}

impl ScriptedIo {
    fn new(input: impl Into<Vec<u8>>) -> Self {
        Self {
            input: input.into(),
            position: 0,
            output: Vec::new(),
            write_calls: 0,
        }
    }

    fn unread(&self) -> &[u8] {
        &self.input[self.position..]
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buf.remaining().min(self.unread().len());
        let start = self.position;
        buf.put_slice(&self.input[start..start + len]);
        self.position += len;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedIo {
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

fn account() -> SocksAccount {
    SocksAccount::new(USER, PASS).unwrap()
}

fn tcp(addr: TargetAddr, port: u16) -> Target {
    Target::new(addr, port, Network::Tcp)
}

fn ipv4_target() -> Target {
    tcp(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        443,
    )
}

fn ipv6_target() -> Target {
    tcp(
        TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10,
        ))),
        8443,
    )
}

fn domain_target() -> Target {
    tcp(TargetAddr::Domain("example.com".to_owned()), 80)
}

/// Each target with its expected `CONNECT` request bytes.
fn targets() -> Vec<(Target, Vec<u8>)> {
    let mut ipv6 = vec![5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8];
    ipv6.extend_from_slice(&[0; 11]);
    ipv6.extend_from_slice(&[0x10, 0x20, 0xfb]);
    let mut domain = vec![5, 1, 0, 3, 11];
    domain.extend_from_slice(b"example.com");
    domain.extend_from_slice(&[0, 80]);
    vec![
        (ipv4_target(), vec![5, 1, 0, 1, 192, 0, 2, 10, 0x01, 0xbb]),
        (ipv6_target(), ipv6),
        (domain_target(), domain),
    ]
}

fn password_message() -> Vec<u8> {
    [&[1, 14][..], USER, &[14], PASS].concat()
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[tokio::test]
async fn no_auth_connects_to_each_target_type() {
    for (target, request) in targets() {
        let mut stream = ScriptedIo::new(concat(&[&[5, 0], &SUCCESS_V4]));

        socks5_connect(&mut stream, None, &target).await.unwrap();

        assert_eq!(stream.output, concat(&[&[5, 1, 0], &request]));
        assert_eq!(stream.write_calls, 2);
        assert!(stream.unread().is_empty());
    }
}

#[tokio::test]
async fn password_auth_connects_to_each_target_type() {
    let account = account();
    for (target, request) in targets() {
        let mut stream = ScriptedIo::new(concat(&[&[5, 2], &[1, 0], &SUCCESS_V4]));

        socks5_connect(&mut stream, Some(&account), &target)
            .await
            .unwrap();

        assert_eq!(
            stream.output,
            concat(&[&[5, 1, 2], &password_message(), &request])
        );
        // Greeting, the whole RFC 1929 message, and the request.
        assert_eq!(stream.write_calls, 3);
        assert!(stream.unread().is_empty());
    }
}

#[tokio::test]
async fn ipv4_mapped_ipv6_target_is_sent_as_ipv4() {
    let target = tcp(
        TargetAddr::Ip(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped())),
        443,
    );
    let mut stream = ScriptedIo::new(concat(&[&[5, 0], &SUCCESS_V4]));

    socks5_connect(&mut stream, None, &target).await.unwrap();

    assert_eq!(
        stream.output,
        [5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 10, 0x01, 0xbb]
    );
}

#[tokio::test]
async fn reply_bound_address_of_each_type_is_consumed_exactly() {
    let mut bound_domain = vec![5, 0, 0, 3, 17];
    bound_domain.extend_from_slice(b"proxy.example.net");
    bound_domain.extend_from_slice(&[0x04, 0x38]);
    let mut bound_ipv6 = vec![5, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8];
    bound_ipv6.extend_from_slice(&[0; 11]);
    bound_ipv6.extend_from_slice(&[1, 0x04, 0x38]);

    for reply in [SUCCESS_V4.to_vec(), bound_domain, bound_ipv6] {
        let mut stream = ScriptedIo::new(concat(&[&[5, 0], &reply, PAYLOAD]));

        socks5_connect(&mut stream, None, &ipv4_target())
            .await
            .unwrap();

        assert_eq!(stream.unread(), PAYLOAD);
    }
}

#[tokio::test]
async fn bytes_after_the_reply_stay_readable_over_a_duplex() {
    let (mut client, mut server) = tokio::io::duplex(256);
    let server_task = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        server.read_exact(&mut request).await.unwrap();
        // Reply and first tunnel bytes arrive in one segment.
        server
            .write_all(&concat(&[&SUCCESS_V4, PAYLOAD]))
            .await
            .unwrap();
        server
    });

    socks5_connect(&mut client, None, &ipv4_target())
        .await
        .unwrap();

    let mut payload = vec![0; PAYLOAD.len()];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, PAYLOAD);
    drop(server_task.await.unwrap());
}

/// Runs the client against the in-crate inbound and returns what it parsed.
async fn round_trip(
    auth: SocksInboundAuth,
    account: Option<&SocksAccount>,
    target: &Target,
) -> (
    Result<(), SocksClientError>,
    Result<Target, SocksParseError>,
) {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        negotiate_socks5(&mut server, &auth).await?;
        let request = parse_socks5_request_message(&mut server).await?;
        assert_eq!(request.command, SocksCommand::Connect);
        write_socks5_success(&mut server).await?;
        server.write_all(PAYLOAD).await.unwrap();
        Ok(request.target)
    });

    let client_result = socks5_connect(&mut client, account, target).await;
    if client_result.is_ok() {
        let mut payload = vec![0; PAYLOAD.len()];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, PAYLOAD);
    }
    drop(client);
    (client_result, server_task.await.unwrap())
}

#[tokio::test]
async fn round_trips_against_the_inbound_without_auth() {
    for (target, _) in targets() {
        let (client, server) = round_trip(SocksInboundAuth::NoAuth, None, &target).await;

        assert_eq!(client, Ok(()));
        assert_eq!(server, Ok(target));
    }
}

#[tokio::test]
async fn round_trips_against_the_inbound_with_password() {
    let account = account();
    for (target, _) in targets() {
        let auth = SocksInboundAuth::Password(vec![account.clone()]);
        let (client, server) = round_trip(auth, Some(&account), &target).await;

        assert_eq!(client, Ok(()));
        assert_eq!(server, Ok(target));
    }
}

#[tokio::test]
async fn round_trip_delivers_ipv4_mapped_targets_as_ipv4() {
    let mapped = tcp(
        TargetAddr::Ip(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped())),
        443,
    );

    let (client, server) = round_trip(SocksInboundAuth::NoAuth, None, &mapped).await;

    assert_eq!(client, Ok(()));
    assert_eq!(server, Ok(ipv4_target()));
}

#[tokio::test]
async fn round_trip_fails_when_auth_modes_differ() {
    let account = account();
    let password = SocksInboundAuth::Password(vec![account.clone()]);

    let (client, server) = round_trip(password, None, &ipv4_target()).await;
    assert_eq!(client, Err(SocksClientError::NoAcceptableMethod));
    assert_eq!(server, Err(SocksParseError::NoAcceptableMethods));

    let (client, server) =
        round_trip(SocksInboundAuth::NoAuth, Some(&account), &ipv4_target()).await;
    assert_eq!(client, Err(SocksClientError::NoAcceptableMethod));
    assert_eq!(server, Err(SocksParseError::NoAcceptableMethods));
}

#[tokio::test]
async fn round_trip_reports_a_rejected_password() {
    let configured = SocksAccount::new(USER, b"other-synthetic-pass").unwrap();
    let auth = SocksInboundAuth::Password(vec![configured]);

    let (client, server) = round_trip(auth, Some(&account()), &ipv4_target()).await;

    assert_eq!(client, Err(SocksClientError::AuthRejected(1)));
    assert_eq!(server, Err(SocksParseError::AuthenticationFailed));
}

#[tokio::test]
async fn no_acceptable_method_is_reported_without_downgrading() {
    let account = account();
    for (account, method) in [(None, 0), (Some(&account), 2)] {
        let mut stream = ScriptedIo::new([5, 0xff]);

        let result = socks5_connect(&mut stream, account, &ipv4_target()).await;

        assert_eq!(result, Err(SocksClientError::NoAcceptableMethod));
        assert_eq!(stream.output, [5, 1, method]);
    }
}

#[tokio::test]
async fn an_unoffered_method_is_rejected() {
    let mut stream = ScriptedIo::new(concat(&[&[5, 2], &[1, 0], &SUCCESS_V4]));
    let result = socks5_connect(&mut stream, None, &ipv4_target()).await;
    assert_eq!(result, Err(SocksClientError::UnexpectedMethod(2)));
    assert_eq!(stream.output, [5, 1, 0]);

    // A server that skips auth never sees the credentials.
    let mut stream = ScriptedIo::new(concat(&[&[5, 0], &SUCCESS_V4]));
    let result = socks5_connect(&mut stream, Some(&account()), &ipv4_target()).await;
    assert_eq!(result, Err(SocksClientError::UnexpectedMethod(0)));
    assert_eq!(stream.output, [5, 1, 2]);
}

#[tokio::test]
async fn unexpected_server_versions_are_rejected() {
    let mut stream = ScriptedIo::new([4, 0]);
    let result = socks5_connect(&mut stream, None, &ipv4_target()).await;
    assert_eq!(result, Err(SocksClientError::UnexpectedVersion(4)));

    let mut stream = ScriptedIo::new([5, 0, 4, 0, 0, 1, 198, 51, 100, 1, 0x1f, 0x90]);
    let result = socks5_connect(&mut stream, None, &ipv4_target()).await;
    assert_eq!(result, Err(SocksClientError::UnexpectedVersion(4)));
}

#[tokio::test]
async fn auth_failures_stop_before_the_request() {
    for (status, expected) in [
        ([1, 1], SocksClientError::AuthRejected(1)),
        ([1, 0xff], SocksClientError::AuthRejected(0xff)),
        ([5, 0], SocksClientError::UnexpectedAuthVersion(5)),
    ] {
        let mut stream = ScriptedIo::new(concat(&[&[5, 2], &status, &SUCCESS_V4]));

        let result = socks5_connect(&mut stream, Some(&account()), &ipv4_target()).await;

        assert_eq!(result, Err(expected));
        assert_eq!(stream.output, concat(&[&[5, 1, 2], &password_message()]));
    }
}

#[tokio::test]
async fn nonzero_reply_codes_are_reported() {
    for code in 1..=9 {
        let mut stream = ScriptedIo::new([5, 0, 5, code, 0]);

        let result = socks5_connect(&mut stream, None, &ipv4_target()).await;

        assert_eq!(result, Err(SocksClientError::RequestRejected(code)));
    }
    assert_eq!(
        SocksClientError::RequestRejected(5).to_string(),
        "SOCKS server rejected the request: connection refused (5)"
    );
}

#[tokio::test]
async fn truncated_replies_are_io_errors() {
    let password_cases = [vec![5], vec![5, 2, 1]];
    let no_auth_cases = [
        vec![],
        vec![5, 0, 5, 0],
        vec![5, 0, 5, 0, 0],
        vec![5, 0, 5, 0, 0, 1, 198, 51, 100, 1, 0x1f],
        vec![5, 0, 5, 0, 0, 3, 11, b'e', b'x'],
        vec![5, 0, 5, 0, 0, 4, 0x20, 0x01],
    ];
    let account = account();
    let cases = password_cases
        .into_iter()
        .map(|input| (Some(&account), input))
        .chain(no_auth_cases.into_iter().map(|input| (None, input)));

    for (account, input) in cases {
        let mut stream = ScriptedIo::new(input.clone());

        let result = socks5_connect(&mut stream, account, &ipv4_target()).await;

        assert_eq!(
            result,
            Err(SocksClientError::Io(io::ErrorKind::UnexpectedEof)),
            "{input:?}"
        );
    }
}

#[tokio::test]
async fn malformed_bound_addresses_are_rejected() {
    for (reply, expected) in [
        (vec![5, 0, 0, 3, 0, 0, 80], SocksClientError::MalformedReply),
        (
            vec![5, 0, 0, 3, 2, 0xff, 0xfe, 0, 80],
            SocksClientError::MalformedReply,
        ),
        (
            vec![5, 0, 0, 0],
            SocksClientError::UnsupportedAddressType(0),
        ),
        (
            vec![5, 0, 0, 2],
            SocksClientError::UnsupportedAddressType(2),
        ),
        (
            vec![5, 0, 0, 5],
            SocksClientError::UnsupportedAddressType(5),
        ),
    ] {
        let mut stream = ScriptedIo::new(concat(&[&[5, 0], &reply]));

        let result = socks5_connect(&mut stream, None, &ipv4_target()).await;

        assert_eq!(result, Err(expected), "{reply:?}");
    }
}

#[tokio::test]
async fn invalid_targets_fail_before_any_io() {
    let domain = |name: &str| tcp(TargetAddr::Domain(name.to_owned()), 443);
    let cases = [
        (
            tcp(ipv4_target().addr, 0),
            SocksClientError::InvalidTargetPort,
        ),
        (
            tcp(domain_target().addr, 0),
            SocksClientError::InvalidTargetPort,
        ),
        (domain(""), SocksClientError::InvalidTargetDomain),
        (
            domain(&"a".repeat(256)),
            SocksClientError::InvalidTargetDomain,
        ),
        (
            domain("exa mple.com"),
            SocksClientError::InvalidTargetDomain,
        ),
        (
            domain("example.com\n"),
            SocksClientError::InvalidTargetDomain,
        ),
        (
            domain("example\u{7f}.com"),
            SocksClientError::InvalidTargetDomain,
        ),
        (
            domain("example\u{a0}.com"),
            SocksClientError::InvalidTargetDomain,
        ),
    ];
    let account = account();

    for (target, expected) in cases {
        for account in [None, Some(&account)] {
            let mut stream = ScriptedIo::new(concat(&[&[5, 0], &SUCCESS_V4]));

            let result = socks5_connect(&mut stream, account, &target).await;

            assert_eq!(result, Err(expected), "{target:?}");
            assert!(stream.output.is_empty());
            assert_eq!(stream.write_calls, 0);
            assert_eq!(stream.position, 0);
        }
    }
}

#[tokio::test]
async fn a_255_byte_domain_is_accepted() {
    let name = "a".repeat(255);
    let target = tcp(TargetAddr::Domain(name.clone()), 443);
    let mut stream = ScriptedIo::new(concat(&[&[5, 0], &SUCCESS_V4]));

    socks5_connect(&mut stream, None, &target).await.unwrap();

    let expected = concat(&[&[5, 1, 0, 5, 1, 0, 3, 255], name.as_bytes(), &[0x01, 0xbb]]);
    assert_eq!(stream.output, expected);
}

#[test]
fn account_exposes_its_credentials_without_debug_leaks() {
    let account = account();

    assert_eq!(account.user(), USER);
    assert_eq!(account.pass(), PASS);
    assert!(!format!("{account:?}").contains("synthetic"));
}
