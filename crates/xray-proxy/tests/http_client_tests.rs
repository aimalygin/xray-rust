use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_proxy::outbound::{
    encode_connect_request, http_connect, HttpAccount, HttpClientError,
    MAX_HTTP_CONNECT_RESPONSE_HEAD, MAX_HTTP_CREDENTIAL_LENGTH,
};
use xray_routing::{Network, Target, TargetAddr};

const USER: &str = "synthetic-user";
const PASS: &str = "synthetic-pass";
/// `base64("synthetic-user:synthetic-pass")`.
const BASIC: &str = "Basic c3ludGhldGljLXVzZXI6c3ludGhldGljLXBhc3M=";
const OK: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// Replays scripted server bytes, at most `chunk` per read, and records what
/// the client writes and how much it read.
struct ScriptedIo {
    input: Vec<u8>,
    position: usize,
    chunk: usize,
    output: Vec<u8>,
}

impl ScriptedIo {
    fn new(input: impl Into<Vec<u8>>) -> Self {
        Self::chunked(input, usize::MAX)
    }

    fn chunked(input: impl Into<Vec<u8>>, chunk: usize) -> Self {
        Self {
            input: input.into(),
            position: 0,
            chunk,
            output: Vec::new(),
        }
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buf
            .remaining()
            .min(self.chunk)
            .min(self.input.len() - self.position);
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

fn tcp(addr: TargetAddr, port: u16) -> Target {
    Target::new(addr, port, Network::Tcp)
}

fn domain(name: &str) -> Target {
    tcp(TargetAddr::Domain(name.into()), 443)
}

fn account() -> HttpAccount {
    HttpAccount::new(USER, PASS).unwrap()
}

fn request(target: &Target, account: Option<&HttpAccount>, headers: &[(&str, &str)]) -> String {
    String::from_utf8(
        encode_connect_request(target, account, headers)
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn respond(response: &[u8]) -> Result<Vec<u8>, HttpClientError> {
    http_connect(&mut ScriptedIo::new(response), b"CONNECT").await
}

#[test]
fn request_follows_go_request_write_order() {
    let headers = [
        ("Sec-Fetch-Mode", "navigate"),
        ("User-Agent", "synthetic-agent"),
        ("Accept", "*/*"),
        ("DNT", "1"),
    ];
    assert_eq!(
        request(&domain("example.com"), Some(&account()), &headers),
        format!(
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             User-Agent: synthetic-agent\r\n\
             Accept: */*\r\n\
             DNT: 1\r\n\
             Proxy-Authorization: {BASIC}\r\n\
             Proxy-Connection: Keep-Alive\r\n\
             Sec-Fetch-Mode: navigate\r\n\r\n"
        )
    );
}

#[test]
fn request_without_headers_uses_go_defaults_and_no_authorization() {
    assert_eq!(
        request(&domain("example.com"), None, &[]),
        "CONNECT example.com:443 HTTP/1.1\r\n\
         Host: example.com:443\r\n\
         User-Agent: Go-http-client/1.1\r\n\
         Proxy-Connection: Keep-Alive\r\n\r\n"
    );
    // Go omits the line when `User-Agent` is set to the empty string.
    assert!(!request(&domain("example.com"), None, &[("User-Agent", "")]).contains("User-Agent"));
}

#[test]
fn request_owns_host_and_proxy_fields() {
    let headers = [
        ("Host", "spoofed.example"),
        ("Proxy-Authorization", "Basic spoofed"),
        ("Proxy-Connection", "close"),
    ];
    let text = request(&domain("example.com"), None, &headers);
    assert!(!text.contains("spoofed"));
    assert!(!text.contains("close"));
    assert_eq!(text.matches("Host:").count(), 1);
    assert!(!text.contains("Proxy-Authorization"));
}

#[test]
fn request_basic_credentials_follow_rfc_7617() {
    let token = HttpAccount::new("synthetic-token", "").unwrap();
    assert!(request(&domain("example.com"), Some(&token), &[])
        .contains("Proxy-Authorization: Basic c3ludGhldGljLXRva2VuOg==\r\n"));
    let colons = HttpAccount::new(USER, "pass:with:colons").unwrap();
    assert!(request(&domain("example.com"), Some(&colons), &[])
        .contains("Proxy-Authorization: Basic c3ludGhldGljLXVzZXI6cGFzczp3aXRoOmNvbG9ucw==\r\n"));
}

#[test]
fn request_authority_matches_join_host_port() {
    let cases = [
        (
            tcp(TargetAddr::Ip(Ipv4Addr::new(192, 0, 2, 1).into()), 80),
            "192.0.2.1:80",
        ),
        (
            tcp(TargetAddr::Ip(Ipv6Addr::LOCALHOST.into()), 8443),
            "[::1]:8443",
        ),
        (
            tcp(
                TargetAddr::Ip(IpAddr::V6(Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped())),
                443,
            ),
            "198.51.100.7:443",
        ),
        (domain("xn--d1acufc.xn--p1ai"), "xn--d1acufc.xn--p1ai:443"),
        (domain("host_name.example"), "host_name.example:443"),
    ];
    for (target, authority) in cases {
        let text = request(&target, None, &[]);
        assert!(
            text.starts_with(&format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
            )),
            "{text}"
        );
    }
}

#[test]
fn request_rejects_unusable_targets_before_building() {
    let long = "a".repeat(256);
    for name in [
        "",
        long.as_str(),
        "exa mple.com",
        "example.com:80",
        "user@example.com",
        "example.com/path",
        "пример.рф",
        "example.com\r\nX-Injected: 1",
        "[::1]",
    ] {
        assert_eq!(
            encode_connect_request(&domain(name), None, &[]).map(drop),
            Err(HttpClientError::InvalidTargetDomain),
            "{name:?}"
        );
    }
    assert_eq!(
        encode_connect_request(&tcp(TargetAddr::Domain("example.com".into()), 0), None, &[])
            .map(drop),
        Err(HttpClientError::InvalidTargetPort)
    );
}

#[test]
fn request_rejects_invalid_extra_headers() {
    for header in [
        ("Bad Name", "value"),
        ("", "value"),
        ("X-Split", "a\r\nX-Injected: 1"),
        ("X-Nul", "a\0b"),
        ("User-Agent", "agent\n"),
    ] {
        assert_eq!(
            encode_connect_request(&domain("example.com"), None, &[header]).map(drop),
            Err(HttpClientError::InvalidHeader),
            "{header:?}"
        );
    }
    assert!(encode_connect_request(&domain("example.com"), None, &[("X-Tab", "a\tb")]).is_ok());
}

#[test]
fn account_validation_and_redaction() {
    assert!(HttpAccount::new("", PASS).is_none());
    assert!(HttpAccount::new("user:name", PASS).is_none());
    assert!(HttpAccount::new("user\u{7}", PASS).is_none());
    assert!(HttpAccount::new(USER, "pass\nword").is_none());
    let max = "a".repeat(MAX_HTTP_CREDENTIAL_LENGTH);
    let over = "a".repeat(MAX_HTTP_CREDENTIAL_LENGTH + 1);
    assert!(HttpAccount::new(&max, &max).is_some());
    assert!(HttpAccount::new(&over, PASS).is_none());
    assert!(HttpAccount::new(USER, &over).is_none());
    assert!(HttpAccount::new("пользователь", "пароль").is_some());
    let debug = format!("{:?}", account());
    assert!(!debug.contains(USER) && !debug.contains(PASS), "{debug}");
}

#[tokio::test]
async fn connect_writes_request_and_accepts_200() {
    let mut io = ScriptedIo::new(OK);
    let early = http_connect(&mut io, b"CONNECT request").await.unwrap();
    assert!(early.is_empty());
    assert_eq!(io.output, b"CONNECT request");
}

#[tokio::test]
async fn connect_returns_tunnel_bytes_read_with_the_head() {
    let response = [OK, b"server-first bytes"].concat();
    assert_eq!(respond(&response).await.unwrap(), b"server-first bytes");
    // RFC 9110: framing headers on a 2xx CONNECT response are ignored.
    let framed = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nabc";
    assert_eq!(respond(framed).await.unwrap(), b"abc");
}

#[tokio::test]
async fn connect_reads_a_head_split_into_single_bytes() {
    let response = [
        b"HTTP/1.1 200 OK\r\nVia: 1.1 proxy\r\n\tcontinued\r\n\r\n".as_slice(),
        b"tail",
    ]
    .concat();
    let mut io = ScriptedIo::chunked(response, 1);
    // One byte per read means the tunnel byte after the head stays unread.
    assert!(http_connect(&mut io, b"").await.unwrap().is_empty());
    assert_eq!(&io.input[io.position..], b"tail");
}

#[tokio::test]
async fn connect_accepts_go_compatible_variants() {
    for response in [
        b"HTTP/1.0 200 Connection established\r\n\r\n".as_slice(),
        b"HTTP/1.1 200\r\n\r\n",
        b"HTTP/1.1 200 OK\n\n",
        b"HTTP/1.1 200 OK\r\nProxy-Agent: synthetic\nX-Mixed:\r\n\n",
        b"HTTP/1.1 200 OK\r\nX-Empty:\r\nX-Obs-Text: \xe2\x9c\x93\r\n\r\n",
    ] {
        assert_eq!(
            respond(response).await,
            Ok(Vec::new()),
            "{:?}",
            String::from_utf8_lossy(response)
        );
    }
}

#[tokio::test]
async fn connect_accepts_only_status_200() {
    let cases: [(&[u8], HttpClientError); 6] = [
        (
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
            HttpClientError::ProxyAuthenticationRequired,
        ),
        (
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            HttpClientError::Rejected(403),
        ),
        (
            b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
            HttpClientError::Rejected(502),
        ),
        (
            b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
            HttpClientError::Rejected(503),
        ),
        // Xray accepts only 200, not every 2xx that RFC 9110 allows.
        (
            b"HTTP/1.1 204 No Content\r\n\r\n",
            HttpClientError::Rejected(204),
        ),
        (
            b"HTTP/1.1 100 Continue\r\n\r\n",
            HttpClientError::Rejected(100),
        ),
    ];
    for (response, error) in cases {
        assert_eq!(respond(response).await, Err(error));
    }
}

#[tokio::test]
async fn connect_rejects_malformed_responses() {
    for response in [
        b"HTTP/2 200 OK\r\n\r\n".as_slice(),
        b"HTTP/1.2 200 OK\r\n\r\n",
        b"http/1.1 200 OK\r\n\r\n",
        b"HTTP/1.1  200 OK\r\n\r\n",
        b"HTTP/1.1 20\r\n\r\n",
        b"HTTP/1.1 2000 OK\r\n\r\n",
        b"HTTP/1.1 200OK\r\n\r\n",
        b"HTTP/1.1 2x0 OK\r\n\r\n",
        b"HTTP/1.1 200 O\x01K\r\n\r\n",
        b"SSH-2.0-OpenSSH\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nNo colon\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nName : value\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n: value\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n continued first\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Bad: a\x00b\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Bad: a\rb\r\n\r\n",
        // A malformed header fails even when the status would be refused.
        b"HTTP/1.1 407 Proxy Authentication Required\r\nbroken\r\n\r\n",
    ] {
        assert_eq!(
            respond(response).await,
            Err(HttpClientError::MalformedResponse),
            "{:?}",
            String::from_utf8_lossy(response)
        );
    }
}

#[tokio::test]
async fn connect_bounds_the_response_head() {
    let header = format!("X-Fill: {}\r\n", "a".repeat(64));
    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
    while response.len() <= MAX_HTTP_CONNECT_RESPONSE_HEAD {
        response.extend_from_slice(header.as_bytes());
    }
    response.extend_from_slice(b"\r\n");
    let mut io = ScriptedIo::new(response);
    assert_eq!(
        http_connect(&mut io, b"").await,
        Err(HttpClientError::ResponseTooLarge)
    );
    assert_eq!(io.position, MAX_HTTP_CONNECT_RESPONSE_HEAD);

    // A head that ends exactly at the limit still succeeds.
    let mut exact = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
    exact.resize(MAX_HTTP_CONNECT_RESPONSE_HEAD - 4, b'a');
    exact.extend_from_slice(b"\r\n\r\n");
    assert_eq!(respond(&exact).await, Ok(Vec::new()));
}

#[tokio::test]
async fn connect_reports_a_closed_connection() {
    for response in [
        b"".as_slice(),
        b"HTTP/1.1 200 OK\r\n",
        b"HTTP/1.1 200 OK\r\n\r",
    ] {
        assert_eq!(
            respond(response).await,
            Err(HttpClientError::ConnectionClosed)
        );
    }
}

#[test]
fn errors_do_not_echo_proxy_text() {
    let message = HttpClientError::Rejected(403).to_string();
    assert_eq!(
        message,
        "HTTP proxy answered CONNECT with status 403, not 200"
    );
}
