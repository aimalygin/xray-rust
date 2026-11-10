//! HTTP messages read and written as Go's `net/http` does in Xray-core's HTTP
//! inbound. Every expected byte string here is what Xray-core v26.10.31 sent
//! on in a live capture.

use std::io::Cursor;

use tokio::io::BufReader;
use xray_proxy::inbound::{
    canonical_header_key, copy_body_chunked, read_http_request_head, read_http_response, HttpBody,
    HttpParseError, PlainHttpError, PlainHttpRequest,
};

async fn request(raw: &[u8]) -> Result<PlainHttpRequest, PlainHttpError> {
    let head = read_http_request_head(&mut Cursor::new(raw.to_vec()))
        .await
        .expect("the head parses");
    PlainHttpRequest::new(&head)
}

async fn forwarded(raw: &str) -> String {
    let head = request(raw.as_bytes())
        .await
        .expect("the request is forwarded")
        .forwarded_head();
    String::from_utf8(head).unwrap()
}

#[test]
fn header_names_read_as_go_canonicalizes_them() {
    for (name, canonical) in [
        ("x-lower", "X-Lower"),
        ("CONTENT-TYPE", "Content-Type"),
        ("etag", "Etag"),
        ("te", "Te"),
        ("X-Already-Fine", "X-Already-Fine"),
        // A name with a byte that is not a token character stays.
        ("Host ", "Host "),
    ] {
        assert_eq!(canonical_header_key(name), canonical, "{name:?}");
    }
}

#[tokio::test]
async fn requests_go_on_as_go_writes_them() {
    for (raw, sent) in [
        (
            "GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.7\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n",
            "GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.7\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        ),
        // Hop-by-hop headers go, with those `Connection` names; `Pragma`
        // adds `Cache-Control`; names come canonical and in order.
        (
            "GET http://Example.COM:8080/p%20q HTTP/1.1\r\nHost: other.example\r\nx-lower: a\r\nX-Multi: 1\r\nX-Multi: 2\r\nConnection: X-Drop, keep-alive\r\nX-Drop: gone\r\nKeep-Alive: 300\r\nTE: trailers\r\nUpgrade: h2c\r\nProxy-Authorization: Basic eDp5\r\nPragma: no-cache\r\n\r\n",
            "GET /p%20q HTTP/1.1\r\nHost: Example.COM:8080\r\nCache-Control: no-cache\r\nConnection: close\r\nPragma: no-cache\r\nX-Lower: a\r\nX-Multi: 1\r\nX-Multi: 2\r\n\r\n",
        ),
        (
            "POST http://example.com/form HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\n",
            "POST /form HTTP/1.1\r\nHost: example.com\r\nContent-Length: 7\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",
        ),
        (
            "POST http://example.com/up HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /up HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        ),
        (
            "POST http://example.com/e HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "POST /e HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        (
            "HEAD http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://example.com/ HTTP/1.0\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://пример.рф/ HTTP/1.1\r\nHost: пример.рф\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: xn--e1afmkfd.xn--p1ai\r\nConnection: close\r\n\r\n",
        ),
        // Paths as Go's `URL.EscapedPath` gives them.
        (
            "GET http://example.com/a!b'c(d)e*f[g]h HTTP/1.1\r\n\r\n",
            "GET /a!b'c(d)e*f[g]h HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://example.com/a\"b<c>d HTTP/1.1\r\n\r\n",
            "GET /a%22b%3Cc%3Ed HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://example.com/пути HTTP/1.1\r\n\r\n",
            "GET /%D0%BF%D1%83%D1%82%D0%B8 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://example.com/%41/пути HTTP/1.1\r\n\r\n",
            "GET /A/%D0%BF%D1%83%D1%82%D0%B8 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://u:p@example.com/ HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://example.com/p? HTTP/1.1\r\n\r\n",
            "GET /p? HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://example.com?x=1 HTTP/1.1\r\n\r\n",
            "GET /?x=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://EXAMPLE.com:8080 HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: EXAMPLE.com:8080\r\nConnection: close\r\n\r\n",
        ),
    ] {
        assert_eq!(forwarded(raw).await, sent, "{raw:?}");
    }
}

#[tokio::test]
async fn requests_read_as_go_reads_them() {
    let keep_alive =
        request(b"GET http://example.com/ HTTP/1.1\r\nProxy-Connection:  Keep-Alive \r\n\r\n")
            .await
            .unwrap();
    assert!(keep_alive.keep_alive);
    assert_eq!(keep_alive.destination.port, 80);
    let https = request(b"GET https://example.com/ HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(!https.keep_alive);
    assert_eq!(https.destination.port, 443);
    // A host, without one or not given as absolute, is what Xray-core
    // answers with a 400.
    for raw in [
        &b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
        b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET http:example.com HTTP/1.1\r\n\r\n",
        b"GET http:///path HTTP/1.1\r\n\r\n",
    ] {
        assert_eq!(request(raw).await, Err(PlainHttpError::NoHost), "{raw:?}");
    }
    assert_eq!(
        request(b"GET http://example.com/%zz HTTP/1.1\r\n\r\n").await,
        Err(PlainHttpError::Malformed)
    );
    // Go refuses a body it cannot delimit before anything else.
    for raw in [
        &b"GET http://example.com/ HTTP/1.1\r\nContent-Length: abc\r\n\r\n"[..],
        b"GET http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: x\r\n\r\n",
    ] {
        assert_eq!(
            read_http_request_head(&mut Cursor::new(raw.to_vec())).await.err(),
            Some(HttpParseError::Malformed),
            "{raw:?}"
        );
    }
    let bodies = [
        (&b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n"[..], HttpBody::Length(2)),
        (b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", HttpBody::Chunked),
        // HTTP/1.0 has no transfer coding.
        (b"POST http://example.com/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBody::None),
        (b"GET http://example.com/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n", HttpBody::None),
    ];
    for (raw, body) in bodies {
        assert_eq!(request(raw).await.unwrap().body, body, "{raw:?}");
    }
}

#[tokio::test]
async fn attributes_read_as_xray_core_records_them() {
    let request = request(
        b"get http://example.com/a%20b?q=1 HTTP/1.1\r\nHost: example.com\r\nX-A: one\r\nX-A: two\r\nX-F: a\r\n  b\r\nProxy-Connection: keep-alive\r\nPragma: no-cache\r\n\r\n",
    )
    .await
    .unwrap();
    let attributes: Vec<(String, Vec<u8>)> = request
        .attributes()
        .map(|(name, value)| (name.to_owned(), value.into_owned()))
        .collect();
    let get = |name: &str| {
        attributes
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, value)| String::from_utf8(value.clone()).unwrap())
    };
    assert_eq!(get(":method").as_deref(), Some("GET"));
    assert_eq!(get(":path").as_deref(), Some("/a b"));
    assert_eq!(get("X-A").as_deref(), Some("one"));
    assert_eq!(get("X-F").as_deref(), Some("a b"));
    assert_eq!(get("Cache-Control").as_deref(), Some("no-cache"));
    // No `User-Agent` reads as empty; `Host` and hop-by-hop headers are gone.
    assert_eq!(get("User-Agent").as_deref(), Some(""));
    assert_eq!(get("Host"), None);
    assert_eq!(get("Proxy-Connection"), None);
}

async fn response(
    raw: &[u8],
    method: &str,
) -> Result<(Option<String>, String, HttpBody, bool), HttpParseError> {
    let response =
        read_http_response(&mut BufReader::new(Cursor::new(raw.to_vec())), method).await?;
    Ok((
        response
            .informational
            .map(|head| String::from_utf8(head).unwrap()),
        String::from_utf8(response.head.client_head(method)).unwrap(),
        response.head.body,
        response.head.keeps_alive(),
    ))
}

#[tokio::test]
async fn responses_come_back_as_go_writes_them() {
    let keep =
        "Connection: keep-alive\r\nKeep-Alive: timeout=60\r\nProxy-Connection: keep-alive\r\n";
    for (raw, method, head, body, keeps_alive) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nX-Origin: yes\r\nConnection: close\r\n\r\nhello"[..],
            "GET",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nKeep-Alive: timeout=60\r\nProxy-Connection: keep-alive\r\nX-Origin: yes\r\n\r\n".to_owned(),
            HttpBody::Length(5),
            true,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-B: 2\r\nX-A: 1\r\n\r\n",
            "GET",
            "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\nX-B: 2\r\n\r\n".to_owned(),
            HttpBody::Chunked,
            false,
        ),
        (
            b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\n",
            "GET",
            "HTTP/1.1 200 OK\r\nConnection: close\r\nX-A: 1\r\n\r\n".to_owned(),
            HttpBody::UntilClose,
            false,
        ),
        (
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n",
            "GET",
            format!("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n{keep}\r\n"),
            HttpBody::Length(2),
            true,
        ),
        (
            b"HTTP/1.1 204 No Content\r\nX-A: 1\r\n\r\n",
            "GET",
            format!("HTTP/1.1 204 No Content\r\n{keep}X-A: 1\r\n\r\n"),
            HttpBody::None,
            true,
        ),
        (
            b"HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n",
            "GET",
            "HTTP/1.1 304 Not Modified\r\nConnection: keep-alive\r\nEtag: \"x\"\r\nKeep-Alive: timeout=60\r\nProxy-Connection: keep-alive\r\n\r\n".to_owned(),
            HttpBody::None,
            true,
        ),
        (
            b"HTTP/1.1 418 I'm a teapot, really\r\nContent-Length: 0\r\n\r\n",
            "GET",
            format!("HTTP/1.1 418 I'm a teapot, really\r\n{keep}Content-Length: 0\r\n\r\n"),
            HttpBody::None,
            true,
        ),
        (
            b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\n",
            "GET",
            format!("HTTP/1.1 200 200\r\nContent-Length: 2\r\n{keep}\r\n"),
            HttpBody::Length(2),
            true,
        ),
        (
            b"HTTP/1.1  200 OK\r\nContent-Length: 2\r\n\r\n",
            "GET",
            format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{keep}\r\n"),
            HttpBody::Length(2),
            true,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            "POST",
            format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n{keep}\r\n"),
            HttpBody::None,
            true,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n",
            "HEAD",
            format!("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n{keep}\r\n"),
            HttpBody::None,
            true,
        ),
        (
            b"HTTP/1.1 200 OK\r\n\r\n",
            "HEAD",
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_owned(),
            HttpBody::None,
            false,
        ),
        (
            b"HTTP/1.1 200 OK\r\nConnection: X-Drop\r\nX-Drop: 1\r\nX-Keep: 2\r\nContent-Length: 2\r\n\r\n",
            "GET",
            format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{keep}X-Keep: 2\r\n\r\n"),
            HttpBody::Length(2),
            true,
        ),
        (
            b"HTTP/1.1 200 OK\r\nX-F: a\r\n b\r\nContent-Length: 2\r\n\r\n",
            "GET",
            format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{keep}X-F: a b\r\n\r\n"),
            HttpBody::Length(2),
            true,
        ),
    ] {
        assert_eq!(
            response(raw, method).await.unwrap(),
            (None, head, body, keeps_alive),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }

    // One informational head goes as it came; a second is the response.
    let (informational, head, _, _) = response(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
        "GET",
    )
    .await
    .unwrap();
    assert_eq!(
        informational.as_deref(),
        Some("HTTP/1.1 100 Continue\r\n\r\n")
    );
    assert_eq!(head, format!("HTTP/1.1 102 Processing\r\n{keep}\r\n"));

    // What Go refuses, Xray-core answers with a 503.
    for raw in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n"[..],
        b"HTTP/1.1 204 No Content\r\nContent-Length: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"not http at all\r\n\r\n",
        b"",
    ] {
        assert!(
            response(raw, "GET").await.is_err(),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[tokio::test]
async fn chunked_bodies_go_on_chunk_by_chunk() {
    use tokio::io::AsyncReadExt;
    let mut source =
        Cursor::new(b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\nNEXT".to_vec());
    let mut sent = Vec::new();
    assert_eq!(copy_body_chunked(&mut source, &mut sent).await.unwrap(), 11);
    // Extensions and the trailer go; reading stops where the body ends.
    assert_eq!(sent, b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    let mut rest = String::new();
    source.read_to_string(&mut rest).await.unwrap();
    assert_eq!(rest, "NEXT");
    for broken in [
        &b"x\r\n"[..],
        b"5\r\nhel",
        b"5\r\nhelloXX\r\n",
        b"\r\n",
        b"-1\r\n",
    ] {
        let mut sent = Vec::new();
        assert!(
            copy_body_chunked(&mut Cursor::new(broken.to_vec()), &mut sent)
                .await
                .is_err(),
            "{:?}",
            String::from_utf8_lossy(broken)
        );
    }
}

/// A peer that never ends its headers is cut off at Go's default header
/// limit rather than read for as long as it sends them.
#[tokio::test]
async fn a_header_block_past_a_mebibyte_is_refused() {
    let line = "a:\r\n";
    let fits = "HTTP/1.1 200 OK\r\n".to_owned() + &line.repeat(1000) + "\r\n";
    assert!(response(fits.as_bytes(), "GET").await.is_ok());
    let endless = "HTTP/1.1 200 OK\r\n".to_owned() + &line.repeat((1 << 20) / line.len() + 1);
    assert_eq!(
        response(endless.as_bytes(), "GET").await.unwrap_err(),
        HttpParseError::HeadTooLarge
    );
    let request = "GET http://example.com/ HTTP/1.1\r\n".to_owned()
        + &line.repeat((1 << 20) / line.len() + 1);
    assert_eq!(
        read_http_request_head(&mut Cursor::new(request.into_bytes()))
            .await
            .unwrap_err(),
        HttpParseError::HeadTooLarge
    );
}

/// Reading keeps a header whose name has a space in it; writing leaves it
/// out, as Go's `Header.writeSubset` does. Forwarded, `Transfer-Encoding :
/// chunked` would announce a body this side framed as none.
#[tokio::test]
async fn a_header_name_that_is_not_a_token_is_not_forwarded() {
    let sent = forwarded(
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding : chunked\r\nProxy-Authorization : Basic eDp5\r\nX-Kept: 1\r\n\r\n",
    )
    .await;
    assert_eq!(
        sent,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nX-Kept: 1\r\n\r\n"
    );
    let (_, head, _, _) = response(
        b"HTTP/1.1 200 OK\r\nContent-Length : 5\r\nX-Kept: 1\r\n\r\n",
        "GET",
    )
    .await
    .unwrap();
    assert!(!head.contains("Content-Length :"), "{head}");
    assert!(head.contains("X-Kept: 1"), "{head}");
}
