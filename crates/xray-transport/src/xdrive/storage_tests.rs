//! The `s3` and `template` storages against a scripted HTTP/1.1 server on
//! the loopback: how they read missing objects, deletes, listings and their
//! pages, retries, two-step operations and tokens, as Xray-core's do.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use super::client::ServiceDialer;
use super::http_storage::HttpShared;
use super::s3::{S3Shared, S3Storage, XdriveS3};
use super::storage::{Storage, StorageError};
use super::template::{StorageTemplate, TemplateShared, TemplateStorage};
use crate::stream::{XhttpRange, XhttpXmuxPolicy};
use crate::{TlsClientConfig, TransportDialer};

/// A request the server read.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// An answer: status, extra headers, body.
type Answer = (u16, Vec<(&'static str, String)>, Vec<u8>);

struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Seen {
        method,
        target,
        headers,
        body,
    })
}

/// Serves every connection with `answer`, keeping what it was asked.
async fn serve(answer: impl Fn(&Seen, usize) -> Answer + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answer = Arc::new(answer);
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let answer = Arc::clone(&answer);
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                while let Some(request) = read_request(&mut stream).await {
                    let index = {
                        let mut log = log.lock().unwrap();
                        log.push(request.clone());
                        log.len() - 1
                    };
                    let (status, headers, body) = answer(&request, index);
                    let mut out =
                        format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n", body.len());
                    for (name, value) in headers {
                        out.push_str(&format!("{name}: {value}\r\n"));
                    }
                    out.push_str("\r\n");
                    let mut bytes = out.into_bytes();
                    bytes.extend_from_slice(&body);
                    if stream.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Server { addr, seen }
}

fn http() -> HttpShared {
    let tls = TlsClientConfig {
        server_name: String::new(),
        allow_insecure: false,
        pinned_peer_cert_sha256: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        alpn: Vec::new(),
        fingerprint: None,
    };
    let dialer = ServiceDialer {
        dialer: TransportDialer::system().unwrap(),
        tls,
        fronting: None,
        keep_alive: None,
    };
    let zero = XhttpRange { from: 0, to: 0 };
    let xmux = XhttpXmuxPolicy {
        max_concurrency: zero,
        max_connections: XhttpRange { from: 1, to: 1 },
        c_max_reuse_times: zero,
        h_max_request_times: zero,
        h_max_reusable_secs: XhttpRange {
            from: 1800,
            to: 3000,
        },
        h_keep_alive_period_secs: 0,
    };
    HttpShared::new(dialer, xmux, 4)
}

fn s3(server: &Server) -> S3Storage {
    let mut shared = S3Shared::new(&XdriveS3 {
        endpoint: format!("http://{}", server.addr),
        region: String::new(),
        bucket: "b".to_owned(),
        path_style: true,
        remote_folder: "root".to_owned(),
        access_key: Zeroizing::new("AKID".to_owned()),
        secret_key: Zeroizing::new("secret".to_owned()),
        session_token: None,
    })
    .unwrap();
    shared.backoff = Duration::from_millis(2);
    S3Storage::new(Arc::new(shared), http().session())
}

fn list_page(keys: &[&str], prefixes: &[&str], next: Option<&str>) -> Vec<u8> {
    let mut xml = String::from("<ListBucketResult>");
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", next.is_some()));
    if let Some(next) = next {
        xml.push_str(&format!(
            "<NextContinuationToken>{next}</NextContinuationToken>"
        ));
    }
    for key in keys {
        xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
    }
    for prefix in prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{prefix}</Prefix></CommonPrefixes>"
        ));
    }
    xml.push_str("</ListBucketResult>");
    xml.into_bytes()
}

fn s3_error(code: &str) -> Vec<u8> {
    format!("<Error><Code>{code}</Code></Error>").into_bytes()
}

#[tokio::test]
async fn s3_reads_missing_objects_as_xray_core_does() {
    let server = serve(|request, _| match request.target.as_str() {
        "/b/root/a" => (404, vec![], s3_error("NoSuchKey")),
        "/b/root/b" => (404, vec![], s3_error("NotFound")),
        "/b/root/c" => (404, vec![], s3_error("NoSuchBucket")),
        "/b/root/d" => (403, vec![], s3_error("AccessDenied")),
        _ => (200, vec![], b"data".to_vec()),
    })
    .await;
    let storage = s3(&server);
    assert_eq!(storage.get("a").await, Err(StorageError::NotFound));
    assert_eq!(storage.get("b").await, Err(StorageError::NotFound));
    assert!(matches!(
        storage.get("c").await,
        Err(StorageError::Failed(_))
    ));
    assert!(matches!(
        storage.get("d").await,
        Err(StorageError::Failed(_))
    ));
    assert_eq!(storage.get("e").await.unwrap(), Bytes::from_static(b"data"));
    assert!(storage.get("../x").await.is_err());
}

#[tokio::test]
async fn s3_deletes_an_object_and_what_lies_under_it() {
    let server = serve(
        |request, _| match (request.method.as_str(), request.target.as_str()) {
            ("GET", target) if target.contains("prefix=root%2Fstreams%2Fs%2F") => (
                200,
                vec![],
                list_page(
                    &["root/streams/s/c2s/1.seg", "root/streams/s/s2c/2.end"],
                    &[],
                    None,
                ),
            ),
            ("DELETE", "/b/root/streams/s/s2c/2.end") => (404, vec![], s3_error("NoSuchKey")),
            ("DELETE", _) => (204, vec![], vec![]),
            _ => (400, vec![], s3_error("Unexpected")),
        },
    )
    .await;
    s3(&server).delete("streams/s").await.unwrap();
    let deleted: Vec<String> = server
        .seen()
        .into_iter()
        .filter(|seen| seen.method == "DELETE")
        .map(|seen| seen.target)
        .collect();
    assert_eq!(
        deleted,
        [
            "/b/root/streams/s",
            "/b/root/streams/s/c2s/1.seg",
            "/b/root/streams/s/s2c/2.end"
        ]
    );
}

#[tokio::test]
async fn s3_lists_names_across_pages_and_checks_them() {
    let server = serve(|request, _| {
        let target = request.target.as_str();
        if target.contains("prefix=root%2Fbad%2F") {
            return (200, vec![], list_page(&["elsewhere/x"], &[], None));
        }
        if target.contains("prefix=root%2Fstuck%2F") {
            return (200, vec![], list_page(&[], &[], Some("same")));
        }
        if target.contains("continuation-token=t2") {
            return (
                200,
                vec![],
                list_page(&["root/s/b.seg"], &["root/s/sub/"], None),
            );
        }
        (
            200,
            vec![],
            list_page(&["root/s/a.seg", "root/s/a.seg"], &[], Some("t2")),
        )
    })
    .await;
    let storage = s3(&server);
    let names: Vec<String> = storage
        .list("s")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["a.seg", "b.seg", "sub"]);
    let first = &server.seen()[0];
    assert!(first.target.contains("delimiter=%2F") && first.target.contains("list-type=2"));
    assert!(first.target.contains("max-keys=1000"));
    assert!(storage.list("bad").await.is_err());
    // A token that does not advance ends the listing, not a loop.
    let stuck = tokio::time::timeout(Duration::from_secs(5), storage.list("stuck")).await;
    assert!(stuck.expect("the listing ends").is_err());
}

#[tokio::test]
async fn s3_retries_what_xray_core_retries() {
    let server = serve(|request, index| match (request.target.as_str(), index) {
        ("/b/root/busy", 0) => (
            503,
            vec![("Retry-After", "0".to_owned())],
            s3_error("SlowDown"),
        ),
        ("/b/root/busy", _) => (200, vec![], b"ok".to_vec()),
        ("/b/root/bad", _) => (400, vec![], s3_error("InvalidRequest")),
        _ => (200, vec![], vec![]),
    })
    .await;
    let storage = s3(&server);
    assert_eq!(
        storage.get("busy").await.unwrap(),
        Bytes::from_static(b"ok")
    );
    assert!(storage.get("bad").await.is_err());
    // One try for the 400, two for the 503.
    assert_eq!(server.seen().len(), 3);
    let put = serve(|_, _| (200, vec![], vec![])).await;
    s3(&put)
        .put("streams/s/c2s/000000001.seg", Bytes::from_static(b"x"))
        .await
        .unwrap();
    let seen = &put.seen()[0];
    assert_eq!(
        seen.header("content-type"),
        Some("application/octet-stream")
    );
    assert!(seen
        .header("authorization")
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256 ")));
    assert_eq!(seen.body, b"x");
}

/// The server's store as a template, with `extra` fields and `get` ones.
fn template(server: &Server, extra: &str, get: &str) -> TemplateStorage {
    let base = format!("http://{}", server.addr);
    let text = format!(
        r#"{{"flatten": true, {extra}
        "put": {{"method": "PUT", "url": "{base}/files/{{folder}}/{{name}}"}},
        "get": {{{get} "url": "{base}/files/{{folder}}/{{name}}"}},
        "delete": {{"method": "DELETE", "url": "{base}/files/{{folder}}/{{name}}"}},
        "list": {{"url": "{base}/list/{{folder}}", "namesRegex": "<n>([^<]+)</n>"}}}}"#
    );
    let mut shared = TemplateShared::new(
        StorageTemplate::parse(&text).unwrap(),
        "f".to_owned(),
        vec![
            Zeroizing::new("refresh".to_owned()),
            Zeroizing::new("id".to_owned()),
        ],
        Arc::new(http()),
    );
    shared.backoff = Duration::from_millis(2);
    let shared = Arc::new(shared);
    let session = shared.http.session();
    TemplateStorage::new(shared, session)
}

#[tokio::test]
async fn template_reads_404s_and_flat_listings_as_xray_core_does() {
    let server = serve(|request, _| match (request.method.as_str(), request.target.as_str()) {
        ("GET", "/files/f/missing") | ("DELETE", "/files/f/gone") => (404, vec![], vec![]),
        ("GET", "/list/f") => (
            200,
            vec![],
            b"<n>streams~s~s2c~000000001.seg</n><n>streams~s~s2c~000000002.end</n><n>streams~t~c2s~1.seg</n><n>streams~s~s2c~000000001.seg</n><n>streams~s</n><n>streams~s~s2c~dir~000000003.seg</n>"
                .to_vec(),
        ),
        ("PUT", _) => (500, vec![], b"broken".to_vec()),
        _ => (200, vec![], b"body".to_vec()),
    })
    .await;
    let storage = template(&server, "", "");
    assert_eq!(storage.get("missing").await, Err(StorageError::NotFound));
    storage.delete("gone").await.unwrap();
    let names: Vec<String> = storage
        .list("streams/s/s2c")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    // A name further down counts once, cut at its next separator.
    assert_eq!(names, ["000000001.seg", "000000002.end", "dir"]);
    // A 500 that the template does not list is no retry.
    assert!(storage.put("x", Bytes::from_static(b"d")).await.is_err());
    assert_eq!(
        server.seen().iter().filter(|s| s.method == "PUT").count(),
        1
    );
}

#[tokio::test]
async fn template_retries_listed_statuses_and_reasons() {
    let server = serve(|request, index| match (request.target.as_str(), index) {
        (_, 0) => (429, vec![], vec![]),
        (_, 1) => (
            403,
            vec![],
            br#"{"error":{"reason":"rateLimitExceeded"}}"#.to_vec(),
        ),
        ("/files/f/denied", _) => (403, vec![], br#"{"error":{}}"#.to_vec()),
        _ => (200, vec![], b"body".to_vec()),
    })
    .await;
    let storage = template(
        &server,
        r#""retry": {"status": [429], "rateReason": "error.reason"},"#,
        "",
    );
    assert_eq!(storage.get("x").await.unwrap(), Bytes::from_static(b"body"));
    assert_eq!(server.seen().len(), 3);
    // A 403 without a reason is the answer.
    assert!(storage.get("denied").await.is_err());
    assert_eq!(server.seen().len(), 4);
}

#[tokio::test]
async fn template_two_steps_and_tokens_work_as_xray_core_does() {
    let issued = Arc::new(Mutex::new(0));
    let tokens = Arc::clone(&issued);
    let link = Arc::new(Mutex::new(String::new()));
    let href = Arc::clone(&link);
    let server = serve(move |request, _| match request.target.as_str() {
        "/token" => {
            let mut issued = tokens.lock().unwrap();
            *issued += 1;
            let body = String::from_utf8_lossy(&request.body).into_owned();
            assert!(
                body.contains("refresh_token=refresh") && body.contains("client_id=id"),
                "{body}"
            );
            (
                200,
                vec![],
                format!(r#"{{"access_token":"tok{issued}","expires_in":3600}}"#).into_bytes(),
            )
        }
        "/files/f/x" if request.header("authorization") == Some("Bearer tok1") => {
            (401, vec![], vec![])
        }
        "/files/f/x" => (
            200,
            vec![],
            format!(r#"{{"href":"{}"}}"#, href.lock().unwrap()).into_bytes(),
        ),
        "/link/x" => {
            assert_eq!(
                request.header("authorization"),
                None,
                "a link takes no auth"
            );
            (200, vec![], b"payload".to_vec())
        }
        _ => (404, vec![], vec![]),
    })
    .await;
    let base = format!("http://{}", server.addr);
    *link.lock().unwrap() = format!("{base}/link/x");
    let auth = format!(
        r#""auth": {{"type": "oauth2", "tokenUrl": "{base}/token",
            "form": {{"grant_type": "refresh_token", "refresh_token": "{{secret0}}", "client_id": "{{secret1}}"}},
            "header": {{"Authorization": "Bearer {{token}}"}}}},"#
    );
    let storage = template(&server, &auth, r#""hrefPath": "href","#);
    assert_eq!(
        storage.get("x").await.unwrap(),
        Bytes::from_static(b"payload")
    );
    assert_eq!(*issued.lock().unwrap(), 2, "a 401 fetches a new token");
    let token_requests = server
        .seen()
        .into_iter()
        .filter(|s| s.target == "/token")
        .count();
    assert_eq!(token_requests, 2);
}

#[tokio::test]
async fn template_tokens_past_gos_durations_run_out_as_on_arm64() {
    let server = serve(|request, _| match request.target.as_str() {
        "/token" => (
            200,
            vec![],
            br#"{"access_token":"tok","expires_in":1e300}"#.to_vec(),
        ),
        "/files/f/x" if request.header("authorization") == Some("Bearer tok") => {
            (200, vec![], b"payload".to_vec())
        }
        _ => (404, vec![], vec![]),
    })
    .await;
    let base = format!("http://{}", server.addr);
    let auth = format!(
        r#""auth": {{"type": "oauth2", "tokenUrl": "{base}/token", "expiryPath": "expires_in",
            "form": {{"grant_type": "refresh_token"}},
            "header": {{"Authorization": "Bearer {{token}}"}}}},"#
    );
    let storage = template(&server, &auth, "");
    for _ in 0..2 {
        assert_eq!(
            storage.get("x").await.unwrap(),
            Bytes::from_static(b"payload")
        );
    }
    // 1e300 saturates to int64's maximum; less the minute's margin and
    // times a second, it wraps to a minute ago, so each request asks for
    // a token again.
    let token_requests = server
        .seen()
        .into_iter()
        .filter(|s| s.target == "/token")
        .count();
    assert_eq!(token_requests, 2);
}
