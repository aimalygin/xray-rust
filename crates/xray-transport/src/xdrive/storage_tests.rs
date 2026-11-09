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
        h3: None,
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

#[test]
fn storage_configs_keep_drive_secrets_out_of_debug() {
    let zero = XhttpRange { from: 0, to: 0 };
    let config = super::XdriveStorageConfig::GoogleDrive {
        folder: "folder-id".to_owned(),
        secrets: ["client-id-1", "client-secret-2", "refresh-token-3"]
            .map(|s| Zeroizing::new(s.to_owned()))
            .to_vec(),
        http: super::XdriveHttpConfig {
            tls: TlsClientConfig {
                server_name: String::new(),
                allow_insecure: false,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
                fingerprint: None,
            },
            fronting: None,
            xmux: XhttpXmuxPolicy {
                max_concurrency: zero,
                max_connections: zero,
                c_max_reuse_times: zero,
                h_max_request_times: zero,
                h_max_reusable_secs: zero,
                h_keep_alive_period_secs: 0,
            },
            keep_alive: None,
            h3: None,
        },
    };
    let text = format!("{config:?}");
    assert!(
        text.contains("folder-id") && text.contains("secrets: 3"),
        "{text}"
    );
    for secret in ["client-id-1", "client-secret-2", "refresh-token-3"] {
        assert!(!text.contains(secret), "{text}");
    }
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

/// A Drive folder in memory, answering the requests `drive.rs` sends.
#[derive(Default)]
struct FakeDrive {
    files: std::collections::BTreeMap<String, (String, String, Vec<u8>)>,
    next: u64,
    tokens: usize,
    /// The `expires_in` of the tokens it hands out, an hour when unset.
    lifetime: Option<i64>,
    /// Answers the next request to a path holding this with this status
    /// and body, once.
    fail: Option<(&'static str, u16, &'static str)>,
    page: usize,
}

fn query_value(target: &str, key: &str) -> Option<String> {
    let query = target.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| {
            let v = v.replace('+', " ");
            String::from_utf8(
                xray_proxy::go_url::unescape_bytes(
                    v.as_bytes(),
                    xray_proxy::go_url::Encoding::QueryComponent,
                )
                .unwrap(),
            )
            .unwrap()
        })
    })
}

fn quoted_after(q: &str, marker: &str) -> Option<String> {
    let start = q.find(marker)? + marker.len();
    let rest = &q[start..];
    Some(rest[..rest.find('\'')?].to_owned())
}

fn multipart_parts(body: &[u8]) -> (serde_json::Value, Vec<u8>) {
    let text = body.to_vec();
    let marker = b"\r\n\r\n";
    let first = text.windows(4).position(|w| w == marker).unwrap() + 4;
    let meta_end = first
        + text[first..]
            .windows(4)
            .position(|w| w == b"\r\n--")
            .unwrap();
    let metadata = serde_json::from_slice(&text[first..meta_end]).unwrap();
    let second = meta_end
        + text[meta_end..]
            .windows(4)
            .position(|w| w == marker)
            .unwrap()
        + 4;
    let end = text.len() - b"\r\n--xdrive-boundary--\r\n".len();
    (metadata, text[second..end].to_vec())
}

impl FakeDrive {
    fn answer(&mut self, request: &Seen) -> Answer {
        if let Some((path, status, body)) = self.fail {
            if request.target.contains(path) {
                self.fail = None;
                return (status, vec![], body.as_bytes().to_vec());
            }
        }
        let path = request.target.split('?').next().unwrap().to_owned();
        let json = |value: serde_json::Value| (200, vec![], value.to_string().into_bytes());
        if path == "/token" {
            self.tokens += 1;
            return json(
                serde_json::json!({"access_token": format!("tok{}", self.tokens), "expires_in": self.lifetime.unwrap_or(3600)}),
            );
        }
        if request.header("authorization") != Some(&format!("Bearer tok{}", self.tokens)) {
            return (401, vec![], vec![]);
        }
        match (request.method.as_str(), path.as_str()) {
            ("GET", "/drive/v3/files") => {
                let q = query_value(&request.target, "q").unwrap();
                assert!(
                    q.starts_with("'folder-id' in parents and trashed = false and "),
                    "{q}"
                );
                let exact = quoted_after(&q, "name = '");
                let prefix = quoted_after(&q, "name contains '");
                let mut files: Vec<serde_json::Value> = self
                    .files
                    .iter()
                    .filter(|(_, (name, _, _))| {
                        exact.as_ref().is_some_and(|e| name == e)
                            || prefix.as_ref().is_some_and(|p| name.contains(p.as_str()))
                    })
                    .map(|(id, (name, description, _))| {
                        serde_json::json!({"id": id, "name": name, "description": description})
                    })
                    .collect();
                // Pages of `page` files, when set.
                let token: usize =
                    query_value(&request.target, "pageToken").map_or(0, |t| t.parse().unwrap());
                let mut answer = serde_json::json!({});
                if self.page > 0 && files.len() > token + self.page {
                    answer["nextPageToken"] = (token + self.page).to_string().into();
                }
                let end = if self.page > 0 {
                    (token + self.page).min(files.len())
                } else {
                    files.len()
                };
                files = files.drain(token.min(end)..end).collect();
                answer["files"] = files.into();
                json(answer)
            }
            ("POST", "/drive/v3/files") => {
                let meta: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(meta["parents"], serde_json::json!(["folder-id"]));
                self.next += 1;
                let id = format!("f{}", self.next);
                self.files.insert(
                    id.clone(),
                    (
                        meta["name"].as_str().unwrap().to_owned(),
                        meta["description"].as_str().unwrap_or_default().to_owned(),
                        Vec::new(),
                    ),
                );
                json(serde_json::json!({"id": id}))
            }
            ("POST", "/upload/drive/v3/files") => {
                let (meta, data) = multipart_parts(&request.body);
                self.next += 1;
                let id = format!("f{}", self.next);
                self.files.insert(
                    id.clone(),
                    (
                        meta["name"].as_str().unwrap().to_owned(),
                        String::new(),
                        data,
                    ),
                );
                json(serde_json::json!({"id": id, "name": meta["name"]}))
            }
            (method, path) => {
                let (kind, id) = if let Some(id) = path.strip_prefix("/upload/drive/v3/files/") {
                    ("upload", id.to_owned())
                } else if let Some(id) = path.strip_prefix("/drive/v3/files/") {
                    ("files", id.to_owned())
                } else {
                    return (404, vec![], vec![]);
                };
                let Some(file) = self.files.get_mut(&id) else {
                    return (404, vec![], vec![]);
                };
                match (method, kind) {
                    ("DELETE", "files") => {
                        self.files.remove(&id);
                        (204, vec![], vec![])
                    }
                    ("PATCH", "files") => {
                        let meta: serde_json::Value =
                            serde_json::from_slice(&request.body).unwrap();
                        file.1 = meta["description"].as_str().unwrap().to_owned();
                        json(serde_json::json!({"id": id}))
                    }
                    ("PATCH", "upload") => {
                        let (meta, data) = multipart_parts(&request.body);
                        file.1 = meta["description"].as_str().unwrap().to_owned();
                        file.2 = data;
                        json(serde_json::json!({"id": id}))
                    }
                    ("GET", "files") if request.target.contains("fields=description") => {
                        json(serde_json::json!({"description": file.1}))
                    }
                    ("GET", "files") if request.target.contains("alt=media") => {
                        (200, vec![], file.2.clone())
                    }
                    _ => (400, vec![], vec![]),
                }
            }
        }
    }
}

async fn drive_server() -> (Server, Arc<Mutex<FakeDrive>>) {
    let fake = Arc::new(Mutex::new(FakeDrive::default()));
    let state = Arc::clone(&fake);
    let server = serve(move |request, _| state.lock().unwrap().answer(request)).await;
    (server, fake)
}

fn drive(server: &Server) -> super::drive::DriveStorage {
    use super::drive::{DriveShared, DriveStorage, DriveUrls};
    let secrets = ["client id", "secret/+", "refresh"].map(|s| Zeroizing::new(s.to_owned()));
    let mut shared = DriveShared::new("folder-id", &secrets, Arc::new(http())).unwrap();
    let base = format!("http://{}", server.addr);
    shared.urls = DriveUrls {
        token: format!("{base}/token"),
        files: format!("{base}/drive/v3/files"),
        upload: format!("{base}/upload/drive/v3/files?uploadType=multipart&fields=id,name"),
    };
    shared.backoff = Duration::from_millis(2);
    let shared = Arc::new(shared);
    let session = shared.http.session();
    DriveStorage::new(shared, session)
}

#[tokio::test]
async fn drive_keeps_small_objects_in_descriptions_and_large_ones_as_media() {
    let (server, fake) = drive_server().await;
    let storage = drive(&server);
    storage
        .put("sessions/1-a", Bytes::from_static(b"data"))
        .await
        .unwrap();
    let large = vec![9u8; 12001];
    storage
        .put("streams/s/c2s/000000001.seg", Bytes::from(large.clone()))
        .await
        .unwrap();
    let seen = server.seen();
    let token = seen.iter().find(|s| s.target == "/token").unwrap();
    // url.Values.Encode: sorted and escaped.
    assert_eq!(
        String::from_utf8_lossy(&token.body),
        "client_id=client+id&client_secret=secret%2F%2B&grant_type=refresh_token&refresh_token=refresh"
    );
    let create = seen
        .iter()
        .find(|s| s.method == "POST" && s.target == "/drive/v3/files?fields=id")
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&create.body),
        r#"{"description":"ZGF0YQ==","name":"sessions~1-a","parents":["folder-id"]}"#
    );
    assert_eq!(
        create.header("content-type"),
        Some("application/json; charset=UTF-8")
    );
    let upload = seen
        .iter()
        .find(|s| s.target.starts_with("/upload/"))
        .unwrap();
    assert_eq!(
        upload.target,
        "/upload/drive/v3/files?uploadType=multipart&fields=id,name"
    );
    assert_eq!(
        upload.header("content-type"),
        Some("multipart/related; boundary=xdrive-boundary")
    );
    assert!(upload.body.starts_with(b"--xdrive-boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"name\":\"streams~s~c2s~000000001.seg\",\"parents\":[\"folder-id\"]}"));
    // Both read back: the inline one through its description.
    assert_eq!(
        storage.get("sessions/1-a").await.unwrap(),
        Bytes::from_static(b"data")
    );
    assert_eq!(
        storage.get("streams/s/c2s/000000001.seg").await.unwrap(),
        Bytes::from(large)
    );
    assert_eq!(storage.get("missing").await, Err(StorageError::NotFound));
    assert_eq!(fake.lock().unwrap().tokens, 1, "one token for all");
}

#[tokio::test]
async fn drive_lists_with_inline_data_across_pages_and_deletes_children() {
    let (server, fake) = drive_server().await;
    let storage = drive(&server);
    for (name, data) in [
        ("streams/s/s2c/000000001.seg", &b"one"[..]),
        ("streams/s/s2c/000000002.end", b""),
        ("streams/s/c2s/000000001.seg", b"up"),
        ("streams/t/s2c/000000001.seg", b"other"),
    ] {
        storage
            .put(name, Bytes::copy_from_slice(data))
            .await
            .unwrap();
    }
    fake.lock().unwrap().page = 1;
    let mut entries = storage.list("streams/s/s2c").await.unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["000000001.seg", "000000002.end"]);
    assert_eq!(entries[0].inline, Some(Bytes::from_static(b"one")));
    assert_eq!(
        entries[1].inline, None,
        "an empty description carries nothing"
    );
    assert!(
        server
            .seen()
            .iter()
            .any(|s| s.target.contains("pageToken=1")),
        "pages go on"
    );
    let streams: Vec<String> = storage
        .list("streams")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(streams.len(), 2, "{streams:?}");
    storage.delete("streams/s").await.unwrap();
    let left: Vec<String> = fake
        .lock()
        .unwrap()
        .files
        .values()
        .map(|f| f.0.clone())
        .collect();
    assert_eq!(left, ["streams~t~s2c~000000001.seg"]);
}

#[tokio::test]
async fn drive_refreshes_tokens_and_retries_rate_limits() {
    let (server, fake) = drive_server().await;
    let storage = drive(&server);
    storage.put("a", Bytes::from_static(b"x")).await.unwrap();
    // The token goes stale: a 401 fetches another.
    fake.lock().unwrap().tokens += 1;
    storage.put("b", Bytes::from_static(b"y")).await.unwrap();
    assert_eq!(
        server
            .seen()
            .iter()
            .filter(|s| s.target == "/token")
            .count(),
        2
    );
    fake.lock().unwrap().fail = Some((
        "/drive/v3/files",
        403,
        r#"{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}"#,
    ));
    storage.put("c", Bytes::from_static(b"z")).await.unwrap();
    fake.lock().unwrap().fail = Some((
        "/drive/v3/files",
        403,
        r#"{"error":{"errors":[{"reason":"forbidden"}]}}"#,
    ));
    assert!(storage.put("d", Bytes::from_static(b"w")).await.is_err());
    fake.lock().unwrap().fail = Some(("/drive/v3/files", 503, "busy"));
    storage.put("e", Bytes::from_static(b"v")).await.unwrap();
}

#[tokio::test]
async fn drive_tokens_past_gos_durations_run_out_at_once() {
    // An hour serves every request; int64's maximum, less the minute and
    // times a second, wraps to a minute ago, and a negative lifetime has
    // passed, so each request then asks for a token first.
    for (lifetime, every_request) in [(3600, false), (i64::MAX, true), (-5, true)] {
        let (server, fake) = drive_server().await;
        fake.lock().unwrap().lifetime = Some(lifetime);
        let storage = drive(&server);
        storage
            .put("sessions/1-a", Bytes::from_static(b"data"))
            .await
            .unwrap();
        assert_eq!(
            storage.get("sessions/1-a").await.unwrap(),
            Bytes::from_static(b"data")
        );
        let seen = server.seen();
        let tokens = seen.iter().filter(|s| s.target == "/token").count();
        let others = seen.len() - tokens;
        assert!(others >= 2, "{lifetime}");
        let want = if every_request { others } else { 1 };
        assert_eq!(tokens, want, "{lifetime}");
    }
}

#[tokio::test]
async fn drive_slots_take_descriptions_and_bodies_by_id() {
    use super::slots::SlotStore;
    let (server, fake) = drive_server().await;
    let storage = drive(&server);
    let id = storage.make_slot("streams/s/c2s/s0").await.unwrap();
    assert_eq!(fake.lock().unwrap().files[&id].0, "streams~s~c2s~s0");
    storage.set_slot(&id, "frame", None).await.unwrap();
    assert_eq!(storage.read_description(&id).await.unwrap(), "frame");
    storage
        .set_slot(&id, "frame2", Some(Bytes::from_static(b"body")))
        .await
        .unwrap();
    assert_eq!(storage.read_description(&id).await.unwrap(), "frame2");
    assert_eq!(
        storage.read_body(&id).await.unwrap(),
        Bytes::from_static(b"body")
    );
    let seen = server.seen();
    let json = seen
        .iter()
        .find(|s| s.method == "PATCH" && !s.target.starts_with("/upload/"))
        .unwrap();
    assert_eq!(
        json.target,
        format!("/drive/v3/files/{id}?fields=id&supportsAllDrives=true")
    );
    assert_eq!(
        String::from_utf8_lossy(&json.body),
        r#"{"description":"frame"}"#
    );
    let media = seen
        .iter()
        .find(|s| s.method == "PATCH" && s.target.starts_with("/upload/"))
        .unwrap();
    assert_eq!(
        media.target,
        format!(
            "/upload/drive/v3/files/{id}?uploadType=multipart&fields=id&supportsAllDrives=true"
        )
    );
    assert!(seen
        .iter()
        .any(|s| s.target == format!("/drive/v3/files/{id}?alt=media&supportsAllDrives=true")));
    assert_eq!(
        storage.read_description("nope").await,
        Err(StorageError::NotFound)
    );
    assert_eq!(
        storage.set_slot("nope", "x", None).await,
        Err(StorageError::NotFound)
    );
}

/// Replays the Drive scenario of `tools/xdrive-oracle/http_oracle_test.go`:
/// Xray-core's `driveStorage` calls one after another against canned
/// answers, each request compared with the one Xray-core sent.
#[tokio::test]
async fn drive_requests_match_xray_core() {
    use super::drive::{DriveShared, DriveStorage, DriveUrls};
    use super::slots::SlotStore;
    use base64::Engine as _;
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/xdrive/http-vectors.json"
    );
    let vectors: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let decode = |value: &serde_json::Value| match value.as_str() {
        Some(text) => base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap(),
        None => Vec::new(),
    };
    let want = vectors["drive"]["requests"].as_array().unwrap().clone();
    let answers: Vec<(u16, Vec<u8>)> = want
        .iter()
        .map(|r| {
            (
                r["status"].as_u64().unwrap() as u16,
                r["answer"].as_str().unwrap().as_bytes().to_vec(),
            )
        })
        .collect();
    let server = serve(move |_, index| {
        let (status, body) = answers
            .get(index)
            .cloned()
            .unwrap_or((500, b"no answer".to_vec()));
        (status, vec![], body)
    })
    .await;
    let secrets = ["client id", "secret/+", "refresh&"].map(|s| Zeroizing::new(s.to_owned()));
    let mut shared = DriveShared::new("folder'id\\", &secrets, Arc::new(http())).unwrap();
    let base = format!("http://{}", server.addr);
    shared.urls = DriveUrls {
        token: format!("{base}/token"),
        files: format!("{base}/drive/v3/files"),
        upload: format!("{base}/upload/drive/v3/files?uploadType=multipart&fields=id,name"),
    };
    shared.backoff = Duration::from_millis(1);
    let shared = Arc::new(shared);
    let storage = DriveStorage::new(Arc::clone(&shared), shared.http.session());
    for step in vectors["drive"]["steps"].as_array().unwrap() {
        let op = step["op"].as_str().unwrap();
        let name = step["name"].as_str().unwrap();
        let data = Bytes::from(decode(&step["data"]));
        let (result, names, error): (Vec<u8>, Vec<String>, bool) = match op {
            "put" => (
                Vec::new(),
                Vec::new(),
                storage.put(name, data).await.is_err(),
            ),
            "get" => match storage.get(name).await {
                Ok(bytes) => (bytes.to_vec(), Vec::new(), false),
                Err(_) => (Vec::new(), Vec::new(), true),
            },
            "list" => match storage.list(name).await {
                Ok(entries) => {
                    let mut names: Vec<String> = entries
                        .iter()
                        .map(|e| {
                            format!(
                                "{}={}",
                                e.name,
                                String::from_utf8_lossy(e.inline.as_deref().unwrap_or_default())
                            )
                        })
                        .collect();
                    names.sort();
                    (Vec::new(), names, false)
                }
                Err(_) => (Vec::new(), Vec::new(), true),
            },
            "delete" => (Vec::new(), Vec::new(), storage.delete(name).await.is_err()),
            "makeSlot" => match storage.make_slot(name).await {
                Ok(id) => (id.into_bytes(), Vec::new(), false),
                Err(_) => (Vec::new(), Vec::new(), true),
            },
            "setSlot" => (
                Vec::new(),
                Vec::new(),
                storage.set_slot(name, "frame", None).await.is_err(),
            ),
            "setSlotBody" => (
                Vec::new(),
                Vec::new(),
                storage.set_slot(name, "frame", Some(data)).await.is_err(),
            ),
            "readDescription" => match storage.read_description(name).await {
                Ok(d) => (d.into_bytes(), Vec::new(), false),
                Err(_) => (Vec::new(), Vec::new(), true),
            },
            "readBody" => match storage.read_body(name).await {
                Ok(b) => (b.to_vec(), Vec::new(), false),
                Err(_) => (Vec::new(), Vec::new(), true),
            },
            other => panic!("unknown op {other}"),
        };
        assert_eq!(result, decode(&step["result"]), "{op} {name}");
        let want_names: Vec<String> = step["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, want_names, "{op} {name}");
        assert_eq!(
            error,
            !step["error"].as_str().unwrap().is_empty(),
            "{op} {name}"
        );
    }
    let seen = server.seen();
    assert_eq!(seen.len(), want.len());
    for (got, want) in seen.iter().zip(&want) {
        let label = format!(
            "{} {}",
            want["op"].as_str().unwrap(),
            want["target"].as_str().unwrap()
        );
        assert_eq!(got.method, want["method"].as_str().unwrap(), "{label}");
        assert_eq!(got.target, want["target"].as_str().unwrap(), "{label}");
        assert_eq!(
            got.header("content-type").unwrap_or_default(),
            want["contentType"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(
            got.header("authorization").unwrap_or_default(),
            want["auth"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(got.body, decode(&want["body"]), "{label}");
    }
}
