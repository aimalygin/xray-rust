//! Replays `tests/fixtures/xdrive/http-vectors.json`, what Xray-core
//! v26.10.31 and the Go library under it make of the HTTP storages
//! (`tools/xdrive-oracle/http_oracle_test.go`): S3 URLs and signatures, S3
//! answers, templates, `subst`, JSON paths, Go's `regexp`, `net/url`
//! resolution and `http.Client` redirects.

use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use http::Method;
use serde_json::Value;
use sha2::{Digest, Sha256};
use xray_proxy::go_url;
use zeroize::Zeroizing;

use super::client::{Prepared, Progress, ServiceRequest, ServiceResponse, ServiceUrl};
use super::goregex::GoRegex;
use super::h2::{build_request, H2Connection};
use super::jsonpath::{json_number, json_string};
use super::redirect::{follow, new_request_url, Followed};
use super::s3::{parse_http_date, S3Shared, XdriveS3};
use super::template::{subst, OpTemplate, StorageTemplate};
use super::xml::{error_code, parse_list_page};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/xdrive/http-vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn text(value: &Value) -> String {
    value.as_str().unwrap().to_owned()
}

/// Pairs as Go wrote them, `null` for none.
fn pairs(value: &Value) -> Vec<(String, String)> {
    value
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|pair| (text(&pair[0]), text(&pair[1])))
        .collect()
}

fn sorted(mut pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    pairs.sort();
    pairs
}

/// Xray-core's errors name their package first.
fn xray_message(error: &str) -> &str {
    error
        .strip_prefix("transport/internet/xdrive: ")
        .unwrap_or(error)
}

#[test]
fn s3_urls_and_signatures_match_xray_core() {
    let vectors = vectors();
    let mut signed = 0;
    for case in vectors["s3"].as_array().unwrap() {
        let name = text(&case["name"]);
        let error = text(&case["error"]);
        let secrets: Vec<String> = case["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        // The configuration refuses what `ValidateS3Config` does; the corpus
        // of tests/fixtures/xdrive/config-verdicts.json holds those cases.
        if !error.is_empty() && !error.contains("S3 object") {
            continue;
        }
        let config = XdriveS3 {
            endpoint: text(&case["endpoint"]),
            region: text(&case["region"]),
            bucket: text(&case["bucket"]),
            path_style: case["pathStyle"].as_bool().unwrap(),
            remote_folder: text(&case["folder"]),
            access_key: Zeroizing::new(secrets[0].clone()),
            secret_key: Zeroizing::new(secrets[1].clone()),
            session_token: secrets.get(2).cloned().map(Zeroizing::new),
        };
        let shared = S3Shared::new(&config).unwrap_or_else(|e| panic!("{name}: {e}"));
        let object = text(&case["object"]);
        let key = if object.is_empty() {
            String::new()
        } else {
            match shared.object_key(&object) {
                Ok(key) => key,
                Err(got) => {
                    assert_eq!(got.to_string(), xray_message(&error), "{name}");
                    continue;
                }
            }
        };
        assert!(error.is_empty(), "{name}: Xray-core refused it: {error}");
        let query = pairs(&case["query"]);
        let query: Vec<(&str, &str)> = query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let url = shared.url(&key, &query);
        let scheme = if url.secure { "https" } else { "http" };
        assert_eq!(
            format!("{scheme}://{}{}", url.authority, url.target),
            text(&case["url"]),
            "{name}"
        );
        let method = Method::from_bytes(case["method"].as_str().unwrap().as_bytes()).unwrap();
        let body = text(&case["body"]);
        let hash: String = Sha256::digest(body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let content_type = (method == Method::PUT).then_some("application/octet-stream");
        let now = UNIX_EPOCH + Duration::from_secs(case["now"].as_u64().unwrap());
        let headers = shared.sign(&method, &url, content_type, &hash, now);
        assert_eq!(sorted(headers), sorted(pairs(&case["headers"])), "{name}");
        signed += 1;
    }
    assert!(signed >= 5, "{signed} signed cases");
}

#[test]
fn s3_answers_read_as_go_reads_them() {
    for case in vectors()["lists"].as_array().unwrap() {
        let payload = text(&case["payload"]);
        let page = parse_list_page(payload.as_bytes());
        assert_eq!(
            page.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{payload}: {page:?}"
        );
        if let Ok(page) = page {
            assert_eq!(
                page.is_truncated,
                case["truncated"].as_bool().unwrap(),
                "{payload}"
            );
            assert_eq!(
                page.next_continuation_token,
                text(&case["next"]),
                "{payload}"
            );
            let strings = |value: &Value| -> Vec<String> {
                value.as_array().unwrap().iter().map(text).collect()
            };
            assert_eq!(page.keys, strings(&case["keys"]), "{payload}");
            assert_eq!(page.prefixes, strings(&case["prefixes"]), "{payload}");
        }
        assert_eq!(
            error_code(payload.as_bytes()),
            text(&case["errorCode"]),
            "{payload}"
        );
    }
}

fn op_matches(got: &OpTemplate, want: &Value, template: &str) {
    assert_eq!(got.method, text(&want["method"]), "{template}");
    assert_eq!(got.url, text(&want["url"]), "{template}");
    assert_eq!(
        sorted(got.headers.clone()),
        pairs(&want["headers"]),
        "{template}"
    );
    assert_eq!(got.body, text(&want["body"]), "{template}");
    assert_eq!(got.names_regex, text(&want["namesRegex"]), "{template}");
    assert_eq!(got.href_path, text(&want["hrefPath"]), "{template}");
    assert_eq!(got.href_method, text(&want["hrefMethod"]), "{template}");
}

#[test]
fn templates_decode_and_check_as_xray_core_does() {
    for case in vectors()["templates"].as_array().unwrap() {
        let source = text(&case["template"]);
        let error = text(&case["error"]);
        match StorageTemplate::parse(&source) {
            Err(got) => {
                let want = xray_message(&error);
                assert!(!want.is_empty(), "{source}: refused here only: {got}");
                // Go's JSON and regexp errors read otherwise; their prefix is
                // Xray-core's.
                match ["invalid template", "bad namesRegex"]
                    .into_iter()
                    .find(|p| want.starts_with(p))
                {
                    Some(prefix) => assert!(got.starts_with(prefix), "{source}: {got} vs {want}"),
                    None => assert_eq!(got, want, "{source}"),
                }
            }
            Ok(template) => {
                assert!(error.is_empty(), "{source}: Xray-core refused it: {error}");
                assert_eq!(
                    template.flatten,
                    case["flatten"].as_bool().unwrap(),
                    "{source}"
                );
                assert_eq!(
                    template.concurrency as u64,
                    case["concurrency"].as_u64().unwrap(),
                    "{source}"
                );
                let auth = &template.auth;
                assert_eq!(auth.kind, text(&case["authType"]), "{source}");
                assert_eq!(
                    sorted(auth.header.clone()),
                    pairs(&case["authHeader"]),
                    "{source}"
                );
                assert_eq!(auth.username, text(&case["username"]), "{source}");
                assert_eq!(auth.password, text(&case["password"]), "{source}");
                assert_eq!(auth.token_url, text(&case["tokenUrl"]), "{source}");
                assert_eq!(sorted(auth.form.clone()), pairs(&case["form"]), "{source}");
                assert_eq!(auth.token_path, text(&case["tokenPath"]), "{source}");
                assert_eq!(auth.expiry_path, text(&case["expiryPath"]), "{source}");
                op_matches(&template.put, &case["put"], &source);
                op_matches(&template.get, &case["get"], &source);
                op_matches(&template.delete, &case["delete"], &source);
                op_matches(&template.list, &case["list"], &source);
                let status: Vec<i64> = case["retryStatus"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_i64().unwrap())
                    .collect();
                assert_eq!(template.retry_status, status, "{source}");
                assert_eq!(template.rate_reason, text(&case["rateReason"]), "{source}");
            }
        }
    }
}

#[test]
fn substitution_and_json_paths_match_xray_core() {
    let vectors = vectors();
    for case in vectors["subst"].as_array().unwrap() {
        let vars: Vec<(String, Zeroizing<String>)> = pairs(&case["vars"])
            .into_iter()
            .map(|(k, v)| (k, Zeroizing::new(v)))
            .collect();
        assert_eq!(
            subst(case["template"].as_str().unwrap(), &vars),
            text(&case["out"])
        );
    }
    for case in vectors["jsonPaths"].as_array().unwrap() {
        let payload = text(&case["payload"]);
        let path = text(&case["path"]);
        assert_eq!(
            json_string(payload.as_bytes(), &path),
            text(&case["string"]),
            "{payload} {path}"
        );
        assert_eq!(
            json_number(payload.as_bytes(), &path),
            case["number"].as_i64().unwrap(),
            "{payload} {path}"
        );
    }
}

#[test]
fn http_dates_match_go() {
    let vectors = vectors();
    let cases = vectors["httpDates"].as_array().unwrap();
    assert!(cases.len() > 70);
    for case in cases {
        let raw = case["raw"].as_str().unwrap();
        let want = case["ok"].as_bool().unwrap().then(|| {
            (
                case["unix"].as_i64().unwrap(),
                case["nanos"].as_u64().unwrap() as u32,
            )
        });
        assert_eq!(parse_http_date(raw), want, "{raw:?}");
    }
}

#[test]
fn names_regexes_match_go() {
    for case in vectors()["regexps"].as_array().unwrap() {
        let pattern = text(&case["pattern"]);
        let error = text(&case["error"]);
        match GoRegex::compile(&pattern) {
            Err(got) => assert_eq!(got, error, "{pattern}"),
            Ok(regex) => {
                assert!(error.is_empty(), "{pattern}: Go refused it: {error}");
                assert_eq!(
                    regex.num_subexp() as u64,
                    case["numSubexp"].as_u64().unwrap(),
                    "{pattern}"
                );
                for (text_case, want) in case["texts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .zip(case["matches"].as_array().unwrap())
                {
                    let got = regex.find_all_submatch(text_case.as_str().unwrap());
                    let want: Vec<Vec<String>> = want
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|groups| groups.as_array().unwrap().iter().map(text).collect())
                        .collect();
                    assert_eq!(got, want, "{pattern} on {text_case}");
                }
            }
        }
    }
}

#[test]
fn urls_resolve_as_net_url_does() {
    for case in vectors()["urls"].as_array().unwrap() {
        let base = text(&case["base"]);
        let reference = text(&case["ref"]);
        let got = go_url::parse(&base).and_then(|base| base.parse_reference(&reference));
        match got {
            Ok(url) => assert_eq!(
                url.to_go_string(),
                text(&case["resolved"]),
                "{base} + {reference:?}"
            ),
            Err(error) => assert_eq!(error, text(&case["error"]), "{base} + {reference:?}"),
        }
    }
}

/// What a hop sent, as Go's RoundTripper saw it without user information
/// or fragment.
fn hop_of(request: &ServiceRequest) -> (String, String, Vec<(String, String)>, String) {
    let scheme = if request.url.secure { "https" } else { "http" };
    (
        request.method.to_string(),
        format!("{scheme}://{}{}", request.url.authority, request.url.target),
        sorted(request.headers.clone()),
        String::from_utf8(request.body.to_vec()).unwrap(),
    )
}

fn go_hop(hop: &Value) -> (String, String, Vec<(String, String)>, String) {
    let url = go_url::parse(hop["url"].as_str().unwrap()).unwrap();
    (
        text(&hop["method"]),
        format!("{}://{}{}", url.scheme, url.host, url.request_uri()),
        sorted(pairs(&hop["headers"])),
        text(&hop["body"]),
    )
}

#[tokio::test]
async fn redirects_follow_go_clients() {
    for case in vectors()["redirects"].as_array().unwrap() {
        let name = text(&case["name"]);
        let answers: Vec<ServiceResponse> = case["answers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|answer| ServiceResponse {
                status: answer["status"].as_u64().unwrap() as u16,
                location: Some(text(&answer["location"])).filter(|l| !l.is_empty()),
                ..ServiceResponse::default()
            })
            .collect();
        let sent = Mutex::new(Vec::new());
        let initial = Followed {
            method: Method::from_bytes(case["method"].as_str().unwrap().as_bytes()).unwrap(),
            url: new_request_url(case["url"].as_str().unwrap()).unwrap(),
            headers: pairs(&case["headers"]),
            body: Bytes::from(text(&case["body"])),
            max_body: 1,
        };
        let result = follow(initial, |request| {
            let mut sent = sent.lock().unwrap();
            sent.push(hop_of(&request));
            let answer = answers[sent.len() - 1].clone();
            async move { Ok(answer) }
        })
        .await;
        let want: Vec<_> = case["hops"]
            .as_array()
            .unwrap()
            .iter()
            .map(go_hop)
            .collect();
        assert_eq!(sent.into_inner().unwrap(), want, "{name}");
        if case["error"].as_bool().unwrap() {
            assert!(result.is_err(), "{name}: {result:?}");
        } else {
            assert_eq!(
                result.unwrap().status as u64,
                case["status"].as_u64().unwrap(),
                "{name}"
            );
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// One HTTP/2 frame: type, flags, stream and payload.
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// The frames in `bytes` after the client preface, and whether the last
/// one ends the request.
fn frames(bytes: &[u8]) -> (Vec<Frame>, bool) {
    let mut frames = Vec::new();
    let mut rest = &bytes[24.min(bytes.len())..];
    while rest.len() >= 9 {
        let length =
            (usize::from(rest[0]) << 16) | (usize::from(rest[1]) << 8) | usize::from(rest[2]);
        if rest.len() < 9 + length {
            break;
        }
        let stream = u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]) & 0x7fff_ffff;
        frames.push(Frame {
            kind: rest[3],
            flags: rest[4],
            stream,
            payload: rest[9..9 + length].to_vec(),
        });
        rest = &rest[9 + length..];
    }
    let ended = frames
        .last()
        .is_some_and(|f| (f.kind == 0 || f.kind == 1) && f.flags & 0x1 != 0);
    (frames, ended)
}

#[tokio::test]
async fn h2_requests_frame_as_gos_client() {
    use tokio::io::AsyncReadExt;
    for case in vectors()["h2"].as_array().unwrap() {
        let name = format!("{} {}", text(&case["method"]), text(&case["url"]));
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let connection = H2Connection::handshake(Box::new(client), None)
            .await
            .unwrap();
        let request = ServiceRequest {
            method: Method::from_bytes(case["method"].as_str().unwrap().as_bytes()).unwrap(),
            url: ServiceUrl::parse(case["url"].as_str().unwrap()).unwrap(),
            headers: pairs(&case["headers"]),
            body: Bytes::from(vec![b'x'; case["bodyBytes"].as_u64().unwrap() as usize]),
            max_body: 1,
        };
        let regular: Vec<(String, String)> = sorted(
            build_request(&Prepared::new(&request))
                .unwrap()
                .headers()
                .iter()
                .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                .collect(),
        );
        assert_eq!(regular, pairs(&case["regular"]), "{name}");
        let exchange = tokio::spawn(async move {
            let _ = connection
                .send(&Prepared::new(&request), &Progress::new())
                .await;
        });
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 65536];
        while !frames(&bytes).1 {
            let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut chunk))
                .await
                .unwrap_or_else(|_| panic!("{name}: the request never ended"))
                .unwrap();
            assert!(n > 0, "{name}: the connection closed");
            bytes.extend_from_slice(&chunk[..n]);
        }
        exchange.abort();
        assert_eq!(&bytes[..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "{name}");
        let (frames, _) = frames(&bytes);
        let settings = frames
            .iter()
            .find(|f| f.kind == 4 && f.flags & 1 == 0)
            .unwrap();
        let got: Vec<(u64, u64)> = settings
            .payload
            .chunks(6)
            .map(|s| {
                (
                    u64::from(u16::from_be_bytes([s[0], s[1]])),
                    u64::from(u32::from_be_bytes([s[2], s[3], s[4], s[5]])),
                )
            })
            .collect();
        let want: Vec<(u64, u64)> = case["settings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| (s[0].as_u64().unwrap(), s[1].as_u64().unwrap()))
            .collect();
        assert_eq!(got, want, "{name}: SETTINGS");
        let update = frames
            .iter()
            .find(|f| f.kind == 8 && f.stream == 0)
            .unwrap();
        let increment = u32::from_be_bytes(update.payload[..4].try_into().unwrap()) & 0x7fff_ffff;
        assert_eq!(
            u64::from(increment),
            case["windowUpdate"].as_u64().unwrap(),
            "{name}: WINDOW_UPDATE"
        );
        let headers = frames.iter().find(|f| f.kind == 1).unwrap();
        let ours: String = headers.payload.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            headers
                .payload
                .starts_with(&unhex(case["pseudoHex"].as_str().unwrap())),
            "{name}: pseudo-headers {ours} vs Go's {}",
            text(&case["pseudoHex"])
        );
        assert_eq!(
            headers.flags & 1 != 0,
            case["endStream"].as_bool().unwrap(),
            "{name}: END_STREAM"
        );
        let data: Vec<(u64, bool)> = frames
            .iter()
            .filter(|f| f.kind == 0)
            .map(|f| (f.payload.len() as u64, f.flags & 1 != 0))
            .collect();
        let want: Vec<(u64, bool)> = case["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["length"].as_u64().unwrap(),
                    d["endStream"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(data, want, "{name}: DATA");
    }
}

fn bytes_of(value: &Value) -> Vec<u8> {
    use base64::Engine as _;
    match value.as_str() {
        Some(text) => base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap(),
        None => Vec::new(),
    }
}

#[test]
fn slot_frames_match_xray_core() {
    use super::slots::SlotFrame;
    let vectors = vectors();
    for case in vectors["slots"].as_array().unwrap() {
        let data = Bytes::from(bytes_of(&case["data"]));
        let frame = SlotFrame::new(
            case["seq"].as_i64().unwrap(),
            case["mode"].as_u64().unwrap() as u8,
            &data,
        );
        assert_eq!(frame.encode(), text(&case["encoded"]), "{case}");
    }
    for case in vectors["slotDecodes"].as_array().unwrap() {
        let description = text(&case["description"]);
        let decoded = SlotFrame::decode(&description);
        assert_eq!(
            decoded.is_some(),
            case["ok"].as_bool().unwrap(),
            "{description}"
        );
        if let Some(frame) = decoded {
            assert_eq!(frame.seq, case["seq"].as_i64().unwrap(), "{description}");
            assert_eq!(
                u64::from(frame.mode),
                case["mode"].as_u64().unwrap(),
                "{description}"
            );
            assert_eq!(
                u64::from(frame.size),
                case["size"].as_u64().unwrap(),
                "{description}"
            );
            assert_eq!(
                u64::from(frame.crc),
                case["crc"].as_u64().unwrap(),
                "{description}"
            );
            assert_eq!(
                frame.data.to_vec(),
                bytes_of(&case["data"]),
                "{description}"
            );
        }
    }
}

#[test]
fn rings_match_xray_core() {
    use super::slots::{Ring, SlotTable};
    for case in vectors()["rings"].as_array().unwrap() {
        let payload = text(&case["payload"]);
        let decoded = Ring::from_json(payload.as_bytes());
        assert_eq!(
            decoded.is_some(),
            case["ok"].as_bool().unwrap(),
            "{payload}"
        );
        let table = |value: &Value| SlotTable {
            slots: value[0].as_array().unwrap().iter().map(text).collect(),
            watermark: text(&value[1][0]),
        };
        if let Some(ring) = decoded {
            assert_eq!(ring.up, table(&case["up"]), "{payload}");
            assert_eq!(ring.down, table(&case["down"]), "{payload}");
            if let Some(marshal) = case["marshal"].as_str().filter(|m| !m.is_empty()) {
                assert_eq!(ring.to_json(), marshal);
            }
        }
    }
}

#[test]
fn drive_helpers_match_xray_core() {
    use super::drive::{multipart_body, quote_value, rate_limited};
    let drive = &vectors()["drive"];
    for pair in drive["quotes"].as_array().unwrap() {
        assert_eq!(quote_value(pair[0].as_str().unwrap()), text(&pair[1]));
    }
    assert_eq!(
        multipart_body(br#"{"name":"n"}"#, &[0, 1, 2]),
        bytes_of(&drive["multipart"])
    );
    for case in drive["rateLimited"].as_array().unwrap() {
        let payload = text(&case["payload"]);
        assert_eq!(
            rate_limited(payload.as_bytes()),
            case["limited"].as_bool().unwrap(),
            "{payload}"
        );
    }
}
