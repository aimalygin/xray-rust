//! RAW's `header` of type `http`, read as Xray-core's `TCPConfig` and HTTP
//! `Authenticator` read it.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, RawHttpHeader, StreamTransport};

fn vless(stream: Value) -> Value {
    json!({"outbounds": [{
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": "192.168.1.10",
            "port": 80,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]
        }]},
        "streamSettings": stream
    }]})
}

fn header_of(raw: &Value) -> Option<RawHttpHeader> {
    let parsed =
        parse_xray_json(&raw.to_string()).unwrap_or_else(|error| panic!("{raw}: {error:?}"));
    let stream = &parsed.config.outbounds[0].stream;
    stream.raw_http_header.clone()
}

fn error_paths(raw: &Value) -> Vec<String> {
    parse_xray_json(&raw.to_string())
        .expect_err("config must be refused")
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .filter_map(|diagnostic| diagnostic.path)
        .collect()
}

#[test]
fn an_http_header_with_its_request_is_read_as_xray_builds_it() {
    let raw = vless(json!({
        "network": "tcp",
        "tcpSettings": {"header": {
            "type": "http",
            "request": {
                "version": "1.1",
                "method": "GET",
                "path": ["/", "/video"],
                "headers": {
                    "Host": ["www.example.com", "cdn.example.com"],
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": ["keep-alive"]
                }
            },
            "response": {
                "version": "1.1",
                "status": "200",
                "reason": "OK",
                "headers": {"Content-Type": ["application/octet-stream", "video/mpeg"]}
            }
        }}
    }));
    assert_eq!(
        header_of(&raw),
        Some(RawHttpHeader {
            method: "GET".to_owned(),
            version: "1.1".to_owned(),
            paths: vec!["/".to_owned(), "/video".to_owned()],
            // Sorted by name, and a string value split at commas, as Go's
            // StringList splits it.
            headers: Some(vec![
                (
                    "Accept-Encoding".to_owned(),
                    vec!["gzip".to_owned(), " deflate".to_owned()]
                ),
                ("Connection".to_owned(), vec!["keep-alive".to_owned()]),
                (
                    "Host".to_owned(),
                    vec!["www.example.com".to_owned(), "cdn.example.com".to_owned()]
                ),
            ]),
        })
    );
}

#[test]
fn an_empty_request_takes_xrays_defaults_and_raw_settings_win() {
    let raw = vless(json!({"network": "raw", "rawSettings": {"header": {"type": "http"}}}));
    assert_eq!(
        header_of(&raw),
        Some(RawHttpHeader {
            method: "GET".to_owned(),
            version: "1.1".to_owned(),
            paths: vec!["/".to_owned()],
            headers: None,
        })
    );

    let raw = vless(json!({
        "network": "tcp",
        "rawSettings": {"header": {"type": "none"}},
        "tcpSettings": {"header": {"type": "http"}}
    }));
    assert_eq!(header_of(&raw), None);

    let raw = vless(json!({
        "network": "tcp",
        "tcpSettings": {"header": {"type": "http", "request": {"path": "/a,/b", "method": ""}}}
    }));
    let header = header_of(&raw).unwrap();
    assert_eq!(header.paths, ["/a", "/b"]);
    assert_eq!(header.method, "GET");
}

#[test]
fn an_http_header_on_another_transport_is_inert() {
    let raw = vless(json!({
        "network": "ws",
        "tcpSettings": {"header": {"type": "http"}}
    }));
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    assert!(matches!(stream.transport, StreamTransport::WebSocket(_)));
    assert_eq!(stream.raw_http_header, None);
}

#[test]
fn malformed_requests_and_responses_fail() {
    let base = "$.outbounds[0].streamSettings.tcpSettings.header";
    for (header, path) in [
        (
            json!({"type": "http", "request": "GET"}),
            format!("{base}.request"),
        ),
        (
            json!({"type": "http", "request": {"uri": "/"}}),
            format!("{base}.request.uri"),
        ),
        (
            json!({"type": "http", "request": {"method": 1}}),
            format!("{base}.request.method"),
        ),
        (
            json!({"type": "http", "request": {"path": ["/a\r\nX-Injected: 1"]}}),
            format!("{base}.request.path[0]"),
        ),
        (
            json!({"type": "http", "request": {"headers": {"Host": null}}}),
            format!("{base}.request.headers.Host"),
        ),
        (
            json!({"type": "http", "request": {"headers": {"": ["x"]}}}),
            format!("{base}.request.headers."),
        ),
        (
            json!({"type": "http", "request": {"headers": {"Host": ["a\nb"]}}}),
            format!("{base}.request.headers.Host[0]"),
        ),
        (
            json!({"type": "http", "response": {"status": 200}}),
            format!("{base}.response.status"),
        ),
        (
            json!({"type": "http", "response": {"headers": []}}),
            format!("{base}.response.headers"),
        ),
        (json!({"type": "HTTP"}), format!("{base}.type")),
    ] {
        let raw = vless(json!({"network": "tcp", "tcpSettings": {"header": header}}));
        assert_eq!(error_paths(&raw), [path], "{header}");
    }
}
