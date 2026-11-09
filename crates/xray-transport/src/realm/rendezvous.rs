//! The rendezvous call Xray-core's realm client makes with Go's
//! `net/http`: `POST /v1/{name}/connect` with the token as a bearer and the
//! client's addresses, nonce and key as JSON, answered by the server's
//! addresses. HTTP/1.1 here, where Go's client may negotiate HTTP/2 over
//! TLS; the request is written as Go writes one over HTTP/1.1.
use std::{net::SocketAddr, time::Duration};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{punch::PunchMetadata, RealmConfig, RealmEnv, RealmError, RealmScheme};
use crate::{
    connect_tcp_dual_stack,
    stream::{
        http_headers::{serialize_request_with_framing, H1BodyFraming},
        xhttp::h1::PendingResponse,
        HeaderMap,
    },
    utls_tls::TlsAlpnPolicy,
    BoxedTransportStream,
};

/// Go's client waits for good; the rendezvous holds a connect for up to
/// ten seconds while the server answers.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// What a successful answer may take, compressed or not.
const MAX_BODY: usize = 1 << 20;
/// `maxErrorBodySize`.
const MAX_ERROR_BODY: usize = 64 * 1024;

/// `Client.Connect`: the server's addresses as the rendezvous lists them.
pub(super) async fn connect(
    config: &RealmConfig,
    env: &RealmEnv,
    addresses: &[String],
    meta: &PunchMetadata,
) -> Result<Vec<String>, RealmError> {
    tokio::time::timeout(REQUEST_TIMEOUT, exchange(config, env, addresses, meta))
        .await
        .map_err(|_| RealmError::Rendezvous("the rendezvous did not answer in time".into()))?
}

async fn exchange(
    config: &RealmConfig,
    env: &RealmEnv,
    addresses: &[String],
    meta: &PunchMetadata,
) -> Result<Vec<String>, RealmError> {
    let candidates = resolve_host(config, env).await?;
    // As Go's dialer reaches it.
    let tcp = connect_tcp_dual_stack(&candidates, env.protector.as_deref())
        .await
        .map_err(|error| RealmError::Rendezvous(format!("connecting: {error}")))?;
    let mut stream: BoxedTransportStream = match (&config.scheme, &config.tls) {
        (RealmScheme::Http, _) => Box::new(tcp),
        (RealmScheme::Https, Some(tls)) => {
            let prepared = env
                .tls
                .prepare_stream(tls, TlsAlpnPolicy::Http1Upgrade)
                .map_err(|error| RealmError::Rendezvous(format!("TLS: {error}")))?;
            env.tls
                .connect_prepared_stream(Box::new(tcp), prepared)
                .await
                .map_err(|error| RealmError::Rendezvous(format!("TLS: {error}")))?
        }
        (RealmScheme::Https, None) => {
            return Err(RealmError::Rendezvous("no TLS settings".into()));
        }
    };
    let body = connect_body(addresses, meta);
    let mut request = request_head(config, body.len());
    request.extend_from_slice(&body);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let (status, mut response) = PendingResponse::new(stream)
        .for_request_method("POST")
        .open_with_status()
        .await
        .map_err(|error| RealmError::Rendezvous(error.to_string()))?;
    let gzip = response
        .content_encoding()
        .is_some_and(|value| value.eq_ignore_ascii_case(b"gzip"));
    if status != 200 {
        let body = read_body(&mut response, MAX_ERROR_BODY, gzip, false).await?;
        return Err(status_error(status, &body));
    }
    let body = read_body(&mut response, MAX_BODY, gzip, true).await?;
    decode_connect_response(&body)
}

/// The rendezvous's addresses: an IP address as it is, a name through the
/// dial's resolver.
async fn resolve_host(config: &RealmConfig, env: &RealmEnv) -> Result<Vec<SocketAddr>, RealmError> {
    if let Ok(ip) = config.host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, config.port)]);
    }
    let name = if config.host.is_ascii() {
        config.host.clone()
    } else {
        idna::domain_to_ascii(&config.host)
            .map_err(|_| RealmError::Rendezvous(format!("invalid host {:?}", config.host)))?
    };
    let lookup = env
        .resolver
        .resolve_all(&name, config.port)
        .await
        .map_err(|error| RealmError::Rendezvous(format!("resolving {name}: {error}")))?;
    Ok(lookup.socket_addrs().to_vec())
}

/// `POST` and the path `newRequest` builds: the name through
/// `url.PathEscape`, and again through the escaping `URL.String` applies
/// to a path, as Go's client sends it.
pub(super) fn request_path(id: &str) -> String {
    let segment = go_escape(go_escape(id.as_bytes(), true).as_bytes(), false);
    format!("/v1/{segment}/connect")
}

/// The head Go's `Request.write` produces: `Host` from the URL, its
/// `User-Agent`, the body's length, the header map sorted, then the
/// transport's `Accept-Encoding`.
pub(super) fn request_head(config: &RealmConfig, body_len: usize) -> Vec<u8> {
    let mut headers = HeaderMap::new();
    headers.set(
        "Authorization",
        &format!("Bearer {}", config.token.as_str()),
    );
    headers.set("Content-Type", "application/json");
    let host = join_host_port(&config.host, &config.port_text);
    let mut head = serialize_request_with_framing(
        "POST",
        &request_path(&config.id),
        &host,
        &headers,
        H1BodyFraming::ContentLength(body_len as u64),
    );
    head.truncate(head.len() - 2);
    head.extend_from_slice(b"Accept-Encoding: gzip\r\n\r\n");
    head
}

/// `net.JoinHostPort`.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Go's `url` escaping of a path segment, or of a path.
fn go_escape(input: &[u8], segment: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || match byte {
                b'$' | b'&' | b'+' | b':' | b'=' | b'@' => true,
                b'/' | b';' | b',' => !segment,
                _ => false,
            };
        if keep {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `json.Marshal(ConnectRequest)`: the addresses, then the embedded
/// metadata's nonce and key.
pub(super) fn connect_body(addresses: &[String], meta: &PunchMetadata) -> Vec<u8> {
    let mut body = String::from("{\"addresses\":[");
    for (i, address) in addresses.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        push_json_string(&mut body, address);
    }
    body.push_str("],\"nonce\":");
    push_json_string(&mut body, &meta.nonce_hex());
    body.push_str(",\"obfs\":");
    push_json_string(&mut body, &meta.obfs_hex());
    body.push('}');
    body.into_bytes()
}

/// A string as `encoding/json` writes one, HTML characters escaped.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The body, gunzipped when the server compressed it, as Go's transport
/// does after asking for gzip. A successful answer is read until its first
/// JSON value is complete, as `json.Decoder` stops there.
async fn read_body(
    response: &mut (impl tokio::io::AsyncRead + Unpin),
    limit: usize,
    gzip: bool,
    until_value: bool,
) -> Result<Vec<u8>, RealmError> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = response.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > limit {
            if until_value || gzip {
                return Err(RealmError::Rendezvous("the answer is too long".into()));
            }
            body.truncate(limit);
            break;
        }
        if until_value && !gzip && first_value_complete(&body) {
            break;
        }
    }
    if !gzip {
        return Ok(body);
    }
    let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(body.as_slice());
    decoder.multiple_members(true);
    let mut plain = Vec::new();
    (&mut decoder)
        .take(limit as u64 + 1)
        .read_to_end(&mut plain)
        .await
        .map_err(|error| RealmError::Rendezvous(format!("gzip: {error}")))?;
    if plain.len() > limit {
        return Err(RealmError::Rendezvous("the answer is too long".into()));
    }
    Ok(plain)
}

/// Whether the bytes hold a whole first JSON value, or an error past which
/// more bytes cannot help.
fn first_value_complete(body: &[u8]) -> bool {
    match serde_json::Deserializer::from_slice(body)
        .into_iter::<Value>()
        .next()
    {
        None => false,
        Some(Ok(_)) => true,
        Some(Err(error)) => !error.is_eof(),
    }
}

/// `decodeStatusError`: the status, and the error and message the body
/// carries when it decodes.
fn status_error(status: u16, body: &[u8]) -> RealmError {
    let fields = serde_json::Deserializer::from_slice(body)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok);
    let text = |key: &str| {
        fields
            .as_ref()
            .and_then(|value| go_field(value, key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let (error, message) = (text("error"), text("message"));
    RealmError::Status {
        status,
        detail: if error.is_empty() && message.is_empty() {
            String::new()
        } else {
            format!(": {error}: {message}")
        },
    }
}

/// A struct field as `encoding/json` finds it: the exact key, else one
/// equal under case folding.
fn go_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let object = value.as_object()?;
    object.get(key).or_else(|| {
        object
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    })
}

/// `json.NewDecoder(body).Decode(&ConnectResponse{})`: the first JSON
/// value, null or an object whose `addresses` is null or strings and whose
/// `nonce` and `obfs` are strings when present.
pub(super) fn decode_connect_response(body: &[u8]) -> Result<Vec<String>, RealmError> {
    let invalid = |why: &str| RealmError::Rendezvous(format!("invalid answer: {why}"));
    let value = serde_json::Deserializer::from_slice(body)
        .into_iter::<Value>()
        .next()
        .ok_or_else(|| invalid("empty body"))?
        .map_err(|error| invalid(&error.to_string()))?;
    let object = match &value {
        Value::Null => return Ok(Vec::new()),
        Value::Object(_) => &value,
        _ => return Err(invalid("not an object")),
    };
    for key in ["nonce", "obfs"] {
        if go_field(object, key).is_some_and(|value| !value.is_null() && !value.is_string()) {
            return Err(invalid("nonce and obfs are strings"));
        }
    }
    match go_field(object, "addresses") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Null => Ok(String::new()),
                Value::String(address) => Ok(address.clone()),
                _ => Err(invalid("addresses are strings")),
            })
            .collect(),
        Some(_) => Err(invalid("addresses are strings")),
    }
}

#[cfg(test)]
mod tests;
