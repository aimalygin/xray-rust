//! Pure XHTTP request composition.
//!
//! This module owns the order-sensitive part of Xray's `Fill*Request` logic:
//! browser headers, payload placement, padding against the pre-metadata URL,
//! session/sequence metadata, then the streaming content type. HTTP engines
//! consume the result without reinterpreting its target or headers.

use std::collections::BTreeMap;

use rand::RngCore;
use thiserror::Error;

use super::super::{
    http_headers::{escape_decoded_path, HeaderMap},
    masquerade::apply_masquerade,
};
use super::config::{
    is_http_token, is_valid_raw_query, is_valid_serialized_fragment, XhttpConfig, XhttpEndpoint,
    XhttpMetadataConfig, XhttpMetadataPlacement, XhttpPaddingMethod, XhttpPaddingPlacement,
    XhttpUplinkDataPlacement,
};
use super::padding::{draw_range, generate_padding, PaddingError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpStreamBody {
    None,
    Streaming,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XhttpRequestBody {
    None,
    Bytes(Vec<u8>),
    Streaming,
}

#[derive(Debug, Clone)]
pub struct XhttpRequest {
    pub method: String,
    /// Escaped origin-form request target, including the query when present.
    pub target: String,
    pub headers: HeaderMap,
    pub body: XhttpRequestBody,
}

#[derive(Debug, Error)]
pub enum XhttpRequestError {
    #[error(transparent)]
    Padding(#[from] PaddingError),
    #[error("XHTTP uplink HTTP method must be a valid ASCII token")]
    InvalidMethod,
    #[error("XHTTP uplink chunk size must be positive")]
    ZeroChunkSize,
    #[error("XHTTP request query is not safe to serialize")]
    InvalidQuery,
}

pub fn compose_stream_request<R: RngCore + ?Sized>(
    config: &XhttpConfig,
    endpoint: &XhttpEndpoint,
    session_id: &str,
    body: XhttpStreamBody,
    rng: &mut R,
) -> Result<XhttpRequest, XhttpRequestError> {
    validate_query(config)?;
    let method = match body {
        XhttpStreamBody::None => "GET".to_owned(),
        XhttpStreamBody::Streaming => validated_uplink_method(config)?.to_owned(),
    };
    let mut parts = request_parts(config);

    let padding_base_url = absolute_url(endpoint, &parts);
    apply_padding(config, &padding_base_url, &mut parts, rng)?;
    apply_metadata(&config.session, session_id, &mut parts);

    if body == XhttpStreamBody::Streaming && !config.no_grpc_header {
        set_generated_header(&mut parts.headers, "Content-Type", "application/grpc");
    }

    Ok(XhttpRequest {
        method,
        target: parts.target(),
        headers: parts.headers,
        body: match body {
            XhttpStreamBody::None => XhttpRequestBody::None,
            XhttpStreamBody::Streaming => XhttpRequestBody::Streaming,
        },
    })
}

pub fn compose_packet_request<R: RngCore + ?Sized>(
    config: &XhttpConfig,
    endpoint: &XhttpEndpoint,
    session_id: &str,
    sequence: &str,
    payload: Vec<u8>,
    rng: &mut R,
) -> Result<XhttpRequest, XhttpRequestError> {
    validate_query(config)?;
    let method = validated_uplink_method(config)?.to_owned();
    let mut parts = request_parts(config);
    let body = place_packet_payload(config, payload, &mut parts.headers, rng)?;

    // Xray snapshots URL.String before padding and before either metadata
    // value. In particular, a Referer never exposes the session identifier.
    let padding_base_url = absolute_url(endpoint, &parts);
    apply_padding(config, &padding_base_url, &mut parts, rng)?;
    apply_metadata(&config.session, session_id, &mut parts);
    apply_metadata(&config.sequence, sequence, &mut parts);

    Ok(XhttpRequest {
        method,
        target: parts.target(),
        headers: parts.headers,
        body,
    })
}

fn validated_uplink_method(config: &XhttpConfig) -> Result<&str, XhttpRequestError> {
    if is_http_token(&config.uplink_http_method) {
        Ok(&config.uplink_http_method)
    } else {
        Err(XhttpRequestError::InvalidMethod)
    }
}

fn validate_query(config: &XhttpConfig) -> Result<(), XhttpRequestError> {
    if is_valid_raw_query(&config.raw_query) && is_valid_serialized_fragment(&config.fragment) {
        Ok(())
    } else {
        Err(XhttpRequestError::InvalidQuery)
    }
}

struct RequestParts {
    path: String,
    raw_query: String,
    fragment: String,
    headers: HeaderMap,
}

impl RequestParts {
    fn target(&self) -> String {
        let mut target = escape_decoded_path(&self.path);
        if !self.raw_query.is_empty() {
            target.push('?');
            target.push_str(&self.raw_query);
        }
        target
    }
}

fn request_parts(config: &XhttpConfig) -> RequestParts {
    let mut headers = config.headers.clone();
    apply_masquerade(&mut headers, "fetch");
    RequestParts {
        path: config.path.clone(),
        raw_query: config.raw_query.clone(),
        fragment: config.fragment.clone(),
        headers,
    }
}

fn absolute_url(endpoint: &XhttpEndpoint, parts: &RequestParts) -> String {
    let mut url = format!(
        "{}://{}{}",
        endpoint.scheme.as_str(),
        endpoint.authority,
        parts.target()
    );
    if !parts.fragment.is_empty() {
        url.push('#');
        url.push_str(&parts.fragment);
    }
    url
}

fn apply_padding<R: RngCore + ?Sized>(
    config: &XhttpConfig,
    padding_base_url: &str,
    parts: &mut RequestParts,
    rng: &mut R,
) -> Result<(), XhttpRequestError> {
    let length = draw_range(config.padding.range, rng)?;
    let (placement, key, header, method) = if config.padding.obfs_mode {
        (
            config.padding.placement,
            config.padding.key.as_str(),
            config.padding.header.as_str(),
            config.padding.method,
        )
    } else {
        (
            XhttpPaddingPlacement::QueryInHeader,
            "x_padding",
            "Referer",
            XhttpPaddingMethod::RepeatX,
        )
    };
    let padding = generate_padding(method, length, rng)?;

    match placement {
        XhttpPaddingPlacement::Cookie if !padding.is_empty() && !key.is_empty() => {
            add_cookie(&mut parts.headers, key, &padding);
        }
        XhttpPaddingPlacement::Header => {
            set_generated_header(&mut parts.headers, header, &padding);
        }
        XhttpPaddingPlacement::Query if !padding.is_empty() && !key.is_empty() => {
            parts.raw_query = set_query_value(&parts.raw_query, key.as_bytes(), padding.as_bytes());
        }
        XhttpPaddingPlacement::QueryInHeader => {
            // Go deliberately assigns RawQuery directly here instead of using
            // url.Values, so the configured key remains byte-for-byte.
            let (before_fragment, fragment) = padding_base_url
                .split_once('#')
                .map_or((padding_base_url, None), |(url, fragment)| {
                    (url, Some(fragment))
                });
            let base = before_fragment
                .split_once('?')
                .map_or(before_fragment, |(without_query, _)| without_query);
            let mut padded_url = format!("{base}?{key}={padding}");
            if let Some(fragment) = fragment {
                padded_url.push('#');
                padded_url.push_str(fragment);
            }
            set_generated_header(&mut parts.headers, header, &padded_url);
        }
        XhttpPaddingPlacement::Cookie | XhttpPaddingPlacement::Query => {}
    }
    Ok(())
}

fn apply_metadata(config: &XhttpMetadataConfig, value: &str, parts: &mut RequestParts) {
    if value.is_empty() {
        return;
    }

    match config.placement {
        XhttpMetadataPlacement::Path => {
            if !parts.path.ends_with('/') {
                parts.path.push('/');
            }
            parts.path.push_str(value);
        }
        XhttpMetadataPlacement::Cookie => add_cookie(&mut parts.headers, &config.key, value),
        XhttpMetadataPlacement::Header => {
            set_generated_header(&mut parts.headers, &config.key, value);
        }
        XhttpMetadataPlacement::Query => {
            parts.raw_query =
                set_query_value(&parts.raw_query, config.key.as_bytes(), value.as_bytes());
        }
    }
}

fn place_packet_payload<R: RngCore + ?Sized>(
    config: &XhttpConfig,
    payload: Vec<u8>,
    headers: &mut HeaderMap,
    rng: &mut R,
) -> Result<XhttpRequestBody, XhttpRequestError> {
    match config.uplink_data.placement {
        XhttpUplinkDataPlacement::Auto | XhttpUplinkDataPlacement::Body => {
            Ok(XhttpRequestBody::Bytes(payload))
        }
        XhttpUplinkDataPlacement::Header | XhttpUplinkDataPlacement::Cookie => {
            let encoded = base64url_no_padding(&payload);
            let mut offset = 0;
            let mut index = 0_u64;
            while offset < encoded.len() {
                let chunk_size = draw_range(config.uplink_data.chunk_size, rng)? as usize;
                if chunk_size == 0 {
                    return Err(XhttpRequestError::ZeroChunkSize);
                }
                let end = offset.saturating_add(chunk_size).min(encoded.len());
                let chunk = &encoded[offset..end];
                match config.uplink_data.placement {
                    XhttpUplinkDataPlacement::Header => set_generated_header(
                        headers,
                        &format!("{}-{index}", config.uplink_data.key),
                        chunk,
                    ),
                    XhttpUplinkDataPlacement::Cookie => add_cookie(
                        headers,
                        &format!("{}_{index}", config.uplink_data.key),
                        chunk,
                    ),
                    XhttpUplinkDataPlacement::Auto | XhttpUplinkDataPlacement::Body => {
                        unreachable!("body placements returned above")
                    }
                }
                offset = end;
                index += 1;
            }
            Ok(XhttpRequestBody::None)
        }
    }
}

fn set_generated_header(headers: &mut HeaderMap, name: &str, value: &str) {
    headers.set(&canonical_mime_header_name(name), value);
}

fn canonical_mime_header_name(name: &str) -> String {
    if !is_http_token(name) {
        return name.to_owned();
    }
    let mut output = String::with_capacity(name.len());
    let mut upper = true;
    for byte in name.bytes() {
        let byte = if upper {
            byte.to_ascii_uppercase()
        } else {
            byte.to_ascii_lowercase()
        };
        output.push(byte as char);
        upper = byte == b'-';
    }
    output
}

fn add_cookie(headers: &mut HeaderMap, name: &str, value: &str) {
    let name = name.replace(['\r', '\n'], "-");
    let mut value: String = value
        .bytes()
        .filter(|&byte| (0x20..0x7f).contains(&byte) && !matches!(byte, b'"' | b';' | b'\\'))
        .map(char::from)
        .collect();
    if value.contains([' ', ',']) {
        value = format!("\"{value}\"");
    }
    let pair = format!("{name}={value}");
    let cookie = match headers.get("Cookie") {
        Some(existing) if !existing.is_empty() => format!("{existing}; {pair}"),
        _ => pair,
    };
    headers.set("Cookie", &cookie);
}

fn set_query_value(raw_query: &str, key: &[u8], value: &[u8]) -> String {
    let mut values: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(key), Some(value)) = (
            decode_query_component(raw_key),
            decode_query_component(raw_value),
        ) else {
            continue;
        };
        values.entry(key).or_default().push(value);
    }
    values.insert(key.to_vec(), vec![value.to_vec()]);

    let mut encoded = String::new();
    for (key, values) in values {
        for value in values {
            if !encoded.is_empty() {
                encoded.push('&');
            }
            encoded.push_str(&encode_query_component(&key));
            encoded.push('=');
            encoded.push_str(&encode_query_component(&value));
        }
    }
    encoded
}

fn decode_query_component(raw: &str) -> Option<Vec<u8>> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let pair = bytes.get(index + 1..index + 3)?;
                decoded.push((hex(pair[0])? << 4) | hex(pair[1])?);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    Some(decoded)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_query_component(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for &byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else if byte == b' ' {
            encoded.push('+');
        } else {
            encoded.push('%');
            encoded.push(HEX[usize::from(byte >> 4)] as char);
            encoded.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    encoded
}

fn base64url_no_padding(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(input.len().saturating_add(2) / 3 * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[usize::from(a >> 2)] as char);
        encoded.push(ALPHABET[usize::from(((a & 0x03) << 4) | (b >> 4))] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[usize::from(((b & 0x0f) << 2) | (c >> 6))] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[usize::from(c & 0x3f)] as char);
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use rand::rngs::mock::StepRng;

    use super::*;
    use crate::stream::xhttp::config::{
        NormalizedRange, XhttpConfigInput, XhttpPaddingPlacement, XhttpRange, XhttpScheme,
    };

    fn config_with_padding(length: i32) -> XhttpConfig {
        let mut input = XhttpConfigInput {
            path: "/api?old=1".to_owned(),
            x_padding_bytes: XhttpRange::exact(length),
            ..XhttpConfigInput::default()
        };
        // A custom UA intentionally suppresses the dynamic browser block so
        // request-composer assertions stay independent of the wall clock.
        input.headers.set("User-Agent", "composer-test");
        XhttpConfig::normalize(input).unwrap()
    }

    #[test]
    fn xhttp_stream_composer_uses_pre_metadata_referer_and_ipv6_authority() {
        let config = config_with_padding(5);
        let endpoint = XhttpEndpoint::new(XhttpScheme::Https, "[2001:db8::1]:8443").unwrap();
        let mut rng = StepRng::new(0, 0);

        let request = compose_stream_request(
            &config,
            &endpoint,
            "session-id",
            XhttpStreamBody::None,
            &mut rng,
        )
        .unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/api/session-id?old=1");
        assert_eq!(
            request.headers.get("Referer"),
            Some("https://[2001:db8::1]:8443/api/?x_padding=XXXXX")
        );
        assert_eq!(request.headers.get("Content-Type"), None);
        assert_eq!(request.body, XhttpRequestBody::None);
    }

    #[test]
    fn xhttp_stream_composer_keeps_fragment_only_in_padding_absolute_url() {
        let endpoint = XhttpEndpoint::new(XhttpScheme::Https, "example.com").unwrap();
        for (path, target, referer) in [
            (
                "/api?x#frag",
                "/api/session?x",
                "https://example.com/api/?x_padding=XXXXX#frag",
            ),
            (
                "/api?x=%23frag",
                "/api/session?x=%23frag",
                "https://example.com/api/?x_padding=XXXXX",
            ),
            (
                "/api#decoded?x",
                "/api%23decoded/session?x",
                "https://example.com/api%23decoded/?x_padding=XXXXX",
            ),
        ] {
            let mut input = XhttpConfigInput {
                path: path.to_owned(),
                x_padding_bytes: XhttpRange::exact(5),
                ..XhttpConfigInput::default()
            };
            input.headers.set("User-Agent", "composer-test");
            let config = XhttpConfig::normalize(input).unwrap();
            let mut rng = StepRng::new(0, 0);
            let request = compose_stream_request(
                &config,
                &endpoint,
                "session",
                XhttpStreamBody::None,
                &mut rng,
            )
            .unwrap();
            assert_eq!(request.target, target, "path {path:?}");
            assert_eq!(
                request.headers.get("Referer"),
                Some(referer),
                "path {path:?}"
            );
        }
    }

    #[test]
    fn xhttp_stream_composer_sets_grpc_header_only_for_streaming_body() {
        let mut config = config_with_padding(5);
        config.uplink_http_method = "M-SEARCH*".to_owned();
        let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.com").unwrap();
        let mut rng = StepRng::new(0, 0);

        let request =
            compose_stream_request(&config, &endpoint, "", XhttpStreamBody::Streaming, &mut rng)
                .unwrap();
        assert_eq!(request.method, "M-SEARCH*");
        assert_eq!(
            request.headers.get("Content-Type"),
            Some("application/grpc")
        );
        assert_eq!(request.body, XhttpRequestBody::Streaming);

        config.no_grpc_header = true;
        let request =
            compose_stream_request(&config, &endpoint, "", XhttpStreamBody::Streaming, &mut rng)
                .unwrap();
        assert_eq!(request.headers.get("Content-Type"), None);
    }

    #[test]
    fn xhttp_packet_composer_applies_query_metadata_in_sorted_go_order() {
        let mut config = config_with_padding(5);
        config.session = XhttpMetadataConfig {
            placement: XhttpMetadataPlacement::Header,
            key: "x-session-id".to_owned(),
        };
        config.sequence = XhttpMetadataConfig {
            placement: XhttpMetadataPlacement::Query,
            key: "x_seq".to_owned(),
        };
        let endpoint = XhttpEndpoint::new(XhttpScheme::Https, "example.com").unwrap();
        let mut rng = StepRng::new(0, 0);

        let request = compose_packet_request(
            &config,
            &endpoint,
            "session",
            "9",
            b"payload".to_vec(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(request.target, "/api/?old=1&x_seq=9");
        assert_eq!(request.headers.get("X-Session-Id"), Some("session"));
        assert_eq!(request.body, XhttpRequestBody::Bytes(b"payload".to_vec()));
    }

    #[test]
    fn xhttp_custom_session_id_uses_target_placement_and_key_encoding() {
        let endpoint = XhttpEndpoint::new(XhttpScheme::Https, "example.com").unwrap();
        for (placement, key, expected_target, expected_header) in [
            (
                XhttpMetadataPlacement::Path,
                "ignored",
                "/api/a/b%20c?old=1",
                None,
            ),
            (
                XhttpMetadataPlacement::Query,
                "sid",
                "/api/?old=1&sid=a%2Fb+c",
                None,
            ),
            (
                XhttpMetadataPlacement::Header,
                "X-Custom-Sid",
                "/api/?old=1",
                Some(("X-Custom-Sid", "a/b c")),
            ),
            (
                XhttpMetadataPlacement::Cookie,
                "sid",
                "/api/?old=1",
                Some(("Cookie", "sid=\"a/b c\"")),
            ),
        ] {
            let mut config = config_with_padding(5);
            config.session = XhttpMetadataConfig {
                placement,
                key: key.to_owned(),
            };
            let mut rng = StepRng::new(0, 0);
            let request = compose_stream_request(
                &config,
                &endpoint,
                "a/b c",
                XhttpStreamBody::None,
                &mut rng,
            )
            .unwrap();

            assert_eq!(request.target, expected_target, "placement={placement:?}");
            if let Some((header, value)) = expected_header {
                assert_eq!(
                    request.headers.get(header),
                    Some(value),
                    "placement={placement:?}"
                );
            }
        }
    }

    #[test]
    fn xhttp_request_path_and_padding_base_follow_metadata_placement() {
        let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.test").unwrap();
        for (session_placement, seq_placement, expected_target, expected_referer) in [
            (
                XhttpMetadataPlacement::Query,
                XhttpMetadataPlacement::Header,
                "/stream?sid=session",
                "http://example.test/stream?x_padding=X",
            ),
            (
                XhttpMetadataPlacement::Path,
                XhttpMetadataPlacement::Header,
                "/stream/session",
                "http://example.test/stream/?x_padding=X",
            ),
            (
                XhttpMetadataPlacement::Query,
                XhttpMetadataPlacement::Path,
                "/stream/9?sid=session",
                "http://example.test/stream/?x_padding=X",
            ),
        ] {
            let mut input = XhttpConfigInput {
                path: "/stream".to_owned(),
                x_padding_bytes: XhttpRange::exact(1),
                session_placement,
                session_key: "sid".to_owned(),
                seq_placement,
                seq_key: "X-Seq".to_owned(),
                ..XhttpConfigInput::default()
            };
            input.headers.set("User-Agent", "composer-test");
            let config = XhttpConfig::normalize(input).unwrap();
            let mut rng = StepRng::new(0, 0);
            let request =
                compose_packet_request(&config, &endpoint, "session", "9", Vec::new(), &mut rng)
                    .unwrap();

            assert_eq!(
                request.target, expected_target,
                "session={session_placement:?} seq={seq_placement:?}"
            );
            assert_eq!(
                request.headers.get("Referer"),
                Some(expected_referer),
                "session={session_placement:?} seq={seq_placement:?}"
            );
        }
    }

    #[test]
    fn xhttp_packet_composer_chunks_base64url_into_headers_and_cookies() {
        let payload: Vec<u8> = (0_u8..100).collect();
        let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.com:8080").unwrap();

        for placement in [
            XhttpUplinkDataPlacement::Header,
            XhttpUplinkDataPlacement::Cookie,
        ] {
            let mut config = config_with_padding(5);
            config.uplink_data.placement = placement;
            config.uplink_data.key = if placement == XhttpUplinkDataPlacement::Header {
                "x-data".to_owned()
            } else {
                "x_data".to_owned()
            };
            config.uplink_data.chunk_size = NormalizedRange::exact(64);
            let mut rng = StepRng::new(0, 0);
            let request =
                compose_packet_request(&config, &endpoint, "", "", payload.clone(), &mut rng)
                    .unwrap();
            assert_eq!(request.body, XhttpRequestBody::None);
            if placement == XhttpUplinkDataPlacement::Header {
                assert_eq!(request.headers.get("X-Data-0").unwrap().len(), 64);
                assert_eq!(request.headers.get("X-Data-1").unwrap().len(), 64);
                assert_eq!(request.headers.get("X-Data-2").unwrap().len(), 6);
            } else {
                let cookie = request.headers.get("Cookie").unwrap();
                assert!(cookie.contains("x_data_0="));
                assert!(cookie.contains("; x_data_1="));
                assert!(cookie.contains("; x_data_2="));
            }
        }
    }

    #[test]
    fn xhttp_padding_obfs_placements_and_non_obfs_override_match_xray() {
        let endpoint = XhttpEndpoint::new(XhttpScheme::Https, "example.com").unwrap();
        for placement in [
            XhttpPaddingPlacement::Cookie,
            XhttpPaddingPlacement::Header,
            XhttpPaddingPlacement::Query,
            XhttpPaddingPlacement::QueryInHeader,
        ] {
            let mut config = config_with_padding(5);
            config.padding.obfs_mode = true;
            config.padding.placement = placement;
            config.padding.key = "pad".to_owned();
            config.padding.header = "x-pad".to_owned();
            let mut rng = StepRng::new(0, 0);
            let request =
                compose_stream_request(&config, &endpoint, "", XhttpStreamBody::None, &mut rng)
                    .unwrap();
            match placement {
                XhttpPaddingPlacement::Cookie => {
                    assert_eq!(request.headers.get("Cookie"), Some("pad=XXXXX"));
                }
                XhttpPaddingPlacement::Header => {
                    assert_eq!(request.headers.get("X-Pad"), Some("XXXXX"));
                }
                XhttpPaddingPlacement::Query => {
                    assert_eq!(request.target, "/api/?old=1&pad=XXXXX");
                }
                XhttpPaddingPlacement::QueryInHeader => {
                    assert_eq!(
                        request.headers.get("X-Pad"),
                        Some("https://example.com/api/?pad=XXXXX")
                    );
                }
            }
        }

        let mut config = config_with_padding(5);
        config.padding.placement = XhttpPaddingPlacement::Header;
        config.padding.key = "ignored".to_owned();
        config.padding.header = "X-Ignored".to_owned();
        let mut rng = StepRng::new(0, 0);
        let request =
            compose_stream_request(&config, &endpoint, "", XhttpStreamBody::None, &mut rng)
                .unwrap();
        assert_eq!(request.headers.get("X-Ignored"), None);
        assert_eq!(
            request.headers.get("Referer"),
            Some("https://example.com/api/?x_padding=XXXXX")
        );
    }

    #[test]
    fn xhttp_composer_defensively_rejects_mutated_invalid_method() {
        let mut config = config_with_padding(5);
        config.uplink_http_method = "POST\r\nX-Evil: 1".to_owned();
        let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.com").unwrap();
        let mut rng = StepRng::new(0, 0);
        assert!(matches!(
            compose_packet_request(&config, &endpoint, "", "", Vec::new(), &mut rng),
            Err(XhttpRequestError::InvalidMethod)
        ));

        config.uplink_http_method = "POST".to_owned();
        config.raw_query = "ok=1\r\nX-Evil: 1".to_owned();
        assert!(matches!(
            compose_packet_request(&config, &endpoint, "", "", Vec::new(), &mut rng),
            Err(XhttpRequestError::InvalidQuery)
        ));
    }
}
