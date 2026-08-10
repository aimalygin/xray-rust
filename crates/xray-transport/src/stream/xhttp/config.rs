//! Dial-independent XHTTP configuration normalization.
//!
//! The JSON layer preserves Xray's config-build values, including zero ranges.
//! This module applies the later `splithttp.Config.GetNormalized*` defaults so
//! every request sees one immutable, concrete policy. It intentionally does
//! not interpret `serverMaxHeaderBytes`: that is an inbound server setting;
//! the client HTTP engines enforce their own defensive response-head limit.

use std::net::{Ipv4Addr, Ipv6Addr};

use http::uri::Authority;
use thiserror::Error;

use super::super::http_headers::HeaderMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpScheme {
    Http,
    Https,
}

impl XhttpScheme {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// The authority after the outbound has applied Xray's
/// `host > serverName > destination` precedence.
///
/// The core mapping owns address formatting: IPv6 literals arrive bracketed,
/// and a port is present exactly when that mapping says the HTTP authority
/// needs one. Keeping the already-resolved string avoids a second, subtly
/// different host/port policy in the composer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpEndpoint {
    pub scheme: XhttpScheme,
    pub authority: String,
}

impl XhttpEndpoint {
    pub fn new(
        scheme: XhttpScheme,
        authority: impl Into<String>,
    ) -> Result<Self, XhttpConfigError> {
        let authority = authority.into();
        if authority.is_empty() {
            return Err(XhttpConfigError::EmptyAuthority);
        }
        let authority =
            normalize_authority(&authority).ok_or(XhttpConfigError::InvalidAuthority)?;
        Ok(Self { scheme, authority })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XhttpRange {
    pub from: i32,
    pub to: i32,
}

impl XhttpRange {
    pub const fn exact(value: i32) -> Self {
        Self {
            from: value,
            to: value,
        }
    }

    fn ordered(self) -> Self {
        Self {
            from: self.from.min(self.to),
            to: self.from.max(self.to),
        }
    }
}

/// A non-negative range ready for Go's half-open `RandBetween(from, to)`.
/// Equal bounds are an exact value rather than an empty range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizedRange {
    pub from: u32,
    pub to: u32,
}

impl NormalizedRange {
    pub const fn exact(value: u32) -> Self {
        Self {
            from: value,
            to: value,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpModeSelection {
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpMode {
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpPaddingPlacement {
    Cookie,
    Header,
    Query,
    #[default]
    QueryInHeader,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpPaddingMethod {
    #[default]
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpMetadataPlacement {
    #[default]
    Path,
    Cookie,
    Header,
    Query,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpUplinkDataPlacement {
    #[default]
    Auto,
    Body,
    Cookie,
    Header,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpMetadataConfig {
    pub placement: XhttpMetadataPlacement,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpPaddingConfig {
    pub range: NormalizedRange,
    pub obfs_mode: bool,
    pub key: String,
    pub header: String,
    pub placement: XhttpPaddingPlacement,
    pub method: XhttpPaddingMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpUplinkDataConfig {
    pub placement: XhttpUplinkDataPlacement,
    pub key: String,
    pub chunk_size: NormalizedRange,
}

/// Inputs copied from the config model plus the security kind needed to
/// resolve `mode: auto`.
#[derive(Debug, Clone)]
pub struct XhttpConfigInput {
    pub mode: XhttpModeSelection,
    pub is_reality: bool,
    pub path: String,
    pub headers: HeaderMap,
    pub x_padding_bytes: XhttpRange,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: XhttpPaddingPlacement,
    pub x_padding_method: XhttpPaddingMethod,
    pub uplink_http_method: String,
    pub session_placement: XhttpMetadataPlacement,
    pub session_key: String,
    pub seq_placement: XhttpMetadataPlacement,
    pub seq_key: String,
    pub uplink_data_placement: XhttpUplinkDataPlacement,
    pub uplink_data_key: String,
    pub uplink_chunk_size: XhttpRange,
    pub no_grpc_header: bool,
    pub sc_max_each_post_bytes: XhttpRange,
    pub sc_min_posts_interval_ms: XhttpRange,
    pub sc_max_buffered_posts: i64,
    pub sc_stream_up_server_secs: XhttpRange,
}

impl Default for XhttpConfigInput {
    fn default() -> Self {
        Self {
            mode: XhttpModeSelection::Auto,
            is_reality: false,
            path: String::new(),
            headers: HeaderMap::new(),
            x_padding_bytes: XhttpRange::default(),
            x_padding_obfs_mode: false,
            x_padding_key: "x_padding".to_owned(),
            x_padding_header: "X-Padding".to_owned(),
            x_padding_placement: XhttpPaddingPlacement::QueryInHeader,
            x_padding_method: XhttpPaddingMethod::RepeatX,
            uplink_http_method: "POST".to_owned(),
            session_placement: XhttpMetadataPlacement::Path,
            session_key: String::new(),
            seq_placement: XhttpMetadataPlacement::Path,
            seq_key: String::new(),
            uplink_data_placement: XhttpUplinkDataPlacement::Auto,
            uplink_data_key: "X-Data".to_owned(),
            uplink_chunk_size: XhttpRange::default(),
            no_grpc_header: false,
            sc_max_each_post_bytes: XhttpRange::default(),
            sc_min_posts_interval_ms: XhttpRange::default(),
            sc_max_buffered_posts: 0,
            sc_stream_up_server_secs: XhttpRange::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub mode: XhttpMode,
    /// Decoded URL path, normalized to both a leading and trailing slash.
    pub path: String,
    /// Configured query kept byte-for-byte until a placement mutates it.
    pub raw_query: String,
    /// Escaped fragment retained for absolute padding headers only. HTTP
    /// request targets never contain fragments.
    pub fragment: String,
    pub headers: HeaderMap,
    pub padding: XhttpPaddingConfig,
    pub uplink_http_method: String,
    pub session: XhttpMetadataConfig,
    pub sequence: XhttpMetadataConfig,
    pub uplink_data: XhttpUplinkDataConfig,
    pub no_grpc_header: bool,
    pub max_each_post_bytes: NormalizedRange,
    pub min_posts_interval_ms: NormalizedRange,
    pub max_buffered_posts: u64,
    pub stream_up_server_secs: NormalizedRange,
}

impl XhttpConfig {
    pub fn normalize(input: XhttpConfigInput) -> Result<Self, XhttpConfigError> {
        let mode = match input.mode {
            XhttpModeSelection::Auto if input.is_reality => XhttpMode::StreamOne,
            XhttpModeSelection::Auto => XhttpMode::PacketUp,
            XhttpModeSelection::PacketUp => XhttpMode::PacketUp,
            XhttpModeSelection::StreamUp => XhttpMode::StreamUp,
            XhttpModeSelection::StreamOne => XhttpMode::StreamOne,
        };

        let (path, query_and_fragment) = input.path.split_once('?').unwrap_or((&input.path, ""));
        if query_and_fragment
            .bytes()
            .any(|byte| byte.is_ascii_control())
            || !has_valid_percent_escapes(query_and_fragment)
        {
            return Err(XhttpConfigError::InvalidQuery);
        }
        // URL.String followed by http.NewRequest performs this split before
        // Fill*Request. The fragment is not part of RequestURI, but is still
        // present when Fill*Request snapshots URL.String for padding.
        let (raw_query, fragment) = query_and_fragment
            .split_once('#')
            .map_or((query_and_fragment, ""), |(query, fragment)| {
                (query, fragment)
            });
        let fragment = normalize_fragment(fragment);
        let mut path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        if !path.ends_with('/') {
            path.push('/');
        }

        let max_each_post_bytes = normalize_positive_range(
            input.sc_max_each_post_bytes,
            NormalizedRange::exact(1_000_000),
            "scMaxEachPostBytes",
        )?;
        let min_posts_interval_ms = normalize_nonnegative_range(
            input.sc_min_posts_interval_ms,
            NormalizedRange::exact(30),
            "scMinPostsIntervalMs",
        )?;
        let stream_up_server_secs = normalize_nonnegative_range(
            input.sc_stream_up_server_secs,
            NormalizedRange { from: 20, to: 80 },
            "scStreamUpServerSecs",
        )?;
        let max_buffered_posts = match input.sc_max_buffered_posts {
            0 => 30,
            value if value > 0 => u64::try_from(value).expect("positive i64 always fits u64"),
            _ => return Err(XhttpConfigError::NegativeLimit("scMaxBufferedPosts")),
        };

        let uplink_chunk_size = normalize_uplink_chunk_size(
            input.uplink_chunk_size,
            input.uplink_data_placement,
            max_each_post_bytes,
        )?;
        let uplink_http_method = non_empty_or(input.uplink_http_method, "POST");
        if !is_http_token(&uplink_http_method) {
            return Err(XhttpConfigError::InvalidMethod);
        }

        let padding = XhttpPaddingConfig {
            range: normalize_positive_range(
                input.x_padding_bytes,
                NormalizedRange {
                    from: 100,
                    to: 1_000,
                },
                "xPaddingBytes",
            )?,
            obfs_mode: input.x_padding_obfs_mode,
            key: non_empty_or(input.x_padding_key, "x_padding"),
            header: non_empty_or(input.x_padding_header, "X-Padding"),
            placement: input.x_padding_placement,
            method: input.x_padding_method,
        };
        let session = XhttpMetadataConfig {
            placement: input.session_placement,
            key: metadata_key(input.session_key, input.session_placement, true),
        };
        let sequence = XhttpMetadataConfig {
            placement: input.seq_placement,
            key: metadata_key(input.seq_key, input.seq_placement, false),
        };
        let uplink_data = XhttpUplinkDataConfig {
            placement: input.uplink_data_placement,
            key: uplink_data_key(input.uplink_data_key, input.uplink_data_placement),
            chunk_size: uplink_chunk_size,
        };
        validate_generated_names(&padding, &session, &sequence, &uplink_data)?;

        Ok(Self {
            mode,
            path,
            raw_query: raw_query.to_owned(),
            fragment,
            headers: input.headers,
            padding,
            uplink_http_method: uplink_http_method.to_ascii_uppercase(),
            session,
            sequence,
            uplink_data,
            no_grpc_header: input.no_grpc_header,
            max_each_post_bytes,
            min_posts_interval_ms,
            max_buffered_posts,
            stream_up_server_secs,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum XhttpConfigError {
    #[error("XHTTP authority must not be empty")]
    EmptyAuthority,
    #[error("XHTTP authority is not a valid host with an optional port")]
    InvalidAuthority,
    #[error("XHTTP uplink HTTP method must be a valid ASCII token")]
    InvalidMethod,
    #[error("XHTTP query contains a control character or invalid percent escape")]
    InvalidQuery,
    #[error("XHTTP generated header name `{0}` must be a valid ASCII token")]
    InvalidHeaderName(&'static str),
    #[error("XHTTP generated cookie name `{0}` must be a valid ASCII token")]
    InvalidCookieName(&'static str),
    #[error("XHTTP range `{0}` must contain positive bounds")]
    NonPositiveRange(&'static str),
    #[error("XHTTP range `{0}` must not contain a negative bound")]
    NegativeRange(&'static str),
    #[error("XHTTP limit `{0}` must not be negative")]
    NegativeLimit(&'static str),
}

fn normalize_positive_range(
    raw: XhttpRange,
    default: NormalizedRange,
    name: &'static str,
) -> Result<NormalizedRange, XhttpConfigError> {
    let raw = raw.ordered();
    if raw.from < 0 || raw.to < 0 {
        return Err(XhttpConfigError::NonPositiveRange(name));
    }
    if raw.to == 0 {
        return Ok(default);
    }
    if raw.from <= 0 || raw.to <= 0 {
        return Err(XhttpConfigError::NonPositiveRange(name));
    }
    Ok(NormalizedRange {
        from: raw.from as u32,
        to: raw.to as u32,
    })
}

fn normalize_authority(raw: &str) -> Option<String> {
    if raw.is_empty()
        || raw.bytes().any(|byte| byte.is_ascii_control())
        || raw.chars().any(char::is_whitespace)
        || raw.contains(['@', '/', '?', '#', '%'])
    {
        return None;
    }

    let authority = if let Some(after_open) = raw.strip_prefix('[') {
        let close = after_open.find(']')?;
        let address = after_open[..close].parse::<Ipv6Addr>().ok()?;
        let suffix = &after_open[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(parse_port(suffix.strip_prefix(':')?)?)
        };
        match port {
            Some(port) => format!("[{address}]:{port}"),
            None => format!("[{address}]"),
        }
    } else {
        if raw.contains(['[', ']']) || raw.matches(':').count() > 1 {
            // Core formatting must bracket IPv6. Accepting it here would make
            // a last colon indistinguishable from a port delimiter.
            return None;
        }
        let (host, port) = match raw.rsplit_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (raw, None),
        };
        if host.is_empty() {
            return None;
        }
        let mut host = match host.parse::<Ipv4Addr>() {
            Ok(address) => address.to_string(),
            Err(_) => idna::domain_to_ascii(host).ok()?,
        };
        if host.is_empty() {
            return None;
        }
        host.make_ascii_lowercase();
        match port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    };

    authority.parse::<Authority>().ok()?;
    Some(authority)
}

fn parse_port(raw: &str) -> Option<u16> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u16>().ok()
}

fn normalize_fragment(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let decoded = percent_decode(raw).expect("fragment escapes were validated before normalize");
    let escaped = escape_fragment(&decoded);
    if raw == escaped || valid_encoded_fragment(raw) {
        raw.to_owned()
    } else {
        escaped
    }
}

fn percent_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            decoded.push((hex_value(hex[0])? << 4) | hex_value(hex[1])?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn escape_fragment(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut escaped = String::new();
    for &byte in value {
        if fragment_byte_is_safe(byte) {
            escaped.push(byte as char);
        } else {
            escaped.push('%');
            escaped.push(HEX[usize::from(byte >> 4)] as char);
            escaped.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    escaped
}

fn fragment_byte_is_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'$'
                | b'&'
                | b'+'
                | b','
                | b'/'
                | b':'
                | b';'
                | b'='
                | b'?'
                | b'@'
                | b'!'
                | b'('
                | b')'
                | b'*'
        )
}

fn valid_encoded_fragment(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| fragment_byte_is_safe(byte) || matches!(byte, b'\'' | b'[' | b']' | b'%'))
}

fn normalize_nonnegative_range(
    raw: XhttpRange,
    default: NormalizedRange,
    name: &'static str,
) -> Result<NormalizedRange, XhttpConfigError> {
    let raw = raw.ordered();
    if raw.from < 0 || raw.to < 0 {
        return Err(XhttpConfigError::NegativeRange(name));
    }
    if raw.to == 0 {
        return Ok(default);
    }
    Ok(NormalizedRange {
        from: raw.from as u32,
        to: raw.to as u32,
    })
}

fn normalize_uplink_chunk_size(
    raw: XhttpRange,
    placement: XhttpUplinkDataPlacement,
    max_each_post_bytes: NormalizedRange,
) -> Result<NormalizedRange, XhttpConfigError> {
    let raw = raw.ordered();
    if raw.from < 0 || raw.to < 0 {
        return Err(XhttpConfigError::NegativeRange("uplinkChunkSize"));
    }
    if raw.to == 0 {
        return Ok(match placement {
            XhttpUplinkDataPlacement::Cookie => NormalizedRange {
                from: 2 * 1_024,
                to: 3 * 1_024,
            },
            XhttpUplinkDataPlacement::Header => NormalizedRange {
                from: 3_000,
                to: 4_000,
            },
            XhttpUplinkDataPlacement::Auto | XhttpUplinkDataPlacement::Body => max_each_post_bytes,
        });
    }
    let from = raw.from.max(64);
    let to = raw.to.max(64);
    Ok(NormalizedRange {
        from: from as u32,
        to: to as u32,
    })
}

fn non_empty_or(value: String, default: &str) -> String {
    if value.is_empty() {
        default.to_owned()
    } else {
        value
    }
}

pub(super) fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

pub(super) fn is_valid_raw_query(value: &str) -> bool {
    !value.contains('#')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && has_valid_percent_escapes(value)
}

pub(super) fn is_valid_serialized_fragment(value: &str) -> bool {
    !value.contains('#')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && has_valid_percent_escapes(value)
        && valid_encoded_fragment(value)
}

fn has_valid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(hex) = bytes.get(index + 1..index + 3) else {
            return false;
        };
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        index += 3;
    }
    true
}

fn metadata_key(configured: String, placement: XhttpMetadataPlacement, session: bool) -> String {
    if !configured.is_empty() {
        return configured;
    }
    match (placement, session) {
        (XhttpMetadataPlacement::Cookie | XhttpMetadataPlacement::Query, true) => {
            "x_session".to_owned()
        }
        (XhttpMetadataPlacement::Header, true) => "X-Session".to_owned(),
        (XhttpMetadataPlacement::Cookie | XhttpMetadataPlacement::Query, false) => {
            "x_seq".to_owned()
        }
        (XhttpMetadataPlacement::Header, false) => "X-Seq".to_owned(),
        (XhttpMetadataPlacement::Path, _) => String::new(),
    }
}

fn uplink_data_key(configured: String, placement: XhttpUplinkDataPlacement) -> String {
    if !configured.is_empty() {
        return configured;
    }
    match placement {
        XhttpUplinkDataPlacement::Cookie => "x_data".to_owned(),
        XhttpUplinkDataPlacement::Auto | XhttpUplinkDataPlacement::Header => "X-Data".to_owned(),
        XhttpUplinkDataPlacement::Body => String::new(),
    }
}

fn validate_generated_names(
    padding: &XhttpPaddingConfig,
    session: &XhttpMetadataConfig,
    sequence: &XhttpMetadataConfig,
    uplink_data: &XhttpUplinkDataConfig,
) -> Result<(), XhttpConfigError> {
    if padding.obfs_mode {
        match padding.placement {
            XhttpPaddingPlacement::Header | XhttpPaddingPlacement::QueryInHeader => {
                validate_header_name(&padding.header, "xPaddingHeader")?;
            }
            XhttpPaddingPlacement::Cookie => {
                validate_cookie_name(&padding.key, "xPaddingKey")?;
            }
            XhttpPaddingPlacement::Query => {}
        }
    }
    validate_metadata_name(session, "sessionKey")?;
    validate_metadata_name(sequence, "seqKey")?;
    match uplink_data.placement {
        XhttpUplinkDataPlacement::Header => {
            validate_header_name(&uplink_data.key, "uplinkDataKey")?;
        }
        XhttpUplinkDataPlacement::Cookie => {
            validate_cookie_name(&uplink_data.key, "uplinkDataKey")?;
        }
        XhttpUplinkDataPlacement::Auto | XhttpUplinkDataPlacement::Body => {}
    }
    Ok(())
}

fn validate_metadata_name(
    metadata: &XhttpMetadataConfig,
    field: &'static str,
) -> Result<(), XhttpConfigError> {
    match metadata.placement {
        XhttpMetadataPlacement::Header => validate_header_name(&metadata.key, field),
        XhttpMetadataPlacement::Cookie => validate_cookie_name(&metadata.key, field),
        XhttpMetadataPlacement::Path | XhttpMetadataPlacement::Query => Ok(()),
    }
}

fn validate_header_name(name: &str, field: &'static str) -> Result<(), XhttpConfigError> {
    if is_http_token(name) {
        Ok(())
    } else {
        Err(XhttpConfigError::InvalidHeaderName(field))
    }
}

fn validate_cookie_name(name: &str, field: &'static str) -> Result<(), XhttpConfigError> {
    if is_http_token(name) {
        Ok(())
    } else {
        Err(XhttpConfigError::InvalidCookieName(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhttp_config_normalizes_path_mode_defaults_and_ranges() {
        let mut input = XhttpConfigInput {
            is_reality: true,
            path: "api/v1?z=2&x=1".to_owned(),
            x_padding_bytes: XhttpRange {
                from: 1_000,
                to: 100,
            },
            uplink_data_placement: XhttpUplinkDataPlacement::Cookie,
            ..XhttpConfigInput::default()
        };
        input.headers.set("X-Test", "yes");

        let config = XhttpConfig::normalize(input).unwrap();
        assert_eq!(config.mode, XhttpMode::StreamOne);
        assert_eq!(config.path, "/api/v1/");
        assert_eq!(config.raw_query, "z=2&x=1");
        assert_eq!(config.fragment, "");
        assert_eq!(config.headers.get("X-Test"), Some("yes"));
        assert_eq!(
            config.padding.range,
            NormalizedRange {
                from: 100,
                to: 1_000
            }
        );
        assert_eq!(
            config.uplink_data.chunk_size,
            NormalizedRange {
                from: 2 * 1_024,
                to: 3 * 1_024
            }
        );
        assert_eq!(
            config.max_each_post_bytes,
            NormalizedRange::exact(1_000_000)
        );
        assert_eq!(config.min_posts_interval_ms, NormalizedRange::exact(30));
        assert_eq!(
            config.stream_up_server_secs,
            NormalizedRange { from: 20, to: 80 }
        );
        assert_eq!(config.max_buffered_posts, 30);
    }

    #[test]
    fn xhttp_endpoint_canonicalizes_idn_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            XhttpEndpoint::new(XhttpScheme::Https, "BÜCHER.example:0443")
                .unwrap()
                .authority,
            "xn--bcher-kva.example:443"
        );
        assert_eq!(
            XhttpEndpoint::new(XhttpScheme::Http, "127.0.0.1:8080")
                .unwrap()
                .authority,
            "127.0.0.1:8080"
        );
        assert_eq!(
            XhttpEndpoint::new(XhttpScheme::Https, "[2001:0db8:0:0::1]:8443")
                .unwrap()
                .authority,
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn xhttp_endpoint_rejects_non_authority_and_invalid_ports() {
        for authority in [
            "user@example.com",
            "example.com/path",
            "example.com?query",
            "example.com fragment",
            "example.com\r\nX-Evil: 1",
            "2001:db8::1",
            "[2001:db8::1",
            "[2001:db8::1]tail",
            "example.com:",
            "example.com:65536",
            "example.com:http",
        ] {
            assert_eq!(
                XhttpEndpoint::new(XhttpScheme::Https, authority),
                Err(XhttpConfigError::InvalidAuthority),
                "{authority:?}"
            );
        }
    }

    #[test]
    fn xhttp_config_rejects_request_line_method_injection() {
        for method in ["POST\r\nX-Evil: 1", "POST GET", "méthod", "\0PING"] {
            let input = XhttpConfigInput {
                uplink_http_method: method.to_owned(),
                ..XhttpConfigInput::default()
            };
            assert_eq!(
                XhttpConfig::normalize(input).unwrap_err(),
                XhttpConfigError::InvalidMethod
            );
        }

        let config = XhttpConfig::normalize(XhttpConfigInput {
            uplink_http_method: "m-search*".to_owned(),
            ..XhttpConfigInput::default()
        })
        .unwrap();
        assert_eq!(config.uplink_http_method, "M-SEARCH*");
    }

    #[test]
    fn xhttp_config_rejects_unsafe_query_and_preserves_serialized_fragment() {
        for path in ["/api?x=%zz", "/api?x=%", "/api?x=1\r\nX-Evil: 1"] {
            let input = XhttpConfigInput {
                path: path.to_owned(),
                ..XhttpConfigInput::default()
            };
            assert_eq!(
                XhttpConfig::normalize(input).unwrap_err(),
                XhttpConfigError::InvalidQuery
            );
        }

        let config = XhttpConfig::normalize(XhttpConfigInput {
            path: "/api?x=1#not-sent".to_owned(),
            ..XhttpConfigInput::default()
        })
        .unwrap();
        assert_eq!(config.raw_query, "x=1");
        assert_eq!(config.fragment, "not-sent");

        let config = XhttpConfig::normalize(XhttpConfigInput {
            path: "/api?x=1#a b!()'*".to_owned(),
            ..XhttpConfigInput::default()
        })
        .unwrap();
        assert_eq!(config.fragment, "a%20b!()%27*");
    }

    #[test]
    fn xhttp_config_rejects_negative_transport_native_limits() {
        for input in [
            XhttpConfigInput {
                x_padding_bytes: XhttpRange { from: -1, to: 0 },
                ..XhttpConfigInput::default()
            },
            XhttpConfigInput {
                sc_min_posts_interval_ms: XhttpRange { from: -1, to: 0 },
                ..XhttpConfigInput::default()
            },
            XhttpConfigInput {
                uplink_chunk_size: XhttpRange { from: -1, to: 0 },
                ..XhttpConfigInput::default()
            },
        ] {
            assert!(XhttpConfig::normalize(input).is_err());
        }
    }

    #[test]
    fn xhttp_config_validates_only_names_used_by_their_placement() {
        let invalid_inputs = [
            XhttpConfigInput {
                x_padding_obfs_mode: true,
                x_padding_placement: XhttpPaddingPlacement::Header,
                x_padding_header: "X Bad".to_owned(),
                ..XhttpConfigInput::default()
            },
            XhttpConfigInput {
                x_padding_obfs_mode: true,
                x_padding_placement: XhttpPaddingPlacement::Cookie,
                x_padding_key: "bad;name".to_owned(),
                ..XhttpConfigInput::default()
            },
            XhttpConfigInput {
                session_placement: XhttpMetadataPlacement::Header,
                session_key: "bad:name".to_owned(),
                ..XhttpConfigInput::default()
            },
            XhttpConfigInput {
                seq_placement: XhttpMetadataPlacement::Cookie,
                seq_key: "bad name".to_owned(),
                ..XhttpConfigInput::default()
            },
            XhttpConfigInput {
                uplink_data_placement: XhttpUplinkDataPlacement::Header,
                uplink_data_key: "X Data".to_owned(),
                ..XhttpConfigInput::default()
            },
            XhttpConfigInput {
                uplink_data_placement: XhttpUplinkDataPlacement::Cookie,
                uplink_data_key: "bad;name".to_owned(),
                ..XhttpConfigInput::default()
            },
        ];
        for input in invalid_inputs {
            assert!(matches!(
                XhttpConfig::normalize(input),
                Err(XhttpConfigError::InvalidHeaderName(_) | XhttpConfigError::InvalidCookieName(_))
            ));
        }

        let config = XhttpConfig::normalize(XhttpConfigInput {
            x_padding_obfs_mode: true,
            x_padding_placement: XhttpPaddingPlacement::Query,
            x_padding_key: "query key&still-encoded".to_owned(),
            session_placement: XhttpMetadataPlacement::Path,
            session_key: "unused bad:key".to_owned(),
            seq_placement: XhttpMetadataPlacement::Query,
            seq_key: "query key".to_owned(),
            uplink_data_placement: XhttpUplinkDataPlacement::Body,
            uplink_data_key: "unused bad:key".to_owned(),
            ..XhttpConfigInput::default()
        })
        .expect("query names are URL-encoded and path/body names are unused");
        assert_eq!(config.padding.key, "query key&still-encoded");
    }
}
