//! Custom header values of the HTTP outbound, read and filled in as
//! Xray-core v26.10.31 does with Go's `text/template`: each value may name
//! the connection's `Source` and `Target` destinations.
//!
//! Only text, comments and these field actions are read:
//! `{{.Source}}`, `{{.Target}}` and their `.Address`, `.Port`, `.Network` and
//! `.NetAddr`, each with Go's `{{-` and `-}}` trim markers. Any other action
//! is refused when the configuration is read, where Xray-core would fail
//! each connection when it fills the value in.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use xray_routing::{Target, TargetAddr};

/// A header value as Xray-core's HTTP outbound fills it in. Its `Debug`
/// shows nothing of it, since a value can carry a token.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpHeaderTemplate {
    parts: Vec<Part>,
}

impl fmt::Debug for HttpHeaderTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpHeaderTemplate(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Text(String),
    Field(Endpoint, Field),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Source,
    Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// The destination itself, as Xray-core's `Destination.String` writes
    /// it: `tcp:` and its `NetAddr`.
    Destination,
    Address,
    Port,
    Network,
    NetAddr,
}

impl HttpHeaderTemplate {
    /// Reads `text` as Go's `text/template` would, refusing actions other
    /// than the fields this module fills in.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut rest = text;
        // Set by `-}}`: Go trims the white space that starts the next text.
        let mut trim_next = false;
        while let Some(open) = rest.find("{{") {
            let mut before = &rest[..open];
            if trim_next {
                before = before.trim_start_matches(is_go_space);
            }
            let mut action = &rest[open + 2..];
            // `{{- ` trims the text before; the dash needs space after it.
            if let Some(trimmed) = action.strip_prefix('-') {
                if trimmed.starts_with(is_go_space) {
                    before = before.trim_end_matches(is_go_space);
                    action = trimmed;
                }
            }
            push_text(&mut parts, before);
            let (body, after, trims) = split_action(action)?;
            trim_next = trims;
            if let Some(part) = parse_action(body)? {
                parts.push(part);
            }
            rest = after;
        }
        let tail = if trim_next {
            rest.trim_start_matches(is_go_space)
        } else {
            rest
        };
        push_text(&mut parts, tail);
        Ok(Self { parts })
    }

    /// Whether the value names the connection's source, which then has to
    /// reach the outbound.
    pub fn uses_source(&self) -> bool {
        self.parts
            .iter()
            .any(|part| matches!(part, Part::Field(Endpoint::Source, _)))
    }

    /// The value for a connection from `source` to `target`, with line
    /// breaks turned into spaces and surrounding white space trimmed, as
    /// Go's `Header.Write` writes it over HTTP/1.1.
    pub fn render(&self, source: Option<SocketAddr>, target: &Target) -> String {
        http1_header_value(&self.render_raw(source, target))
    }

    /// The value for a connection from `source` to `target` as Go's
    /// `text/template` fills it in, before any encoding: Go's HTTP/2 client
    /// sends it as it is. Without a source, as for a connection no inbound
    /// made, Xray-core names `tcp:0.0.0.0:0`.
    pub fn render_raw(&self, source: Option<SocketAddr>, target: &Target) -> String {
        let mut value = String::new();
        for part in &self.parts {
            match part {
                Part::Text(text) => value.push_str(text),
                Part::Field(endpoint, field) => {
                    let (address, port) = match endpoint {
                        Endpoint::Source => source.map_or_else(
                            || ("0.0.0.0".to_owned(), 0),
                            |source| (ip_text(source.ip()), source.port()),
                        ),
                        Endpoint::Target => (target_address(target), target.port),
                    };
                    match field {
                        Field::Destination => {
                            value.push_str("tcp:");
                            value.push_str(&address);
                            value.push(':');
                            value.push_str(&port.to_string());
                        }
                        Field::Address => value.push_str(&address),
                        Field::Port => value.push_str(&port.to_string()),
                        Field::Network => value.push_str("TCP"),
                        Field::NetAddr => {
                            value.push_str(&address);
                            value.push(':');
                            value.push_str(&port.to_string());
                        }
                    }
                }
            }
        }
        value
    }
}

/// `value` as Go's `Header.Write` sends it over HTTP/1.1: line breaks turned
/// into spaces and surrounding spaces and tabs trimmed.
fn http1_header_value(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .trim_matches(|c| matches!(c, ' ' | '\t'))
        .to_owned()
}

fn push_text(parts: &mut Vec<Part>, text: &str) {
    if !text.is_empty() {
        parts.push(Part::Text(text.to_owned()));
    }
}

/// Go's `text/template` reads these as white space around trim markers.
fn is_go_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Splits an action after its `{{` (and any `{{-`) into its body, the text
/// after its `}}`, and whether it ends with the `-}}` trim marker.
fn split_action(action: &str) -> Result<(&str, &str, bool), String> {
    // A comment may hold `}}` before its `*/`.
    let search_from = if action.trim_start_matches(is_go_space).starts_with("/*") {
        action.find("*/").ok_or("an unclosed template comment")?
    } else {
        0
    };
    let close = action[search_from..]
        .find("}}")
        .map(|close| close + search_from)
        .ok_or("an unclosed template action")?;
    let body = &action[..close];
    let after = &action[close + 2..];
    if let Some(trimmed) = body.strip_suffix('-') {
        if trimmed.ends_with(is_go_space) {
            return Ok((trimmed, after, true));
        }
    }
    Ok((body, after, false))
}

/// One action's body: a comment, which fills in nothing, or a field.
fn parse_action(body: &str) -> Result<Option<Part>, String> {
    let body = body.trim_matches(is_go_space);
    if let Some(comment) = body.strip_prefix("/*") {
        return if comment.ends_with("*/") {
            Ok(None)
        } else {
            Err("a template comment must end its action".to_owned())
        };
    }
    let mut names = body.strip_prefix('.').map(|chain| chain.split('.'));
    let endpoint = match names.as_mut().and_then(Iterator::next) {
        Some("Source") => Endpoint::Source,
        Some("Target") => Endpoint::Target,
        _ => return Err(format!("unsupported template action `{{{{{body}}}}}`")),
    };
    let field = match names.as_mut().and_then(Iterator::next) {
        None => Field::Destination,
        Some("Address") => Field::Address,
        Some("Port") => Field::Port,
        Some("Network") => Field::Network,
        Some("NetAddr") => Field::NetAddr,
        Some(_) => return Err(format!("unsupported template action `{{{{{body}}}}}`")),
    };
    if names.and_then(|mut rest| rest.next()).is_some() {
        return Err(format!("unsupported template action `{{{{{body}}}}}`"));
    }
    Ok(Some(Part::Field(endpoint, field)))
}

/// An address as Xray-core's `Address.String` writes it: IPv6 in brackets,
/// an IPv4-mapped one as IPv4.
fn ip_text(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

fn target_address(target: &Target) -> String {
    match &target.addr {
        TargetAddr::Ip(ip) => ip_text(*ip),
        TargetAddr::Domain(domain) => domain.clone(),
    }
}
