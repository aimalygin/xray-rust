//! Xray-core v26.10.31's list grammars shared by routing rules, freedom's
//! final rules, DNS and the DNS outbound: `StringList`, `NetworkList`,
//! `PortList` and the domain rules `geodata.ParseDomainRule` reads.

use super::{normalize_u16_ranges, Parser, U16SelectorKind};
use crate::{Network, RoutingPortRange};
use serde_json::Value;
use xray_routing::{DomainMatcher, RegexMatcher};

/// One entry of a `StringList`, with the path an error about it names.
pub(super) struct ListEntry<'v> {
    pub(super) text: &'v str,
    pub(super) path: String,
}

/// A `PortList`: the ranges a port can match, and whether the list had any
/// range at all. Xray-core keeps a reversed range, which matches no port.
pub(super) struct PortList {
    pub(super) ranges: Vec<RoutingPortRange>,
    pub(super) has_ranges: bool,
}

/// What `geodata.ParseDomainRule` makes of text with no known prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlainDomain {
    /// A substring, as routing rules, DNS servers' `domains` and the DNS
    /// outbound's rules read it.
    Substring,
    /// The whole name, as `dns.hosts` keys read it.
    Full,
}

impl Parser<'_> {
    /// Xray-core's `StringList`: an array of strings, where Go reads `null`
    /// as an empty string, or one string split at commas without trimming.
    /// `None` inside is an absent or `null` list.
    pub(super) fn string_list<'v>(
        &mut self,
        raw: Option<&'v Value>,
        path: &str,
    ) -> Option<Option<Vec<ListEntry<'v>>>> {
        let entries = match raw {
            None | Some(Value::Null) => return Some(None),
            Some(Value::String(list)) => list
                .split(',')
                .enumerate()
                .map(|(index, text)| ListEntry {
                    text,
                    path: format!("{path}[{index}]"),
                })
                .collect(),
            Some(Value::Array(items)) => {
                let mut entries = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let text = match item {
                        Value::String(text) => text.as_str(),
                        Value::Null => "",
                        _ => {
                            self.error(format!("{path}[{index}]"), "list entry must be a string");
                            return None;
                        }
                    };
                    entries.push(ListEntry {
                        text,
                        path: format!("{path}[{index}]"),
                    });
                }
                entries
            }
            Some(_) => {
                self.error(path, "must be a string or an array of strings");
                return None;
            }
        };
        Some(Some(entries))
    }

    /// Xray-core's `NetworkList`, as a `StringList` of names. Names other
    /// than `tcp` and `udp` are kept as networks nothing travels over, and an
    /// empty list sets no condition.
    pub(super) fn network_list(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<Option<Vec<Network>>> {
        let Some(entries) = self.string_list(raw, path)? else {
            return Some(None);
        };
        if entries.is_empty() {
            return Some(None);
        }
        let mut networks = Vec::with_capacity(2);
        for entry in entries {
            let network = if entry.text.eq_ignore_ascii_case("tcp") {
                Network::Tcp
            } else if entry.text.eq_ignore_ascii_case("udp") {
                Network::Udp
            } else {
                continue;
            };
            if !networks.contains(&network) {
                networks.push(network);
            }
        }
        Some(Some(networks))
    }

    /// Xray-core's `PortList`: a number, or a comma-separated string of
    /// ports and `from-to` ranges. A number of zero and empty entries add no
    /// range. A single port reads as a JSON integer, a range's ends as plain
    /// decimal digits, as Go's `json.Unmarshal` and `strconv.ParseUint` read
    /// them, and every port fits 16 bits.
    ///
    /// Deliberately, a number above 65535 is rejected: Xray-core keeps it and
    /// truncates it to 16 bits when matching, so 65617 would match port 81.
    /// `kind` picks the budget the entries count against.
    pub(super) fn port_list(
        &mut self,
        raw: Option<&Value>,
        path: &str,
        kind: U16SelectorKind,
    ) -> Option<Option<PortList>> {
        let mut pairs = Vec::new();
        let mut has_ranges = false;
        match raw {
            None | Some(Value::Null) => return Some(None),
            Some(Value::Number(number)) => {
                let Some(port) = number.as_u64().and_then(|port| u32::try_from(port).ok()) else {
                    self.error(path, "port must be a nonnegative integer or a string");
                    return None;
                };
                if port != 0 {
                    if !self.consume_u16_selector(kind, path) {
                        return None;
                    }
                    let Ok(port) = u16::try_from(port) else {
                        self.error(
                            path,
                            format!(
                                "port {port} exceeds 65535; Xray-core would truncate it to 16 bits"
                            ),
                        );
                        return None;
                    };
                    pairs.push((port, port));
                    has_ranges = true;
                }
            }
            Some(Value::String(entries)) => {
                for (index, entry) in entries.split(',').enumerate() {
                    let entry_path = format!("{path}[{index}]");
                    let entry = entry.trim();
                    if entry.is_empty() {
                        continue;
                    }
                    if !self.consume_u16_selector(kind, &entry_path) {
                        return None;
                    }
                    let range = if entry.contains('-') || entry.contains("env:") {
                        self.port_range_entry(entry, &entry_path)?
                    } else {
                        let Some(port) = json_uint_port(entry) else {
                            self.error(&entry_path, format!("invalid port `{entry}`"));
                            return None;
                        };
                        Some((port, port))
                    };
                    has_ranges = true;
                    pairs.extend(range);
                }
            }
            Some(_) => {
                self.error(path, "port must be a number or a string");
                return None;
            }
        }
        // Normalized ranges are ordered, so none is lost here.
        let ranges = normalize_u16_ranges(pairs)
            .into_iter()
            .filter_map(|(start, end)| RoutingPortRange::new(start, end).ok())
            .collect();
        Some(Some(PortList { ranges, has_ranges }))
    }

    /// A `from-to` range. `None` inside is a reversed range, which Xray-core
    /// keeps and never matches.
    fn port_range_entry(&mut self, entry: &str, path: &str) -> Option<Option<(u16, u16)>> {
        if entry.starts_with("env:") {
            self.error(path, "port environment references are not supported");
            return None;
        }
        let (start, end) = entry.split_once('-').unwrap_or((entry, entry));
        let (Some(start), Some(end)) = (decimal_port(start), decimal_port(end)) else {
            self.error(path, format!("invalid port range `{entry}`"));
            return None;
        };
        Some((start <= end).then_some((start, end)))
    }

    /// A domain rule as Xray-core's `geodata.ParseDomainRule` reads it:
    /// `geosite:` and the `ext:` spellings name geodata, whose selection may
    /// hold no domain; the custom prefixes take any value, even an empty one;
    /// anything else, even text with a colon, is `plain`.
    pub(super) fn domain_rule(
        &mut self,
        value: &str,
        path: &str,
        max_matchers: usize,
        plain: PlainDomain,
    ) -> Option<Vec<DomainMatcher>> {
        if let Some(spec) = value.strip_prefix("geosite:") {
            return self.parse_geosite_matchers("geosite.dat", spec, path, max_matchers);
        }
        for prefix in ["ext:", "ext-domain:", "ext-site:"] {
            if let Some(spec) = value.strip_prefix(prefix) {
                return self.parse_external_geosite_matchers(spec, path, max_matchers);
            }
        }
        let matcher = if let Some(pattern) = value.strip_prefix("regexp:") {
            self.domain_regex(pattern.to_owned(), path)?
        } else if let Some(domain) = value.strip_prefix("domain:") {
            DomainMatcher::Suffix(domain.to_owned())
        } else if let Some(domain) = value.strip_prefix("full:") {
            DomainMatcher::Full(domain.to_owned())
        } else if let Some(keyword) = value.strip_prefix("keyword:") {
            DomainMatcher::Keyword(keyword.to_owned())
        } else if let Some(text) = value.strip_prefix("dotless:") {
            if text.contains('.') {
                self.error(path, "dotless domain matcher must not contain a dot");
                return None;
            }
            self.domain_regex(format!("^[^.]*{text}[^.]*$"), path)?
        } else {
            match plain {
                PlainDomain::Substring => DomainMatcher::Keyword(value.to_owned()),
                PlainDomain::Full => DomainMatcher::Full(value.to_owned()),
            }
        };
        Some(vec![matcher])
    }

    fn domain_regex(&mut self, pattern: String, path: &str) -> Option<DomainMatcher> {
        match RegexMatcher::new(pattern) {
            Ok(matcher) => Some(DomainMatcher::Regex(matcher)),
            Err(error) => {
                self.error(path, error.to_string());
                None
            }
        }
    }
}

/// A port as Go's `json.Unmarshal` reads a `uint32`: a JSON integer with no
/// sign, fraction, exponent or leading zero, then at most 65535.
fn json_uint_port(text: &str) -> Option<u16> {
    let well_formed = text == "0"
        || (text.starts_with(|c: char| ('1'..='9').contains(&c))
            && text.bytes().all(|byte| byte.is_ascii_digit()));
    well_formed.then(|| text.parse().ok()).flatten()
}

/// A range end as `strconv.ParseUint(s, 10, 32)` reads it: decimal digits
/// only, then at most 65535.
fn decimal_port(text: &str) -> Option<u16> {
    (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}
