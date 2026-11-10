//! Freedom's `proxyProtocol`, `finalRules`, `noises` and the removed
//! `ipsBlocked` and `noise`, read as Xray-core v26.11.9 reads them.

use super::*;
use crate::{
    go_lowercase, FreedomBlockDelay, FreedomFinalRule, FreedomNoise, FreedomNoiseFamily,
    FreedomNoisePacket, FreedomRuleAction, FreedomRuleLogLevel, ProxyProtocolVersion,
};

/// Bounds Xray-core does not set, as for FinalMask noise.
const MAX_FREEDOM_NOISES: usize = 16;
const MAX_FREEDOM_NOISE_BYTES: usize = 4096;
const MAX_FREEDOM_NOISE_DELAY_MS: i32 = 1000;

impl Parser<'_> {
    /// `proxyProtocol` is a `uint32`; Xray-core ignores every value but 1
    /// and 2.
    pub(super) fn freedom_proxy_protocol(
        &mut self,
        settings: &Value,
        path: &str,
    ) -> Option<ProxyProtocolVersion> {
        match self.nullable_u32_at(settings, "proxyProtocol", path.to_owned())? {
            1 => Some(ProxyProtocolVersion::V1),
            2 => Some(ProxyProtocolVersion::V2),
            _ => None,
        }
    }

    /// Xray-core warns that `ipsBlocked` moved to `finalRules` and ignores
    /// it, once it decodes as a string list.
    pub(super) fn freedom_ips_blocked(&mut self, settings: &Value, path: &str) {
        match settings.get("ipsBlocked") {
            None | Some(Value::Null) => {}
            Some(Value::String(_)) => self.ips_blocked_warning(path),
            // Go decodes a null element as an empty string.
            Some(Value::Array(items))
                if items.iter().all(|item| item.is_string() || item.is_null()) =>
            {
                self.ips_blocked_warning(path)
            }
            Some(_) => self.error(
                path,
                "field `ipsBlocked` must be a string or an array of strings",
            ),
        }
    }

    fn ips_blocked_warning(&mut self, path: &str) {
        self.warning(
            path,
            "freedom `ipsBlocked` has been removed and is ignored; use `finalRules`",
        );
    }

    pub(super) fn freedom_final_rules(
        &mut self,
        settings: &Value,
        path: &str,
    ) -> Vec<FreedomFinalRule> {
        let rules = match settings.get("finalRules") {
            None | Some(Value::Null) => return Vec::new(),
            Some(Value::Array(rules)) => rules,
            Some(_) => {
                self.error(path, "field `finalRules` must be an array");
                return Vec::new();
            }
        };
        rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| self.freedom_final_rule(rule, &format!("{path}[{index}]")))
            .collect()
    }

    fn freedom_final_rule(&mut self, rule: &Value, path: &str) -> Option<FreedomFinalRule> {
        if !rule.is_object() {
            self.error(path, "final rule must be an object");
            return None;
        }
        self.reject_unknown_fields(rule, path, &surface::FREEDOM_FINAL_RULE);
        let action_path = format!("{path}.action");
        let action = match rule.get("action") {
            Some(Value::String(action)) if action.eq_ignore_ascii_case("allow") => {
                Some(FreedomRuleAction::Allow)
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("block") => {
                Some(FreedomRuleAction::Block)
            }
            Some(Value::String(action)) => {
                self.error(action_path, format!("unknown final rule action `{action}`"));
                None
            }
            None | Some(Value::Null) => {
                self.error(action_path, "final rule action must be `allow` or `block`");
                None
            }
            Some(_) => {
                self.error(action_path, "field `action` must be a string");
                None
            }
        };
        let networks = self.network_list(rule.get("network"), &format!("{path}.network"));
        // A final rule checks ports only once its list has a range, so `0`
        // and `""` apply to every port.
        let port_ranges = self
            .port_list(
                rule.get("port"),
                &format!("{path}.port"),
                U16SelectorKind::RoutingPort,
            )
            .map(|list| list.and_then(|list| list.has_ranges.then_some(list.ranges)));
        let ip_matchers = self.final_rule_ips(rule.get("ip"), &format!("{path}.ip"));
        let delay = self.block_delay(rule.get("delay"), &format!("{path}.delay"));
        let deprecated_path = format!("{path}.blockDelay");
        let deprecated = self.block_delay(rule.get("blockDelay"), &deprecated_path);
        let log_level_path = format!("{path}.logLevel");
        let log_level = self.final_rule_log_level(rule.get("logLevel"), &log_level_path);
        let (action, delay, deprecated, log_level) = (action?, delay?, deprecated?, log_level?);

        // Xray-core's `FreedomFinalRuleConfig.Build`: `blockDelay` warns and
        // takes the place of `delay`; an allow rule then refuses a delay and
        // any nonempty `logLevel`, before the level's value is looked at.
        let (block_delay, delay_path) = match deprecated {
            Some(deprecated) => {
                self.warning(
                    &deprecated_path,
                    "freedom final rule `blockDelay` is deprecated; use `delay`",
                );
                (Some(deprecated), deprecated_path)
            }
            None => (delay, format!("{path}.delay")),
        };
        if action == FreedomRuleAction::Allow {
            let refused = if block_delay.is_some() {
                Some(delay_path)
            } else {
                (!log_level.is_empty()).then(|| log_level_path.clone())
            };
            if let Some(refused) = refused {
                self.error(
                    refused,
                    "delay and logLevel are only supported for block final rules",
                );
                return None;
            }
        }
        let log_level = match go_lowercase(log_level).as_ref() {
            "" | "info" => FreedomRuleLogLevel::Info,
            "none" => FreedomRuleLogLevel::None,
            "debug" => FreedomRuleLogLevel::Debug,
            "warning" => FreedomRuleLogLevel::Warning,
            "error" => FreedomRuleLogLevel::Error,
            _ => {
                self.error(
                    log_level_path,
                    format!("unknown final rule logLevel `{log_level}`"),
                );
                return None;
            }
        };
        Some(FreedomFinalRule {
            action,
            networks: networks?,
            port_ranges: port_ranges?,
            ip_matchers: ip_matchers?,
            block_delay,
            log_level,
        })
    }

    /// Xray-core's `logLevel` string field; Go leaves one that decodes null
    /// empty.
    fn final_rule_log_level<'v>(&mut self, raw: Option<&'v Value>, path: &str) -> Option<&'v str> {
        match raw {
            None | Some(Value::Null) => Some(""),
            Some(Value::String(level)) => Some(level),
            Some(_) => {
                self.error(path, "field `logLevel` must be a string");
                None
            }
        }
    }

    /// Xray-core's `StringList` of routing IP rules: a comma-separated
    /// string, split without trimming, or an array of strings. An empty list
    /// sets no address condition.
    fn final_rule_ips(&mut self, raw: Option<&Value>, path: &str) -> Option<Option<IpMatcherSet>> {
        match self.string_list(raw, path)? {
            Some(entries) if !entries.is_empty() => self
                .routing_ip_matcher_set(
                    entries
                        .into_iter()
                        .map(|entry| (Some(entry.text), entry.path)),
                )
                .map(Some),
            _ => Some(None),
        }
    }

    /// Xray-core's `Int32Range` of seconds, for `delay` and `blockDelay`: an
    /// integer or a `min-max` string, in either order.
    fn block_delay(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<Option<FreedomBlockDelay>> {
        let pair = match raw {
            None | Some(Value::Null) => return Some(None),
            Some(Value::String(range)) => parse_xhttp_range_string(range),
            Some(value) => value
                .as_i64()
                .and_then(|seconds| i32::try_from(seconds).ok())
                .map(|seconds| (seconds, seconds)),
        };
        match pair {
            Some((a, b)) if a >= 0 && b >= 0 => Some(Some(FreedomBlockDelay {
                min_secs: a.min(b).unsigned_abs(),
                max_secs: a.max(b).unsigned_abs(),
            })),
            _ => {
                let field = path.rsplit('.').next().unwrap_or("delay");
                self.error(
                    path,
                    format!("{field} must be a nonnegative integer or `min-max` range of seconds"),
                );
                None
            }
        }
    }

    /// `noises`, which Xray-core v26.10.31 deprecates with a warning, and the
    /// removed `noise` object, which it refuses.
    pub(super) fn freedom_noises(&mut self, settings: &Value, base: &str) -> Vec<FreedomNoise> {
        if !matches!(settings.get("noise"), None | Some(Value::Null)) {
            self.error(
                format!("{base}.noise"),
                "freedom `noise` has been removed; use `noises`",
            );
        }
        let path = format!("{base}.noises");
        let items = match settings.get("noises") {
            None | Some(Value::Null) => return Vec::new(),
            Some(Value::Array(items)) => items,
            Some(_) => {
                self.error(path, "field `noises` must be an array");
                return Vec::new();
            }
        };
        self.warning(
            &path,
            "freedom `noises` is deprecated; use `noise` in `streamSettings.finalmask.udp`",
        );
        if items.len() > MAX_FREEDOM_NOISES {
            self.error(
                path,
                format!("freedom takes at most {MAX_FREEDOM_NOISES} noises"),
            );
            return Vec::new();
        }
        items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| self.freedom_noise(item, &format!("{path}[{index}]")))
            .collect()
    }

    /// One noise, read as Xray-core's `ParseNoise` reads it: `type` names how
    /// the trimmed `packet` reads, case-sensitively.
    fn freedom_noise(&mut self, item: &Value, path: &str) -> Option<FreedomNoise> {
        // Xray-core panics on a `null` entry and refuses any other value.
        if !item.is_object() {
            self.error(path, "a freedom noise must be an object");
            return None;
        }
        self.reject_unknown_fields(item, path, &surface::FREEDOM_NOISE);
        let kind = self.nullable_string_at(item, "type", format!("{path}.type"));
        let packet = self.nullable_string_at(item, "packet", format!("{path}.packet"));
        let delay_ms = self.freedom_noise_delay(item.get("delay"), &format!("{path}.delay"));
        let apply_to = self.freedom_noise_family(item, &format!("{path}.applyTo"));
        let packet = self.freedom_noise_packet(kind?, packet?.trim(), &format!("{path}.packet"))?;
        Some(FreedomNoise {
            packet,
            delay_ms: delay_ms?,
            apply_to: apply_to?,
        })
    }

    fn freedom_noise_packet(
        &mut self,
        kind: &str,
        packet: &str,
        path: &str,
    ) -> Option<FreedomNoisePacket> {
        let bytes = match kind {
            "rand" => {
                // Go's `ParseRangeString`, in the order written; a range
                // that starts at 0 is refused.
                let lengths = parse_xhttp_range_string(packet)
                    .filter(|&(first, second)| first > 0 && second >= 0)
                    .and_then(|(first, second)| {
                        let first = u32::try_from(first).ok()?;
                        let second = u32::try_from(second).ok()?;
                        (first.max(second) as usize <= MAX_FREEDOM_NOISE_BYTES)
                            .then_some((first, second))
                    });
                return match lengths {
                    Some((first, second)) => Some(FreedomNoisePacket::Random(first, second)),
                    None => {
                        self.error(
                            path,
                            format!(
                                "a rand noise is a length or range from 1 to {MAX_FREEDOM_NOISE_BYTES}"
                            ),
                        );
                        None
                    }
                };
            }
            "str" => Some(packet.as_bytes().to_vec()),
            "hex" => decode_go_hex(packet),
            "base64" => decode_go_base64(packet),
            _ => {
                self.error(
                    path.replace(".packet", ".type"),
                    "a freedom noise type is rand, str, hex or base64",
                );
                return None;
            }
        };
        match bytes {
            Some(bytes) if bytes.len() <= MAX_FREEDOM_NOISE_BYTES => {
                Some(FreedomNoisePacket::Bytes(bytes))
            }
            Some(_) => {
                self.error(
                    path,
                    format!("a noise packet holds at most {MAX_FREEDOM_NOISE_BYTES} bytes"),
                );
                None
            }
            None => {
                self.error(path, format!("invalid {kind} noise packet"));
                None
            }
        }
    }

    /// Xray-core's `Int32Range`: a number, or a range string, ordered.
    fn freedom_noise_delay(&mut self, raw: Option<&Value>, path: &str) -> Option<(u32, u32)> {
        let pair = match raw {
            None | Some(Value::Null) => return Some((0, 0)),
            Some(Value::String(text)) => parse_xhttp_range_string(text),
            Some(value) => value
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .map(|value| (value, value)),
        };
        match pair {
            Some((first, second))
                if first.min(second) >= 0 && first.max(second) <= MAX_FREEDOM_NOISE_DELAY_MS =>
            {
                Some((
                    first.min(second).unsigned_abs(),
                    first.max(second).unsigned_abs(),
                ))
            }
            _ => {
                self.error(
                    path,
                    format!(
                        "a noise delay is milliseconds from 0 to {MAX_FREEDOM_NOISE_DELAY_MS}, a number or range"
                    ),
                );
                None
            }
        }
    }

    fn freedom_noise_family(&mut self, item: &Value, path: &str) -> Option<FreedomNoiseFamily> {
        let apply_to = self.nullable_string_at(item, "applyTo", path.to_owned())?;
        match apply_to.to_ascii_lowercase().as_str() {
            "" | "ip" | "all" => Some(FreedomNoiseFamily::Ip),
            "ipv4" => Some(FreedomNoiseFamily::Ipv4),
            "ipv6" => Some(FreedomNoiseFamily::Ipv6),
            _ => {
                self.error(path, "applyTo is ip, ipv4 or ipv6");
                None
            }
        }
    }
}

/// Go's `hex.DecodeString`: pairs of hex digits in either case.
fn decode_go_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// Xray-core's base64: `+`, `/` and `=` turned into the URL alphabet without
/// padding, then Go's lenient `RawURLEncoding`, which skips line breaks and
/// ignores leftover bits.
fn decode_go_base64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::{
        general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig,
    };
    use base64::Engine as _;
    let engine = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    let text: String = text
        .chars()
        .filter(|character| !matches!(character, '=' | '\r' | '\n'))
        .map(|character| match character {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    engine.decode(text).ok()
}
