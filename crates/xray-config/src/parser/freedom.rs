//! Freedom's `proxyProtocol`, `finalRules` and the removed `ipsBlocked`, read
//! as Xray-core v26.10.31 reads them.

use super::*;
use crate::{
    FreedomBlockDelay, FreedomFinalRule, FreedomRuleAction, ProxyProtocolVersion, RoutingPortRange,
};

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
        let networks = self.final_rule_networks(rule.get("network"), &format!("{path}.network"));
        let port_path = format!("{path}.port");
        let port_ranges = self
            .parse_u16_selector_ranges(rule.get("port"), &port_path, U16SelectorKind::RoutingPort)
            .and_then(|pairs| {
                pairs
                    .into_iter()
                    .map(|(start, end)| RoutingPortRange::new(start, end))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| self.error(&port_path, error.to_string()))
                    .ok()
            });
        let ip_matchers = self.final_rule_ips(rule.get("ip"), &format!("{path}.ip"));
        let block_delay = self.block_delay(rule.get("blockDelay"), &format!("{path}.blockDelay"));
        Some(FreedomFinalRule {
            action: action?,
            networks: networks?,
            port_ranges: port_ranges?,
            ip_matchers: ip_matchers?,
            block_delay: block_delay?,
        })
    }

    /// Xray-core's `NetworkList`: a comma-separated string or an array of
    /// strings, absent or empty for every network. Names other than `tcp` and
    /// `udp` are kept as networks nothing travels over.
    fn final_rule_networks(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<Option<Vec<Network>>> {
        let names: Vec<&str> = match raw {
            None | Some(Value::Null) => return Some(None),
            Some(Value::String(names)) => names.split(',').collect(),
            Some(Value::Array(items)) => {
                let mut names = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::String(name) => names.push(name.as_str()),
                        // Go decodes a null element as an empty name.
                        Value::Null => names.push(""),
                        _ => {
                            self.error(
                                path,
                                "field `network` must be a string or an array of strings",
                            );
                            return None;
                        }
                    }
                }
                names
            }
            Some(_) => {
                self.error(
                    path,
                    "field `network` must be a string or an array of strings",
                );
                return None;
            }
        };
        if names.is_empty() {
            return Some(None);
        }
        let mut networks = Vec::with_capacity(2);
        for name in names {
            let network = if name.eq_ignore_ascii_case("tcp") {
                Network::Tcp
            } else if name.eq_ignore_ascii_case("udp") {
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

    /// Xray-core's `StringList` of routing IP rules: a comma-separated
    /// string, split without trimming, or an array of strings. An empty list
    /// sets no address condition.
    fn final_rule_ips(&mut self, raw: Option<&Value>, path: &str) -> Option<Option<IpMatcherSet>> {
        let entries: Vec<(Option<&str>, String)> = match raw {
            None | Some(Value::Null) => return Some(None),
            Some(Value::String(list)) => list
                .split(',')
                .enumerate()
                .map(|(index, entry)| (Some(entry), format!("{path}[{index}]")))
                .collect(),
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(index, item)| (item.as_str(), format!("{path}[{index}]")))
                .collect(),
            Some(_) => {
                self.error(path, "field `ip` must be a string or an array of strings");
                return None;
            }
        };
        if entries.is_empty() {
            return Some(None);
        }
        self.routing_ip_matcher_set(entries).map(Some)
    }

    /// Xray-core's `Int32Range` of seconds: an integer or a `min-max` string,
    /// in either order.
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
                self.error(
                    path,
                    "blockDelay must be a nonnegative integer or `min-max` range of seconds",
                );
                None
            }
        }
    }
}
