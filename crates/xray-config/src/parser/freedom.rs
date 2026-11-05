//! Freedom's `proxyProtocol`, `finalRules` and the removed `ipsBlocked`, read
//! as Xray-core v26.10.31 reads them.

use super::*;
use crate::{FreedomBlockDelay, FreedomFinalRule, FreedomRuleAction, ProxyProtocolVersion};

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
        let block_delay = self.block_delay(rule.get("blockDelay"), &format!("{path}.blockDelay"));
        Some(FreedomFinalRule {
            action: action?,
            networks: networks?,
            port_ranges: port_ranges?,
            ip_matchers: ip_matchers?,
            block_delay: block_delay?,
        })
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
