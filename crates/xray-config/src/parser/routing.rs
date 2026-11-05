//! Routing configuration, selectors, and their bounded parser budgets.

use super::xray_lists::ListEntry;
use super::{parse_xray_duration, Parser, U16SelectorKind, OBSERVATORY_PROBE_TIMEOUT};
use crate::surface;
use crate::{
    DomainNameMode, RoutingAttributes, RoutingBalancer, RoutingBalancerStrategy, RoutingConfig,
    RoutingDomainStrategy, RoutingLeastLoadCost, RoutingLeastLoadSettings, RoutingOrigin,
    RoutingRule, RoutingRuleTarget, RoutingUsers,
};
use serde_json::Value;
use std::collections::HashSet;
use xray_routing::{DomainMatcherSet, IpMatcherSet, RegexMatcher};

const MAX_ROUTING_BALANCERS: usize = 256;
const MAX_ROUTING_BALANCER_SELECTORS: usize = 4_096;
const MAX_LEAST_LOAD_EXPECTED: u64 = 16;
const MAX_LEAST_LOAD_BASELINES: usize = 16;
const MAX_LEAST_LOAD_COSTS: usize = 64;
const MAX_LEAST_LOAD_COST: f64 = 1_000.0;

impl Parser<'_> {
    pub(super) fn parse_routing(&mut self) -> RoutingConfig {
        let Some(routing) = self.root.get("routing") else {
            return RoutingConfig::default();
        };
        let routing_path = "$.routing";
        if !routing.is_object() {
            self.error(routing_path, "routing must be an object");
            return RoutingConfig::default();
        }

        self.reject_unknown_fields(routing, routing_path, &surface::ROUTING);

        let domain_strategy = self.parse_routing_domain_strategy(routing);

        let balancers = self.parse_routing_balancers(routing);
        let balancer_tags = balancers
            .iter()
            .map(|balancer| balancer.tag.as_str())
            .collect::<HashSet<_>>();
        RoutingConfig {
            rules: self.parse_routing_rules(routing, &balancer_tags),
            balancers,
            domain_strategy,
        }
    }

    fn parse_routing_balancers(&mut self, routing: &Value) -> Vec<RoutingBalancer> {
        let Some(raw_balancers) = routing.get("balancers") else {
            return Vec::new();
        };
        let Some(balancers) = raw_balancers.as_array() else {
            self.error("$.routing.balancers", "field `balancers` must be an array");
            return Vec::new();
        };
        if balancers.len() > MAX_ROUTING_BALANCERS {
            self.error(
                "$.routing.balancers",
                format!(
                    "routing config contains {} balancers; maximum supported per configuration is {MAX_ROUTING_BALANCERS}",
                    balancers.len()
                ),
            );
            return Vec::new();
        }

        let mut seen_tags = HashSet::with_capacity(balancers.len());
        let mut selector_count = 0usize;
        balancers
            .iter()
            .enumerate()
            .filter_map(|(index, balancer)| {
                let parsed = self.parse_routing_balancer(balancer, index, &mut selector_count)?;
                if !seen_tags.insert(parsed.tag.clone()) {
                    self.error(
                        format!("$.routing.balancers[{index}].tag"),
                        format!("duplicate routing balancer tag {:?}", parsed.tag),
                    );
                    return None;
                }
                Some(parsed)
            })
            .collect()
    }

    fn parse_routing_balancer(
        &mut self,
        balancer: &Value,
        index: usize,
        selector_count: &mut usize,
    ) -> Option<RoutingBalancer> {
        let path = format!("$.routing.balancers[{index}]");
        if !balancer.is_object() {
            self.error(&path, "routing balancer must be an object");
            return None;
        }
        self.reject_unknown_fields(balancer, &path, &surface::BALANCER);

        let tag_path = format!("{path}.tag");
        let tag = self.optional_string_at(balancer, "tag", tag_path.clone())?;
        if tag.is_empty() {
            self.error(tag_path, "routing balancer tag cannot be empty");
            return None;
        }

        let selector_path = format!("{path}.selector");
        let selectors = match balancer.get("selector") {
            Some(Value::String(selector)) => vec![selector.clone()],
            Some(Value::Array(values)) => {
                let mut selectors = Vec::with_capacity(values.len());
                for (selector_index, selector) in values.iter().enumerate() {
                    let Some(selector) = selector.as_str() else {
                        self.error(
                            format!("{selector_path}[{selector_index}]"),
                            "routing balancer selector must be a string",
                        );
                        return None;
                    };
                    selectors.push(selector.to_owned());
                }
                selectors
            }
            Some(_) => {
                self.error(
                    selector_path,
                    "routing balancer selector must be a string or array",
                );
                return None;
            }
            None => {
                self.error(selector_path, "missing routing balancer selector");
                return None;
            }
        };
        if selectors.is_empty() {
            self.error(
                format!("{path}.selector"),
                "routing balancer selector cannot be empty",
            );
            return None;
        }
        *selector_count = selector_count.saturating_add(selectors.len());
        if *selector_count > MAX_ROUTING_BALANCER_SELECTORS {
            self.error(
                format!("{path}.selector"),
                format!(
                    "configuration exceeds the routing balancer selector budget (maximum {MAX_ROUTING_BALANCER_SELECTORS})"
                ),
            );
            return None;
        }

        let strategy = self.parse_routing_balancer_strategy(balancer, &path)?;
        let fallback_tag = match balancer.get("fallbackTag") {
            None | Some(Value::Null) => None,
            Some(Value::String(tag)) if tag.is_empty() => None,
            Some(Value::String(tag)) => Some(tag.clone()),
            Some(_) => {
                self.error(
                    format!("{path}.fallbackTag"),
                    "routing balancer fallbackTag must be a string or null",
                );
                return None;
            }
        };

        Some(RoutingBalancer {
            tag: tag.to_owned(),
            selectors,
            strategy,
            fallback_tag,
        })
    }

    fn parse_routing_balancer_strategy(
        &mut self,
        balancer: &Value,
        balancer_path: &str,
    ) -> Option<RoutingBalancerStrategy> {
        let Some(strategy) = balancer.get("strategy") else {
            return Some(RoutingBalancerStrategy::Random);
        };
        if strategy.is_null() {
            return Some(RoutingBalancerStrategy::Random);
        }
        let strategy_path = format!("{balancer_path}.strategy");
        if !strategy.is_object() {
            self.error(
                strategy_path,
                "routing balancer strategy must be an object or null",
            );
            return None;
        }
        self.reject_unknown_fields(strategy, &strategy_path, &surface::BALANCER_STRATEGY);
        let kind = match strategy.get("type") {
            None | Some(Value::Null) => "random",
            Some(Value::String(kind)) => kind.as_str(),
            Some(_) => {
                self.error(
                    format!("{strategy_path}.type"),
                    "routing balancer strategy type must be a string or null",
                );
                return None;
            }
        };
        if kind.eq_ignore_ascii_case("leastload") {
            return self
                .parse_least_load_settings(strategy.get("settings"), &strategy_path)
                .map(RoutingBalancerStrategy::LeastLoad);
        }
        if let Some(settings) = strategy.get("settings") {
            match settings {
                Value::Null => {}
                Value::Object(settings) if settings.is_empty() => {}
                _ => self.error(
                    format!("{strategy_path}.settings"),
                    "routing balancer strategy settings are only supported for leastLoad",
                ),
            }
        }
        if kind.eq_ignore_ascii_case("random") {
            Some(RoutingBalancerStrategy::Random)
        } else if kind.eq_ignore_ascii_case("roundrobin") {
            Some(RoutingBalancerStrategy::RoundRobin)
        } else if kind.eq_ignore_ascii_case("leastping") {
            Some(RoutingBalancerStrategy::LeastPing)
        } else {
            self.error(
                format!("{strategy_path}.type"),
                format!("unsupported routing balancer strategy `{kind}`"),
            );
            None
        }
    }

    fn parse_least_load_settings(
        &mut self,
        raw_settings: Option<&Value>,
        strategy_path: &str,
    ) -> Option<RoutingLeastLoadSettings> {
        let settings_path = format!("{strategy_path}.settings");
        let settings_value = match raw_settings {
            None | Some(Value::Null) => return Some(RoutingLeastLoadSettings::default()),
            Some(settings @ Value::Object(_)) => settings,
            Some(_) => {
                self.error(
                    &settings_path,
                    "leastLoad settings must be an object or null",
                );
                return None;
            }
        };
        self.reject_unknown_fields(settings_value, &settings_path, &surface::LEAST_LOAD);
        let settings = settings_value
            .as_object()
            .expect("leastLoad settings were validated as an object");

        let expected = match settings.get("expected") {
            None | Some(Value::Null) => 0,
            Some(value) => match value.as_u64() {
                Some(value) if value <= MAX_LEAST_LOAD_EXPECTED => value as u8,
                _ => {
                    self.error(
                        format!("{settings_path}.expected"),
                        format!(
                            "leastLoad expected must be an integer between 0 and {MAX_LEAST_LOAD_EXPECTED}"
                        ),
                    );
                    return None;
                }
            },
        };
        let max_rtt = match settings.get("maxRTT") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if value.is_empty() => None,
            Some(Value::String(value)) => match parse_xray_duration(value) {
                Some(duration) if duration.is_zero() => None,
                Some(duration) if duration <= OBSERVATORY_PROBE_TIMEOUT => Some(duration),
                _ => {
                    self.error(
                        format!("{settings_path}.maxRTT"),
                        "leastLoad maxRTT must be a valid duration no greater than the 5s probe timeout",
                    );
                    return None;
                }
            },
            Some(_) => {
                self.error(
                    format!("{settings_path}.maxRTT"),
                    "leastLoad maxRTT must be a duration string or null",
                );
                return None;
            }
        };
        let tolerance_millionths = match settings.get("tolerance") {
            None | Some(Value::Null) => 0,
            Some(value) => match value.as_f64() {
                Some(value) if value.is_finite() && (0.0..=1.0).contains(&value) => {
                    if value == 0.0 {
                        0
                    } else {
                        ((value * 1_000_000.0).round() as u32).max(1)
                    }
                }
                _ => {
                    self.error(
                        format!("{settings_path}.tolerance"),
                        "leastLoad tolerance must be a number between 0 and 1",
                    );
                    return None;
                }
            },
        };
        let baselines =
            self.parse_least_load_baselines(settings.get("baselines"), &settings_path)?;
        let costs = self.parse_least_load_costs(settings.get("costs"), &settings_path)?;

        Some(RoutingLeastLoadSettings {
            expected,
            max_rtt,
            tolerance_millionths,
            baselines,
            costs,
        })
    }

    fn parse_least_load_baselines(
        &mut self,
        raw: Option<&Value>,
        settings_path: &str,
    ) -> Option<Vec<std::time::Duration>> {
        let path = format!("{settings_path}.baselines");
        let values = match raw {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(values)) if values.len() <= MAX_LEAST_LOAD_BASELINES => values,
            Some(Value::Array(_)) => {
                self.error(
                    &path,
                    format!("leastLoad baselines may contain at most {MAX_LEAST_LOAD_BASELINES} entries"),
                );
                return None;
            }
            Some(_) => {
                self.error(&path, "leastLoad baselines must be an array or null");
                return None;
            }
        };
        values
            .iter()
            .enumerate()
            .map(
                |(index, value)| match value.as_str().and_then(parse_xray_duration) {
                    Some(duration)
                        if !duration.is_zero() && duration <= OBSERVATORY_PROBE_TIMEOUT =>
                    {
                        Some(duration)
                    }
                    _ => {
                        self.error(
                            format!("{path}[{index}]"),
                            "leastLoad baseline must be a positive duration no greater than 5s",
                        );
                        None
                    }
                },
            )
            .collect()
    }

    fn parse_least_load_costs(
        &mut self,
        raw: Option<&Value>,
        settings_path: &str,
    ) -> Option<Vec<RoutingLeastLoadCost>> {
        let path = format!("{settings_path}.costs");
        let values = match raw {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(values)) if values.len() <= MAX_LEAST_LOAD_COSTS => values,
            Some(Value::Array(_)) => {
                self.error(
                    &path,
                    format!("leastLoad costs may contain at most {MAX_LEAST_LOAD_COSTS} entries"),
                );
                return None;
            }
            Some(_) => {
                self.error(&path, "leastLoad costs must be an array or null");
                return None;
            }
        };
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let item_path = format!("{path}[{index}]");
                let Some(cost) = value.as_object() else {
                    self.error(&item_path, "leastLoad cost must be an object");
                    return None;
                };
                self.reject_unknown_fields(value, &item_path, &surface::LEAST_LOAD_COST);
                if cost.get("regexp").and_then(Value::as_bool).unwrap_or(false) {
                    self.error(
                        format!("{item_path}.regexp"),
                        "leastLoad regexp costs are not supported by the bounded mobile profile",
                    );
                    return None;
                }
                if cost.get("regexp").is_some_and(|value| !value.is_boolean()) {
                    self.error(
                        format!("{item_path}.regexp"),
                        "leastLoad cost regexp must be a boolean",
                    );
                    return None;
                }
                let Some(tag_substring) = cost.get("match").and_then(Value::as_str) else {
                    self.error(
                        format!("{item_path}.match"),
                        "leastLoad cost match must be a string",
                    );
                    return None;
                };
                if tag_substring.is_empty() {
                    self.error(
                        format!("{item_path}.match"),
                        "leastLoad cost match cannot be empty",
                    );
                    return None;
                }
                let Some(value) = cost.get("value").and_then(Value::as_f64) else {
                    self.error(
                        format!("{item_path}.value"),
                        "leastLoad cost value must be a number",
                    );
                    return None;
                };
                if !value.is_finite() || value <= 0.0 || value > MAX_LEAST_LOAD_COST {
                    self.error(
                        format!("{item_path}.value"),
                        format!("leastLoad cost value must be greater than 0 and no greater than {MAX_LEAST_LOAD_COST}"),
                    );
                    return None;
                }
                Some(RoutingLeastLoadCost {
                    tag_substring: tag_substring.to_owned(),
                    value_millionths: ((value * 1_000_000.0).round() as u64).max(1),
                })
            })
            .collect()
    }

    fn parse_routing_domain_strategy(&mut self, routing: &Value) -> RoutingDomainStrategy {
        match self.optional_string_at(
            routing,
            "domainStrategy",
            "$.routing.domainStrategy".to_owned(),
        ) {
            None | Some("AsIs") => RoutingDomainStrategy::AsIs,
            Some("IPIfNonMatch") => RoutingDomainStrategy::IpIfNonMatch,
            Some("IPOnDemand") => RoutingDomainStrategy::IpOnDemand,
            Some(strategy) => {
                self.error(
                    "$.routing.domainStrategy",
                    format!("unsupported routing domainStrategy `{strategy}`"),
                );
                RoutingDomainStrategy::AsIs
            }
        }
    }

    fn parse_routing_rules(
        &mut self,
        routing: &Value,
        balancer_tags: &HashSet<&str>,
    ) -> Vec<RoutingRule> {
        let Some(raw_rules) = routing.get("rules") else {
            return Vec::new();
        };
        let Some(rules) = raw_rules.as_array() else {
            self.error("$.routing.rules", "field `rules` must be an array");
            return Vec::new();
        };
        if rules.len() > self.matcher_budget.limits.routing_rules {
            self.error(
                "$.routing.rules",
                format!(
                    "routing config contains {} rules; maximum supported per configuration is {}",
                    rules.len(),
                    self.matcher_budget.limits.routing_rules
                ),
            );
            return Vec::new();
        }

        rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| self.parse_routing_rule(rule, index, balancer_tags))
            .collect()
    }

    fn parse_routing_rule(
        &mut self,
        rule: &Value,
        index: usize,
        balancer_tags: &HashSet<&str>,
    ) -> Option<RoutingRule> {
        let rule_path = format!("$.routing.rules[{index}]");
        if !rule.is_object() {
            self.error(&rule_path, "routing rule must be an object");
            return None;
        }

        self.reject_unknown_fields(rule, &rule_path, &surface::ROUTING_RULE);

        // Xray-core v26.10.31 does not read `type`, so any value is ignored.
        if !matches!(
            rule.get("ruleTag"),
            None | Some(Value::Null | Value::String(_))
        ) {
            self.error(
                format!("{rule_path}.ruleTag"),
                "field `ruleTag` must be a string",
            );
            return None;
        }
        let outbound_tag = self.routing_tag(rule, "outboundTag", &rule_path)?;
        let balancer_tag = self.routing_tag(rule, "balancerTag", &rule_path)?;
        // As in Xray-core, a nonempty outboundTag wins over balancerTag.
        let target = if !outbound_tag.is_empty() {
            RoutingRuleTarget::Outbound(outbound_tag.to_owned())
        } else if !balancer_tag.is_empty() {
            if !balancer_tags.contains(balancer_tag) {
                self.error(
                    format!("{rule_path}.balancerTag"),
                    format!("routing balancer {balancer_tag:?} is not configured"),
                );
                return None;
            }
            RoutingRuleTarget::Balancer(balancer_tag.to_owned())
        } else {
            self.error(
                format!("{rule_path}.outboundTag"),
                "routing rule requires outboundTag or balancerTag",
            );
            return None;
        };

        let inbound_tags = self
            .string_list(rule.get("inboundTag"), &format!("{rule_path}.inboundTag"))?
            .unwrap_or_default()
            .into_iter()
            .map(|entry| entry.text.to_owned())
            .collect();
        let networks = self.network_list(rule.get("network"), &format!("{rule_path}.network"))?;
        // Unlike a final rule, a routing rule checks ports for any `port`
        // given, so `0` and `""` match no port.
        let port_ranges = self
            .port_list(
                rule.get("port"),
                &format!("{rule_path}.port"),
                U16SelectorKind::RoutingPort,
            )?
            .map(|list| list.ranges);
        let domain_matchers = self.routing_rule_domains(rule, &rule_path)?;
        let ip_matchers = match self.string_list(rule.get("ip"), &format!("{rule_path}.ip"))? {
            Some(entries) if !entries.is_empty() => Some(
                self.routing_ip_matcher_set(
                    entries
                        .into_iter()
                        .map(|entry| (Some(entry.text), entry.path)),
                )?,
            ),
            _ => None,
        };
        let local_os = self.parse_routing_local_os(rule, &rule_path)?;
        let origin = self.routing_rule_origin(rule, &rule_path)?;
        // As in Xray-core, any entry sets a condition, and empty names drop.
        let protocols = self
            .string_list(rule.get("protocol"), &format!("{rule_path}.protocol"))?
            .filter(|entries| !entries.is_empty())
            .map(|entries| {
                entries
                    .into_iter()
                    .filter(|entry| !entry.text.is_empty())
                    .map(|entry| entry.text.to_owned())
                    .collect()
            });
        let attributes =
            self.routing_attributes(rule.get("attrs"), &format!("{rule_path}.attrs"))?;

        let rule = RoutingRule {
            inbound_tags,
            networks,
            port_ranges,
            domain_matchers,
            ip_matchers,
            local_os,
            origin,
            protocols,
            attributes,
            target,
        };
        if !rule.has_condition() {
            self.error(rule_path, "routing rule has no effective fields");
            return None;
        }
        Some(rule)
    }

    /// `sourceIP` (or `source`), `sourcePort`, `localIP`, `localPort` and
    /// `user`, read as Xray-core v26.10.31 reads them.
    fn routing_rule_origin(&mut self, rule: &Value, rule_path: &str) -> Option<RoutingOrigin> {
        // Go decodes both, but reads `source` only when `sourceIP` is absent
        // or null.
        let source_ip = self.string_list(rule.get("sourceIP"), &format!("{rule_path}.sourceIP"))?;
        let source = self.string_list(rule.get("source"), &format!("{rule_path}.source"))?;
        let source_ips = self.routing_ip_list(source_ip.or(source))?;
        let local_ips = {
            let local = self.string_list(rule.get("localIP"), &format!("{rule_path}.localIP"))?;
            self.routing_ip_list(local)?
        };
        let source_ports = self
            .port_list(
                rule.get("sourcePort"),
                &format!("{rule_path}.sourcePort"),
                U16SelectorKind::RoutingPort,
            )?
            .map(|list| list.ranges);
        let local_ports = self
            .port_list(
                rule.get("localPort"),
                &format!("{rule_path}.localPort"),
                U16SelectorKind::RoutingPort,
            )?
            .map(|list| list.ranges);
        let users = self.routing_users(rule.get("user"), &format!("{rule_path}.user"))?;
        Some(RoutingOrigin {
            source_ips,
            source_ports,
            local_ips,
            local_ports,
            users,
        })
    }

    /// IP rules from a `StringList`; an absent, `null` or empty list sets no
    /// condition.
    fn routing_ip_list(
        &mut self,
        entries: Option<Vec<ListEntry<'_>>>,
    ) -> Option<Option<IpMatcherSet>> {
        match entries {
            Some(entries) if !entries.is_empty() => Some(Some(
                self.routing_ip_matcher_set(
                    entries
                        .into_iter()
                        .map(|entry| (Some(entry.text), entry.path)),
                )?,
            )),
            _ => Some(None),
        }
    }

    /// `user`: names, and `regexp:` patterns longer than the prefix. As in
    /// Xray-core, any entry sets a condition, empty names are dropped, and a
    /// pattern that does not compile is ignored, here with a warning.
    fn routing_users(&mut self, raw: Option<&Value>, path: &str) -> Option<Option<RoutingUsers>> {
        let Some(entries) = self.string_list(raw, path)? else {
            return Some(None);
        };
        if entries.is_empty() {
            return Some(None);
        }
        let mut users = RoutingUsers::default();
        for entry in entries {
            match entry.text.strip_prefix("regexp:") {
                Some(pattern) if !pattern.is_empty() => match RegexMatcher::new(pattern) {
                    Ok(pattern) => users.patterns.push(pattern),
                    Err(error) => self.warning(
                        &entry.path,
                        format!("ignoring the user pattern, as Xray-core does: {error}"),
                    ),
                },
                _ if entry.text.is_empty() => {}
                _ => users.names.push(entry.text.to_owned()),
            }
        }
        Some(Some(users))
    }

    /// `attrs`, Go's `map[string]string` of attribute names to regular
    /// expressions. As in Xray-core, `null` or `{}` sets no condition, a
    /// `null` pattern reads as an empty one, and a pattern that does not
    /// compile fails the config, where Xray-core panics.
    fn routing_attributes(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<Option<RoutingAttributes>> {
        let entries = match raw {
            None | Some(Value::Null) => return Some(None),
            Some(Value::Object(entries)) => entries,
            Some(_) => {
                self.error(path, "field `attrs` must be an object of strings");
                return None;
            }
        };
        if entries.is_empty() {
            return Some(None);
        }
        let mut attributes = RoutingAttributes::default();
        for (name, pattern) in entries {
            let pattern_path = format!("{path}.{name}");
            let pattern = match pattern {
                Value::String(pattern) => pattern.as_str(),
                Value::Null => "",
                _ => {
                    self.error(pattern_path, "an attribute pattern must be a string");
                    return None;
                }
            };
            match RegexMatcher::new(pattern) {
                Ok(pattern) => attributes.insert(name, pattern),
                Err(error) => {
                    self.error(
                        pattern_path,
                        format!("attribute pattern does not compile: {}", error.message),
                    );
                    return None;
                }
            }
        }
        Some(Some(attributes))
    }

    /// `outboundTag` or `balancerTag`: a string, or empty when absent or
    /// `null`.
    fn routing_tag<'v>(&mut self, rule: &'v Value, key: &str, rule_path: &str) -> Option<&'v str> {
        match rule.get(key) {
            None | Some(Value::Null) => Some(""),
            Some(Value::String(tag)) => Some(tag),
            Some(_) => {
                self.error(
                    format!("{rule_path}.{key}"),
                    format!("field `{key}` must be a string"),
                );
                None
            }
        }
    }

    /// `domain` and `domains`, each a `StringList` of domain rules. As in
    /// Xray-core, `domains` replaces `domain` when both are given, though
    /// both must parse.
    fn routing_rule_domains(
        &mut self,
        rule: &Value,
        rule_path: &str,
    ) -> Option<Option<DomainMatcherSet>> {
        let domain =
            self.routing_domain_list(rule.get("domain"), &format!("{rule_path}.domain"))?;
        let domains =
            self.routing_domain_list(rule.get("domains"), &format!("{rule_path}.domains"))?;
        Some(
            if rule.get("domains").is_some_and(|value| !value.is_null()) {
                domains
            } else {
                domain
            },
        )
    }

    fn routing_domain_list(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<Option<DomainMatcherSet>> {
        self.domain_rule_list(raw, path, DomainNameMode::Routing)
    }

    /// Xray's `localOS` is a Go `StringList`: an array of strings, or one
    /// string split at commas without trimming. Names are not validated; one
    /// that is no `runtime.GOOS` value simply never matches.
    fn parse_routing_local_os(&mut self, rule: &Value, rule_path: &str) -> Option<Vec<String>> {
        let path = format!("{rule_path}.localOS");
        match rule.get("localOS") {
            None | Some(Value::Null) => Some(Vec::new()),
            // As in Go, `""` splits into one empty name that no platform has.
            Some(Value::String(names)) => Some(names.split(',').map(str::to_owned).collect()),
            Some(Value::Array(names)) => names
                .iter()
                .enumerate()
                .map(|(index, name)| match name {
                    Value::String(name) => Some(name.to_owned()),
                    // Go reads `null` as an empty name.
                    Value::Null => Some(String::new()),
                    _ => {
                        self.error(format!("{path}[{index}]"), "localOS entry must be a string");
                        None
                    }
                })
                .collect(),
            Some(_) => {
                self.error(
                    path,
                    "localOS must be a string, an array of strings or null",
                );
                None
            }
        }
    }
}
