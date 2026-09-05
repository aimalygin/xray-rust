//! Routing configuration, selectors, and their bounded parser budgets.

use super::{parse_xray_duration, Parser, U16SelectorKind, OBSERVATORY_PROBE_TIMEOUT};
use crate::surface;
use crate::{
    Network, RoutingBalancer, RoutingBalancerStrategy, RoutingConfig, RoutingDomainStrategy,
    RoutingLeastLoadCost, RoutingLeastLoadSettings, RoutingPortRange, RoutingRule,
    RoutingRuleTarget,
};
use serde_json::Value;
use std::collections::HashSet;
use xray_routing::DomainMatcherSet;

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

        let type_path = format!("{rule_path}.type");
        let Some(rule_type) = self.optional_string_at(rule, "type", type_path.clone()) else {
            if rule.get("type").is_none() {
                self.error(type_path, "missing routing rule type");
            }
            return None;
        };
        if rule_type != "field" {
            self.error(
                type_path,
                format!("unsupported routing rule type `{rule_type}`"),
            );
            return None;
        }

        let outbound_tag = rule.get("outboundTag").filter(|value| !value.is_null());
        let balancer_tag = rule.get("balancerTag").filter(|value| !value.is_null());
        if outbound_tag.is_some() && balancer_tag.is_some() {
            self.error(
                format!("{rule_path}.balancerTag"),
                "routing rule cannot combine outboundTag and balancerTag",
            );
            return None;
        }
        let target = if outbound_tag.is_some() {
            let path = format!("{rule_path}.outboundTag");
            let tag = self.optional_string_at(rule, "outboundTag", path.clone())?;
            if tag.is_empty() {
                self.error(path, "routing rule outboundTag cannot be empty");
                return None;
            }
            RoutingRuleTarget::Outbound(tag.to_owned())
        } else if balancer_tag.is_some() {
            let path = format!("{rule_path}.balancerTag");
            let tag = self.optional_string_at(rule, "balancerTag", path.clone())?;
            if tag.is_empty() {
                self.error(path, "routing rule balancerTag cannot be empty");
                return None;
            }
            if !balancer_tags.contains(tag) {
                self.error(path, format!("routing balancer {tag:?} is not configured"));
                return None;
            }
            RoutingRuleTarget::Balancer(tag.to_owned())
        } else {
            self.error(
                format!("{rule_path}.outboundTag"),
                "routing rule requires outboundTag or balancerTag",
            );
            return None;
        };

        let inbound_tags =
            self.optional_string_array_at(rule, "inboundTag", format!("{rule_path}.inboundTag"))?;
        let networks = self.parse_routing_networks(rule, &rule_path)?;
        let port_ranges = self.parse_routing_port_ranges(rule, &rule_path)?;
        let domain_matchers = self.parse_routing_rule_domain_matchers(rule, &rule_path)?;
        let ip_matchers = self.parse_ip_matchers(rule, "ip", format!("{rule_path}.ip"))?;

        Some(RoutingRule {
            inbound_tags,
            networks,
            port_ranges,
            domain_matchers,
            ip_matchers,
            target,
        })
    }

    fn parse_routing_networks(&mut self, rule: &Value, rule_path: &str) -> Option<Vec<Network>> {
        let path = format!("{rule_path}.network");
        let mut networks = Vec::new();
        match rule.get("network") {
            None | Some(Value::Null) => return Some(networks),
            Some(Value::String(values)) => {
                for (index, value) in values.split(',').enumerate() {
                    self.push_routing_network(value, &format!("{path}[{index}]"), &mut networks)?;
                }
            }
            Some(Value::Array(values)) => {
                networks.reserve(values.len().min(2));
                for (index, value) in values.iter().enumerate() {
                    let item_path = format!("{path}[{index}]");
                    let Some(value) = value.as_str() else {
                        self.error(item_path, "routing network must be a string");
                        return None;
                    };
                    self.push_routing_network(value, &item_path, &mut networks)?;
                }
            }
            Some(_) => {
                self.error(path, "routing network must be a string, array, or null");
                return None;
            }
        }
        Some(networks)
    }

    fn push_routing_network(
        &mut self,
        raw: &str,
        path: &str,
        networks: &mut Vec<Network>,
    ) -> Option<()> {
        let network = if raw.eq_ignore_ascii_case("tcp") {
            Network::Tcp
        } else if raw.eq_ignore_ascii_case("udp") {
            Network::Udp
        } else {
            self.error(path, format!("unsupported routing network `{raw}`"));
            return None;
        };
        if !networks.contains(&network) {
            networks.push(network);
        }
        Some(())
    }

    fn parse_routing_port_ranges(
        &mut self,
        rule: &Value,
        rule_path: &str,
    ) -> Option<Vec<RoutingPortRange>> {
        let path = format!("{rule_path}.port");
        let pairs =
            self.parse_u16_selector_ranges(rule.get("port"), &path, U16SelectorKind::RoutingPort)?;
        let mut ranges = Vec::with_capacity(pairs.len());
        for (start, end) in pairs {
            match RoutingPortRange::new(start, end) {
                Ok(range) => ranges.push(range),
                Err(error) => {
                    self.error(&path, error.to_string());
                    return None;
                }
            }
        }
        Some(ranges)
    }

    fn parse_routing_rule_domain_matchers(
        &mut self,
        rule: &Value,
        rule_path: &str,
    ) -> Option<DomainMatcherSet> {
        let mut matchers = DomainMatcherSet::builder();
        self.parse_domain_matchers(rule, "domain", format!("{rule_path}.domain"), &mut matchers)?;
        self.parse_domain_matchers(
            rule,
            "domains",
            format!("{rule_path}.domains"),
            &mut matchers,
        )?;
        self.build_domain_matcher_set(matchers, &format!("{rule_path}.domain"))
    }
}
