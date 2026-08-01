use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use serde_json::Value;
use uuid::Uuid;

use crate::{
    geodata::{default_geodata_dirs, GeodataLoader},
    CoreConfig, Diagnostic, DnsConfig, DnsFakeIpConfig, DnsHostMapping, DnsHostTarget, DnsIpFilter,
    DnsNameServerConfig, DnsOutboundRule, DnsOutboundRuleAction, DnsOutboundSettings,
    DnsQTypeRange, DnsQueryStrategy, DnsServerConfig, DnsServerEndpoint, DnsServerTransport,
    DomainMatcher, HappyEyeballsSettings, InboundConfig, InboundProtocol, InboundSniffingConfig,
    IpCidr, IpMatcher, Network, OutboundConfig, OutboundProtocol, OutboundSettings, PolicyConfig,
    PolicyLevelConfig, PolicySystemConfig, RealitySettings, RealityShortId, RegexMatcher,
    RoutingConfig, RoutingDomainStrategy, RoutingPortRange, RoutingRule, SniffingDestination,
    SocketOptions, StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings,
    VlessUser, MAX_DNS_SERVER_TIMEOUT_MS,
};

const MAX_ROUTING_RULES: usize = 4_096;
const MAX_DNS_OUTBOUND_RULES: usize = 4_096;
const MAX_DNS_QTYPE_SELECTORS: usize = 65_536;
const MAX_ROUTING_PORT_SELECTORS: usize = 65_536;
const MAX_CONFIG_DOMAIN_MATCHERS: usize = 250_000;
const MAX_CONFIG_IP_MATCHERS: usize = 300_000;
const MAX_CONFIG_MATCHERS: usize = 500_000;
const MAX_CONFIG_GEODATA_ATTR_FILTERS: usize = 32;
const MAX_CONFIG_GEODATA_ATTRIBUTE_SIZE: usize = 256;
const MAX_DNS_SERVERS: usize = 8;
const DEFAULT_FAKE_IP_POOL_SIZE: u32 = 32_768;
const TUN_DNS_ANCHOR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const TUN_CLIENT_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpMatcherParseMode {
    Routing,
    XrayDns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum U16SelectorKind {
    DnsQType,
    RoutingPort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyDnsNonIpMode {
    Reject,
    Drop,
    Skip,
}

fn is_tun_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => matches!(ip, TUN_DNS_ANCHOR | TUN_CLIENT_IPV4),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .is_some_and(|ip| matches!(ip, TUN_DNS_ANCHOR | TUN_CLIENT_IPV4)),
    }
}

fn dns_query_strategies_overlap(global: DnsQueryStrategy, server: DnsQueryStrategy) -> bool {
    global == DnsQueryStrategy::UseIp || server == DnsQueryStrategy::UseIp || global == server
}

fn parse_dns_tcp_server_uri(
    address: &str,
) -> Result<Option<(DnsServerTransport, DnsServerEndpoint)>, String> {
    let Some((scheme, remainder)) = address.split_once(':') else {
        return Ok(None);
    };
    let transport = if scheme.eq_ignore_ascii_case("tcp") {
        DnsServerTransport::TcpRouted
    } else if scheme.eq_ignore_ascii_case("tcp+local") {
        DnsServerTransport::TcpLocal
    } else {
        return Ok(None);
    };
    let Some(authority) = remainder.strip_prefix("//") else {
        return Err("dns TCP server URL must use `tcp://` or `tcp+local://`".to_owned());
    };
    if address
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(
            "dns TCP server URL must not contain whitespace or control characters".to_owned(),
        );
    }
    if authority.is_empty() {
        return Err("dns TCP server URL must include a host".to_owned());
    }
    if authority.contains('@') {
        return Err("dns TCP server URL must not include userinfo".to_owned());
    }
    if authority.contains('/') {
        return Err("dns TCP server URL must not include a path".to_owned());
    }
    if authority.contains('?') {
        return Err("dns TCP server URL must not include a query".to_owned());
    }
    if authority.contains('#') {
        return Err("dns TCP server URL must not include a fragment".to_owned());
    }

    let endpoint = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return Err("dns TCP server URL contains a malformed bracketed IPv6 host".to_owned());
        };
        if host.is_empty() || host.contains(['[', ']']) {
            return Err("dns TCP server URL contains a malformed bracketed IPv6 host".to_owned());
        }
        let port = match suffix {
            "" => 53,
            suffix => {
                let Some(port) = suffix.strip_prefix(':') else {
                    return Err(
                        "dns TCP server URL must contain only a host and optional port".to_owned(),
                    );
                };
                parse_dns_tcp_server_port(port)?
            }
        };
        let socket = format!("[{host}]:{port}")
            .parse::<SocketAddr>()
            .map_err(|_| "dns TCP server URL contains an invalid bracketed IPv6 host".to_owned())?;
        if !socket.is_ipv6() {
            return Err("dns TCP server URL brackets are only valid for IPv6 hosts".to_owned());
        }
        DnsServerEndpoint::Ip(socket)
    } else {
        if authority.contains(['[', ']']) {
            return Err("dns TCP server URL contains malformed host brackets".to_owned());
        }
        if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
            return Err("dns TCP server URL requires brackets around an IPv6 host".to_owned());
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, parse_dns_tcp_server_port(port)?),
            None => (authority, 53),
        };
        if host.is_empty() {
            return Err("dns TCP server URL must include a host".to_owned());
        }
        if host.contains(['\\', '%']) {
            return Err("dns TCP server URL contains an invalid host".to_owned());
        }
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => DnsServerEndpoint::Ip(SocketAddr::new(ip.into(), port)),
            Ok(IpAddr::V6(_)) => {
                return Err("dns TCP server URL requires brackets around an IPv6 host".to_owned());
            }
            Err(_) => DnsServerEndpoint::Domain {
                domain: host.to_owned(),
                port,
            },
        }
    };

    if matches!(&endpoint, DnsServerEndpoint::Ip(address) if is_tun_reserved_ip(address.ip())) {
        return Err("dns server cannot point at a tunnel-local DNS address".to_owned());
    }

    Ok(Some((transport, endpoint)))
}

fn parse_dns_tcp_server_port(port: &str) -> Result<u16, String> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("dns TCP server URL contains an invalid port".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "dns TCP server URL contains an invalid port".to_owned())?;
    if port == 0 {
        return Err("dns server port must be greater than zero".to_owned());
    }
    Ok(port)
}

fn dns_tcp_server_policy(
    transport: DnsServerTransport,
    endpoint: DnsServerEndpoint,
) -> DnsServerConfig {
    DnsServerConfig::Policy(DnsNameServerConfig {
        endpoint,
        transport,
        domains: Vec::new(),
        expected_ips: DnsIpFilter::default(),
        unexpected_ips: DnsIpFilter::default(),
        tag: String::new(),
        timeout_ms: 0,
        skip_fallback: false,
        query_strategy: DnsQueryStrategy::UseIp,
        final_query: false,
    })
}

fn fake_ip_usable_address_count(pool: IpCidr) -> u64 {
    let IpAddr::V4(network) = pool.network() else {
        return 0;
    };

    let address_count = 1_u64 << u32::from(32 - pool.prefix());
    let first_offset = u64::from(address_count > 2);
    let end_offset = if address_count > 2 {
        address_count - 1
    } else {
        address_count
    };
    let mut usable = end_offset - first_offset;

    let mask = if pool.prefix() == 0 {
        0
    } else {
        u32::MAX << u32::from(32 - pool.prefix())
    };
    let network_base = u32::from(network) & mask;
    for reserved in [TUN_DNS_ANCHOR, TUN_CLIENT_IPV4] {
        let reserved_offset = u32::from(reserved)
            .checked_sub(network_base)
            .map(u64::from)
            .filter(|offset| (first_offset..end_offset).contains(offset));
        if reserved_offset.is_some() {
            usable -= 1;
        }
    }

    usable
}

#[derive(Debug, Clone, Copy)]
struct MatcherBudgetLimits {
    routing_rules: usize,
    domain_matchers: usize,
    ip_matchers: usize,
    total_matchers: usize,
}

const DEFAULT_MATCHER_BUDGET_LIMITS: MatcherBudgetLimits = MatcherBudgetLimits {
    routing_rules: MAX_ROUTING_RULES,
    domain_matchers: MAX_CONFIG_DOMAIN_MATCHERS,
    ip_matchers: MAX_CONFIG_IP_MATCHERS,
    total_matchers: MAX_CONFIG_MATCHERS,
};

#[derive(Debug)]
struct MatcherBudget {
    limits: MatcherBudgetLimits,
    domain_matchers: usize,
    ip_matchers: usize,
}

#[derive(Debug, Default)]
struct SelectorBudget {
    dns_outbound_rules: usize,
    dns_qtype_selectors: usize,
    routing_port_selectors: usize,
}

impl SelectorBudget {
    fn consume_dns_outbound_rules(&mut self, count: usize) -> bool {
        let Some(next) = self.dns_outbound_rules.checked_add(count) else {
            return false;
        };
        if next > MAX_DNS_OUTBOUND_RULES {
            return false;
        }
        self.dns_outbound_rules = next;
        true
    }

    fn consume_dns_qtype_selector(&mut self) -> bool {
        if self.dns_qtype_selectors >= MAX_DNS_QTYPE_SELECTORS {
            return false;
        }
        self.dns_qtype_selectors += 1;
        true
    }

    fn consume_routing_port_selector(&mut self) -> bool {
        if self.routing_port_selectors >= MAX_ROUTING_PORT_SELECTORS {
            return false;
        }
        self.routing_port_selectors += 1;
        true
    }
}

impl MatcherBudget {
    fn new(limits: MatcherBudgetLimits) -> Self {
        Self {
            limits,
            domain_matchers: 0,
            ip_matchers: 0,
        }
    }

    fn remaining_domain_matchers(&self) -> usize {
        self.limits
            .domain_matchers
            .saturating_sub(self.domain_matchers)
            .min(self.remaining_total_matchers())
    }

    fn remaining_ip_matchers(&self) -> usize {
        self.limits
            .ip_matchers
            .saturating_sub(self.ip_matchers)
            .min(self.remaining_total_matchers())
    }

    fn remaining_total_matchers(&self) -> usize {
        self.limits
            .total_matchers
            .saturating_sub(self.domain_matchers.saturating_add(self.ip_matchers))
    }

    fn consume_domain_matchers(&mut self, count: usize) -> bool {
        if count > self.remaining_domain_matchers() {
            return false;
        }
        self.domain_matchers += count;
        true
    }

    fn consume_ip_matchers(&mut self, count: usize) -> bool {
        if count > self.remaining_ip_matchers() {
            return false;
        }
        self.ip_matchers += count;
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig {
    pub config: CoreConfig,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("xray config parse failed")]
pub struct ConfigParseError {
    pub diagnostics: Vec<Diagnostic>,
}

pub fn parse_xray_json(raw: &str) -> Result<ParsedConfig, ConfigParseError> {
    parse_xray_json_with_loader(raw, GeodataLoader::default())
}

pub fn parse_xray_json_with_geodata_dir<P: AsRef<Path>>(
    raw: &str,
    dir: P,
) -> Result<ParsedConfig, ConfigParseError> {
    parse_xray_json_with_geodata_dirs(raw, &[dir])
}

pub fn parse_xray_json_with_geodata_dirs<P: AsRef<Path>>(
    raw: &str,
    dirs: &[P],
) -> Result<ParsedConfig, ConfigParseError> {
    parse_xray_json_with_loader(
        raw,
        GeodataLoader::from_dirs(geodata_dirs_with_defaults(dirs)),
    )
}

fn geodata_dirs_with_defaults<P: AsRef<Path>>(dirs: &[P]) -> Vec<PathBuf> {
    let mut search_dirs = dirs
        .iter()
        .map(|dir| dir.as_ref().to_path_buf())
        .collect::<Vec<PathBuf>>();

    for dir in default_geodata_dirs() {
        if !search_dirs.iter().any(|existing| existing == &dir) {
            search_dirs.push(dir);
        }
    }

    search_dirs
}

fn parse_xray_json_with_loader(
    raw: &str,
    geodata_loader: GeodataLoader,
) -> Result<ParsedConfig, ConfigParseError> {
    parse_xray_json_with_loader_and_limits(raw, geodata_loader, DEFAULT_MATCHER_BUDGET_LIMITS)
}

fn parse_xray_json_with_loader_and_limits(
    raw: &str,
    geodata_loader: GeodataLoader,
    matcher_budget_limits: MatcherBudgetLimits,
) -> Result<ParsedConfig, ConfigParseError> {
    let value = serde_json::from_str::<Value>(raw).map_err(|err| ConfigParseError {
        diagnostics: vec![Diagnostic::error("$", err.to_string())],
    })?;

    let mut parser = Parser {
        root: &value,
        diagnostics: Vec::new(),
        geodata_loader,
        matcher_budget: MatcherBudget::new(matcher_budget_limits),
        selector_budget: SelectorBudget::default(),
    };
    let config = parser.parse_config();

    if parser
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == crate::DiagnosticSeverity::Error)
    {
        Err(ConfigParseError {
            diagnostics: parser.diagnostics,
        })
    } else {
        Ok(ParsedConfig {
            config,
            diagnostics: parser.diagnostics,
        })
    }
}

struct Parser<'a> {
    root: &'a Value,
    diagnostics: Vec<Diagnostic>,
    geodata_loader: GeodataLoader,
    matcher_budget: MatcherBudget,
    selector_budget: SelectorBudget,
}

impl Parser<'_> {
    fn parse_config(&mut self) -> CoreConfig {
        self.validate_top_level_fields();
        let inbounds = self.parse_inbounds();
        let outbounds = self.parse_outbounds();
        let routing = self.parse_routing();
        let dns = self.parse_dns();
        let policy = self.parse_policy();
        let default_outbound_tag = outbounds.first().and_then(|outbound| outbound.tag.clone());

        CoreConfig {
            inbounds,
            outbounds,
            default_outbound_tag,
            routing,
            dns,
            policy,
        }
    }

    fn validate_top_level_fields(&mut self) {
        self.reject_unknown_fields(
            self.root,
            "$",
            &["log", "inbounds", "outbounds", "routing", "dns", "policy"],
        );
    }

    fn parse_dns(&mut self) -> DnsConfig {
        let Some(dns) = self.root.get("dns") else {
            return DnsConfig::default();
        };
        let dns_path = "$.dns";
        if !dns.is_object() {
            self.error(dns_path, "dns must be an object");
            return DnsConfig::default();
        }

        self.reject_unknown_fields(
            dns,
            dns_path,
            &[
                "fakeIp",
                "servers",
                "hosts",
                "tag",
                "queryStrategy",
                "disableFallback",
                "disableFallbackIfMatch",
            ],
        );
        let query_strategy = self.parse_dns_query_strategy(dns);
        DnsConfig {
            fake_ip: self.parse_dns_fake_ip(dns),
            servers: self.parse_dns_servers(dns, query_strategy),
            hosts: self.parse_dns_hosts(dns),
            tag: self
                .nullable_string_at(dns, "tag", "$.dns.tag".to_owned())
                .unwrap_or_default()
                .to_owned(),
            query_strategy,
            disable_fallback: self
                .optional_bool_at(dns, "disableFallback", "$.dns.disableFallback".to_owned())
                .unwrap_or(false),
            disable_fallback_if_match: self
                .optional_bool_at(
                    dns,
                    "disableFallbackIfMatch",
                    "$.dns.disableFallbackIfMatch".to_owned(),
                )
                .unwrap_or(false),
        }
    }

    fn parse_dns_query_strategy(&mut self, dns: &Value) -> DnsQueryStrategy {
        self.parse_dns_query_strategy_at(dns.get("queryStrategy"), "$.dns.queryStrategy")
    }

    fn parse_dns_query_strategy_at(
        &mut self,
        raw_strategy: Option<&Value>,
        path: &str,
    ) -> DnsQueryStrategy {
        let Some(raw_strategy) = raw_strategy else {
            return DnsQueryStrategy::default();
        };
        let Some(strategy) = raw_strategy.as_str() else {
            self.error(path, "dns queryStrategy must be a string");
            return DnsQueryStrategy::default();
        };

        match strategy.to_ascii_lowercase().as_str() {
            "useip" | "use_ip" | "use-ip" => DnsQueryStrategy::UseIp,
            "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4"
            | "use-ipv4" | "use-ip-v4" => DnsQueryStrategy::UseIpv4,
            "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6"
            | "use-ipv6" | "use-ip-v6" => DnsQueryStrategy::UseIpv6,
            "usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys" | "use-system" => {
                self.error(
                    path,
                    "dns queryStrategy `UseSystem` requires platform route capability and is not supported",
                );
                DnsQueryStrategy::default()
            }
            _ => {
                self.error(
                    path,
                    format!(
                        "unsupported dns queryStrategy `{strategy}`; expected UseIP, UseIPv4, or UseIPv6"
                    ),
                );
                DnsQueryStrategy::default()
            }
        }
    }

    fn parse_dns_servers(
        &mut self,
        dns: &Value,
        global_query_strategy: DnsQueryStrategy,
    ) -> Vec<DnsServerConfig> {
        let Some(raw_servers) = dns.get("servers") else {
            return Vec::new();
        };
        let Some(servers) = raw_servers.as_array() else {
            self.error("$.dns.servers", "field `servers` must be an array");
            return Vec::new();
        };
        if servers.len() > MAX_DNS_SERVERS {
            self.error(
                "$.dns.servers",
                format!(
                    "dns config contains {} servers; maximum supported per configuration is {}",
                    servers.len(),
                    MAX_DNS_SERVERS
                ),
            );
            return Vec::new();
        }

        servers
            .iter()
            .enumerate()
            .filter_map(|(index, server)| {
                let path = format!("$.dns.servers[{index}]");
                match server {
                    Value::String(server) => self.parse_dns_server(server, &path),
                    Value::Object(_) => {
                        self.parse_dns_name_server(server, &path, global_query_strategy)
                    }
                    _ => {
                        self.error(path, "dns server must be a string or an object");
                        None
                    }
                }
            })
            .collect()
    }

    fn parse_dns_name_server(
        &mut self,
        server: &Value,
        path: &str,
        global_query_strategy: DnsQueryStrategy,
    ) -> Option<DnsServerConfig> {
        self.reject_unknown_fields(
            server,
            path,
            &[
                "address",
                "port",
                "domains",
                "expectedIPs",
                "expectIPs",
                "unexpectedIPs",
                "tag",
                "timeoutMs",
                "skipFallback",
                "queryStrategy",
                "finalQuery",
            ],
        );

        let address_path = format!("{path}.address");
        let Some(address) = self.optional_string_at(server, "address", address_path.clone()) else {
            if server.get("address").is_none() {
                self.error(address_path, "missing dns server address");
            }
            return None;
        };
        let port_path = format!("{path}.port");
        let port = if server.get("port").is_some() {
            self.u16_at(server, "port", port_path.clone())?
        } else {
            53
        };
        let port = if port == 0 { 53 } else { port };
        let (transport, endpoint) = match parse_dns_tcp_server_uri(address) {
            Ok(Some((transport, endpoint))) => (transport, endpoint),
            Ok(None) => (
                DnsServerTransport::Classic,
                self.parse_dns_server_endpoint(address, port, &address_path)?,
            ),
            Err(message) => {
                self.error(&address_path, message);
                return None;
            }
        };
        let domains = self.parse_dns_server_domains(server, path)?;
        let (expected_ips, unexpected_ips) = self.parse_dns_server_ip_filters(server, path)?;
        let timeout_path = format!("{path}.timeoutMs");
        let timeout_ms = match server.get("timeoutMs") {
            None | Some(Value::Null) => 0,
            Some(_) => self.optional_u64_at(server, "timeoutMs", timeout_path.clone())?,
        };
        if timeout_ms > MAX_DNS_SERVER_TIMEOUT_MS {
            self.error(
                timeout_path,
                format!(
                    "dns server timeoutMs {timeout_ms} exceeds the largest timeout safe across Xray duration conversions {MAX_DNS_SERVER_TIMEOUT_MS}ms"
                ),
            );
            return None;
        }
        let query_strategy_path = format!("{path}.queryStrategy");
        let query_strategy =
            self.parse_dns_query_strategy_at(server.get("queryStrategy"), &query_strategy_path);
        if !dns_query_strategies_overlap(global_query_strategy, query_strategy) {
            self.error(
                query_strategy_path,
                "dns server queryStrategy has no address family in common with global dns.queryStrategy",
            );
            return None;
        }

        Some(DnsServerConfig::Policy(DnsNameServerConfig {
            endpoint,
            transport,
            domains,
            expected_ips,
            unexpected_ips,
            tag: self
                .nullable_string_at(server, "tag", format!("{path}.tag"))
                .unwrap_or_default()
                .to_owned(),
            timeout_ms,
            skip_fallback: self
                .optional_bool_at(server, "skipFallback", format!("{path}.skipFallback"))
                .unwrap_or(false),
            query_strategy,
            final_query: self
                .optional_bool_at(server, "finalQuery", format!("{path}.finalQuery"))
                .unwrap_or(false),
        }))
    }

    fn parse_dns_server_ip_filters(
        &mut self,
        server: &Value,
        path: &str,
    ) -> Option<(DnsIpFilter, DnsIpFilter)> {
        let expected_path = format!("{path}.expectedIPs");
        let alias_path = format!("{path}.expectIPs");
        let expected = self.parse_dns_string_list(server, "expectedIPs", &expected_path)?;
        let alias = self.parse_dns_string_list(server, "expectIPs", &alias_path)?;
        let expected_ips = if expected.is_empty() {
            self.parse_dns_ip_filter(&alias, &alias_path)?
        } else {
            self.parse_dns_ip_filter(&expected, &expected_path)?
        };

        let unexpected_path = format!("{path}.unexpectedIPs");
        let unexpected = self.parse_dns_string_list(server, "unexpectedIPs", &unexpected_path)?;
        let unexpected_ips = self.parse_dns_ip_filter(&unexpected, &unexpected_path)?;

        Some((expected_ips, unexpected_ips))
    }

    fn parse_dns_string_list<'value>(
        &mut self,
        value: &'value Value,
        key: &str,
        path: &str,
    ) -> Option<Vec<&'value str>> {
        let Some(raw) = value.get(key) else {
            return Some(Vec::new());
        };

        match raw {
            Value::Null => Some(Vec::new()),
            Value::String(values) => Some(values.split(',').collect()),
            Value::Array(values) => {
                let mut strings = Vec::with_capacity(values.len());
                for (index, value) in values.iter().enumerate() {
                    let Some(value) = value.as_str() else {
                        self.error(
                            format!("{path}[{index}]"),
                            "dns server IP matcher must be a string",
                        );
                        return None;
                    };
                    strings.push(value);
                }
                Some(strings)
            }
            _ => {
                self.error(path, format!("field `{key}` must be a string or an array"));
                None
            }
        }
    }

    fn parse_dns_ip_filter(&mut self, values: &[&str], path: &str) -> Option<DnsIpFilter> {
        let mut filter = DnsIpFilter::default();
        for (index, value) in values.iter().copied().enumerate() {
            if value == "*" {
                filter.soft = true;
                continue;
            }

            let item_path = format!("{path}[{index}]");
            let remaining = self.matcher_budget.remaining_ip_matchers();
            if remaining == 0 {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
            let is_geoip = dns_ip_rule_uses_geodata(value);
            let matchers = self.parse_dns_ip_matcher(value, &item_path, remaining)?;
            if !self.matcher_budget.consume_ip_matchers(matchers.len()) {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
            if is_geoip {
                filter.geoip_matchers.extend(matchers);
            } else {
                filter.custom_matchers.extend(matchers);
            }
        }
        Some(filter)
    }

    fn parse_dns_server_endpoint(
        &mut self,
        address: &str,
        port: u16,
        path: &str,
    ) -> Option<DnsServerEndpoint> {
        if address.is_empty() {
            self.error(path, "dns server address cannot be empty");
            return None;
        }
        if address.trim() != address {
            self.error(
                path,
                "dns server address must not contain surrounding whitespace",
            );
            return None;
        }
        if let Ok(ip) = address.parse::<IpAddr>() {
            if is_tun_reserved_ip(ip) {
                self.error(
                    path,
                    "dns server cannot point at a tunnel-local DNS address",
                );
                return None;
            }
            return Some(DnsServerEndpoint::Ip(SocketAddr::new(ip, port)));
        }
        if address.eq_ignore_ascii_case("localhost") || address.eq_ignore_ascii_case("fakedns") {
            self.error(
                path,
                format!("special dns server `{address}` is not supported yet"),
            );
            return None;
        }
        if address.parse::<SocketAddr>().is_ok() || address.contains(':') {
            self.error(
                path,
                "object dns server address must not include a port or unsupported URL scheme",
            );
            return None;
        }

        Some(DnsServerEndpoint::Domain {
            domain: address.to_owned(),
            port,
        })
    }

    fn parse_dns_server_domains(
        &mut self,
        server: &Value,
        path: &str,
    ) -> Option<Vec<DomainMatcher>> {
        let domains_path = format!("{path}.domains");
        let Some(raw_domains) = server.get("domains") else {
            return Some(Vec::new());
        };
        let mut matchers = Vec::new();
        match raw_domains {
            Value::String(domains) => {
                for (index, domain) in domains.split(',').enumerate() {
                    let item_path = format!("{domains_path}[{index}]");
                    self.parse_dns_server_domain_matcher(domain, &item_path, &mut matchers)?;
                }
            }
            Value::Array(domains) => {
                matchers.reserve(
                    domains
                        .len()
                        .min(self.matcher_budget.remaining_domain_matchers()),
                );
                for (index, domain) in domains.iter().enumerate() {
                    let item_path = format!("{domains_path}[{index}]");
                    let Some(domain) = domain.as_str() else {
                        self.error(item_path, "dns server domain matcher must be a string");
                        return None;
                    };
                    self.parse_dns_server_domain_matcher(domain, &item_path, &mut matchers)?;
                }
            }
            _ => {
                self.error(domains_path, "field `domains` must be a string or an array");
                return None;
            }
        }
        Some(matchers)
    }

    fn parse_dns_server_domain_matcher(
        &mut self,
        domain: &str,
        path: &str,
        matchers: &mut Vec<DomainMatcher>,
    ) -> Option<()> {
        if domain.is_empty() {
            self.error(path, "dns server domain matcher cannot be empty");
            return None;
        }
        let remaining = self.matcher_budget.remaining_domain_matchers();
        if remaining == 0 {
            self.domain_matcher_budget_error(path);
            return None;
        }
        let parsed_matchers = self.parse_domain_matcher(domain, path, remaining)?;
        if !self
            .matcher_budget
            .consume_domain_matchers(parsed_matchers.len())
        {
            self.domain_matcher_budget_error(path);
            return None;
        }
        matchers.extend(parsed_matchers);
        Some(())
    }

    fn parse_dns_server(&mut self, server: &str, path: &str) -> Option<DnsServerConfig> {
        if server.is_empty() {
            self.error(path, "dns server cannot be empty");
            return None;
        }
        if server.trim() != server {
            self.error(path, "dns server must not contain surrounding whitespace");
            return None;
        }

        match parse_dns_tcp_server_uri(server) {
            Ok(Some((transport, endpoint))) => {
                return Some(dns_tcp_server_policy(transport, endpoint));
            }
            Ok(None) => {}
            Err(message) => {
                self.error(path, message);
                return None;
            }
        }

        if let Ok(socket_addr) = server.parse::<SocketAddr>() {
            if socket_addr.port() == 0 {
                self.error(path, "dns server port must be greater than zero");
                return None;
            }
            if is_tun_reserved_ip(socket_addr.ip()) {
                self.error(
                    path,
                    "dns server cannot point at a tunnel-local DNS address",
                );
                return None;
            }
            return Some(DnsServerConfig::Ip(socket_addr));
        }
        if let Ok(ip) = server.parse::<IpAddr>() {
            if is_tun_reserved_ip(ip) {
                self.error(
                    path,
                    "dns server cannot point at a tunnel-local DNS address",
                );
                return None;
            }
            return Some(DnsServerConfig::Ip(SocketAddr::new(ip, 53)));
        }

        let (domain, port) = match server.rsplit_once(':') {
            Some((domain, port)) if !domain.contains(':') => {
                let Some(port) = port.parse::<u16>().ok() else {
                    self.error(path, format!("invalid dns server port `{port}`"));
                    return None;
                };
                if port == 0 {
                    self.error(path, "dns server port must be greater than zero");
                    return None;
                }
                (domain, port)
            }
            _ => (server, 53),
        };
        if domain.is_empty() {
            self.error(path, "dns server domain cannot be empty");
            return None;
        }

        Some(DnsServerConfig::Domain {
            domain: domain.to_owned(),
            port,
        })
    }

    fn parse_dns_hosts(&mut self, dns: &Value) -> Vec<DnsHostMapping> {
        let Some(raw_hosts) = dns.get("hosts") else {
            return Vec::new();
        };
        let Some(hosts) = raw_hosts.as_object() else {
            self.error("$.dns.hosts", "field `hosts` must be an object");
            return Vec::new();
        };

        let mut mappings = Vec::new();
        for (host, target) in hosts {
            let path = format!("$.dns.hosts.{host}");
            let Some(target) = self.parse_dns_host_target(target, &path) else {
                continue;
            };
            let remaining = self.matcher_budget.remaining_domain_matchers();
            if remaining == 0 {
                self.domain_matcher_budget_error(&path);
                continue;
            }
            let Some(matchers) = self.parse_dns_host_matcher(host, &path, remaining) else {
                continue;
            };
            if !self.matcher_budget.consume_domain_matchers(matchers.len()) {
                self.domain_matcher_budget_error(&path);
                continue;
            }
            mappings.extend(matchers.into_iter().map(|matcher| DnsHostMapping {
                matcher,
                target: target.clone(),
            }));
        }

        mappings
    }

    fn parse_dns_host_matcher(
        &mut self,
        value: &str,
        path: &str,
        max_matchers: usize,
    ) -> Option<Vec<DomainMatcher>> {
        // Xray's `dns.hosts` grammar defaults an unprefixed key to `full:`.
        // Routing rules deliberately keep their separate keyword default.
        if !value.contains(':') {
            if value.is_empty() {
                self.error(path, "DNS host domain cannot be empty");
                return None;
            }
            return Some(vec![DomainMatcher::Full(value.to_owned())]);
        }

        self.parse_domain_matcher(value, path, max_matchers)
    }

    fn parse_dns_host_target(&mut self, target: &Value, path: &str) -> Option<DnsHostTarget> {
        if let Some(target) = target.as_str() {
            return Some(match target.parse::<IpAddr>() {
                Ok(ip) => DnsHostTarget::Ip(ip),
                Err(_) => DnsHostTarget::Domain(target.to_owned()),
            });
        }

        let Some(targets) = target.as_array() else {
            self.error(path, "dns host target must be a string or an array");
            return None;
        };
        if targets.is_empty() {
            self.error(path, "dns host target array must not be empty");
            return None;
        }

        let mut ips = Vec::with_capacity(targets.len());
        for (index, target) in targets.iter().enumerate() {
            let element_path = format!("{path}[{index}]");
            let Some(target) = target.as_str() else {
                self.error(element_path, "dns host target array item must be a string");
                return None;
            };
            let Ok(ip) = target.parse::<IpAddr>() else {
                self.error(
                    element_path,
                    "dns host target array item must be an IP address",
                );
                return None;
            };
            ips.push(ip);
        }

        Some(DnsHostTarget::Ips(ips))
    }

    fn parse_dns_fake_ip(&mut self, dns: &Value) -> Option<DnsFakeIpConfig> {
        let fake_ip = dns.get("fakeIp")?;
        let fake_ip_path = "$.dns.fakeIp";
        if !fake_ip.is_object() {
            self.error(fake_ip_path, "dns fakeIp must be an object");
            return None;
        }

        self.reject_unknown_fields(
            fake_ip,
            fake_ip_path,
            &["enabled", "ipv4Pool", "poolSize", "ttl"],
        );
        let enabled = self
            .optional_bool_at(fake_ip, "enabled", format!("{fake_ip_path}.enabled"))
            .unwrap_or(false);
        let ttl = self
            .optional_u32_at(fake_ip, "ttl", format!("{fake_ip_path}.ttl"))
            .unwrap_or(60);

        if !enabled {
            return None;
        }
        if ttl == 0 {
            self.error(
                format!("{fake_ip_path}.ttl"),
                "fakeIp ttl must be greater than zero",
            );
            return None;
        }

        let ipv4_pool_path = format!("{fake_ip_path}.ipv4Pool");
        let Some(raw_pool) = self.optional_string_at(fake_ip, "ipv4Pool", ipv4_pool_path.clone())
        else {
            if fake_ip.get("ipv4Pool").is_none() {
                self.error(ipv4_pool_path, "missing fakeIp ipv4Pool");
            }
            return None;
        };
        let pool = self.parse_ip_cidr(raw_pool, &ipv4_pool_path)?;
        if !matches!(pool.network(), IpAddr::V4(_)) {
            self.error(ipv4_pool_path, "fakeIp ipv4Pool must be an IPv4 CIDR");
            return None;
        }

        let usable_address_count = fake_ip_usable_address_count(pool);
        if usable_address_count == 0 {
            self.error(ipv4_pool_path, "fakeIp ipv4Pool has no usable addresses");
            return None;
        }

        let pool_size_path = format!("{fake_ip_path}.poolSize");
        let explicit_pool_size = self.optional_u32_at(fake_ip, "poolSize", pool_size_path.clone());
        let pool_size = match explicit_pool_size {
            Some(0) => {
                self.error(pool_size_path, "fakeIp poolSize must be greater than zero");
                return None;
            }
            Some(pool_size) if u64::from(pool_size) > usable_address_count => {
                self.error(
                    pool_size_path,
                    format!(
                        "fakeIp poolSize exceeds the {usable_address_count} usable addresses in ipv4Pool"
                    ),
                );
                return None;
            }
            Some(pool_size) => pool_size,
            None => u32::try_from(usable_address_count.min(u64::from(DEFAULT_FAKE_IP_POOL_SIZE)))
                .unwrap_or(DEFAULT_FAKE_IP_POOL_SIZE),
        };

        Some(DnsFakeIpConfig {
            enabled,
            ipv4_pool: pool,
            pool_size,
            ttl,
        })
    }

    fn parse_policy(&mut self) -> PolicyConfig {
        let Some(policy) = self.root.get("policy") else {
            return PolicyConfig::default();
        };
        let policy_path = "$.policy";
        if !policy.is_object() {
            self.error(policy_path, "policy must be an object");
            return PolicyConfig::default();
        }

        self.reject_unknown_fields(policy, policy_path, &["levels", "system"]);
        PolicyConfig {
            levels: self.parse_policy_levels(policy),
            system: self.parse_policy_system(policy),
        }
    }

    fn parse_policy_levels(
        &mut self,
        policy: &Value,
    ) -> std::collections::BTreeMap<u32, PolicyLevelConfig> {
        let Some(raw_levels) = policy.get("levels") else {
            return std::collections::BTreeMap::new();
        };
        let Some(levels) = raw_levels.as_object() else {
            self.error("$.policy.levels", "policy levels must be an object");
            return std::collections::BTreeMap::new();
        };

        let mut parsed = std::collections::BTreeMap::new();
        for (level, config) in levels {
            let level_path = format!("$.policy.levels.{level}");
            let Some(level) = level.parse::<u32>().ok() else {
                self.error(&level_path, "policy level key must be a u32");
                continue;
            };
            if !config.is_object() {
                self.error(level_path, "policy level config must be an object");
                continue;
            }
            self.reject_unknown_fields(
                config,
                &level_path,
                &[
                    "handshake",
                    "connIdle",
                    "uplinkOnly",
                    "downlinkOnly",
                    "statsUserUplink",
                    "statsUserDownlink",
                    "bufferSize",
                ],
            );
            parsed.insert(
                level,
                PolicyLevelConfig {
                    handshake: self.optional_u32_at(
                        config,
                        "handshake",
                        format!("{level_path}.handshake"),
                    ),
                    conn_idle: self.optional_u32_at(
                        config,
                        "connIdle",
                        format!("{level_path}.connIdle"),
                    ),
                    uplink_only: self.optional_u32_at(
                        config,
                        "uplinkOnly",
                        format!("{level_path}.uplinkOnly"),
                    ),
                    downlink_only: self.optional_u32_at(
                        config,
                        "downlinkOnly",
                        format!("{level_path}.downlinkOnly"),
                    ),
                    stats_user_uplink: self
                        .optional_bool_at(
                            config,
                            "statsUserUplink",
                            format!("{level_path}.statsUserUplink"),
                        )
                        .unwrap_or(false),
                    stats_user_downlink: self
                        .optional_bool_at(
                            config,
                            "statsUserDownlink",
                            format!("{level_path}.statsUserDownlink"),
                        )
                        .unwrap_or(false),
                    buffer_size: self.optional_i32_at(
                        config,
                        "bufferSize",
                        format!("{level_path}.bufferSize"),
                    ),
                },
            );
        }

        parsed
    }

    fn parse_policy_system(&mut self, policy: &Value) -> PolicySystemConfig {
        let Some(system) = policy.get("system") else {
            return PolicySystemConfig::default();
        };
        let system_path = "$.policy.system";
        if !system.is_object() {
            self.error(system_path, "policy system must be an object");
            return PolicySystemConfig::default();
        }

        self.reject_unknown_fields(
            system,
            system_path,
            &[
                "statsInboundUplink",
                "statsInboundDownlink",
                "statsOutboundUplink",
                "statsOutboundDownlink",
            ],
        );

        PolicySystemConfig {
            stats_inbound_uplink: self
                .optional_bool_at(
                    system,
                    "statsInboundUplink",
                    format!("{system_path}.statsInboundUplink"),
                )
                .unwrap_or(false),
            stats_inbound_downlink: self
                .optional_bool_at(
                    system,
                    "statsInboundDownlink",
                    format!("{system_path}.statsInboundDownlink"),
                )
                .unwrap_or(false),
            stats_outbound_uplink: self
                .optional_bool_at(
                    system,
                    "statsOutboundUplink",
                    format!("{system_path}.statsOutboundUplink"),
                )
                .unwrap_or(false),
            stats_outbound_downlink: self
                .optional_bool_at(
                    system,
                    "statsOutboundDownlink",
                    format!("{system_path}.statsOutboundDownlink"),
                )
                .unwrap_or(false),
        }
    }

    fn parse_routing(&mut self) -> RoutingConfig {
        let Some(routing) = self.root.get("routing") else {
            return RoutingConfig::default();
        };
        let routing_path = "$.routing";
        if !routing.is_object() {
            self.error(routing_path, "routing must be an object");
            return RoutingConfig::default();
        }

        self.reject_unknown_fields(
            routing,
            routing_path,
            &["domainStrategy", "rules", "balancers"],
        );

        let domain_strategy = self.parse_routing_domain_strategy(routing);

        self.reject_non_empty_array(routing, "balancers", "$.routing.balancers".to_owned());
        RoutingConfig {
            rules: self.parse_routing_rules(routing),
            domain_strategy,
        }
    }

    fn parse_routing_domain_strategy(&mut self, routing: &Value) -> RoutingDomainStrategy {
        match self.optional_string_at(
            routing,
            "domainStrategy",
            "$.routing.domainStrategy".to_owned(),
        ) {
            None | Some("AsIs") => RoutingDomainStrategy::AsIs,
            Some("IPIfNonMatch") => RoutingDomainStrategy::IpIfNonMatch,
            Some(strategy) => {
                self.error(
                    "$.routing.domainStrategy",
                    format!("unsupported routing domainStrategy `{strategy}`"),
                );
                RoutingDomainStrategy::AsIs
            }
        }
    }

    fn parse_routing_rules(&mut self, routing: &Value) -> Vec<RoutingRule> {
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
            .filter_map(|(index, rule)| self.parse_routing_rule(rule, index))
            .collect()
    }

    fn parse_routing_rule(&mut self, rule: &Value, index: usize) -> Option<RoutingRule> {
        let rule_path = format!("$.routing.rules[{index}]");
        if !rule.is_object() {
            self.error(&rule_path, "routing rule must be an object");
            return None;
        }

        self.reject_unknown_fields(
            rule,
            &rule_path,
            &[
                "type",
                "inboundTag",
                "network",
                "port",
                "domain",
                "domains",
                "ip",
                "outboundTag",
                "ruleTag",
            ],
        );

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

        let outbound_tag_path = format!("{rule_path}.outboundTag");
        let Some(outbound_tag) =
            self.optional_string_at(rule, "outboundTag", outbound_tag_path.clone())
        else {
            if rule.get("outboundTag").is_none() {
                self.error(outbound_tag_path, "missing routing rule outboundTag");
            }
            return None;
        };
        if outbound_tag.is_empty() {
            self.error(
                outbound_tag_path,
                "routing rule outboundTag cannot be empty",
            );
            return None;
        }

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
            outbound_tag: outbound_tag.to_owned(),
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

    fn parse_inbounds(&mut self) -> Vec<InboundConfig> {
        let Some(inbounds) = self.root.get("inbounds").and_then(Value::as_array) else {
            return Vec::new();
        };

        inbounds
            .iter()
            .enumerate()
            .filter_map(|(index, inbound)| self.parse_inbound(inbound, index))
            .collect()
    }

    fn parse_inbound(&mut self, inbound: &Value, index: usize) -> Option<InboundConfig> {
        let protocol_path = format!("$.inbounds[{index}].protocol");
        let protocol = match self.string_at(inbound, "protocol") {
            Some("socks") => InboundProtocol::Socks,
            Some("http") => InboundProtocol::Http,
            Some("tun") => InboundProtocol::Tun,
            Some(protocol) => {
                self.error(
                    protocol_path,
                    format!("unsupported inbound protocol `{protocol}`"),
                );
                return None;
            }
            None => {
                self.error(protocol_path, "missing inbound protocol");
                return None;
            }
        };
        self.validate_inbound_compatibility(inbound, index, &protocol);

        let port_path = format!("$.inbounds[{index}].port");
        let port = if matches!(&protocol, InboundProtocol::Tun) && inbound.get("port").is_none() {
            0
        } else {
            self.u16_at(inbound, "port", port_path).unwrap_or(0)
        };

        let listen = self
            .string_at(inbound, "listen")
            .unwrap_or("127.0.0.1")
            .to_owned();
        let allow_unauthenticated_lan =
            self.parse_allow_unauthenticated_lan(inbound, index, &protocol);
        if matches!(protocol, InboundProtocol::Socks | InboundProtocol::Http)
            && !is_loopback_listener(&listen)
        {
            if allow_unauthenticated_lan {
                if !matches!(listen.as_str(), "0.0.0.0" | "::") {
                    self.warning(
                        format!("$.inbounds[{index}].listen"),
                        "unauthenticated SOCKS/HTTP inbound is explicitly exposed beyond loopback",
                    );
                }
            } else {
                self.error(
                    format!("$.inbounds[{index}].listen"),
                    "unauthenticated SOCKS/HTTP inbounds may only listen on loopback; set settings.allowUnauthenticatedLan=true to explicitly permit LAN exposure",
                );
            }
        }
        if matches!(listen.as_str(), "0.0.0.0" | "::") {
            self.warning(
                format!("$.inbounds[{index}].listen"),
                "wildcard listen address exposes this inbound to other devices on the network; use 127.0.0.1 unless LAN sharing is intended",
            );
        }

        Some(InboundConfig {
            tag: self.string_at(inbound, "tag").map(ToOwned::to_owned),
            protocol,
            listen,
            port,
            allow_unauthenticated_lan,
            sniffing: self.parse_inbound_sniffing(inbound, index),
            user_level: self.parse_inbound_user_level(inbound, index),
        })
    }

    fn parse_allow_unauthenticated_lan(
        &mut self,
        inbound: &Value,
        index: usize,
        protocol: &InboundProtocol,
    ) -> bool {
        if !matches!(protocol, InboundProtocol::Socks | InboundProtocol::Http) {
            return false;
        }
        let Some(settings) = inbound.get("settings").filter(|value| value.is_object()) else {
            return false;
        };

        self.optional_bool_at(
            settings,
            "allowUnauthenticatedLan",
            format!("$.inbounds[{index}].settings.allowUnauthenticatedLan"),
        )
        .unwrap_or(false)
    }

    fn validate_inbound_compatibility(
        &mut self,
        inbound: &Value,
        index: usize,
        protocol: &InboundProtocol,
    ) {
        let inbound_path = format!("$.inbounds[{index}]");
        self.reject_unknown_fields(
            inbound,
            &inbound_path,
            &["tag", "protocol", "listen", "port", "settings", "sniffing"],
        );

        let Some(settings) = inbound.get("settings") else {
            return;
        };

        match protocol {
            InboundProtocol::Socks => self.validate_socks_inbound_settings(settings, index),
            InboundProtocol::Http => self.validate_http_inbound_settings(settings, index),
            InboundProtocol::Tun => {}
        }
    }

    fn parse_inbound_user_level(&mut self, inbound: &Value, index: usize) -> Option<u32> {
        inbound.get("settings").and_then(|settings| {
            self.optional_u32_at(
                settings,
                "userLevel",
                format!("$.inbounds[{index}].settings.userLevel"),
            )
        })
    }

    fn parse_inbound_sniffing(
        &mut self,
        inbound: &Value,
        index: usize,
    ) -> Option<InboundSniffingConfig> {
        let sniffing = inbound.get("sniffing")?;
        let sniffing_path = format!("$.inbounds[{index}].sniffing");
        if !sniffing.is_object() {
            self.error(sniffing_path, "inbound sniffing must be an object");
            return None;
        }

        self.reject_unknown_fields(
            sniffing,
            &sniffing_path,
            &[
                "enabled",
                "destOverride",
                "metadataOnly",
                "routeOnly",
                "domainsExcluded",
                "excludedDomains",
            ],
        );
        self.validate_ignored_string_array(
            sniffing,
            "excludedDomains",
            format!("{sniffing_path}.excludedDomains"),
            false,
        );
        self.validate_ignored_string_array(
            sniffing,
            "domainsExcluded",
            format!("{sniffing_path}.domainsExcluded"),
            true,
        );

        let enabled = self
            .optional_bool_at(sniffing, "enabled", format!("{sniffing_path}.enabled"))
            .unwrap_or(false);
        if !enabled {
            return None;
        }

        Some(InboundSniffingConfig {
            enabled,
            dest_override: self.parse_sniffing_dest_override(sniffing, &sniffing_path)?,
            metadata_only: self
                .optional_bool_at(
                    sniffing,
                    "metadataOnly",
                    format!("{sniffing_path}.metadataOnly"),
                )
                .unwrap_or(false),
            route_only: self
                .optional_bool_at(sniffing, "routeOnly", format!("{sniffing_path}.routeOnly"))
                .unwrap_or(false),
        })
    }

    fn parse_sniffing_dest_override(
        &mut self,
        sniffing: &Value,
        sniffing_path: &str,
    ) -> Option<Vec<SniffingDestination>> {
        let Some(raw_values) = sniffing.get("destOverride") else {
            return Some(Vec::new());
        };
        let Some(values) = raw_values.as_array() else {
            self.error(
                format!("{sniffing_path}.destOverride"),
                "field `destOverride` must be an array",
            );
            return None;
        };

        let mut parsed = Vec::with_capacity(values.len());
        for (index, value) in values.iter().enumerate() {
            let path = format!("{sniffing_path}.destOverride[{index}]");
            match value.as_str() {
                Some("http") => parsed.push(SniffingDestination::Http),
                Some("tls") => parsed.push(SniffingDestination::Tls),
                Some("quic") => parsed.push(SniffingDestination::Quic),
                Some(value) => {
                    self.error(path, format!("unsupported sniffing destOverride `{value}`"));
                    return None;
                }
                None => {
                    self.error(path, "sniffing destOverride must be a string");
                    return None;
                }
            }
        }

        Some(parsed)
    }

    fn validate_ignored_string_array(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
        require_empty: bool,
    ) {
        let Some(raw) = value.get(key) else {
            return;
        };
        let Some(values) = raw.as_array() else {
            self.error(path, format!("field `{key}` must be an array"));
            return;
        };
        if require_empty && !values.is_empty() {
            self.error(path, format!("field `{key}` is unsupported"));
            return;
        }
        for (index, value) in values.iter().enumerate() {
            if !value.is_string() {
                self.error(
                    format!("{path}[{index}]"),
                    "domain matcher must be a string",
                );
                return;
            }
        }
    }

    fn validate_socks_inbound_settings(&mut self, settings: &Value, index: usize) {
        let settings_path = format!("$.inbounds[{index}].settings");
        if !settings.is_object() {
            self.error(settings_path, "socks inbound settings must be an object");
            return;
        }

        self.reject_unknown_fields(
            settings,
            &settings_path,
            &[
                "auth",
                "accounts",
                "udp",
                "ip",
                "userLevel",
                "allowUnauthenticatedLan",
            ],
        );

        if let Some(auth) =
            self.optional_string_at(settings, "auth", format!("{settings_path}.auth"))
        {
            if auth != "noauth" {
                self.error(
                    format!("{settings_path}.auth"),
                    format!("unsupported socks auth `{auth}`"),
                );
            }
        }

        self.reject_non_empty_array(settings, "accounts", format!("{settings_path}.accounts"));

        self.optional_bool_at(settings, "udp", format!("{settings_path}.udp"));
    }

    fn validate_http_inbound_settings(&mut self, settings: &Value, index: usize) {
        let settings_path = format!("$.inbounds[{index}].settings");
        if !settings.is_object() {
            self.error(settings_path, "http inbound settings must be an object");
            return;
        }

        self.reject_unknown_fields(
            settings,
            &settings_path,
            &[
                "timeout",
                "accounts",
                "allowTransparent",
                "userLevel",
                "allowUnauthenticatedLan",
            ],
        );
        self.reject_non_empty_array(settings, "accounts", format!("{settings_path}.accounts"));

        if matches!(
            self.optional_bool_at(
                settings,
                "allowTransparent",
                format!("{settings_path}.allowTransparent"),
            ),
            Some(true)
        ) {
            self.error(
                format!("{settings_path}.allowTransparent"),
                "http transparent proxy mode is unsupported",
            );
        }
    }

    fn parse_outbounds(&mut self) -> Vec<OutboundConfig> {
        let Some(outbounds) = self.root.get("outbounds").and_then(Value::as_array) else {
            return Vec::new();
        };

        outbounds
            .iter()
            .enumerate()
            .filter_map(|(index, outbound)| self.parse_outbound(outbound, index))
            .collect()
    }

    fn parse_outbound(&mut self, outbound: &Value, index: usize) -> Option<OutboundConfig> {
        let protocol_path = format!("$.outbounds[{index}].protocol");
        let protocol = match self
            .string_at(outbound, "protocol")
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("freedom") => OutboundProtocol::Freedom,
            Some("dns") => OutboundProtocol::Dns,
            Some("vless") => OutboundProtocol::Vless,
            Some(protocol) => {
                self.error(
                    protocol_path,
                    format!("unsupported outbound protocol `{protocol}`"),
                );
                return None;
            }
            None => {
                self.error(protocol_path, "missing outbound protocol");
                return None;
            }
        };
        self.validate_outbound_compatibility(outbound, index);

        let settings = match protocol {
            OutboundProtocol::Freedom => {
                self.validate_freedom_settings(outbound.get("settings"), index);
                OutboundSettings::Freedom
            }
            OutboundProtocol::Dns => {
                OutboundSettings::Dns(self.parse_dns_outbound_settings(outbound, index)?)
            }
            OutboundProtocol::Vless => {
                OutboundSettings::Vless(self.parse_vless_settings(outbound, index)?)
            }
        };
        let stream = self.parse_stream_settings(outbound, index)?;

        Some(OutboundConfig {
            tag: self.string_at(outbound, "tag").map(ToOwned::to_owned),
            stream,
            settings,
        })
    }

    fn validate_outbound_compatibility(&mut self, outbound: &Value, index: usize) {
        let outbound_path = format!("$.outbounds[{index}]");
        self.reject_unknown_fields(
            outbound,
            &outbound_path,
            &[
                "tag",
                "protocol",
                "settings",
                "streamSettings",
                "mux",
                "proxySettings",
                "sendThrough",
            ],
        );

        if outbound.get("sendThrough").is_some() {
            self.error(
                format!("{outbound_path}.sendThrough"),
                "outbound sendThrough is unsupported",
            );
        }

        if outbound.get("proxySettings").is_some() {
            self.error(
                format!("{outbound_path}.proxySettings"),
                "outbound proxySettings is unsupported",
            );
        }

        let Some(mux) = outbound.get("mux") else {
            return;
        };
        let mux_path = format!("{outbound_path}.mux");
        if !mux.is_object() {
            self.error(mux_path, "outbound mux must be an object");
            return;
        }
        self.reject_unknown_fields(mux, &mux_path, &["enabled", "concurrency"]);
        if matches!(
            self.optional_bool_at(mux, "enabled", format!("{mux_path}.enabled")),
            Some(true)
        ) {
            self.error(format!("{mux_path}.enabled"), "outbound mux is unsupported");
        }
        self.optional_u32_at(mux, "concurrency", format!("{mux_path}.concurrency"));
    }

    fn validate_freedom_settings(&mut self, settings: Option<&Value>, index: usize) {
        let Some(settings) = settings else {
            return;
        };
        let settings_path = format!("$.outbounds[{index}].settings");
        if !settings.is_object() {
            self.error(settings_path, "freedom settings must be an object");
            return;
        }

        self.reject_unknown_fields(settings, &settings_path, &[]);
    }

    fn parse_dns_outbound_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<DnsOutboundSettings> {
        let settings_path = format!("$.outbounds[{index}].settings");
        let settings = match outbound.get("settings") {
            None | Some(Value::Null) => return Some(DnsOutboundSettings::default()),
            Some(settings) if settings.is_object() => settings,
            Some(_) => {
                self.error(
                    &settings_path,
                    "dns outbound settings must be an object or null",
                );
                return None;
            }
        };

        self.reject_unknown_fields(
            settings,
            &settings_path,
            &[
                "rewriteNetwork",
                "rewriteAddress",
                "rewritePort",
                "network",
                "address",
                "port",
                "userLevel",
                "rules",
                "nonIPQuery",
                "blockTypes",
            ],
        );

        // Xray unmarshals both spellings before Build applies the legacy
        // aliases. Keep type errors from either field visible, but defer
        // semantic validation until the effective value is known.
        let canonical_network = self.dns_rewrite_text_at(
            settings,
            "rewriteNetwork",
            format!("{settings_path}.rewriteNetwork"),
        )?;
        let legacy_network =
            self.dns_rewrite_text_at(settings, "network", format!("{settings_path}.network"))?;
        let rewrite_network = match legacy_network.filter(|network| !network.is_empty()) {
            Some(network) => {
                self.parse_dns_rewrite_network(network, format!("{settings_path}.network"))
            }
            None => canonical_network.and_then(|network| {
                self.parse_dns_rewrite_network(network, format!("{settings_path}.rewriteNetwork"))
            }),
        };

        let canonical_address = self.dns_rewrite_text_at(
            settings,
            "rewriteAddress",
            format!("{settings_path}.rewriteAddress"),
        )?;
        let legacy_address =
            self.dns_rewrite_text_at(settings, "address", format!("{settings_path}.address"))?;
        let rewrite_address = match legacy_address {
            Some(address) => {
                self.parse_dns_rewrite_address(address, format!("{settings_path}.address"))
            }
            None => canonical_address.and_then(|address| {
                self.parse_dns_rewrite_address(address, format!("{settings_path}.rewriteAddress"))
            }),
        };

        let mut rewrite_port = self.nullable_u16_at(
            settings,
            "rewritePort",
            format!("{settings_path}.rewritePort"),
        )?;
        let alias_port = self.nullable_u16_at(settings, "port", format!("{settings_path}.port"))?;
        if alias_port != 0 {
            rewrite_port = alias_port;
        }

        let user_level =
            self.nullable_u32_at(settings, "userLevel", format!("{settings_path}.userLevel"))?;

        let rules_present = settings.get("rules").is_some_and(|value| !value.is_null());
        let legacy_present = ["nonIPQuery", "blockTypes"]
            .iter()
            .any(|field| settings.get(*field).is_some_and(|value| !value.is_null()));
        if rules_present && legacy_present {
            self.error(
                format!("{settings_path}.rules"),
                "legacy nonIPQuery and blockTypes cannot be mixed with rules",
            );
            return None;
        }

        let rules = if legacy_present {
            let rules = self.parse_legacy_dns_outbound_rules(settings, &settings_path)?;
            self.warning(
                &settings_path,
                "dns outbound nonIPQuery and blockTypes are deprecated; use rules",
            );
            rules
        } else {
            self.parse_dns_outbound_rules(settings.get("rules"), &settings_path)?
        };

        Some(DnsOutboundSettings {
            rewrite_network,
            rewrite_address,
            rewrite_port,
            user_level,
            rules,
        })
    }

    fn dns_rewrite_text_at<'a>(
        &mut self,
        settings: &'a Value,
        key: &str,
        path: String,
    ) -> Option<Option<&'a str>> {
        match settings.get(key) {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(value)) => Some(Some(value)),
            Some(_) => {
                self.error(path, format!("field `{key}` must be a string or null"));
                None
            }
        }
    }

    fn parse_dns_rewrite_network(&mut self, network: &str, path: String) -> Option<Network> {
        if network.is_empty() {
            None
        } else if network.eq_ignore_ascii_case("tcp") {
            Some(Network::Tcp)
        } else if network.eq_ignore_ascii_case("udp") {
            Some(Network::Udp)
        } else {
            self.error(path, format!("unsupported dns rewrite network `{network}`"));
            None
        }
    }

    fn parse_dns_rewrite_address(&mut self, address: &str, path: String) -> Option<TargetAddr> {
        let address = normalize_xray_address_text(address);
        if address.starts_with("env:") {
            self.error(
                path,
                "dns rewrite address environment references are not supported",
            );
            return None;
        }
        if address.is_empty() {
            self.error(path, "dns rewrite address cannot be empty");
            return None;
        }

        Some(
            address
                .parse::<IpAddr>()
                .map_or_else(|_| TargetAddr::Domain(address.to_owned()), TargetAddr::Ip),
        )
    }

    fn parse_dns_outbound_rules(
        &mut self,
        raw_rules: Option<&Value>,
        settings_path: &str,
    ) -> Option<Vec<DnsOutboundRule>> {
        let rules_path = format!("{settings_path}.rules");
        let rules = match raw_rules {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(rules)) => rules,
            Some(_) => {
                self.error(&rules_path, "dns outbound rules must be an array or null");
                return None;
            }
        };
        if !self.selector_budget.consume_dns_outbound_rules(rules.len()) {
            self.error(
                &rules_path,
                format!(
                    "configuration exceeds the DNS outbound rule budget (maximum {MAX_DNS_OUTBOUND_RULES})"
                ),
            );
            return None;
        }

        let mut parsed = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            parsed.push(self.parse_dns_outbound_rule(rule, &format!("{rules_path}[{index}]"))?);
        }
        Some(parsed)
    }

    fn parse_dns_outbound_rule(
        &mut self,
        rule: &Value,
        rule_path: &str,
    ) -> Option<DnsOutboundRule> {
        if !rule.is_object() {
            self.error(rule_path, "dns outbound rule must be an object");
            return None;
        }
        self.reject_unknown_fields(rule, rule_path, &["action", "qtype", "domain"]);

        let action_path = format!("{rule_path}.action");
        let action = match rule.get("action") {
            Some(Value::String(action)) if action.eq_ignore_ascii_case("direct") => {
                DnsOutboundRuleAction::Direct
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("drop") => {
                DnsOutboundRuleAction::Drop
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("reject") => {
                DnsOutboundRuleAction::Reject
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("hijack") => {
                DnsOutboundRuleAction::Hijack
            }
            Some(Value::String(action)) => {
                self.error(
                    action_path,
                    format!("unknown dns outbound action `{action}`"),
                );
                return None;
            }
            Some(_) => {
                self.error(action_path, "dns outbound rule action must be a string");
                return None;
            }
            None => {
                self.error(action_path, "missing dns outbound rule action");
                return None;
            }
        };

        let qtype_ranges = self.parse_dns_qtype_ranges(rule.get("qtype"), rule_path)?;
        let domain_matchers =
            self.parse_dns_outbound_domain_matchers(rule.get("domain"), rule_path)?;
        Some(DnsOutboundRule {
            action,
            qtype_ranges,
            domain_matchers,
        })
    }

    fn parse_dns_qtype_ranges(
        &mut self,
        raw: Option<&Value>,
        rule_path: &str,
    ) -> Option<Vec<DnsQTypeRange>> {
        let path = format!("{rule_path}.qtype");
        let pairs = self.parse_u16_selector_ranges(raw, &path, U16SelectorKind::DnsQType)?;
        let mut ranges = Vec::with_capacity(pairs.len());
        for (start, end) in pairs {
            match DnsQTypeRange::new(start, end) {
                Ok(range) => ranges.push(range),
                Err(error) => {
                    self.error(&path, error.to_string());
                    return None;
                }
            }
        }
        Some(ranges)
    }

    fn parse_dns_outbound_domain_matchers(
        &mut self,
        raw: Option<&Value>,
        rule_path: &str,
    ) -> Option<Vec<DomainMatcher>> {
        let path = format!("{rule_path}.domain");
        let mut matchers = Vec::new();
        match raw {
            None | Some(Value::Null) => return Some(matchers),
            Some(Value::String(domains)) => {
                for (index, domain) in domains.split(',').enumerate() {
                    self.push_dns_outbound_domain_matcher(
                        domain,
                        &format!("{path}[{index}]"),
                        &mut matchers,
                    )?;
                }
            }
            Some(Value::Array(domains)) => {
                matchers.reserve(
                    domains
                        .len()
                        .min(self.matcher_budget.remaining_domain_matchers()),
                );
                for (index, domain) in domains.iter().enumerate() {
                    let item_path = format!("{path}[{index}]");
                    let Some(domain) = domain.as_str() else {
                        self.error(item_path, "dns outbound domain matcher must be a string");
                        return None;
                    };
                    self.push_dns_outbound_domain_matcher(domain, &item_path, &mut matchers)?;
                }
            }
            Some(_) => {
                self.error(path, "dns outbound domain must be a string, array, or null");
                return None;
            }
        }
        Some(matchers)
    }

    fn push_dns_outbound_domain_matcher(
        &mut self,
        domain: &str,
        path: &str,
        matchers: &mut Vec<DomainMatcher>,
    ) -> Option<()> {
        let remaining = self.matcher_budget.remaining_domain_matchers();
        if remaining == 0 {
            self.domain_matcher_budget_error(path);
            return None;
        }
        let parsed = self.parse_domain_matcher(domain, path, remaining)?;
        if !self.matcher_budget.consume_domain_matchers(parsed.len()) {
            self.domain_matcher_budget_error(path);
            return None;
        }
        matchers.extend(parsed);
        Some(())
    }

    fn parse_legacy_dns_outbound_rules(
        &mut self,
        settings: &Value,
        settings_path: &str,
    ) -> Option<Vec<DnsOutboundRule>> {
        let mode_path = format!("{settings_path}.nonIPQuery");
        let mode = match settings.get("nonIPQuery") {
            None | Some(Value::Null) => LegacyDnsNonIpMode::Reject,
            Some(Value::String(mode)) if mode.is_empty() => LegacyDnsNonIpMode::Reject,
            Some(Value::String(mode)) if mode == "reject" => LegacyDnsNonIpMode::Reject,
            Some(Value::String(mode)) if mode == "drop" => LegacyDnsNonIpMode::Drop,
            Some(Value::String(mode)) if mode == "skip" => LegacyDnsNonIpMode::Skip,
            Some(Value::String(mode)) => {
                self.error(
                    mode_path,
                    format!("unknown dns outbound nonIPQuery `{mode}`"),
                );
                return None;
            }
            Some(_) => {
                self.error(
                    mode_path,
                    "dns outbound nonIPQuery must be a string or null",
                );
                return None;
            }
        };

        let block_path = format!("{settings_path}.blockTypes");
        let mut blocked = Vec::new();
        match settings.get("blockTypes") {
            None | Some(Value::Null) => {}
            Some(Value::Array(values)) => {
                for (index, value) in values.iter().enumerate() {
                    let item_path = format!("{block_path}[{index}]");
                    if !self.selector_budget.consume_dns_qtype_selector() {
                        self.dns_qtype_selector_budget_error(&item_path);
                        return None;
                    }
                    let Some(value) = value.as_i64().and_then(|value| u16::try_from(value).ok())
                    else {
                        self.error(item_path, "dns outbound blockTypes value must fit in u16");
                        return None;
                    };
                    blocked.push((value, value));
                }
            }
            Some(_) => {
                self.error(
                    block_path,
                    "dns outbound blockTypes must be an array or null",
                );
                return None;
            }
        }
        let blocked = normalize_u16_ranges(blocked);
        let rule_count = usize::from(!blocked.is_empty()) + 2;
        if !self.selector_budget.consume_dns_outbound_rules(rule_count) {
            self.error(
                settings_path,
                format!(
                    "configuration exceeds the DNS outbound rule budget (maximum {MAX_DNS_OUTBOUND_RULES})"
                ),
            );
            return None;
        }

        let mut rules = Vec::with_capacity(rule_count);
        if !blocked.is_empty() {
            let mut qtype_ranges = Vec::with_capacity(blocked.len());
            for (start, end) in blocked {
                match DnsQTypeRange::new(start, end) {
                    Ok(range) => qtype_ranges.push(range),
                    Err(error) => {
                        self.error(&block_path, error.to_string());
                        return None;
                    }
                }
            }
            rules.push(DnsOutboundRule {
                action: if mode == LegacyDnsNonIpMode::Reject {
                    DnsOutboundRuleAction::Reject
                } else {
                    DnsOutboundRuleAction::Drop
                },
                qtype_ranges,
                domain_matchers: Vec::new(),
            });
        }
        rules.push(DnsOutboundRule {
            action: DnsOutboundRuleAction::Hijack,
            qtype_ranges: vec![DnsQTypeRange::single(1), DnsQTypeRange::single(28)],
            domain_matchers: Vec::new(),
        });
        rules.push(DnsOutboundRule {
            action: match mode {
                LegacyDnsNonIpMode::Reject => DnsOutboundRuleAction::Reject,
                LegacyDnsNonIpMode::Drop => DnsOutboundRuleAction::Drop,
                LegacyDnsNonIpMode::Skip => DnsOutboundRuleAction::Direct,
            },
            qtype_ranges: Vec::new(),
            domain_matchers: Vec::new(),
        });
        Some(rules)
    }

    fn parse_vless_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<VlessOutboundSettings> {
        let settings_path = format!("$.outbounds[{index}].settings");
        if let Some(settings) = outbound.get("settings") {
            self.reject_unknown_fields(settings, &settings_path, &["vnext"]);
        }

        let vnext_array_path = format!("$.outbounds[{index}].settings.vnext");
        let Some(vnext_array) = outbound
            .get("settings")
            .and_then(|settings| settings.get("vnext"))
            .and_then(Value::as_array)
        else {
            self.error(vnext_array_path, "missing vless vnext servers");
            return None;
        };
        if vnext_array.len() > 1 {
            self.error(
                vnext_array_path,
                "multiple vless vnext servers are unsupported",
            );
            return None;
        }

        let vnext_path = format!("$.outbounds[{index}].settings.vnext[0]");
        let Some(vnext) = vnext_array.first() else {
            self.error(vnext_path, "missing vless vnext server");
            return None;
        };
        self.reject_unknown_fields(vnext, &vnext_path, &["address", "port", "users"]);

        let address_path = format!("$.outbounds[{index}].settings.vnext[0].address");
        let Some(address) = self.string_at(vnext, "address") else {
            self.error(address_path, "missing vless server address");
            return None;
        };
        if address.is_empty() {
            self.error(address_path, "vless server address must not be empty");
            return None;
        }
        let server = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.to_owned()), TargetAddr::Ip);

        let port_path = format!("$.outbounds[{index}].settings.vnext[0].port");
        let port = self.u16_at(vnext, "port", port_path.clone())?;
        if port == 0 {
            self.error(port_path, "vless server port must not be 0");
            return None;
        }

        let users = self.parse_vless_users(vnext, index)?;

        Some(VlessOutboundSettings {
            server,
            port,
            users,
        })
    }

    fn parse_vless_users(
        &mut self,
        vnext: &Value,
        outbound_index: usize,
    ) -> Option<Vec<VlessUser>> {
        let users_path = format!("$.outbounds[{outbound_index}].settings.vnext[0].users");
        let Some(users) = vnext.get("users").and_then(Value::as_array) else {
            self.error(users_path, "vless users must be a non-empty array");
            return None;
        };
        if users.is_empty() {
            self.error(users_path, "vless users must be a non-empty array");
            return None;
        }

        let parsed_users = users
            .iter()
            .enumerate()
            .filter_map(|(user_index, user)| {
                self.parse_vless_user(user, outbound_index, user_index)
            })
            .collect::<Vec<_>>();

        if parsed_users.is_empty() {
            None
        } else {
            Some(parsed_users)
        }
    }

    fn parse_vless_user(
        &mut self,
        user: &Value,
        outbound_index: usize,
        user_index: usize,
    ) -> Option<VlessUser> {
        let id_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].id");
        let user_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}]");
        self.reject_unknown_fields(
            user,
            &user_path,
            &["id", "encryption", "flow", "level", "email", "security"],
        );

        let Some(id) = self.string_at(user, "id") else {
            self.error(id_path, "missing vless user id");
            return None;
        };
        let id = match Uuid::parse_str(id) {
            Ok(id) => id,
            Err(err) => {
                self.error(id_path, err.to_string());
                return None;
            }
        };

        let encryption_path = format!(
            "$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].encryption"
        );
        let encryption = self.string_at(user, "encryption").unwrap_or("none");
        if encryption != "none" {
            self.error(
                encryption_path,
                format!("unsupported vless user encryption `{encryption}`"),
            );
            return None;
        }

        let flow_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].flow");
        let flow = match self.string_at(user, "flow") {
            Some("") | None => None,
            Some("xtls-rprx-vision") => Some("xtls-rprx-vision".to_owned()),
            Some("xtls-rprx-vision-udp443") => Some("xtls-rprx-vision-udp443".to_owned()),
            Some(flow) => {
                self.error(flow_path, format!("unsupported vless user flow `{flow}`"));
                return None;
            }
        };

        self.optional_string_at(user, "security", format!("{user_path}.security"));
        let level = self
            .optional_u32_at(user, "level", format!("{user_path}.level"))
            .unwrap_or_default();

        Some(VlessUser {
            id,
            encryption: encryption.to_owned(),
            flow,
            level,
        })
    }

    fn parse_stream_settings(&mut self, outbound: &Value, index: usize) -> Option<StreamSettings> {
        let stream = outbound.get("streamSettings");
        let network = self.parse_network(stream, index)?;
        let security = self.parse_security(stream, index)?;
        let socket_options = self.parse_socket_options(stream, index);
        if let Some(stream) = stream {
            self.validate_stream_settings_compatibility(stream, index);
        }

        Some(StreamSettings {
            network,
            security,
            socket_options,
        })
    }

    fn parse_socket_options(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<SocketOptions> {
        let socket_options = stream.and_then(|stream| stream.get("sockopt"))?;
        let socket_options_path = format!("$.outbounds[{index}].streamSettings.sockopt");
        if !socket_options.is_object() {
            self.error(socket_options_path, "sockopt must be an object");
            return None;
        }

        self.reject_unknown_fields(socket_options, &socket_options_path, &["happyEyeballs"]);
        let happy_eyeballs = socket_options
            .get("happyEyeballs")
            .and_then(|settings| self.parse_happy_eyeballs_settings(settings, index));

        Some(SocketOptions { happy_eyeballs })
    }

    fn parse_happy_eyeballs_settings(
        &mut self,
        settings: &Value,
        index: usize,
    ) -> Option<HappyEyeballsSettings> {
        let settings_path = format!("$.outbounds[{index}].streamSettings.sockopt.happyEyeballs");
        if !settings.is_object() {
            self.error(settings_path, "happyEyeballs must be an object");
            return None;
        }

        self.reject_unknown_fields(
            settings,
            &settings_path,
            &[
                "prioritizeIPv6",
                "interleave",
                "tryDelayMs",
                "maxConcurrentTry",
            ],
        );

        Some(HappyEyeballsSettings {
            prioritize_ipv6: self
                .optional_bool_at(
                    settings,
                    "prioritizeIPv6",
                    format!("{settings_path}.prioritizeIPv6"),
                )
                .unwrap_or(false),
            interleave: self
                .optional_u32_at(
                    settings,
                    "interleave",
                    format!("{settings_path}.interleave"),
                )
                .unwrap_or(1),
            try_delay_ms: self
                .optional_u64_at(
                    settings,
                    "tryDelayMs",
                    format!("{settings_path}.tryDelayMs"),
                )
                .unwrap_or(0),
            max_concurrent_try: self
                .optional_u32_at(
                    settings,
                    "maxConcurrentTry",
                    format!("{settings_path}.maxConcurrentTry"),
                )
                .unwrap_or(4),
        })
    }

    fn parse_network(&mut self, stream: Option<&Value>, index: usize) -> Option<Network> {
        let network_path = format!("$.outbounds[{index}].streamSettings.network");
        match stream
            .and_then(|stream| stream.get("network"))
            .and_then(Value::as_str)
            .unwrap_or("tcp")
        {
            "tcp" => Some(Network::Tcp),
            network => {
                self.error(
                    network_path,
                    format!("unsupported stream network `{network}`"),
                );
                None
            }
        }
    }

    fn parse_security(&mut self, stream: Option<&Value>, index: usize) -> Option<StreamSecurity> {
        let security_path = format!("$.outbounds[{index}].streamSettings.security");
        match stream
            .and_then(|stream| stream.get("security"))
            .and_then(Value::as_str)
            .unwrap_or("none")
        {
            "none" => Some(StreamSecurity::None),
            "tls" => {
                let tls_settings = stream.and_then(|stream| stream.get("tlsSettings"));
                self.validate_tls_settings(tls_settings, index);
                let allow_insecure = tls_settings
                    .and_then(|settings| {
                        self.optional_bool_at(
                            settings,
                            "allowInsecure",
                            format!(
                                "$.outbounds[{index}].streamSettings.tlsSettings.allowInsecure"
                            ),
                        )
                    })
                    .unwrap_or(false);
                if allow_insecure {
                    self.warning(
                        format!("$.outbounds[{index}].streamSettings.tlsSettings.allowInsecure"),
                        "allowInsecure=true disables TLS certificate verification; the proxy connection can be intercepted",
                    );
                }
                Some(StreamSecurity::Tls(TlsSettings {
                    server_name: tls_settings
                        .and_then(|settings| self.string_at(settings, "serverName"))
                        .map(ToOwned::to_owned),
                    fingerprint: tls_settings
                        .and_then(|settings| self.string_at(settings, "fingerprint"))
                        .map(ToOwned::to_owned),
                    allow_insecure,
                }))
            }
            "reality" => self
                .parse_reality_settings(stream, index)
                .map(StreamSecurity::Reality),
            security => {
                self.error(
                    security_path,
                    format!("unsupported stream security `{security}`"),
                );
                None
            }
        }
    }

    fn validate_stream_settings_compatibility(&mut self, stream: &Value, index: usize) {
        let stream_path = format!("$.outbounds[{index}].streamSettings");
        if !stream.is_object() {
            self.error(stream_path, "streamSettings must be an object");
            return;
        }

        self.reject_unknown_fields(
            stream,
            &stream_path,
            &[
                "network",
                "security",
                "tlsSettings",
                "realitySettings",
                "tcpSettings",
                "sockopt",
            ],
        );
        self.validate_tcp_settings(stream, index);
    }

    fn validate_tls_settings(&mut self, settings: Option<&Value>, index: usize) {
        let Some(settings) = settings else {
            return;
        };
        let settings_path = format!("$.outbounds[{index}].streamSettings.tlsSettings");
        if !settings.is_object() {
            self.error(settings_path, "tlsSettings must be an object");
            return;
        }

        self.reject_unknown_fields(
            settings,
            &settings_path,
            &["serverName", "allowInsecure", "fingerprint", "alpn"],
        );

        if settings.get("fingerprint").is_some() {
            self.error(
                format!("{settings_path}.fingerprint"),
                "tls fingerprint is unsupported",
            );
        }

        if let Some(alpn) = settings.get("alpn") {
            match alpn.as_array() {
                Some(values) if values.is_empty() => {}
                Some(_) => self.error(format!("{settings_path}.alpn"), "tls alpn is unsupported"),
                None => self.error(format!("{settings_path}.alpn"), "tls alpn must be an array"),
            }
        }
    }

    fn validate_tcp_settings(&mut self, stream: &Value, index: usize) {
        let Some(settings) = stream.get("tcpSettings") else {
            return;
        };
        let settings_path = format!("$.outbounds[{index}].streamSettings.tcpSettings");
        if !settings.is_object() {
            self.error(settings_path, "tcpSettings must be an object");
            return;
        }

        self.reject_unknown_fields(settings, &settings_path, &["header", "acceptProxyProtocol"]);

        let Some(header) = settings.get("header") else {
            return;
        };
        let header_path = format!("{settings_path}.header");
        if !header.is_object() {
            self.error(header_path, "tcpSettings header must be an object");
            return;
        }
        self.reject_unknown_fields(header, &header_path, &["type", "request", "response"]);

        if let Some(header_type) =
            self.optional_string_at(header, "type", format!("{header_path}.type"))
        {
            if !header_type.is_empty() && header_type != "none" {
                self.error(
                    format!("{header_path}.type"),
                    format!("unsupported tcp header type `{header_type}`"),
                );
            }
        }
    }

    fn parse_reality_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<RealitySettings> {
        let settings = stream.and_then(|stream| stream.get("realitySettings"));
        let base_path = format!("$.outbounds[{index}].streamSettings.realitySettings");
        let public_key_path = format!("{base_path}.publicKey");
        let public_key = self.parse_reality_public_key(settings, &public_key_path)?;
        let short_id = self.parse_reality_short_id(settings, &format!("{base_path}.shortId"))?;
        let server_name_path = format!("{base_path}.serverName");
        let Some(server_name) =
            settings.and_then(|settings| self.string_at(settings, "serverName"))
        else {
            self.error(server_name_path, "missing reality server name");
            return None;
        };
        if server_name.is_empty() {
            self.error(server_name_path, "reality server name must not be empty");
            return None;
        }

        let fingerprint_path = format!("{base_path}.fingerprint");
        let raw_fingerprint = settings
            .and_then(|settings| self.string_at(settings, "fingerprint"))
            .unwrap_or_default();
        let Some(fingerprint) = xray_utls::normalize_reality_fingerprint(raw_fingerprint) else {
            self.error(
                fingerprint_path,
                format!("unsupported reality fingerprint `{raw_fingerprint}`"),
            );
            return None;
        };
        if xray_utls::normalize_reality_supported_fingerprint(fingerprint).is_none() {
            self.error(
                fingerprint_path,
                format!(
                    "reality fingerprint `{fingerprint}` does not support REALITY because it has no X25519-compatible key share"
                ),
            );
            return None;
        }

        Some(RealitySettings {
            server_name: server_name.to_owned(),
            fingerprint: fingerprint.to_owned(),
            public_key,
            short_id,
            spider_x: settings
                .and_then(|settings| self.string_at(settings, "spiderX"))
                .unwrap_or_default()
                .to_owned(),
            mldsa65_verify: self
                .parse_reality_mldsa65_verify(settings, &format!("{base_path}.mldsa65Verify"))?,
        })
    }

    fn parse_reality_mldsa65_verify(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<Option<Vec<u8>>> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("mldsa65Verify"))
            .and_then(Value::as_str)
        else {
            return Some(None);
        };
        if encoded.is_empty() {
            return Some(None);
        }
        let bytes = match decode_base64url_no_padding(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        if bytes.len() != 1952 {
            self.error(path, "reality mldsa65Verify must decode to 1952 bytes");
            return None;
        }
        Some(Some(bytes))
    }

    fn parse_reality_public_key(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<[u8; 32]> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("publicKey"))
            .and_then(Value::as_str)
        else {
            self.error(path, "missing reality public key");
            return None;
        };
        let bytes = match decode_base64url_no_padding(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        match <[u8; 32]>::try_from(bytes.as_slice()) {
            Ok(public_key) => Some(public_key),
            Err(_) => {
                self.error(path, "reality public key must decode to 32 bytes");
                None
            }
        }
    }

    fn parse_reality_short_id(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<RealityShortId> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("shortId"))
            .and_then(Value::as_str)
        else {
            self.error(path, "missing reality short id");
            return None;
        };
        let bytes = match decode_hex(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        match RealityShortId::try_from_slice(&bytes) {
            Ok(short_id) => Some(short_id),
            Err(err) => {
                self.error(path, err.to_string());
                None
            }
        }
    }

    fn string_at<'a>(&self, value: &'a Value, key: &str) -> Option<&'a str> {
        value.get(key).and_then(Value::as_str)
    }

    fn optional_string_at<'a>(
        &mut self,
        value: &'a Value,
        key: &str,
        path: String,
    ) -> Option<&'a str> {
        match value.get(key) {
            None => None,
            Some(Value::String(value)) => Some(value),
            Some(_) => {
                self.error(path, format!("field `{key}` must be a string"));
                None
            }
        }
    }

    fn nullable_string_at<'a>(
        &mut self,
        value: &'a Value,
        key: &str,
        path: String,
    ) -> Option<&'a str> {
        match value.get(key) {
            None | Some(Value::Null) => Some(""),
            Some(Value::String(value)) => Some(value),
            Some(_) => {
                self.error(path, format!("field `{key}` must be a string or null"));
                None
            }
        }
    }

    fn optional_bool_at(&mut self, value: &Value, key: &str, path: String) -> Option<bool> {
        match value.get(key) {
            None => None,
            Some(Value::Bool(value)) => Some(*value),
            Some(_) => {
                self.error(path, format!("field `{key}` must be a boolean"));
                None
            }
        }
    }

    fn optional_string_array_at(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
    ) -> Option<Vec<String>> {
        let Some(raw) = value.get(key) else {
            return Some(Vec::new());
        };
        let Some(values) = raw.as_array() else {
            self.error(path, format!("field `{key}` must be an array"));
            return None;
        };

        let mut strings = Vec::with_capacity(values.len());
        for (index, value) in values.iter().enumerate() {
            let Some(value) = value.as_str() else {
                self.error(
                    format!("{path}[{index}]"),
                    "routing matcher must be a string",
                );
                return None;
            };
            if value.is_empty() {
                self.error(
                    format!("{path}[{index}]"),
                    "routing matcher cannot be empty",
                );
                return None;
            }
            strings.push(value.to_owned());
        }

        Some(strings)
    }

    fn parse_domain_matchers(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
    ) -> Option<Vec<DomainMatcher>> {
        let Some(raw) = value.get(key) else {
            return Some(Vec::new());
        };
        let Some(values) = raw.as_array() else {
            self.error(path, format!("field `{key}` must be an array"));
            return None;
        };
        let mut matchers = Vec::with_capacity(
            values
                .len()
                .min(self.matcher_budget.remaining_domain_matchers()),
        );

        for (index, value) in values.iter().enumerate() {
            let item_path = format!("{path}[{index}]");
            let Some(value) = value.as_str() else {
                self.error(&item_path, "routing matcher must be a string");
                return None;
            };
            if value.is_empty() {
                self.error(&item_path, "routing matcher cannot be empty");
                return None;
            }

            let remaining = self.matcher_budget.remaining_domain_matchers();
            if remaining == 0 {
                self.domain_matcher_budget_error(&item_path);
                return None;
            }
            let parsed_matchers = self.parse_domain_matcher(value, &item_path, remaining)?;
            if !self
                .matcher_budget
                .consume_domain_matchers(parsed_matchers.len())
            {
                self.domain_matcher_budget_error(&item_path);
                return None;
            }
            matchers.extend(parsed_matchers);
        }

        Some(matchers)
    }

    fn parse_routing_rule_domain_matchers(
        &mut self,
        rule: &Value,
        rule_path: &str,
    ) -> Option<Vec<DomainMatcher>> {
        let mut matchers =
            self.parse_domain_matchers(rule, "domain", format!("{rule_path}.domain"))?;
        matchers.extend(self.parse_domain_matchers(
            rule,
            "domains",
            format!("{rule_path}.domains"),
        )?);
        Some(matchers)
    }

    fn parse_domain_matcher(
        &mut self,
        value: &str,
        path: &str,
        max_matchers: usize,
    ) -> Option<Vec<DomainMatcher>> {
        if let Some(spec) = value.strip_prefix("geosite:") {
            return self.parse_geosite_matchers("geosite.dat", spec, path, max_matchers);
        }
        if let Some(spec) = value.strip_prefix("ext-domain:") {
            return self.parse_external_geosite_matchers(spec, path, max_matchers);
        }
        if let Some(spec) = value.strip_prefix("ext:") {
            return self.parse_external_geosite_matchers(spec, path, max_matchers);
        }

        let Some((kind, domain)) = value.split_once(':') else {
            return Some(vec![DomainMatcher::Keyword(value.to_owned())]);
        };
        if domain.is_empty() && kind != "dotless" {
            self.error(path, "routing domain cannot be empty");
            return None;
        }

        match kind {
            "domain" => Some(vec![DomainMatcher::Suffix(domain.to_owned())]),
            "full" => Some(vec![DomainMatcher::Full(domain.to_owned())]),
            "keyword" => Some(vec![DomainMatcher::Keyword(domain.to_owned())]),
            "dotless" => {
                if domain.contains('.') {
                    self.error(path, "dotless domain matcher must not contain a dot");
                    return None;
                }
                match RegexMatcher::new(format!("^[^.]*{domain}[^.]*$")) {
                    Ok(matcher) => Some(vec![DomainMatcher::Regex(matcher)]),
                    Err(error) => {
                        self.error(path, error.to_string());
                        None
                    }
                }
            }
            "regexp" => match RegexMatcher::new(domain.to_owned()) {
                Ok(matcher) => Some(vec![DomainMatcher::Regex(matcher)]),
                Err(error) => {
                    self.error(path, error.to_string());
                    None
                }
            },
            _ => {
                self.error(path, format!("unsupported routing domain matcher `{kind}`"));
                None
            }
        }
    }

    fn parse_external_geosite_matchers(
        &mut self,
        spec: &str,
        path: &str,
        max_matchers: usize,
    ) -> Option<Vec<DomainMatcher>> {
        let (file_name, code_spec) = self.parse_external_geodata_ref(spec, path)?;
        self.parse_geosite_matchers(file_name, code_spec, path, max_matchers)
    }

    fn parse_geosite_matchers(
        &mut self,
        file_name: &str,
        code_spec: &str,
        path: &str,
        max_matchers: usize,
    ) -> Option<Vec<DomainMatcher>> {
        let (code, attrs) = self.parse_geosite_code_and_attrs(code_spec, path)?;
        match self
            .geodata_loader
            .load_site_matchers(file_name, code, &attrs, max_matchers)
        {
            Ok(matchers) if matchers.is_empty() => {
                self.error(
                    path,
                    format!("geosite `{file_name}:{code}` produced no domain matchers"),
                );
                None
            }
            Ok(matchers) => Some(matchers),
            Err(error) => {
                self.error(path, error.to_string());
                None
            }
        }
    }

    fn parse_ip_matchers(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
    ) -> Option<Vec<IpMatcher>> {
        let Some(raw) = value.get(key) else {
            return Some(Vec::new());
        };
        let Some(values) = raw.as_array() else {
            self.error(path, format!("field `{key}` must be an array"));
            return None;
        };
        let mut matchers = Vec::with_capacity(
            values
                .len()
                .min(self.matcher_budget.remaining_ip_matchers()),
        );

        for (index, value) in values.iter().enumerate() {
            let item_path = format!("{path}[{index}]");
            let Some(value) = value.as_str() else {
                self.error(&item_path, "routing matcher must be a string");
                return None;
            };
            if value.is_empty() {
                self.error(&item_path, "routing matcher cannot be empty");
                return None;
            }

            let remaining = self.matcher_budget.remaining_ip_matchers();
            if remaining == 0 {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
            let parsed_matchers = self.parse_ip_matcher(value, &item_path, remaining)?;
            if !self
                .matcher_budget
                .consume_ip_matchers(parsed_matchers.len())
            {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
            matchers.extend(parsed_matchers);
        }

        Some(matchers)
    }

    fn parse_ip_matcher(
        &mut self,
        value: &str,
        path: &str,
        max_matchers: usize,
    ) -> Option<Vec<IpMatcher>> {
        self.parse_ip_matcher_with_mode(value, path, max_matchers, IpMatcherParseMode::Routing)
    }

    fn parse_dns_ip_matcher(
        &mut self,
        value: &str,
        path: &str,
        max_matchers: usize,
    ) -> Option<Vec<IpMatcher>> {
        self.parse_ip_matcher_with_mode(value, path, max_matchers, IpMatcherParseMode::XrayDns)
    }

    fn parse_ip_matcher_with_mode(
        &mut self,
        value: &str,
        path: &str,
        max_matchers: usize,
        mode: IpMatcherParseMode,
    ) -> Option<Vec<IpMatcher>> {
        let (value, inverse) = strip_inverse_prefix(value);
        if let Some(code) = value.strip_prefix("geoip:") {
            let (code, code_inverse) = strip_inverse_prefix(code);
            let inverse = inverse ^ code_inverse;
            if code.is_empty() {
                self.error(path, "geoip code cannot be empty");
                return None;
            }
            if mode == IpMatcherParseMode::Routing && code.eq_ignore_ascii_case("private") {
                return Some(vec![wrap_ip_matcher_inverse(IpMatcher::Private, inverse)]);
            }
            return self.parse_geoip_matchers("geoip.dat", code, inverse, path, max_matchers, mode);
        }

        if let Some(spec) = value.strip_prefix("ext-ip:") {
            return self.parse_external_geoip_matchers(spec, inverse, path, max_matchers, mode);
        }
        if let Some(spec) = value.strip_prefix("ext:") {
            return self.parse_external_geoip_matchers(spec, inverse, path, max_matchers, mode);
        }

        self.parse_ip_cidr(value, path)
            .map(|cidr| vec![wrap_ip_matcher_inverse(IpMatcher::Cidr(cidr), inverse)])
    }

    fn parse_external_geoip_matchers(
        &mut self,
        spec: &str,
        inverse: bool,
        path: &str,
        max_matchers: usize,
        mode: IpMatcherParseMode,
    ) -> Option<Vec<IpMatcher>> {
        let (file_name, code) = self.parse_external_geodata_ref(spec, path)?;
        let (code, code_inverse) = strip_inverse_prefix(code);
        let inverse = inverse ^ code_inverse;
        if code.is_empty() {
            self.error(path, "geoip code cannot be empty");
            return None;
        }

        self.parse_geoip_matchers(file_name, code, inverse, path, max_matchers, mode)
    }

    fn parse_geoip_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
        path: &str,
        max_matchers: usize,
        mode: IpMatcherParseMode,
    ) -> Option<Vec<IpMatcher>> {
        let matchers = match mode {
            IpMatcherParseMode::Routing => {
                self.geodata_loader
                    .load_ip_matchers(file_name, code, inverse, max_matchers)
            }
            IpMatcherParseMode::XrayDns => {
                self.geodata_loader
                    .load_dns_ip_matchers(file_name, code, inverse, max_matchers)
            }
        };
        match matchers {
            Ok(matchers) if matchers.is_empty() => {
                self.error(
                    path,
                    format!("geoip `{file_name}:{code}` produced no IP matchers"),
                );
                None
            }
            Ok(matchers) => Some(matchers),
            Err(error) => {
                self.error(path, error.to_string());
                None
            }
        }
    }

    fn parse_external_geodata_ref<'value>(
        &mut self,
        spec: &'value str,
        path: &str,
    ) -> Option<(&'value str, &'value str)> {
        let Some((file_name, code)) = spec.split_once(':') else {
            self.error(path, "external geodata matcher must be file:code");
            return None;
        };
        if file_name.is_empty() {
            self.error(path, "external geodata file cannot be empty");
            return None;
        }
        if code.is_empty() {
            self.error(path, "external geodata code cannot be empty");
            return None;
        }

        Some((file_name, code))
    }

    fn parse_geosite_code_and_attrs<'value>(
        &mut self,
        spec: &'value str,
        path: &str,
    ) -> Option<(&'value str, Vec<String>)> {
        let mut parts = spec.split('@');
        let code = parts.next().unwrap_or_default();
        if code.is_empty() {
            self.error(path, "geosite code cannot be empty");
            return None;
        }

        let mut attrs = HashSet::new();
        for attr in parts {
            if attr.is_empty() {
                self.error(path, "geosite attribute cannot be empty");
                return None;
            }
            if attr.len() > MAX_CONFIG_GEODATA_ATTRIBUTE_SIZE {
                self.error(
                    path,
                    format!(
                        "geosite attribute is {} bytes; maximum supported size is {} bytes",
                        attr.len(),
                        MAX_CONFIG_GEODATA_ATTRIBUTE_SIZE
                    ),
                );
                return None;
            }
            attrs.insert(attr.to_ascii_lowercase());
            if attrs.len() > MAX_CONFIG_GEODATA_ATTR_FILTERS {
                self.error(
                    path,
                    format!(
                        "geosite reference contains more than {} unique attribute filters",
                        MAX_CONFIG_GEODATA_ATTR_FILTERS
                    ),
                );
                return None;
            }
        }

        let mut attrs = attrs.into_iter().collect::<Vec<_>>();
        attrs.sort_unstable();
        Some((code, attrs))
    }

    fn parse_ip_cidr(&mut self, value: &str, path: &str) -> Option<IpCidr> {
        let (ip, prefix) = match value.split_once('/') {
            Some((ip, "")) => (ip, None),
            Some((ip, prefix)) => {
                let Some(prefix) = prefix.parse::<u8>().ok() else {
                    self.error(path, format!("invalid routing CIDR prefix `{prefix}`"));
                    return None;
                };
                (ip, Some(prefix))
            }
            None => (value, None),
        };

        let Some(ip) = parse_xray_ip_address(ip) else {
            self.error(path, format!("invalid routing IP matcher `{value}`"));
            return None;
        };
        let cidr = match prefix {
            Some(prefix) => match IpCidr::new(ip, prefix) {
                Ok(cidr) => cidr,
                Err(error) => {
                    self.error(path, error.to_string());
                    return None;
                }
            },
            None => IpCidr::full(ip),
        };

        Some(cidr)
    }

    fn parse_u16_selector_ranges(
        &mut self,
        raw: Option<&Value>,
        path: &str,
        kind: U16SelectorKind,
    ) -> Option<Vec<(u16, u16)>> {
        let mut ranges = Vec::new();
        match raw {
            None | Some(Value::Null) => return Some(ranges),
            Some(Value::Number(value)) => {
                if !self.consume_u16_selector(kind, path) {
                    return None;
                }
                let Some(value) = value.as_u64().and_then(|value| u16::try_from(value).ok()) else {
                    self.error(
                        path,
                        format!("{} must fit in u16", u16_selector_label(kind)),
                    );
                    return None;
                };
                // Xray's shared PortList treats a numeric zero as an empty list.
                if value != 0 {
                    ranges.push((value, value));
                }
            }
            Some(Value::String(values)) => {
                for (index, raw_range) in values.split(',').enumerate() {
                    let item_path = format!("{path}[{index}]");
                    if !self.consume_u16_selector(kind, &item_path) {
                        return None;
                    }
                    let raw_range = raw_range.trim();
                    if raw_range.is_empty() {
                        continue;
                    }
                    let range = self.parse_u16_selector_range(raw_range, &item_path, kind)?;
                    ranges.push(range);
                }
            }
            Some(_) => {
                self.error(
                    path,
                    format!(
                        "{} must be an integer, comma-separated range string, or null",
                        u16_selector_label(kind)
                    ),
                );
                return None;
            }
        }
        Some(normalize_u16_ranges(ranges))
    }

    fn parse_u16_selector_range(
        &mut self,
        raw: &str,
        path: &str,
        kind: U16SelectorKind,
    ) -> Option<(u16, u16)> {
        if raw.starts_with("env:") {
            self.error(
                path,
                format!(
                    "{} environment references are not supported",
                    u16_selector_label(kind)
                ),
            );
            return None;
        }
        let (start, end) = match raw.split_once('-') {
            Some((start, end)) => (start, end),
            None => (raw, raw),
        };
        let Some(start) = start.parse::<u16>().ok() else {
            self.error(
                path,
                format!("invalid {} range `{raw}`", u16_selector_label(kind)),
            );
            return None;
        };
        let Some(end) = end.parse::<u16>().ok() else {
            self.error(
                path,
                format!("invalid {} range `{raw}`", u16_selector_label(kind)),
            );
            return None;
        };
        if start > end {
            self.error(
                path,
                format!(
                    "invalid {} range `{raw}`: start exceeds end",
                    u16_selector_label(kind)
                ),
            );
            return None;
        }
        Some((start, end))
    }

    fn consume_u16_selector(&mut self, kind: U16SelectorKind, path: &str) -> bool {
        let consumed = match kind {
            U16SelectorKind::DnsQType => self.selector_budget.consume_dns_qtype_selector(),
            U16SelectorKind::RoutingPort => self.selector_budget.consume_routing_port_selector(),
        };
        if !consumed {
            match kind {
                U16SelectorKind::DnsQType => self.dns_qtype_selector_budget_error(path),
                U16SelectorKind::RoutingPort => self.routing_port_selector_budget_error(path),
            }
        }
        consumed
    }

    fn nullable_u16_at(&mut self, value: &Value, key: &str, path: String) -> Option<u16> {
        match value.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_u64().and_then(|value| u16::try_from(value).ok()) {
                Some(value) => Some(value),
                None => {
                    self.error(path, format!("field `{key}` must fit in u16 or be null"));
                    None
                }
            },
        }
    }

    fn nullable_u32_at(&mut self, value: &Value, key: &str, path: String) -> Option<u32> {
        match value.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_u64().and_then(|value| u32::try_from(value).ok()) {
                Some(value) => Some(value),
                None => {
                    self.error(path, format!("field `{key}` must fit in u32 or be null"));
                    None
                }
            },
        }
    }

    fn u16_at(&mut self, value: &Value, key: &str, path: String) -> Option<u16> {
        let Some(raw) = value.get(key).and_then(Value::as_u64) else {
            self.error(path, format!("missing numeric field `{key}`"));
            return None;
        };
        match u16::try_from(raw) {
            Ok(port) => Some(port),
            Err(_) => {
                self.error(path, format!("field `{key}` must fit in u16"));
                None
            }
        }
    }

    fn optional_u32_at(&mut self, value: &Value, key: &str, path: String) -> Option<u32> {
        match value.get(key) {
            None => None,
            Some(raw) => match raw.as_u64().and_then(|value| u32::try_from(value).ok()) {
                Some(value) => Some(value),
                None => {
                    self.error(path, format!("field `{key}` must fit in u32"));
                    None
                }
            },
        }
    }

    fn optional_u64_at(&mut self, value: &Value, key: &str, path: String) -> Option<u64> {
        match value.get(key) {
            None => None,
            Some(raw) => match raw.as_u64() {
                Some(value) => Some(value),
                None => {
                    self.error(path, format!("field `{key}` must fit in u64"));
                    None
                }
            },
        }
    }

    fn optional_i32_at(&mut self, value: &Value, key: &str, path: String) -> Option<i32> {
        match value.get(key) {
            None => None,
            Some(raw) => match raw.as_i64().and_then(|value| i32::try_from(value).ok()) {
                Some(value) => Some(value),
                None => {
                    self.error(path, format!("field `{key}` must fit in i32"));
                    None
                }
            },
        }
    }

    fn domain_matcher_budget_error(&mut self, path: &str) {
        self.error(
            path,
            format!(
                "configuration exceeds the domain matcher budget (maximum {} domain matchers and {} total domain/IP matchers)",
                self.matcher_budget.limits.domain_matchers,
                self.matcher_budget.limits.total_matchers
            ),
        );
    }

    fn ip_matcher_budget_error(&mut self, path: &str) {
        self.error(
            path,
            format!(
                "configuration exceeds the IP matcher budget (maximum {} IP matchers and {} total domain/IP matchers)",
                self.matcher_budget.limits.ip_matchers,
                self.matcher_budget.limits.total_matchers
            ),
        );
    }

    fn dns_qtype_selector_budget_error(&mut self, path: &str) {
        self.error(
            path,
            format!(
                "configuration exceeds the DNS qtype selector budget (maximum {MAX_DNS_QTYPE_SELECTORS})"
            ),
        );
    }

    fn routing_port_selector_budget_error(&mut self, path: &str) {
        self.error(
            path,
            format!(
                "configuration exceeds the routing port selector budget (maximum {MAX_ROUTING_PORT_SELECTORS})"
            ),
        );
    }

    fn error(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::error(path, message));
    }

    fn warning(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::warning(path, message));
    }

    fn reject_unknown_fields(&mut self, value: &Value, base_path: &str, allowed: &[&str]) {
        let Some(object) = value.as_object() else {
            return;
        };

        for key in object.keys() {
            if !allowed.contains(&key.as_str()) {
                self.error(
                    child_path(base_path, key),
                    format!("unsupported field `{key}`"),
                );
            }
        }
    }

    fn reject_non_empty_array(&mut self, value: &Value, key: &str, path: String) {
        let Some(raw) = value.get(key) else {
            return;
        };
        match raw.as_array() {
            Some(values) if values.is_empty() => {}
            Some(_) => self.error(path, format!("field `{key}` is unsupported")),
            None => self.error(path, format!("field `{key}` must be an array")),
        }
    }
}

fn u16_selector_label(kind: U16SelectorKind) -> &'static str {
    match kind {
        U16SelectorKind::DnsQType => "dns outbound qtype",
        U16SelectorKind::RoutingPort => "routing port",
    }
}

fn normalize_u16_ranges(mut ranges: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    ranges.sort_unstable();
    let mut normalized: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = normalized.last_mut() {
            if start <= previous_end.saturating_add(1) {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        normalized.push((start, end));
    }
    normalized
}

fn child_path(base_path: &str, key: &str) -> String {
    if base_path == "$" {
        format!("$.{key}")
    } else {
        format!("{base_path}.{key}")
    }
}

fn strip_inverse_prefix(mut value: &str) -> (&str, bool) {
    let mut inverse = false;
    while let Some(stripped) = value.strip_prefix('!') {
        value = stripped;
        inverse = !inverse;
    }
    (value, inverse)
}

fn dns_ip_rule_uses_geodata(value: &str) -> bool {
    let (value, _) = strip_inverse_prefix(value);
    value.starts_with("geoip:") || value.starts_with("ext:") || value.starts_with("ext-ip:")
}

fn normalize_xray_address_text(mut value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.first() == Some(&b'[') && bytes.last() == Some(&b']') {
        value = &value[1..value.len() - 1];
    } else if bytes
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || bytes
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        value = value.trim();
    }

    value
}

fn parse_xray_ip_address(value: &str) -> Option<IpAddr> {
    normalize_xray_address_text(value).parse().ok()
}

fn wrap_ip_matcher_inverse(matcher: IpMatcher, inverse: bool) -> IpMatcher {
    if inverse {
        IpMatcher::Not(Box::new(matcher))
    } else {
        matcher
    }
}

fn is_loopback_listener(listen: &str) -> bool {
    let listen = listen
        .strip_prefix('[')
        .and_then(|address| address.strip_suffix(']'))
        .unwrap_or(listen);
    listen.eq_ignore_ascii_case("localhost")
        || listen
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn decode_base64url_no_padding(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.contains('=') {
        return Err("base64url value must not be padded".to_owned());
    }

    let mut output = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut chunk_len = 0;

    for byte in encoded.bytes() {
        chunk[chunk_len] = base64url_value(byte)?;
        chunk_len += 1;

        if chunk_len == 4 {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
            output.push((chunk[2] << 6) | chunk[3]);
            chunk_len = 0;
        }
    }

    match chunk_len {
        0 => {}
        1 => return Err("invalid base64url length".to_owned()),
        2 => {
            if chunk[1] & 0x0f != 0 {
                return Err("invalid base64url tail bits".to_owned());
            }
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        3 => {
            if chunk[2] & 0x03 != 0 {
                return Err("invalid base64url tail bits".to_owned());
            }
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        _ => unreachable!(),
    }

    Ok(output)
}

fn base64url_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err("invalid base64url character".to_owned()),
    }
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    let bytes = encoded.as_bytes();
    let chunks = bytes.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err("hex value must have an even length".to_owned());
    }

    chunks
        .map(|chunk| Ok((hex_value(chunk[0])? << 4) | hex_value(chunk[1])?))
        .collect()
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use prost::Message;

    use super::{
        default_geodata_dirs, geodata_dirs_with_defaults, parse_xray_json_with_loader_and_limits,
        GeodataLoader, MatcherBudget, MatcherBudgetLimits, Parser, SelectorBudget,
        DEFAULT_MATCHER_BUDGET_LIMITS, MAX_CONFIG_GEODATA_ATTRIBUTE_SIZE,
        MAX_CONFIG_GEODATA_ATTR_FILTERS, MAX_DNS_OUTBOUND_RULES, MAX_DNS_QTYPE_SELECTORS,
        MAX_ROUTING_PORT_SELECTORS,
    };

    #[test]
    fn explicit_geodata_dirs_are_searched_before_defaults() {
        let custom_dir = PathBuf::from("custom-geodata");
        let dirs = geodata_dirs_with_defaults(std::slice::from_ref(&custom_dir));

        assert_eq!(dirs.first(), Some(&custom_dir));
        for default_dir in default_geodata_dirs() {
            assert!(dirs.contains(&default_dir));
        }
    }

    #[test]
    fn empty_geodata_dirs_use_defaults() {
        let dirs = geodata_dirs_with_defaults::<PathBuf>(&[]);

        assert_eq!(dirs, default_geodata_dirs());
    }

    #[test]
    fn default_matcher_budget_enforces_domain_ip_and_combined_limits() {
        let mut domain_budget = MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS);
        let mut ip_budget = MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS);
        let mut combined_budget = MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS);

        assert!(domain_budget.consume_domain_matchers(250_000));
        assert!(!domain_budget.consume_domain_matchers(1));
        assert!(ip_budget.consume_ip_matchers(300_000));
        assert!(!ip_budget.consume_ip_matchers(1));
        assert!(combined_budget.consume_domain_matchers(200_000));
        assert!(combined_budget.consume_ip_matchers(300_000));
        assert!(!combined_budget.consume_domain_matchers(1));
    }

    #[test]
    fn selector_budget_enforces_dns_rule_qtype_and_routing_port_limits() {
        let mut budget = SelectorBudget::default();

        assert!(budget.consume_dns_outbound_rules(MAX_DNS_OUTBOUND_RULES));
        assert!(!budget.consume_dns_outbound_rules(1));
        for _ in 0..MAX_DNS_QTYPE_SELECTORS {
            assert!(budget.consume_dns_qtype_selector());
        }
        assert!(!budget.consume_dns_qtype_selector());
        for _ in 0..MAX_ROUTING_PORT_SELECTORS {
            assert!(budget.consume_routing_port_selector());
        }
        assert!(!budget.consume_routing_port_selector());
    }

    #[test]
    fn dns_outbound_domains_consume_the_global_domain_matcher_budget() {
        let raw = r#"{
          "outbounds": [{
            "protocol": "dns",
            "tag": "dns-out",
            "settings": {
              "rules": [{
                "action": "direct",
                "domain": ["full:first.example", "full:second.example"]
              }]
            }
          }]
        }"#;
        let limits = MatcherBudgetLimits {
            routing_rules: 16,
            domain_matchers: 1,
            ip_matchers: 8,
            total_matchers: 8,
        };

        let error = parse_xray_json_with_loader_and_limits(
            raw,
            GeodataLoader::from_dirs(Vec::new()),
            limits,
        )
        .unwrap_err();

        assert_eq!(
            error.diagnostics[0].path.as_deref(),
            Some("$.outbounds[0].settings.rules[0].domain[1]")
        );
    }

    #[test]
    fn dns_ip_filters_consume_the_global_ip_matcher_budget() {
        let raw = r#"{
          "dns": {
            "servers": [{
              "address": "192.0.2.53",
              "expectedIPs": ["192.0.2.0/24", "198.51.100.0/24"]
            }]
          },
          "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let limits = MatcherBudgetLimits {
            routing_rules: 16,
            domain_matchers: 8,
            ip_matchers: 1,
            total_matchers: 8,
        };

        let error = parse_xray_json_with_loader_and_limits(
            raw,
            GeodataLoader::from_dirs(Vec::new()),
            limits,
        )
        .unwrap_err();

        assert_eq!(
            error.diagnostics[0].path.as_deref(),
            Some("$.dns.servers[0].expectedIPs[1]")
        );
    }

    #[test]
    fn ignored_expect_ips_alias_does_not_consume_matcher_budget() {
        let raw = r#"{
          "dns": {
            "servers": [{
              "address": "192.0.2.53",
              "expectedIPs": ["192.0.2.0/24"],
              "expectIPs": ["198.51.100.0/24", "203.0.113.0/24"]
            }]
          },
          "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let limits = MatcherBudgetLimits {
            routing_rules: 16,
            domain_matchers: 8,
            ip_matchers: 1,
            total_matchers: 8,
        };

        let parsed = parse_xray_json_with_loader_and_limits(
            raw,
            GeodataLoader::from_dirs(Vec::new()),
            limits,
        );

        assert!(
            parsed.is_ok(),
            "ignored alias must not consume matcher slots"
        );
    }

    #[test]
    fn repeated_cached_geosite_is_rejected_by_global_matcher_budget() {
        let asset_dir = unique_temp_dir("repeated-budget");
        write_geosite(
            &asset_dir,
            TestGeoSite {
                code: "TEST".to_owned(),
                domain: (0..3)
                    .map(|index| TestGeoDomain {
                        r#type: 2,
                        value: format!("{index}.example"),
                    })
                    .collect(),
            },
        );
        let raw = r#"{
          "outbounds": [{ "protocol": "freedom", "tag": "direct" }],
          "routing": {
            "rules": [{
              "type": "field",
              "domain": ["geosite:test"],
              "outboundTag": "direct"
            }, {
              "type": "field",
              "domain": ["geosite:test"],
              "outboundTag": "direct"
            }]
          }
        }"#;
        let limits = MatcherBudgetLimits {
            routing_rules: 16,
            domain_matchers: 5,
            ip_matchers: 5,
            total_matchers: 8,
        };

        let error = parse_xray_json_with_loader_and_limits(
            raw,
            GeodataLoader::from_dirs(vec![asset_dir.clone()]),
            limits,
        )
        .unwrap_err();

        assert_eq!(
            error.diagnostics[0].path.as_deref(),
            Some("$.routing.rules[1].domain[0]")
        );
        assert!(error.diagnostics[0]
            .message
            .contains("requires at least 3 domain matchers"));
        assert!(error.diagnostics[0].message.contains("only 2 slots remain"));

        fs::remove_dir_all(asset_dir).unwrap();
    }

    #[test]
    fn repeated_geosite_attributes_are_case_insensitively_deduplicated() {
        let root = serde_json::Value::Null;
        let mut parser = Parser {
            root: &root,
            diagnostics: Vec::new(),
            geodata_loader: GeodataLoader::from_dirs(Vec::new()),
            matcher_budget: MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS),
            selector_budget: SelectorBudget::default(),
        };
        let spec = format!("test{}", "@AdS".repeat(MAX_CONFIG_GEODATA_ATTR_FILTERS + 1));

        let (_, attrs) = parser
            .parse_geosite_code_and_attrs(&spec, "$.routing.rules[0].domain[0]")
            .unwrap();

        assert_eq!(attrs, vec!["ads"]);
        assert!(parser.diagnostics.is_empty());
    }

    #[test]
    fn unique_geosite_attribute_count_is_bounded() {
        let root = serde_json::Value::Null;
        let mut parser = Parser {
            root: &root,
            diagnostics: Vec::new(),
            geodata_loader: GeodataLoader::from_dirs(Vec::new()),
            matcher_budget: MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS),
            selector_budget: SelectorBudget::default(),
        };
        let attrs = (0..=MAX_CONFIG_GEODATA_ATTR_FILTERS)
            .map(|index| format!("attr{index}"))
            .collect::<Vec<_>>()
            .join("@");
        let spec = format!("test@{attrs}");

        let parsed = parser.parse_geosite_code_and_attrs(&spec, "$.routing.rules[0].domain[0]");

        assert!(parsed.is_none());
        assert!(parser.diagnostics[0]
            .message
            .contains("more than 32 unique attribute filters"));
    }

    #[test]
    fn oversized_geosite_attribute_is_rejected_before_geodata_load() {
        let attribute = "a".repeat(MAX_CONFIG_GEODATA_ATTRIBUTE_SIZE + 1);
        let raw = format!(
            r#"{{
              "outbounds": [{{ "protocol": "freedom", "tag": "direct" }}],
              "routing": {{
                "rules": [{{
                  "type": "field",
                  "domain": ["geosite:test@{attribute}"],
                  "outboundTag": "direct"
                }}]
              }}
            }}"#
        );

        let error = parse_xray_json_with_loader_and_limits(
            &raw,
            GeodataLoader::from_dirs(Vec::new()),
            DEFAULT_MATCHER_BUDGET_LIMITS,
        )
        .unwrap_err();

        assert!(error.diagnostics[0]
            .message
            .contains("maximum supported size is 256 bytes"));
        assert!(!error.diagnostics[0].message.contains("not found"));
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "xray-config-parser-{label}-{}-{timestamp}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn write_geosite(root: &Path, site: TestGeoSite) {
        let body = site.encode_to_vec();
        let mut bytes = vec![0];
        encode_varint(body.len() as u64, &mut bytes);
        bytes.extend_from_slice(&body);
        fs::write(root.join("geosite.dat"), bytes).unwrap();
    }

    fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
        while value >= 0x80 {
            output.push(value as u8 | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    #[derive(Clone, PartialEq, Message)]
    struct TestGeoSite {
        #[prost(string, tag = "1")]
        code: String,
        #[prost(message, repeated, tag = "2")]
        domain: Vec<TestGeoDomain>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct TestGeoDomain {
        #[prost(enumeration = "TestGeoDomainType", tag = "1")]
        r#type: i32,
        #[prost(string, tag = "2")]
        value: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    #[repr(i32)]
    enum TestGeoDomainType {
        Substr = 0,
        Regex = 1,
        Domain = 2,
        Full = 3,
    }
}
