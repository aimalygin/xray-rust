mod dns;
mod routing;
mod stream;
mod vless;
mod xhttp;

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use crate::surface;
use serde_json::Value;
use xray_routing::{DomainMatcherSet, DomainMatcherSetBuilder, IpMatcherSet, IpMatcherSetBuilder};

use crate::model::build_domain_matcher_set;
use crate::{
    geodata::{default_geodata_dirs, GeodataLoader},
    CoreConfig, Diagnostic, DnsConfig, DnsFakeIpConfig, DnsHostTarget, DnsIpFilter,
    DnsNameServerConfig, DnsOutboundRule, DnsOutboundRuleAction, DnsOutboundSettings,
    DnsQTypeRange, DnsQueryStrategy, DnsServerConfig, DnsServerEndpoint, DnsServerTransport,
    DomainHostIndex, DomainMatcher, DomainNameMode, GrpcSettings, HappyEyeballsSettings,
    HttpUpgradeSettings, InboundConfig, InboundProtocol, InboundSniffingConfig, IpCidr, Network,
    ObservatoryConfig, OutboundConfig, OutboundProtocol, OutboundProxySettings, OutboundSettings,
    PolicyConfig, PolicyLevelConfig, PolicySystemConfig, QuicBbrProfile, QuicCongestion,
    QuicIntervalRange, QuicParamsSettings, QuicUdpHopSettings, RealitySettings, RealityShortId,
    RegexMatcher, SniffingDestination, SocketOptions, StreamSecurity, StreamSettings,
    StreamTransport, TargetAddr, TlsSettings, WebSocketSettings, XhttpMode, XhttpPaddingMethod,
    XhttpPaddingPlacement, XhttpPlacement, XhttpRange, XhttpSettings, XhttpUplinkDataPlacement,
    XhttpXmuxSettings, DEFAULT_OBSERVATORY_PROBE_INTERVAL, DEFAULT_OBSERVATORY_PROBE_URL,
    MAX_DNS_SERVER_TIMEOUT_MS, MAX_DNS_SERVE_EXPIRED_TTL_SECONDS, OBSERVATORY_PROBE_TIMEOUT,
};

const MAX_ROUTING_RULES: usize = 4_096;
const MAX_OBSERVATORY_SUBJECT_SELECTORS: usize = 4_096;
const MIN_OBSERVATORY_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_OBSERVATORY_PROBE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);
const MAX_DNS_OUTBOUND_RULES: usize = 4_096;
const MAX_DNS_QTYPE_SELECTORS: usize = 65_536;
const MAX_ROUTING_PORT_SELECTORS: usize = 65_536;
pub const MAX_CONFIG_DOMAIN_MATCHERS: usize = 250_000;
const MAX_CONFIG_IP_MATCHERS: usize = 750_000;
const MAX_CONFIG_MATCHERS: usize = 1_000_000;
const MAX_CONFIG_GEODATA_ATTR_FILTERS: usize = 32;
const MAX_CONFIG_GEODATA_ATTRIBUTE_SIZE: usize = 256;
const MAX_DNS_SERVERS: usize = 8;
const DEFAULT_FAKE_IP_POOL_SIZE: u32 = 32_768;
const TUN_DNS_ANCHOR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const TUN_CLIENT_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

/// The transport `streamSettings.network` names, before their settings block
/// has been read. All of them dial TCP; the variant only says what gets
/// layered on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamNetwork {
    Raw,
    WebSocket,
    HttpUpgrade,
    Grpc,
    Xhttp,
}

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

fn parse_xray_duration(raw: &str) -> Option<std::time::Duration> {
    if raw.is_empty() || raw.starts_with(['-', '+']) {
        return None;
    }

    let mut rest = raw;
    let mut total_seconds = 0.0f64;
    while !rest.is_empty() {
        let number_end = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
            .map(|(index, ch)| index + ch.len_utf8())
            .last()?;
        let number = rest[..number_end].parse::<f64>().ok()?;
        if !number.is_finite() || number < 0.0 {
            return None;
        }
        rest = &rest[number_end..];
        let (unit, multiplier) = [
            ("ns", 1e-9),
            ("us", 1e-6),
            ("µs", 1e-6),
            ("μs", 1e-6),
            ("ms", 1e-3),
            ("s", 1.0),
            ("m", 60.0),
            ("h", 3600.0),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))?;
        total_seconds += number * multiplier;
        rest = &rest[unit.len()..];
    }

    std::time::Duration::try_from_secs_f64(total_seconds).ok()
}

fn insert_domain_matchers(
    builder: &mut DomainMatcherSetBuilder,
    matchers: &[DomainMatcher],
    mode: DomainNameMode,
) {
    for matcher in matchers {
        builder.insert(matcher, mode);
    }
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

pub fn parse_xray_json_with_exclusive_geodata_dirs<P: AsRef<Path>>(
    raw: &str,
    dirs: &[P],
) -> Result<ParsedConfig, ConfigParseError> {
    parse_xray_json_with_loader(raw, GeodataLoader::from_dirs(configured_geodata_dirs(dirs)))
}

fn configured_geodata_dirs<P: AsRef<Path>>(dirs: &[P]) -> Vec<PathBuf> {
    dirs.iter().map(|dir| dir.as_ref().to_path_buf()).collect()
}

fn geodata_dirs_with_defaults<P: AsRef<Path>>(dirs: &[P]) -> Vec<PathBuf> {
    let mut search_dirs = configured_geodata_dirs(dirs);

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
        parsing_xhttp_download: false,
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
    parsing_xhttp_download: bool,
}

impl Parser<'_> {
    fn parse_config(&mut self) -> CoreConfig {
        self.validate_top_level_fields();
        let inbounds = self.parse_inbounds();
        let outbounds = self.parse_outbounds();
        let routing = self.parse_routing();
        let observatory = self.parse_observatory();
        let dns = self.parse_dns();
        let policy = self.parse_policy();
        let default_outbound_tag = outbounds.first().and_then(|outbound| outbound.tag.clone());

        CoreConfig {
            inbounds,
            outbounds,
            default_outbound_tag,
            routing,
            observatory,
            dns,
            policy,
        }
    }

    fn validate_top_level_fields(&mut self) {
        self.reject_unknown_fields(self.root, "$", &surface::ROOT);
    }

    fn parse_observatory(&mut self) -> Option<ObservatoryConfig> {
        let observatory = self.root.get("observatory")?;
        let path = "$.observatory";
        if observatory.is_null() {
            return None;
        }
        if !observatory.is_object() {
            self.error(path, "observatory must be an object or null");
            return None;
        }
        self.reject_unknown_fields(observatory, path, &surface::OBSERVATORY);

        let subject_selectors = match observatory.get("subjectSelector") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(values)) => {
                if values.len() > MAX_OBSERVATORY_SUBJECT_SELECTORS {
                    self.error(
                        format!("{path}.subjectSelector"),
                        format!(
                            "observatory contains {} subject selectors; maximum supported per configuration is {MAX_OBSERVATORY_SUBJECT_SELECTORS}",
                            values.len()
                        ),
                    );
                    return None;
                }
                let mut selectors = Vec::with_capacity(values.len());
                for (index, value) in values.iter().enumerate() {
                    let Some(value) = value.as_str() else {
                        self.error(
                            format!("{path}.subjectSelector[{index}]"),
                            "observatory subject selector must be a string",
                        );
                        return None;
                    };
                    selectors.push(value.to_owned());
                }
                selectors
            }
            Some(_) => {
                self.error(
                    format!("{path}.subjectSelector"),
                    "observatory subjectSelector must be an array",
                );
                return None;
            }
        };
        let probe_url = match observatory.get("probeURL") {
            None | Some(Value::Null) => DEFAULT_OBSERVATORY_PROBE_URL.to_owned(),
            Some(Value::String(value)) if value.is_empty() => {
                DEFAULT_OBSERVATORY_PROBE_URL.to_owned()
            }
            Some(Value::String(value)) => value.clone(),
            Some(_) => {
                self.error(
                    format!("{path}.probeURL"),
                    "observatory probeURL must be a string or null",
                );
                return None;
            }
        };
        let probe_interval = match observatory.get("probeInterval") {
            None | Some(Value::Null) => DEFAULT_OBSERVATORY_PROBE_INTERVAL,
            Some(Value::String(value)) if value.is_empty() => DEFAULT_OBSERVATORY_PROBE_INTERVAL,
            Some(Value::String(value)) => match parse_xray_duration(value) {
                Some(duration) if duration.is_zero() => DEFAULT_OBSERVATORY_PROBE_INTERVAL,
                Some(duration)
                    if (MIN_OBSERVATORY_PROBE_INTERVAL..=MAX_OBSERVATORY_PROBE_INTERVAL)
                        .contains(&duration) =>
                {
                    duration
                }
                Some(_) => {
                    self.error(
                        format!("{path}.probeInterval"),
                        "observatory probeInterval must be between 1s and 24h",
                    );
                    return None;
                }
                None => {
                    self.error(
                        format!("{path}.probeInterval"),
                        "observatory probeInterval must be a valid Xray duration string",
                    );
                    return None;
                }
            },
            Some(_) => {
                self.error(
                    format!("{path}.probeInterval"),
                    "observatory probeInterval must be a duration string or null",
                );
                return None;
            }
        };
        let enable_concurrency = self
            .optional_bool_at(
                observatory,
                "enableConcurrency",
                format!("{path}.enableConcurrency"),
            )
            .unwrap_or(false);

        Some(ObservatoryConfig {
            subject_selectors,
            probe_url,
            probe_interval,
            enable_concurrency,
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

        self.reject_unknown_fields(policy, policy_path, &surface::POLICY);
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
            self.reject_unknown_fields(config, &level_path, &surface::POLICY_LEVEL);
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

        self.reject_unknown_fields(system, system_path, &surface::POLICY_SYSTEM);

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
        self.reject_unknown_fields(inbound, &inbound_path, &surface::INBOUND);

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

        self.reject_unknown_fields(sniffing, &sniffing_path, &surface::SNIFFING);
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

        self.reject_unknown_fields(settings, &settings_path, &surface::SOCKS_SETTINGS);

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

        self.reject_unknown_fields(settings, &settings_path, &surface::HTTP_SETTINGS);
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
        let proxy_settings = self.parse_outbound_proxy_settings(outbound, index);

        if proxy_settings.is_some() && matches!(stream.security, StreamSecurity::Reality(_)) {
            self.error(
                format!("$.outbounds[{index}].proxySettings"),
                "outbound chaining over REALITY is unsupported",
            );
        }

        // Xray v26.7.28 applies this policy only to its simplified top-level
        // VLESS settings. Its legacy `vnext` path bypasses that validation.
        // xray-rust supports the legacy shape and deliberately applies the
        // same fail-closed security policy here instead of preserving that
        // unsafe compatibility gap.
        let rejects_plaintext_server = match &settings {
            OutboundSettings::Vless(vless) => {
                matches!(&stream.security, StreamSecurity::None)
                    && vless
                        .users
                        .first()
                        .is_none_or(|user| user.encryption.is_none())
                    && !vless.server.is_xray_plaintext_server_exempt()
            }
            OutboundSettings::Freedom | OutboundSettings::Dns(_) => false,
        };
        if rejects_plaintext_server {
            self.error(
                format!("$.outbounds[{index}].settings.vnext[0].address"),
                "vless without TLS or other encryption is prohibited unless the server address is a private IP or domain",
            );
            return None;
        }

        if let (OutboundSettings::Vless(vless), StreamTransport::Xhttp(xhttp)) =
            (&settings, &stream.transport)
        {
            if let Some(download) = &xhttp.download {
                if download.stream.security == StreamSecurity::None
                    && vless
                        .users
                        .first()
                        .is_none_or(|user| user.encryption.is_none())
                    && !download.address.is_xray_plaintext_server_exempt()
                {
                    self.error(
                        xhttp::download_path(outbound.get("streamSettings"), index) + ".address",
                        "unencrypted VLESS download requires a private or test server address",
                    );
                }
            }
        }

        Some(OutboundConfig {
            tag: self.string_at(outbound, "tag").map(ToOwned::to_owned),
            proxy_settings,
            stream,
            settings,
        })
    }

    fn validate_outbound_compatibility(&mut self, outbound: &Value, index: usize) {
        let outbound_path = format!("$.outbounds[{index}]");
        self.reject_unknown_fields(outbound, &outbound_path, &surface::OUTBOUND);

        if outbound.get("sendThrough").is_some() {
            self.error(
                format!("{outbound_path}.sendThrough"),
                "outbound sendThrough is unsupported",
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
        self.reject_unknown_fields(mux, &mux_path, &surface::MUX);
        if matches!(
            self.optional_bool_at(mux, "enabled", format!("{mux_path}.enabled")),
            Some(true)
        ) {
            self.error(format!("{mux_path}.enabled"), "outbound mux is unsupported");
        }
        self.optional_u32_at(mux, "concurrency", format!("{mux_path}.concurrency"));
    }

    fn parse_outbound_proxy_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<OutboundProxySettings> {
        let proxy = outbound.get("proxySettings")?;
        let path = format!("$.outbounds[{index}].proxySettings");
        if !proxy.is_object() {
            self.error(path, "outbound proxySettings must be an object");
            return None;
        }
        self.reject_unknown_fields(proxy, &path, &surface::PROXY);

        let tag = self
            .optional_string_at(proxy, "tag", format!("{path}.tag"))
            .filter(|tag| !tag.is_empty())
            .map(ToOwned::to_owned);
        if tag.is_none() {
            self.error(
                format!("{path}.tag"),
                "outbound proxySettings tag must be a non-empty string",
            );
        }

        let transport_layer =
            self.optional_bool_at(proxy, "transportLayer", format!("{path}.transportLayer"));
        if transport_layer != Some(true) {
            self.error(
                format!("{path}.transportLayer"),
                "only transport-layer outbound chaining is supported; transportLayer must be true",
            );
        }

        Some(OutboundProxySettings {
            tag: tag?,
            transport_layer: transport_layer?,
        })
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

        self.reject_unknown_fields(settings, &settings_path, &surface::FREEDOM_SETTINGS);
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
        matchers: &mut DomainMatcherSetBuilder,
    ) -> Option<()> {
        let Some(raw) = value.get(key) else {
            return Some(());
        };
        let Some(values) = raw.as_array() else {
            self.error(path, format!("field `{key}` must be an array"));
            return None;
        };

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
            insert_domain_matchers(matchers, &parsed_matchers, DomainNameMode::Routing);
        }

        Some(())
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
    ) -> Option<IpMatcherSet> {
        let Some(raw) = value.get(key) else {
            return Some(IpMatcherSet::default());
        };
        let Some(values) = raw.as_array() else {
            self.error(path, format!("field `{key}` must be an array"));
            return None;
        };
        let mut matchers = IpMatcherSet::builder();

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

            if self.matcher_budget.remaining_ip_matchers() == 0 {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
            let inserted = self.parse_ip_matcher(value, &item_path, &mut matchers)?;
            if !self.matcher_budget.consume_ip_matchers(inserted) {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
        }

        Some(matchers.build())
    }

    fn parse_ip_matcher(
        &mut self,
        value: &str,
        path: &str,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Option<usize> {
        self.parse_ip_matcher_with_mode(value, path, IpMatcherParseMode::Routing, matchers)
    }

    fn parse_dns_ip_matcher(
        &mut self,
        value: &str,
        path: &str,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Option<usize> {
        self.parse_ip_matcher_with_mode(value, path, IpMatcherParseMode::XrayDns, matchers)
    }

    fn parse_ip_matcher_with_mode(
        &mut self,
        value: &str,
        path: &str,
        mode: IpMatcherParseMode,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Option<usize> {
        let (value, inverse) = strip_inverse_prefix(value);
        if let Some(code) = value.strip_prefix("geoip:") {
            let (code, code_inverse) = strip_inverse_prefix(code);
            let inverse = inverse ^ code_inverse;
            if code.is_empty() {
                self.error(path, "geoip code cannot be empty");
                return None;
            }
            if mode == IpMatcherParseMode::Routing && code.eq_ignore_ascii_case("private") {
                matchers.insert_private_networks(inverse);
                return Some(1);
            }
            return self.parse_geoip_matchers("geoip.dat", code, inverse, path, mode, matchers);
        }

        if let Some(spec) = value.strip_prefix("ext-ip:") {
            return self.parse_external_geoip_matchers(spec, inverse, path, mode, matchers);
        }
        if let Some(spec) = value.strip_prefix("ext:") {
            return self.parse_external_geoip_matchers(spec, inverse, path, mode, matchers);
        }

        let cidr = self.parse_ip_cidr(value, path)?;
        matchers.insert_cidr(cidr.cidr(), inverse);
        Some(1)
    }

    fn parse_external_geoip_matchers(
        &mut self,
        spec: &str,
        inverse: bool,
        path: &str,
        mode: IpMatcherParseMode,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Option<usize> {
        let (file_name, code) = self.parse_external_geodata_ref(spec, path)?;
        let (code, code_inverse) = strip_inverse_prefix(code);
        let inverse = inverse ^ code_inverse;
        if code.is_empty() {
            self.error(path, "geoip code cannot be empty");
            return None;
        }

        self.parse_geoip_matchers(file_name, code, inverse, path, mode, matchers)
    }

    fn parse_geoip_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
        path: &str,
        mode: IpMatcherParseMode,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Option<usize> {
        let max_matchers = self.matcher_budget.remaining_ip_matchers();
        let inserted = match mode {
            IpMatcherParseMode::Routing => self.geodata_loader.load_ip_matchers(
                file_name,
                code,
                inverse,
                max_matchers,
                matchers,
            ),
            IpMatcherParseMode::XrayDns => self.geodata_loader.load_dns_ip_matchers(
                file_name,
                code,
                inverse,
                max_matchers,
                matchers,
            ),
        };
        match inserted {
            Ok(0) => {
                self.error(
                    path,
                    format!("geoip `{file_name}:{code}` produced no IP matchers"),
                );
                None
            }
            Ok(inserted) => Some(inserted),
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

    fn reject_unknown_fields(
        &mut self,
        value: &Value,
        base_path: &str,
        allowed: &surface::ObjectFields,
    ) {
        let Some(object) = value.as_object() else {
            return;
        };

        for key in object.keys() {
            if !allowed.fields.contains(&key.as_str()) {
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

fn non_empty_or(value: Option<&str>, default: &str) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
        .to_owned()
}

fn zero_xhttp_xmux_settings() -> XhttpXmuxSettings {
    XhttpXmuxSettings {
        max_concurrency: XhttpRange::default(),
        max_connections: XhttpRange::default(),
        c_max_reuse_times: XhttpRange::default(),
        h_max_request_times: XhttpRange::default(),
        h_max_reusable_secs: XhttpRange::default(),
        h_keep_alive_period_secs: 0,
    }
}

/// Xray only applies `SplitHTTPConfig.Build` defaults when either JSON settings
/// pointer is non-nil. With no settings block the transport registry creates a
/// zero-valued protobuf config instead, whose XMUX policy must remain zero.
fn xhttp_settings_without_config_block() -> XhttpSettings {
    XhttpSettings {
        xmux: zero_xhttp_xmux_settings(),
        ..XhttpSettings::default()
    }
}

fn predefined_xhttp_session_id_table_size(table: &str) -> Option<usize> {
    match table {
        "ALPHABET" | "alphabet" => Some(26),
        "Alphabet" => Some(52),
        "BASE36" | "base36" => Some(36),
        "Base62" => Some(62),
        "HEX" | "hex" => Some(16),
        "number" => Some(10),
        _ => None,
    }
}

/// Mirrors Xray's `roomSize(tableSize, min, max) >= 2 << 30` check without
/// allocating a big integer or iterating an attacker-controlled i32 range.
fn xhttp_session_id_room_is_large_enough(table_size: usize, length: XhttpRange) -> bool {
    const MINIMUM_ROOM: u64 = 2 << 30;

    let count = (i64::from(length.to) - i64::from(length.from) + 1) as u64;
    if table_size == 1 {
        return count >= MINIMUM_ROOM;
    }
    if table_size == 0 {
        return false;
    }

    let base = table_size as u64;
    let mut exponent = length.from as u32;
    let mut factor = base.min(MINIMUM_ROOM);
    let mut term = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            term = term.saturating_mul(factor).min(MINIMUM_ROOM);
        }
        exponent >>= 1;
        if exponent > 0 {
            factor = factor.saturating_mul(factor).min(MINIMUM_ROOM);
        }
    }

    let mut room = 0_u64;
    for _ in 0..count {
        room = room.saturating_add(term).min(MINIMUM_ROOM);
        if room == MINIMUM_ROOM {
            return true;
        }
        term = term.saturating_mul(base).min(MINIMUM_ROOM);
    }
    false
}

/// Parses Xray's `Bandwidth` spelling. JSON values are bits per second with
/// binary unit multipliers; the normalized runtime value is bytes per second.
fn parse_quic_bandwidth(value: &str) -> Result<u64, String> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        return Ok(0);
    }

    let unit_start = normalized
        .char_indices()
        .find(|(_, character)| !character.is_ascii_digit() && *character != '.')
        .map_or(normalized.len(), |(index, _)| index);
    let (number, unit) = normalized.split_at(unit_start);
    let bits = number
        .parse::<f64>()
        .map_err(|_| "bandwidth must start with a decimal number".to_owned())?;
    let multiplier = match unit.trim() {
        "" | "b" | "bps" => 1_u64,
        "k" | "kb" | "kbps" => 1_024,
        "m" | "mb" | "mbps" => 1_024_u64.pow(2),
        "g" | "gb" | "gbps" => 1_024_u64.pow(3),
        "t" | "tb" | "tbps" => 1_024_u64.pow(4),
        unit => return Err(format!("unsupported bandwidth unit `{unit}`")),
    };
    let scaled_bits = bits * multiplier as f64;
    // The grammar cannot express a sign or exponent, but a very long decimal
    // can still overflow f64/u64. Reject it rather than relying on a target-
    // dependent float-to-integer conversion.
    if !scaled_bits.is_finite() || scaled_bits < 0.0 || scaled_bits >= u64::MAX as f64 {
        return Err("bandwidth is outside the supported u64 range".to_owned());
    }
    Ok((scaled_bits.trunc() as u64) / 8)
}

/// Dedicated `PortList` parser for UDP hopping. Unlike routing selectors,
/// order and duplicates are wire/runtime significant and must be preserved.
fn parse_quic_udp_hop_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for token in value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        if token.contains("env:") {
            return Err("environment-backed udpHop ports are unsupported".to_owned());
        }

        let (from, to) = match token.split_once('-') {
            Some((from, to)) => (parse_quic_udp_hop_port(from)?, parse_quic_udp_hop_port(to)?),
            None => {
                let port = parse_quic_udp_hop_port(token)?;
                (port, port)
            }
        };
        if from > to {
            return Err(format!("udpHop port range is reversed: {from}-{to}"));
        }
        ports.extend(from..=to);
    }
    Ok(ports)
}

fn parse_quic_udp_hop_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u32>()
        .map_err(|_| format!("invalid udpHop port `{value}`"))?;
    if !(1..=u16::MAX as u32).contains(&port) {
        return Err(format!("udpHop port `{value}` must be in 1..=65535"));
    }
    Ok(port as u16)
}

/// Xray's `Int32Range` syntax accepts a single signed number, an ordered or
/// reversed pair, and the empty string as its zero value. Parsing directly to
/// i32 also prevents the reference implementation's lossy `int`-to-`int32`
/// cast for an oversized string from turning into a surprising wire setting.
fn parse_xhttp_range_string(value: &str) -> Option<(i32, i32)> {
    if value.is_empty() {
        return Some((0, 0));
    }
    if let Ok(single) = value.parse::<i32>() {
        return Some((single, single));
    }

    let separator = value
        .char_indices()
        .find(|(index, character)| *character == '-' && *index != 0)?
        .0;
    let (left, right_with_separator) = value.split_at(separator);
    let right = right_with_separator.strip_prefix('-')?;
    Some((left.parse::<i32>().ok()?, right.parse::<i32>().ok()?))
}

/// Splits `?ed=N` out of a configured path, returning the normalized path and
/// the early-data budget.
///
/// Xray strips `ed` at config-build time, so it never reaches the wire, and
/// re-encodes whatever query remains through Go's `url.Values.Encode()` —
/// which sorts parameters alphabetically. The server compares the whole path,
/// so both halves of that are load-bearing.
///
/// The rewrite is gated on `q.Get("ed") != ""`, which is narrower than it
/// looks: a path with no `ed`, or with an empty `ed=`, is passed through
/// byte-for-byte with its original parameter order. Sorting those too would
/// itself be a path mismatch.
///
/// Everything that makes Xray *skip* the rewrite is reproduced, because those
/// are the cases where rewriting anyway silently changes the path: a query
/// with no usable `ed`, a `url.Parse` failure (a control byte or a truncated
/// `%` escape), and a `?` that is really inside a `#` fragment.
///
/// When the rewrite fires, Xray stores `u.String()` rather than the decoded
/// path. That percent-escapes the path (and fragment) once at config-build
/// time while preserving an already-valid escape. HTTPUpgrade later assigns
/// that stored string to a fresh `URL.Path`, deliberately producing a second
/// escape; WebSocket reparses it as a URI and therefore keeps only one.
fn split_early_data_from_path(raw: &str) -> (String, u32) {
    let normalized_path = |path: &str| {
        if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    };

    // Go runs the value through `url.Parse` first and leaves the path
    // untouched when that fails, which a control byte does.
    if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return (normalized_path(raw), 0);
    }

    // `url.Parse` splits the fragment off before the query, so a `?` that
    // follows a `#` is part of the fragment and never carries an `ed`.
    let (before_fragment, fragment) = match raw.split_once('#') {
        Some((before_fragment, fragment)) => (before_fragment, Some(fragment)),
        None => (raw, None),
    };

    let Some((path, query)) = before_fragment.split_once('?') else {
        return (normalized_path(raw), 0);
    };
    // The other way `url.Parse` fails: a `%` in the path that is not a
    // complete hex escape.
    if !has_valid_percent_escapes(path)
        || fragment.is_some_and(|fragment| !has_valid_percent_escapes(fragment))
    {
        return (normalized_path(raw), 0);
    }

    let parsed = parse_go_query(query);
    // `q.Get("ed")` reads the first value stored under the key, whatever it
    // is. A first `ed` that is empty ends the rewrite even when a later one
    // carries a number: `/x?ed=&ed=7` keeps its whole query and no early data.
    let Some(early_data) = parsed
        .iter()
        .find(|(key, _)| key == b"ed")
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
    else {
        return (normalized_path(raw), 0);
    };

    // Go's `Ed, _ := strconv.Atoi(...); ed = uint32(Ed)` keeps zero on a
    // non-numeric value, truncates a wider one, wraps a negative one, and
    // saturates at `int` range on overflow — and deletes the parameter
    // regardless of which happened. Parsing wide and clamping reproduces all
    // four.
    let early_data = std::str::from_utf8(early_data)
        .ok()
        .and_then(|value| value.parse::<i128>().ok())
        .unwrap_or(0)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64 as u32;
    let kept = encode_go_query(parsed.into_iter().filter(|(key, _)| key != b"ed"));

    let mut normalized = escape_go_url_component(&normalized_path(path), GoUrlComponent::Path);
    if !kept.is_empty() {
        normalized.push('?');
        normalized.push_str(&kept);
    }
    if let Some(fragment) = fragment {
        normalized.push('#');
        normalized.push_str(&escape_go_url_component(fragment, GoUrlComponent::Fragment));
    }
    (normalized, early_data)
}

#[derive(Clone, Copy)]
enum GoUrlComponent {
    Path,
    Fragment,
}

/// The part of `url.URL.String()` relevant to an already-parsed path. A valid
/// `%XX` triplet is `RawPath`/`RawFragment` and keeps its original spelling;
/// other bytes follow Go's `shouldEscape` tables byte-for-byte.
fn escape_go_url_component(value: &str, component: GoUrlComponent) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%'
            && bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        {
            out.push('%');
            out.push(bytes[index + 1] as char);
            out.push(bytes[index + 2] as char);
            index += 3;
            continue;
        }

        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        let reserved = matches!(
            byte,
            b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@'
        );
        let safe = unreserved
            || match component {
                GoUrlComponent::Path => reserved && byte != b'?',
                GoUrlComponent::Fragment => reserved || matches!(byte, b'!' | b'(' | b')' | b'*'),
            };
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
        index += 1;
    }
    out
}

/// Whether every `%` in the value begins a complete two-digit hex escape.
/// Go's `url.Parse` rejects a path where one does not, which makes Xray leave
/// the whole path alone.
fn has_valid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let valid = bytes
            .get(index + 1)
            .zip(bytes.get(index + 2))
            .is_some_and(|(high, low)| hex_value(*high).is_ok() && hex_value(*low).is_ok());
        if !valid {
            return false;
        }
        index += 3;
    }
    true
}

/// Go's `url.ParseQuery`: `&`-separated pairs, percent-decoded with `+` as a
/// space. Segments that are empty, contain `;`, or carry a broken escape are
/// dropped, and `url.URL.Query()` discards the resulting error.
///
/// Keys and values stay raw bytes. `%FF` decodes to one byte in Go and
/// re-encodes to `%FF`; forcing it through a `String` would replace it with
/// U+FFFD and put `%EF%BF%BD` on the wire.
fn parse_go_query(query: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    query
        .split('&')
        .filter(|segment| !segment.is_empty() && !segment.contains(';'))
        .filter_map(|segment| {
            let (key, value) = segment.split_once('=').unwrap_or((segment, ""));
            Some((query_unescape(key)?, query_unescape(value)?))
        })
        .collect()
}

/// Go's `url.Values.Encode`: keys sorted, values kept in their original order
/// within a key, every pair emitted as `key=value` even when the value is
/// empty.
fn encode_go_query(pairs: impl Iterator<Item = (Vec<u8>, Vec<u8>)>) -> String {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = pairs.collect();
    pairs.sort_by(|(left, _), (right, _)| left.cmp(right));
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", query_escape(key), query_escape(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Go's `url.QueryUnescape`. `None` on a truncated or non-hex `%` escape,
/// which is how Go signals the segment should be dropped.
fn query_unescape(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = hex_value(*bytes.get(index + 1)?).ok()?;
                let low = hex_value(*bytes.get(index + 2)?).ok()?;
                out.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    Some(out)
}

/// Go's `url.QueryEscape`: only unreserved characters survive, and a space
/// becomes `+`. Takes bytes, since a decoded escape need not be UTF-8.
fn query_escape(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Go's `textproto.CanonicalMIMEHeaderKey`, which `http.Header.Add` applies:
/// the first letter and every letter after a `-` is upper-cased and the rest
/// lower-cased. A key holding a byte that is invalid in a header name is left
/// exactly as it came in, matching Go's bail-out.
fn canonical_header_name(name: &str) -> String {
    let valid = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    if !valid {
        return name.to_owned();
    }

    let mut canonical = String::with_capacity(name.len());
    let mut upper = true;
    for byte in name.bytes() {
        let byte = if upper {
            byte.to_ascii_uppercase()
        } else {
            byte.to_ascii_lowercase()
        };
        upper = byte == b'-';
        canonical.push(byte as char);
    }
    canonical
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
    let original_bytes = value.as_bytes();
    if original_bytes.first() == Some(&b'[') && original_bytes.last() == Some(&b']') {
        value = &value[1..value.len() - 1];
    }

    let normalized_bytes = value.as_bytes();
    if normalized_bytes
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || normalized_bytes
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

/// RFC 9110 `token` / RFC 7230 `tchar`, used for the HTTP request method.
/// Keeping this ASCII-only is security-critical because XHTTP's H1 engine
/// writes the method directly into the request line.
fn is_http_token(value: &str) -> bool {
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
        canonical_header_name, configured_geodata_dirs, default_geodata_dirs,
        geodata_dirs_with_defaults, parse_xray_json_with_loader_and_limits,
        split_early_data_from_path, GeodataLoader, MatcherBudget, MatcherBudgetLimits, Parser,
        SelectorBudget, DEFAULT_MATCHER_BUDGET_LIMITS, MAX_CONFIG_GEODATA_ATTRIBUTE_SIZE,
        MAX_CONFIG_GEODATA_ATTR_FILTERS, MAX_DNS_OUTBOUND_RULES, MAX_DNS_QTYPE_SELECTORS,
        MAX_ROUTING_PORT_SELECTORS,
    };

    /// Every expectation below is the printed output of a Go program running
    /// Xray's own `WebSocketConfig.Build` ed block followed by
    /// `Config.GetNormalizedPath` — the two steps that decide what path the
    /// server is asked for.
    #[test]
    fn path_normalization_matches_the_go_config_builder() {
        let oracle = [
            ("", "/", 0),
            ("/", "/", 0),
            ("chat", "/chat", 0),
            ("/chat", "/chat", 0),
            ("/x?ed=2048", "/x", 2048),
            ("/x?zulu=1&alpha=2&ed=64", "/x?alpha=2&zulu=1", 64),
            ("/x?ed=lots&keep=1", "/x?keep=1", 0),
            ("/x?zulu=1&alpha=2", "/x?zulu=1&alpha=2", 0),
            ("/x?ed=&zulu=1", "/x?ed=&zulu=1", 0),
            ("/x?ed=16&ed=32", "/x", 16),
            ("/x?b=a+b&a&ed=8", "/x?a=&b=a+b", 8),
            ("?ed=2048", "/", 2048),
            ("/x?ed=0", "/x", 0),
            ("/x?ed=-1", "/x", 4294967295),
            ("/x?ed=4294967296", "/x", 0),
            ("/x?a%2Fb=1&ed=1", "/x?a%2Fb=1", 1),
            ("/x?flag&ed=1", "/x?flag=", 1),
            ("/x?a=1;b=2&ed=1", "/x", 1),
            ("/x?ed=1&%zz=1", "/x", 1),
            ("/x?a b=c&ed=1", "/x?a+b=c", 1),
            // `q.Get` reads the first value under the key whatever it is, so a
            // leading empty `ed` ends the rewrite and a trailing one does not.
            ("/x?ed=&ed=7", "/x?ed=&ed=7", 0),
            ("/x?ed=7&ed=", "/x", 7),
            ("/x?ed=2048&ed=", "/x", 2048),
            ("/x?a=1&ed", "/x?a=1&ed", 0),
            // Raw bytes survive the decode/encode round trip.
            ("/x?k=%FF&ed=1", "/x?k=%FF", 1),
            ("/x?%FF=1&ed=1", "/x?%FF=1", 1),
            ("/x?ed=%37", "/x", 7),
            // Key matching is case-sensitive.
            ("/x?ED=8&ed=9", "/x?ED=8", 9),
            ("/x?ED=8", "/x?ED=8", 0),
            // Fragments are split off before the query is read.
            ("/x?ed=1#frag", "/x#frag", 1),
            ("/x#frag?ed=1", "/x#frag?ed=1", 0),
            // A path `url.Parse` rejects is left entirely alone.
            ("/%zz?ed=1", "/%zz?ed=1", 0),
            // `strconv.Atoi` saturates at int range before the uint32 cast.
            ("/x?ed=99999999999999999999", "/x", 4294967295),
            ("/x?ed=2147483648", "/x", 2147483648),
            ("/x?ed=+5", "/x", 0),
            ("/x?ed=0x10", "/x", 0),
            ("/x?ed= 5", "/x", 0),
            ("//host/x?ed=1", "//host/x", 1),
            ("/x%2Fy?ed=1", "/x%2Fy", 1),
            ("/x?ed=1&a=%2F", "/x?a=%2F", 1),
        ];

        for (raw, path, early_data) in oracle {
            assert_eq!(
                split_early_data_from_path(raw),
                (path.to_owned(), early_data),
                "path {raw:?}"
            );
        }
    }

    #[test]
    fn the_rewritten_path_and_fragment_are_escaped_like_go_url_string() {
        for (raw, expected) in [
            ("/a b?ed=1", "/a%20b"),
            ("/日本?ed=1", "/%E6%97%A5%E6%9C%AC"),
            ("/x%2fy?ed=1#日本", "/x%2fy#%E6%97%A5%E6%9C%AC"),
            ("/x?ed=1#a b!()'*", "/x#a%20b!()%27*"),
        ] {
            let (path, early_data) = split_early_data_from_path(raw);
            assert_eq!((path.as_str(), early_data), (expected, 1), "path {raw:?}");
        }
    }

    #[test]
    fn an_invalid_fragment_escape_makes_go_leave_early_data_untouched() {
        assert_eq!(
            split_early_data_from_path("/x?ed=1#%zz"),
            ("/x?ed=1#%zz".to_owned(), 0)
        );
    }

    /// Go's `http.Header.Add` runs the key through
    /// `textproto.CanonicalMIMEHeaderKey`, which websocket depends on and
    /// httpupgrade deliberately skips.
    #[test]
    fn header_names_are_canonicalized_the_way_go_canonicalizes_them() {
        assert_eq!(canonical_header_name("accept"), "Accept");
        assert_eq!(canonical_header_name("SEC-ch-ua"), "Sec-Ch-Ua");
        assert_eq!(canonical_header_name("X-Thing"), "X-Thing");
        assert_eq!(canonical_header_name("x--y"), "X--Y");
        assert_eq!(canonical_header_name("-x"), "-X");
        assert_eq!(canonical_header_name(""), "");
        // A byte that cannot appear in a header name makes Go give up and
        // return the key untouched.
        assert_eq!(canonical_header_name("bad key"), "bad key");
        assert_eq!(canonical_header_name("naïve"), "naïve");
    }

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
    fn exclusive_geodata_dirs_omit_defaults() {
        let custom_dir = PathBuf::from("exclusive-geodata");
        let dirs = configured_geodata_dirs(std::slice::from_ref(&custom_dir));

        assert_eq!(dirs, vec![custom_dir]);
    }

    #[test]
    fn default_matcher_budget_enforces_domain_ip_and_combined_limits() {
        let mut domain_budget = MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS);
        let mut ip_budget = MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS);
        let mut combined_budget = MatcherBudget::new(DEFAULT_MATCHER_BUDGET_LIMITS);

        assert!(domain_budget.consume_domain_matchers(250_000));
        assert!(!domain_budget.consume_domain_matchers(1));
        assert!(ip_budget.consume_ip_matchers(750_000));
        assert!(!ip_budget.consume_ip_matchers(1));
        assert!(combined_budget.consume_domain_matchers(250_000));
        assert!(combined_budget.consume_ip_matchers(750_000));
        assert_eq!(combined_budget.remaining_total_matchers(), 0);
        assert!(!combined_budget.consume_domain_matchers(1));
        assert!(!combined_budget.consume_ip_matchers(1));
    }

    #[test]
    fn combined_matcher_budget_can_be_stricter_than_individual_limits() {
        let mut budget = MatcherBudget::new(MatcherBudgetLimits {
            domain_matchers: 3,
            ip_matchers: 3,
            total_matchers: 4,
            ..DEFAULT_MATCHER_BUDGET_LIMITS
        });

        assert!(budget.consume_domain_matchers(2));
        assert!(budget.consume_ip_matchers(2));
        assert!(!budget.consume_domain_matchers(1));
        assert!(!budget.consume_ip_matchers(1));
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
            parsing_xhttp_download: false,
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
            parsing_xhttp_download: false,
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
