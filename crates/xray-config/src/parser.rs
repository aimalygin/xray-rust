use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde_json::Value;
use uuid::Uuid;

use crate::{
    geodata::{default_geodata_dirs, GeodataLoader},
    CoreConfig, Diagnostic, DnsConfig, DnsFakeIpConfig, DomainMatcher, InboundConfig,
    InboundProtocol, IpCidr, IpMatcher, Network, OutboundConfig, OutboundProtocol,
    OutboundSettings, RealitySettings, RealityShortId, RegexMatcher, RoutingConfig, RoutingRule,
    StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser,
};

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
    let value = serde_json::from_str::<Value>(raw).map_err(|err| ConfigParseError {
        diagnostics: vec![Diagnostic::error("$", err.to_string())],
    })?;

    let mut parser = Parser {
        root: &value,
        diagnostics: Vec::new(),
        geodata_loader,
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
}

impl Parser<'_> {
    fn parse_config(&mut self) -> CoreConfig {
        self.validate_top_level_fields();
        let inbounds = self.parse_inbounds();
        let outbounds = self.parse_outbounds();
        let routing = self.parse_routing(&outbounds);
        let dns = self.parse_dns();
        let default_outbound_tag = outbounds.first().and_then(|outbound| outbound.tag.clone());

        CoreConfig {
            inbounds,
            outbounds,
            default_outbound_tag,
            routing,
            dns,
        }
    }

    fn validate_top_level_fields(&mut self) {
        self.reject_unknown_fields(
            self.root,
            "$",
            &["log", "inbounds", "outbounds", "routing", "dns"],
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

        self.reject_unknown_fields(dns, dns_path, &["fakeIp"]);
        DnsConfig {
            fake_ip: self.parse_dns_fake_ip(dns),
        }
    }

    fn parse_dns_fake_ip(&mut self, dns: &Value) -> Option<DnsFakeIpConfig> {
        let fake_ip = dns.get("fakeIp")?;
        let fake_ip_path = "$.dns.fakeIp";
        if !fake_ip.is_object() {
            self.error(fake_ip_path, "dns fakeIp must be an object");
            return None;
        }

        self.reject_unknown_fields(fake_ip, fake_ip_path, &["enabled", "ipv4Pool", "ttl"]);
        let enabled = self
            .optional_bool_at(fake_ip, "enabled", format!("{fake_ip_path}.enabled"))
            .unwrap_or(false);
        let ttl = self
            .optional_u32_at(fake_ip, "ttl", format!("{fake_ip_path}.ttl"))
            .unwrap_or(60);

        if !enabled {
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

        Some(DnsFakeIpConfig {
            enabled,
            ipv4_pool: pool,
            ttl,
        })
    }

    fn parse_routing(&mut self, outbounds: &[OutboundConfig]) -> RoutingConfig {
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

        if let Some(strategy) = self.optional_string_at(
            routing,
            "domainStrategy",
            "$.routing.domainStrategy".to_owned(),
        ) {
            if strategy != "AsIs" {
                self.error(
                    "$.routing.domainStrategy",
                    format!("unsupported routing domainStrategy `{strategy}`"),
                );
            }
        }

        self.reject_non_empty_array(routing, "balancers", "$.routing.balancers".to_owned());
        RoutingConfig {
            rules: self.parse_routing_rules(routing, outbounds),
        }
    }

    fn parse_routing_rules(
        &mut self,
        routing: &Value,
        outbounds: &[OutboundConfig],
    ) -> Vec<RoutingRule> {
        let Some(raw_rules) = routing.get("rules") else {
            return Vec::new();
        };
        let Some(rules) = raw_rules.as_array() else {
            self.error("$.routing.rules", "field `rules` must be an array");
            return Vec::new();
        };

        rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| self.parse_routing_rule(rule, index, outbounds))
            .collect()
    }

    fn parse_routing_rule(
        &mut self,
        rule: &Value,
        index: usize,
        outbounds: &[OutboundConfig],
    ) -> Option<RoutingRule> {
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
                "domain",
                "domains",
                "ip",
                "outboundTag",
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
        if !outbounds
            .iter()
            .any(|outbound| outbound.tag.as_deref() == Some(outbound_tag))
        {
            self.error(
                outbound_tag_path,
                format!("routing rule references unknown outboundTag `{outbound_tag}`"),
            );
            return None;
        }

        let inbound_tags =
            self.optional_string_array_at(rule, "inboundTag", format!("{rule_path}.inboundTag"))?;
        let domain_matchers = self.parse_routing_rule_domain_matchers(rule, &rule_path)?;
        let ip_matchers = self.parse_ip_matchers(rule, "ip", format!("{rule_path}.ip"))?;

        Some(RoutingRule {
            inbound_tags,
            domain_matchers,
            ip_matchers,
            outbound_tag: outbound_tag.to_owned(),
        })
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

        let port = self
            .u16_at(inbound, "port", format!("$.inbounds[{index}].port"))
            .unwrap_or(0);

        let listen = self
            .string_at(inbound, "listen")
            .unwrap_or("127.0.0.1")
            .to_owned();
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
        })
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
        self.validate_inbound_sniffing(inbound, index);

        let Some(settings) = inbound.get("settings") else {
            return;
        };

        match protocol {
            InboundProtocol::Socks => self.validate_socks_inbound_settings(settings, index),
            InboundProtocol::Http => self.validate_http_inbound_settings(settings, index),
            InboundProtocol::Tun => {}
        }
    }

    fn validate_inbound_sniffing(&mut self, inbound: &Value, index: usize) {
        let Some(sniffing) = inbound.get("sniffing") else {
            return;
        };
        let sniffing_path = format!("$.inbounds[{index}].sniffing");
        if !sniffing.is_object() {
            self.error(sniffing_path, "inbound sniffing must be an object");
            return;
        }

        if matches!(
            self.optional_bool_at(sniffing, "enabled", format!("{sniffing_path}.enabled")),
            Some(true)
        ) {
            self.error(
                format!("{sniffing_path}.enabled"),
                "inbound sniffing is unsupported",
            );
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
            &["auth", "accounts", "udp", "ip", "userLevel"],
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
            &["timeout", "accounts", "allowTransparent", "userLevel"],
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
        let protocol = match self.string_at(outbound, "protocol") {
            Some("freedom") => OutboundProtocol::Freedom,
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
        if matches!(
            self.optional_bool_at(mux, "enabled", format!("{mux_path}.enabled")),
            Some(true)
        ) {
            self.error(format!("{mux_path}.enabled"), "outbound mux is unsupported");
        }
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
            &["id", "encryption", "flow", "level", "email"],
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

        Some(VlessUser {
            id,
            encryption: encryption.to_owned(),
            flow,
        })
    }

    fn parse_stream_settings(&mut self, outbound: &Value, index: usize) -> Option<StreamSettings> {
        let stream = outbound.get("streamSettings");
        let network = self.parse_network(stream, index)?;
        let security = self.parse_security(stream, index)?;
        if let Some(stream) = stream {
            self.validate_stream_settings_compatibility(stream, index);
        }

        Some(StreamSettings { network, security })
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
        let Some(fingerprint) =
            settings.and_then(|settings| self.string_at(settings, "fingerprint"))
        else {
            self.error(fingerprint_path, "missing reality fingerprint");
            return None;
        };
        if fingerprint != "chrome" {
            self.error(
                fingerprint_path,
                format!("unsupported reality fingerprint `{fingerprint}`"),
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
        })
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
        let values = self.optional_string_array_at(value, key, path.clone())?;
        let mut matchers = Vec::with_capacity(values.len());

        for (index, value) in values.iter().enumerate() {
            let item_path = format!("{path}[{index}]");
            matchers.extend(self.parse_domain_matcher(value, &item_path)?);
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

    fn parse_domain_matcher(&mut self, value: &str, path: &str) -> Option<Vec<DomainMatcher>> {
        if let Some(spec) = value.strip_prefix("geosite:") {
            return self.parse_geosite_matchers("geosite.dat", spec, path);
        }
        if let Some(spec) = value.strip_prefix("ext-domain:") {
            return self.parse_external_geosite_matchers(spec, path);
        }
        if let Some(spec) = value.strip_prefix("ext:") {
            return self.parse_external_geosite_matchers(spec, path);
        }

        let Some((kind, domain)) = value.split_once(':') else {
            return Some(vec![DomainMatcher::Keyword(value.to_owned())]);
        };
        if domain.is_empty() {
            self.error(path, "routing domain cannot be empty");
            return None;
        }

        match kind {
            "domain" => Some(vec![DomainMatcher::Suffix(domain.to_owned())]),
            "full" => Some(vec![DomainMatcher::Full(domain.to_owned())]),
            "keyword" => Some(vec![DomainMatcher::Keyword(domain.to_owned())]),
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
    ) -> Option<Vec<DomainMatcher>> {
        let (file_name, code_spec) = self.parse_external_geodata_ref(spec, path)?;
        self.parse_geosite_matchers(file_name, code_spec, path)
    }

    fn parse_geosite_matchers(
        &mut self,
        file_name: &str,
        code_spec: &str,
        path: &str,
    ) -> Option<Vec<DomainMatcher>> {
        let (code, attrs) = self.parse_geosite_code_and_attrs(code_spec, path)?;
        match self
            .geodata_loader
            .load_site_matchers(file_name, code, &attrs)
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
        let values = self.optional_string_array_at(value, key, path.clone())?;
        let mut matchers = Vec::with_capacity(values.len());

        for (index, value) in values.iter().enumerate() {
            let item_path = format!("{path}[{index}]");
            match self.parse_ip_matcher(value, &item_path) {
                Some(parsed_matchers) => matchers.extend(parsed_matchers),
                None => return None,
            }
        }

        Some(matchers)
    }

    fn parse_ip_matcher(&mut self, value: &str, path: &str) -> Option<Vec<IpMatcher>> {
        let (value, inverse) = strip_inverse_prefix(value);
        if let Some(code) = value.strip_prefix("geoip:") {
            let (code, code_inverse) = strip_inverse_prefix(code);
            let inverse = inverse ^ code_inverse;
            if code.is_empty() {
                self.error(path, "geoip code cannot be empty");
                return None;
            }
            if code.eq_ignore_ascii_case("private") {
                return Some(vec![wrap_ip_matcher_inverse(IpMatcher::Private, inverse)]);
            }
            return self.parse_geoip_matchers("geoip.dat", code, inverse, path);
        }

        if let Some(spec) = value.strip_prefix("ext-ip:") {
            return self.parse_external_geoip_matchers(spec, inverse, path);
        }
        if let Some(spec) = value.strip_prefix("ext:") {
            return self.parse_external_geoip_matchers(spec, inverse, path);
        }

        self.parse_ip_cidr(value, path)
            .map(|cidr| vec![wrap_ip_matcher_inverse(IpMatcher::Cidr(cidr), inverse)])
    }

    fn parse_external_geoip_matchers(
        &mut self,
        spec: &str,
        inverse: bool,
        path: &str,
    ) -> Option<Vec<IpMatcher>> {
        let (file_name, code) = self.parse_external_geodata_ref(spec, path)?;
        let (code, code_inverse) = strip_inverse_prefix(code);
        let inverse = inverse ^ code_inverse;
        if code.is_empty() {
            self.error(path, "geoip code cannot be empty");
            return None;
        }

        self.parse_geoip_matchers(file_name, code, inverse, path)
    }

    fn parse_geoip_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
        path: &str,
    ) -> Option<Vec<IpMatcher>> {
        match self
            .geodata_loader
            .load_ip_matchers(file_name, code, inverse)
        {
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

        let mut attrs = Vec::new();
        for attr in parts {
            if attr.is_empty() {
                self.error(path, "geosite attribute cannot be empty");
                return None;
            }
            attrs.push(attr.to_ascii_lowercase());
        }

        Some((code, attrs))
    }

    fn parse_ip_cidr(&mut self, value: &str, path: &str) -> Option<IpCidr> {
        let (ip, prefix) = match value.split_once('/') {
            Some((ip, prefix)) => {
                let Some(prefix) = prefix.parse::<u8>().ok() else {
                    self.error(path, format!("invalid routing CIDR prefix `{prefix}`"));
                    return None;
                };
                (ip, Some(prefix))
            }
            None => (value, None),
        };

        let Some(ip) = ip.parse::<IpAddr>().ok() else {
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

fn wrap_ip_matcher_inverse(matcher: IpMatcher, inverse: bool) -> IpMatcher {
    if inverse {
        IpMatcher::Not(Box::new(matcher))
    } else {
        matcher
    }
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
    use std::path::PathBuf;

    use super::{default_geodata_dirs, geodata_dirs_with_defaults};

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
}
