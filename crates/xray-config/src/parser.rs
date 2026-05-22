use std::net::IpAddr;

use serde_json::Value;
use uuid::Uuid;

use crate::{
    CoreConfig, Diagnostic, DomainMatcher, InboundConfig, InboundProtocol, IpCidr, IpMatcher,
    Network, OutboundConfig, OutboundProtocol, OutboundSettings, RealitySettings, RealityShortId,
    RoutingConfig, RoutingRule, StreamSecurity, StreamSettings, TargetAddr, TlsSettings,
    VlessOutboundSettings, VlessUser,
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
    let value = serde_json::from_str::<Value>(raw).map_err(|err| ConfigParseError {
        diagnostics: vec![Diagnostic::error("$", err.to_string())],
    })?;

    let mut parser = Parser {
        root: &value,
        diagnostics: Vec::new(),
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
}

impl Parser<'_> {
    fn parse_config(&mut self) -> CoreConfig {
        self.validate_top_level_fields();
        let inbounds = self.parse_inbounds();
        let outbounds = self.parse_outbounds();
        let routing = self.parse_routing(&outbounds);
        let default_outbound_tag = outbounds.first().and_then(|outbound| outbound.tag.clone());

        CoreConfig {
            inbounds,
            outbounds,
            default_outbound_tag,
            routing,
        }
    }

    fn validate_top_level_fields(&mut self) {
        self.reject_unknown_fields(self.root, "$", &["log", "inbounds", "outbounds", "routing"]);
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
            &["type", "inboundTag", "domain", "ip", "outboundTag"],
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
        let domain_matchers =
            self.parse_domain_matchers(rule, "domain", format!("{rule_path}.domain"))?;
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

        Some(InboundConfig {
            tag: self.string_at(inbound, "tag").map(ToOwned::to_owned),
            protocol,
            listen: self
                .string_at(inbound, "listen")
                .unwrap_or("127.0.0.1")
                .to_owned(),
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
                Some(StreamSecurity::Tls(TlsSettings {
                    server_name: tls_settings
                        .and_then(|settings| self.string_at(settings, "serverName"))
                        .map(ToOwned::to_owned),
                    fingerprint: tls_settings
                        .and_then(|settings| self.string_at(settings, "fingerprint"))
                        .map(ToOwned::to_owned),
                    allow_insecure: tls_settings
                        .and_then(|settings| {
                            self.optional_bool_at(
                                settings,
                                "allowInsecure",
                                format!(
                                    "$.outbounds[{index}].streamSettings.tlsSettings.allowInsecure"
                                ),
                            )
                        })
                        .unwrap_or(false),
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
            let Some((kind, domain)) = value.split_once(':') else {
                self.error(
                    format!("{path}[{index}]"),
                    "routing domain matcher must use domain: or full:",
                );
                return None;
            };
            if domain.is_empty() {
                self.error(format!("{path}[{index}]"), "routing domain cannot be empty");
                return None;
            }

            match kind {
                "domain" => matchers.push(DomainMatcher::Suffix(domain.to_owned())),
                "full" => matchers.push(DomainMatcher::Full(domain.to_owned())),
                _ => {
                    self.error(
                        format!("{path}[{index}]"),
                        format!("unsupported routing domain matcher `{kind}`"),
                    );
                    return None;
                }
            }
        }

        Some(matchers)
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
                Some(matcher) => matchers.push(matcher),
                None => return None,
            }
        }

        Some(matchers)
    }

    fn parse_ip_matcher(&mut self, value: &str, path: &str) -> Option<IpMatcher> {
        if let Some(code) = value.strip_prefix("geoip:") {
            if code == "private" {
                return Some(IpMatcher::Private);
            }
            self.error(
                path,
                format!("unsupported routing ip matcher `geoip:{code}`"),
            );
            return None;
        }

        if value.starts_with("ext:") || value.starts_with("ext-ip:") {
            self.error(path, "external routing ip data is unsupported");
            return None;
        }

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

        Some(IpMatcher::Cidr(cidr))
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

    fn error(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::error(path, message));
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
