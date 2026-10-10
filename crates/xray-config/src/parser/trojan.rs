use super::*;
use crate::TrojanOutboundSettings;

impl Parser<'_> {
    pub(super) fn parse_trojan_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<TrojanOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|v| v.is_object()) else {
            self.error(path, "Trojan settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::TROJAN);
        let (server, path) = if let Some(servers) = settings.get("servers") {
            if surface::TROJAN_SERVER
                .fields
                .iter()
                .any(|key| settings.get(*key).is_some())
            {
                self.error(
                    path,
                    "Trojan flattened settings and servers cannot be combined",
                );
                return None;
            }
            let Some(servers) = servers.as_array().filter(|a| a.len() == 1) else {
                self.error(
                    format!("{path}.servers"),
                    "Trojan requires exactly one server",
                );
                return None;
            };
            let path = format!("{path}.servers[0]");
            if !servers[0].is_object() {
                self.error(path, "Trojan server must be an object");
                return None;
            }
            self.reject_unknown_fields(&servers[0], &path, &surface::TROJAN_SERVER);
            (&servers[0], path)
        } else {
            (settings, path)
        };
        let Some(address) = self.string_at(server, "address") else {
            self.error(
                format!("{path}.address"),
                "Trojan requires a server address",
            );
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty()
            || address.len() > 255
            || address.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            self.error(format!("{path}.address"), "invalid Trojan server address");
            return None;
        }
        let address = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip);
        let port = self.u16_at(server, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(format!("{path}.port"), "Trojan port must be nonzero");
        }
        let Some(password) = self.string_at(server, "password") else {
            self.error(format!("{path}.password"), "Trojan requires a password");
            return None;
        };
        if password.is_empty() || password.len() > xray_proxy::trojan::MAX_PASSWORD_LENGTH {
            self.error(
                format!("{path}.password"),
                "Trojan password must contain 1..4096 UTF-8 bytes",
            );
            return None;
        }
        let password = zeroize::Zeroizing::new(password.to_owned());
        if self
            .optional_string_at(server, "flow", format!("{path}.flow"))
            .is_some_and(|v| !v.is_empty())
        {
            self.error(format!("{path}.flow"), "Trojan flow is unsupported");
        }
        self.optional_string_at(server, "email", format!("{path}.email"));
        let level = self
            .optional_u32_at(server, "level", format!("{path}.level"))
            .unwrap_or_default();
        if level > 255 {
            self.error(format!("{path}.level"), "Trojan level must be 0..255");
        }
        Some(TrojanOutboundSettings {
            server: address,
            port,
            password,
            level,
        })
    }

    pub(super) fn validate_trojan_stream(
        &mut self,
        settings: &OutboundSettings,
        stream: &StreamSettings,
        index: usize,
    ) {
        let OutboundSettings::Trojan(settings) = settings else {
            return;
        };
        if stream.security == StreamSecurity::None
            && !settings.server.is_xray_plaintext_server_exempt()
        {
            self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                "Trojan requires TLS or REALITY for a public server",
            );
        }
        if let StreamTransport::Xhttp(xhttp) = &stream.transport {
            if let Some(download) = &xhttp.download {
                if download.stream.security == StreamSecurity::None
                    && !download.address.is_xray_plaintext_server_exempt()
                {
                    self.error(
                        format!(
                            "$.outbounds[{index}].streamSettings.xhttpSettings.downloadSettings"
                        ),
                        "Trojan requires a protected public download",
                    );
                }
            }
        }
    }
}
