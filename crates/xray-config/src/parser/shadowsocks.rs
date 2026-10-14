use super::*;
use crate::Shadowsocks2022OutboundSettings;

impl Parser<'_> {
    pub(super) fn parse_shadowsocks_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<Shadowsocks2022OutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|v| v.is_object()) else {
            self.error(path, "Shadowsocks2022 settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::SHADOWSOCKS);
        let (server, path) = if let Some(servers) = settings.get("servers") {
            if surface::SHADOWSOCKS_SERVER
                .fields
                .iter()
                .any(|key| settings.get(*key).is_some())
            {
                self.error(
                    path,
                    "Shadowsocks2022 flattened settings and servers cannot be combined",
                );
                return None;
            }
            let Some(servers) = servers.as_array().filter(|a| a.len() == 1) else {
                self.error(
                    format!("{path}.servers"),
                    "Shadowsocks2022 requires exactly one server",
                );
                return None;
            };
            let path = format!("{path}.servers[0]");
            if !servers[0].is_object() {
                self.error(path, "Shadowsocks2022 server must be an object");
                return None;
            }
            self.reject_unknown_fields(&servers[0], &path, &surface::SHADOWSOCKS_SERVER);
            (&servers[0], path)
        } else {
            (settings, path)
        };
        let Some(address) = self.string_at(server, "address") else {
            self.error(
                format!("{path}.address"),
                "Shadowsocks2022 requires a server address",
            );
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty()
            || address.len() > 255
            || address.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            self.error(
                format!("{path}.address"),
                "invalid Shadowsocks2022 server address",
            );
            return None;
        }
        let address = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip);
        let port = self.u16_at(server, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(
                format!("{path}.port"),
                "Shadowsocks2022 port must be nonzero",
            );
        }
        let Some(password) = self.string_at(server, "password") else {
            self.error(
                format!("{path}.password"),
                "Shadowsocks2022 requires a password",
            );
            return None;
        };
        let Some(method) = self.string_at(server, "method") else {
            self.error(
                format!("{path}.method"),
                "Shadowsocks 2022 requires a method",
            );
            return None;
        };
        if let Err(error) = xray_proxy::shadowsocks2022::Method::new(method, password) {
            self.error(format!("{path}.password"), error.to_string());
            return None;
        }
        let password = zeroize::Zeroizing::new(password.to_owned());
        let method = method.to_owned();
        self.optional_string_at(server, "email", format!("{path}.email"));
        let level = self
            .optional_u32_at(server, "level", format!("{path}.level"))
            .unwrap_or_default();
        if level > 255 {
            self.error(
                format!("{path}.level"),
                "Shadowsocks2022 level must be 0..255",
            );
        }
        Some(Shadowsocks2022OutboundSettings {
            server: address,
            port,
            password,
            method,
            level,
        })
    }
}
