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
            self.error(path, "Shadowsocks settings must be an object");
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
                    "Shadowsocks flattened settings and servers cannot be combined",
                );
                return None;
            }
            let Some(servers) = servers.as_array().filter(|a| a.len() == 1) else {
                self.error(
                    format!("{path}.servers"),
                    "Shadowsocks requires exactly one server",
                );
                return None;
            };
            let path = format!("{path}.servers[0]");
            if !servers[0].is_object() {
                self.error(path, "Shadowsocks server must be an object");
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
                "Shadowsocks requires a server address",
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
                "invalid Shadowsocks server address",
            );
            return None;
        }
        let address = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip);
        let port = self.u16_at(server, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(format!("{path}.port"), "Shadowsocks port must be nonzero");
        }
        let Some(password) = self.string_at(server, "password") else {
            self.error(
                format!("{path}.password"),
                "Shadowsocks requires a password",
            );
            return None;
        };
        let Some(method) = self.string_at(server, "method") else {
            self.error(format!("{path}.method"), "Shadowsocks requires a method");
            return None;
        };
        // Xray-core lowercases the method for both families. Name the method
        // before judging the password so the diagnostic points at the cause.
        let lower = method.to_lowercase();
        if xray_proxy::shadowsocks::aead2017::Cipher::parse(&lower).is_none()
            && xray_proxy::shadowsocks2022::Cipher::parse(&lower).is_err()
        {
            self.error(
                format!("{path}.method"),
                "unsupported Shadowsocks method; use 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305, aes-128-gcm, aes-256-gcm, chacha20-poly1305 or xchacha20-poly1305 (or their Xray aliases)",
            );
            return None;
        }
        if let Err(error) = xray_proxy::shadowsocks::Method::new(method, password) {
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
            self.error(format!("{path}.level"), "Shadowsocks level must be 0..255");
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
