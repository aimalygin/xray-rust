use super::*;
use crate::SocksOutboundSettings;
use xray_proxy::inbound::{SocksAccount, MAX_SOCKS_CREDENTIAL_LENGTH};

impl Parser<'_> {
    pub(super) fn parse_socks_outbound_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<SocksOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|v| v.is_object()) else {
            self.error(path, "SOCKS outbound settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::SOCKS_OUTBOUND);
        let Some(servers) = settings.get("servers") else {
            return self.parse_socks_outbound_server(settings, settings, &path, &path);
        };
        // Every other settings key belongs to the flattened form.
        if surface::SOCKS_OUTBOUND
            .fields
            .iter()
            .any(|key| *key != "servers" && settings.get(*key).is_some())
        {
            self.error(
                path,
                "SOCKS outbound flattened settings and servers cannot be combined",
            );
            return None;
        }
        let Some(servers) = servers.as_array().filter(|a| a.len() == 1) else {
            self.error(
                format!("{path}.servers"),
                "SOCKS outbound requires exactly one server",
            );
            return None;
        };
        let path = format!("{path}.servers[0]");
        let server = &servers[0];
        if !server.is_object() {
            self.error(path, "SOCKS outbound server must be an object");
            return None;
        }
        self.reject_unknown_fields(server, &path, &surface::SOCKS_OUTBOUND_SERVER);
        let users_path = format!("{path}.users");
        let users = match server
            .get("users")
            .map(|users| users.as_array().filter(|a| a.len() <= 1))
        {
            None => &[][..],
            Some(Some(users)) => users.as_slice(),
            Some(None) => {
                self.error(
                    users_path,
                    "SOCKS outbound users must be an array with at most one user",
                );
                return None;
            }
        };
        let Some(user) = users.first() else {
            return self.parse_socks_outbound_server(server, &Value::Null, &path, &path);
        };
        let user_path = format!("{users_path}[0]");
        if !user.is_object() {
            self.error(user_path, "SOCKS outbound user must be an object");
            return None;
        }
        self.reject_unknown_fields(user, &user_path, &surface::SOCKS_OUTBOUND_USER);
        if user.get("user").is_none() && user.get("pass").is_none() {
            self.error(
                user_path,
                "SOCKS outbound user requires `user` and `pass`; omit `users` for no authentication",
            );
            return None;
        }
        self.parse_socks_outbound_server(server, user, &path, &user_path)
    }

    /// Parses the endpoint from `server` and the credentials, level and email
    /// from `user`; both are the settings object in the flattened form.
    fn parse_socks_outbound_server(
        &mut self,
        server: &Value,
        user: &Value,
        path: &str,
        user_path: &str,
    ) -> Option<SocksOutboundSettings> {
        let Some(address) = self.string_at(server, "address") else {
            self.error(
                format!("{path}.address"),
                "SOCKS outbound requires a server address",
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
                "invalid SOCKS outbound server address",
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
                "SOCKS outbound port must be nonzero",
            );
        }
        let account = self.parse_socks_outbound_account(user, user_path)?;
        self.optional_string_at(user, "email", format!("{user_path}.email"));
        let level = self
            .optional_u32_at(user, "level", format!("{user_path}.level"))
            .unwrap_or_default();
        if level > 255 {
            self.error(
                format!("{user_path}.level"),
                "SOCKS outbound level must be 0..255",
            );
        }
        Some(SocksOutboundSettings {
            server: address,
            port,
            account,
            level,
        })
    }

    /// `Some(None)` means no authentication; `None` means an error was
    /// reported. Messages name the field and never echo a credential value.
    fn parse_socks_outbound_account(
        &mut self,
        user: &Value,
        path: &str,
    ) -> Option<Option<SocksAccount>> {
        let user_name = self.socks_outbound_credential(user, "user", path);
        let pass = self.socks_outbound_credential(user, "pass", path);
        match (user_name?, pass?) {
            (None, None) => Some(None),
            (Some(user_name), Some(pass)) => {
                let account = SocksAccount::new(user_name.as_bytes(), pass.as_bytes());
                if account.is_none() {
                    self.error(
                        path,
                        "SOCKS outbound `user` and `pass` must each contain 1..255 bytes",
                    );
                }
                account.map(Some)
            }
            (user_name, _) => {
                let missing = if user_name.is_some() { "pass" } else { "user" };
                self.error(
                    format!("{path}.{missing}"),
                    "SOCKS outbound credentials require both `user` and `pass`",
                );
                None
            }
        }
    }

    /// `Some(None)` means the key is absent; `None` means an error was reported.
    fn socks_outbound_credential<'a>(
        &mut self,
        user: &'a Value,
        key: &str,
        path: &str,
    ) -> Option<Option<&'a str>> {
        let path = format!("{path}.{key}");
        match user.get(key) {
            None => Some(None),
            Some(Value::String(value))
                if (1..=MAX_SOCKS_CREDENTIAL_LENGTH).contains(&value.len()) =>
            {
                Some(Some(value))
            }
            Some(Value::String(_)) => {
                self.error(
                    path,
                    format!("SOCKS outbound `{key}` must contain 1..255 UTF-8 bytes"),
                );
                None
            }
            Some(_) => {
                self.error(path, format!("field `{key}` must be a string"));
                None
            }
        }
    }

    pub(super) fn validate_socks_outbound_stream(
        &mut self,
        settings: &OutboundSettings,
        stream: &StreamSettings,
        index: usize,
    ) {
        if !matches!(settings, OutboundSettings::Socks(_)) {
            return;
        }
        let path = format!("$.outbounds[{index}].streamSettings");
        if stream.transport != StreamTransport::Raw {
            self.error(
                format!("{path}.network"),
                "SOCKS outbound supports only the raw (tcp) network",
            );
        }
        if matches!(stream.security, StreamSecurity::Reality(_)) {
            self.error(
                format!("{path}.security"),
                "SOCKS outbound supports only none or TLS security",
            );
        }
    }
}
