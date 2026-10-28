use super::*;
use crate::HttpOutboundSettings;
use xray_proxy::outbound::{HttpAccount, MAX_HTTP_CREDENTIAL_LENGTH};

/// Settings keys of the flattened server form; `headers` belongs to both.
const FLAT_SERVER_FIELDS: [&str; 6] = ["address", "port", "user", "pass", "level", "email"];

impl Parser<'_> {
    pub(super) fn parse_http_outbound_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<HttpOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|v| v.is_object()) else {
            self.error(path, "HTTP outbound settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::HTTP_OUTBOUND);
        self.reject_http_outbound_headers(settings, &path);
        let Some(servers) = settings.get("servers") else {
            return self.parse_http_outbound_server(settings, settings, &path, &path);
        };
        if FLAT_SERVER_FIELDS
            .iter()
            .any(|key| settings.get(*key).is_some())
        {
            self.error(
                path,
                "HTTP outbound flattened settings and servers cannot be combined",
            );
            return None;
        }
        let Some(servers) = servers.as_array().filter(|a| a.len() == 1) else {
            self.error(
                format!("{path}.servers"),
                "HTTP outbound requires exactly one server",
            );
            return None;
        };
        let path = format!("{path}.servers[0]");
        let server = &servers[0];
        if !server.is_object() {
            self.error(path, "HTTP outbound server must be an object");
            return None;
        }
        self.reject_unknown_fields(server, &path, &surface::HTTP_OUTBOUND_SERVER);
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
                    "HTTP outbound users must be an array with at most one user",
                );
                return None;
            }
        };
        let Some(user) = users.first() else {
            return self.parse_http_outbound_server(server, &Value::Null, &path, &path);
        };
        let user_path = format!("{users_path}[0]");
        if !user.is_object() {
            self.error(user_path, "HTTP outbound user must be an object");
            return None;
        }
        self.reject_unknown_fields(user, &user_path, &surface::HTTP_OUTBOUND_USER);
        if user.get("user").is_none() {
            self.error(
                user_path,
                "HTTP outbound user requires `user`; omit `users` for no authentication",
            );
            return None;
        }
        self.parse_http_outbound_server(server, user, &path, &user_path)
    }

    /// Xray sends custom headers, expanded as Go templates, with every
    /// CONNECT. That is not implemented, so any header fails instead of
    /// being dropped; `null` and `{}` configure none and are accepted.
    fn reject_http_outbound_headers(&mut self, settings: &Value, path: &str) {
        match settings.get("headers") {
            None | Some(Value::Null) => {}
            Some(Value::Object(headers)) if headers.is_empty() => {}
            Some(Value::Object(_)) => self.error(
                format!("{path}.headers"),
                "HTTP outbound custom `headers` are unsupported",
            ),
            Some(_) => self.error(
                format!("{path}.headers"),
                "field `headers` must be an object",
            ),
        }
    }

    /// Parses the endpoint from `server` and the credentials, level and email
    /// from `user`; both are the settings object in the flattened form.
    fn parse_http_outbound_server(
        &mut self,
        server: &Value,
        user: &Value,
        path: &str,
        user_path: &str,
    ) -> Option<HttpOutboundSettings> {
        let Some(address) = self.string_at(server, "address") else {
            self.error(
                format!("{path}.address"),
                "HTTP outbound requires a server address",
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
                "invalid HTTP outbound server address",
            );
            return None;
        }
        let address = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip);
        let port = self.u16_at(server, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(format!("{path}.port"), "HTTP outbound port must be nonzero");
        }
        let account = self.parse_http_outbound_account(user, user_path)?;
        self.optional_string_at(user, "email", format!("{user_path}.email"));
        let level = self
            .optional_u32_at(user, "level", format!("{user_path}.level"))
            .unwrap_or_default();
        if level > 255 {
            self.error(
                format!("{user_path}.level"),
                "HTTP outbound level must be 0..255",
            );
        }
        Some(HttpOutboundSettings {
            server: address,
            port,
            account,
            level,
        })
    }

    /// `Some(None)` means no authentication; `None` means an error was
    /// reported. A `pass` needs a `user`, while a missing `pass` is the empty
    /// password RFC 7617 allows. Messages never echo a credential value.
    fn parse_http_outbound_account(
        &mut self,
        user: &Value,
        path: &str,
    ) -> Option<Option<HttpAccount>> {
        let user_name = self.http_outbound_credential(user, "user", path);
        let pass = self.http_outbound_credential(user, "pass", path);
        let (user_name, pass) = (user_name?, pass?);
        let Some(user_name) = user_name else {
            if pass.is_some() {
                self.error(
                    format!("{path}.pass"),
                    "HTTP outbound `pass` requires `user`",
                );
                return None;
            }
            return Some(None);
        };
        // Length and control characters are already checked, so only an
        // empty `user` or one containing `:` is left to fail here.
        let account = HttpAccount::new(user_name, pass.unwrap_or_default());
        if account.is_none() {
            self.error(
                format!("{path}.user"),
                "HTTP outbound `user` must be nonempty and must not contain `:`",
            );
        }
        account.map(Some)
    }

    /// `Some(None)` means the key is absent; `None` means an error was reported.
    fn http_outbound_credential<'a>(
        &mut self,
        user: &'a Value,
        key: &str,
        path: &str,
    ) -> Option<Option<&'a str>> {
        let path = format!("{path}.{key}");
        match user.get(key) {
            None => Some(None),
            Some(Value::String(value))
                if value.len() <= MAX_HTTP_CREDENTIAL_LENGTH
                    && !value.chars().any(char::is_control) =>
            {
                Some(Some(value))
            }
            Some(Value::String(_)) => {
                self.error(
                    path,
                    format!(
                        "HTTP outbound `{key}` must contain at most {MAX_HTTP_CREDENTIAL_LENGTH} bytes without control characters"
                    ),
                );
                None
            }
            Some(_) => {
                self.error(path, format!("field `{key}` must be a string"));
                None
            }
        }
    }

    /// Only HTTP/1.1 over raw/tcp with none or TLS is implemented, so TLS
    /// must not offer another application protocol.
    pub(super) fn validate_http_outbound_stream(
        &mut self,
        settings: &OutboundSettings,
        stream: &StreamSettings,
        index: usize,
    ) {
        if !matches!(settings, OutboundSettings::Http(_)) {
            return;
        }
        let path = format!("$.outbounds[{index}].streamSettings");
        if stream.transport != StreamTransport::Raw {
            self.error(
                format!("{path}.network"),
                "HTTP outbound supports only the raw (tcp) network",
            );
        }
        match &stream.security {
            StreamSecurity::None => {}
            StreamSecurity::Tls(tls) => {
                if tls.alpn.len() > 1 || tls.alpn.iter().any(|p| p != "http/1.1") {
                    self.error(
                        format!("{path}.tlsSettings.alpn"),
                        "HTTP outbound supports only the `http/1.1` ALPN; HTTP/2 CONNECT is unsupported",
                    );
                }
            }
            StreamSecurity::Reality(_) => self.error(
                format!("{path}.security"),
                "HTTP outbound supports only none or TLS security",
            ),
        }
    }
}
