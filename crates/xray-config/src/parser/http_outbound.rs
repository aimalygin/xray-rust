use super::*;
use crate::HttpOutboundSettings;
use xray_proxy::inbound::canonical_header_key;
use xray_proxy::outbound::{HttpAccount, HttpHeaderTemplate, MAX_HTTP_CREDENTIAL_LENGTH};

/// Bounds a profile's custom headers; Xray-core sets no limit.
const MAX_HTTP_OUTBOUND_HEADERS: usize = 64;
const MAX_HTTP_OUTBOUND_HEADER_VALUE: usize = 8 * 1024;

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
        let headers = self.parse_http_outbound_headers(settings, &path);
        let mut parsed = self.parse_http_outbound_endpoint(settings, &path)?;
        parsed.headers = headers?;
        Some(parsed)
    }

    fn parse_http_outbound_endpoint(
        &mut self,
        settings: &Value,
        path: &str,
    ) -> Option<HttpOutboundSettings> {
        let path = path.to_owned();
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

    /// `headers`, which Xray-core sets on each `CONNECT` after the
    /// credentials with Go's `Header.Set`, so a name is canonicalized and a
    /// later one that canonicalizes alike replaces an earlier one. A `null`
    /// value is empty. Each value is a Go template naming the connection's
    /// `Source` and `Target`, read as [`HttpHeaderTemplate`] reads it.
    ///
    /// Unlike Xray-core, an invalid name, which Go would drop when writing,
    /// a control character other than a tab or line break, which Go would
    /// write as it is, and a template action other than those fields are
    /// refused here, as are more than 64 headers or a value over 8 KiB.
    fn parse_http_outbound_headers(
        &mut self,
        settings: &Value,
        path: &str,
    ) -> Option<Vec<(String, HttpHeaderTemplate)>> {
        let path = format!("{path}.headers");
        let entries = match settings.get("headers") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Object(entries)) => entries,
            Some(_) => {
                self.error(path, "field `headers` must be an object");
                return None;
            }
        };
        if entries.len() > MAX_HTTP_OUTBOUND_HEADERS {
            self.error(
                path,
                format!("an HTTP outbound takes at most {MAX_HTTP_OUTBOUND_HEADERS} headers"),
            );
            return None;
        }
        let mut headers: Vec<(String, HttpHeaderTemplate)> = Vec::new();
        let mut valid = true;
        for (name, value) in entries {
            let header_path = format!("{path}.{name}");
            let text = match value {
                Value::Null => "",
                Value::String(text) => text,
                _ => {
                    self.error(header_path, "a header value must be a string or null");
                    valid = false;
                    continue;
                }
            };
            let token =
                |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
            if name.is_empty() || !name.bytes().all(token) {
                self.error(header_path, "a header name must be an HTTP token");
                valid = false;
                continue;
            }
            if text.len() > MAX_HTTP_OUTBOUND_HEADER_VALUE
                || text
                    .bytes()
                    .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\t' | b'\r' | b'\n'))
            {
                self.error(
                    header_path,
                    format!(
                        "a header value holds at most {MAX_HTTP_OUTBOUND_HEADER_VALUE} bytes and no control characters but tabs and line breaks"
                    ),
                );
                valid = false;
                continue;
            }
            let template = match HttpHeaderTemplate::parse(text) {
                Ok(template) => template,
                Err(why) => {
                    self.error(header_path, format!("invalid header template: {why}"));
                    valid = false;
                    continue;
                }
            };
            let name = canonical_header_key(name).into_owned();
            match headers.iter_mut().find(|(known, _)| *known == name) {
                Some(known) => known.1 = template,
                None => headers.push((name, template)),
            }
        }
        valid.then_some(headers)
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
            headers: Vec::new(),
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
}
