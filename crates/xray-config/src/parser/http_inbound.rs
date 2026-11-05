use super::*;
use crate::HttpInboundSettings;
use xray_proxy::inbound::HttpInboundAccounts;

/// Bounds the per-request account scan, as for SOCKS; Xray-core has no limit.
const MAX_HTTP_ACCOUNTS: usize = 64;

impl Parser<'_> {
    /// `accounts` or `users`, as Xray-core v26.10.31 reads them: `accounts`
    /// replaces `users` unless it is absent or `null`, though both must parse.
    pub(super) fn parse_http_inbound_settings(
        &mut self,
        inbound: &Value,
        index: usize,
    ) -> HttpInboundSettings {
        let Some(settings) = inbound.get("settings").filter(|value| value.is_object()) else {
            return HttpInboundSettings::default();
        };
        let path = format!("$.inbounds[{index}].settings");
        let accounts = self.parse_http_accounts(settings, "accounts", &path);
        let users = self.parse_http_accounts(settings, "users", &path);
        HttpInboundSettings {
            accounts: accounts.or(users).unwrap_or_default(),
        }
    }

    /// One list of accounts: `None` when it is absent or `null`. Each entry is
    /// an object of a `user` and a `pass`, absent or `null` reading as empty,
    /// and a later account replaces an earlier one of the same name.
    fn parse_http_accounts(
        &mut self,
        settings: &Value,
        key: &str,
        path: &str,
    ) -> Option<HttpInboundAccounts> {
        let path = format!("{path}.{key}");
        let entries = match settings.get(key)? {
            Value::Null => return None,
            Value::Array(entries) => entries,
            _ => {
                self.error(path, format!("field `{key}` must be an array of accounts"));
                return None;
            }
        };
        if entries.len() > MAX_HTTP_ACCOUNTS {
            self.error(
                path,
                format!("an HTTP inbound takes at most {MAX_HTTP_ACCOUNTS} accounts"),
            );
            return None;
        }
        let mut accounts = HttpInboundAccounts::default();
        for (index, entry) in entries.iter().enumerate() {
            let entry_path = format!("{path}[{index}]");
            // Xray-core panics on a `null` entry and refuses any other value.
            if !entry.is_object() {
                self.error(entry_path, "an HTTP account must be an object");
                continue;
            }
            self.reject_unknown_fields(entry, &entry_path, &surface::HTTP_ACCOUNT);
            let user = self.nullable_string_at(entry, "user", format!("{entry_path}.user"));
            let pass = self.nullable_string_at(entry, "pass", format!("{entry_path}.pass"));
            if let (Some(user), Some(pass)) = (user, pass) {
                accounts.insert(user.as_bytes(), pass.as_bytes());
            }
        }
        Some(accounts)
    }
}
