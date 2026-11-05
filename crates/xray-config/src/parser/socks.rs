use super::*;
use crate::SocksInboundSettings;
use xray_proxy::inbound::{SocksAccount, SocksInboundAuth, MAX_SOCKS_CREDENTIAL_LENGTH};

/// Bounds the per-handshake account scan; RFC 1929 has no limit of its own.
const MAX_SOCKS_ACCOUNTS: usize = 64;

impl Parser<'_> {
    /// Absent or `null` settings, as Xray-core reads them, are the defaults.
    pub(super) fn parse_socks_inbound_settings(
        &mut self,
        inbound: &Value,
        index: usize,
    ) -> SocksInboundSettings {
        let Some(settings) = inbound.get("settings").filter(|value| value.is_object()) else {
            return SocksInboundSettings::default();
        };
        let path = format!("$.inbounds[{index}].settings");
        SocksInboundSettings {
            auth: self.parse_socks_inbound_auth(settings, &path),
            // Xray-core reads an absent or `null` `udp` as false; keeping it
            // enabled preserves this runtime's earlier behavior until that is
            // decided.
            udp: match settings.get("udp") {
                None | Some(Value::Null) => true,
                Some(_) => self
                    .optional_bool_at(settings, "udp", format!("{path}.udp"))
                    .unwrap_or(true),
            },
        }
    }

    /// `auth` and the accounts, as Xray-core v26.10.31 reads them: `accounts`
    /// replaces `users` unless it is absent or `null`, though both must parse.
    /// Unlike Xray-core, which takes any other `auth` for `noauth` and then
    /// ignores the accounts, both are refused, so a typo cannot leave the
    /// inbound open.
    fn parse_socks_inbound_auth(&mut self, settings: &Value, path: &str) -> SocksInboundAuth {
        let accounts_given = settings
            .get("accounts")
            .is_some_and(|value| !value.is_null());
        let accounts = self.parse_socks_accounts(settings, "accounts", path, accounts_given);
        let users = self.parse_socks_accounts(settings, "users", path, !accounts_given);
        let users_given = settings.get("users").is_some_and(|value| !value.is_null());
        let key = if !accounts_given && users_given {
            "users"
        } else {
            "accounts"
        };
        let used = accounts.or(users);
        let auth = self
            .nullable_string_at(settings, "auth", format!("{path}.auth"))
            .unwrap_or_default();
        match auth {
            "" | "noauth" => {
                if used.is_some_and(|accounts| !accounts.is_empty()) {
                    self.error(
                        format!("{path}.{key}"),
                        format!("socks {key} require `auth: \"password\"`; with noauth they would be ignored"),
                    );
                }
                SocksInboundAuth::NoAuth
            }
            "password" => match used {
                Some(accounts) if !accounts.is_empty() => SocksInboundAuth::Password(accounts),
                _ => {
                    self.error(
                        format!("{path}.{key}"),
                        format!("socks password auth requires 1..{MAX_SOCKS_ACCOUNTS} accounts"),
                    );
                    SocksInboundAuth::NoAuth
                }
            },
            other => {
                self.error(
                    format!("{path}.auth"),
                    format!("unsupported socks auth `{other}`"),
                );
                SocksInboundAuth::NoAuth
            }
        }
    }

    /// One list of accounts: `None` when it is absent or `null`. Each entry is
    /// an object of a `user` and a `pass`, absent or `null` reading as empty,
    /// and a later account replaces an earlier one of the same name, as in
    /// Xray-core's map. Go reads a `null` entry as no account, which Xray-core
    /// panics on only in the list it `used`.
    fn parse_socks_accounts(
        &mut self,
        settings: &Value,
        key: &str,
        path: &str,
        used: bool,
    ) -> Option<Vec<SocksAccount>> {
        let path = format!("{path}.{key}");
        let entries = match settings.get(key)? {
            Value::Null => return None,
            Value::Array(entries) => entries,
            _ => {
                self.error(path, format!("field `{key}` must be an array of accounts"));
                return None;
            }
        };
        if entries.len() > MAX_SOCKS_ACCOUNTS {
            self.error(
                path,
                format!("socks password auth requires 1..{MAX_SOCKS_ACCOUNTS} accounts"),
            );
            return None;
        }
        let mut accounts: Vec<SocksAccount> = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let entry_path = format!("{path}[{index}]");
            if entry.is_null() && !used {
                continue;
            }
            let Some(account) = self.parse_socks_account(entry, &entry_path) else {
                continue;
            };
            match accounts
                .iter_mut()
                .find(|known| known.user() == account.user())
            {
                Some(known) => *known = account,
                None => accounts.push(account),
            }
        }
        Some(accounts)
    }

    fn parse_socks_account(&mut self, account: &Value, path: &str) -> Option<SocksAccount> {
        // Xray-core panics on a `null` entry and refuses any other value.
        if !account.is_object() {
            self.error(path, "socks account must be an object");
            return None;
        }
        self.reject_unknown_fields(account, path, &surface::SOCKS_ACCOUNT);
        let user = self.nullable_string_at(account, "user", format!("{path}.user"));
        let pass = self.nullable_string_at(account, "pass", format!("{path}.pass"));
        let account = SocksAccount::new(user?.as_bytes(), pass?.as_bytes());
        if account.is_none() {
            self.error(
                path,
                format!(
                    "socks account `user` and `pass` hold at most {MAX_SOCKS_CREDENTIAL_LENGTH} bytes each"
                ),
            );
        }
        account
    }
}
