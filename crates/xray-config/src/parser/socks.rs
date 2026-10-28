use super::*;
use crate::SocksInboundSettings;
use xray_proxy::inbound::{SocksAccount, SocksInboundAuth};

/// Bounds the per-handshake account scan; RFC 1929 has no limit of its own.
const MAX_SOCKS_ACCOUNTS: usize = 64;

impl Parser<'_> {
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
            // Xray-core reads an absent `udp` as false; keeping it enabled
            // preserves this runtime's earlier behavior until that is decided.
            udp: self
                .optional_bool_at(settings, "udp", format!("{path}.udp"))
                .unwrap_or(true),
        }
    }

    fn parse_socks_inbound_auth(&mut self, settings: &Value, path: &str) -> SocksInboundAuth {
        let auth = self
            .optional_string_at(settings, "auth", format!("{path}.auth"))
            .unwrap_or("noauth");
        match auth {
            "noauth" => {
                if settings
                    .get("accounts")
                    .is_some_and(|accounts| accounts.as_array().is_none_or(|a| !a.is_empty()))
                {
                    self.error(
                        format!("{path}.accounts"),
                        "socks accounts require `auth: \"password\"`; with noauth they would be ignored",
                    );
                }
                SocksInboundAuth::NoAuth
            }
            "password" => self.parse_socks_accounts(settings, path),
            other => {
                self.error(
                    format!("{path}.auth"),
                    format!("unsupported socks auth `{other}`"),
                );
                SocksInboundAuth::NoAuth
            }
        }
    }

    fn parse_socks_accounts(&mut self, settings: &Value, path: &str) -> SocksInboundAuth {
        let path = format!("{path}.accounts");
        let Some(accounts) = settings.get("accounts").and_then(Value::as_array) else {
            self.error(path, "socks password auth requires an accounts array");
            return SocksInboundAuth::NoAuth;
        };
        if accounts.is_empty() || accounts.len() > MAX_SOCKS_ACCOUNTS {
            self.error(
                path,
                format!("socks password auth requires 1..{MAX_SOCKS_ACCOUNTS} accounts"),
            );
            return SocksInboundAuth::NoAuth;
        }
        let parsed = accounts
            .iter()
            .enumerate()
            .filter_map(|(index, account)| {
                self.parse_socks_account(account, &format!("{path}[{index}]"))
            })
            .collect::<Vec<_>>();
        SocksInboundAuth::Password(parsed)
    }

    fn parse_socks_account(&mut self, account: &Value, path: &str) -> Option<SocksAccount> {
        if !account.is_object() {
            self.error(path, "socks account must be an object");
            return None;
        }
        self.reject_unknown_fields(account, path, &surface::SOCKS_ACCOUNT);
        let (Some(user), Some(pass)) = (
            self.string_at(account, "user"),
            self.string_at(account, "pass"),
        ) else {
            self.error(path, "socks account requires string `user` and `pass`");
            return None;
        };
        let account = SocksAccount::new(user.as_bytes(), pass.as_bytes());
        if account.is_none() {
            self.error(
                path,
                "socks account `user` and `pass` must each contain 1..255 bytes",
            );
        }
        account
    }
}
