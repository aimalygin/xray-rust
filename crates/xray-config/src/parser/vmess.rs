use super::*;
use crate::VmessOutboundSettings;
impl Parser<'_> {
    pub(super) fn parse_vmess_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<VmessOutboundSettings> {
        let root = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|v| v.is_object()) else {
            self.error(root, "VMess settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &root, &surface::VMESS);
        let (server, user, path, user_path) = if let Some(vnext) = settings.get("vnext") {
            if surface::VMESS
                .fields
                .iter()
                .filter(|&&k| k != "vnext")
                .any(|k| settings.get(*k).is_some())
            {
                self.error(
                    root,
                    "VMess flattened settings and vnext cannot be combined",
                );
                return None;
            }
            let Some(servers) = vnext.as_array().filter(|v| v.len() == 1) else {
                self.error(format!("{root}.vnext"), "VMess requires exactly one server");
                return None;
            };
            let path = format!("{root}.vnext[0]");
            if !servers[0].is_object() {
                self.error(path, "VMess server must be an object");
                return None;
            }
            self.reject_unknown_fields(&servers[0], &path, &surface::VMESS_SERVER);
            let Some(users) = servers[0]
                .get("users")
                .and_then(Value::as_array)
                .filter(|v| v.len() == 1)
            else {
                self.error(format!("{path}.users"), "VMess requires exactly one user");
                return None;
            };
            let user_path = format!("{path}.users[0]");
            if !users[0].is_object() {
                self.error(user_path, "VMess user must be an object");
                return None;
            }
            self.reject_unknown_fields(&users[0], &user_path, &surface::VMESS_USER);
            (&servers[0], &users[0], path, user_path)
        } else {
            (settings, settings, root.clone(), root)
        };
        let Some(address) = self.string_at(server, "address") else {
            self.error(format!("{path}.address"), "VMess requires an address");
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty()
            || address.len() > 255
            || address.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            self.error(format!("{path}.address"), "invalid VMess address");
            return None;
        }
        let server_address = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip);
        let port = self.u16_at(server, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(format!("{path}.port"), "VMess port must be nonzero");
        }
        let Some(id) = self
            .string_at(user, "id")
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
        else {
            self.error(format!("{user_path}.id"), "VMess requires a UUID");
            return None;
        };
        let user_id = zeroize::Zeroizing::new(*id.as_bytes());
        if self
            .optional_u32_at(user, "alterId", format!("{user_path}.alterId"))
            .is_some_and(|n| n != 0)
        {
            self.error(
                format!("{user_path}.alterId"),
                "legacy VMess alterId is unsupported",
            );
        }
        let security = self
            .optional_string_at(user, "security", format!("{user_path}.security"))
            .unwrap_or("auto")
            .to_lowercase();
        if xray_proxy::vmess::Cipher::parse(&security).is_err() {
            self.error(
                format!("{user_path}.security"),
                "unsupported VMess AEAD security",
            );
        }
        let mut options = xray_proxy::vmess::Options::default();
        if let Some(experiments) =
            self.optional_string_at(user, "experiments", format!("{user_path}.experiments"))
        {
            for option in experiments.split('|').filter(|v| !v.is_empty()) {
                match option {
                    "AuthenticatedLength" if !options.authenticated_length => {
                        options.authenticated_length = true
                    }
                    "NoTerminationSignal" if !options.no_termination_signal => {
                        options.no_termination_signal = true
                    }
                    _ => {
                        self.error(
                            format!("{user_path}.experiments"),
                            "unsupported or duplicate VMess experiment",
                        );
                        break;
                    }
                }
            }
        }
        let level = self
            .optional_u32_at(user, "level", format!("{user_path}.level"))
            .unwrap_or_default();
        self.optional_string_at(user, "email", format!("{user_path}.email"));
        Some(VmessOutboundSettings {
            server: server_address,
            port,
            user_id,
            security,
            options,
            level,
        })
    }
}
