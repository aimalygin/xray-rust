use super::{normalize_xray_address_text, Parser};
use crate::surface;
use crate::{TargetAddr, VlessOutboundSettings, VlessUser};
use serde_json::Value;
use std::net::IpAddr;
use uuid::Uuid;

impl Parser<'_> {
    pub(super) fn parse_vless_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<VlessOutboundSettings> {
        let settings_path = format!("$.outbounds[{index}].settings");
        if let Some(settings) = outbound.get("settings") {
            self.reject_unknown_fields(settings, &settings_path, &surface::VLESS);
        }

        let vnext_array_path = format!("$.outbounds[{index}].settings.vnext");
        let Some(vnext_array) = outbound
            .get("settings")
            .and_then(|settings| settings.get("vnext"))
            .and_then(Value::as_array)
        else {
            self.error(vnext_array_path, "missing vless vnext servers");
            return None;
        };
        if vnext_array.len() > 1 {
            self.error(
                vnext_array_path,
                "multiple vless vnext servers are unsupported",
            );
            return None;
        }

        let vnext_path = format!("$.outbounds[{index}].settings.vnext[0]");
        let Some(vnext) = vnext_array.first() else {
            self.error(vnext_path, "missing vless vnext server");
            return None;
        };
        self.reject_unknown_fields(vnext, &vnext_path, &surface::VLESS_SERVER);

        let address_path = format!("$.outbounds[{index}].settings.vnext[0].address");
        let Some(address) = self.string_at(vnext, "address") else {
            self.error(address_path, "missing vless server address");
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty() {
            self.error(address_path, "vless server address must not be empty");
            return None;
        }
        let server = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.to_owned()), TargetAddr::Ip);

        let port_path = format!("$.outbounds[{index}].settings.vnext[0].port");
        let port = self.u16_at(vnext, "port", port_path.clone())?;
        if port == 0 {
            self.error(port_path, "vless server port must not be 0");
            return None;
        }

        let users = self.parse_vless_users(vnext, index)?;

        Some(VlessOutboundSettings {
            server,
            port,
            users,
        })
    }

    fn parse_vless_users(
        &mut self,
        vnext: &Value,
        outbound_index: usize,
    ) -> Option<Vec<VlessUser>> {
        let users_path = format!("$.outbounds[{outbound_index}].settings.vnext[0].users");
        let Some(users) = vnext.get("users").and_then(Value::as_array) else {
            self.error(users_path, "vless users must be a non-empty array");
            return None;
        };
        if users.is_empty() {
            self.error(users_path, "vless users must be a non-empty array");
            return None;
        }

        let parsed_users = users
            .iter()
            .enumerate()
            .filter_map(|(user_index, user)| {
                self.parse_vless_user(user, outbound_index, user_index)
            })
            .collect::<Vec<_>>();

        if parsed_users.is_empty() {
            None
        } else {
            Some(parsed_users)
        }
    }

    fn parse_vless_user(
        &mut self,
        user: &Value,
        outbound_index: usize,
        user_index: usize,
    ) -> Option<VlessUser> {
        let id_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].id");
        let user_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}]");
        self.reject_unknown_fields(user, &user_path, &surface::VLESS_USER);

        let Some(id) = self.string_at(user, "id") else {
            self.error(id_path, "missing vless user id");
            return None;
        };
        let id = match Uuid::parse_str(id) {
            Ok(id) => id,
            Err(err) => {
                self.error(id_path, err.to_string());
                return None;
            }
        };

        let encryption_path = format!(
            "$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].encryption"
        );
        let encryption = match user.get("encryption") {
            None => crate::VlessEncryption::None,
            Some(Value::String(value)) => match value.parse() {
                Ok(encryption) => encryption,
                Err(error) => {
                    self.error(encryption_path, format!("{error}"));
                    return None;
                }
            },
            Some(_) => {
                self.error(encryption_path, "vless user encryption must be a string");
                return None;
            }
        };

        let flow_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].flow");
        let flow = match self.string_at(user, "flow") {
            Some("") | None => None,
            Some("xtls-rprx-vision") => Some("xtls-rprx-vision".to_owned()),
            Some("xtls-rprx-vision-udp443") => Some("xtls-rprx-vision-udp443".to_owned()),
            Some(flow) => {
                self.error(flow_path, format!("unsupported vless user flow `{flow}`"));
                return None;
            }
        };

        self.optional_string_at(user, "security", format!("{user_path}.security"));
        let level = self
            .optional_u32_at(user, "level", format!("{user_path}.level"))
            .unwrap_or_default();

        Some(VlessUser {
            id,
            encryption,
            flow,
            level,
        })
    }
}
