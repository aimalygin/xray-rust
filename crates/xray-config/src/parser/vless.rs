use super::{normalize_xray_address_text, Parser};
use crate::surface;
use crate::{TargetAddr, VlessOutboundSettings, VlessUser};
use serde_json::Value;
use std::net::IpAddr;
use xray_proxy::vless::DEFAULT_VISION_SEED;

/// Where the server and its users are: Xray-core's simplified form, with
/// both in `settings`, or its one `vnext` entry.
enum VlessForm<'a> {
    Flattened(&'a Value),
    Vnext {
        server: &'a Value,
        users: &'a [Value],
    },
}

/// The most `testpre` connections one VLESS outbound keeps open.
const MAX_PRE_CONNECTIONS: u32 = 64;

impl Parser<'_> {
    /// Reads VLESS outbound settings as Xray-core v26.10.31's
    /// `VLessOutboundConfig.Build` reads them.
    pub(super) fn parse_vless_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<VlessOutboundSettings> {
        let settings_path = format!("$.outbounds[{index}].settings");
        let settings = outbound
            .get("settings")
            .filter(|settings| !settings.is_null());
        if let Some(settings) = settings {
            if !settings.is_object() {
                self.error(settings_path, "VLESS settings must be an object");
                return None;
            }
            self.reject_unknown_fields(settings, &settings_path, &surface::VLESS);
        }
        let empty = Value::Object(Default::default());
        let settings = settings.unwrap_or(&empty);
        // Every field decodes, whichever form is read.
        let flat = self.check_vless_flattened_types(settings, &settings_path);
        let vnext = self.check_vless_vnext_types(settings, &settings_path);
        let (form, server_path, user_path) = match settings.get("address") {
            // A non-null address puts the server and its user in `settings`,
            // and `vnext` is not read.
            Some(address) if !address.is_null() => (
                VlessForm::Flattened(settings),
                settings_path.clone(),
                settings_path.clone(),
            ),
            _ => {
                let vnext_path = format!("{settings_path}.vnext");
                let servers = settings
                    .get("vnext")
                    .and_then(Value::as_array)
                    .map_or(&[][..], Vec::as_slice);
                let [server] = servers else {
                    self.error(
                        vnext_path,
                        "VLESS settings: \"vnext\" should have one and only one member",
                    );
                    return None;
                };
                let server_path = format!("{vnext_path}[0]");
                let users = server
                    .get("users")
                    .and_then(Value::as_array)
                    .map_or(&[][..], Vec::as_slice);
                // Xray-core wants exactly one user; the first of several is
                // used here, the others only checked.
                if users.is_empty() {
                    self.error(
                        format!("{server_path}.users"),
                        "vless users must be a non-empty array",
                    );
                    return None;
                }
                let user_path = format!("{server_path}.users");
                (VlessForm::Vnext { server, users }, server_path, user_path)
            }
        };
        flat?;
        vnext?;

        let server_value = match form {
            VlessForm::Flattened(settings) => settings,
            VlessForm::Vnext { server, .. } => server,
        };
        let server = self.vless_server_address(server_value, &server_path)?;
        let port_path = format!("{server_path}.port");
        let port = self.u16_at(server_value, "port", port_path.clone())?;
        if port == 0 {
            self.error(port_path, "vless server port must not be 0");
            return None;
        }
        let users = match form {
            VlessForm::Flattened(settings) => {
                vec![self.parse_vless_user(settings, &user_path, true)?]
            }
            VlessForm::Vnext { users, .. } => {
                let parsed: Vec<_> = users
                    .iter()
                    .enumerate()
                    .filter_map(|(index, user)| {
                        self.parse_vless_user(user, &format!("{user_path}[{index}]"), false)
                    })
                    .collect();
                if parsed.len() != users.len() {
                    return None;
                }
                parsed
            }
        };
        Some(VlessOutboundSettings {
            server,
            port,
            users,
        })
    }

    fn vless_server_address(&mut self, server: &Value, server_path: &str) -> Option<TargetAddr> {
        let address_path = format!("{server_path}.address");
        let Some(address) = self.string_at(server, "address") else {
            self.error(address_path, "missing vless server address");
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty() {
            self.error(address_path, "vless server address must not be empty");
            return None;
        }
        Some(
            address
                .parse::<IpAddr>()
                .map_or_else(|_| TargetAddr::Domain(address.to_owned()), TargetAddr::Ip),
        )
    }

    /// The simplified form's fields, which decode as Go's types even when
    /// `vnext` is the form read.
    fn check_vless_flattened_types(&mut self, settings: &Value, path: &str) -> Option<()> {
        let mut valid = true;
        for key in ["email", "id", "flow", "seed", "encryption"] {
            valid &= self
                .nullable_string_at(settings, key, format!("{path}.{key}"))
                .is_some();
        }
        for key in ["level", "testpre"] {
            if settings.get(key).is_some_and(|value| !value.is_null()) {
                valid &= self
                    .optional_u32_at(settings, key, format!("{path}.{key}"))
                    .is_some();
            }
        }
        if settings.get("port").is_some_and(|value| !value.is_null())
            && settings
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .is_none()
        {
            self.error(format!("{path}.port"), "field `port` must fit in u16");
            valid = false;
        }
        if settings
            .get("address")
            .is_some_and(|address| !address.is_null() && !address.is_string())
        {
            self.error(
                format!("{path}.address"),
                "field `address` must be a string or null",
            );
            valid = false;
        }
        valid &= self.vision_seed_at(settings, path).is_some();
        if settings
            .get("reverse")
            .is_some_and(|reverse| !reverse.is_null() && !reverse.is_object())
        {
            self.error(
                format!("{path}.reverse"),
                "field `reverse` must be an object or null",
            );
            valid = false;
        }
        valid.then_some(())
    }

    /// `vnext`, which decodes as Go's `[]*VLessOutboundVnext` even when the
    /// simplified form is read.
    fn check_vless_vnext_types(&mut self, settings: &Value, path: &str) -> Option<()> {
        let vnext_path = format!("{path}.vnext");
        let servers = match settings.get("vnext") {
            None | Some(Value::Null) => return Some(()),
            Some(Value::Array(servers)) => servers,
            Some(_) => {
                self.error(vnext_path, "field `vnext` must be an array or null");
                return None;
            }
        };
        let mut valid = true;
        for (index, server) in servers.iter().enumerate() {
            let server_path = format!("{vnext_path}[{index}]");
            match server {
                Value::Null => {}
                Value::Object(_) => {
                    self.reject_unknown_fields(server, &server_path, &surface::VLESS_SERVER);
                    if server
                        .get("users")
                        .is_some_and(|users| !users.is_null() && !users.is_array())
                    {
                        self.error(
                            format!("{server_path}.users"),
                            "field `users` must be an array or null",
                        );
                        valid = false;
                    }
                }
                _ => {
                    self.error(server_path, "vnext entries must be objects");
                    valid = false;
                }
            }
        }
        valid.then_some(())
    }

    fn parse_vless_user(
        &mut self,
        user: &Value,
        user_path: &str,
        flattened: bool,
    ) -> Option<VlessUser> {
        if !flattened {
            if !user.is_object() {
                self.error(user_path, "VLESS users: invalid user");
                return None;
            }
            self.reject_unknown_fields(user, user_path, &surface::VLESS_USER);
            if user
                .get("reverse")
                .is_some_and(|reverse| !reverse.is_null())
            {
                self.error(
                    format!("{user_path}.reverse"),
                    "VLESS users: please use simplified outbound's config style to use \"reverse\"",
                );
                return None;
            }
            self.optional_string_at(user, "security", format!("{user_path}.security"));
        } else if user
            .get("reverse")
            .is_some_and(|reverse| !reverse.is_null())
        {
            self.error(
                format!("{user_path}.reverse"),
                "VLESS reverse is unsupported",
            );
            return None;
        }

        let id_path = format!("{user_path}.id");
        let id = self.nullable_string_at(user, "id", id_path.clone())?;
        let Some(id) = crate::xray_uuid::parse(id) else {
            // The id is a credential, so the message does not repeat it.
            self.error(id_path, "invalid UUID");
            return None;
        };

        let flow_path = format!("{user_path}.flow");
        let flow = match self.nullable_string_at(user, "flow", flow_path.clone())? {
            "" => None,
            "xtls-rprx-vision" => Some("xtls-rprx-vision".to_owned()),
            "xtls-rprx-vision-udp443" => Some("xtls-rprx-vision-udp443".to_owned()),
            flow => {
                self.error(
                    flow_path,
                    format!("VLESS users: \"flow\" doesn't support \"{flow}\" in this version"),
                );
                return None;
            }
        };

        // Xray-core wants `encryption` set; an absent one is `none` here, as
        // before.
        let encryption_path = format!("{user_path}.encryption");
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

        let level = match user.get("level") {
            None | Some(Value::Null) => 0,
            Some(_) => self.optional_u32_at(user, "level", format!("{user_path}.level"))?,
        };
        self.nullable_string_at(user, "email", format!("{user_path}.email"))?;
        let pre_connections = match user.get("testpre") {
            None | Some(Value::Null) => 0,
            Some(_) => self.optional_u32_at(user, "testpre", format!("{user_path}.testpre"))?,
        };
        // Xray-core starts as many dialers as the number asks for; here each
        // holds a connection open, so the number is bounded.
        if pre_connections > MAX_PRE_CONNECTIONS {
            self.error(
                format!("{user_path}.testpre"),
                format!("VLESS testpre is at most {MAX_PRE_CONNECTIONS} here"),
            );
            return None;
        }
        let vision_seed = self.vision_seed_at(user, user_path)?;

        Some(VlessUser {
            id,
            encryption,
            flow,
            level,
            vision_seed,
            pre_connections,
        })
    }

    /// `testseed`, the Vision padding parameters: the first four numbers when
    /// there are at least four, else Xray-core's defaults.
    fn vision_seed_at(&mut self, value: &Value, path: &str) -> Option<[u32; 4]> {
        let seed_path = format!("{path}.testseed");
        let numbers = match value.get("testseed") {
            None | Some(Value::Null) => return Some(DEFAULT_VISION_SEED),
            Some(Value::Array(numbers)) => numbers,
            Some(_) => {
                self.error(
                    seed_path,
                    "field `testseed` must be an array of numbers or null",
                );
                return None;
            }
        };
        let mut seed = Vec::with_capacity(numbers.len());
        for (index, number) in numbers.iter().enumerate() {
            match number
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
            {
                Some(number) => seed.push(number),
                None => {
                    self.error(
                        format!("{seed_path}[{index}]"),
                        "testseed numbers must fit in u32",
                    );
                    return None;
                }
            }
        }
        Some(match seed.as_slice() {
            [first, second, third, fourth, ..] => [*first, *second, *third, *fourth],
            _ => DEFAULT_VISION_SEED,
        })
    }
}
