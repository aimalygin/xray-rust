//! The `xmc` finalmask, as Xray-core v26.10.31's `XMC.Build` reads it.
use super::*;
use crate::{XmcMask, XmcProfile};

/// The longest password Xray-core's client can send: RSA-1024 with PKCS #1
/// v1.5 carries 117 bytes, and the server's verify token takes four.
pub(super) const MAX_XMC_PASSWORD: usize = 113;

impl Parser<'_> {
    /// `XMC`: `hostname`, `password` and `profiles`. Absent or null settings
    /// read as `{}`, which has no profiles.
    pub(super) fn parse_xmc(&mut self, settings: &Value, path: &str) -> Option<XmcMask> {
        let empty = Value::Object(Default::default());
        let settings = match settings {
            Value::Null => &empty,
            Value::Object(_) => settings,
            _ => {
                self.error(path, "xmc settings must be an object or null");
                return None;
            }
        };
        self.reject_unknown_fields(settings, path, &surface::XMC_MASK);
        let hostname = self.nullable_string_at(settings, "hostname", format!("{path}.hostname"));
        let password = self.nullable_string_at(settings, "password", format!("{path}.password"));
        let profiles = self.xmc_profiles(settings, &format!("{path}.profiles"));
        let (hostname, password, profiles) = (hostname?, password?, profiles?);
        if profiles.is_empty() {
            self.error(
                format!("{path}.profiles"),
                "minecraft profiles are required",
            );
            return None;
        }
        if password.is_empty() {
            self.error(format!("{path}.password"), "empty password");
            return None;
        }
        // Xray-core takes a longer password and then fails every login.
        if password.len() > MAX_XMC_PASSWORD {
            self.error(
                format!("{path}.password"),
                format!(
                    "an xmc password is at most {MAX_XMC_PASSWORD} bytes, which RSA-1024 carries beside the server's verify token"
                ),
            );
            return None;
        }
        Some(XmcMask {
            hostname: hostname.to_owned(),
            password: password.to_owned().into(),
            profiles,
        })
    }

    /// `profiles`: null or an array of profiles, a null entry read as an
    /// empty profile, which has no valid username.
    fn xmc_profiles(&mut self, settings: &Value, path: &str) -> Option<Vec<XmcProfile>> {
        let items = match settings.get("profiles") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(items)) => items,
            Some(_) => {
                self.error(path, "xmc profiles must be an array or null");
                return None;
            }
        };
        let empty = Value::Object(Default::default());
        let mut profiles = Vec::with_capacity(items.len());
        let mut valid = true;
        for (i, item) in items.iter().enumerate() {
            let item_path = format!("{path}[{i}]");
            let item = match item {
                Value::Null => &empty,
                Value::Object(_) => item,
                _ => {
                    self.error(item_path, "an xmc profile must be an object or null");
                    valid = false;
                    continue;
                }
            };
            match self.xmc_profile(item, &item_path) {
                Some(profile) => profiles.push(profile),
                None => valid = false,
            }
        }
        valid.then_some(profiles)
    }

    /// `XMCProfile.Build`.
    fn xmc_profile(&mut self, profile: &Value, path: &str) -> Option<XmcProfile> {
        self.reject_unknown_fields(profile, path, &surface::XMC_PROFILE);
        let field = |parser: &mut Self, key: &str| {
            parser
                .nullable_string_at(profile, key, format!("{path}.{key}"))
                .map(str::to_owned)
        };
        let username = field(self, "username");
        let uuid = field(self, "uuid");
        let textures_value = field(self, "texturesValue");
        let textures_signature = field(self, "texturesSignature");
        let (username, uuid, textures_value, textures_signature) =
            (username?, uuid?, textures_value?, textures_signature?);
        let name_valid = (3..=16).contains(&username.len())
            && username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !name_valid {
            self.error(
                format!("{path}.username"),
                format!("invalid minecraft profile username: {username:?}"),
            );
            return None;
        }
        let Some(uuid) = crate::xray_uuid::parse_google(&uuid) else {
            self.error(format!("{path}.uuid"), "invalid minecraft profile UUID");
            return None;
        };
        if textures_value.is_empty() || textures_signature.is_empty() {
            self.error(path, "incomplete minecraft profile textures");
            return None;
        }
        Some(XmcProfile {
            username,
            uuid,
            textures_value,
            textures_signature,
        })
    }
}
