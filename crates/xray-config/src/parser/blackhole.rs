//! Xray `blackhole` outbound settings.
//!
//! Mirrors Xray-core v26.7.28 `infra/conf/blackhole.go`: `settings` may be
//! absent or null, and `response` is optional. A present `response` goes
//! through Xray's typed config loader, which rejects a null/non-object value,
//! a missing or null `type` and any type other than case-insensitive `none`,
//! `http` or `custom`; those inputs fail closed here as well. Unknown keys
//! fail like every other registered grammar node, where Go would silently
//! ignore them.

use base64::Engine as _;

use super::*;
use crate::{BlackholeOutboundSettings, BlackholeResponse};

/// Xray-core sets no limit. This keeps a custom reply within one UDP datagram,
/// which is how a blackholed UDP flow receives it.
const MAX_CUSTOM_RESPONSE_BYTES: usize = 65_535;

impl Parser<'_> {
    pub(super) fn parse_blackhole_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<BlackholeOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let settings = match outbound.get("settings") {
            None | Some(Value::Null) => return Some(BlackholeOutboundSettings::default()),
            Some(settings) if settings.is_object() => settings,
            Some(_) => {
                self.error(path, "blackhole settings must be an object or null");
                return None;
            }
        };
        self.reject_unknown_fields(settings, &path, &surface::BLACKHOLE_SETTINGS);

        let Some(response) = settings.get("response") else {
            return Some(BlackholeOutboundSettings::default());
        };
        let response_path = format!("{path}.response");
        if !response.is_object() {
            self.error(
                response_path,
                "blackhole response must be an object with a `type`",
            );
            return None;
        }
        self.reject_unknown_fields(response, &response_path, &surface::BLACKHOLE_RESPONSE);

        let type_path = format!("{response_path}.type");
        let response = match response.get("type") {
            Some(Value::String(kind)) if kind.eq_ignore_ascii_case("none") => {
                BlackholeResponse::None
            }
            Some(Value::String(kind)) if kind.eq_ignore_ascii_case("http") => {
                BlackholeResponse::Http
            }
            Some(Value::String(kind)) if kind.eq_ignore_ascii_case("custom") => {
                BlackholeResponse::Custom(self.parse_blackhole_custom_response(
                    response.get("customResponseData"),
                    &format!("{response_path}.customResponseData"),
                )?)
            }
            Some(Value::String(_)) => {
                self.error(
                    type_path,
                    "unsupported blackhole response type; expected `none`, `http` or `custom`",
                );
                return None;
            }
            None | Some(Value::Null) => {
                self.error(type_path, "blackhole response requires a `type`");
                return None;
            }
            Some(_) => {
                self.error(type_path, "blackhole response type must be a string");
                return None;
            }
        };
        Some(BlackholeOutboundSettings { response })
    }

    /// Xray decodes `customResponseData` with Go's padded standard base64;
    /// an absent or null value is the empty string, so nothing is sent.
    fn parse_blackhole_custom_response(
        &mut self,
        data: Option<&Value>,
        path: &str,
    ) -> Option<Vec<u8>> {
        let encoded = match data {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::String(encoded)) => encoded,
            Some(_) => {
                self.error(path, "customResponseData must be a base64 string");
                return None;
            }
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            self.error(path, "customResponseData is not padded standard base64");
            return None;
        };
        if decoded.len() > MAX_CUSTOM_RESPONSE_BYTES {
            self.error(
                path,
                format!(
                    "customResponseData decodes to more than {MAX_CUSTOM_RESPONSE_BYTES} bytes"
                ),
            );
            return None;
        }
        Some(decoded)
    }
}
