//! Xray `blackhole` outbound settings.
//!
//! Mirrors Xray-core v26.7.28 `infra/conf/blackhole.go`: `settings` may be
//! absent or null, and `response` is optional. A present `response` goes
//! through Xray's typed config loader, which rejects a null/non-object value,
//! a missing or null `type` and any type other than case-insensitive `none`
//! or `http`; those inputs fail closed here as well. Unknown keys fail like
//! every other registered grammar node, where Go would silently ignore them.

use super::*;
use crate::{BlackholeOutboundSettings, BlackholeResponse};

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
            Some(Value::String(_)) => {
                self.error(
                    type_path,
                    "unsupported blackhole response type; expected `none` or `http`",
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
}
