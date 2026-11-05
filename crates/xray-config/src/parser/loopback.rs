//! Xray `loopback` outbound settings, as Xray-core v26.10.31's
//! `infra/conf/loopback.go` reads them: `inboundTag` and `sniffing`.

use super::*;
use crate::LoopbackOutboundSettings;

impl Parser<'_> {
    /// Absent or `null` settings, and a `null` `inboundTag`, mean the empty
    /// tag, as in Xray-core.
    pub(super) fn parse_loopback_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<LoopbackOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let settings = match outbound.get("settings") {
            None | Some(Value::Null) => return Some(LoopbackOutboundSettings::default()),
            Some(settings) if settings.is_object() => settings,
            Some(_) => {
                self.error(path, "loopback settings must be an object or null");
                return None;
            }
        };
        self.reject_unknown_fields(settings, &path, &surface::LOOPBACK_SETTINGS);
        let inbound_tag =
            self.nullable_string_at(settings, "inboundTag", format!("{path}.inboundTag"));
        let sniffing_path = format!("{path}.sniffing");
        if self
            .parse_sniffing(settings.get("sniffing"), &sniffing_path)
            .is_some()
        {
            self.error(
                sniffing_path,
                "loopback sniffing is not supported yet; leave it disabled",
            );
            return None;
        }
        Some(LoopbackOutboundSettings {
            inbound_tag: inbound_tag?.to_owned(),
        })
    }
}
