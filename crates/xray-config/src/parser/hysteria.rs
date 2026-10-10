use super::*;
use crate::{HysteriaOutboundSettings, HysteriaSettings};

impl Parser<'_> {
    pub(super) fn parse_hysteria_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<HysteriaOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|s| s.is_object()) else {
            self.error(path, "Hysteria settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::HYSTERIA);
        self.require_hysteria_version(settings, &path);
        let Some(address) = settings.get("address").and_then(Value::as_str) else {
            self.error(
                format!("{path}.address"),
                "Hysteria requires a server address",
            );
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty() || address.len() > 253 || address.chars().any(char::is_whitespace) {
            self.error(format!("{path}.address"), "invalid Hysteria server address");
            return None;
        }
        let server = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip);
        let port = self.u16_at(settings, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(format!("{path}.port"), "Hysteria port must be nonzero");
        }
        Some(HysteriaOutboundSettings { server, port })
    }

    fn require_hysteria_version(&mut self, settings: &Value, path: &str) {
        if settings.get("version").and_then(Value::as_i64) != Some(2) {
            self.error(
                format!("{path}.version"),
                "only Hysteria version 2 is supported",
            );
        }
    }

    pub(super) fn parse_hysteria_transport(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<HysteriaSettings> {
        let path = format!("$.outbounds[{index}].streamSettings.hysteriaSettings");
        let Some(settings) = stream
            .and_then(|s| s.get("hysteriaSettings"))
            .filter(|s| s.is_object())
        else {
            self.error(path, "hysteriaSettings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::HYSTERIA_TRANSPORT);
        self.require_hysteria_version(settings, &path);
        let Some(auth) = settings.get("auth").and_then(Value::as_str) else {
            self.error(format!("{path}.auth"), "Hysteria requires authentication");
            return None;
        };
        if auth.is_empty() || auth.len() > 4096 || auth.bytes().any(|b| b < 0x20 || b == 0x7f) {
            self.error(
                format!("{path}.auth"),
                "invalid Hysteria authentication value",
            );
            return None;
        }
        Some(HysteriaSettings {
            auth: zeroize::Zeroizing::new(auth.into()),
            salamander_password: self.parse_hysteria_salamander(stream, index),
        })
    }

    fn parse_hysteria_salamander(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<zeroize::Zeroizing<String>> {
        let masks = stream?.get("finalmask")?.get("udp")?;
        if masks.is_null() {
            return None;
        }
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp");
        let Some(masks) = masks.as_array() else {
            self.error(path, "finalmask.udp must be an array or null");
            return None;
        };
        if masks.is_empty() {
            return None;
        }
        if masks.len() != 1
            || !masks[0]
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("salamander"))
        {
            self.error(path, "Hysteria supports one salamander UDP mask only");
            return None;
        }
        let mask = &masks[0];
        self.reject_unknown_fields(mask, &format!("{path}[0]"), &surface::FINALMASK_ENTRY);
        let settings = mask.get("settings").filter(|v| v.is_object());
        let Some(settings) = settings else {
            self.error(
                format!("{path}[0].settings"),
                "Salamander settings must be an object",
            );
            return None;
        };
        self.reject_unknown_fields(
            settings,
            &format!("{path}[0].settings"),
            &surface::SALAMANDER,
        );
        // A positive packetSize selects Gecko in Xray, not Salamander.
        if settings
            .get("packetSize")
            .is_some_and(|v| !v.is_null() && v.as_i64() != Some(0) && v.as_str() != Some("0"))
        {
            self.error(
                format!("{path}[0].settings.packetSize"),
                "Gecko packetSize is unsupported",
            );
        }
        let Some(password) = settings.get("password").and_then(Value::as_str) else {
            self.error(
                format!("{path}[0].settings.password"),
                "Salamander requires a password",
            );
            return None;
        };
        if !(4..=4096).contains(&password.len()) {
            self.error(
                format!("{path}[0].settings.password"),
                "Salamander password must contain 4..=4096 UTF-8 bytes",
            );
            return None;
        }
        Some(zeroize::Zeroizing::new(password.into()))
    }

    pub(super) fn validate_hysteria_pair(
        &mut self,
        settings: &OutboundSettings,
        stream: &StreamSettings,
        chained: bool,
        index: usize,
    ) {
        let hysteria = matches!(settings, OutboundSettings::Hysteria(_));
        if hysteria != matches!(stream.transport, StreamTransport::Hysteria(_)) {
            self.error(
                format!("$.outbounds[{index}].streamSettings.network"),
                "Hysteria outbound and transport must be selected together",
            );
        }
        if !hysteria {
            return;
        }
        match &stream.security {
            StreamSecurity::Tls(tls) if tls.alpn.is_empty() || tls.alpn == ["h3"] => {}
            _ => self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                "Hysteria requires TLS with ALPN h3",
            ),
        }
        if chained {
            self.error(
                format!("$.outbounds[{index}].proxySettings"),
                "Hysteria outbound chaining is unsupported",
            );
        }
        if stream.socket_options.is_some() {
            self.error(
                format!("$.outbounds[{index}].streamSettings.sockopt"),
                "Hysteria socket option overrides are unsupported",
            );
        }
    }
}
