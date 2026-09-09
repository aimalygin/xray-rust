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
        })
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
        if stream.quic_params.is_some() {
            self.error(format!("$.outbounds[{index}].streamSettings.finalmask.quicParams"), "Hysteria currently uses bounded default QUIC parameters; overrides are unsupported");
        }
        if stream.socket_options.is_some() {
            self.error(
                format!("$.outbounds[{index}].streamSettings.sockopt"),
                "Hysteria socket option overrides are unsupported",
            );
        }
    }
}
