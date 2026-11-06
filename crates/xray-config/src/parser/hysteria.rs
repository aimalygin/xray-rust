use super::*;
use crate::{FragmentRange, HysteriaOutboundSettings, HysteriaSettings};

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
        let (salamander_password, gecko_packet_size) = self
            .parse_hysteria_salamander(stream, index)
            .map_or((None, None), |(password, gecko)| (Some(password), gecko));
        Some(HysteriaSettings {
            auth: zeroize::Zeroizing::new(auth.into()),
            salamander_password,
            gecko_packet_size,
        })
    }

    fn parse_hysteria_salamander(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<(zeroize::Zeroizing<String>, Option<FragmentRange>)> {
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
        let (mask_index, mask) = masks.iter().enumerate().find(|(_, m)| {
            m.get("type")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case("salamander"))
        })?;
        let path = format!("{path}[{mask_index}]");
        self.reject_unknown_fields(mask, &path, &surface::FINALMASK_ENTRY);
        let settings = mask.get("settings").filter(|v| v.is_object());
        let Some(settings) = settings else {
            self.error(
                format!("{path}.settings"),
                "Salamander settings must be an object",
            );
            return None;
        };
        self.reject_unknown_fields(settings, &format!("{path}.settings"), &surface::SALAMANDER);
        let gecko = self.gecko_packet_size(
            settings.get("packetSize"),
            &format!("{path}.settings.packetSize"),
        );
        let Some(password) = settings.get("password").and_then(Value::as_str) else {
            self.error(
                format!("{path}.settings.password"),
                "Salamander requires a password",
            );
            return None;
        };
        if !(4..=4096).contains(&password.len()) {
            self.error(
                format!("{path}.settings.password"),
                "Salamander password must contain 4..=4096 UTF-8 bytes",
            );
            return None;
        }
        Some((zeroize::Zeroizing::new(password.into()), gecko?))
    }

    /// Salamander's `packetSize`, an Xray `Int32Range`: a number, or a
    /// string holding one or a `from-to` range, in either order. A positive
    /// upper bound selects Gecko and needs `1 <= from` and `to <= 2048`;
    /// anything else keeps plain Salamander.
    fn gecko_packet_size(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<Option<FragmentRange>> {
        let pair = match raw {
            None | Some(Value::Null) => Some((0, 0)),
            Some(Value::String(s)) => parse_xhttp_range_string(s),
            Some(v) => v
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .map(|n| (n, n)),
        };
        let Some((a, b)) = pair else {
            self.error(path, "packetSize must be an i32 or an i32 range string");
            return None;
        };
        let (from, to) = (a.min(b), a.max(b));
        if to <= 0 {
            return Some(None);
        }
        if from <= 0 || to > 2048 {
            self.error(
                path,
                "Gecko packetSize bounds must satisfy 1 <= from <= to <= 2048",
            );
            return None;
        }
        Some(Some(FragmentRange {
            from: from as u32,
            to: to as u32,
        }))
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
    }
}
