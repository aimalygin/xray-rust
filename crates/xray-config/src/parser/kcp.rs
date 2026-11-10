//! mKCP: `kcpSettings` and the `mkcp-legacy` masks, read as Xray-core
//! v26.10.31 reads them.
use super::*;
use crate::{go_lowercase, KcpHeader, KcpMask, KcpSettings};

/// The largest `mtu` accepted. Xray-core serializes a segment into an
/// 8192-byte buffer and panics on one that does not fit, so a larger MTU
/// crashes it on the first write that fills a segment.
const MAX_MTU: u32 = 8192;

/// The domain of a `dns` header without a value.
const DEFAULT_DNS_HEADER_DOMAIN: &str = "www.baidu.com";

impl Parser<'_> {
    /// `kcpSettings` as `KCPConfig.Build` reads it. Absent or null keeps
    /// Xray-core's defaults. `header` and `seed` decode and do nothing there:
    /// since v26 the old header and seed are `mkcp-legacy` masks.
    pub(super) fn parse_kcp_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<KcpSettings> {
        let path = format!("$.outbounds[{index}].streamSettings.kcpSettings");
        let mut kcp = KcpSettings::default();
        let Some(settings) = stream
            .and_then(|stream| stream.get("kcpSettings"))
            .filter(|settings| !settings.is_null())
        else {
            return Some(kcp);
        };
        if !settings.is_object() {
            self.error(path, "kcpSettings must be an object or null");
            return None;
        }
        self.reject_unknown_fields(settings, &path, &surface::KCP_SETTINGS);
        let mut valid = true;
        for (key, field) in [
            ("mtu", &mut kcp.mtu),
            ("tti", &mut kcp.tti),
            ("uplinkCapacity", &mut kcp.uplink_capacity),
            ("downlinkCapacity", &mut kcp.downlink_capacity),
            ("cwndMultiplier", &mut kcp.cwnd_multiplier),
            ("maxSendingWindow", &mut kcp.max_sending_window),
        ] {
            // Each is a `*uint32`, which null leaves at its default.
            if settings.get(key).is_none_or(Value::is_null) {
                continue;
            }
            match self.optional_u32_at(settings, key, format!("{path}.{key}")) {
                Some(value) => *field = value,
                None => valid = false,
            }
        }
        // `seed` decodes into a `*string`; `header` is kept as raw JSON.
        if settings
            .get("seed")
            .is_some_and(|seed| !seed.is_null() && !seed.is_string())
        {
            self.error(
                format!("{path}.seed"),
                "field `seed` must be a string or null",
            );
            valid = false;
        }
        if settings
            .get("header")
            .and_then(|header| header.get("type"))
            .and_then(Value::as_str)
            .is_some_and(|kind| !kind.is_empty() && !kind.eq_ignore_ascii_case("none"))
        {
            self.warning(
                format!("{path}.header"),
                "Xray-core v26 ignores kcpSettings.header; an mkcp-legacy mask in finalmask.udp sends a header",
            );
        }
        if settings
            .get("seed")
            .and_then(Value::as_str)
            .is_some_and(|seed| !seed.is_empty())
        {
            self.warning(
                format!("{path}.seed"),
                "Xray-core v26 ignores kcpSettings.seed; an mkcp-legacy mask in finalmask.udp with the seed as its value encrypts",
            );
        }
        if !valid {
            return None;
        }
        if kcp.mtu < 21 {
            self.error(format!("{path}.mtu"), "MTU must be at least 21");
            valid = false;
        } else if kcp.mtu > MAX_MTU {
            self.error(
                format!("{path}.mtu"),
                "MTU must be at most 8192, the largest segment Xray-core can send",
            );
            valid = false;
        } else if kcp.max_sending_window / kcp.mtu == 0 {
            self.error(
                format!("{path}.maxSendingWindow"),
                format!("MaxSendingWindow must be at least {}", kcp.mtu),
            );
            valid = false;
        }
        if !(10..=1000).contains(&kcp.tti) {
            self.error(format!("{path}.tti"), "TTI must be between 10 and 1000");
            valid = false;
        }
        if kcp.cwnd_multiplier < 1 {
            self.error(
                format!("{path}.cwndMultiplier"),
                "CwndMultiplier must be at least 1",
            );
            valid = false;
        }
        valid.then_some(kcp)
    }

    /// The `finalmask.udp` masks an mKCP stream applies, in array order.
    /// Masks of other types are reported by `parse_udp_noise`. A filter
    /// applies nothing: between two header masks it splits Xray-core's
    /// group in two, which writes and reads the same bytes as one group.
    pub(super) fn parse_kcp_masks(&mut self, stream: Option<&Value>, index: usize) -> Vec<KcpMask> {
        let Some(masks) = stream
            .and_then(|stream| stream.pointer("/finalmask/udp"))
            .and_then(Value::as_array)
        else {
            return Vec::new();
        };
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp");
        let mut result = Vec::new();
        for (i, mask) in masks.iter().enumerate() {
            let Some(kind) = mask.get("type").and_then(Value::as_str) else {
                continue;
            };
            match go_lowercase(kind).as_ref() {
                "mkcp-legacy" => {
                    if let Some(mask) = self.parse_mkcp_legacy(mask, &format!("{path}[{i}]")) {
                        result.push(mask);
                    }
                }
                "noise" => result.push(KcpMask::Noise),
                "header-custom" => result.push(KcpMask::HeaderCustom),
                "sudoku" => result.push(KcpMask::Sudoku),
                "salamander" => result.push(KcpMask::Salamander),
                _ => {}
            }
        }
        result
    }

    /// One `mkcp-legacy` mask, as `MkcpLegacy.Build` reads it.
    fn parse_mkcp_legacy(&mut self, mask: &Value, path: &str) -> Option<KcpMask> {
        let settings_path = format!("{path}.settings");
        let empty = Value::Object(Default::default());
        let settings = match mask.get("settings") {
            None | Some(Value::Null) => &empty,
            Some(settings) if settings.is_object() => settings,
            Some(_) => {
                self.error(
                    settings_path,
                    "mkcp-legacy settings must be an object or null",
                );
                return None;
            }
        };
        self.reject_unknown_fields(settings, &settings_path, &surface::MKCP_LEGACY);
        let header = self.nullable_string_at(settings, "header", format!("{settings_path}.header"));
        let value = self.nullable_string_at(settings, "value", format!("{settings_path}.value"));
        let (header, value) = (header?, value?);
        if header.is_empty() {
            return Some(if value.is_empty() {
                KcpMask::Original
            } else {
                KcpMask::Aes128Gcm(zeroize::Zeroizing::new(value.to_owned()))
            });
        }
        let header = match go_lowercase(header).as_ref() {
            "dns" => KcpHeader::Dns(if value.is_empty() {
                DEFAULT_DNS_HEADER_DOMAIN.to_owned()
            } else {
                value.to_owned()
            }),
            "dtls" => KcpHeader::Dtls,
            "srtp" => KcpHeader::Srtp,
            "utp" => KcpHeader::Utp,
            "wechat" => KcpHeader::Wechat,
            "wireguard" => KcpHeader::Wireguard,
            _ => {
                self.error(
                    format!("{settings_path}.header"),
                    format!("invalid header {header}"),
                );
                return None;
            }
        };
        Some(KcpMask::Header(header))
    }
}
