use super::*;
use crate::{FragmentRange, UdpNoiseItem, UdpNoiseSettings};
use base64::Engine as _;

impl Parser<'_> {
    pub(super) fn parse_udp_noise(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<UdpNoiseSettings> {
        let raw = stream?.get("finalmask")?.get("udp")?;
        if raw.is_null() {
            return None;
        }
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp");
        let Some(masks) = raw.as_array() else {
            self.error(path, "finalmask.udp must be an array or null");
            return None;
        };
        let mut noise = None;
        let mut salamander = None;
        if masks.len() > 2 {
            self.error(
                &path,
                "at most one noise and one Salamander mask are supported",
            );
            return None;
        }
        for (i, mask) in masks.iter().enumerate() {
            let p = format!("{path}[{i}]");
            self.reject_unknown_fields(mask, &p, &surface::FINALMASK_ENTRY);
            match mask
                .get("type")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("noise") if noise.is_none() => {
                    noise = Some(i);
                }
                Some("salamander") if salamander.is_none() => {
                    salamander = Some(i);
                }
                _ => self.error(
                    &p,
                    "only one noise and one Salamander UDP mask are supported",
                ),
            }
        }
        let i = noise?;
        let p = format!("{path}[{i}].settings");
        let Some(settings) = masks[i].get("settings").filter(|v| v.is_object()) else {
            self.error(p, "noise settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &p, &surface::UDP_NOISE);
        let reset_secs = self.fragment_range(settings.get("reset"), &format!("{p}.reset"))?;
        let items = match settings.get("noise") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) if items.len() <= 16 => {
                let mut result = Vec::new();
                for (i, item) in items.iter().enumerate() {
                    let p = format!("{p}.noise[{i}]");
                    if !item.is_object() {
                        self.error(p, "noise item must be an object");
                        continue;
                    }
                    self.reject_unknown_fields(item, &p, &surface::UDP_NOISE_ITEM);
                    let random_length =
                        self.fragment_range(item.get("rand"), &format!("{p}.rand"))?;
                    let random_bytes = if item.get("randRange").is_none_or(Value::is_null) {
                        FragmentRange { from: 0, to: 255 }
                    } else {
                        self.fragment_range(item.get("randRange"), &format!("{p}.randRange"))?
                    };
                    let delay_ms = self.fragment_range(item.get("delay"), &format!("{p}.delay"))?;
                    if random_length.to > 0 && item.get("packet").is_some() {
                        self.error(&p, "packet and nonzero rand cannot be combined");
                    }
                    let packet = self.noise_packet(item.get("packet"), item.get("type"), &p)?;
                    if random_length.to > 4096
                        || packet.len() > 4096
                        || random_bytes.to > 255
                        || delay_ms.to > 1000
                    {
                        self.error(&p, "noise supports 0..4096 bytes, randRange 0..255 and delay 0..1000 milliseconds");
                    }
                    result.push(UdpNoiseItem {
                        packet,
                        random_length,
                        random_bytes,
                        delay_ms,
                    });
                }
                result
            }
            _ => {
                self.error(
                    format!("{p}.noise"),
                    "noise must be an array of at most 16 items",
                );
                return None;
            }
        };
        if items.iter().map(|i| i.delay_ms.to as u64).sum::<u64>() > 10_000 {
            self.error(p, "total noise delay must not exceed 10 seconds");
        }
        Some(UdpNoiseSettings {
            items,
            reset_secs,
            before_salamander: salamander.is_some_and(|s| i < s),
        })
    }

    fn noise_packet(
        &mut self,
        packet: Option<&Value>,
        kind: Option<&Value>,
        path: &str,
    ) -> Option<Vec<u8>> {
        let kind = match kind {
            None | Some(Value::Null) => "",
            Some(Value::String(s)) => s,
            _ => {
                self.error(path, "noise type must be a string");
                return None;
            }
        };
        let packet = packet.unwrap_or(&Value::Null);
        let result = match kind.to_ascii_lowercase().as_str() {
            "" | "array" => match packet {
                Value::Null => Some(Vec::new()),
                Value::Array(items) => items
                    .iter()
                    .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                    .collect(),
                Value::String(s) => base64::engine::general_purpose::STANDARD
                    .decode(s.replace(['\r', '\n'], ""))
                    .ok(),
                _ => None,
            },
            "str" => packet.as_str().map(|s| s.as_bytes().to_vec()),
            "base64" => packet.as_str().and_then(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s.replace(['\r', '\n'], ""))
                    .ok()
            }),
            "hex" => packet.as_str().and_then(|s| {
                if !s.is_ascii() || s.len() % 2 != 0 {
                    return None;
                }
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                    .collect()
            }),
            _ => None,
        };
        if result.is_none() {
            self.error(
                format!("{path}.packet"),
                "invalid noise packet or type (array, str, hex, base64)",
            );
        }
        result
    }
}
