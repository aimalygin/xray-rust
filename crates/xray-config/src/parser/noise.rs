use super::*;
use crate::{go_lowercase, FragmentRange, NoiseSegment, UdpNoiseItem, UdpNoiseSettings};
use base64::Engine as _;

impl Parser<'_> {
    pub(super) fn parse_udp_hop_mask(
        &mut self,
        stream: Option<&Value>,
        is_quic: bool,
        index: usize,
    ) -> Option<QuicUdpHopSettings> {
        let masks = stream?.pointer("/finalmask/udp")?.as_array()?;
        let (i, mask) = masks.iter().enumerate().find(|(_, m)| {
            m.get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t.eq_ignore_ascii_case("udphop"))
        })?;
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp[{i}].settings");
        // Xray applies UDP masks to any UDP dial; here the QUIC carriers hop.
        // Xray reverses the list and dials only an outermost udphop, so any
        // mask after it fails every dial with "incorrect index". A filter
        // there fails them too: the check counts places, not what wraps.
        if !is_quic || i + 1 != masks.len() {
            self.error(
                &path,
                "udphop requires Hysteria or XHTTP with exact h3 ALPN and must be the last UDP mask",
            );
        }
        let settings = mask.get("settings").filter(|s| s.is_object());
        let Some(settings) = settings else {
            self.error(path, "udphop settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::UDP_HOP_MASK);
        // Xray splits `mode` at commas without trimming and refuses any part
        // that is not a mode, an empty one included.
        let (mut local, mut remote, mut remote_once) = (false, false, false);
        match settings.get("mode") {
            None | Some(Value::Null) | Some(Value::String(_)) => {
                let mode = settings.get("mode").and_then(Value::as_str).unwrap_or("");
                for part in mode.split(',') {
                    match part.to_ascii_lowercase().as_str() {
                        "intervallocal" => local = true,
                        "intervalremote" => remote = true,
                        "perconnremote" => remote_once = true,
                        _ => self.error(
                            format!("{path}.mode"),
                            format!(
                                "udphop mode `{part}` is not intervalLocal, intervalRemote or perConnRemote"
                            ),
                        ),
                    }
                }
            }
            Some(_) => self.error(format!("{path}.mode"), "udphop mode must be a string"),
        }
        let remote_ips = self.parse_udp_hop_remote_ips(settings.get("remoteIPs"), &path);
        let mut hop = self.parse_udp_hop_fields(settings, &path, "remotePorts")?;
        if (hop.interval.from == 0) != (hop.interval.to == 0) {
            self.error(
                format!("{path}.interval"),
                "udphop interval must be zero or have both bounds at least 5 seconds",
            );
        }
        hop.local = local;
        hop.remote = remote;
        hop.remote_once = remote_once;
        hop.remote_ips = remote_ips;
        Some(hop)
    }

    /// Xray's `remoteIPs`: each an IP or a prefix, as `netip` reads them.
    fn parse_udp_hop_remote_ips(&mut self, raw: Option<&Value>, path: &str) -> Vec<IpCidr> {
        let path = format!("{path}.remoteIPs");
        let entries = match raw {
            None | Some(Value::Null) => return Vec::new(),
            Some(Value::Array(entries)) => entries,
            Some(_) => {
                self.error(path, "udphop remoteIPs must be an array of strings");
                return Vec::new();
            }
        };
        let mut ips = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let parsed = entry.as_str().and_then(parse_netip_prefix_or_addr);
            match parsed {
                Some(cidr) => ips.push(cidr),
                None => self.error(
                    format!("{path}[{i}]"),
                    "udphop remoteIPs entries must be an IP address or prefix",
                ),
            }
        }
        ips
    }

    pub(super) fn parse_udp_noise(
        &mut self,
        stream: Option<&Value>,
        network: StreamNetwork,
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
        let mut hop = None;
        let mut header = None;
        let mut sudoku = None;
        let mut xdns = None;
        let mut realm = None;
        let mut xicmp = None;
        // mKCP takes any number of `mkcp-legacy` masks besides these, and
        // every carrier any number of filters, which wrap nothing on a
        // client.
        let counted = |mask: &Value| {
            let kind = mask.get("type").and_then(Value::as_str).map(go_lowercase);
            !matches!(kind.as_deref(), Some("mkcp-legacy" | "filter"))
        };
        if masks.iter().filter(|mask| counted(mask)).count() > 8 {
            self.error(
                &path,
                "at most one udphop, one noise, one Salamander, one header-custom, one sudoku, one xdns, one realm and one xicmp mask are supported",
            );
            return None;
        }
        for (i, mask) in masks.iter().enumerate() {
            let p = format!("{path}[{i}]");
            self.reject_unknown_fields(mask, &p, &surface::FINALMASK_ENTRY);
            match mask
                .get("type")
                .and_then(Value::as_str)
                .map(go_lowercase)
                .as_deref()
            {
                Some("filter") => {
                    self.validate_filter_mask(mask.get("settings"), &format!("{p}.settings"));
                }
                Some("noise") if noise.is_none() => {
                    noise = Some(i);
                }
                Some("salamander") if salamander.is_none() => {
                    salamander = Some(i);
                }
                Some("udphop") if hop.is_none() => {
                    hop = Some(i);
                }
                // Read by `parse_udp_header_custom`.
                Some("header-custom") if header.is_none() => {
                    header = Some(i);
                }
                // Read by `parse_udp_sudoku`.
                Some("sudoku") if sudoku.is_none() => {
                    sudoku = Some(i);
                }
                // Read by `parse_udp_xdns`.
                Some("xdns") if xdns.is_none() => {
                    xdns = Some(i);
                }
                // Read by `parse_udp_realm`.
                Some("realm") if realm.is_none() => {
                    realm = Some(i);
                }
                // Read by `parse_udp_xicmp`.
                Some("xicmp") if xicmp.is_none() => {
                    xicmp = Some(i);
                }
                // Read by `parse_kcp_masks`.
                Some("mkcp-legacy") if network == StreamNetwork::Kcp => {}
                Some("mkcp-legacy") => self.error(&p, "mkcp-legacy requires mKCP"),
                _ => self.error(
                    &p,
                    "only one udphop, one noise, one Salamander, one header-custom, one sudoku, one xdns, one realm and one xicmp UDP mask are supported",
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
        // Xray-core runs a nonempty script in Lua instead of the items.
        if settings
            .get("script")
            .is_some_and(|script| script.as_str() != Some(""))
        {
            self.error(
                format!("{p}.script"),
                "a noise script runs Lua, which is not supported yet",
            );
        }
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
                    // Xray-core skips randRange's bounds for an `exp` item.
                    let exp = item
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| go_lowercase(kind) == "exp");
                    if exp {
                        let segments = self.noise_exp(item.get("packet"), &p)?;
                        let length = segments.iter().map(NoiseSegment::max_len).sum::<usize>();
                        if length > 4096 || delay_ms.to > 1000 {
                            self.error(&p, "an exp noise packet takes at most 4096 bytes here, and delay 0..1000 milliseconds");
                        }
                        result.push(UdpNoiseItem {
                            packet: Vec::new(),
                            random_length: FragmentRange::default(),
                            random_bytes,
                            delay_ms,
                            segments,
                        });
                        continue;
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
                        segments: Vec::new(),
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
            // Go's `hex.DecodeString`, which takes no sign.
            "hex" => packet.as_str().and_then(|s| decode_hex(s).ok()),
            _ => None,
        };
        if result.is_none() {
            self.error(
                format!("{path}.packet"),
                "invalid noise packet or type (array, str, hex, base64, exp)",
            );
        }
        result
    }

    /// The segments of an `exp` item's packet, which must be a string.
    fn noise_exp(&mut self, packet: Option<&Value>, path: &str) -> Option<Vec<NoiseSegment>> {
        let path = format!("{path}.packet");
        let Some(Value::String(exp)) = packet else {
            self.error(path, "the packet of an exp noise item must be a string");
            return None;
        };
        parse_noise_exp(exp)
            .map_err(|message| self.error(path, message))
            .ok()
    }
}

/// RE2's `\s`, which Xray-core's pattern for a segment uses.
fn is_re2_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0c' | '\r' | ' ')
}

/// Xray-core's `parseNoiseExp`: segments `<key arg>`, nothing but whitespace
/// between them. A key is lowercase letters; its argument follows after
/// whitespace and runs to the next `>`.
fn parse_noise_exp(exp: &str) -> Result<Vec<NoiseSegment>, String> {
    let mut segments = Vec::new();
    let mut rest = exp;
    loop {
        // Between segments, whatever Go's `strings.TrimSpace` removes.
        let segment = rest.trim_start();
        if segment.is_empty() {
            break;
        }
        let near = || format!("invalid noise exp near {segment}");
        let tag = segment.strip_prefix('<').ok_or_else(near)?;
        let tag = tag.trim_start_matches(is_re2_space);
        let key_len = tag
            .find(|c: char| !c.is_ascii_lowercase())
            .unwrap_or(tag.len());
        let close = tag.find('>').ok_or_else(near)?;
        if key_len == 0 || key_len > close {
            return Err(near());
        }
        let (key, inside) = (&tag[..key_len], &tag[key_len..close]);
        let arg = if inside.is_empty() || inside.starts_with(is_re2_space) {
            inside.trim_matches(is_re2_space)
        } else {
            return Err(near());
        };
        segments.push(noise_segment(key, arg)?);
        rest = &tag[close + 1..];
    }
    if segments.is_empty() {
        return Err(format!("empty noise exp: {exp}"));
    }
    Ok(segments)
}

/// Xray-core's `buildNoiseSegment`.
fn noise_segment(key: &str, arg: &str) -> Result<NoiseSegment, String> {
    let size = || {
        if arg.is_empty() {
            return Err(format!("<{key}> in noise exp needs a size"));
        }
        match parse_xhttp_range_string(arg) {
            Some((from, to)) if from >= 0 && from <= to && to <= 65_535 => Ok(FragmentRange {
                from: from as u32,
                to: to as u32,
            }),
            _ => Err(format!("invalid size in noise exp: {arg}")),
        }
    };
    let bare = |segment| {
        if arg.is_empty() {
            Ok(segment)
        } else {
            Err(format!("<{key}> in noise exp takes no argument"))
        }
    };
    match key {
        "b" => {
            let digits = arg.split_whitespace().collect::<String>();
            let digits = digits.strip_prefix("0x").unwrap_or(&digits);
            let digits = digits.strip_prefix("0X").unwrap_or(digits);
            if digits.is_empty() {
                return Err("empty bytes in noise exp".to_owned());
            }
            decode_hex(digits)
                .map(NoiseSegment::Bytes)
                .map_err(|_| format!("invalid hex in noise exp: {arg}"))
        }
        "r" => size().map(NoiseSegment::Random),
        "rc" => size().map(NoiseSegment::RandomLetters),
        "rd" => size().map(NoiseSegment::RandomDigits),
        "t" => bare(NoiseSegment::Timestamp),
        "c" => bare(NoiseSegment::Counter),
        "n" => bare(NoiseSegment::Nonce),
        _ => Err(format!("unknown <{key}> in noise exp")),
    }
}

/// Go's `netip.ParsePrefix`, then `netip.ParseAddr`, as Xray reads a
/// `remoteIPs` entry: an IP with an optional decimal `/bits`, without
/// brackets, a zone, a sign or leading zeros.
fn parse_netip_prefix_or_addr(text: &str) -> Option<IpCidr> {
    let (address, bits) = match text.split_once('/') {
        Some((address, bits)) => (address, Some(bits)),
        None => (text, None),
    };
    let ip: IpAddr = address.parse().ok()?;
    let bits = match bits {
        None if ip.is_ipv4() => 32,
        None => 128,
        Some(bits) => {
            if bits.is_empty()
                || !bits.bytes().all(|byte| byte.is_ascii_digit())
                || (bits.len() > 1 && bits.starts_with('0'))
            {
                return None;
            }
            bits.parse::<u8>().ok()?
        }
    };
    IpCidr::new(ip, bits).ok()
}
