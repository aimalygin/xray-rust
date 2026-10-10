use super::*;
use crate::{FragmentRange, TcpFragmentSettings};

impl Parser<'_> {
    pub(super) fn parse_tcp_fragment_mask(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<TcpFragmentSettings> {
        let raw = stream?.get("finalmask")?.get("tcp")?;
        if raw.is_null() {
            return None;
        }
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.tcp");
        let Some(masks) = raw.as_array() else {
            self.error(path, "finalmask.tcp must be an array or null");
            return None;
        };
        if masks.is_empty() {
            return None;
        }
        if masks.len() != 1
            || !masks[0]
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|v| v.eq_ignore_ascii_case("fragment"))
        {
            self.error(path, "only one TCP fragment mask is supported");
            return None;
        }
        self.reject_unknown_fields(&masks[0], &format!("{path}[0]"), &surface::TCP_MASK_ENTRY);
        self.parse_tcp_fragment(
            masks[0].get("settings").unwrap_or(&Value::Null),
            &format!("{path}[0].settings"),
            false,
        )
    }

    pub(super) fn parse_tcp_fragment(
        &mut self,
        raw: &Value,
        path: &str,
        legacy: bool,
    ) -> Option<TcpFragmentSettings> {
        if !raw.is_object() {
            self.error(path, "fragment settings must be an object");
            return None;
        }
        self.reject_unknown_fields(
            raw,
            path,
            if legacy {
                &surface::FREEDOM_FRAGMENT
            } else {
                &surface::TCP_FRAGMENT
            },
        );
        if !raw
            .get("packets")
            .and_then(Value::as_str)
            .is_some_and(|p| p.eq_ignore_ascii_case("tlshello"))
        {
            self.error(format!("{path}.packets"), "only packets=tlshello is supported; arbitrary/all-write fragmentation is unsupported");
            return None;
        }
        let length = self.fragment_range(raw.get("length"), &format!("{path}.length"))?;
        let delay_key = if legacy { "interval" } else { "delay" };
        if legacy && raw.get(delay_key).is_none_or(Value::is_null) {
            self.error(
                format!("{path}.{delay_key}"),
                "legacy freedom fragment requires interval",
            );
            return None;
        }
        let delay = self.fragment_range(raw.get(delay_key), &format!("{path}.{delay_key}"))?;
        let lengths = if legacy {
            vec![length]
        } else {
            self.fragment_ranges(raw.get("lengths"), &format!("{path}.lengths"), length)?
        };
        let delays_ms = if legacy {
            vec![delay]
        } else {
            self.fragment_ranges(raw.get("delays"), &format!("{path}.delays"), delay)?
        };
        let max_split = self.fragment_range(raw.get("maxSplit"), &format!("{path}.maxSplit"))?;
        if lengths.iter().any(|r| r.from == 0 || r.to > 16_384) {
            self.error(
                format!("{path}.length"),
                "fragment lengths must be in 1..=16384 bytes",
            );
        }
        if delays_ms.iter().any(|r| r.to > 1000) {
            self.error(
                format!("{path}.{delay_key}"),
                "fragment delays must be in 0..=1000 milliseconds",
            );
        }
        if max_split.to > 4096 {
            self.error(
                format!("{path}.maxSplit"),
                "fragment maxSplit must be in 0..=4096; zero means no explicit split limit",
            );
        }
        Some(TcpFragmentSettings {
            lengths,
            delays_ms,
            max_split,
        })
    }

    fn fragment_range(&mut self, raw: Option<&Value>, path: &str) -> Option<FragmentRange> {
        let pair = match raw {
            None | Some(Value::Null) => Some((0, 0)),
            Some(Value::String(s)) => parse_xhttp_range_string(s),
            Some(v) => v
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .map(|n| (n, n)),
        };
        match pair {
            Some((a, b)) if a >= 0 && b >= 0 => Some(FragmentRange {
                from: a.min(b) as u32,
                to: a.max(b) as u32,
            }),
            _ => {
                self.error(
                    path,
                    "fragment range must be a nonnegative i32 or i32 range string",
                );
                None
            }
        }
    }

    fn fragment_ranges(
        &mut self,
        raw: Option<&Value>,
        path: &str,
        fallback: FragmentRange,
    ) -> Option<Vec<FragmentRange>> {
        let values = match raw {
            None | Some(Value::Null) => return Some(vec![fallback]),
            Some(Value::Array(v)) if v.is_empty() => return Some(vec![fallback]),
            Some(Value::Array(v)) if v.len() <= 16 => v,
            _ => {
                self.error(
                    path,
                    "fragment sequences must be arrays with at most 16 entries",
                );
                return None;
            }
        };
        values
            .iter()
            .enumerate()
            .map(|(i, v)| self.fragment_range(Some(v), &format!("{path}[{i}]")))
            .collect()
    }

    pub(super) fn resolve_fragment_dialer_proxies(
        &mut self,
        raw: &[Value],
        outbounds: &mut [OutboundConfig],
    ) {
        for index in 0..raw.len() {
            let Some(tag) = raw[index]
                .pointer("/streamSettings/sockopt/dialerProxy")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            let path = format!("$.outbounds[{index}].streamSettings.sockopt.dialerProxy");
            let matches: Vec<_> = outbounds
                .iter()
                .enumerate()
                .filter(|(_, o)| o.tag.as_deref() == Some(tag))
                .map(|(i, _)| i)
                .collect();
            let [target_index] = matches.as_slice() else {
                self.error(
                    path,
                    "fragment dialerProxy must reference exactly one existing outbound tag",
                );
                continue;
            };
            let target = &outbounds[*target_index];
            if *target_index == index
                || !matches!(target.settings, OutboundSettings::Freedom)
                || target.stream.security != StreamSecurity::None
                || target.stream.transport != StreamTransport::Raw
                || target.proxy_settings.is_some()
                || target.mux.is_some()
                || target.stream.socket_options.is_some()
                || target.stream.quic_params.is_some()
                || target.stream.tcp_fragment.is_none()
                || outbounds[index].proxy_settings.is_some()
                || outbounds[index].stream.tcp_fragment.is_some()
            {
                self.error(path, "dialerProxy supports only a dedicated raw freedom fragment outbound, without chaining, socket overrides, mux or a second fragment mask");
                continue;
            }
            // This restricted freedom handler has no destination rewrite, DNS,
            // security or transport behavior. Inline its sole socket transform
            // before the caller's TLS/REALITY handshake; no proxy protocol exists
            // to chain and the existing REALITY-over-proxy restriction stays intact.
            let fragment = target.stream.tcp_fragment.clone();
            outbounds[index].stream.tcp_fragment = fragment;
        }
    }

    pub(super) fn validate_tcp_fragment_scope(&mut self, outbound: &OutboundConfig, index: usize) {
        if outbound.stream.tcp_fragment.is_none() {
            return;
        }
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.tcp");
        if outbound.stream.network != Network::Tcp
            || matches!(
                outbound.settings,
                OutboundSettings::Dns(_)
                    | OutboundSettings::Hysteria(_)
                    | OutboundSettings::Wireguard(_)
                    | OutboundSettings::Blackhole(_)
            )
            || !matches!(outbound.settings, OutboundSettings::Freedom)
                && outbound.stream.security == StreamSecurity::None
            || matches!(outbound.settings, OutboundSettings::Freedom)
                && (outbound.stream.security != StreamSecurity::None
                    || outbound.stream.transport != StreamTransport::Raw)
        {
            self.error(path, "tlshello fragmentation requires a TCP TLS/REALITY carrier or a raw freedom outbound");
            return;
        }
        if let StreamTransport::Xhttp(xhttp) = &outbound.stream.transport {
            if xhttp.download.is_some()
                || matches!(&outbound.stream.security, StreamSecurity::Tls(tls) if tls.alpn == ["h3"])
            {
                self.error(
                    path,
                    "TCP fragmentation cannot be applied to QUIC or split XHTTP downloads",
                );
            }
        }
    }
}
