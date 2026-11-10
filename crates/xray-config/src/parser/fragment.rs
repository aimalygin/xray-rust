use super::*;
use crate::{go_lowercase, FragmentPackets, FragmentRange, TcpFragmentSettings};

/// Xray's `packets`: `tlshello` in any case, empty for every write, or what
/// `ParseRangeString` reads as one number or a `from-to` range. A zero, a
/// negative or a reversed range, which Xray-core either refuses or accepts
/// and never applies, is refused.
fn parse_fragment_packets(packets: &str) -> Option<FragmentPackets> {
    if go_lowercase(packets) == "tlshello" {
        return Some(FragmentPackets::TlsHello);
    }
    if packets.is_empty() {
        return Some(FragmentPackets::AllWrites);
    }
    let (from, to) = parse_xhttp_range_string(packets)?;
    let (from, to) = (u32::try_from(from).ok()?, u32::try_from(to).ok()?);
    (from >= 1 && to >= from).then_some(FragmentPackets::Writes { from, to })
}

impl Parser<'_> {
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
        // Xray reads an absent `packets` as empty: every write is cut.
        let packets = match raw.get("packets") {
            None | Some(Value::Null) => Some(FragmentPackets::AllWrites),
            Some(Value::String(packets)) => parse_fragment_packets(packets),
            Some(_) => None,
        };
        let Some(packets) = packets else {
            self.error(
                format!("{path}.packets"),
                "fragment packets must be tlshello, empty for every write, or a write number or from-to range counting from 1",
            );
            return None;
        };
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
            packets,
            lengths,
            delays_ms,
            max_split,
            folded_final_rules: None,
        })
    }

    pub(super) fn fragment_range(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<FragmentRange> {
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
        // Classify targets before inlining: an outbound that itself chains to
        // a fragment handler gains its mask below, and must still be an ordinary
        // chaining target for outbounds listed after it, as Xray resolves
        // dialerProxy tags at dial time regardless of order.
        let fragment_handlers: Vec<bool> = outbounds
            .iter()
            .map(|o| o.stream.tcp_fragment.is_some())
            .collect();
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
                    "dialerProxy must reference exactly one existing outbound tag",
                );
                continue;
            };
            let target = &outbounds[*target_index];
            if *target_index == index {
                self.error(path, "dialerProxy cannot reference its own outbound");
                continue;
            }
            if !fragment_handlers[*target_index]
                || !matches!(target.settings, OutboundSettings::Freedom(_))
            {
                // Ordinary transport-layer chaining is compiled and cycle-checked
                // by the same core graph as the legacy proxySettings form.
                continue;
            }
            if target
                .stream
                .socket_options
                .as_ref()
                .is_some_and(|options| options.domain_strategy.has_strategy())
            {
                // Inlining keeps only the fragment mask, and the caller's own
                // server lookup does not read a domain strategy yet.
                self.error(
                    path,
                    "dialerProxy cannot use a freedom fragment outbound with a domain strategy",
                );
                continue;
            }
            if !matches!(target.settings, OutboundSettings::Freedom(_))
                || target.stream.security != StreamSecurity::None
                || target.stream.transport != StreamTransport::Raw
                || target.proxy_settings.is_some()
                || target.mux.is_some()
                || target.stream.socket_options.is_some()
                || target.stream.quic_params.is_some()
                || outbounds[index].stream.tcp_fragment.is_some()
            {
                self.error(path, "dialerProxy supports only a dedicated raw freedom fragment outbound, without chaining, socket overrides, mux or a second fragment mask");
                continue;
            }
            // This restricted freedom handler has no destination rewrite, DNS,
            // security or transport behavior. Inline its sole socket transform
            // before the caller's TLS/REALITY handshake; no proxy protocol exists
            // to chain and the existing REALITY-over-proxy restriction stays intact.
            let final_rules = match &target.settings {
                OutboundSettings::Freedom(freedom) => freedom.final_rules.clone(),
                _ => Vec::new(),
            };
            let fragment = target
                .stream
                .tcp_fragment
                .clone()
                .map(|fragment| TcpFragmentSettings {
                    folded_final_rules: Some(final_rules),
                    ..fragment
                });
            outbounds[index].stream.tcp_fragment = fragment;
            outbounds[index].proxy_settings = None;
            // Xray-core's sockets here are the handler's, which sets no
            // socket option, so the caller's own socket options never reach
            // them; what its dial reads stays.
            if let Some(options) = outbounds[index].stream.socket_options.take() {
                outbounds[index].stream.socket_options = Some(SocketOptions {
                    happy_eyeballs: options.happy_eyeballs,
                    domain_strategy: options.domain_strategy,
                    address_port_strategy: options.address_port_strategy,
                    penetrate: options.penetrate,
                    ..SocketOptions::default()
                });
            }
        }
    }

    pub(super) fn validate_tcp_fragment_scope(&mut self, outbound: &OutboundConfig, index: usize) {
        let Some(fragment) = &outbound.stream.tcp_fragment else {
            return;
        };
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.tcp");
        // `tlshello` needs a TLS record to split; raw pieces go on any TCP
        // carrier, as Xray-core cuts every TCP dial's writes.
        let tls_hello = fragment.packets == FragmentPackets::TlsHello;
        let freedom = matches!(outbound.settings, OutboundSettings::Freedom(_));
        if outbound.stream.network != Network::Tcp
            || matches!(
                outbound.settings,
                OutboundSettings::Dns(_)
                    | OutboundSettings::Hysteria(_)
                    | OutboundSettings::Wireguard(_)
                    | OutboundSettings::Blackhole(_)
                    | OutboundSettings::Loopback(_)
            )
            || matches!(outbound.stream.transport, StreamTransport::Kcp(_))
            || tls_hello && !freedom && outbound.stream.security == StreamSecurity::None
            || freedom
                && (outbound.stream.security != StreamSecurity::None
                    || outbound.stream.transport != StreamTransport::Raw)
        {
            self.error(
                path,
                if tls_hello {
                    "tlshello fragmentation requires a TCP TLS/REALITY carrier or a raw freedom outbound"
                } else {
                    "fragmentation requires a TCP carrier: a proxy outbound over a TCP transport or a raw freedom outbound"
                },
            );
            return;
        }
        if matches!(outbound.stream.transport, StreamTransport::Masque(_))
            && matches!(&outbound.stream.security, StreamSecurity::Tls(tls)
                if !super::masque::masque_uses_http2(&tls.alpn))
        {
            self.error(
                &path,
                "TCP fragmentation cannot be applied to QUIC or split XHTTP downloads",
            );
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
