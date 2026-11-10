//! Transport selection, carrier settings and TLS/REALITY security.
use super::*;
use crate::KcpSettings;

impl Parser<'_> {
    pub(super) fn parse_stream_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<StreamSettings> {
        let stream = outbound.get("streamSettings");
        let stream_network = self.parse_network(stream, index)?;
        let mut security = self.parse_security(stream, index)?;
        if stream_network == StreamNetwork::Hysteria {
            if let StreamSecurity::Tls(tls) = &mut security {
                let explicit = stream
                    .and_then(|s| s.get("tlsSettings"))
                    .and_then(|s| s.get("fingerprint"));
                if explicit.is_some_and(|v| !v.is_null() && v.as_str() != Some("")) {
                    self.error(
                        format!("$.outbounds[{index}].streamSettings.tlsSettings.fingerprint"),
                        "Hysteria uses stock QUIC TLS; fingerprints are unsupported",
                    );
                }
                // Generic TCP TLS defaults to Chrome; QUIC is unshaped.
                tls.fingerprint = None;
            }
        }
        // Xray refuses this in `StreamConfig.Build`, so a profile pairing them
        // would build cleanly here and then fail against a real server. The
        // check lives here rather than in `validate_stream_settings_compatibility`
        // because only this function has both halves parsed.
        //
        // Xray permits REALITY on raw, XHTTP and gRPC
        // (`infra/conf/transport_internet.go`). The alias `splithttp` is
        // normalized to the XHTTP variant by `parse_network` below.
        if matches!(security, StreamSecurity::Reality(_))
            && !matches!(
                stream_network,
                StreamNetwork::Raw | StreamNetwork::Grpc | StreamNetwork::Xhttp
            )
        {
            self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                "REALITY only supports RAW, XHTTP and gRPC for now",
            );
        }
        // MASQUE runs over HTTP/3 unless its ALPN asks for HTTP/2 alone.
        let masque_h3 = stream_network == StreamNetwork::Masque
            && matches!(&security, StreamSecurity::Tls(tls) if !super::masque::masque_uses_http2(&tls.alpn));
        // XDRIVE reaches an HTTP storage over HTTP/3 only when that is the
        // one protocol its ALPN names.
        let xdrive_h3 = stream_network == StreamNetwork::Xdrive
            && matches!(&security, StreamSecurity::Tls(tls) if tls.alpn == ["h3"]);
        let is_quic = stream_network == StreamNetwork::Hysteria
            || masque_h3
            || xdrive_h3
            || stream_network == StreamNetwork::Xhttp
                && matches!(&security, StreamSecurity::Tls(tls) if tls.alpn == ["h3"]);
        let mut quic_params = self.parse_quic_params(stream, stream_network, is_quic, index);
        if let Some(hop) = self.parse_udp_hop_mask(stream, is_quic, index) {
            if stream
                .and_then(|s| s.pointer("/finalmask/quicParams/udpHop"))
                .is_some()
            {
                self.error(
                    format!("$.outbounds[{index}].streamSettings.finalmask"),
                    "legacy quicParams.udpHop and an udphop mask cannot be combined",
                );
            }
            quic_params.get_or_insert_with(Default::default).udp_hop = hop;
        }
        let tcp_masks = self.parse_tcp_masks(stream, index);
        // Xray-core v26.10.31's REALITY server asserts that its connection
        // can half-close, which xmc's server connection cannot: every
        // connection through both panics the server, so no server takes them.
        if tcp_masks.xmc.is_some() && matches!(security, StreamSecurity::Reality(_)) {
            self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                "REALITY cannot run over an xmc mask: Xray-core's REALITY server panics on every connection through one",
            );
        }
        let udp_noise = self.parse_udp_noise(stream, stream_network, index);
        let udp_header_custom = self.parse_udp_header_custom(stream, index);
        let udp_sudoku = self.parse_udp_sudoku(stream, index);
        let udp_xdns = self.parse_udp_xdns(stream, index);
        let udp_realm = self.parse_udp_realm(stream, index);
        let udp_xicmp = self.parse_udp_xicmp(stream, index);
        let socket_options = self.parse_socket_options(stream, index);
        if let Some(stream) = stream {
            self.validate_stream_settings_compatibility(stream, index);
        }
        self.validate_unconsumed_transport_settings(stream, stream_network, index);
        let mut transport =
            self.parse_stream_transport(stream, stream_network, xdrive_h3, index)?;
        let fronting = self.parse_stream_fronting(stream, stream_network, index)?;
        if let StreamTransport::Xdrive(settings) = &mut transport {
            settings.fronting = fronting;
        }
        if xdrive_h3 {
            self.validate_xdrive_h3_stream(stream, &transport, quic_params.as_ref(), index);
        }
        if let StreamTransport::Xhttp(xhttp) = &transport {
            if let Some(download) = &xhttp.download {
                if security != StreamSecurity::None
                    && download.stream.security == StreamSecurity::None
                {
                    self.error(
                        xhttp::download_path(stream, index) + ".security",
                        "a protected XHTTP upload cannot use a plaintext download",
                    );
                }
            }
        }

        // Freedom's flows and WireGuard's socket carry plain datagrams,
        // which Xray-core's `FinalMask.DialUDP` masks as it masks a QUIC
        // carrier's.
        let direct_udp = matches!(
            outbound
                .get("protocol")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("freedom" | "direct" | "wireguard")
        );
        let udp_carrier = matches!(stream_network, StreamNetwork::Hysteria | StreamNetwork::Kcp)
            || masque_h3
            || xdrive_h3
            || direct_udp
            || stream_network == StreamNetwork::Xhttp
                && matches!(&security, StreamSecurity::Tls(tls) if tls.alpn == ["h3"]);
        if udp_noise.is_some() && !udp_carrier {
            self.error(
                format!("$.outbounds[{index}].streamSettings.finalmask.udp"),
                "UDP noise requires Hysteria, mKCP or XHTTP with exact h3 ALPN",
            );
        }
        if udp_sudoku.is_some() && !udp_carrier {
            self.error(
                format!("$.outbounds[{index}].streamSettings.finalmask.udp"),
                "a sudoku UDP mask requires mKCP, Hysteria or XHTTP with exact h3 ALPN",
            );
        }
        if udp_header_custom.is_some() && !udp_carrier {
            self.error(
                format!("$.outbounds[{index}].streamSettings.finalmask.udp"),
                "a header-custom UDP mask requires mKCP, Hysteria or XHTTP with exact h3 ALPN",
            );
        }
        if udp_xdns.is_some() {
            let has = |kind: &str| {
                stream
                    .and_then(|s| s.pointer("/finalmask/udp"))
                    .and_then(Value::as_array)
                    .is_some_and(|masks| {
                        masks.iter().any(|mask| {
                            mask.get("type")
                                .and_then(Value::as_str)
                                .is_some_and(|t| crate::go_lowercase(t) == kind)
                        })
                    })
            };
            let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp");
            if !udp_carrier {
                self.error(
                    &path,
                    "an xdns UDP mask requires mKCP, Hysteria or XHTTP with exact h3 ALPN",
                );
            }
            // Both must be the last mask; under xdns, Xray-core opens the
            // hopping socket and never uses it.
            if has("udphop") {
                self.error(&path, "an xdns UDP mask cannot be combined with udphop");
            }
            // One xdns packet takes 4096 bytes; sudoku's datagram is four
            // times a QUIC packet of at least 1200, or a WireGuard packet.
            if is_quic && udp_sudoku.is_some() {
                self.error(
                    &path,
                    "a sudoku UDP mask cannot run under xdns on QUIC: its datagrams exceed the 4096 bytes an xdns packet takes",
                );
            }
            if direct_udp && udp_sudoku.is_some() {
                self.error(
                    &path,
                    "a sudoku UDP mask cannot run under xdns on freedom or WireGuard: its datagrams exceed the 4096 bytes an xdns packet takes",
                );
            }
        }
        if udp_realm.is_some() {
            let has = |kind: &str| {
                stream
                    .and_then(|s| s.pointer("/finalmask/udp"))
                    .and_then(Value::as_array)
                    .is_some_and(|masks| {
                        masks.iter().any(|mask| {
                            mask.get("type")
                                .and_then(Value::as_str)
                                .is_some_and(|t| crate::go_lowercase(t) == kind)
                        })
                    })
            };
            let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp");
            if !udp_carrier {
                self.error(
                    &path,
                    "a realm UDP mask requires mKCP, Hysteria or XHTTP with exact h3 ALPN",
                );
            }
            // Its rendezvous introduces the socket first, which only the
            // QUIC carriers and mKCP do here.
            if direct_udp {
                self.error(
                    &path,
                    "a realm UDP mask is not supported on freedom or WireGuard yet",
                );
            }
            // Each must be the last mask, and each sends somewhere else than
            // the other expects: udphop to the server's ports, xdns to its
            // resolvers.
            for other in ["udphop", "xdns"] {
                if has(other) {
                    self.error(
                        &path,
                        format!("a realm UDP mask cannot be combined with {other}"),
                    );
                }
            }
            // Xray-core writes to the server's address under realm but reads
            // from the punched peer's, so a header-custom mask's state never
            // matches, as under udphop.
            if udp_header_custom.is_some() {
                self.error(
                    &path,
                    "a header-custom UDP mask cannot be combined with realm",
                );
            }
        }
        if udp_xicmp.is_some() {
            let has = |kind: &str| {
                stream
                    .and_then(|s| s.pointer("/finalmask/udp"))
                    .and_then(Value::as_array)
                    .is_some_and(|masks| {
                        masks.iter().any(|mask| {
                            mask.get("type")
                                .and_then(Value::as_str)
                                .is_some_and(|t| crate::go_lowercase(t) == kind)
                        })
                    })
            };
            let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp");
            if !udp_carrier {
                self.error(
                    &path,
                    "an xicmp UDP mask requires mKCP, Hysteria or XHTTP with exact h3 ALPN",
                );
            }
            // Each must be the last mask: udphop and xicmp both open their
            // own sockets, xdns sends to resolvers and realm punches.
            for other in ["udphop", "xdns", "realm"] {
                if has(other) {
                    self.error(
                        &path,
                        format!("an xicmp UDP mask cannot be combined with {other}"),
                    );
                }
            }
            // Xray-core writes to the server's address and port under xicmp
            // but reads from the replying address without one, so a
            // header-custom mask's state never matches.
            if udp_header_custom.is_some() {
                self.error(
                    &path,
                    "a header-custom UDP mask cannot be combined with xicmp",
                );
            }
            // An echo carries at most 4080 bytes; sudoku's datagram is four
            // times a QUIC packet of at least 1200, or a WireGuard packet.
            if is_quic && udp_sudoku.is_some() {
                self.error(
                    &path,
                    "a sudoku UDP mask cannot run under xicmp on QUIC: its datagrams exceed the 4080 bytes an echo carries",
                );
            }
            if direct_udp && udp_sudoku.is_some() {
                self.error(
                    &path,
                    "a sudoku UDP mask cannot run under xicmp on freedom or WireGuard: its datagrams exceed the 4080 bytes an echo carries",
                );
            }
        }
        // Xray-core writes to 0.0.0.0:0 under udphop but reads from the hop's
        // address, so its standalone reply never completes and prefix
        // captures never match.
        if udp_header_custom.is_some()
            && stream
                .and_then(|s| s.pointer("/finalmask/udp"))
                .and_then(Value::as_array)
                .is_some_and(|masks| {
                    masks.iter().any(|mask| {
                        mask.get("type")
                            .and_then(Value::as_str)
                            .is_some_and(|kind| kind.eq_ignore_ascii_case("udphop"))
                    })
                })
        {
            self.error(
                format!("$.outbounds[{index}].streamSettings.finalmask.udp"),
                "a header-custom UDP mask cannot be combined with udphop",
            );
        }
        // Hysteria reads its own Salamander mask; the other UDP carriers take
        // one here, at its place among their masks.
        let udp_salamander = if stream_network == StreamNetwork::Hysteria {
            None
        } else {
            let salamander = self.parse_udp_salamander(stream, index);
            let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp");
            if salamander.is_some() && !udp_carrier {
                self.error(
                    &path,
                    "Salamander requires Hysteria, mKCP, XHTTP with exact h3 ALPN, MASQUE over HTTP/3, XDRIVE with exact h3 ALPN, freedom or WireGuard",
                );
            }
            if stream_network == StreamNetwork::Kcp
                && salamander
                    .as_ref()
                    .is_some_and(|salamander| salamander.gecko_packet_size.is_some())
            {
                self.error(
                    &path,
                    "Gecko, Salamander's packetSize, is not supported on mKCP yet",
                );
            }
            salamander
        };
        Some(StreamSettings {
            // Native Hysteria owns a UDP carrier; other transports retain
            // their existing TCP classification (XHTTP selects H3 later).
            network: if stream_network == StreamNetwork::Hysteria {
                Network::Udp
            } else {
                Network::Tcp
            },
            transport,
            security,
            quic_params,
            tcp_fragment: tcp_masks.fragment,
            tcp_header_custom: tcp_masks.header,
            udp_header_custom,
            tcp_sudoku: tcp_masks.sudoku,
            udp_sudoku,
            tcp_xmc: tcp_masks.xmc,
            udp_xdns,
            udp_realm,
            udp_xicmp,
            udp_noise,
            udp_salamander,
            socket_options,
        })
    }

    pub(super) fn parse_stream_transport(
        &mut self,
        stream: Option<&Value>,
        network: StreamNetwork,
        xdrive_h3: bool,
        index: usize,
    ) -> Option<StreamTransport> {
        match network {
            StreamNetwork::Hysteria => self
                .parse_hysteria_transport(stream, index)
                .map(StreamTransport::Hysteria),
            StreamNetwork::Raw => Some(StreamTransport::Raw),
            StreamNetwork::WebSocket => self
                .parse_websocket_settings(stream, index)
                .map(StreamTransport::WebSocket),
            StreamNetwork::HttpUpgrade => self
                .parse_httpupgrade_settings(stream, index)
                .map(StreamTransport::HttpUpgrade),
            StreamNetwork::Grpc => self
                .parse_grpc_settings(stream, index)
                .map(StreamTransport::Grpc),
            StreamNetwork::Xhttp => self
                .parse_xhttp_settings(stream, index)
                .map(Box::new)
                .map(StreamTransport::Xhttp),
            StreamNetwork::Kcp => {
                let masks = self.parse_kcp_masks(stream, index);
                self.parse_kcp_settings(stream, index)
                    .map(|kcp| StreamTransport::Kcp(KcpSettings { masks, ..kcp }))
            }
            StreamNetwork::Masque => self
                .parse_masque_transport(stream, index)
                .map(Box::new)
                .map(StreamTransport::Masque),
            StreamNetwork::Xdrive => self
                .parse_xdrive_transport(stream, index, xdrive_h3)
                .map(Box::new)
                .map(StreamTransport::Xdrive),
        }
    }

    /// Flags a settings block the selected network will never read.
    ///
    /// Xray's `StreamConfig.Build` builds *every* block that is present, not
    /// just the selected one, and only picks between them by protocol name at
    /// dial time. So the block is still validated — under `network: "raw"` an
    /// Xray config with `httpupgradeSettings.headers.Host` still fails to
    /// build — but it is also inert, which is how a copy-pasted `wsSettings`
    /// silently downgrades a profile to plain TCP. Hence a warning for its
    /// presence plus the block's own validation, which is exactly as strict as
    /// Xray and no stricter.
    pub(super) fn validate_unconsumed_transport_settings(
        &mut self,
        stream: Option<&Value>,
        network: StreamNetwork,
        index: usize,
    ) {
        let Some(stream) = stream else {
            return;
        };
        // `rawSettings` is `tcpSettings` renamed, so the raw transport reads
        // either spelling. Both are validated for every network already.
        let consumed: &[&str] = match network {
            StreamNetwork::Hysteria => &["hysteriaSettings"],
            StreamNetwork::Raw => &["tcpSettings", "rawSettings"],
            StreamNetwork::WebSocket => &["wsSettings"],
            StreamNetwork::HttpUpgrade => &["httpupgradeSettings"],
            StreamNetwork::Grpc => &["grpcSettings"],
            StreamNetwork::Xhttp => &["xhttpSettings", "splithttpSettings"],
            StreamNetwork::Kcp => &["kcpSettings"],
            StreamNetwork::Masque => &["masqueSettings"],
            StreamNetwork::Xdrive => &["xdriveSettings"],
        };

        for key in [
            "hysteriaSettings",
            "tcpSettings",
            "rawSettings",
            "wsSettings",
            "httpupgradeSettings",
            "grpcSettings",
            "xhttpSettings",
            "splithttpSettings",
            "kcpSettings",
            "masqueSettings",
            "xdriveSettings",
        ] {
            let value = stream.get(key);
            let null_xhttp_pointer = matches!(key, "xhttpSettings" | "splithttpSettings")
                && value.is_some_and(Value::is_null);
            if consumed.contains(&key) || value.is_none() || null_xhttp_pointer {
                continue;
            }

            self.warning(
                format!("$.outbounds[{index}].streamSettings.{key}"),
                format!(
                    "`{key}` is ignored because it doesn't match the selected stream transport"
                ),
            );
            match key {
                "hysteriaSettings" => {
                    self.error(
                        format!("$.outbounds[{index}].streamSettings.hysteriaSettings"),
                        "hysteriaSettings requires the hysteria transport",
                    );
                }
                "wsSettings" => {
                    let _ = self.parse_websocket_settings(Some(stream), index);
                }
                "httpupgradeSettings" => {
                    let _ = self.parse_httpupgrade_settings(Some(stream), index);
                }
                "grpcSettings" => {
                    let _ = self.parse_grpc_settings(Some(stream), index);
                }
                "xhttpSettings" => {
                    let _ = self.parse_xhttp_settings(Some(stream), index);
                }
                "splithttpSettings" if stream.get("xhttpSettings").is_none_or(Value::is_null) => {
                    let _ = self.parse_xhttp_settings(Some(stream), index);
                }
                "kcpSettings" => {
                    let _ = self.parse_kcp_settings(Some(stream), index);
                }
                // Xray-core builds it under any network.
                "masqueSettings" => {
                    let _ = self.parse_masque_transport(Some(stream), index);
                }
                // So it does this one, as over HTTP/1.1 and HTTP/2: its h3
                // flag needs the xdrive network.
                "xdriveSettings" => {
                    let _ = self.parse_xdrive_transport(Some(stream), index, false);
                }
                // `xhttpSettings` has priority over the legacy spelling, so
                // the lower-priority block is inert when both are present.
                "splithttpSettings" => {}
                // `validate_tcp_settings` already ran for both spellings.
                _ => {}
            }
        }
    }

    pub(super) fn parse_websocket_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<WebSocketSettings> {
        let settings_path = format!("$.outbounds[{index}].streamSettings.wsSettings");
        let Some(settings) = stream.and_then(|stream| stream.get("wsSettings")) else {
            // Xray builds a zero-valued config when the block is absent, and a
            // zero path normalizes to `/`.
            return Some(WebSocketSettings {
                path: "/".to_owned(),
                ..WebSocketSettings::default()
            });
        };
        if !settings.is_object() {
            self.error(settings_path, "wsSettings must be an object");
            return None;
        }
        self.reject_unknown_fields(settings, &settings_path, &surface::WEBSOCKET);

        let (path, early_data_bytes) = split_early_data_from_path(
            self.optional_string_at(settings, "path", format!("{settings_path}.path"))
                .unwrap_or_default(),
        );
        let mut host = self
            .optional_string_at(settings, "host", format!("{settings_path}.host"))
            .filter(|host| !host.is_empty())
            .map(ToOwned::to_owned);
        let mut headers = self.parse_transport_headers(settings, &settings_path)?;

        // Xray folds a `Host` key of any casing out of `headers` and into
        // `host`, keeping the explicit `host` when both are set, and warns.
        if let Some(position) = headers
            .iter()
            .position(|(name, _)| name.eq_ignore_ascii_case("host"))
        {
            let (_, value) = headers.remove(position);
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
            if host.is_none() {
                host = Some(value);
            }
            self.warning(
                format!("{settings_path}.headers"),
                "`host` in `headers` is deprecated; use the independent `host` field",
            );
        }

        Some(WebSocketSettings {
            path,
            host,
            // Go's `header.Add` MIME-canonicalizes the key on the way in, so a
            // config that writes `accept` puts `Accept` on the wire.
            headers: headers
                .into_iter()
                .map(|(name, value)| (canonical_header_name(&name), value))
                .collect(),
            early_data_bytes,
            heartbeat_period_secs: self
                .optional_u32_at(
                    settings,
                    "heartbeatPeriod",
                    format!("{settings_path}.heartbeatPeriod"),
                )
                .unwrap_or_default(),
        })
    }

    pub(super) fn parse_httpupgrade_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<HttpUpgradeSettings> {
        let settings_path = format!("$.outbounds[{index}].streamSettings.httpupgradeSettings");
        let Some(settings) = stream.and_then(|stream| stream.get("httpupgradeSettings")) else {
            return Some(HttpUpgradeSettings {
                path: "/".to_owned(),
                ..HttpUpgradeSettings::default()
            });
        };
        if !settings.is_object() {
            self.error(settings_path, "httpupgradeSettings must be an object");
            return None;
        }
        self.reject_unknown_fields(settings, &settings_path, &surface::HTTPUPGRADE);

        let (path, early_data_bytes) = split_early_data_from_path(
            self.optional_string_at(settings, "path", format!("{settings_path}.path"))
                .unwrap_or_default(),
        );
        if early_data_bytes != 0 {
            self.warning(
                format!("{settings_path}.path"),
                "httpupgrade `ed` is parsed for compatibility, but the client waits for the 101 response to avoid losing coalesced payload bytes in Xray's inbound handler",
            );
        }
        let headers = self.parse_transport_headers(settings, &settings_path)?;

        // Where websocket folds it away with a warning, httpupgrade refuses:
        // its `Host` comes from `host` alone.
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"))
        {
            self.error(
                format!("{settings_path}.headers"),
                "`headers` can't contain `host`; use the independent `host` field",
            );
            return None;
        }

        Some(HttpUpgradeSettings {
            path,
            host: self
                .optional_string_at(settings, "host", format!("{settings_path}.host"))
                .filter(|host| !host.is_empty())
                .map(ToOwned::to_owned),
            // No canonicalization here: Xray assigns straight into the header
            // map so that a config keeps the casing it wrote.
            headers,
            early_data_bytes,
        })
    }

    /// Reads `grpcSettings`. No `path`, no `host`, no `headers`, no `?ed=`:
    /// `GRPCConfig` has eight fields and none of them are those
    /// (`Xray-core/infra/conf/grpc.go:8-17`).
    pub(super) fn parse_grpc_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<GrpcSettings> {
        let settings_path = format!("$.outbounds[{index}].streamSettings.grpcSettings");
        let Some(settings) = stream.and_then(|stream| stream.get("grpcSettings")) else {
            // `StreamConfig.Build` only appends a transport entry for a block
            // that is present, and `GetTransportSettingsFor` then falls
            // through to a zero-valued `CreateTransportConfig`
            // (`transport/internet/config.go:71-81`) — which is a legal gRPC
            // outbound dialing `//Tun`, not a missing one.
            return Some(GrpcSettings::default());
        };
        if !settings.is_object() {
            self.error(settings_path, "grpcSettings must be an object");
            return None;
        }
        // Spelled exactly as the struct tags spell them: five snake_case,
        // `serviceName` and `multiMode` camelCase, `authority` neither. Go
        // matches on the tag, so `idleTimeout` is an unknown key upstream that
        // is silently dropped, and accepting it here would let a profile work
        // that does nothing against a real server.
        self.reject_unknown_fields(settings, &settings_path, &surface::GRPC);

        Some(GrpcSettings {
            // Passed through untouched, including a leading `/`: which of the
            // two `:path` dialects it selects is the transport's decision, not
            // the parser's.
            service_name: self
                .optional_string_at(
                    settings,
                    "serviceName",
                    format!("{settings_path}.serviceName"),
                )
                .unwrap_or_default()
                .to_owned(),
            multi_mode: self
                .optional_bool_at(settings, "multiMode", format!("{settings_path}.multiMode"))
                .unwrap_or_default(),
            authority: self
                .optional_string_at(settings, "authority", format!("{settings_path}.authority"))
                .filter(|authority| !authority.is_empty())
                .map(ToOwned::to_owned),
            // Not validated against `chrome`/`firefox`/`edge`/`golang`: those
            // are resolved when the outbound is built and anything else is a
            // literal UA (`transport/internet/grpc/dial.go:193-205`).
            //
            // Nor validated as a header value, which it has to be to reach the
            // wire. That refusal is a layer up, in `xray-core-rs`'s
            // `grpc_user_agent`, for the reason the authority above is parsed
            // there: the value's ceiling is `http::HeaderValue`'s, and stating
            // that rule a second time here is how the two come to disagree.
            // The cost is the `$.outbounds[N]` prefix this layer could have
            // put on the message, which is the cost `authority` already pays.
            user_agent: self
                .optional_string_at(
                    settings,
                    "user_agent",
                    format!("{settings_path}.user_agent"),
                )
                .filter(|user_agent| !user_agent.is_empty())
                .map(ToOwned::to_owned),
            idle_timeout_secs: self.grpc_clamped_int32_at(settings, "idle_timeout", &settings_path),
            health_check_timeout_secs: self.grpc_clamped_int32_at(
                settings,
                "health_check_timeout",
                &settings_path,
            ),
            permit_without_stream: self
                .optional_bool_at(
                    settings,
                    "permit_without_stream",
                    format!("{settings_path}.permit_without_stream"),
                )
                .unwrap_or_default(),
            initial_windows_size: self.grpc_clamped_int32_at(
                settings,
                "initial_windows_size",
                &settings_path,
            ),
        })
    }

    /// One of `grpcSettings`' three `int32` numbers, clamped the way
    /// `GRPCConfig.Build` clamps it.
    ///
    /// All three are negative-to-zero there (`Xray-core/infra/conf/
    /// grpc.go:20-29`), so nothing negative survives into `grpc.Config` and an
    /// unsigned field loses no reachable value. Reading through `i32` rather
    /// than `u32` is what keeps that true in both directions: it accepts the
    /// negatives Xray accepts, and it still refuses anything past `i32::MAX`,
    /// which Go's decoder refuses too ("cannot unmarshal number 2147483648
    /// into Go struct field GRPCConfig.idle_timeout of type int32").
    pub(super) fn grpc_clamped_int32_at(
        &mut self,
        settings: &Value,
        key: &str,
        settings_path: &str,
    ) -> u32 {
        self.optional_i32_at(settings, key, format!("{settings_path}.{key}"))
            .unwrap_or_default()
            .max(0) as u32
    }

    pub(super) fn parse_transport_headers(
        &mut self,
        settings: &Value,
        settings_path: &str,
    ) -> Option<Vec<(String, String)>> {
        let headers = match settings.get("headers") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(headers) => headers,
        };
        let headers_path = format!("{settings_path}.headers");
        let Some(headers) = headers.as_object() else {
            self.error(headers_path, "headers must be an object");
            return None;
        };

        let mut parsed = Vec::with_capacity(headers.len());
        let mut rejected = false;
        for (name, value) in headers {
            match value {
                Value::String(value) => parsed.push((name.clone(), value.to_owned())),
                Value::Null => parsed.push((name.clone(), String::new())),
                _ => {
                    self.error(
                        format!("{headers_path}.{name}"),
                        "header value must be a string or null",
                    );
                    rejected = true;
                }
            }
        }

        if rejected {
            return None;
        }
        Some(parsed)
    }

    /// Parses the supported stream-wide `finalmask.quicParams` subset.
    ///
    /// `quicParams` is a Go pointer, so `None` deliberately distinguishes an
    /// absent/null pointer from an explicitly present, default-valued object.
    /// Unsupported masks fail closed; Hysteria parses its Salamander mask separately.
    pub(super) fn parse_quic_params(
        &mut self,
        stream: Option<&Value>,
        network: StreamNetwork,
        is_quic: bool,
        index: usize,
    ) -> Option<QuicParamsSettings> {
        let finalmask = stream?.get("finalmask")?;
        if finalmask.is_null() {
            return None;
        }

        let finalmask_path = format!("$.outbounds[{index}].streamSettings.finalmask");
        if !finalmask.is_object() {
            self.error(finalmask_path, "finalmask must be an object or null");
            return None;
        }
        self.reject_unknown_fields(finalmask, &finalmask_path, &surface::FINALMASK);

        let quic = finalmask.get("quicParams")?;
        if quic.is_null() {
            return None;
        }
        let quic_path = format!("{finalmask_path}.quicParams");
        if !quic.is_object() {
            self.error(quic_path, "quicParams must be an object or null");
            return None;
        }
        self.reject_unknown_fields(quic, &quic_path, &surface::QUIC_PARAMS);

        // Go's encoding/json treats null for scalar struct fields as their
        // existing zero value. The nullable helpers below preserve that rule.
        let congestion = match crate::go_lowercase(self.nullable_string_at(
            quic,
            "congestion",
            format!("{quic_path}.congestion"),
        )?)
        .as_ref()
        {
            "" => QuicCongestion::Default,
            "brutal" => QuicCongestion::Brutal,
            "reno" => QuicCongestion::Reno,
            "bbr" => QuicCongestion::Bbr,
            "force-brutal" => QuicCongestion::ForceBrutal,
            unsupported => {
                self.error(
                    format!("{quic_path}.congestion"),
                    format!("unsupported QUIC congestion control `{unsupported}`"),
                );
                return None;
            }
        };
        // Xray-core accepts every profile wherever quicParams goes; its
        // Hysteria and XHTTP H3 dialers run them all.
        let bbr_profile = match crate::go_lowercase(self.nullable_string_at(
            quic,
            "bbrProfile",
            format!("{quic_path}.bbrProfile"),
        )?)
        .as_ref()
        {
            "" | "standard" => QuicBbrProfile::Standard,
            "conservative" => QuicBbrProfile::Conservative,
            "aggressive" => QuicBbrProfile::Aggressive,
            unsupported => {
                self.error(
                    format!("{quic_path}.bbrProfile"),
                    format!("unsupported QUIC BBR profile `{unsupported}`"),
                );
                return None;
            }
        };

        let brutal_up_bytes_per_sec = self.quic_bandwidth_at(quic, "brutalUp", &quic_path)?;
        let brutal_down_bytes_per_sec = self.quic_bandwidth_at(quic, "brutalDown", &quic_path)?;
        if brutal_up_bytes_per_sec > 0 && brutal_up_bytes_per_sec < 65_536 {
            self.error(
                format!("{quic_path}.brutalUp"),
                "brutalUp must be at least 65536 bytes per second",
            );
        }
        if brutal_down_bytes_per_sec > 0 && brutal_down_bytes_per_sec < 65_536 {
            self.error(
                format!("{quic_path}.brutalDown"),
                "brutalDown must be at least 65536 bytes per second",
            );
        }
        if congestion == QuicCongestion::ForceBrutal && brutal_up_bytes_per_sec == 0 {
            self.error(
                format!("{quic_path}.congestion"),
                "force-brutal requires nonzero brutalUp",
            );
        }
        if is_quic && network == StreamNetwork::Xhttp && congestion == QuicCongestion::Brutal {
            self.error(
                format!("{quic_path}.congestion"),
                "congestion `brutal` follows the rate a Hysteria server announces, and Xray's XHTTP dialer panics on it; use bbr, reno or force-brutal",
            );
        }

        let udp_hop = self.parse_quic_udp_hop(quic, &quic_path, is_quic)?;
        let init_stream_receive_window =
            self.quic_u64_at(quic, "initStreamReceiveWindow", &quic_path)?;
        let max_stream_receive_window =
            self.quic_u64_at(quic, "maxStreamReceiveWindow", &quic_path)?;
        let init_connection_receive_window =
            self.quic_u64_at(quic, "initConnectionReceiveWindow", &quic_path)?;
        let max_connection_receive_window =
            self.quic_u64_at(quic, "maxConnectionReceiveWindow", &quic_path)?;
        for (key, value) in [
            ("initStreamReceiveWindow", init_stream_receive_window),
            ("maxStreamReceiveWindow", max_stream_receive_window),
            (
                "initConnectionReceiveWindow",
                init_connection_receive_window,
            ),
            ("maxConnectionReceiveWindow", max_connection_receive_window),
        ] {
            if value > 0 && value < 16_384 {
                self.error(
                    format!("{quic_path}.{key}"),
                    format!("{key} must be at least 16384"),
                );
            }
        }

        let max_idle_timeout_secs = self.quic_i64_at(quic, "maxIdleTimeout", &quic_path)?;
        if max_idle_timeout_secs != 0 && !(4..=120).contains(&max_idle_timeout_secs) {
            self.error(
                format!("{quic_path}.maxIdleTimeout"),
                "maxIdleTimeout must be zero or between 4 and 120 seconds",
            );
        }
        let keep_alive_period_secs = self.quic_i64_at(quic, "keepAlivePeriod", &quic_path)?;
        if keep_alive_period_secs != 0 && !(2..=60).contains(&keep_alive_period_secs) {
            self.error(
                format!("{quic_path}.keepAlivePeriod"),
                "keepAlivePeriod must be zero or between 2 and 60 seconds",
            );
        }
        let max_incoming_streams = self.quic_i64_at(quic, "maxIncomingStreams", &quic_path)?;
        if max_incoming_streams != 0 && max_incoming_streams < 8 {
            self.error(
                format!("{quic_path}.maxIncomingStreams"),
                "maxIncomingStreams must be zero or at least 8",
            );
        }

        Some(QuicParamsSettings {
            congestion,
            bbr_profile,
            brutal_up_bytes_per_sec,
            brutal_down_bytes_per_sec,
            udp_hop,
            init_stream_receive_window,
            max_stream_receive_window,
            init_connection_receive_window,
            max_connection_receive_window,
            max_idle_timeout_secs,
            keep_alive_period_secs,
            disable_path_mtu_discovery: self.quic_bool_at(
                quic,
                "disablePathMTUDiscovery",
                &quic_path,
            )?,
            max_incoming_streams,
            disable_chrome_parrot: self.quic_bool_at(quic, "disableChromeParrot", &quic_path)?,
            disable_gso: self.quic_bool_at(quic, "disableGSO", &quic_path)?,
            disable_stateless_reset: self.quic_bool_at(
                quic,
                "disableStatelessReset",
                &quic_path,
            )?,
            brutal_disable_loss_compensation: self.quic_bool_at(
                quic,
                "brutalDisableLossCompensation",
                &quic_path,
            )?,
            debug: self.quic_bool_at(quic, "debug", &quic_path)?,
        })
    }

    pub(super) fn quic_bandwidth_at(
        &mut self,
        quic: &Value,
        key: &str,
        quic_path: &str,
    ) -> Option<u64> {
        let Some(raw) = quic.get(key) else {
            return Some(0);
        };
        let value = match raw {
            Value::Null => return Some(0),
            Value::String(value) => value,
            _ => {
                self.error(
                    format!("{quic_path}.{key}"),
                    format!("field `{key}` must be a bandwidth string or null"),
                );
                return None;
            }
        };
        match parse_quic_bandwidth(value) {
            Ok(bytes_per_sec) => Some(bytes_per_sec),
            Err(message) => {
                self.error(format!("{quic_path}.{key}"), message);
                None
            }
        }
    }

    pub(super) fn parse_quic_udp_hop(
        &mut self,
        quic: &Value,
        quic_path: &str,
        is_quic: bool,
    ) -> Option<QuicUdpHopSettings> {
        let Some(udp_hop) = quic.get("udpHop") else {
            return Some(QuicUdpHopSettings::default());
        };
        if udp_hop.is_null() {
            return Some(QuicUdpHopSettings::default());
        }
        let udp_hop_path = format!("{quic_path}.udpHop");
        // Only QUIC carriers use quicParams; pointing others at the udphop
        // mask, which they reject, would trade a no-op for a parse error.
        if is_quic {
            self.warning(&udp_hop_path, "legacy udpHop: migrate to finalmask.udp udphop with mode=intervalLocal,intervalRemote and remotePorts");
        } else {
            self.warning(&udp_hop_path, "legacy udpHop has no effect: UDP hopping applies only to Hysteria and XHTTP with exact h3 ALPN");
        }
        self.parse_udp_hop_fields(udp_hop, &udp_hop_path, "ports")
    }

    pub(super) fn parse_udp_hop_fields(
        &mut self,
        udp_hop: &Value,
        udp_hop_path: &str,
        ports_key: &str,
    ) -> Option<QuicUdpHopSettings> {
        if !udp_hop.is_object() {
            self.error(udp_hop_path, "udpHop must be an object or null");
            return None;
        }
        if ports_key == "ports" {
            self.reject_unknown_fields(udp_hop, udp_hop_path, &surface::UDP_HOP);
        }

        let ports = match udp_hop.get(ports_key) {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Number(number)) => match number.as_u64() {
                Some(0) => Vec::new(),
                Some(port) if port <= u16::MAX as u64 => vec![port as u16],
                _ => {
                    self.error(
                        format!("{udp_hop_path}.{ports_key}"),
                        "udpHop ports must be 0 or a port in 1..=65535",
                    );
                    return None;
                }
            },
            Some(Value::String(ports)) => match parse_quic_udp_hop_ports(ports) {
                Ok(ports) => ports,
                Err(message) => {
                    self.error(format!("{udp_hop_path}.{ports_key}"), message);
                    return None;
                }
            },
            Some(_) => {
                self.error(
                    format!("{udp_hop_path}.{ports_key}"),
                    "udpHop ports must be an integer, comma-separated string, or null",
                );
                return None;
            }
        };

        let interval = match udp_hop.get("interval") {
            None | Some(Value::Null) => QuicIntervalRange::default(),
            Some(raw) => {
                let range = if let Some(value) = raw.as_i64() {
                    i32::try_from(value).ok().map(|value| (value, value))
                } else if let Some(value) = raw.as_str() {
                    parse_xhttp_range_string(value)
                } else {
                    None
                };
                let Some((left, right)) = range else {
                    self.error(
                        format!("{udp_hop_path}.interval"),
                        "udpHop interval must be an i32, i32 range string, or null",
                    );
                    return None;
                };
                QuicIntervalRange {
                    from: left.min(right),
                    to: left.max(right),
                }
            }
        };
        if (interval.from != 0 && interval.from < 5) || (interval.to != 0 && interval.to < 5) {
            self.error(
                format!("{udp_hop_path}.interval"),
                "udpHop interval bounds must be zero or at least 5 seconds",
            );
        }

        // The legacy `quicParams.udpHop` hops the local socket and the
        // remote port together when it has ports; a mask's `mode` sets its
        // own.
        let hops = !ports.is_empty();
        Some(QuicUdpHopSettings {
            ports,
            interval,
            local: hops,
            remote: hops,
            remote_once: false,
            remote_ips: Vec::new(),
        })
    }

    pub(super) fn quic_u64_at(&mut self, quic: &Value, key: &str, quic_path: &str) -> Option<u64> {
        match quic.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_u64() {
                Some(value) => Some(value),
                None => {
                    self.error(
                        format!("{quic_path}.{key}"),
                        format!("field `{key}` must fit in u64"),
                    );
                    None
                }
            },
        }
    }

    pub(super) fn quic_i64_at(&mut self, quic: &Value, key: &str, quic_path: &str) -> Option<i64> {
        match quic.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_i64() {
                Some(value) => Some(value),
                None => {
                    self.error(
                        format!("{quic_path}.{key}"),
                        format!("field `{key}` must fit in i64"),
                    );
                    None
                }
            },
        }
    }

    pub(super) fn quic_bool_at(
        &mut self,
        quic: &Value,
        key: &str,
        quic_path: &str,
    ) -> Option<bool> {
        match quic.get(key) {
            None | Some(Value::Null) => Some(false),
            Some(Value::Bool(value)) => Some(*value),
            Some(_) => {
                self.error(
                    format!("{quic_path}.{key}"),
                    format!("field `{key}` must be a boolean or null"),
                );
                None
            }
        }
    }

    pub(super) fn parse_socket_options(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<SocketOptions> {
        let socket_options = stream.and_then(|stream| stream.get("sockopt"))?;
        let socket_options_path = format!("$.outbounds[{index}].streamSettings.sockopt");
        if !socket_options.is_object() {
            self.error(socket_options_path, "sockopt must be an object");
            return None;
        }

        self.reject_unknown_fields(socket_options, &socket_options_path, &surface::SOCKOPT);
        let at = |key: &str| format!("{socket_options_path}.{key}");
        // Chaining is parsed on the outbound; dedicated freedom fragment
        // handlers are normalized across outbounds after parsing.
        let dialer_proxy =
            self.nullable_string_at(socket_options, "dialerProxy", at("dialerProxy"));
        let happy_eyeballs = socket_options
            .get("happyEyeballs")
            .filter(|settings| !settings.is_null())
            .and_then(|settings| self.parse_happy_eyeballs_settings(settings, index));
        let domain_strategy =
            self.domain_strategy_at(socket_options, "domainStrategy", &at("domainStrategy"));
        let mark = self.go_int32_at(socket_options, "mark", at("mark"));
        let tcp_fast_open = self.tcp_fast_open_at(socket_options, at("tcpFastOpen"));
        let tproxy = self
            .nullable_string_at(socket_options, "tproxy", at("tproxy"))
            .map(|mode| match mode.to_ascii_lowercase().as_str() {
                "tproxy" => TproxyMode::Tproxy,
                "redirect" => TproxyMode::Redirect,
                _ => TproxyMode::Off,
            });
        let tcp_keep_alive_idle =
            self.go_int32_at(socket_options, "tcpKeepAliveIdle", at("tcpKeepAliveIdle"));
        let tcp_keep_alive_interval = self.go_int32_at(
            socket_options,
            "tcpKeepAliveInterval",
            at("tcpKeepAliveInterval"),
        );
        let tcp_congestion =
            self.nullable_string_at(socket_options, "tcpCongestion", at("tcpCongestion"));
        let tcp_window_clamp =
            self.go_int32_at(socket_options, "tcpWindowClamp", at("tcpWindowClamp"));
        let tcp_max_seg = self.go_int32_at(socket_options, "tcpMaxSeg", at("tcpMaxSeg"));
        let tcp_user_timeout =
            self.go_int32_at(socket_options, "tcpUserTimeout", at("tcpUserTimeout"));
        let interface = self.nullable_string_at(socket_options, "interface", at("interface"));
        let tcp_mptcp = self.go_bool_at(socket_options, "tcpMptcp", at("tcpMptcp"));
        let penetrate = self.go_bool_at(socket_options, "penetrate", at("penetrate"));
        // Inbound options, which Xray-core reads only on a listener: their
        // types are checked, and they are ignored.
        self.go_bool_at(
            socket_options,
            "acceptProxyProtocol",
            at("acceptProxyProtocol"),
        );
        self.go_bool_at(socket_options, "v6only", at("v6only"));
        self.go_string_list_at(
            socket_options,
            "trustedXForwardedFor",
            at("trustedXForwardedFor"),
        );
        let custom = self.parse_custom_socket_options(socket_options, &at("customSockopt"));
        let address_port_strategy =
            self.address_port_strategy_at(socket_options, &at("addressPortStrategy"));

        dialer_proxy?;
        Some(SocketOptions {
            happy_eyeballs,
            domain_strategy: domain_strategy?,
            address_port_strategy: address_port_strategy?,
            mark: mark?,
            tcp_fast_open: tcp_fast_open?,
            tproxy: tproxy?,
            tcp_keep_alive_idle: tcp_keep_alive_idle?,
            tcp_keep_alive_interval: tcp_keep_alive_interval?,
            tcp_congestion: tcp_congestion?.to_owned(),
            tcp_window_clamp: tcp_window_clamp?,
            tcp_max_seg: tcp_max_seg?,
            tcp_user_timeout: tcp_user_timeout?,
            interface: interface?.to_owned(),
            tcp_mptcp: tcp_mptcp?,
            penetrate: penetrate?,
            custom: custom?,
        })
    }

    /// A Go `int32` field: absent and null are zero, and only an integer
    /// literal within range decodes, as `encoding/json` decodes one.
    pub(super) fn go_int32_at(&mut self, value: &Value, key: &str, path: String) -> Option<i32> {
        match value.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_i64().and_then(|value| i32::try_from(value).ok()) {
                Some(value) => Some(value),
                None => {
                    self.error(
                        path,
                        format!("field `{key}` must be a 32-bit integer or null"),
                    );
                    None
                }
            },
        }
    }

    /// A Go `bool` field: absent and null are false.
    pub(super) fn go_bool_at(&mut self, value: &Value, key: &str, path: String) -> Option<bool> {
        match value.get(key) {
            None | Some(Value::Null) => Some(false),
            Some(Value::Bool(value)) => Some(*value),
            Some(_) => {
                self.error(path, format!("field `{key}` must be a boolean or null"));
                None
            }
        }
    }

    /// A Go `[]string` field: absent and null are empty, and a null element
    /// is an empty string.
    pub(super) fn go_string_list_at(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
    ) -> Option<Vec<String>> {
        match value.get(key) {
            None | Some(Value::Null) => Some(Vec::new()),
            Some(Value::Array(items)) => {
                let mut list = Vec::with_capacity(items.len());
                for (item_index, item) in items.iter().enumerate() {
                    match item {
                        Value::Null => list.push(String::new()),
                        Value::String(text) => list.push(text.clone()),
                        _ => {
                            self.error(
                                format!("{path}[{item_index}]"),
                                format!("field `{key}` must hold strings"),
                            );
                            return None;
                        }
                    }
                }
                Some(list)
            }
            Some(_) => {
                self.error(
                    path,
                    format!("field `{key}` must be an array of strings or null"),
                );
                None
            }
        }
    }

    /// `tcpFastOpen`, which Xray-core reads as `true` (256), `false` (-1)
    /// or a number it truncates and caps at `math.MaxInt32`.
    fn tcp_fast_open_at(&mut self, socket_options: &Value, path: String) -> Option<i32> {
        match socket_options.get("tcpFastOpen") {
            None | Some(Value::Null) => Some(0),
            Some(Value::Bool(true)) => Some(256),
            Some(Value::Bool(false)) => Some(-1),
            // `int32(math.Min(v, math.MaxInt32))`; Go's conversion of a value
            // below `math.MinInt32` gives `math.MinInt32` on every supported
            // architecture, as Rust's saturating cast does.
            Some(Value::Number(number)) => number.as_f64().map(|value| value as i32),
            Some(_) => {
                self.error(
                    path,
                    "tcpFastOpen: only boolean and integer value is acceptable",
                );
                None
            }
        }
    }

    /// `customSockopt`, kept as text: Xray-core reads each entry only when it
    /// sets a socket up.
    fn parse_custom_socket_options(
        &mut self,
        socket_options: &Value,
        path: &str,
    ) -> Option<Vec<CustomSocketOption>> {
        let items = match socket_options.get("customSockopt") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(items)) => items,
            Some(_) => {
                self.error(path, "field `customSockopt` must be an array or null");
                return None;
            }
        };
        let mut options = Vec::with_capacity(items.len());
        let mut failed = false;
        for (item_index, item) in items.iter().enumerate() {
            let item_path = format!("{path}[{item_index}]");
            // Xray-core dereferences each entry, so a null one stops it.
            if !item.is_object() {
                self.error(item_path, "customSockopt entries must be objects");
                return None;
            }
            self.reject_unknown_fields(item, &item_path, &surface::CUSTOM_SOCKOPT);
            let fields = ["system", "network", "level", "opt", "value", "type"].map(|key| {
                self.nullable_string_at(item, key, format!("{item_path}.{key}"))
                    .map(str::to_owned)
            });
            if fields.iter().any(Option::is_none) {
                failed = true;
                continue;
            }
            let [system, network, level, opt, value, kind] = fields.map(Option::unwrap_or_default);
            options.push(CustomSocketOption {
                system,
                network,
                level,
                opt,
                value,
                kind,
            });
        }
        (!failed).then_some(options)
    }

    /// `addressPortStrategy`, Xray-core's names ignoring case.
    fn address_port_strategy_at(
        &mut self,
        socket_options: &Value,
        path: &str,
    ) -> Option<AddressPortStrategy> {
        let strategy =
            self.nullable_string_at(socket_options, "addressPortStrategy", path.to_owned())?;
        match strategy.to_ascii_lowercase().as_str() {
            "" | "none" => Some(AddressPortStrategy::None),
            "srvportonly" => Some(AddressPortStrategy::SrvPortOnly),
            "srvaddressonly" => Some(AddressPortStrategy::SrvAddressOnly),
            "srvportandaddress" => Some(AddressPortStrategy::SrvPortAndAddress),
            "txtportonly" => Some(AddressPortStrategy::TxtPortOnly),
            "txtaddressonly" => Some(AddressPortStrategy::TxtAddressOnly),
            "txtportandaddress" => Some(AddressPortStrategy::TxtPortAndAddress),
            _ => {
                self.error(
                    path,
                    format!("unsupported address and port strategy: {strategy}"),
                );
                None
            }
        }
    }

    pub(super) fn parse_happy_eyeballs_settings(
        &mut self,
        settings: &Value,
        index: usize,
    ) -> Option<HappyEyeballsSettings> {
        let settings_path = format!("$.outbounds[{index}].streamSettings.sockopt.happyEyeballs");
        if !settings.is_object() {
            self.error(settings_path, "happyEyeballs must be an object");
            return None;
        }

        self.reject_unknown_fields(settings, &settings_path, &surface::HAPPY_EYEBALLS);

        Some(HappyEyeballsSettings {
            prioritize_ipv6: self
                .optional_bool_at(
                    settings,
                    "prioritizeIPv6",
                    format!("{settings_path}.prioritizeIPv6"),
                )
                .unwrap_or(false),
            interleave: self
                .optional_u32_at(
                    settings,
                    "interleave",
                    format!("{settings_path}.interleave"),
                )
                .unwrap_or(1),
            try_delay_ms: self
                .optional_u64_at(
                    settings,
                    "tryDelayMs",
                    format!("{settings_path}.tryDelayMs"),
                )
                .unwrap_or(0),
            max_concurrent_try: self
                .optional_u32_at(
                    settings,
                    "maxConcurrentTry",
                    format!("{settings_path}.maxConcurrentTry"),
                )
                .unwrap_or(4),
        })
    }

    pub(super) fn parse_network(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<StreamNetwork> {
        let Some(stream_settings) = stream else {
            return Some(StreamNetwork::Raw);
        };
        let stream_path = format!("$.outbounds[{index}].streamSettings");

        // v26.7.28 accepts both names and gives `method` priority. Both are
        // pointers, so JSON null is the same as an absent key. Decode-shape
        // validation still applies to the lower-priority `network` value.
        let method = match stream_settings.get("method") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => Some(value.as_str()),
            Some(_) => {
                self.error(
                    format!("{stream_path}.method"),
                    "field `method` must be a string or null",
                );
                return None;
            }
        };
        let network = match stream_settings.get("network") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => Some(value.as_str()),
            Some(_) => {
                self.error(
                    format!("{stream_path}.network"),
                    "field `network` must be a string or null",
                );
                return None;
            }
        };
        let (network_key, network) = method
            .map(|value| ("method", value))
            .or_else(|| network.map(|value| ("network", value)))
            .unwrap_or(("network", "tcp"));
        let network_path = format!("{stream_path}.{network_key}");
        // `TransportProtocol.Build` lowercases before matching, so `WS` and
        // `RAW` are as valid as `ws` and `raw`.
        let network = network.to_ascii_lowercase();

        match network.as_str() {
            "hysteria" => Some(StreamNetwork::Hysteria),
            // Xray renamed the `tcp` transport to `raw`; both names stay valid.
            "tcp" | "raw" => Some(StreamNetwork::Raw),
            "ws" | "websocket" => Some(StreamNetwork::WebSocket),
            "httpupgrade" => Some(StreamNetwork::HttpUpgrade),
            // No `gun` alias: v26.7.28's `TransportProtocol.Build` has only the
            // `grpc` arm, and `gun` falls through to "unknown transport
            // protocol" there.
            "grpc" => Some(StreamNetwork::Grpc),
            // Xray still accepts the original protocol spelling, but both
            // names select the same SplitHTTP/XHTTP transport.
            "xhttp" | "splithttp" => Some(StreamNetwork::Xhttp),
            // Xray deleted these outright, so `unsupported` would send someone
            // hunting for a flag to turn them on.
            network @ ("h2" | "h3" | "http" | "quic") => {
                self.error(
                    network_path,
                    format!(
                        "stream network `{network}` was removed from Xray; use `xhttp` instead"
                    ),
                );
                None
            }
            "kcp" | "mkcp" => Some(StreamNetwork::Kcp),
            "masque" => Some(StreamNetwork::Masque),
            "xdrive" => Some(StreamNetwork::Xdrive),
            network => {
                self.error(
                    network_path,
                    format!("unsupported stream network `{network}`"),
                );
                None
            }
        }
    }

    pub(super) fn parse_security(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<StreamSecurity> {
        let security_path = format!("$.outbounds[{index}].streamSettings.security");
        // As with `network`, only an absent key defaults. A silent fallback
        // here is worse than a wrong transport: `"security": 5` would strip a
        // REALITY or TLS outbound down to plaintext.
        let Some(stream_settings) = stream.filter(|stream| stream.get("security").is_some()) else {
            return Some(StreamSecurity::None);
        };
        // Xray switches on `strings.ToLower(c.Security)`, so `TLS` and
        // `REALITY` are as valid as their lowercase spellings.
        let security = self
            .optional_string_at(stream_settings, "security", security_path.clone())?
            .to_ascii_lowercase();

        match security.as_str() {
            // Xray's arm is `case "", "none":` — an explicitly empty security
            // is how a lot of generated configs spell "no TLS".
            "" | "none" => Some(StreamSecurity::None),
            "tls" => {
                let tls_settings = stream.and_then(|stream| stream.get("tlsSettings"));
                let path = format!("$.outbounds[{index}].streamSettings.tlsSettings");
                Some(StreamSecurity::Tls(
                    self.parse_tls_object(tls_settings, &path),
                ))
            }
            "reality" => self
                .parse_reality_settings(stream, index)
                .map(StreamSecurity::Reality),
            // Xray deleted legacy XTLS outright, so `unsupported` would send
            // someone hunting for a flag to turn it back on.
            "xtls" => {
                self.error(
                    security_path,
                    "stream security `xtls` was removed from Xray; use `tls` or `reality` with the `xtls-rprx-vision` flow",
                );
                None
            }
            security => {
                self.error(
                    security_path,
                    format!("unsupported stream security `{security}`"),
                );
                None
            }
        }
    }

    /// A TLS settings object at `path`, as Xray-core's `TLSConfig` reads it:
    /// `streamSettings.tlsSettings`, or a mask's `tlsConfig`.
    pub(super) fn parse_tls_object(
        &mut self,
        tls_settings: Option<&Value>,
        path: &str,
    ) -> TlsSettings {
        self.validate_tls_settings(tls_settings, path);
        let allow_insecure_path = format!("{path}.allowInsecure");
        let allow_insecure = match tls_settings.and_then(|settings| settings.get("allowInsecure")) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => false,
            Some(Value::Bool(true)) => {
                self.error(
                    allow_insecure_path,
                    "allowInsecure=true was removed by Xray; use pinnedPeerCertSha256 instead",
                );
                // Never let a rejected canonical config carry an
                // insecure verifier into a partially built model.
                false
            }
            Some(_) => {
                self.error(
                    allow_insecure_path,
                    "field `allowInsecure` must be a boolean or null",
                );
                false
            }
        };
        let pinned_peer_cert_sha256 = self.parse_tls_pinned_peer_cert_sha256(tls_settings, path);
        let verify_peer_cert_by_name = self.parse_tls_verify_peer_cert_by_name(tls_settings, path);
        // An absent fingerprint normalizes to chrome, matching Xray's
        // GetFingerprint(""): shaping is the default, not an opt-in.
        let raw_fingerprint = tls_settings
            .and_then(|settings| self.string_at(settings, "fingerprint"))
            .unwrap_or_default();
        let fingerprint = match xray_utls::normalize_tls_fingerprint(raw_fingerprint) {
            Some(fingerprint) => Some(fingerprint.to_owned()),
            None => {
                self.error(
                    format!("{path}.fingerprint"),
                    format!("unsupported tls fingerprint `{raw_fingerprint}`"),
                );
                None
            }
        };
        let alpn = tls_settings
            .and_then(|settings| settings.get("alpn"))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        TlsSettings {
            server_name: tls_settings
                .and_then(|settings| self.string_at(settings, "serverName"))
                .map(ToOwned::to_owned),
            fingerprint,
            pinned_peer_cert_sha256,
            verify_peer_cert_by_name,
            allow_insecure,
            alpn,
        }
    }

    pub(super) fn validate_stream_settings_compatibility(&mut self, stream: &Value, index: usize) {
        let stream_path = format!("$.outbounds[{index}].streamSettings");
        if !stream.is_object() {
            self.error(stream_path, "streamSettings must be an object");
            return;
        }

        self.reject_unknown_fields(stream, &stream_path, &surface::STREAM);
        self.validate_tcp_settings(stream, "tcpSettings", index);
        self.validate_tcp_settings(stream, "rawSettings", index);
    }

    pub(super) fn validate_tls_settings(&mut self, settings: Option<&Value>, path: &str) {
        let Some(settings) = settings else {
            return;
        };
        let settings_path = path.to_owned();
        if !settings.is_object() {
            self.error(settings_path, "tlsSettings must be an object");
            return;
        }

        self.reject_unknown_fields(settings, &settings_path, &surface::TLS);

        if settings
            .get("serverName")
            .is_some_and(|server_name| !server_name.is_string() && !server_name.is_null())
        {
            self.error(
                format!("{settings_path}.serverName"),
                "tls server name must be a string or null",
            );
        }
        if settings
            .get("serverName")
            .and_then(Value::as_str)
            .is_some_and(|server_name| server_name.eq_ignore_ascii_case("frommitm"))
        {
            self.error(
                format!("{settings_path}.serverName"),
                "tls serverName `fromMitm` requires Xray's MITM context and is not supported",
            );
        }

        // Go unmarshals this field into a string and rejects every JSON type
        // other than string/null. `string_at` intentionally has no diagnostics,
        // so without an explicit check a typo such as `"fingerprint": 42`
        // falls through to the empty-string default and silently enables the
        // Chrome profile.
        if settings
            .get("fingerprint")
            .is_some_and(|fingerprint| !fingerprint.is_string() && !fingerprint.is_null())
        {
            self.error(
                format!("{settings_path}.fingerprint"),
                "tls fingerprint must be a string",
            );
        }

        // Go reads a bool and, with a uTLS fingerprint, never hands its session
        // cache to uTLS (transport/internet/tls/tls.go copyConfig), so a shaped
        // handshake does not resume whatever the value. Shaped handshakes
        // here disable resumption as well.
        if settings
            .get("enableSessionResumption")
            .is_some_and(|value| !value.is_boolean() && !value.is_null())
        {
            self.error(
                format!("{settings_path}.enableSessionResumption"),
                "field `enableSessionResumption` must be a boolean",
            );
        }

        if let Some(alpn) = settings.get("alpn").filter(|alpn| !alpn.is_null()) {
            match alpn.as_array() {
                None => self.error(format!("{settings_path}.alpn"), "tls alpn must be an array"),
                // Xray unmarshals `alpn` into a `[]string` and fails outright on
                // an entry that is not one; dropping it silently would put a
                // list on the wire that the config never asked for.
                Some(values) => {
                    for (index, value) in values.iter().enumerate() {
                        if !value.is_string() {
                            self.error(
                                format!("{settings_path}.alpn[{index}]"),
                                "tls alpn entry must be a string",
                            );
                        } else if value
                            .as_str()
                            .is_some_and(|protocol| protocol.eq_ignore_ascii_case("frommitm"))
                        {
                            self.error(
                                format!("{settings_path}.alpn[{index}]"),
                                "tls alpn `fromMitm` requires Xray's MITM context and is not supported",
                            );
                        }
                    }
                }
            }
        }
    }

    pub(super) fn parse_tls_pinned_peer_cert_sha256(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Vec<[u8; 32]> {
        let path = format!("{path}.pinnedPeerCertSha256");
        let Some(value) = settings.and_then(|settings| settings.get("pinnedPeerCertSha256")) else {
            return Vec::new();
        };
        let encoded = match value {
            // encoding/json unmarshals JSON null into the Go string zero value.
            Value::Null => return Vec::new(),
            Value::String(encoded) => encoded,
            _ => {
                self.error(
                    path,
                    "field `pinnedPeerCertSha256` must be a string or null",
                );
                return Vec::new();
            }
        };

        let mut fingerprints = Vec::new();
        for fingerprint in encoded
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            // Xray accepts both compact hex and OpenSSL's colon-separated
            // representation, removing every colon before decoding.
            let compact = fingerprint.replace(':', "");
            let bytes = match decode_hex(&compact) {
                Ok(bytes) => bytes,
                Err(message) => {
                    self.error(path.clone(), message);
                    return Vec::new();
                }
            };
            let Ok(fingerprint) = <[u8; 32]>::try_from(bytes) else {
                self.error(
                    path,
                    "pinned peer certificate SHA-256 must decode to 32 bytes",
                );
                return Vec::new();
            };
            fingerprints.push(fingerprint);
        }
        fingerprints
    }

    pub(super) fn parse_tls_verify_peer_cert_by_name(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Vec<String> {
        let path = format!("{path}.verifyPeerCertByName");
        let Some(value) = settings.and_then(|settings| settings.get("verifyPeerCertByName")) else {
            return Vec::new();
        };
        let encoded = match value {
            // encoding/json unmarshals JSON null into the Go string zero value.
            Value::Null => return Vec::new(),
            Value::String(encoded) => encoded,
            _ => {
                self.error(
                    path,
                    "field `verifyPeerCertByName` must be a string or null",
                );
                return Vec::new();
            }
        };

        let mut names = Vec::new();
        for name in encoded.split(',').map(str::trim) {
            if name.is_empty() {
                continue;
            }
            if name.eq_ignore_ascii_case("frommitm") {
                self.error(
                    path.clone(),
                    "tls verifyPeerCertByName `fromMitm` requires Xray's MITM context and is not supported",
                );
                continue;
            }
            names.push(name.to_owned());
        }
        names
    }

    pub(super) fn validate_tcp_settings(&mut self, stream: &Value, key: &str, index: usize) {
        let Some(settings) = stream.get(key) else {
            return;
        };
        let settings_path = format!("$.outbounds[{index}].streamSettings.{key}");
        if !settings.is_object() {
            self.error(settings_path, format!("{key} must be an object"));
            return;
        }

        self.reject_unknown_fields(settings, &settings_path, &surface::RAW);

        let Some(header) = settings.get("header") else {
            return;
        };
        let header_path = format!("{settings_path}.header");
        if !header.is_object() {
            self.error(header_path, format!("{key} header must be an object"));
            return;
        }
        self.reject_unknown_fields(header, &header_path, &surface::RAW_HEADER);

        if let Some(header_type) =
            self.optional_string_at(header, "type", format!("{header_path}.type"))
        {
            if !header_type.is_empty() && header_type != "none" {
                self.error(
                    format!("{header_path}.type"),
                    format!("unsupported tcp header type `{header_type}`"),
                );
            }
        }
    }

    pub(super) fn parse_reality_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<RealitySettings> {
        let settings = stream.and_then(|stream| stream.get("realitySettings"));
        let base_path = format!("$.outbounds[{index}].streamSettings.realitySettings");
        let public_key_path = format!("{base_path}.publicKey");
        let public_key = self.parse_reality_public_key(settings, &public_key_path)?;
        let short_id = self.parse_reality_short_id(settings, &format!("{base_path}.shortId"))?;
        let server_name_path = format!("{base_path}.serverName");
        let Some(server_name) =
            settings.and_then(|settings| self.string_at(settings, "serverName"))
        else {
            self.error(server_name_path, "missing reality server name");
            return None;
        };
        if server_name.is_empty() {
            self.error(server_name_path, "reality server name must not be empty");
            return None;
        }

        let fingerprint_path = format!("{base_path}.fingerprint");
        let raw_fingerprint = settings
            .and_then(|settings| self.string_at(settings, "fingerprint"))
            .unwrap_or_default();
        let Some(fingerprint) = xray_utls::normalize_utls_fingerprint(raw_fingerprint) else {
            self.error(
                fingerprint_path,
                format!("unsupported reality fingerprint `{raw_fingerprint}`"),
            );
            return None;
        };
        if xray_utls::normalize_reality_supported_fingerprint(fingerprint).is_none() {
            self.error(
                fingerprint_path,
                format!(
                    "reality fingerprint `{fingerprint}` does not support REALITY because it has no X25519-compatible key share; use chrome, firefox, safari, or random"
                ),
            );
            return None;
        }
        // Xray-core's client still accepts these, and so do servers older than
        // v26.10.21, so this is a warning rather than an error.
        if !xray_utls::is_reality_fingerprint_hybrid(fingerprint) {
            self.warning(
                fingerprint_path,
                format!(
                    "reality fingerprint `{fingerprint}` has no X25519MLKEM768 key share, which REALITY servers from Xray-core v26.10.21 require; it still works with older servers, while chrome, firefox, safari, or random work with both"
                ),
            );
        }

        // Xray-core reads an empty spiderX as `/` and rejects any other value
        // that is not an absolute path (`infra/conf/transport_security.go`).
        let spider_x = settings
            .and_then(|settings| self.string_at(settings, "spiderX"))
            .unwrap_or_default();
        if !spider_x.is_empty() && !spider_x.starts_with('/') {
            self.error(
                format!("{base_path}.spiderX"),
                "reality spiderX must start with `/`",
            );
            return None;
        }

        Some(RealitySettings {
            server_name: server_name.to_owned(),
            fingerprint: fingerprint.to_owned(),
            public_key,
            short_id,
            spider_x: spider_x.to_owned(),
            mldsa65_verify: self
                .parse_reality_mldsa65_verify(settings, &format!("{base_path}.mldsa65Verify"))?,
        })
    }

    pub(super) fn parse_reality_mldsa65_verify(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<Option<Vec<u8>>> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("mldsa65Verify"))
            .and_then(Value::as_str)
        else {
            return Some(None);
        };
        if encoded.is_empty() {
            return Some(None);
        }
        let bytes = match decode_base64url_no_padding(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        if bytes.len() != 1952 {
            self.error(path, "reality mldsa65Verify must decode to 1952 bytes");
            return None;
        }
        Some(Some(bytes))
    }

    pub(super) fn parse_reality_public_key(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<[u8; 32]> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("publicKey"))
            .and_then(Value::as_str)
        else {
            self.error(path, "missing reality public key");
            return None;
        };
        let bytes = match decode_base64url_no_padding(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        match <[u8; 32]>::try_from(bytes.as_slice()) {
            Ok(public_key) => Some(public_key),
            Err(_) => {
                self.error(path, "reality public key must decode to 32 bytes");
                None
            }
        }
    }

    pub(super) fn parse_reality_short_id(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<RealityShortId> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("shortId"))
            .and_then(Value::as_str)
        else {
            self.error(path, "missing reality short id");
            return None;
        };
        let bytes = match decode_hex(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        match RealityShortId::try_from_slice(&bytes) {
            Ok(short_id) => Some(short_id),
            Err(err) => {
                self.error(path, err.to_string());
                None
            }
        }
    }
}
