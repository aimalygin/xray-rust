//! Transport selection, carrier settings and TLS/REALITY security.
use super::*;

impl Parser<'_> {
    pub(super) fn parse_stream_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<StreamSettings> {
        let stream = outbound.get("streamSettings");
        let stream_network = self.parse_network(stream, index)?;
        let security = self.parse_security(stream, index)?;
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
        let quic_params = self.parse_quic_params(stream, index);
        let socket_options = self.parse_socket_options(stream, index);
        if let Some(stream) = stream {
            self.validate_stream_settings_compatibility(stream, index);
        }
        self.validate_unconsumed_transport_settings(stream, stream_network, index);
        let transport = self.parse_stream_transport(stream, stream_network, index)?;
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

        Some(StreamSettings {
            // Every transport we accept dials TCP; `transport` carries what
            // gets layered on top of it.
            network: Network::Tcp,
            transport,
            security,
            quic_params,
            socket_options,
        })
    }

    pub(super) fn parse_stream_transport(
        &mut self,
        stream: Option<&Value>,
        network: StreamNetwork,
        index: usize,
    ) -> Option<StreamTransport> {
        match network {
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
            StreamNetwork::Raw => &["tcpSettings", "rawSettings"],
            StreamNetwork::WebSocket => &["wsSettings"],
            StreamNetwork::HttpUpgrade => &["httpupgradeSettings"],
            StreamNetwork::Grpc => &["grpcSettings"],
            StreamNetwork::Xhttp => &["xhttpSettings", "splithttpSettings"],
        };

        for key in [
            "tcpSettings",
            "rawSettings",
            "wsSettings",
            "httpupgradeSettings",
            "grpcSettings",
            "xhttpSettings",
            "splithttpSettings",
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

    /// Parses Xray v26.7.28's stream-wide `finalmask.quicParams` block.
    ///
    /// `quicParams` is a Go pointer, so `None` deliberately distinguishes an
    /// absent/null pointer from an explicitly present, default-valued object.
    /// TCP/UDP masks require runtime plugins we do not implement and therefore
    /// fail closed instead of being silently discarded.
    pub(super) fn parse_quic_params(
        &mut self,
        stream: Option<&Value>,
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
        self.reject_finalmask_masks(finalmask, "tcp", &finalmask_path);
        self.reject_finalmask_masks(finalmask, "udp", &finalmask_path);

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
        let congestion = match self
            .nullable_string_at(quic, "congestion", format!("{quic_path}.congestion"))?
            .to_lowercase()
            .as_str()
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
        let bbr_profile = match self
            .nullable_string_at(quic, "bbrProfile", format!("{quic_path}.bbrProfile"))?
            .to_lowercase()
            .as_str()
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

        let udp_hop = self.parse_quic_udp_hop(quic, &quic_path)?;
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
            debug: self.quic_bool_at(quic, "debug", &quic_path)?,
        })
    }

    pub(super) fn reject_finalmask_masks(
        &mut self,
        finalmask: &Value,
        key: &str,
        finalmask_path: &str,
    ) {
        match finalmask.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(masks)) if masks.is_empty() => {}
            Some(Value::Array(_)) => self.error(
                format!("{finalmask_path}.{key}"),
                format!("nonempty finalmask.{key} masks are unsupported"),
            ),
            Some(_) => self.error(
                format!("{finalmask_path}.{key}"),
                format!("finalmask.{key} must be an array or null"),
            ),
        }
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
    ) -> Option<QuicUdpHopSettings> {
        let Some(udp_hop) = quic.get("udpHop") else {
            return Some(QuicUdpHopSettings::default());
        };
        if udp_hop.is_null() {
            return Some(QuicUdpHopSettings::default());
        }
        let udp_hop_path = format!("{quic_path}.udpHop");
        if !udp_hop.is_object() {
            self.error(udp_hop_path, "udpHop must be an object or null");
            return None;
        }
        self.reject_unknown_fields(udp_hop, &udp_hop_path, &surface::UDP_HOP);

        let ports = match udp_hop.get("ports") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Number(number)) => match number.as_u64() {
                Some(0) => Vec::new(),
                Some(port) if port <= u16::MAX as u64 => vec![port as u16],
                _ => {
                    self.error(
                        format!("{udp_hop_path}.ports"),
                        "udpHop ports must be 0 or a port in 1..=65535",
                    );
                    return None;
                }
            },
            Some(Value::String(ports)) => match parse_quic_udp_hop_ports(ports) {
                Ok(ports) => ports,
                Err(message) => {
                    self.error(format!("{udp_hop_path}.ports"), message);
                    return None;
                }
            },
            Some(_) => {
                self.error(
                    format!("{udp_hop_path}.ports"),
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

        Some(QuicUdpHopSettings { ports, interval })
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
        let happy_eyeballs = socket_options
            .get("happyEyeballs")
            .and_then(|settings| self.parse_happy_eyeballs_settings(settings, index));

        Some(SocketOptions { happy_eyeballs })
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
            network @ ("kcp" | "mkcp" | "hysteria") => {
                self.error(
                    network_path,
                    format!("stream network `{network}` is not supported by xray-rust"),
                );
                None
            }
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
                self.validate_tls_settings(tls_settings, index);
                let allow_insecure_path =
                    format!("$.outbounds[{index}].streamSettings.tlsSettings.allowInsecure");
                let allow_insecure = match tls_settings
                    .and_then(|settings| settings.get("allowInsecure"))
                {
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
                let pinned_peer_cert_sha256 =
                    self.parse_tls_pinned_peer_cert_sha256(tls_settings, index);
                let verify_peer_cert_by_name =
                    self.parse_tls_verify_peer_cert_by_name(tls_settings, index);
                // An absent fingerprint normalizes to chrome, matching Xray's
                // GetFingerprint(""): shaping is the default, not an opt-in.
                let raw_fingerprint = tls_settings
                    .and_then(|settings| self.string_at(settings, "fingerprint"))
                    .unwrap_or_default();
                let fingerprint = match xray_utls::normalize_tls_fingerprint(raw_fingerprint) {
                    Some(fingerprint) => Some(fingerprint.to_owned()),
                    None => {
                        self.error(
                            format!("$.outbounds[{index}].streamSettings.tlsSettings.fingerprint"),
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

                Some(StreamSecurity::Tls(TlsSettings {
                    server_name: tls_settings
                        .and_then(|settings| self.string_at(settings, "serverName"))
                        .map(ToOwned::to_owned),
                    fingerprint,
                    pinned_peer_cert_sha256,
                    verify_peer_cert_by_name,
                    allow_insecure,
                    alpn,
                }))
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

    pub(super) fn validate_tls_settings(&mut self, settings: Option<&Value>, index: usize) {
        let Some(settings) = settings else {
            return;
        };
        let settings_path = format!("$.outbounds[{index}].streamSettings.tlsSettings");
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
        index: usize,
    ) -> Vec<[u8; 32]> {
        let path = format!("$.outbounds[{index}].streamSettings.tlsSettings.pinnedPeerCertSha256");
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
        index: usize,
    ) -> Vec<String> {
        let path = format!("$.outbounds[{index}].streamSettings.tlsSettings.verifyPeerCertByName");
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
                    "reality fingerprint `{fingerprint}` does not support REALITY because it has no X25519-compatible key share"
                ),
            );
            return None;
        }

        Some(RealitySettings {
            server_name: server_name.to_owned(),
            fingerprint: fingerprint.to_owned(),
            public_key,
            short_id,
            spider_x: settings
                .and_then(|settings| self.string_at(settings, "spiderX"))
                .unwrap_or_default()
                .to_owned(),
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
