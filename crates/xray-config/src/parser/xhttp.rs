//! XHTTP normalization and the bounded independent download stack.
use super::*;

impl Parser<'_> {
    /// Reads the current `xhttpSettings` spelling or its legacy
    /// `splithttpSettings` alias. When both exist Xray gives the former
    /// unconditional priority (`StreamConfig.Build`), so only that block may
    /// influence the normalized model.
    pub(super) fn parse_xhttp_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<XhttpSettings> {
        let Some(stream) = stream else {
            return Some(xhttp_settings_without_config_block());
        };

        // Both fields are Go pointers. JSON null therefore means nil, not a
        // present higher-priority block.
        let current = stream
            .get("xhttpSettings")
            .filter(|settings| !settings.is_null());
        let legacy = stream
            .get("splithttpSettings")
            .filter(|settings| !settings.is_null());
        let (settings_key, settings) = match (current, legacy) {
            (Some(settings), Some(legacy_settings)) => {
                // encoding/json decodes both typed pointer targets before
                // StreamConfig.Build applies alias priority. Validate that
                // the ignored block could be decoded, without applying its
                // mode/default/conflict semantics.
                self.validate_xhttp_settings_shape(
                    legacy_settings,
                    &format!("$.outbounds[{index}].streamSettings.splithttpSettings"),
                    true,
                );
                self.warning(
                    format!("$.outbounds[{index}].streamSettings.splithttpSettings"),
                    "`splithttpSettings` is ignored because `xhttpSettings` takes priority",
                );
                ("xhttpSettings", settings)
            }
            (Some(settings), None) => ("xhttpSettings", settings),
            (None, Some(settings)) => ("splithttpSettings", settings),
            (None, None) => return Some(xhttp_settings_without_config_block()),
        };
        let settings_path = format!("$.outbounds[{index}].streamSettings.{settings_key}");
        if !settings.is_object() {
            self.error(settings_path, format!("{settings_key} must be an object"));
            return None;
        }

        self.reject_unknown_fields(settings, &settings_path, &surface::XHTTP);
        self.warn_removed_xhttp_concurrent_posts(settings, &settings_path);

        // SplitHTTPConfig.Build always keeps these three values from the
        // outer object, even when `extra` supplies different values. Decode
        // and normalize them before selecting the replacement object so the
        // implementation cannot accidentally turn `extra` into a merge.
        let host = self
            .nullable_string_at(settings, "host", format!("{settings_path}.host"))?
            .to_owned();
        let path = self
            .nullable_string_at(settings, "path", format!("{settings_path}.path"))?
            .to_owned();
        let mode =
            match self.nullable_string_at(settings, "mode", format!("{settings_path}.mode"))? {
                "" | "auto" => XhttpMode::Auto,
                "packet-up" => XhttpMode::PacketUp,
                "stream-up" => XhttpMode::StreamUp,
                "stream-one" => XhttpMode::StreamOne,
                mode => {
                    self.error(
                        format!("{settings_path}.mode"),
                        format!("unsupported xhttp mode `{mode}`"),
                    );
                    return None;
                }
            };

        // `extra` is a json.RawMessage upstream. When present, Xray decodes a
        // fresh SplitHTTPConfig from it and discards every outer field except
        // host/path/mode. JSON null therefore means a zero-valued replacement,
        // while arrays and scalars fail the second decode. Build is invoked
        // once, so a nested `extra` in the replacement is inert.
        let mut effective_storage = None;
        let mut effective_path = settings_path.clone();
        if let Some(extra) = settings.get("extra") {
            let diagnostic_start = self.diagnostics.len();
            self.validate_xhttp_settings_shape(settings, &settings_path, false);
            if self.diagnostics[diagnostic_start..]
                .iter()
                .any(|diagnostic| diagnostic.severity == crate::DiagnosticSeverity::Error)
            {
                return None;
            }

            let extra_path = format!("{settings_path}.extra");
            let mut replacement = match extra {
                Value::Null => serde_json::Map::new(),
                Value::Object(replacement) => replacement.clone(),
                _ => {
                    self.error(extra_path, "xhttp `extra` must be an object or null");
                    return None;
                }
            };
            let replacement_value = Value::Object(replacement.clone());
            let diagnostic_start = self.diagnostics.len();
            self.validate_xhttp_settings_shape(&replacement_value, &extra_path, true);
            if self.diagnostics[diagnostic_start..]
                .iter()
                .any(|diagnostic| diagnostic.severity == crate::DiagnosticSeverity::Error)
            {
                return None;
            }
            self.warn_removed_xhttp_concurrent_posts(&replacement_value, &extra_path);
            if replacement.remove("extra").is_some() {
                self.warning(
                    format!("{extra_path}.extra"),
                    "nested xhttp `extra` is ignored because Xray applies replacement only once",
                );
            }
            // These inner values were decode-shape checked above, then are
            // deliberately erased just as SplitHTTPConfig.Build erases them.
            replacement.remove("host");
            replacement.remove("path");
            replacement.remove("mode");
            effective_storage = Some(Value::Object(replacement));
            effective_path = extra_path;
        }
        let effective_settings = effective_storage.as_ref().unwrap_or(settings);

        let download = match effective_settings.get("downloadSettings") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let download_path = format!("{effective_path}.downloadSettings");
                if self.parsing_xhttp_download {
                    self.error(
                        download_path,
                        "nested XHTTP downloadSettings are unsupported",
                    );
                    return None;
                }
                if mode == XhttpMode::StreamOne {
                    self.error(
                        download_path,
                        "downloadSettings cannot be used with stream-one",
                    );
                    return None;
                }
                Some(Box::new(self.parse_xhttp_download(
                    value,
                    index,
                    &download_path,
                )?))
            }
        };

        let settings = effective_settings;
        let settings_path = effective_path;
        let session_id_table = self
            .nullable_string_at(
                settings,
                "sessionIDTable",
                format!("{settings_path}.sessionIDTable"),
            )
            .unwrap_or_default();
        let session_id_length = self.xhttp_range_at(settings, "sessionIDLength", &settings_path)?;
        self.validate_xhttp_session_id_generation(
            session_id_table,
            session_id_length,
            &settings_path,
        );
        let headers = self.parse_transport_headers(settings, &settings_path)?;
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
        // XHTTP, like websocket, feeds configured headers through
        // `http.Header.Add`, which MIME-canonicalizes valid field names.
        let headers = headers
            .into_iter()
            .map(|(name, value)| (canonical_header_name(&name), value))
            .collect();

        let x_padding_bytes = self.xhttp_range_at(settings, "xPaddingBytes", &settings_path)?;
        if x_padding_bytes != XhttpRange::default()
            && (x_padding_bytes.from <= 0 || x_padding_bytes.to <= 0)
        {
            self.error(
                format!("{settings_path}.xPaddingBytes"),
                "xPaddingBytes cannot be disabled or contain a non-positive bound",
            );
        }

        let x_padding_placement = match self
            .nullable_string_at(
                settings,
                "xPaddingPlacement",
                format!("{settings_path}.xPaddingPlacement"),
            )
            .unwrap_or_default()
        {
            "" | "queryInHeader" => XhttpPaddingPlacement::QueryInHeader,
            "cookie" => XhttpPaddingPlacement::Cookie,
            "header" => XhttpPaddingPlacement::Header,
            "query" => XhttpPaddingPlacement::Query,
            placement => {
                self.error(
                    format!("{settings_path}.xPaddingPlacement"),
                    format!("unsupported xhttp padding placement `{placement}`"),
                );
                return None;
            }
        };

        let x_padding_method = match self
            .nullable_string_at(
                settings,
                "xPaddingMethod",
                format!("{settings_path}.xPaddingMethod"),
            )
            .unwrap_or_default()
        {
            "" | "repeat-x" => XhttpPaddingMethod::RepeatX,
            "tokenish" => XhttpPaddingMethod::Tokenish,
            method => {
                self.error(
                    format!("{settings_path}.xPaddingMethod"),
                    format!("unsupported xhttp padding method `{method}`"),
                );
                return None;
            }
        };

        let uplink_data_placement = match self
            .nullable_string_at(
                settings,
                "uplinkDataPlacement",
                format!("{settings_path}.uplinkDataPlacement"),
            )
            .unwrap_or_default()
        {
            "" | "auto" => XhttpUplinkDataPlacement::Auto,
            "body" => XhttpUplinkDataPlacement::Body,
            "cookie" if mode == XhttpMode::PacketUp => XhttpUplinkDataPlacement::Cookie,
            "header" if mode == XhttpMode::PacketUp => XhttpUplinkDataPlacement::Header,
            placement @ ("cookie" | "header") => {
                self.error(
                    format!("{settings_path}.uplinkDataPlacement"),
                    format!(
                        "uplinkDataPlacement `{placement}` is only supported in packet-up mode"
                    ),
                );
                return None;
            }
            placement => {
                self.error(
                    format!("{settings_path}.uplinkDataPlacement"),
                    format!("unsupported xhttp uplink data placement `{placement}`"),
                );
                return None;
            }
        };

        let uplink_http_method = self
            .nullable_string_at(
                settings,
                "uplinkHTTPMethod",
                format!("{settings_path}.uplinkHTTPMethod"),
            )
            .filter(|method| !method.is_empty())
            .unwrap_or("POST");
        if !is_http_token(uplink_http_method) {
            self.error(
                format!("{settings_path}.uplinkHTTPMethod"),
                "uplinkHTTPMethod must be a valid ASCII HTTP token",
            );
            return None;
        }
        let uplink_http_method = uplink_http_method.to_ascii_uppercase();
        if uplink_http_method == "GET" && mode != XhttpMode::PacketUp {
            self.error(
                format!("{settings_path}.uplinkHTTPMethod"),
                "uplinkHTTPMethod can be GET only in packet-up mode",
            );
        }

        let session_placement =
            self.xhttp_metadata_placement_at(settings, "sessionIDPlacement", &settings_path)?;
        let seq_placement =
            self.xhttp_metadata_placement_at(settings, "seqPlacement", &settings_path)?;

        let session_key = self
            .nullable_string_at(
                settings,
                "sessionIDKey",
                format!("{settings_path}.sessionIDKey"),
            )
            .unwrap_or_default();
        let session_key = if session_key.is_empty() {
            match session_placement {
                XhttpPlacement::Cookie | XhttpPlacement::Query => "x_session",
                XhttpPlacement::Header => "X-Session",
                XhttpPlacement::Path => "",
            }
        } else {
            session_key
        }
        .to_owned();

        let seq_key = self
            .nullable_string_at(settings, "seqKey", format!("{settings_path}.seqKey"))
            .unwrap_or_default();
        let seq_key = if seq_key.is_empty() {
            match seq_placement {
                XhttpPlacement::Cookie | XhttpPlacement::Query => "x_seq",
                XhttpPlacement::Header => "X-Seq",
                XhttpPlacement::Path => "",
            }
        } else {
            seq_key
        }
        .to_owned();

        let uplink_data_key = self
            .nullable_string_at(
                settings,
                "uplinkDataKey",
                format!("{settings_path}.uplinkDataKey"),
            )
            .unwrap_or_default();
        let uplink_data_key = if uplink_data_key.is_empty() {
            match uplink_data_placement {
                XhttpUplinkDataPlacement::Cookie => "x_data",
                XhttpUplinkDataPlacement::Auto | XhttpUplinkDataPlacement::Header => "X-Data",
                XhttpUplinkDataPlacement::Body => "",
            }
        } else {
            uplink_data_key
        }
        .to_owned();

        let server_max_header_bytes = self
            .xhttp_nullable_i32_at(
                settings,
                "serverMaxHeaderBytes",
                format!("{settings_path}.serverMaxHeaderBytes"),
            )
            .unwrap_or_default();
        if server_max_header_bytes < 0 {
            self.error(
                format!("{settings_path}.serverMaxHeaderBytes"),
                "serverMaxHeaderBytes cannot be negative",
            );
        }

        Some(XhttpSettings {
            download,
            host: (!host.is_empty()).then_some(host),
            path,
            mode,
            headers,
            x_padding_bytes,
            x_padding_obfs_mode: self
                .xhttp_nullable_bool_at(
                    settings,
                    "xPaddingObfsMode",
                    format!("{settings_path}.xPaddingObfsMode"),
                )
                .unwrap_or_default(),
            x_padding_key: non_empty_or(
                self.nullable_string_at(
                    settings,
                    "xPaddingKey",
                    format!("{settings_path}.xPaddingKey"),
                ),
                "x_padding",
            ),
            x_padding_header: non_empty_or(
                self.nullable_string_at(
                    settings,
                    "xPaddingHeader",
                    format!("{settings_path}.xPaddingHeader"),
                ),
                "X-Padding",
            ),
            x_padding_placement,
            x_padding_method,
            uplink_http_method,
            session_placement,
            session_key,
            session_id_table: session_id_table.to_owned(),
            session_id_length,
            seq_placement,
            seq_key,
            uplink_data_placement,
            uplink_data_key,
            uplink_chunk_size: self.xhttp_range_at(settings, "uplinkChunkSize", &settings_path)?,
            no_grpc_header: self
                .xhttp_nullable_bool_at(
                    settings,
                    "noGRPCHeader",
                    format!("{settings_path}.noGRPCHeader"),
                )
                .unwrap_or_default(),
            no_sse_header: self
                .xhttp_nullable_bool_at(
                    settings,
                    "noSSEHeader",
                    format!("{settings_path}.noSSEHeader"),
                )
                .unwrap_or_default(),
            sc_max_each_post_bytes: self.xhttp_range_at(
                settings,
                "scMaxEachPostBytes",
                &settings_path,
            )?,
            sc_min_posts_interval_ms: self.xhttp_range_at(
                settings,
                "scMinPostsIntervalMs",
                &settings_path,
            )?,
            sc_max_buffered_posts: self
                .xhttp_nullable_i64_at(
                    settings,
                    "scMaxBufferedPosts",
                    format!("{settings_path}.scMaxBufferedPosts"),
                )
                .unwrap_or_default(),
            sc_stream_up_server_secs: self.xhttp_range_at(
                settings,
                "scStreamUpServerSecs",
                &settings_path,
            )?,
            server_max_header_bytes,
            xmux: self.parse_xhttp_xmux(settings, &settings_path)?,
        })
    }

    pub(super) fn validate_xhttp_session_id_generation(
        &mut self,
        table: &str,
        length: XhttpRange,
        settings_path: &str,
    ) {
        if table.is_empty() {
            return;
        }

        if length.from <= 0 {
            self.error(
                format!("{settings_path}.sessionIDLength"),
                "sessionIDLength.from must be greater than zero when sessionIDTable is set",
            );
            return;
        }
        if !table.is_ascii() {
            self.error(
                format!("{settings_path}.sessionIDTable"),
                "sessionIDTable must contain only ASCII characters",
            );
            return;
        }

        let table_size = predefined_xhttp_session_id_table_size(table).unwrap_or(table.len());
        if !xhttp_session_id_room_is_large_enough(table_size, length) {
            self.error(
                format!("{settings_path}.sessionIDTable"),
                "sessionIDTable or sessionIDLength is too small",
            );
        }
    }

    /// Validates the JSON decoding surface of a lower-priority XHTTP alias.
    /// This deliberately does not apply `SplitHTTPConfig.Build`: an invalid
    /// mode or conflicting xmux values in the ignored block never reach that
    /// method upstream, while a wrong JSON type fails before alias priority is
    /// considered.
    pub(super) fn validate_xhttp_settings_shape(
        &mut self,
        settings: &Value,
        settings_path: &str,
        validate_identity: bool,
    ) {
        if !settings.is_object() {
            self.error(settings_path, "splithttpSettings must be an object");
            return;
        }
        self.reject_unknown_fields(settings, settings_path, &surface::XHTTP);

        let identity_keys: &[&str] = if validate_identity {
            &["host", "path", "mode"]
        } else {
            &[]
        };
        for key in identity_keys.iter().copied().chain([
            "xPaddingKey",
            "xPaddingHeader",
            "xPaddingPlacement",
            "xPaddingMethod",
            "uplinkHTTPMethod",
            "sessionIDPlacement",
            "sessionIDKey",
            "sessionIDTable",
            "seqPlacement",
            "seqKey",
            "uplinkDataPlacement",
            "uplinkDataKey",
        ]) {
            let _ = self.nullable_string_at(settings, key, format!("{settings_path}.{key}"));
        }
        for key in ["xPaddingObfsMode", "noGRPCHeader", "noSSEHeader"] {
            let _ = self.xhttp_nullable_bool_at(settings, key, format!("{settings_path}.{key}"));
        }
        for key in [
            "xPaddingBytes",
            "sessionIDLength",
            "uplinkChunkSize",
            "scMaxEachPostBytes",
            "scMinPostsIntervalMs",
            "scStreamUpServerSecs",
        ] {
            let _ = self.xhttp_range_at(settings, key, settings_path);
        }
        let _ = self.parse_transport_headers(settings, settings_path);
        let _ = self.xhttp_nullable_i64_at(
            settings,
            "scMaxBufferedPosts",
            format!("{settings_path}.scMaxBufferedPosts"),
        );
        let _ = self.xhttp_nullable_i32_at(
            settings,
            "serverMaxHeaderBytes",
            format!("{settings_path}.serverMaxHeaderBytes"),
        );
        self.validate_xhttp_xmux_shape(settings, settings_path);

        if settings
            .get("downloadSettings")
            .is_some_and(|download| !download.is_null() && !download.is_object())
        {
            self.error(
                format!("{settings_path}.downloadSettings"),
                "downloadSettings must be an object or null",
            );
        }
        // `extra` is json.RawMessage, so every JSON value has a valid decode
        // shape. Its runtime support is considered only for the winning block.
    }

    pub(super) fn warn_removed_xhttp_concurrent_posts(
        &mut self,
        settings: &Value,
        settings_path: &str,
    ) {
        if settings.get("scMaxConcurrentPosts").is_some() {
            self.warning(
                format!("{settings_path}.scMaxConcurrentPosts"),
                "xhttp `scMaxConcurrentPosts` was removed in Xray v24.12.15 and is ignored",
            );
        }
    }

    pub(super) fn validate_xhttp_xmux_shape(&mut self, settings: &Value, settings_path: &str) {
        let xmux = match settings.get("xmux") {
            None | Some(Value::Null) => return,
            Some(xmux) => xmux,
        };
        let xmux_path = format!("{settings_path}.xmux");
        if !xmux.is_object() {
            self.error(xmux_path, "xmux must be an object");
            return;
        }
        self.reject_unknown_fields(xmux, &xmux_path, &surface::XMUX);
        for key in [
            "maxConcurrency",
            "maxConnections",
            "cMaxReuseTimes",
            "hMaxRequestTimes",
            "hMaxReusableSecs",
        ] {
            let _ = self.xhttp_range_at(xmux, key, &xmux_path);
        }
        let _ = self.xhttp_nullable_i64_at(
            xmux,
            "hKeepAlivePeriod",
            format!("{xmux_path}.hKeepAlivePeriod"),
        );
    }

    pub(super) fn xhttp_metadata_placement_at(
        &mut self,
        settings: &Value,
        key: &str,
        settings_path: &str,
    ) -> Option<XhttpPlacement> {
        match self
            .nullable_string_at(settings, key, format!("{settings_path}.{key}"))
            .unwrap_or_default()
        {
            "" | "path" => Some(XhttpPlacement::Path),
            "cookie" => Some(XhttpPlacement::Cookie),
            "header" => Some(XhttpPlacement::Header),
            "query" => Some(XhttpPlacement::Query),
            placement => {
                self.error(
                    format!("{settings_path}.{key}"),
                    format!("unsupported xhttp {key} `{placement}`"),
                );
                None
            }
        }
    }

    pub(super) fn xhttp_range_at(
        &mut self,
        settings: &Value,
        key: &str,
        settings_path: &str,
    ) -> Option<XhttpRange> {
        let raw = match settings.get(key) {
            None | Some(Value::Null) => return Some(XhttpRange::default()),
            Some(raw) => raw,
        };
        let range = if let Some(value) = raw.as_i64() {
            i32::try_from(value).ok().map(|value| (value, value))
        } else if let Some(value) = raw.as_str() {
            parse_xhttp_range_string(value)
        } else {
            None
        };
        let Some((left, right)) = range else {
            self.error(
                format!("{settings_path}.{key}"),
                format!(
                    "field `{key}` must be an i32, an i32 range string such as `100-1000`, or null"
                ),
            );
            return None;
        };
        Some(XhttpRange {
            from: left.min(right),
            to: left.max(right),
        })
    }

    pub(super) fn parse_xhttp_xmux(
        &mut self,
        settings: &Value,
        settings_path: &str,
    ) -> Option<XhttpXmuxSettings> {
        let xmux = match settings.get("xmux") {
            None | Some(Value::Null) => return Some(XhttpXmuxSettings::default()),
            Some(xmux) => xmux,
        };
        let xmux_path = format!("{settings_path}.xmux");
        if !xmux.is_object() {
            self.error(xmux_path, "xmux must be an object");
            return None;
        }
        self.reject_unknown_fields(xmux, &xmux_path, &surface::XMUX);

        let parsed = XhttpXmuxSettings {
            max_concurrency: self.xhttp_range_at(xmux, "maxConcurrency", &xmux_path)?,
            max_connections: self.xhttp_range_at(xmux, "maxConnections", &xmux_path)?,
            c_max_reuse_times: self.xhttp_range_at(xmux, "cMaxReuseTimes", &xmux_path)?,
            h_max_request_times: self.xhttp_range_at(xmux, "hMaxRequestTimes", &xmux_path)?,
            h_max_reusable_secs: self.xhttp_range_at(xmux, "hMaxReusableSecs", &xmux_path)?,
            h_keep_alive_period_secs: self
                .xhttp_nullable_i64_at(
                    xmux,
                    "hKeepAlivePeriod",
                    format!("{xmux_path}.hKeepAlivePeriod"),
                )
                .unwrap_or_default(),
        };

        if parsed.max_connections.to > 0 && parsed.max_concurrency.to > 0 {
            self.error(
                xmux_path,
                "maxConnections cannot be specified together with maxConcurrency",
            );
        }

        let zero = zero_xhttp_xmux_settings();
        Some(if parsed == zero {
            XhttpXmuxSettings::default()
        } else {
            parsed
        })
    }

    /// Xray's `SplitHTTPConfig` fields are non-pointer Go scalars. The Go JSON
    /// decoder treats `null` as a no-op for those fields, leaving their zero
    /// value behind, so XHTTP must distinguish that case from a wrong type.
    pub(super) fn xhttp_nullable_bool_at(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
    ) -> Option<bool> {
        match value.get(key) {
            None | Some(Value::Null) => Some(false),
            Some(Value::Bool(value)) => Some(*value),
            Some(_) => {
                self.error(path, format!("field `{key}` must be a boolean or null"));
                None
            }
        }
    }

    pub(super) fn xhttp_nullable_i32_at(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
    ) -> Option<i32> {
        match value.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_i64().and_then(|value| i32::try_from(value).ok()) {
                Some(value) => Some(value),
                None => {
                    self.error(path, format!("field `{key}` must fit in i32 or be null"));
                    None
                }
            },
        }
    }

    pub(super) fn xhttp_nullable_i64_at(
        &mut self,
        value: &Value,
        key: &str,
        path: String,
    ) -> Option<i64> {
        match value.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_i64() {
                Some(value) => Some(value),
                None => {
                    self.error(path, format!("field `{key}` must fit in i64 or be null"));
                    None
                }
            },
        }
    }

    /// Reads a transport `headers` object. Xray types it as
    /// `map[string]string`: object/map null becomes an empty map, and a null
    /// map value becomes Go's zero string. Every other non-string value fails.
    fn parse_xhttp_download(
        &mut self,
        value: &Value,
        index: usize,
        path: &str,
    ) -> Option<crate::XhttpDownloadSettings> {
        let Some(object) = value.as_object() else {
            self.error(path, "downloadSettings must be an object or null");
            return None;
        };
        let Some(address) = object
            .get("address")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control()))
        else {
            self.error(
                format!("{path}.address"),
                "downloadSettings requires a non-empty address",
            );
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty() {
            self.error(
                format!("{path}.address"),
                "downloadSettings requires a non-empty address",
            );
            return None;
        }
        let address = parse_xray_ip_address(address)
            .map(TargetAddr::Ip)
            .unwrap_or_else(|| TargetAddr::Domain(address.to_owned()));
        let Some(port) = object
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n != 0)
        else {
            self.error(
                format!("{path}.port"),
                "downloadSettings requires a port between 1 and 65535",
            );
            return None;
        };
        // Validate selection before parsing another stream; only XHTTP owns a
        // download request and no unrelated transport may silently consume it.
        let selected = object
            .get("method")
            .filter(|v| !v.is_null())
            .or_else(|| object.get("network"));
        if !matches!(
            selected
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("xhttp" | "splithttp")
        ) {
            self.error(
                format!("{path}.network"),
                "downloadSettings requires network xhttp or splithttp",
            );
            return None;
        }
        let mut stream = object.clone();
        stream.remove("address");
        stream.remove("port");
        let outbound = serde_json::json!({"streamSettings": stream});
        let start = self.diagnostics.len();
        self.parsing_xhttp_download = true;
        let parsed = self.parse_stream_settings(&outbound, index);
        self.parsing_xhttp_download = false;
        let prefix = format!("$.outbounds[{index}].streamSettings");
        for diagnostic in &mut self.diagnostics[start..] {
            if let Some(suffix) = diagnostic
                .path
                .as_deref()
                .and_then(|p| p.strip_prefix(&prefix))
            {
                diagnostic.path = Some(format!("{path}{suffix}"));
            }
        }
        Some(crate::XhttpDownloadSettings {
            address,
            port,
            stream: parsed?,
        })
    }
}

pub(super) fn download_path(stream: Option<&Value>, index: usize) -> String {
    let key = if stream
        .and_then(|s| s.get("xhttpSettings"))
        .is_some_and(|v| !v.is_null())
    {
        "xhttpSettings"
    } else {
        "splithttpSettings"
    };
    let extra = if stream
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("extra"))
        .is_some()
    {
        ".extra"
    } else {
        ""
    };
    format!("$.outbounds[{index}].streamSettings.{key}{extra}.downloadSettings")
}
