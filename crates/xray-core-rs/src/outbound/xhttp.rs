//! Compilation and opening of independently owned XHTTP carriers.
use super::*;
use xray_transport::stream::XhttpConnectTarget;

#[derive(Debug)]
pub(super) struct XhttpDownloadOutbound {
    server: Target,
    connector: ConnectorConfig,
    transport: XhttpTransport,
    happy_eyeballs: Option<HappyEyeballsConfig>,
}

pub(super) fn build_vless_connector(
    security: &StreamSecurity,
    destination: &TargetAddr,
) -> ConnectorConfig {
    match security {
        StreamSecurity::None => ConnectorConfig::Tcp,
        StreamSecurity::Tls(tls) => {
            let server_name = match tls.server_name.as_deref() {
                Some(name) if !name.is_empty() => name.to_owned(),
                Some(_) | None => match destination {
                    TargetAddr::Domain(domain) => domain.clone(),
                    TargetAddr::Ip(ip) => ip.to_string(),
                },
            };

            ConnectorConfig::Tls(TlsClientConfig {
                server_name,
                allow_insecure: tls.allow_insecure,
                pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                alpn: tls.alpn.clone(),
                fingerprint: tls.fingerprint.clone(),
            })
        }
        StreamSecurity::Reality(reality) => ConnectorConfig::Reality(RealityClientConfig {
            server_name: reality.server_name.clone(),
            fingerprint: reality.fingerprint.clone(),
            public_key: reality.public_key,
            short_id: reality.short_id.as_slice().to_vec(),
            spider_x: reality.spider_x.clone(),
            mldsa65_verify: reality.mldsa65_verify.clone(),
        }),
    }
}

pub(super) fn build_xhttp_download(
    outbound: &OutboundConfig,
) -> Result<Option<XhttpDownloadOutbound>, CoreError> {
    let StreamTransport::Xhttp(up) = &outbound.stream.transport else {
        return Ok(None);
    };
    let Some(download) = &up.download else {
        return Ok(None);
    };
    let StreamTransport::Xhttp(settings) = &download.stream.transport else {
        return Err(invalid_xhttp_configuration(
            "downloadSettings requires XHTTP",
        ));
    };
    if settings.download.is_some()
        || up.mode == xray_config::XhttpMode::StreamOne
        || download.port == 0
        || download.stream.network != Network::Tcp
    {
        return Err(invalid_xhttp_configuration(
            "invalid nested downloadSettings or stream-one combination",
        ));
    }
    if outbound.stream.security != StreamSecurity::None
        && download.stream.security == StreamSecurity::None
    {
        return Err(invalid_xhttp_configuration(
            "protected upload cannot use plaintext download",
        ));
    }
    if let OutboundSettings::Vless(vless) = &outbound.settings {
        if download.stream.security == StreamSecurity::None
            && vless.users.first().is_none_or(|u| u.encryption.is_none())
            && !download.address.is_xray_plaintext_server_exempt()
        {
            return Err(invalid_xhttp_configuration(
                "unencrypted VLESS download requires a private or test server",
            ));
        }
    }
    if matches!(&download.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure) {
        return Err(invalid_xhttp_configuration(
            "downloadSettings cannot disable TLS authentication",
        ));
    }
    let addr = match &download.address {
        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
        TargetAddr::Domain(domain) if !domain.is_empty() => {
            RoutingTargetAddr::Domain(domain.clone())
        }
        _ => {
            return Err(invalid_xhttp_configuration(
                "downloadSettings address is empty",
            ))
        }
    };
    Ok(Some(XhttpDownloadOutbound {
        server: Target::new(addr, download.port, RoutingNetwork::Tcp),
        connector: build_vless_connector(&download.stream.security, &download.address),
        transport: build_xhttp_transport(
            settings,
            &download.stream.security,
            &download.address,
            download.stream.quic_params.as_ref(),
        )?,
        happy_eyeballs: happy_eyeballs_config(&download.stream),
    }))
}

pub(super) async fn resolve_xhttp_download(
    outbound: &VlessTcpOutbound,
    resolver: &dyn DnsResolver,
) -> Result<Vec<SocketAddr>, CoreError> {
    match &outbound.payload.download {
        Some(down) => resolve_server_candidates(&down.server, resolver).await,
        None => Ok(Vec::new()),
    }
}

pub(super) async fn open_vless_carrier(
    outbound: &VlessTcpOutbound,
    candidates: &[SocketAddr],
    download_candidates: &[SocketAddr],
    dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    if let Some(down) = &outbound.payload.download {
        let TransportLayer::Xhttp(up) = outbound.transport_layer() else {
            return Err(invalid_xhttp_configuration(
                "split download requires XHTTP upload",
            ));
        };
        return up
            .open_split_stream(
                dialer,
                XhttpConnectTarget {
                    connector: outbound.transport(),
                    target: outbound.server(),
                    candidates,
                    happy_eyeballs: outbound.happy_eyeballs(),
                },
                &down.transport,
                XhttpConnectTarget {
                    connector: &down.connector,
                    target: &down.server,
                    candidates: download_candidates,
                    happy_eyeballs: down.happy_eyeballs.as_ref(),
                },
            )
            .await
            .map_err(|e| CoreError::from(TransportError::Xhttp(e.to_string())));
    }
    Ok(dialer
        .connect_stream(
            outbound.transport(),
            outbound.transport_layer(),
            outbound.server(),
            candidates,
            outbound.happy_eyeballs(),
        )
        .await?)
}

pub(super) fn build_xhttp_transport(
    settings: &XhttpSettings,
    security: &StreamSecurity,
    destination: &TargetAddr,
    quic_params: Option<&QuicParamsSettings>,
) -> Result<XhttpTransport, CoreError> {
    let http_version = xhttp_http_version(security)?;
    let endpoint = xhttp_endpoint(settings, security, destination)?;
    let config = xhttp_config(settings, matches!(security, StreamSecurity::Reality(_)))?;
    let xmux = xhttp_xmux_policy(settings);
    let h3_quic = if http_version == XhttpHttpVersion::Http3 {
        xhttp_h3_quic_config(quic_params)?
    } else {
        // Xray retains finalmask.quicParams in every stream config but only
        // consults it after exact `alpn: ["h3"]` selected the UDP path.
        H3QuicConfig::default()
    };

    XhttpTransport::new_with_h3_quic(config, endpoint, http_version, xmux, h3_quic)
        .map_err(invalid_xhttp_configuration)
}

/// Xray's `decideHTTPVersion` decision, before a socket is opened.
///
/// HTTP/3 changes the destination to UDP inside the transport dialer. Every
/// other TLS list follows Xray's HTTP/2 branch, including an empty or
/// multi-value list; REALITY is always HTTP/2.
pub(super) fn xhttp_http_version(security: &StreamSecurity) -> Result<XhttpHttpVersion, CoreError> {
    match security {
        StreamSecurity::None => Ok(XhttpHttpVersion::Http1),
        StreamSecurity::Reality(_) => Ok(XhttpHttpVersion::Http2),
        StreamSecurity::Tls(tls) => match tls.alpn.as_slice() {
            [only] if only == "http/1.1" => Ok(XhttpHttpVersion::Http1),
            [only] if only == "h3" => Ok(XhttpHttpVersion::Http3),
            _ => Ok(XhttpHttpVersion::Http2),
        },
    }
}

/// Resolves XHTTP's request URL endpoint.
///
/// The native Xray HTTP client fixes the dial destination in its custom
/// dialer and does not append the VLESS destination port to `URL.Host`.
/// Non-default ports are appended only by Xray's optional browser dialer,
/// which this runtime does not use. A port explicitly written in
/// `xhttpSettings.host` remains part of the authority.
pub(super) fn xhttp_endpoint(
    settings: &XhttpSettings,
    security: &StreamSecurity,
    destination: &TargetAddr,
) -> Result<XhttpEndpoint, CoreError> {
    let scheme = match security {
        StreamSecurity::None => XhttpScheme::Http,
        StreamSecurity::Tls(_) | StreamSecurity::Reality(_) => XhttpScheme::Https,
    };
    let authority = settings
        .host
        .as_deref()
        .filter(|host| !host.is_empty())
        .or_else(|| match security {
            StreamSecurity::Tls(tls) => tls
                .server_name
                .as_deref()
                .filter(|server_name| !server_name.is_empty()),
            StreamSecurity::Reality(reality) => {
                (!reality.server_name.is_empty()).then_some(reality.server_name.as_str())
            }
            StreamSecurity::None => None,
        })
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| xhttp_destination_authority(destination));

    XhttpEndpoint::new(scheme, authority).map_err(invalid_xhttp_configuration)
}

pub(super) fn xhttp_destination_authority(destination: &TargetAddr) -> String {
    match destination {
        TargetAddr::Domain(domain) => domain.clone(),
        TargetAddr::Ip(ip) => match ip.to_canonical() {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        },
    }
}

pub(super) fn xhttp_config(
    settings: &XhttpSettings,
    is_reality: bool,
) -> Result<XhttpConfig, CoreError> {
    let mut headers = HeaderMap::new();
    for (name, value) in &settings.headers {
        // Xray feeds the protobuf map through `http.Header.Add`. The JSON map
        // can contain keys which differ only by case; config parsing MIME-
        // canonicalizes both, so appending is what preserves both values.
        headers.add(name, value);
    }

    // `noSSEHeader` and `serverMaxHeaderBytes` are deliberately absent. Both
    // are inbound/server-only in Xray: the former changes hub response
    // headers, while the latter caps listener request heads. The H1/H2 client
    // engines retain their independent defensive 10 MiB response-head cap.
    XhttpConfig::normalize(XhttpConfigInput {
        mode: if is_reality
            && settings.download.is_some()
            && settings.mode == xray_config::XhttpMode::Auto
        {
            XhttpModeSelection::StreamUp
        } else {
            xhttp_mode_selection(settings.mode)
        },
        is_reality,
        path: settings.path.clone(),
        headers,
        x_padding_bytes: xhttp_range(settings.x_padding_bytes),
        x_padding_obfs_mode: settings.x_padding_obfs_mode,
        x_padding_key: settings.x_padding_key.clone(),
        x_padding_header: settings.x_padding_header.clone(),
        x_padding_placement: xhttp_padding_placement(settings.x_padding_placement),
        x_padding_method: xhttp_padding_method(settings.x_padding_method),
        uplink_http_method: settings.uplink_http_method.clone(),
        session_placement: xhttp_metadata_placement(settings.session_placement),
        session_key: settings.session_key.clone(),
        session_id_table: settings.session_id_table.clone(),
        session_id_length: xhttp_range(settings.session_id_length),
        seq_placement: xhttp_metadata_placement(settings.seq_placement),
        seq_key: settings.seq_key.clone(),
        uplink_data_placement: xhttp_uplink_data_placement(settings.uplink_data_placement),
        uplink_data_key: settings.uplink_data_key.clone(),
        uplink_chunk_size: xhttp_range(settings.uplink_chunk_size),
        no_grpc_header: settings.no_grpc_header,
        sc_max_each_post_bytes: xhttp_range(settings.sc_max_each_post_bytes),
        sc_min_posts_interval_ms: xhttp_range(settings.sc_min_posts_interval_ms),
        sc_max_buffered_posts: settings.sc_max_buffered_posts,
        sc_stream_up_server_secs: xhttp_range(settings.sc_stream_up_server_secs),
    })
    .map_err(invalid_xhttp_configuration)
}

pub(super) fn invalid_xhttp_configuration(error: impl ToString) -> CoreError {
    CoreError::InvalidXhttpConfiguration(error.to_string())
}

/// Maps Xray's QUIC surface into the phase-one HTTP/3 engine.
///
/// Defaults remain usable and interoperable, with the engine's diagnostics
/// naming its fixed-window and Quinn-BBR performance approximations. Explicit
/// UDP hopping, debug side-effects, adaptive receive-window pairs,
/// non-standard BBR profiles and Brutal are retained by the parser but
/// rejected by `H3QuicConfig` (or here) until their runtime implementation
/// exists.
pub(super) fn xhttp_h3_quic_config(
    settings: Option<&QuicParamsSettings>,
) -> Result<H3QuicConfig, CoreError> {
    let Some(settings) = settings else {
        return Ok(H3QuicConfig::default());
    };
    let mut config = H3QuicConfig::default();
    config.initial_stream_receive_window = quic_u64_or_default(
        "initStreamReceiveWindow",
        settings.init_stream_receive_window,
        config.initial_stream_receive_window,
    )?;
    config.max_stream_receive_window =
        quic_optional_u64("maxStreamReceiveWindow", settings.max_stream_receive_window)?;
    config.initial_connection_receive_window = quic_u64_or_default(
        "initConnectionReceiveWindow",
        settings.init_connection_receive_window,
        config.initial_connection_receive_window,
    )?;
    config.max_connection_receive_window = quic_optional_u64(
        "maxConnectionReceiveWindow",
        settings.max_connection_receive_window,
    )?;
    match settings.max_idle_timeout_secs {
        0 => {}
        value if value > 0 => {
            config.max_idle_timeout = Duration::from_secs(u64::try_from(value).map_err(|_| {
                CoreError::InvalidXhttpConfiguration(
                    "finalmask.quicParams.maxIdleTimeout is negative".to_owned(),
                )
            })?);
        }
        _ => {
            return Err(CoreError::InvalidXhttpConfiguration(
                "finalmask.quicParams.maxIdleTimeout is negative".to_owned(),
            ));
        }
    }
    config.keep_alive_interval = match settings.keep_alive_period_secs {
        0 => None,
        value if value > 0 => Some(Duration::from_secs(u64::try_from(value).map_err(|_| {
            CoreError::InvalidXhttpConfiguration(
                "finalmask.quicParams.keepAlivePeriod is negative".to_owned(),
            )
        })?)),
        _ => {
            return Err(CoreError::InvalidXhttpConfiguration(
                "finalmask.quicParams.keepAlivePeriod is negative".to_owned(),
            ));
        }
    };
    config.max_incoming_bidirectional_streams = quic_incoming_streams_or_default(
        "maxIncomingStreams",
        settings.max_incoming_streams,
        config.max_incoming_bidirectional_streams,
    )?;
    config.disable_path_mtu_discovery = settings.disable_path_mtu_discovery
        || !cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        ));
    config.congestion = match settings.congestion {
        xray_config::QuicCongestion::Reno => H3Congestion::Reno,
        xray_config::QuicCongestion::Brutal => H3Congestion::Brutal,
        xray_config::QuicCongestion::ForceBrutal => H3Congestion::ForceBrutal {
            bytes_per_second: settings.brutal_up_bytes_per_sec,
        },
        xray_config::QuicCongestion::Default | xray_config::QuicCongestion::Bbr => {
            match settings.bbr_profile {
                xray_config::QuicBbrProfile::Conservative => H3Congestion::BbrConservative,
                xray_config::QuicBbrProfile::Standard => H3Congestion::BbrStandard,
                xray_config::QuicBbrProfile::Aggressive => H3Congestion::BbrAggressive,
            }
        }
    };
    config.udp_hop = H3UdpHopConfig {
        ports: settings.udp_hop.ports.clone(),
        interval_min: quic_i32_seconds("udpHop.interval.from", settings.udp_hop.interval.from)?,
        interval_max: quic_i32_seconds("udpHop.interval.to", settings.udp_hop.interval.to)?,
    };
    config.debug = settings.debug;
    Ok(config)
}

pub(super) const QUIC_VARINT_MAX: u64 = (1_u64 << 62) - 1;
pub(super) const QUIC_MAX_STREAM_COUNT: u64 = 1_u64 << 60;

pub(super) fn quic_u64_or_default(
    name: &'static str,
    value: u64,
    default: u64,
) -> Result<u64, CoreError> {
    if value == 0 {
        Ok(default)
    } else {
        quic_varint(name, value)
    }
}

pub(super) fn quic_optional_u64(name: &'static str, value: u64) -> Result<Option<u64>, CoreError> {
    if value == 0 {
        Ok(None)
    } else {
        quic_varint(name, value).map(Some)
    }
}

pub(super) fn quic_varint(name: &'static str, value: u64) -> Result<u64, CoreError> {
    if value <= QUIC_VARINT_MAX {
        Ok(value)
    } else {
        Err(CoreError::InvalidXhttpConfiguration(format!(
            "finalmask.quicParams.{name}={value} exceeds QUIC's 62-bit varint limit"
        )))
    }
}

pub(super) fn quic_incoming_streams_or_default(
    name: &'static str,
    value: i64,
    default: u64,
) -> Result<u64, CoreError> {
    if value == 0 {
        return Ok(default);
    }
    let value = u64::try_from(value).map_err(|_| {
        CoreError::InvalidXhttpConfiguration(format!(
            "finalmask.quicParams.{name}={value} cannot be negative"
        ))
    })?;
    // quic-go clamps this transport parameter to the QUIC stream-count
    // domain during config validation. Mirror that instead of allowing Quinn
    // to emit a peer-invalid INITIAL_MAX_STREAMS value.
    Ok(value.min(QUIC_MAX_STREAM_COUNT))
}

pub(super) fn quic_i32_seconds(name: &'static str, value: i32) -> Result<Duration, CoreError> {
    let value = u64::try_from(value).map_err(|_| {
        CoreError::InvalidXhttpConfiguration(format!(
            "finalmask.quicParams.{name}={value} cannot be negative"
        ))
    })?;
    Ok(Duration::from_secs(value))
}

pub(super) fn xhttp_xmux_policy(settings: &XhttpSettings) -> XhttpXmuxPolicy {
    XhttpXmuxPolicy {
        max_concurrency: xhttp_range(settings.xmux.max_concurrency),
        max_connections: xhttp_range(settings.xmux.max_connections),
        c_max_reuse_times: xhttp_range(settings.xmux.c_max_reuse_times),
        h_max_request_times: xhttp_range(settings.xmux.h_max_request_times),
        h_max_reusable_secs: xhttp_range(settings.xmux.h_max_reusable_secs),
        h_keep_alive_period_secs: settings.xmux.h_keep_alive_period_secs,
    }
}

pub(super) const fn xhttp_range(range: xray_config::XhttpRange) -> XhttpRange {
    XhttpRange {
        from: range.from,
        to: range.to,
    }
}

pub(super) const fn xhttp_mode_selection(mode: xray_config::XhttpMode) -> XhttpModeSelection {
    match mode {
        xray_config::XhttpMode::Auto => XhttpModeSelection::Auto,
        xray_config::XhttpMode::PacketUp => XhttpModeSelection::PacketUp,
        xray_config::XhttpMode::StreamUp => XhttpModeSelection::StreamUp,
        xray_config::XhttpMode::StreamOne => XhttpModeSelection::StreamOne,
    }
}

pub(super) const fn xhttp_padding_placement(
    placement: xray_config::XhttpPaddingPlacement,
) -> XhttpPaddingPlacement {
    match placement {
        xray_config::XhttpPaddingPlacement::Cookie => XhttpPaddingPlacement::Cookie,
        xray_config::XhttpPaddingPlacement::Header => XhttpPaddingPlacement::Header,
        xray_config::XhttpPaddingPlacement::Query => XhttpPaddingPlacement::Query,
        xray_config::XhttpPaddingPlacement::QueryInHeader => XhttpPaddingPlacement::QueryInHeader,
    }
}

pub(super) const fn xhttp_padding_method(
    method: xray_config::XhttpPaddingMethod,
) -> XhttpPaddingMethod {
    match method {
        xray_config::XhttpPaddingMethod::RepeatX => XhttpPaddingMethod::RepeatX,
        xray_config::XhttpPaddingMethod::Tokenish => XhttpPaddingMethod::Tokenish,
    }
}

pub(super) const fn xhttp_metadata_placement(
    placement: xray_config::XhttpPlacement,
) -> XhttpMetadataPlacement {
    match placement {
        xray_config::XhttpPlacement::Path => XhttpMetadataPlacement::Path,
        xray_config::XhttpPlacement::Cookie => XhttpMetadataPlacement::Cookie,
        xray_config::XhttpPlacement::Header => XhttpMetadataPlacement::Header,
        xray_config::XhttpPlacement::Query => XhttpMetadataPlacement::Query,
    }
}

pub(super) const fn xhttp_uplink_data_placement(
    placement: xray_config::XhttpUplinkDataPlacement,
) -> XhttpUplinkDataPlacement {
    match placement {
        xray_config::XhttpUplinkDataPlacement::Auto => XhttpUplinkDataPlacement::Auto,
        xray_config::XhttpUplinkDataPlacement::Body => XhttpUplinkDataPlacement::Body,
        xray_config::XhttpUplinkDataPlacement::Cookie => XhttpUplinkDataPlacement::Cookie,
        xray_config::XhttpUplinkDataPlacement::Header => XhttpUplinkDataPlacement::Header,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn config() -> Value {
        json!({"outbounds":[{"tag":"split","protocol":"vless","settings":{"vnext":[{"address":"upload.test","port":443,"users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"downloadSettings":{"address":"download.test","port":8443,"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h3"]},"xhttpSettings":{"path":"/down"}}}}}]})
    }

    #[test]
    fn independent_download_compiles_its_own_destination_tls_http_and_pool() {
        let parsed = xray_config::parse_xray_json(&config().to_string()).unwrap();
        let outbound = build_vless_tcp_outbound(&parsed.config.outbounds[0]).unwrap();
        let down = outbound.payload.download.as_ref().unwrap();
        assert_eq!(down.server.port, 8443);
        assert_eq!(target_domain(&down.server), Some("download.test"));
        let ConnectorConfig::Tls(tls) = &down.connector else {
            panic!("TLS")
        };
        assert_eq!(tls.server_name, "download.test");
        assert_eq!(down.transport.http_version(), XhttpHttpVersion::Http3);
        let TransportLayer::Xhttp(up) = outbound.transport_layer() else {
            panic!("XHTTP")
        };
        assert_eq!(up.http_version(), XhttpHttpVersion::Http1);
        assert!(!up.shares_xmux_with(&down.transport));
    }

    #[test]
    fn reality_auto_selects_stream_up_only_when_download_is_present() {
        let parsed = xray_config::parse_xray_json(&config().to_string()).unwrap();
        let StreamTransport::Xhttp(mut settings) =
            parsed.config.outbounds[0].stream.transport.clone()
        else {
            panic!("XHTTP")
        };
        assert_eq!(
            xhttp_config(&settings, true).unwrap().mode,
            xray_transport::stream::XhttpMode::StreamUp
        );
        settings.download = None;
        assert_eq!(
            xhttp_config(&settings, true).unwrap().mode,
            xray_transport::stream::XhttpMode::StreamOne
        );
        assert_eq!(
            xhttp_config(&settings, false).unwrap().mode,
            xray_transport::stream::XhttpMode::PacketUp
        );
    }

    #[test]
    fn chain_rejects_split_download_as_both_entry_and_proxy_target() {
        for target in [false, true] {
            let mut config = config();
            let mut other = json!({"tag":"other","protocol":"freedom"});
            if target {
                other["proxySettings"] = json!({"tag":"split","transportLayer":true});
            } else {
                config["outbounds"][0]["proxySettings"] =
                    json!({"tag":"other","transportLayer":true});
            }
            config["outbounds"].as_array_mut().unwrap().push(other);
            let parsed = xray_config::parse_xray_json(&config.to_string()).unwrap();
            let router = OutboundRouter::new(Arc::new(parsed.config));
            assert!(router.graph().validate_proxy_chains().is_err());
        }
    }

    #[test]
    fn programmatic_configs_cannot_bypass_the_download_security_or_depth_contract() {
        for mutation in 0..5 {
            let parsed = xray_config::parse_xray_json(&config().to_string()).unwrap();
            let mut outbound = parsed.config.outbounds[0].clone();
            let StreamTransport::Xhttp(up) = &mut outbound.stream.transport else {
                panic!("XHTTP")
            };
            let down = up.download.as_mut().unwrap();
            match mutation {
                0 => down.port = 0,
                1 => down.stream.network = Network::Udp,
                2 => {
                    if let StreamSecurity::Tls(tls) = &mut down.stream.security {
                        tls.allow_insecure = true;
                    }
                }
                3 => {
                    let nested = down.clone();
                    let StreamTransport::Xhttp(settings) = &mut down.stream.transport else {
                        panic!("XHTTP")
                    };
                    settings.download = Some(nested);
                }
                4 => up.mode = xray_config::XhttpMode::StreamOne,
                _ => unreachable!(),
            }
            assert!(
                build_vless_tcp_outbound(&outbound).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[tokio::test]
    async fn failed_download_resolution_never_opens_the_upload_socket() {
        struct FailDownload;
        #[async_trait]
        impl DnsResolver for FailDownload {
            async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
                if domain == "download.test" {
                    Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
                } else {
                    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
                }
            }
        }
        struct RejectSocket;
        impl xray_transport::SocketProtector for RejectSocket {
            fn protect(&self, _: xray_transport::SocketHandle) -> io::Result<()> {
                panic!("DNS failure must precede both socket dials")
            }
        }
        let parsed = xray_config::parse_xray_json(&config().to_string()).unwrap();
        let outbound = build_vless_tcp_outbound(&parsed.config.outbounds[0]).unwrap();
        let dialer =
            TransportDialer::system_with_socket_protector(Some(Arc::new(RejectSocket))).unwrap();
        let target = Target::new(
            RoutingTargetAddr::Ip(std::net::Ipv4Addr::LOCALHOST.into()),
            80,
            RoutingNetwork::Tcp,
        );
        let result = open_vless_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &FailDownload,
            &dialer,
        )
        .await;
        assert!(matches!(result, Err(CoreError::Transport(_))));
    }
}
