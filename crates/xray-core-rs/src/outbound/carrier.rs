//! Shared endpoint, authenticated connector and stream transport compilation.
use super::*;
use xray_transport::stream::XhttpConnectTarget;

#[derive(Clone, Copy)]
pub(super) struct ServerConfigPaths {
    pub(super) address: &'static str,
    pub(super) endpoint: &'static str,
}
pub(super) const VLESS_PATHS: ServerConfigPaths = ServerConfigPaths {
    address: "settings.vnext[0].address",
    endpoint: "settings.vnext[0].address and settings.vnext[0].port",
};
pub(super) const TROJAN_PATHS: ServerConfigPaths = ServerConfigPaths {
    address: "settings.address or settings.servers[0].address",
    endpoint: "settings.address/port or settings.servers[0].address/port",
};

#[derive(Debug)]
pub(super) struct StreamCarrier {
    pub(super) server: Target,
    pub(super) transport: ConnectorConfig,
    pub(super) transport_layer: TransportLayer,
    pub(super) download: Option<XhttpDownloadOutbound>,
    pub(super) happy_eyeballs: Option<HappyEyeballsConfig>,
    pub(super) fragment: Option<Arc<xray_transport::TcpFragmentConfig>>,
}

impl StreamCarrier {
    pub(super) fn new(
        stream: &StreamSettings,
        server: &TargetAddr,
        port: u16,
        unencrypted_payload: bool,
        paths: ServerConfigPaths,
    ) -> Result<Self, CoreError> {
        if stream.network != Network::Tcp {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let fragment = fragment_config(stream)?;
        let transport = build_connector(&stream.security, server);
        let transport_layer = build_transport_layer(stream, server, port, &transport, paths)?;
        if fragment.is_some()
            && (matches!(transport, ConnectorConfig::Tcp)
                || matches!(&transport_layer, TransportLayer::Xhttp(xhttp) if xhttp.http_version() == XhttpHttpVersion::Http3)
                || matches!(&stream.transport, StreamTransport::Xhttp(xhttp) if xhttp.download.is_some()))
        {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let addr = match server {
            TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
            TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
        };
        Ok(Self {
            server: Target::new(addr, port, RoutingNetwork::Tcp),
            transport_layer,
            fragment,
            transport,
            download: build_xhttp_download(stream, unencrypted_payload)?,
            happy_eyeballs: happy_eyeballs_config(stream),
        })
    }
    pub(super) async fn resolve_download(
        &self,
        resolver: &dyn DnsResolver,
    ) -> Result<Vec<SocketAddr>, CoreError> {
        match &self.download {
            Some(down) => resolve_server_candidates(&down.server, resolver).await,
            None => Ok(Vec::new()),
        }
    }

    pub(super) async fn open(
        &self,
        candidates: &[SocketAddr],
        download_candidates: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        let fragmented_dialer = self
            .fragment
            .as_ref()
            .map(|fragment| dialer.clone().with_tcp_fragment(fragment.clone()));
        let dialer = fragmented_dialer.as_ref().unwrap_or(dialer);
        if let Some(down) = &self.download {
            let TransportLayer::Xhttp(up) = &self.transport_layer else {
                return Err(invalid_xhttp_configuration(
                    "split download requires XHTTP upload",
                ));
            };
            return up
                .open_split_stream(
                    dialer,
                    XhttpConnectTarget {
                        connector: &self.transport,
                        target: &self.server,
                        candidates,
                        happy_eyeballs: self.happy_eyeballs.as_ref(),
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
                &self.transport,
                &self.transport_layer,
                &self.server,
                candidates,
                self.happy_eyeballs.as_ref(),
            )
            .await?)
    }
}

pub(super) fn build_connector(
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

/// Resolves the config's transport into the dial-ready one.
///
/// WebSocket and HTTPUpgrade's `Host` header follows Xray's precedence -- the
/// transport's own `host`, else the TLS/REALITY server name, else the
/// destination address -- and never carries a port. XHTTP resolves the same
/// sources separately below because its scheme, authority validation, and
/// native-client port rule belong to its request URL.
///
/// gRPC's `:authority` looks like the same question and is not: it has its own
/// chain, its own view of REALITY, and a fallback that does carry the port.
/// [`grpc_authority`] has it, and `host_fallback` below is the wrong answer to
/// it in three separate ways.
fn build_transport_layer(
    stream: &StreamSettings,
    server: &TargetAddr,
    port: u16,
    connector: &ConnectorConfig,
    paths: ServerConfigPaths,
) -> Result<TransportLayer, CoreError> {
    let host_fallback = || match connector {
        ConnectorConfig::Tls(tls) if !tls.server_name.is_empty() => tls.server_name.clone(),
        ConnectorConfig::Reality(reality) if !reality.server_name.is_empty() => {
            reality.server_name.clone()
        }
        _ => match server {
            TargetAddr::Domain(domain) => domain.clone(),
            TargetAddr::Ip(ip) => ip.to_string(),
        },
    };

    Ok(match &stream.transport {
        StreamTransport::Raw => TransportLayer::Raw,
        StreamTransport::Hysteria(_) => return Err(CoreError::UnsupportedOutboundNetwork),
        StreamTransport::WebSocket(websocket) => TransportLayer::WebSocket(WebSocketConfig {
            path: websocket.path.clone(),
            host: websocket.host.clone().unwrap_or_else(host_fallback),
            headers: websocket.headers.clone(),
            early_data_bytes: websocket.early_data_bytes,
            heartbeat_period_secs: websocket.heartbeat_period_secs,
        }),
        StreamTransport::HttpUpgrade(upgrade) => TransportLayer::HttpUpgrade(HttpUpgradeConfig {
            path: upgrade.path.clone(),
            host: upgrade.host.clone().unwrap_or_else(host_fallback),
            headers: upgrade.headers.clone(),
        }),
        StreamTransport::Grpc(grpc) => TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
            service_name: grpc.service_name.clone(),
            multi_mode: grpc.multi_mode,
            authority: grpc_authority(
                grpc.authority.as_deref(),
                &stream.security,
                server,
                port,
                paths,
            )?,
            user_agent: grpc_user_agent(grpc.user_agent.as_deref())?,
            idle_timeout_secs: grpc.idle_timeout_secs,
            health_check_timeout_secs: grpc.health_check_timeout_secs,
            permit_without_stream: grpc.permit_without_stream,
            initial_windows_size: grpc.initial_windows_size,
        })),
        StreamTransport::Xhttp(xhttp) => TransportLayer::Xhttp(build_xhttp_transport(
            xhttp,
            &stream.security,
            server,
            stream.quic_params.as_ref(),
        )?),
    })
}

// The config keys the derived half of the `:authority` chain can come from, as
// `CoreError::UnrepresentableGrpcAuthority` names them.
//
// Spelled as the paths the config parser reports its own errors under — the
// address key verbatim (`crates/xray-config/src/parser.rs:2440`), and the TLS
// server name as the object path the parser uses plus the key it accepts
// inside it (`parser.rs:3211,3220`) — minus the `$.outbounds[N]` prefix this
// layer no longer knows, so the message is something to search a profile for
// rather than a description of it. `realitySettings.serverName` is not among
// them on purpose: `dial.go:162` never reads it, for the reason `grpc_authority`
// gives.
//
// `SERVER_ENDPOINT_KEYS` names a pair because the last-resort branch *composes*
// its value out of two keys, and printing one of them next to `例え.jp:443`
// would send the user looking for a `:443` that key does not hold.
const TLS_SERVER_NAME_KEY: &str = "streamSettings.tlsSettings.serverName";

/// The `:authority` one gRPC outbound dials with.
///
/// Xray's chain is `grpcSettings.authority`, else `tlsSettings.serverName`,
/// else the destination *domain* and only when REALITY is absent, else the
/// empty string (`Xray-core/transport/internet/grpc/dial.go:159-167`).
///
/// **Three ways this differs from `build_transport_layer`'s `host_fallback`**,
/// which resolves the `Host` header for ws and httpupgrade and is the obvious
/// thing to reuse here:
///
/// * REALITY's server name is not in the chain. `dial.go:162` reads
///   `tlsConfig.ServerName`, and `tls.ConfigFromStreamSettings` returns nil for
///   a REALITY stream because the type assertion on `SecuritySettings` fails
///   (`transport/internet/tls/config.go:510-519`), so under REALITY the whole
///   branch is skipped rather than answered with the REALITY SNI.
/// * The destination branch needs the destination to be a domain. An IP one
///   leaves the authority empty even with no REALITY in sight.
/// * **The empty string is not an omitted header.** `initAuthority` walks past
///   the dial option to the transport credentials, and Xray's are
///   `insecure.NewCredentials()` (`dial.go:157`), whose `Info().ServerName` is
///   empty (`grpc@v1.81.0/credentials/insecure/insecure.go:51-53`); the
///   passthrough resolver is no `AuthorityOverrider` either, so the chain ends
///   at `encodeAuthority(endpoint)` (`clientconn.go:1976-1986`) over the target
///   Xray built as `passthrough:///host:port` (`dial.go:181-191`) — port
///   included. Verified on the wire against grpc-go v1.81.0 for a domain, an
///   IPv4 and an IPv6 destination. `encodeAuthority` leaves `:`, `[`, `]` and
///   `@` unescaped (`clientconn.go:1889-1942`), which is why an IPv6 literal
///   keeps its brackets instead of arriving as `%5B`. Under REALITY this
///   fallback is the default path, not an edge case.
///
/// **The parse is split between the configured value and the derived ones**,
/// because refusing an outbound over them is two different acts.
///
/// `grpcSettings.authority` is a string the user typed, and refusing it is the
/// better of two bad options: [`xray_transport::stream::GrpcConfig::authority`]
/// has the reasoning, which is that a `/` in it silently calls a gRPC method
/// nobody configured. They can fix what they typed.
///
/// The other three are values *we* derive on their behalf, and
/// `CoreError::InvalidGrpcAuthority` over one of those would blame a key their
/// config does not contain. They get
/// [`CoreError::UnrepresentableGrpcAuthority`], which names the key that
/// actually produced the value.
///
/// **Both still refuse, because nothing else is reachable.** An IDN
/// destination is the case that provokes the question — `Authority` rejects
/// every byte above `0x7f` (`http-1.5.0/src/uri/authority.rs:493-516`), and
/// grpc-go sends `例え.jp` verbatim, verified on the wire against v1.81.0 — and
/// none of the alternatives survive contact with it:
///
/// * **Falling through the chain does not rescue it, it moves it.** The step
///   after the destination domain is [`host_and_port`], which is that same
///   domain with a `:443` appended, so it fails identically. The step after
///   `tlsSettings.serverName` is the destination, which would answer — with a
///   *different* authority than Xray sends, on a stream whose TLS layer is
///   about to refuse the same name anyway (`TransportError::InvalidTlsServerName`).
///   Sending the wrong authority to buy one extra failed handshake is not a
///   trade worth making.
/// * **Carrying it as a `String` only relocates the refusal.** `h2` reads
///   `:authority` out of `Request::uri()` and nowhere else
///   (`h2-0.4.15/src/frame/headers.rs:561-604`, `src/client.rs:1604-1664`), and
///   an `http::Uri`'s authority *is* an [`Authority`]. A value this rejects is
///   one no request can carry, so the only thing deferring the parse buys is
///   the same failure once per dial, each behind a TCP connect and a TLS or
///   REALITY handshake.
/// * **Reproducing grpc-go's escaping does not help either.** `encodeAuthority`
///   percent-escapes the `host:port` fallback, so upstream really does put
///   `%E4%BE%8B%E3%81%88.jp:443` on the wire for an IDN destination under
///   REALITY — also verified — and that form is *pure ASCII*. It still will not
///   parse: `http` allows `%` only in userinfo or an IPv6 zone id and rejects
///   it in a host (`authority.rs:503-514,564-567`).
/// * **The IDNA A-label is the one form that would parse, and nothing here can
///   build it.** `Authority::try_from("xn--r8jz45g.jp")` is `Ok` where the raw
///   `例え.jp` is `InvalidUriChar` and grpc-go's escaping is
///   `InvalidAuthority`, all three checked against `http` 1.5.0 — so punycode
///   is a real escape hatch and it is still not reachable: no `idna` crate
///   appears anywhere in this workspace's dependency graph. Adding one to
///   convert silently would put an authority on the wire that upstream does
///   not send, and under TLS the same name is refused a layer down regardless,
///   since an IDN is not a rustls `ServerName` either
///   (`crates/xray-transport/src/tls.rs:220`). A profile that wants the
///   A-label can write it, and that already works.
///
/// So an IDN gRPC profile runs on xray-core and does not run here. That is a
/// real parity gap, and it is a property of `http`/`h2`, not of this function;
/// what this function owes the user is a message that names the address they
/// wrote instead of a key they did not.
fn grpc_authority(
    configured: Option<&str>,
    security: &StreamSecurity,
    server: &TargetAddr,
    port: u16,
    paths: ServerConfigPaths,
) -> Result<Authority, CoreError> {
    // The config layer has already collapsed an empty `authority` to `None`,
    // matching Go's inability to tell one from an absent key.
    if let Some(configured) = configured {
        return Authority::try_from(configured)
            .map_err(|_| CoreError::InvalidGrpcAuthority(configured.to_owned()));
    }

    let (key, derived) = match configured_tls_server_name(security) {
        Some(server_name) => (TLS_SERVER_NAME_KEY, server_name.to_owned()),
        None => match server {
            TargetAddr::Domain(domain) if !matches!(security, StreamSecurity::Reality(_)) => {
                (paths.address, domain.clone())
            }
            _ => (paths.endpoint, host_and_port(server, port)),
        },
    };

    Authority::try_from(derived.as_str()).map_err(|_| CoreError::UnrepresentableGrpcAuthority {
        key,
        value: derived,
    })
}

/// The `user-agent` one gRPC outbound sends, through Xray's keyword table.
///
/// A wrapper over [`resolve_user_agent`] and not much else: what it adds is the
/// error, and the error is the reason the resolution happens here rather than
/// at the dial. [`xray_transport::stream::GrpcConfig::user_agent`] has why the
/// value is refused at all — measured against grpc-go rather than reasoned
/// about, and the short version is that every value refused here is a value
/// whose every stream a grpc-go peer resets, so no profile that ran upstream
/// stops running.
///
/// **Only [`CoreError::InvalidGrpcUserAgent`] and no derived-value twin**,
/// which is where this parts company with [`grpc_authority`]. That chain has
/// two error variants because three of its four branches produce a value the
/// user never typed, and blaming `grpcSettings.authority` for the destination
/// address would send them looking for a key their config does not hold. This
/// one has no such branch: the three browser keywords resolve through the
/// masquerade table to printable ASCII and `golang` to the empty string, so
/// the only arm that can fail is the one that hands back the configured string
/// verbatim. Naming the key is therefore always right, and the value in the
/// message is always one they can search their profile for.
fn grpc_user_agent(configured: Option<&str>) -> Result<HeaderValue, CoreError> {
    resolve_user_agent(configured)
        .map_err(|_| CoreError::InvalidGrpcUserAgent(configured.unwrap_or_default().to_owned()))
}

/// `tlsSettings.serverName`, read from the config the way `dial.go:162` reads
/// it and not from the connector this outbound was built with.
///
/// The distinction has no effect on the resolved authority and every effect on
/// which key gets blamed for it. `ConnectorConfig::Tls::server_name` is already
/// the destination domain when the key is absent — `build_vless_tcp_outbound`
/// substitutes it — where Xray's `tls.ConfigFromStreamSettings` hands
/// `dial.go:162` the raw proto field, which is empty; the mutation that copies
/// the domain in happens later, inside the dial closure, on a `*gotls.Config`
/// the authority chain never sees (`dial.go:136-142`). Reading the connector
/// therefore answers branch 2 with a value upstream answers branch 3 with,
/// which is the same string, from a key the user may never have written. The
/// difference is only observable once that key reaches a message, which is the
/// last row of `a_derived_authority_is_not_refused_as_the_configured_one`.
///
/// The distinction becomes visible for a TLS stream over an IP destination:
/// the connector carries that IP for certificate-name verification, while
/// upstream gRPC still sees the raw absent/empty setting and falls through to
/// `host:port`. Reading this function from the config preserves that split.
fn configured_tls_server_name(security: &StreamSecurity) -> Option<&str> {
    match security {
        StreamSecurity::Tls(tls) => tls
            .server_name
            .as_deref()
            .filter(|server_name| !server_name.is_empty()),
        StreamSecurity::None | StreamSecurity::Reality(_) => None,
    }
}

/// grpc-go's resolver-endpoint fallback, i.e. Go's `net.JoinHostPort` over the
/// destination — which brackets an IPv6 literal, as `SocketAddr` does.
///
/// `to_canonical` is what makes the IPv4-mapped case agree: Go builds the host
/// from `dest.Address.IP().String()` (`dial.go:181-186`), and `net.IP.String`
/// writes a 16-byte address whose `To4()` matches as a dotted quad, where
/// Rust's `Display` would keep `::ffff:`. Both fold exactly the v4-mapped
/// prefix and nothing else, so the two agree everywhere once this is applied.
fn host_and_port(server: &TargetAddr, port: u16) -> String {
    match server {
        TargetAddr::Domain(domain) => format!("{domain}:{port}"),
        TargetAddr::Ip(ip) => SocketAddr::new(ip.to_canonical(), port).to_string(),
    }
}

pub(super) fn fragment_config(
    stream: &StreamSettings,
) -> Result<Option<Arc<xray_transport::TcpFragmentConfig>>, CoreError> {
    stream
        .tcp_fragment
        .as_ref()
        .map(|settings| {
            xray_transport::TcpFragmentConfig::new(
                settings.lengths.iter().map(|r| r.from..=r.to).collect(),
                settings.delays_ms.iter().map(|r| r.from..=r.to).collect(),
                settings.max_split.from..=settings.max_split.to,
            )
            .map(Arc::new)
            .map_err(|_| CoreError::UnsupportedOutboundNetwork)
        })
        .transpose()
}
