use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_config::{
    CoreConfig, Network, OutboundConfig, OutboundSettings, RoutingDomainStrategy, StreamSecurity,
    TargetAddr, VlessUser,
};
use xray_proxy::vless::{
    encode_request_header, VisionStream, VisionStreamIo, VlessCommand, VlessRequest,
    VlessResponseStream,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, RealityClientConfig, SystemDnsResolver,
    TlsClientConfig, TransportDialer, TransportStream,
};

use crate::CoreError;

const VISION_FLOW: &str = "xtls-rprx-vision";
const VISION_UDP443_FLOW: &str = "xtls-rprx-vision-udp443";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisionFlow {
    None,
    Vision,
    VisionUdp443,
}

impl VisionFlow {
    fn uses_vision(self) -> bool {
        matches!(self, Self::Vision | Self::VisionUdp443)
    }

    fn allows_udp443(self) -> bool {
        matches!(self, Self::VisionUdp443)
    }

    fn request_flow(self) -> Option<String> {
        self.uses_vision().then(|| VISION_FLOW.to_owned())
    }
}

struct VlessOutboundStream {
    inner: VlessResponseStream<BoxedTransportStream>,
}

impl VlessOutboundStream {
    fn new(inner: VlessResponseStream<BoxedTransportStream>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for VlessOutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for VlessOutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl TransportStream for VlessOutboundStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

struct VisionTransportStream {
    inner: BoxedTransportStream,
}

impl VisionTransportStream {
    fn new(inner: BoxedTransportStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for VisionTransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for VisionTransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl VisionStreamIo for VisionTransportStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read_direct(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown_direct(cx)
    }
}

struct VisionOutboundStream {
    inner: VisionStream<VlessResponseStream<VisionTransportStream>>,
}

impl VisionOutboundStream {
    fn new(inner: VisionStream<VlessResponseStream<VisionTransportStream>>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for VisionOutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for VisionOutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl TransportStream for VisionOutboundStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

#[derive(Debug, Clone)]
pub struct VlessTcpOutbound {
    server: Target,
    user: VlessUser,
    transport: ConnectorConfig,
}

#[derive(Debug, Clone)]
pub enum TcpOutbound {
    Freedom,
    Vless(Box<VlessTcpOutbound>),
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedTcpOutbound {
    pub(crate) outbound: TcpOutbound,
    pub(crate) tag: Option<String>,
}

#[derive(Debug, Clone)]
pub enum UdpOutbound {
    Freedom,
    Vless(Box<VlessTcpOutbound>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessUdpFraming {
    LengthPrefixed,
    Xudp,
}

impl VlessTcpOutbound {
    pub fn server(&self) -> &Target {
        &self.server
    }

    pub fn transport(&self) -> &ConnectorConfig {
        &self.transport
    }

    pub fn user(&self) -> &VlessUser {
        &self.user
    }

    /// True for the regular `xtls-rprx-vision` flow, which (matching upstream
    /// xray-core) cannot carry UDP/443 and must refuse it so QUIC apps fall back
    /// to TCP. The `xtls-rprx-vision-udp443` variant returns false.
    pub(crate) fn blocks_udp443(&self) -> bool {
        validate_connector_flow(self.user.flow.as_deref(), &self.transport)
            .map(|flow| flow.uses_vision() && !flow.allows_udp443())
            .unwrap_or(false)
    }
}

pub fn select_tcp_outbound(config: &CoreConfig) -> Result<TcpOutbound, CoreError> {
    let outbound = select_configured_outbound(config, None, None, None)?;
    build_tcp_outbound(outbound)
}

#[allow(dead_code)]
pub(crate) fn select_tcp_outbound_direct(
    config: &CoreConfig,
    outbound_tag: Option<&str>,
) -> Result<TcpOutbound, CoreError> {
    let outbound = select_configured_outbound_direct(config, outbound_tag)?;
    build_tcp_outbound(outbound)
}

/// Selects a session outbound using only the original target metadata.
///
/// Runtime paths that need `routing.domainStrategy = IPIfNonMatch` should use
/// `select_tcp_outbound_for_session_with_resolver` so DNS-based second-pass
/// routing can run.
pub fn select_tcp_outbound_for_session(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
) -> Result<TcpOutbound, CoreError> {
    let outbound = select_configured_outbound(
        config,
        inbound_tag,
        target_domain(target),
        target_ip(target),
    )?;
    build_tcp_outbound(outbound)
}

pub async fn select_tcp_outbound_for_session_with_resolver(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<TcpOutbound, CoreError> {
    let outbound =
        select_configured_outbound_with_resolver(config, inbound_tag, target, dns_resolver).await?;
    build_tcp_outbound(outbound)
}

pub(crate) async fn select_tcp_outbound_for_session_with_tag_and_resolver(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    include_tag: bool,
    dns_resolver: &dyn DnsResolver,
) -> Result<SelectedTcpOutbound, CoreError> {
    let outbound =
        select_configured_outbound_with_resolver(config, inbound_tag, target, dns_resolver).await?;
    let tag = include_tag.then(|| outbound.tag.clone()).flatten();
    let outbound = build_tcp_outbound(outbound)?;
    Ok(SelectedTcpOutbound { outbound, tag })
}

/// Selects a UDP session outbound using only the original target metadata.
///
/// Runtime paths that need `routing.domainStrategy = IPIfNonMatch` should use
/// `select_udp_outbound_for_session_with_resolver` so DNS-based second-pass
/// routing can run.
pub fn select_udp_outbound_for_session(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
) -> Result<UdpOutbound, CoreError> {
    let outbound = select_configured_outbound(
        config,
        inbound_tag,
        target_domain(target),
        target_ip(target),
    )?;
    build_udp_outbound(outbound)
}

pub async fn select_udp_outbound_for_session_with_resolver(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<UdpOutbound, CoreError> {
    let outbound =
        select_configured_outbound_with_resolver(config, inbound_tag, target, dns_resolver).await?;
    build_udp_outbound(outbound)
}

fn build_tcp_outbound(outbound: &OutboundConfig) -> Result<TcpOutbound, CoreError> {
    if outbound.stream.network != Network::Tcp {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }

    match &outbound.settings {
        OutboundSettings::Freedom => {
            if outbound.stream.security != StreamSecurity::None {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }
            Ok(TcpOutbound::Freedom)
        }
        OutboundSettings::Vless(_) => build_vless_tcp_outbound(outbound)
            .map(|outbound| TcpOutbound::Vless(Box::new(outbound))),
    }
}

fn build_udp_outbound(outbound: &OutboundConfig) -> Result<UdpOutbound, CoreError> {
    match &outbound.settings {
        OutboundSettings::Freedom => {
            if outbound.stream.security != StreamSecurity::None {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }
            Ok(UdpOutbound::Freedom)
        }
        OutboundSettings::Vless(_) => {
            if outbound.stream.network != Network::Tcp {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
            build_vless_tcp_outbound(outbound)
                .map(|outbound| UdpOutbound::Vless(Box::new(outbound)))
        }
    }
}

pub fn select_vless_tcp_outbound(config: &CoreConfig) -> Result<VlessTcpOutbound, CoreError> {
    let outbound = select_configured_outbound(config, None, None, None)?;
    build_vless_tcp_outbound(outbound)
}

fn select_configured_outbound<'a>(
    config: &'a CoreConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&IpAddr>,
) -> Result<&'a OutboundConfig, CoreError> {
    let routed_tag = select_routed_outbound_tag(config, inbound_tag, target_domain, target_ip);

    let outbound = match routed_tag.or(config.default_outbound_tag.as_deref()) {
        Some(tag) => config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
            .ok_or(CoreError::NoSupportedOutbound)?,
        None => config
            .outbounds
            .first()
            .ok_or(CoreError::NoSupportedOutbound)?,
    };

    Ok(outbound)
}

async fn select_configured_outbound_with_resolver<'a>(
    config: &'a CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<&'a OutboundConfig, CoreError> {
    if let Some(routed_tag) = select_routed_outbound_tag(
        config,
        inbound_tag,
        target_domain(target),
        target_ip(target),
    ) {
        return select_configured_outbound_by_tag(config, routed_tag);
    }

    if config.routing.domain_strategy == RoutingDomainStrategy::IpIfNonMatch {
        if let Some(domain) = target_domain(target) {
            let resolved = dns_resolver.resolve(domain, target.port).await?;
            let resolved_ip = resolved.ip();
            if let Some(routed_tag) =
                select_routed_outbound_tag(config, inbound_tag, None, Some(&resolved_ip))
            {
                return select_configured_outbound_by_tag(config, routed_tag);
            }
        }
    }

    select_default_configured_outbound(config)
}

fn select_routed_outbound_tag<'a>(
    config: &'a CoreConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&IpAddr>,
) -> Option<&'a str> {
    config
        .routing
        .rules
        .iter()
        .find(|rule| rule.matches(inbound_tag, target_domain, target_ip))
        .map(|rule| rule.outbound_tag.as_str())
}

fn select_configured_outbound_by_tag<'a>(
    config: &'a CoreConfig,
    tag: &str,
) -> Result<&'a OutboundConfig, CoreError> {
    config
        .outbounds
        .iter()
        .find(|outbound| outbound.tag.as_deref() == Some(tag))
        .ok_or(CoreError::NoSupportedOutbound)
}

fn select_default_configured_outbound(config: &CoreConfig) -> Result<&OutboundConfig, CoreError> {
    match config.default_outbound_tag.as_deref() {
        Some(tag) => select_configured_outbound_by_tag(config, tag),
        None => config
            .outbounds
            .first()
            .ok_or(CoreError::NoSupportedOutbound),
    }
}

#[allow(dead_code)]
fn select_configured_outbound_direct<'a>(
    config: &'a CoreConfig,
    outbound_tag: Option<&str>,
) -> Result<&'a OutboundConfig, CoreError> {
    match outbound_tag.or(config.default_outbound_tag.as_deref()) {
        Some(tag) => config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
            .ok_or(CoreError::NoSupportedOutbound),
        None => config
            .outbounds
            .first()
            .ok_or(CoreError::NoSupportedOutbound),
    }
}

fn target_domain(target: &Target) -> Option<&str> {
    match &target.addr {
        RoutingTargetAddr::Domain(domain) => Some(domain.as_str()),
        RoutingTargetAddr::Ip(_) => None,
    }
}

fn target_ip(target: &Target) -> Option<&IpAddr> {
    match &target.addr {
        RoutingTargetAddr::Ip(ip) => Some(ip),
        RoutingTargetAddr::Domain(_) => None,
    }
}

fn build_vless_tcp_outbound(outbound: &OutboundConfig) -> Result<VlessTcpOutbound, CoreError> {
    if outbound.stream.network != Network::Tcp {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }

    let OutboundSettings::Vless(settings) = &outbound.settings else {
        return Err(CoreError::NoSupportedOutbound);
    };
    let user = settings
        .users
        .first()
        .cloned()
        .ok_or(CoreError::NoSupportedOutbound)?;
    validate_stream_flow(user.flow.as_deref(), &outbound.stream.security)?;

    let transport = match &outbound.stream.security {
        StreamSecurity::None => ConnectorConfig::Tcp,
        StreamSecurity::Tls(tls) => {
            if tls.fingerprint.is_some() {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }

            let server_name = match tls.server_name.as_deref() {
                Some(name) if !name.is_empty() => name.to_owned(),
                Some(_) => return Err(CoreError::UnsupportedOutboundSecurity),
                None => match &settings.server {
                    TargetAddr::Domain(domain) => domain.clone(),
                    TargetAddr::Ip(_) => return Err(CoreError::UnsupportedOutboundSecurity),
                },
            };

            ConnectorConfig::Tls(TlsClientConfig {
                server_name,
                allow_insecure: tls.allow_insecure,
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
    };

    let addr = match &settings.server {
        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
        TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
    };

    Ok(VlessTcpOutbound {
        server: Target::new(addr, settings.port, RoutingNetwork::Tcp),
        user,
        transport,
    })
}

fn validate_stream_flow(flow: Option<&str>, security: &StreamSecurity) -> Result<(), CoreError> {
    validate_vision_flow(
        flow,
        matches!(
            security,
            StreamSecurity::Tls(_) | StreamSecurity::Reality(_)
        ),
    )
    .map(|_| ())
}

fn validate_connector_flow(
    flow: Option<&str>,
    transport: &ConnectorConfig,
) -> Result<VisionFlow, CoreError> {
    validate_vision_flow(
        flow,
        matches!(
            transport,
            ConnectorConfig::Tls(_) | ConnectorConfig::Reality(_)
        ),
    )
}

fn validate_vision_flow(flow: Option<&str>, is_protected: bool) -> Result<VisionFlow, CoreError> {
    match flow {
        None => Ok(VisionFlow::None),
        Some(VISION_FLOW) if is_protected => Ok(VisionFlow::Vision),
        Some(VISION_UDP443_FLOW) if is_protected => Ok(VisionFlow::VisionUdp443),
        Some(_) => Err(CoreError::UnsupportedOutboundFlow),
    }
}

async fn resolve_server_target(
    server: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<Target, CoreError> {
    match &server.addr {
        RoutingTargetAddr::Ip(ip) => Ok(Target::new(
            RoutingTargetAddr::Ip(*ip),
            server.port,
            server.network,
        )),
        RoutingTargetAddr::Domain(domain) => {
            let resolved = dns_resolver.resolve(domain, server.port).await?;
            Ok(Target::new(
                RoutingTargetAddr::Ip(resolved.ip()),
                resolved.port(),
                server.network,
            ))
        }
    }
}

pub async fn open_vless_tcp_stream_with_resolver(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<BoxedTransportStream, CoreError> {
    let transport_dialer = TransportDialer::system()?;
    open_vless_tcp_stream_with_resolver_and_dialer(
        outbound,
        target,
        dns_resolver,
        &transport_dialer,
    )
    .await
}

pub async fn open_tcp_stream_with_resolver_and_dialer(
    outbound: &TcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    match outbound {
        TcpOutbound::Freedom => {
            let resolved_target = resolve_server_target(target, dns_resolver).await?;
            Ok(transport_dialer
                .connect(&ConnectorConfig::Tcp, &resolved_target)
                .await?)
        }
        TcpOutbound::Vless(outbound) => {
            open_vless_tcp_stream_with_resolver_and_dialer(
                outbound,
                target,
                dns_resolver,
                transport_dialer,
            )
            .await
        }
    }
}

pub async fn open_vless_tcp_stream_with_resolver_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    let flow = validate_connector_flow(outbound.user.flow.as_deref(), &outbound.transport)?;

    let resolved_server = resolve_server_target(&outbound.server, dns_resolver).await?;
    let mut stream = transport_dialer
        .connect(&outbound.transport, &resolved_server)
        .await?;
    let request = VlessRequest {
        user_id: outbound.user.id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: flow.request_flow(),
    };
    let header = encode_request_header(&request)?;

    stream.write_all(&header).await?;

    if flow.uses_vision() {
        let stream = VlessResponseStream::new(VisionTransportStream::new(stream));
        return Ok(Box::new(VisionOutboundStream::new(VisionStream::new(
            stream,
            *outbound.user.id.as_bytes(),
            [0, 0, 0, 0],
        ))));
    }

    let stream = VlessResponseStream::new(stream);
    Ok(Box::new(VlessOutboundStream::new(stream)))
}

pub async fn open_vless_udp_stream_with_resolver_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<(BoxedTransportStream, VlessUdpFraming), CoreError> {
    open_vless_udp_stream_with_resolver_dialer_and_options(
        outbound,
        target,
        dns_resolver,
        transport_dialer,
        VlessUdpOpenOptions::default(),
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VlessUdpOpenOptions {
    pub(crate) reject_udp443_for_regular_vision: bool,
}

impl Default for VlessUdpOpenOptions {
    fn default() -> Self {
        Self {
            reject_udp443_for_regular_vision: true,
        }
    }
}

pub(crate) async fn open_vless_udp_stream_with_resolver_dialer_and_options(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    options: VlessUdpOpenOptions,
) -> Result<(BoxedTransportStream, VlessUdpFraming), CoreError> {
    let flow = validate_connector_flow(outbound.user.flow.as_deref(), &outbound.transport)?;
    let uses_vision = flow.uses_vision();
    if options.reject_udp443_for_regular_vision
        && uses_vision
        && !flow.allows_udp443()
        && is_udp443_target(target)
    {
        return Err(CoreError::VisionUdp443Rejected);
    }
    let uses_xudp = uses_vision || should_use_xudp_for_udp_target(target);

    let resolved_server = resolve_server_target(&outbound.server, dns_resolver).await?;
    let mut stream = transport_dialer
        .connect(&outbound.transport, &resolved_server)
        .await?;
    let request = VlessRequest {
        user_id: outbound.user.id,
        command: if uses_xudp {
            VlessCommand::Mux
        } else {
            VlessCommand::Udp
        },
        target: target.clone(),
        flow: flow.request_flow(),
    };
    let header = encode_request_header(&request)?;

    stream.write_all(&header).await?;

    if uses_vision {
        let stream = VlessResponseStream::new(VisionTransportStream::new(stream));
        return Ok((
            Box::new(VisionOutboundStream::new(VisionStream::new(
                stream,
                *outbound.user.id.as_bytes(),
                [0, 0, 0, 0],
            ))),
            VlessUdpFraming::Xudp,
        ));
    }

    let stream = VlessResponseStream::new(stream);
    if uses_xudp {
        return Ok((
            Box::new(VlessOutboundStream::new(stream)),
            VlessUdpFraming::Xudp,
        ));
    }

    Ok((
        Box::new(VlessOutboundStream::new(stream)),
        VlessUdpFraming::LengthPrefixed,
    ))
}

fn should_use_xudp_for_udp_target(target: &Target) -> bool {
    target.network == xray_routing::Network::Udp && target.port != 53 && target.port != 443
}

fn is_udp443_target(target: &Target) -> bool {
    target.network == xray_routing::Network::Udp && target.port == 443
}

pub async fn open_vless_tcp_stream(
    outbound: &VlessTcpOutbound,
    target: &Target,
) -> Result<BoxedTransportStream, CoreError> {
    open_vless_tcp_stream_with_resolver(outbound, target, &SystemDnsResolver).await
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;
    use xray_config::{
        IpCidr, IpMatcher, RoutingConfig, RoutingDomainStrategy, RoutingRule, StreamSettings,
        VlessOutboundSettings,
    };
    use xray_proxy::vless::{unpad_vision_block, VisionCommand};
    use xray_transport::{RealityTlsEngine, TransportError};

    use super::*;

    fn direct_selection_freedom(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: Some(tag.to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                security: StreamSecurity::None,
            },
            settings: OutboundSettings::Freedom,
        }
    }

    fn direct_selection_vless(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: Some(tag.to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                security: StreamSecurity::None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 443,
                users: vec![VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: None,
                    level: 0,
                }],
            }),
        }
    }

    fn direct_selection_config() -> CoreConfig {
        CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![
                direct_selection_freedom("direct"),
                direct_selection_vless("proxy"),
            ],
            default_outbound_tag: Some("proxy".to_owned()),
            routing: RoutingConfig {
                rules: vec![RoutingRule {
                    inbound_tags: Vec::new(),
                    domain_matchers: Vec::new(),
                    ip_matchers: Vec::new(),
                    outbound_tag: "direct".to_owned(),
                }],
                ..Default::default()
            },
            dns: Default::default(),
            policy: Default::default(),
        }
    }

    #[derive(Debug)]
    struct FakeDnsResolver {
        result: Result<SocketAddr, TransportError>,
        expected: Option<(&'static str, u16)>,
        calls: AtomicUsize,
    }

    impl FakeDnsResolver {
        fn resolving_to(addr: SocketAddr) -> Self {
            Self {
                result: Ok(addr),
                expected: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn failing_with(error: TransportError) -> Self {
            Self {
                result: Err(error),
                expected: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn expect_lookup(mut self, domain: &'static str, port: u16) -> Self {
            self.expected = Some((domain, port));
            self
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DnsResolver for FakeDnsResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            if let Some((expected_domain, expected_port)) = self.expected {
                assert_eq!(domain, expected_domain);
                assert_eq!(port, expected_port);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.result {
                Ok(addr) => Ok(*addr),
                Err(TransportError::NoResolvedAddress(domain, port)) => {
                    Err(TransportError::NoResolvedAddress(domain.clone(), *port))
                }
                Err(error) => panic!("fake resolver cannot clone transport error: {error}"),
            }
        }
    }

    fn domain_tcp_target(domain: &str) -> Target {
        Target::new(
            RoutingTargetAddr::Domain(domain.to_owned()),
            443,
            RoutingNetwork::Tcp,
        )
    }

    fn ip_rule(tag: &str, ip: Ipv4Addr) -> RoutingRule {
        RoutingRule {
            inbound_tags: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: vec![IpMatcher::Cidr(IpCidr::full(IpAddr::V4(ip)))],
            outbound_tag: tag.to_owned(),
        }
    }

    fn inbound_rule(inbound_tag: &str, outbound_tag: &str) -> RoutingRule {
        RoutingRule {
            inbound_tags: vec![inbound_tag.to_owned()],
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: outbound_tag.to_owned(),
        }
    }

    #[test]
    fn select_tcp_outbound_direct_uses_explicit_tag() {
        let selected =
            select_tcp_outbound_direct(&direct_selection_config(), Some("direct")).unwrap();

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn select_tcp_outbound_direct_uses_default_tag_without_routing() {
        let selected = select_tcp_outbound_direct(&direct_selection_config(), None).unwrap();

        assert!(matches!(selected, TcpOutbound::Vless(_)));
    }

    #[test]
    fn select_tcp_outbound_direct_errors_when_explicit_tag_is_missing() {
        let error =
            select_tcp_outbound_direct(&direct_selection_config(), Some("missing")).unwrap_err();

        assert!(matches!(error, CoreError::NoSupportedOutbound));
    }

    #[test]
    fn select_tcp_outbound_direct_uses_first_outbound_without_default() {
        let mut config = direct_selection_config();
        config.default_outbound_tag = None;

        let selected = select_tcp_outbound_direct(&config, None).unwrap();

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[tokio::test]
    async fn ip_if_non_match_uses_dns_second_pass_for_ip_rules() {
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", Ipv4Addr::new(203, 0, 113, 7))];
        let resolver =
            FakeDnsResolver::resolving_to(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)))
                .expect_lookup("example.test", 443);

        let selected = select_tcp_outbound_for_session_with_resolver(
            &config,
            None,
            &domain_tcp_target("example.test"),
            &resolver,
        )
        .await
        .expect("select route using resolved IP");

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[tokio::test]
    async fn ip_if_non_match_does_not_resolve_when_rule_matches_first_pass() {
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![
            inbound_rule("socks-in", "proxy"),
            ip_rule("direct", Ipv4Addr::new(203, 0, 113, 7)),
        ];
        let resolver =
            FakeDnsResolver::resolving_to(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)));

        let selected = select_tcp_outbound_for_session_with_resolver(
            &config,
            Some("socks-in"),
            &domain_tcp_target("example.test"),
            &resolver,
        )
        .await
        .expect("select first-pass route");

        assert!(matches!(selected, TcpOutbound::Vless(_)));
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn missing_outbound_tag_errors_only_when_selected() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![inbound_rule("api", "api")];

        let selected = select_tcp_outbound_for_session(
            &config,
            Some("socks-in"),
            &domain_tcp_target("example.test"),
        )
        .expect("unmatched missing tag rule should fall back to default");
        assert!(matches!(selected, TcpOutbound::Vless(_)));

        let error = select_tcp_outbound_for_session(
            &config,
            Some("api"),
            &domain_tcp_target("example.test"),
        )
        .unwrap_err();
        assert!(matches!(error, CoreError::NoSupportedOutbound));
    }

    #[tokio::test]
    async fn ip_if_non_match_dns_failure_is_reported() {
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", Ipv4Addr::new(203, 0, 113, 7))];
        let resolver = FakeDnsResolver::failing_with(TransportError::NoResolvedAddress(
            "example.test".to_owned(),
            443,
        ))
        .expect_lookup("example.test", 443);

        let error = select_tcp_outbound_for_session_with_resolver(
            &config,
            None,
            &domain_tcp_target("example.test"),
            &resolver,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            CoreError::Transport(TransportError::NoResolvedAddress(_, 443))
        ));
    }

    #[derive(Debug)]
    struct DuplexRealityEngine {
        stream: Mutex<Option<tokio::io::DuplexStream>>,
        seen: Mutex<Option<(RealityClientConfig, Target)>>,
    }

    impl DuplexRealityEngine {
        fn new(stream: tokio::io::DuplexStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
                seen: Mutex::new(None),
            }
        }

        fn seen(&self) -> Option<(RealityClientConfig, Target)> {
            self.seen.lock().expect("seen lock").clone()
        }
    }

    #[async_trait]
    impl RealityTlsEngine for DuplexRealityEngine {
        async fn connect(
            &self,
            config: &RealityClientConfig,
            target: &Target,
        ) -> Result<BoxedTransportStream, TransportError> {
            *self.seen.lock().expect("seen lock") = Some((config.clone(), target.clone()));
            let stream = self
                .stream
                .lock()
                .expect("stream lock")
                .take()
                .expect("fake REALITY stream should be consumed once");

            Ok(Box::new(stream))
        }
    }

    #[tokio::test]
    async fn open_vless_tcp_stream_rejects_outbound_with_flow_before_connecting() {
        let outbound = VlessTcpOutbound {
            server: Target::new(
                RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                0,
                RoutingNetwork::Tcp,
            ),
            user: VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: Some("xtls-rprx-vision".to_owned()),
                level: 0,
            },
            transport: ConnectorConfig::Tcp,
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );

        let result = open_vless_tcp_stream(&outbound, &target).await;

        assert!(matches!(result, Err(CoreError::UnsupportedOutboundFlow)));
    }

    #[tokio::test]
    async fn open_vless_tcp_stream_uses_default_live_reality_transport_for_vision_flow() {
        let outbound = VlessTcpOutbound {
            server: Target::new(
                RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                0,
                RoutingNetwork::Tcp,
            ),
            user: VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: Some(VISION_FLOW.to_owned()),
                level: 0,
            },
            transport: ConnectorConfig::Reality(RealityClientConfig {
                server_name: "example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: [7; 32],
                short_id: vec![1, 2, 3, 4],
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );

        let result = open_vless_tcp_stream(&outbound, &target).await;

        assert!(matches!(
            result,
            Err(CoreError::Transport(xray_transport::TransportError::Tcp(_)))
        ));
    }

    #[tokio::test]
    async fn open_vless_tcp_stream_wraps_injected_reality_stream_with_vision() {
        let reality_config = RealityClientConfig {
            server_name: "example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        };
        let outbound = VlessTcpOutbound {
            server: Target::new(
                RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                443,
                RoutingNetwork::Tcp,
            ),
            user: VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: Some(VISION_FLOW.to_owned()),
                level: 0,
            },
            transport: ConnectorConfig::Reality(reality_config.clone()),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );
        let (client, mut protected_side) = tokio::io::duplex(4096);
        let engine = Arc::new(DuplexRealityEngine::new(client));
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(engine.clone());

        let mut stream = open_vless_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await
        .expect("open VLESS over injected REALITY stream");

        let expected_header = encode_request_header(&VlessRequest {
            user_id: outbound.user.id,
            command: VlessCommand::Tcp,
            target: target.clone(),
            flow: outbound.user.flow.clone(),
        })
        .unwrap();
        let mut received_header = vec![0; expected_header.len()];
        protected_side
            .read_exact(&mut received_header)
            .await
            .expect("read VLESS header from protected stream");
        assert_eq!(received_header, expected_header);

        stream.write_all(b"vision payload").await.unwrap();
        stream.flush().await.unwrap();

        let mut padded = vec![0; 16 + 5 + "vision payload".len()];
        protected_side
            .read_exact(&mut padded)
            .await
            .expect("read first Vision block");
        let unpadded = unpad_vision_block(&padded, outbound.user.id.as_bytes()).unwrap();
        assert_eq!(unpadded.command, VisionCommand::Continue);
        assert_eq!(&unpadded.payload[..], b"vision payload");

        let (seen_config, seen_target) = engine.seen().expect("engine saw config and target");
        assert_eq!(seen_config, reality_config);
        assert_eq!(seen_target.addr, outbound.server.addr);
        assert_eq!(seen_target.port, outbound.server.port);
        assert_eq!(seen_target.network, outbound.server.network);
    }

    #[tokio::test]
    async fn open_vless_udp_stream_rejects_udp443_for_regular_vision_flow_before_connecting() {
        let outbound = VlessTcpOutbound {
            server: Target::new(
                RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                443,
                RoutingNetwork::Tcp,
            ),
            user: VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: Some(VISION_FLOW.to_owned()),
                level: 0,
            },
            transport: ConnectorConfig::Reality(RealityClientConfig {
                server_name: "example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: [7; 32],
                short_id: vec![1, 2, 3, 4],
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Udp,
        );
        let (client, _protected_side) = tokio::io::duplex(4096);
        let engine = Arc::new(DuplexRealityEngine::new(client));
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(engine.clone());

        let result = open_vless_udp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await;

        match result {
            Err(error) => assert_eq!(error.to_string(), "XTLS rejected UDP/443 traffic"),
            Ok(_) => panic!("expected UDP/443 rejection for regular Vision flow"),
        }
        assert!(
            engine.seen().is_none(),
            "UDP/443 rejection should happen before dialing the VLESS server"
        );
    }

    #[tokio::test]
    async fn open_vless_udp_stream_allows_udp443_flow_and_sends_vision_addons() {
        let outbound = VlessTcpOutbound {
            server: Target::new(
                RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                443,
                RoutingNetwork::Tcp,
            ),
            user: VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: Some("xtls-rprx-vision-udp443".to_owned()),
                level: 0,
            },
            transport: ConnectorConfig::Reality(RealityClientConfig {
                server_name: "example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: [7; 32],
                short_id: vec![1, 2, 3, 4],
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Udp,
        );
        let (client, mut protected_side) = tokio::io::duplex(4096);
        let engine = Arc::new(DuplexRealityEngine::new(client));
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(engine.clone());

        let (_stream, framing) = open_vless_udp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await
        .expect("open VLESS UDP/443 stream with explicit udp443 Vision flow");

        assert_eq!(framing, VlessUdpFraming::Xudp);
        let expected_header = encode_request_header(&VlessRequest {
            user_id: outbound.user.id,
            command: VlessCommand::Mux,
            target: target.clone(),
            flow: Some(VISION_FLOW.to_owned()),
        })
        .unwrap();
        let mut received_header = vec![0; expected_header.len()];
        protected_side
            .read_exact(&mut received_header)
            .await
            .expect("read VLESS header from protected stream");
        assert_eq!(received_header, expected_header);
        assert!(engine.seen().is_some());
    }
}
