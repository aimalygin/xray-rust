use tokio::io::AsyncWriteExt;
use xray_config::{CoreConfig, Network, OutboundSettings, StreamSecurity, TargetAddr, VlessUser};
use xray_proxy::vless::{encode_request_header, VlessCommand, VlessRequest};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, SystemDnsResolver, TcpConnector,
    TransportConnector,
};

use crate::CoreError;

#[derive(Debug, Clone)]
pub struct VlessTcpOutbound {
    server: Target,
    user: VlessUser,
}

impl VlessTcpOutbound {
    pub fn server(&self) -> &Target {
        &self.server
    }
}

pub fn select_vless_tcp_outbound(config: &CoreConfig) -> Result<VlessTcpOutbound, CoreError> {
    let outbound = match &config.default_outbound_tag {
        Some(tag) => config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag.as_str()))
            .ok_or(CoreError::NoSupportedOutbound)?,
        None => config
            .outbounds
            .first()
            .ok_or(CoreError::NoSupportedOutbound)?,
    };

    if outbound.stream.network != Network::Tcp {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }

    if !matches!(outbound.stream.security, StreamSecurity::None) {
        return Err(CoreError::UnsupportedOutboundSecurity);
    }

    let OutboundSettings::Vless(settings) = &outbound.settings;
    let user = settings
        .users
        .first()
        .cloned()
        .ok_or(CoreError::NoSupportedOutbound)?;
    if user.flow.is_some() {
        return Err(CoreError::UnsupportedOutboundFlow);
    }

    let addr = match &settings.server {
        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
        TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
    };

    Ok(VlessTcpOutbound {
        server: Target::new(addr, settings.port, RoutingNetwork::Tcp),
        user,
    })
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
    if outbound.user.flow.is_some() {
        return Err(CoreError::UnsupportedOutboundFlow);
    }

    let resolved_server = resolve_server_target(&outbound.server, dns_resolver).await?;
    let connector = TcpConnector::new(ConnectorConfig::Tcp);
    let mut stream = connector.connect(&resolved_server).await?;
    let request = VlessRequest {
        user_id: outbound.user.id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: outbound.user.flow.clone(),
    };
    let header = encode_request_header(&request)?;

    stream.write_all(&header).await?;

    Ok(stream)
}

pub async fn open_vless_tcp_stream(
    outbound: &VlessTcpOutbound,
    target: &Target,
) -> Result<BoxedTransportStream, CoreError> {
    open_vless_tcp_stream_with_resolver(outbound, target, &SystemDnsResolver).await
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use uuid::Uuid;

    use super::*;

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
            },
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );

        let result = open_vless_tcp_stream(&outbound, &target).await;

        assert!(matches!(result, Err(CoreError::UnsupportedOutboundFlow)));
    }
}
