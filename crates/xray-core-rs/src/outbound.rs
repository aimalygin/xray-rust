use tokio::io::AsyncWriteExt;
use xray_config::{CoreConfig, Network, OutboundSettings, StreamSecurity, TargetAddr, VlessUser};
use xray_proxy::vless::{encode_request_header, VlessCommand, VlessRequest};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{ConnectorConfig, TcpConnector, TransportConnector};

use crate::CoreError;

#[derive(Debug, Clone)]
pub struct VlessTcpOutbound {
    pub server: Target,
    pub user: VlessUser,
}

pub fn select_vless_tcp_outbound(config: &CoreConfig) -> Result<VlessTcpOutbound, CoreError> {
    let outbound = config
        .outbounds
        .first()
        .ok_or(CoreError::NoSupportedOutbound)?;

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

    let addr = match settings.server {
        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(ip),
        TargetAddr::Domain(_) => return Err(CoreError::UnsupportedOutboundServerAddress),
    };

    Ok(VlessTcpOutbound {
        server: Target::new(addr, settings.port, RoutingNetwork::Tcp),
        user,
    })
}

pub async fn open_vless_tcp_stream(
    outbound: &VlessTcpOutbound,
    target: &Target,
) -> Result<tokio::net::TcpStream, CoreError> {
    let connector = TcpConnector::new(ConnectorConfig::Tcp);
    let mut stream = connector.connect(&outbound.server).await?;
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
