use tokio::io::AsyncWriteExt;
use xray_config::{CoreConfig, Network, OutboundSettings, StreamSecurity, TargetAddr, VlessUser};
use xray_proxy::vless::{
    encode_request_header, VisionStream, VlessCommand, VlessRequest, VlessResponseStream,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, RealityClientConfig, SystemDnsResolver,
    TlsClientConfig, TransportDialer,
};

use crate::CoreError;

const VISION_FLOW: &str = "xtls-rprx-vision";

#[derive(Debug, Clone)]
pub struct VlessTcpOutbound {
    server: Target,
    user: VlessUser,
    transport: ConnectorConfig,
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

    let OutboundSettings::Vless(settings) = &outbound.settings;
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

            ConnectorConfig::Tls(TlsClientConfig { server_name })
        }
        StreamSecurity::Reality(reality) => ConnectorConfig::Reality(RealityClientConfig {
            server_name: reality.server_name.clone(),
            fingerprint: reality.fingerprint.clone(),
            public_key: reality.public_key,
            short_id: reality.short_id.as_slice().to_vec(),
            spider_x: reality.spider_x.clone(),
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
) -> Result<bool, CoreError> {
    validate_vision_flow(
        flow,
        matches!(
            transport,
            ConnectorConfig::Tls(_) | ConnectorConfig::Reality(_)
        ),
    )
}

fn validate_vision_flow(flow: Option<&str>, is_protected: bool) -> Result<bool, CoreError> {
    match flow {
        None => Ok(false),
        Some(VISION_FLOW) if is_protected => Ok(true),
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

pub async fn open_vless_tcp_stream_with_resolver_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    let uses_vision = validate_connector_flow(outbound.user.flow.as_deref(), &outbound.transport)?;

    let resolved_server = resolve_server_target(&outbound.server, dns_resolver).await?;
    let mut stream = transport_dialer
        .connect(&outbound.transport, &resolved_server)
        .await?;
    let request = VlessRequest {
        user_id: outbound.user.id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: outbound.user.flow.clone(),
    };
    let header = encode_request_header(&request)?;

    stream.write_all(&header).await?;

    let stream = VlessResponseStream::new(stream);

    if uses_vision {
        return Ok(Box::new(VisionStream::new(
            stream,
            *outbound.user.id.as_bytes(),
            [0, 0, 0, 0],
        )));
    }

    Ok(Box::new(stream))
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
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;
    use xray_proxy::vless::{unpad_vision_block, VisionCommand};
    use xray_transport::{RealityTlsEngine, TransportError};

    use super::*;

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
    async fn open_vless_tcp_stream_keeps_default_reality_transport_gate_for_vision_flow() {
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
            },
            transport: ConnectorConfig::Reality(RealityClientConfig {
                server_name: "example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: [7; 32],
                short_id: vec![1, 2, 3, 4],
                spider_x: "/".to_owned(),
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
            Err(CoreError::Transport(
                xray_transport::TransportError::UnsupportedConnectorConfig("reality")
            ))
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
}
