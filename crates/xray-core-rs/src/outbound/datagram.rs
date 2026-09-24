//! Shared bounded datagram relay for connection-oriented UDP outbounds.
use super::*;
use xray_transport::hysteria::{HysteriaError, HysteriaUdpSession};

pub(crate) enum Session {
    Hysteria(HysteriaUdpSession),
    Wireguard {
        session: xray_wireguard::UdpSession,
        requested: Target,
    },
}
pub(crate) struct Datagram {
    pub(crate) source: Target,
    pub(crate) payload: Vec<u8>,
}
pub(crate) async fn open(
    outbound: &UdpOutbound,
    target: &Target,
    destination: &dyn DnsResolver,
    bootstrap: &dyn DnsResolver,
    dialer: &TransportDialer,
) -> Result<Session, CoreError> {
    match outbound {
        UdpOutbound::Hysteria(outbound) => Ok(Session::Hysteria(
            outbound.open_udp(bootstrap, dialer).await?,
        )),
        UdpOutbound::Wireguard(outbound) => Ok(Session::Wireguard {
            session: outbound
                .open_udp(target, destination, bootstrap, dialer)
                .await?,
            requested: target.clone(),
        }),
        _ => Err(CoreError::UnsupportedOutboundNetwork),
    }
}
impl Session {
    pub(crate) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        match self {
            Self::Hysteria(session) => Ok(session.send(target, payload).await?),
            Self::Wireguard { session, requested } => {
                if target != requested {
                    return Err(xray_wireguard::Error::NoRoute.into());
                }
                Ok(session.send(payload).await?)
            }
        }
    }
    pub(crate) async fn recv(&self) -> Result<Datagram, CoreError> {
        match self {
            Self::Hysteria(session) => {
                let packet = session.recv().await?;
                Ok(Datagram {
                    source: packet.source,
                    payload: packet.payload,
                })
            }
            Self::Wireguard { session, .. } => {
                let peer = session.peer_addr();
                Ok(Datagram {
                    source: Target::new(
                        RoutingTargetAddr::Ip(peer.ip()),
                        peer.port(),
                        RoutingNetwork::Udp,
                    ),
                    payload: session.recv().await?.to_vec(),
                })
            }
        }
    }
}

/// Shared flow loop; the inbound adapter owns shutdown/host-close cancellation.
#[expect(
    clippy::too_many_arguments,
    reason = "shared relay carries optional TUN telemetry and inbound delivery"
)]
pub(crate) async fn relay_udp<F, Fut>(
    session: Session,
    target: &Target,
    mut input: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    first: bytes::Bytes,
    traffic: &crate::connection::ConnectionTraffic,
    idle: Duration,
    tun: Option<&xray_tun::TunEndpoint>,
    mut deliver: F,
) -> Result<(), CoreError>
where
    F: FnMut(Target, bytes::Bytes) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    session.send(target, &first).await.inspect_err(|_| {
        if let Some(tun) = tun {
            tun.record_udp_remote_write_error();
        }
    })?;
    if let Some(tun) = tun {
        tun.record_udp_remote_written(first.len());
    }
    traffic.record_uplink(first.len() as u64);
    let idle_deadline = tokio::time::sleep(idle);
    tokio::pin!(idle_deadline);
    loop {
        tokio::select! {
            _ = &mut idle_deadline => break,
            payload = input.recv() => {
                let Some(payload) = payload else { break; };
                session.send(target, &payload).await.inspect_err(|_| { if let Some(tun) = tun { tun.record_udp_remote_write_error(); } })?;
                if let Some(tun) = tun { tun.record_udp_remote_written(payload.len()); }
                traffic.record_uplink(payload.len() as u64);
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + idle);
            }
            packet = session.recv() => {
                let packet = packet.inspect_err(|error| { if let Some(tun) = tun {
                    if matches!(error, CoreError::Hysteria(HysteriaError::Closed) | CoreError::Wireguard(xray_wireguard::Error::Closed)) { tun.record_udp_remote_closed(); } else { tun.record_udp_remote_read_error(); }
                } })?;
                if let Some(tun) = tun { tun.record_udp_remote_read(packet.payload.len()); }
                traffic.record_downlink(packet.payload.len() as u64);
                deliver(packet.source, bytes::Bytes::from(packet.payload)).await?;
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + idle);
            }
        }
    }
    Ok(())
}
