//! Lazy shared WireGuard device with separate bootstrap and destination DNS.
use super::*;
use xray_config::{WireguardDomainStrategy, WireguardOutboundSettings};
use xray_wireguard::{Client, Config, Error, PeerConfig};

#[derive(Clone, Debug)]
pub struct WireguardOutbound(Arc<Owner>);
#[derive(Debug)]
struct Owner {
    settings: WireguardOutboundSettings,
    session: Mutex<Option<Cached>>,
    connecting: tokio::sync::Mutex<()>,
    shutdown: tokio::sync::watch::Sender<bool>,
}
struct Cached {
    client: Client,
    protector: Option<Arc<dyn xray_transport::SocketProtector>>,
}
impl std::fmt::Debug for Cached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardSession")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}
impl Drop for Cached {
    fn drop(&mut self) {
        self.client.close();
    }
}
impl WireguardOutbound {
    pub(crate) fn new(outbound: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Wireguard(settings) = &outbound.settings else {
            return Err(CoreError::UnsupportedOutboundNetwork);
        };
        if outbound.stream.network != Network::Tcp
            || outbound.stream.transport != StreamTransport::Raw
            || outbound.stream.security != StreamSecurity::None
            || outbound.stream.quic_params.is_some()
            || outbound.stream.socket_options.is_some()
            || outbound.proxy_settings.is_some()
            || settings.peers.iter().any(|p| matches!(&p.endpoint, TargetAddr::Domain(d) if d.is_empty() || d.len() > 253 || !d.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))))
        {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        engine_config(settings)
            .validate()
            .map_err(|_| CoreError::UnsupportedOutboundNetwork)?;
        Ok(Self(Arc::new(Owner {
            settings: settings.clone(),
            session: Mutex::new(None),
            connecting: tokio::sync::Mutex::new(()),
            shutdown: tokio::sync::watch::channel(false).0,
        })))
    }
    pub(super) fn close(&self) {
        self.0.shutdown.send_replace(true);
        self.0
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
    async fn bounded<T>(
        &self,
        operation: impl Future<Output = Result<T, CoreError>>,
    ) -> Result<T, CoreError> {
        let mut shutdown = self.0.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(Error::Closed.into());
        }
        tokio::select! { biased;
            _ = shutdown.changed() => Err(Error::Closed.into()),
            result = tokio::time::timeout(Duration::from_secs(10), operation) => result.map_err(|_| Error::Timeout)?,
        }
    }
    async fn client(
        &self,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<Client, CoreError> {
        let _admission = self.0.connecting.lock().await;
        if *self.0.shutdown.borrow() {
            return Err(Error::Closed.into());
        }
        let protector = dialer.socket_protector_arc();
        {
            let mut slot = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = slot.as_ref().filter(|s| s.client.is_live()) {
                if !same_protector(&cached.protector, &protector) {
                    return Err(Error::Configuration.into());
                }
                return Ok(cached.client.clone());
            }
            slot.take();
        }
        // Resolve the complete immutable peer set before creating any sockets.
        // The caller's single deadline and cancellation cover all lookups.
        let mut config = engine_config(&self.0.settings);
        for (peer, settings) in config.peers.iter_mut().zip(&self.0.settings.peers) {
            let target = Target::new(
                match &settings.endpoint {
                    TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
                    TargetAddr::Domain(d) => RoutingTargetAddr::Domain(d.clone()),
                },
                settings.port,
                RoutingNetwork::Udp,
            );
            peer.endpoint = resolve_server_candidates(&target, bootstrap)
                .await?
                .into_iter()
                .next()
                .ok_or(Error::NoRoute)?;
        }
        let client = Client::start(config, protector.clone()).await?;
        let mut slot = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        if *self.0.shutdown.borrow() {
            client.close();
            return Err(Error::Closed.into());
        }
        *slot = Some(Cached {
            client: client.clone(),
            protector,
        });
        Ok(client)
    }
    async fn destinations(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
    ) -> Result<Vec<SocketAddr>, CoreError> {
        use xray_transport::DnsQueryStrategy;
        let config = &self.0.settings;
        let strategy = match config.domain_strategy {
            WireguardDomainStrategy::ForceIpv4 => DnsQueryStrategy::UseIpv4,
            WireguardDomainStrategy::ForceIpv6 => DnsQueryStrategy::UseIpv6,
            _ if config.addresses.iter().all(IpAddr::is_ipv4) => DnsQueryStrategy::UseIpv4,
            _ if config.addresses.iter().all(IpAddr::is_ipv6) => DnsQueryStrategy::UseIpv6,
            _ => DnsQueryStrategy::UseIp,
        };
        let mut candidates = match &target.addr {
            RoutingTargetAddr::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
            RoutingTargetAddr::Domain(domain) => match domain.parse::<IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, target.port)],
                Err(_) => resolver
                    .resolve_all_with_strategy(domain, target.port, strategy)
                    .await?
                    .socket_addrs()
                    .iter()
                    .take(8)
                    .copied()
                    .collect(),
            },
        };
        candidates.retain(|addr| {
            config
                .addresses
                .iter()
                .any(|ip| ip.is_ipv4() == addr.is_ipv4())
                && config
                    .peers
                    .iter()
                    .flat_map(|p| &p.allowed_ips)
                    .any(|p| p.contains(addr.ip()))
        });
        match config.domain_strategy {
            WireguardDomainStrategy::ForceIpv4v6 => candidates.sort_by_key(SocketAddr::is_ipv6),
            WireguardDomainStrategy::ForceIpv6v4 => candidates.sort_by_key(SocketAddr::is_ipv4),
            _ => {}
        }
        if candidates.is_empty() {
            return Err(Error::NoRoute.into());
        }
        Ok(candidates)
    }
    pub(crate) async fn open_tcp(
        &self,
        target: &Target,
        destination: &dyn DnsResolver,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        self.bounded(async {
            let addresses = self.destinations(target, destination).await?;
            let client = self.client(bootstrap, dialer).await?;
            let mut error = Error::NoRoute;
            let last = addresses.len() - 1;
            for (index, address) in addresses.into_iter().enumerate() {
                // A freshly restarted identity can hit the peer's handshake
                // rate limit. Let the final candidate wait for WireGuard's
                // retransmission; the enclosing deadline still caps all work.
                let attempt = if index == last { 10 } else { 3 };
                match tokio::time::timeout(Duration::from_secs(attempt), client.connect(address))
                    .await
                    .unwrap_or(Err(Error::Timeout))
                {
                    Ok(stream) => return Ok(Box::new(stream) as BoxedTransportStream),
                    Err(e @ (Error::Closed | Error::Busy | Error::SocketProtection)) => {
                        return Err(e.into())
                    }
                    Err(e) => error = e,
                }
            }
            Err(error.into())
        })
        .await
    }
    pub(crate) async fn open_udp(
        &self,
        target: &Target,
        destination: &dyn DnsResolver,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<xray_wireguard::UdpSession, CoreError> {
        self.bounded(async {
            let address = self
                .destinations(target, destination)
                .await?
                .into_iter()
                .next()
                .ok_or(Error::NoRoute)?;
            Ok(self
                .client(bootstrap, dialer)
                .await?
                .open_udp(address)
                .await?)
        })
        .await
    }
}
fn engine_config(settings: &WireguardOutboundSettings) -> Config {
    Config {
        secret_key: settings.secret_key.clone(),
        peers: settings
            .peers
            .iter()
            .map(|peer| PeerConfig {
                public_key: peer.public_key.clone(),
                preshared_key: peer.preshared_key.clone(),
                // A placeholder permits typed validation without bootstrap I/O.
                endpoint: SocketAddr::new(
                    match peer.endpoint {
                        TargetAddr::Ip(ip) => ip,
                        TargetAddr::Domain(_) => IpAddr::from([127, 0, 0, 1]),
                    },
                    peer.port,
                ),
                allowed_ips: peer.allowed_ips.clone(),
                keepalive: peer.keepalive,
            })
            .collect(),
        addresses: settings.addresses.clone(),
        mtu: settings.mtu,
    }
}
fn same_protector(
    a: &Option<Arc<dyn xray_transport::SocketProtector>>,
    b: &Option<Arc<dyn xray_transport::SocketProtector>>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
