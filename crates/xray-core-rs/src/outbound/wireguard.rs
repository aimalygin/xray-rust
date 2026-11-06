//! Lazy shared WireGuard device with separate bootstrap and destination DNS.
mod dns;
use super::*;
use xray_config::{AddressFamilies, WireguardOutboundSettings};
use xray_wireguard::{Client, Config, Error, PeerConfig};

#[derive(Clone, Debug)]
pub struct WireguardOutbound(Arc<Owner>);
#[derive(Debug)]
struct Owner {
    settings: WireguardOutboundSettings,
    /// `sockopt`, for the UDP socket.
    socket_options: Option<Arc<xray_transport::SocketOptions>>,
    /// `sockopt.domainStrategy`, which picks a domain endpoint's address.
    endpoint_strategy: DomainStrategy,
    /// The dialer given and the one made from it with `socket_options`,
    /// kept so its protector, which a cached session is matched by, stays
    /// the same.
    socket_dialer: Mutex<Option<(TransportDialer, TransportDialer)>>,
    session: Mutex<Option<Cached>>,
    connecting: tokio::sync::Mutex<()>,
    shutdown: tokio::sync::watch::Sender<bool>,
    network_generation: std::sync::atomic::AtomicU64,
}
struct Cached {
    client: Client,
    dns: Arc<dyn DnsResolver>,
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
            || outbound.proxy_settings.is_some()
            || settings.remote_dns.is_empty()
            || settings.remote_dns.len() > 8
            || settings.remote_dns.iter().any(|ip| ip.is_unspecified() || ip.is_multicast()
                || matches!(ip, IpAddr::V4(v4) if *v4 == std::net::Ipv4Addr::BROADCAST)
                || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local() || v6.to_ipv4_mapped().is_some()))
            || settings.peers.iter().any(|p| matches!(&p.endpoint, TargetAddr::Domain(d) if d.is_empty() || d.len() > 253 || !d.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))))
        {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        engine_config(settings)
            .validate()
            .map_err(|_| CoreError::UnsupportedOutboundNetwork)?;
        Ok(Self(Arc::new(Owner {
            settings: settings.clone(),
            socket_options: socket_options::compile(&outbound.stream),
            endpoint_strategy: outbound
                .stream
                .socket_options
                .as_ref()
                .map(|options| options.domain_strategy)
                .unwrap_or_default(),
            socket_dialer: Mutex::new(None),
            session: Mutex::new(None),
            connecting: tokio::sync::Mutex::new(()),
            shutdown: tokio::sync::watch::channel(false).0,
            network_generation: std::sync::atomic::AtomicU64::new(0),
        })))
    }
    /// `dialer` with this outbound's socket options: the same dialer each
    /// time `dialer` is the same, so a cached session still matches it.
    pub(super) fn socket_dialer<'a>(
        &self,
        dialer: &'a TransportDialer,
    ) -> std::borrow::Cow<'a, TransportDialer> {
        let Some(options) = &self.0.socket_options else {
            return std::borrow::Cow::Borrowed(dialer);
        };
        let mut cached = self
            .0
            .socket_dialer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((given, derived)) = cached.as_ref() {
            if given
                .tls_connector()
                .shares_session_context(dialer.tls_connector())
            {
                return std::borrow::Cow::Owned(derived.clone());
            }
        }
        let derived = dialer.clone().with_socket_options(Arc::clone(options));
        *cached = Some((dialer.clone(), derived.clone()));
        std::borrow::Cow::Owned(derived)
    }
    pub(super) fn close(&self) {
        self.0.shutdown.send_replace(true);
        self.0
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
    pub(super) fn rebind(&self) -> bool {
        let slot = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        self.0.network_generation.fetch_add(1, Ordering::AcqRel);
        slot.as_ref().is_some_and(|cached| cached.client.rebind())
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
    ) -> Result<(Client, Arc<dyn DnsResolver>), CoreError> {
        let _admission = self.0.connecting.lock().await;
        if *self.0.shutdown.borrow() {
            return Err(Error::Closed.into());
        }
        let dialer = self.socket_dialer(dialer);
        let protector = dialer.socket_protector_arc();
        {
            let mut slot = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = slot.as_ref().filter(|s| s.client.is_live()) {
                if !same_protector(&cached.protector, &protector) {
                    return Err(Error::Configuration.into());
                }
                return Ok((cached.client.clone(), cached.dns.clone()));
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
            let candidates = resolve_server_candidates(&target, bootstrap).await?;
            peer.endpoint = match &settings.endpoint {
                TargetAddr::Ip(_) => candidates.into_iter().next(),
                TargetAddr::Domain(_) => endpoint_address(&candidates, self.0.endpoint_strategy),
            }
            .ok_or(Error::NoRoute)?;
        }
        let generation = self.0.network_generation.load(Ordering::Acquire);
        let client = Client::start(config, protector.clone()).await?;
        let mut slot = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        if *self.0.shutdown.borrow() {
            client.close();
            return Err(Error::Closed.into());
        }
        // A path notification may arrive while socket creation is in flight,
        // before the candidate is visible to rebind(). Do not lose that update.
        if self.0.network_generation.load(Ordering::Acquire) != generation {
            client.rebind();
        }
        let dns = dns::resolver(client.clone(), &self.0.settings.remote_dns);
        *slot = Some(Cached {
            client: client.clone(),
            dns: dns.clone(),
            protector,
        });
        Ok((client, dns))
    }
    /// Destination DNS runs through the tunnel when a `remoteDNS` server is
    /// routable there. With none routable (a split `allowedIPs` excluding the
    /// configured servers), every tunnel query would fail with NoRoute, so the
    /// caller's resolver is used, as wg-quick sends such DNS outside the tunnel.
    fn destination_resolver<'a>(
        &self,
        tunnel: &'a dyn DnsResolver,
        caller: &'a dyn DnsResolver,
    ) -> &'a dyn DnsResolver {
        let settings = &self.0.settings;
        if settings.remote_dns.iter().any(|ip| routable(settings, *ip)) {
            tunnel
        } else {
            caller
        }
    }
    async fn destinations(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
    ) -> Result<Vec<SocketAddr>, CoreError> {
        use xray_transport::DnsQueryStrategy;
        let config = &self.0.settings;
        // The families the device has a local address of, as the tunnel's
        // own lookup in Xray-core asks for.
        let has_ipv6 = config.addresses.iter().any(IpAddr::is_ipv6);
        let strategy = if !has_ipv6 {
            DnsQueryStrategy::UseIpv4
        } else if config.addresses.iter().all(IpAddr::is_ipv6) {
            DnsQueryStrategy::UseIpv6
        } else {
            DnsQueryStrategy::UseIp
        };
        let mut candidates = match &target.addr {
            RoutingTargetAddr::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
            RoutingTargetAddr::Domain(domain) => match domain.parse::<IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, target.port)],
                Err(_) => resolver
                    .resolve_all_with_strategy(domain, target.port, strategy)
                    .await?
                    .socket_addrs()
                    .to_vec(),
            },
        };
        candidates.retain(|addr| routable(config, addr.ip()));
        // That lookup also puts IPv6 answers first when there is an IPv6
        // local address.
        if has_ipv6 {
            candidates.sort_by_key(SocketAddr::is_ipv4);
        }
        candidates.truncate(8);
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
            let (client, dns) = self.client(bootstrap, dialer).await?;
            let resolver = self.destination_resolver(dns.as_ref(), destination);
            let addresses = self.destinations(target, resolver).await?;
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
            let (client, dns) = self.client(bootstrap, dialer).await?;
            let resolver = self.destination_resolver(dns.as_ref(), destination);
            let address = self
                .destinations(target, resolver)
                .await?
                .into_iter()
                .next()
                .ok_or(Error::NoRoute)?;
            Ok(client.open_udp(address).await?)
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
/// The address a domain endpoint dials, as Xray-core's `MakeResolveLocal`
/// picks it: one of the families `strategy` prefers, else of its fallback
/// family. Xray-core picks one of them at random; the first is taken here.
fn endpoint_address(candidates: &[SocketAddr], strategy: DomainStrategy) -> Option<SocketAddr> {
    let of = |families: AddressFamilies| {
        candidates.iter().copied().find(|candidate| match families {
            AddressFamilies::Both => true,
            AddressFamilies::Ipv4 => candidate.is_ipv4(),
            AddressFamilies::Ipv6 => candidate.is_ipv6(),
        })
    };
    of(strategy.preferred()).or_else(|| strategy.fallback().and_then(of))
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
/// An address the tunnel can reach: covered by a peer's `allowedIPs` and with a
/// local interface address of the same family.
fn routable(settings: &WireguardOutboundSettings, address: IpAddr) -> bool {
    settings
        .addresses
        .iter()
        .any(|ip| ip.is_ipv4() == address.is_ipv4())
        && settings
            .peers
            .iter()
            .flat_map(|p| &p.allowed_ips)
            .any(|p| p.contains(address))
}
