//! The MASQUE outbound, as Xray-core v26.10.31's `proxy/masque` client runs
//! it: CONNECT-IP tunnels over HTTP/3 or HTTP/2, pooled as its
//! `XmuxManager` pools them, each with a userspace TCP/IP stack that every
//! TCP and UDP flow goes through.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::sync::Weak;
use std::time::Instant;

use rand::RngCore;
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use xray_config::{MasqueOutboundSettings, MasqueSettings, XhttpXmuxSettings};
use xray_transport::masque::{
    dial_h2, dial_h3, IpPrefix, MasqueError, MasqueH2Config, MasqueH3Config, MasqueRequest,
    MasqueTunnel, MasqueWarp, WriteOutcome, ESTABLISH_TIMEOUT, H2_KEEP_ALIVE, INITIAL_PACKET_SIZE,
    MIN_PACKET_SIZE, QUIC_CONNECTION_ID_LEN, QUIC_IDLE_TIMEOUT, QUIC_KEEP_ALIVE,
};
/// Xray's WARP dial: `quic.Transport.ConnectionIDLength = 20`.
const WARP_CONNECTION_ID_LEN: u8 = 20;
use xray_wireguard::Netstack;

/// Xray's `retryInterval`: after a failed tunnel, flows take an existing one
/// or the same error for this long, without dialing again.
const RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// Xray's client defaults for `remoteDNS`.
const DEFAULT_REMOTE_DNS: [&str; 4] = [
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
];
/// quic-go's default receive windows, which Xray's MASQUE dial keeps unless
/// `quicParams` sets them.
const QUIC_GO_STREAM_WINDOW: u64 = 512 * 1024;
const QUIC_GO_CONNECTION_WINDOW: u64 = 768 * 1024;
/// Where the HTTP/2 carrier's errors point in the config.
const MASQUE_PATHS: super::carrier::ServerConfigPaths = super::carrier::ServerConfigPaths {
    address: "settings.address",
    endpoint: "settings.address and settings.port",
};

#[derive(Clone, Debug)]
pub struct MasqueOutbound(Arc<Owner>);

struct Owner {
    settings: MasqueOutboundSettings,
    dial: Dial,
    authority: String,
    request: MasqueRequest,
    remote_dns: Vec<IpAddr>,
    socket_options: Option<Arc<xray_transport::SocketOptions>>,
    endpoint_strategy: DomainStrategy,
    /// `sockopt.addressPortStrategy`, which Xray's system dialer applies to
    /// the server.
    address_port: xray_config::AddressPortStrategy,
    socket_dialer: Mutex<Option<(TransportDialer, TransportDialer)>>,
    pool: Arc<AsyncMutex<Pool>>,
    /// Every live tunnel, for closing the outbound while a dial holds the
    /// pool.
    tunnels: Mutex<Vec<Weak<Tunnel>>>,
    shutdown: watch::Sender<bool>,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueOutbound")
            .field("server", &self.settings.server)
            .field("port", &self.settings.port)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

/// How tunnels are dialed: Xray's `usesHTTP2` picks HTTP/2 when the TLS
/// ALPN names `h2` and not `h3`.
enum Dial {
    H3 {
        tls: TlsClientConfig,
        quic: Box<H3QuicConfig>,
        warp: Option<MasqueWarp>,
    },
    /// TCP and TLS as the stream settings ask, then Xray's HTTP/2 client.
    /// For WARP the carrier stops at TCP: the TLS that authenticates the
    /// device runs over it with these settings.
    H2 {
        carrier: Box<super::carrier::StreamCarrier>,
        keep_alive: Option<Duration>,
        warp: Option<(MasqueWarp, TlsClientConfig)>,
    },
}

/// Where a dial goes: the QUIC server's address, or the TCP candidates.
enum Endpoint {
    Quic(SocketAddr),
    Tcp(Vec<SocketAddr>),
}

/// Xray's `usesHTTP2`: HTTP/2 when the ALPN names `h2` and not `h3`.
pub(super) fn uses_http2(alpn: &[String]) -> bool {
    alpn.iter().any(|p| p == "h2") && !alpn.iter().any(|p| p == "h3")
}

/// Whether `outbound` is MASQUE over HTTP/2, whose TCP carrier takes the
/// TCP masks as a raw TCP transport does.
pub(crate) fn over_http2(outbound: &OutboundConfig) -> bool {
    matches!(outbound.settings, OutboundSettings::Masque(_))
        && matches!(&outbound.stream.security, StreamSecurity::Tls(tls) if uses_http2(&tls.alpn))
}

/// The HTTP/2 keepalive for `xmux.hKeepAlivePeriod`: Chrome's 45 seconds
/// for zero, none when negative.
fn h2_keep_alive(secs: i64) -> Option<Duration> {
    match secs {
        0 => Some(H2_KEEP_ALIVE),
        secs if secs > 0 => Some(Duration::from_secs(secs as u64)),
        _ => None,
    }
}

/// Xray's check of the HTTP/2 carrier's ALPN: `h2` or nothing to dial.
fn negotiated_h2(alpn: Option<&[u8]>) -> Result<(), MasqueError> {
    match alpn {
        Some(b"h2") => Ok(()),
        other => Err(MasqueError::Dial(format!(
            "the server negotiated {:?} instead of h2",
            String::from_utf8_lossy(other.unwrap_or_default())
        ))),
    }
}

/// Xray's `XmuxManager` as MASQUE uses it: flows count as running
/// requests, and `hMaxRequestTimes` is never spent, so it is not kept.
struct Pool<T: Pooled = Tunnel> {
    xmux: XhttpXmuxSettings,
    concurrency: i32,
    connections: i32,
    entries: Vec<Arc<Entry<T>>>,
    last_error: Option<(String, Instant)>,
}

/// What the pool needs of a tunnel.
trait Pooled {
    fn is_closed(&self) -> bool;
    fn close(&self);
}

/// One pooled tunnel, Xray's `XmuxClient`.
struct Entry<T: Pooled = Tunnel> {
    tunnel: Arc<T>,
    running: AtomicI32,
    left_usage: AtomicI32,
    unreusable_at: Option<Instant>,
    not_used: AtomicBool,
}

impl<T: Pooled> Entry<T> {
    /// Xray's `maybeClose`: a retired tunnel closes with its last flow.
    fn maybe_close(&self) {
        if self.not_used.load(Ordering::Acquire) && self.running.load(Ordering::Acquire) <= 0 {
            self.tunnel.close();
        }
    }
}

/// A flow's hold on its tunnel, Xray's `AddRunning` and `DoneRunning`.
struct Lease<T: Pooled = Tunnel>(Arc<Entry<T>>);

impl<T: Pooled> Lease<T> {
    fn new(entry: Arc<Entry<T>>) -> Self {
        entry.running.fetch_add(1, Ordering::AcqRel);
        Self(entry)
    }
}

impl<T: Pooled> Drop for Lease<T> {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::AcqRel);
        self.0.maybe_close();
    }
}

/// An established tunnel with its stack and its resolver.
struct Tunnel {
    masque: Arc<MasqueTunnel>,
    stack: Netstack,
    dns: Arc<dyn DnsResolver>,
    pumps: Vec<JoinHandle<()>>,
}

impl Pooled for Tunnel {
    fn is_closed(&self) -> bool {
        self.masque.is_closed() || !self.stack.is_live()
    }

    fn close(&self) {
        self.masque.close();
        self.stack.close();
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.close();
        for pump in &self.pumps {
            pump.abort();
        }
    }
}

impl MasqueOutbound {
    pub(crate) fn new(outbound: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Masque(settings) = &outbound.settings else {
            return Err(CoreError::UnsupportedOutboundNetwork);
        };
        let StreamTransport::Masque(transport) = &outbound.stream.transport else {
            return Err(CoreError::UnsupportedOutboundNetwork);
        };
        let StreamSecurity::Tls(tls) = &outbound.stream.security else {
            return Err(CoreError::UnsupportedOutboundSecurity);
        };
        if outbound.proxy_settings.is_some() {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let warp = transport.warp.as_ref().map(|warp| MasqueWarp {
            private_key: warp.private_key.clone(),
            public_key: warp.public_key.clone(),
            addresses: warp
                .addresses
                .iter()
                .map(|&(addr, len)| IpPrefix::new(addr, len))
                .collect(),
        });
        super::carrier::check_xicmp_server(&outbound.stream, &settings.server)?;
        let server_name = tls
            .server_name
            .clone()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| match &settings.server {
                TargetAddr::Domain(domain) => domain.clone(),
                TargetAddr::Ip(ip) => ip.to_string(),
            });
        xray_transport::validate_tls_server_name(&server_name)
            .map_err(|_| CoreError::UnsupportedOutboundSecurity)?;
        let dial = if uses_http2(&tls.alpn) {
            let mut stream = outbound.stream.clone();
            stream.network = Network::Tcp;
            stream.transport = StreamTransport::Raw;
            let mut carrier = super::carrier::StreamCarrier::new(
                &stream,
                &settings.server,
                settings.port,
                false,
                MASQUE_PATHS,
            )?;
            let warp = match warp {
                Some(warp) => {
                    let ConnectorConfig::Tls(tls) =
                        std::mem::replace(&mut carrier.transport, ConnectorConfig::Tcp)
                    else {
                        return Err(CoreError::UnsupportedOutboundSecurity);
                    };
                    Some((warp, tls))
                }
                None => None,
            };
            Dial::H2 {
                carrier: Box::new(carrier),
                keep_alive: h2_keep_alive(transport.xmux.h_keep_alive_period_secs),
                warp,
            }
        } else {
            let mut quic = masque_quic_config(&outbound.stream, transport)?;
            if warp.is_some() {
                quic.connection_id_len = Some(WARP_CONNECTION_ID_LEN);
            }
            quic.diagnostics()
                .map_err(|error| CoreError::InvalidXhttpConfiguration(error.to_string()))?;
            Dial::H3 {
                tls: TlsClientConfig {
                    server_name: server_name.clone(),
                    allow_insecure: tls.allow_insecure,
                    pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                    verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                    alpn: vec!["h3".into()],
                    fingerprint: None,
                },
                quic: Box::new(quic),
                warp,
            }
        };
        let remote_dns = if settings.remote_dns.is_empty() {
            DEFAULT_REMOTE_DNS
                .iter()
                .map(|ip| ip.parse().expect("default DNS"))
                .collect()
        } else {
            settings.remote_dns.clone()
        };
        let authority =
            xray_transport::masque::authority(&transport.host, &server_name, settings.port);
        let xmux = transport.xmux;
        let (concurrency, connections) = {
            let mut rng = rand::thread_rng();
            (
                draw_range(xmux.max_concurrency, &mut rng),
                draw_range(xmux.max_connections, &mut rng),
            )
        };
        Ok(Self(Arc::new(Owner {
            settings: settings.clone(),
            dial,
            authority,
            request: MasqueRequest {
                host: transport.host.clone(),
                path: transport.path.clone(),
                headers: transport.headers.clone(),
            },
            remote_dns,
            socket_options: socket_options::compile(&outbound.stream),
            endpoint_strategy: outbound
                .stream
                .socket_options
                .as_ref()
                .map(|options| options.domain_strategy)
                .unwrap_or_default(),
            address_port: super::carrier::address_port_strategy(&outbound.stream),
            socket_dialer: Mutex::new(None),
            pool: Arc::new(AsyncMutex::new(Pool {
                xmux,
                concurrency,
                connections,
                entries: Vec::new(),
                last_error: None,
            })),
            tunnels: Mutex::new(Vec::new()),
            shutdown: watch::channel(false).0,
        })))
    }

    /// `dialer` with this outbound's socket options: the same dialer each
    /// time `dialer` is the same.
    fn socket_dialer<'a>(
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
        for tunnel in self
            .0
            .tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            if let Some(tunnel) = tunnel.upgrade() {
                tunnel.close();
            }
        }
    }

    /// Xray's `getTunnel`: a pooled tunnel, or a new one, held for the flow.
    /// The pool stays locked while a tunnel is dialed, as Xray's `c.mu`, and
    /// the dial runs on without the flow that started it, as Xray detaches it
    /// from the flow's context.
    async fn tunnel(
        &self,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<Lease, CoreError> {
        let base = dialer.clone();
        let dialer = self.socket_dialer(dialer).into_owned();
        let mut pool = Arc::clone(&self.0.pool).lock_owned().await;
        if *self.0.shutdown.borrow() {
            return Err(MasqueError::Closed("the outbound is closed".into()).into());
        }
        match pool.take() {
            Take::Lease(lease) => return Ok(lease),
            Take::Failed(error) => return Err(MasqueError::Dial(error).into()),
            Take::Dial => {}
        }
        let endpoint = match &self.0.dial {
            Dial::H3 { .. } => self
                .server_address(bootstrap, &dialer)
                .await
                .map(Endpoint::Quic),
            // The carrier applies the socket options itself.
            Dial::H2 { carrier, .. } => carrier
                .resolve_server(bootstrap, &base)
                .await
                .map(Endpoint::Tcp),
        };
        let endpoint = match endpoint {
            Ok(endpoint) => endpoint,
            Err(error) => return pool.dialed(Err(error)),
        };
        let outbound = self.clone();
        let task = tokio::spawn(async move {
            let result = outbound.establish(endpoint, &dialer, &base).await;
            pool.dialed(result)
        });
        let lease = task.await.map_err(|_| {
            CoreError::from(MasqueError::Closed("the tunnel dial was cancelled".into()))
        })??;
        if *self.0.shutdown.borrow() {
            return Err(MasqueError::Closed("the outbound is closed".into()).into());
        }
        Ok(lease)
    }

    /// The server's address, as Xray's system dialer picks it: after
    /// `sockopt.addressPortStrategy`, an IP as given, a domain's first
    /// address of the families `sockopt.domainStrategy` prefers.
    async fn server_address(
        &self,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<SocketAddr, CoreError> {
        let settings = &self.0.settings;
        let server = Target::new(
            match &settings.server {
                TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
                TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
            },
            settings.port,
            RoutingNetwork::Udp,
        );
        let candidates =
            super::address_port::resolve_server(&server, self.0.address_port, bootstrap, dialer)
                .await?;
        match &settings.server {
            TargetAddr::Ip(_) => candidates.into_iter().next(),
            TargetAddr::Domain(_) => {
                super::wireguard::endpoint_address(&candidates, self.0.endpoint_strategy)
            }
        }
        .ok_or_else(|| stack_error(xray_wireguard::Error::NoRoute).into())
    }

    /// Xray's `establish`: a CONNECT-IP tunnel within ten seconds and the
    /// stack over it. `dialer` carries this outbound's socket options;
    /// `base`, for the HTTP/2 carrier, does not.
    async fn establish(
        &self,
        endpoint: Endpoint,
        dialer: &TransportDialer,
        base: &TransportDialer,
    ) -> Result<Arc<Tunnel>, CoreError> {
        let mut shutdown = self.0.shutdown.subscribe();
        let dial = async {
            match (&self.0.dial, endpoint) {
                (Dial::H3 { tls, quic, warp }, Endpoint::Quic(remote_addr)) => Ok(dial_h3(
                    MasqueH3Config {
                        remote_addr,
                        tls: tls.clone(),
                        socket_protector: dialer.socket_protector_arc(),
                        quic: (**quic).clone(),
                        authority: self.0.authority.clone(),
                        request: self.0.request.clone(),
                        warp: warp.clone(),
                        // A realm introduction counts toward the ten seconds,
                        // as it runs under the context of Xray's dial.
                        realm: quic.udp_realm.as_ref().map(|_| dialer.realm_env()),
                    },
                    dialer.tls_connector(),
                )
                .await?),
                (
                    Dial::H2 {
                        carrier,
                        keep_alive,
                        warp,
                    },
                    Endpoint::Tcp(candidates),
                ) => {
                    let stream = carrier.open(&candidates, &[], base).await?;
                    let (mut stream, addresses) = match warp {
                        None => {
                            negotiated_h2(stream.negotiated_alpn())?;
                            (stream, None)
                        }
                        Some((warp, tls)) => {
                            let warp_tls = warp.tls()?;
                            let (stream, alpn) = base
                                .tls_connector()
                                .connect_warp_stream(stream, tls, &warp_tls)
                                .await?;
                            // Xray takes `h2`, or for WARP no protocol at all.
                            if alpn.is_some() {
                                negotiated_h2(alpn.as_deref())?;
                            }
                            (stream, Some(warp.addresses.clone()))
                        }
                    };
                    stream.release_record_alignment();
                    Ok(dial_h2(
                        stream,
                        MasqueH2Config {
                            authority: self.0.authority.clone(),
                            request: self.0.request.clone(),
                            keep_alive: *keep_alive,
                            warp: addresses,
                        },
                    )
                    .await?)
                }
                _ => Err(CoreError::from(MasqueError::Dial(
                    "the dial and its endpoint disagree".into(),
                ))),
            }
        };
        let masque = tokio::select! { biased;
            _ = shutdown.changed() => return Err(MasqueError::Closed("the outbound is closed".into()).into()),
            result = tokio::time::timeout(ESTABLISH_TIMEOUT, dial) => {
                result.map_err(|_| CoreError::from(MasqueError::Timeout))??
            }
        };
        let tunnel = self.start_stack(masque)?;
        let mut tunnels = self.0.tunnels.lock().unwrap_or_else(|e| e.into_inner());
        tunnels.retain(|tunnel| tunnel.strong_count() > 0);
        tunnels.push(Arc::downgrade(&tunnel));
        if *self.0.shutdown.borrow() {
            tunnel.close();
            return Err(MasqueError::Closed("the outbound is closed".into()).into());
        }
        Ok(tunnel)
    }

    /// Xray's `newTunnel`: a stack of MTU 1280 on the assigned addresses,
    /// fed from the tunnel and back, resolving through the `remoteDNS`
    /// servers of its families, or all of them when none matches.
    fn start_stack(&self, masque: MasqueTunnel) -> Result<Arc<Tunnel>, CoreError> {
        let local = masque.local_addrs().to_vec();
        let (stack, packets) =
            Netstack::start(local.clone(), MIN_PACKET_SIZE as u16).map_err(stack_error)?;
        let masque = Arc::new(masque);
        let xray_wireguard::NetstackPackets {
            mut outgoing,
            incoming,
        } = packets;
        let reader = tokio::spawn({
            let masque = Arc::clone(&masque);
            let stack = stack.clone();
            let incoming = incoming.clone();
            async move {
                while let Ok(packet) = masque.read_packet().await {
                    if incoming.send(packet).await.is_err() {
                        break;
                    }
                }
                stack.close();
            }
        });
        let writer = tokio::spawn({
            let masque = Arc::clone(&masque);
            let stack = stack.clone();
            async move {
                while let Some(packet) = outgoing.recv().await {
                    match masque.write_packet(&packet).await {
                        // Xray writes the ICMP message back into its stack.
                        Ok(WriteOutcome::TooBig(icmp)) => {
                            let _ = incoming.try_send(bytes::Bytes::from(icmp));
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                masque.close();
                stack.close();
            }
        });
        let mut servers: Vec<IpAddr> = self
            .0
            .remote_dns
            .iter()
            .copied()
            .filter(|dns| local.iter().any(|ip| ip.is_ipv4() == dns.is_ipv4()))
            .collect();
        if servers.is_empty() {
            servers = self.0.remote_dns.clone();
        }
        let dns = super::wireguard::dns::resolver(
            super::wireguard::dns::TunnelFlows::Netstack(stack.clone()),
            &servers,
        );
        Ok(Arc::new(Tunnel {
            masque,
            stack,
            dns,
            pumps: vec![reader, writer],
        }))
    }

    async fn destinations(
        &self,
        tunnel: &Tunnel,
        target: &Target,
    ) -> Result<Vec<SocketAddr>, CoreError> {
        use xray_transport::DnsQueryStrategy;
        let local = tunnel.stack.addresses();
        let has_ipv4 = local.iter().any(IpAddr::is_ipv4);
        let has_ipv6 = local.iter().any(IpAddr::is_ipv6);
        let strategy = match (has_ipv4, has_ipv6) {
            (true, false) => DnsQueryStrategy::UseIpv4,
            (false, true) => DnsQueryStrategy::UseIpv6,
            _ => DnsQueryStrategy::UseIp,
        };
        let mut candidates = match &target.addr {
            RoutingTargetAddr::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
            RoutingTargetAddr::Domain(domain) => match domain.parse::<IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, target.port)],
                Err(_) => tunnel
                    .dns
                    .resolve_all_with_strategy(domain, target.port, strategy)
                    .await?
                    .socket_addrs()
                    .to_vec(),
            },
        };
        candidates.retain(|addr| if addr.is_ipv4() { has_ipv4 } else { has_ipv6 });
        // The stack's lookup puts IPv6 answers first when it has an IPv6
        // address, as the WireGuard client's does.
        if has_ipv6 {
            candidates.sort_by_key(SocketAddr::is_ipv4);
        }
        candidates.truncate(8);
        if candidates.is_empty() {
            return Err(stack_error(xray_wireguard::Error::NoRoute).into());
        }
        Ok(candidates)
    }

    async fn bounded<T>(
        &self,
        operation: impl Future<Output = Result<T, CoreError>>,
    ) -> Result<T, CoreError> {
        let mut shutdown = self.0.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(MasqueError::Closed("the outbound is closed".into()).into());
        }
        tokio::select! { biased;
            _ = shutdown.changed() => Err(MasqueError::Closed("the outbound is closed".into()).into()),
            result = tokio::time::timeout(Duration::from_secs(20), operation) => {
                result.map_err(|_| CoreError::from(MasqueError::Timeout))?
            }
        }
    }

    pub(crate) async fn open_tcp(
        &self,
        target: &Target,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        self.bounded(async {
            let lease = self.tunnel(bootstrap, dialer).await?;
            let tunnel = Arc::clone(&lease.0.tunnel);
            let addresses = self.destinations(&tunnel, target).await?;
            let mut error = xray_wireguard::Error::NoRoute;
            let last = addresses.len() - 1;
            for (index, address) in addresses.into_iter().enumerate() {
                let attempt = if index == last { 10 } else { 3 };
                match tokio::time::timeout(
                    Duration::from_secs(attempt),
                    tunnel.stack.connect(address),
                )
                .await
                .unwrap_or(Err(xray_wireguard::Error::Timeout))
                {
                    Ok(stream) => {
                        return Ok(Box::new(MasqueTcpStream {
                            stream,
                            _lease: lease,
                        }) as BoxedTransportStream)
                    }
                    Err(e @ (xray_wireguard::Error::Closed | xray_wireguard::Error::Busy)) => {
                        return Err(stack_error(e).into())
                    }
                    Err(e) => error = e,
                }
            }
            Err(stack_error(error).into())
        })
        .await
    }

    pub(crate) async fn open_udp(
        &self,
        target: &Target,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<MasqueUdpSession, CoreError> {
        self.bounded(async {
            let lease = self.tunnel(bootstrap, dialer).await?;
            let tunnel = Arc::clone(&lease.0.tunnel);
            let address = self
                .destinations(&tunnel, target)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| stack_error(xray_wireguard::Error::NoRoute))?;
            let session = tunnel.stack.open_udp(address).await.map_err(stack_error)?;
            Ok(MasqueUdpSession {
                session,
                _lease: lease,
            })
        })
        .await
    }
}

/// What a flow does next, Xray's `getTunnel` before it dials.
enum Take<T: Pooled> {
    Lease(Lease<T>),
    Dial,
    /// A dial failed within the last second and no tunnel is left.
    Failed(String),
}

impl<T: Pooled> Pool<T> {
    /// A tunnel to hold, or whether to dial one. Within a second of a failed
    /// dial, flows take an existing tunnel or the failure.
    fn take(&mut self) -> Take<T> {
        let recent_failure = self
            .last_error
            .as_ref()
            .filter(|(_, at)| at.elapsed() < RETRY_INTERVAL)
            .map(|(error, _)| error.clone());
        if let Some(error) = recent_failure {
            return match self.select(false) {
                Some(entry) => Take::Lease(Lease::new(entry)),
                None => Take::Failed(error),
            };
        }
        match self.select(true) {
            Some(entry) => Take::Lease(Lease::new(entry)),
            None => Take::Dial,
        }
    }

    /// After a dial: the new tunnel, or after a failure an existing one.
    fn dialed(&mut self, result: Result<Arc<T>, CoreError>) -> Result<Lease<T>, CoreError> {
        match result {
            Ok(tunnel) => {
                self.last_error = None;
                Ok(Lease::new(self.push(tunnel)))
            }
            Err(error) => {
                self.last_error = Some((error.to_string(), Instant::now()));
                self.select(false).map(Lease::new).ok_or(error)
            }
        }
    }

    /// Xray's `getXmuxClient`: drops tunnels that are closed, used up or too
    /// old, then picks one. `None` with `create` asks for a new tunnel.
    fn select(&mut self, create: bool) -> Option<Arc<Entry<T>>> {
        let now = Instant::now();
        self.entries.retain(|entry| {
            let retired = entry.tunnel.is_closed()
                || entry.left_usage.load(Ordering::Acquire) == 0
                || entry.unreusable_at.is_some_and(|at| now > at);
            if retired {
                entry.not_used.store(true, Ordering::Release);
                entry.maybe_close();
            }
            !retired
        });
        if self.entries.is_empty() {
            return None;
        }
        if create && self.connections > 0 && self.entries.len() < self.connections as usize {
            return None;
        }
        let eligible: Vec<&Arc<Entry<T>>> = self
            .entries
            .iter()
            .filter(|entry| {
                self.concurrency <= 0 || entry.running.load(Ordering::Acquire) < self.concurrency
            })
            .collect();
        if eligible.is_empty() {
            return None;
        }
        let entry = Arc::clone(eligible[rand::thread_rng().gen_range(0..eligible.len())]);
        let left = entry.left_usage.load(Ordering::Acquire);
        if left > 0 {
            entry.left_usage.store(left - 1, Ordering::Release);
        }
        Some(entry)
    }

    /// Xray's `newXmuxClient`.
    fn push(&mut self, tunnel: Arc<T>) -> Arc<Entry<T>> {
        let mut rng = rand::thread_rng();
        let reuse = draw_range(self.xmux.c_max_reuse_times, &mut rng);
        let secs = draw_range(self.xmux.h_max_reusable_secs, &mut rng);
        let entry = Arc::new(Entry {
            tunnel,
            running: AtomicI32::new(0),
            left_usage: AtomicI32::new(if reuse > 0 { reuse - 1 } else { -1 }),
            unreusable_at: (secs > 0).then(|| Instant::now() + Duration::from_secs(secs as u64)),
            not_used: AtomicBool::new(false),
        });
        self.entries.push(Arc::clone(&entry));
        entry
    }
}

/// The open deadline of a MASQUE flow: Xray dials the tunnel, for up to ten
/// seconds, before the handshake timeout starts. Zero stays unbounded.
pub(crate) fn open_timeout(handshake: Duration) -> Duration {
    if handshake.is_zero() {
        handshake
    } else {
        handshake + ESTABLISH_TIMEOUT
    }
}

/// Xray's `RangeConfig.rand`, `crypto.RandBetween`: from `from` up to but
/// not including `to`.
fn draw_range(range: xray_config::XhttpRange, rng: &mut impl RngCore) -> i32 {
    let (from, to) = (range.from.min(range.to), range.from.max(range.to));
    let span = (i64::from(to) - i64::from(from)) as u64;
    if span <= 1 {
        return from;
    }
    (i64::from(from) + rng.gen_range(0..span) as i64) as i32
}

/// A flow's error from the stack, worded for MASQUE.
fn stack_error(error: xray_wireguard::Error) -> MasqueError {
    use xray_wireguard::Error;
    MasqueError::Closed(
        match error {
            Error::Busy => "the tunnel's flow budget is exhausted",
            Error::NoRoute => "the destination has no address family the tunnel was assigned",
            Error::Timeout => "a connection through the tunnel timed out",
            Error::Connect => "a TCP connection through the tunnel failed",
            Error::PacketTooLarge => "the UDP payload exceeds the tunnel's MTU",
            Error::Closed => "the tunnel is closed",
            _ => "the tunnel's stack failed",
        }
        .to_owned(),
    )
}

/// Xray's MASQUE QUIC configuration: `quicParams` with quic-go's defaults
/// where it is silent, a 30-second idle timeout, the 10-second keepalive or
/// `xmux.hKeepAlivePeriod`, no incoming streams, 1350-byte first packets,
/// four-byte connection IDs, and `brutal` as BBR.
fn masque_quic_config(
    stream: &StreamSettings,
    transport: &MasqueSettings,
) -> Result<H3QuicConfig, CoreError> {
    let params = stream.quic_params.as_ref();
    let mut config = xhttp_h3_quic_config(
        params
            .map(|params| {
                if params.congestion == xray_config::QuicCongestion::Brutal {
                    // Xray's dial runs BBR for it; nothing negotiates a rate.
                    let mut params = params.clone();
                    params.congestion = xray_config::QuicCongestion::Bbr;
                    std::borrow::Cow::Owned(params)
                } else {
                    std::borrow::Cow::Borrowed(params)
                }
            })
            .as_deref(),
    )?;
    if params.is_none_or(|p| p.init_stream_receive_window == 0) {
        config.initial_stream_receive_window = QUIC_GO_STREAM_WINDOW;
    }
    if params.is_none_or(|p| p.init_connection_receive_window == 0) {
        config.initial_connection_receive_window = QUIC_GO_CONNECTION_WINDOW;
    }
    if params.is_none_or(|p| p.max_idle_timeout_secs == 0) {
        config.max_idle_timeout = QUIC_IDLE_TIMEOUT;
    }
    if params.is_none_or(|p| p.keep_alive_period_secs == 0) {
        config.keep_alive_interval = match transport.xmux.h_keep_alive_period_secs {
            0 => Some(QUIC_KEEP_ALIVE),
            secs if secs > 0 => Some(Duration::from_secs(secs as u64)),
            _ => None,
        };
    }
    config.max_incoming_bidirectional_streams = 0;
    config.initial_packet_size = Some(INITIAL_PACKET_SIZE);
    config.connection_id_len = Some(QUIC_CONNECTION_ID_LEN);
    config.udp_noise = stream
        .udp_noise
        .as_ref()
        .map(udp_noise_config)
        .transpose()?;
    config.udp_header_custom = stream
        .udp_header_custom
        .as_ref()
        .map(super::carrier::quic_header_custom);
    config.udp_sudoku = stream.udp_sudoku.as_ref().map(super::carrier::quic_sudoku);
    config.udp_xdns = stream.udp_xdns.as_ref().map(super::carrier::xdns_config);
    config.udp_realm = stream.udp_realm.as_ref().map(super::carrier::realm_config);
    config.udp_xicmp = stream.udp_xicmp.as_ref().map(super::carrier::xicmp_config);
    Ok(config)
}

/// A TCP flow through a tunnel; it holds the tunnel while open.
struct MasqueTcpStream {
    stream: xray_wireguard::TcpStream,
    _lease: Lease,
}

impl AsyncRead for MasqueTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MasqueTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl TransportStream for MasqueTcpStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, buf)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }
}

/// A UDP flow through a tunnel, to one destination; it holds the tunnel.
pub(crate) struct MasqueUdpSession {
    session: xray_wireguard::UdpSession,
    _lease: Lease,
}

impl MasqueUdpSession {
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.session.peer_addr()
    }
    pub(crate) fn max_payload(&self) -> usize {
        self.session.max_payload()
    }
    pub(crate) async fn send(&self, payload: &[u8]) -> Result<(), CoreError> {
        Ok(self.session.send(payload).await.map_err(stack_error)?)
    }
    pub(crate) async fn recv(&self) -> Result<bytes::Bytes, CoreError> {
        Ok(self.session.recv().await.map_err(stack_error)?)
    }
}

#[cfg(test)]
mod tests;
