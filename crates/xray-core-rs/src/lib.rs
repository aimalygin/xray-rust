use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use xray_config::{CoreConfig, DnsHostTarget, DnsServerConfig, DomainMatcher, InboundProtocol};
use xray_runtime::Shutdown;
use xray_transport::{
    CachingDnsResolver, ConfiguredDnsResolver, DnsQueryTransport, DnsResolver, NameServer,
    SocketProtector, StaticHostRule, StaticHostTarget, SystemDnsResolver, TransportDialer,
    TransportDomainMatcher, TransportError,
};
use xray_tun::{TunConfig, TunEndpoint};

mod debug_log;
mod dns;
mod http;
mod outbound;
mod policy;
mod runtime_log;
mod runtime_stats_log;
mod sniffing;
mod socks;
mod startup_probe;
mod tun;
mod tun_fd;

const TUN_MTU: usize = 1500;
const TUN_INBOUND_QUEUE_DEPTH: usize = 1024;
const TUN_OUTBOUND_QUEUE_DEPTH: usize = 4096;

pub use outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_tcp_stream,
    open_vless_tcp_stream_with_resolver, open_vless_tcp_stream_with_resolver_and_dialer,
    open_vless_udp_stream_with_resolver_and_dialer, select_tcp_outbound,
    select_tcp_outbound_for_session, select_tcp_outbound_for_session_with_resolver,
    select_udp_outbound_for_session, select_udp_outbound_for_session_with_resolver,
    select_vless_tcp_outbound, OutboundRouter, TcpOutbound, UdpOutbound, VlessTcpOutbound,
    VlessUdpFraming,
};
pub use runtime_log::{RuntimeLogConfig, RuntimeLogger};
pub use startup_probe::{StartupProbeError, StartupProbeOptions};
pub use tun_fd::{TunFdClosePolicy, TunFdConfig, TunFdPacketFormat, TunFdRuntime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreState {
    Created,
    Running,
    Stopped,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunRuntimeOptions {
    pub collect_tcp_timings: bool,
    pub profile: TunRuntimeProfile,
    pub dns_bootstrap: DnsBootstrapMode,
}

/// Controls bootstrap and final-fallback policy for managed runtime DNS.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DnsBootstrapMode {
    /// Resolve destinations through `dns.hosts`, routed `dns.servers`, then
    /// the operating-system fallback. DNS-upstream and outbound-server
    /// bootstrap uses `dns.hosts` plus the operating-system resolver. This is
    /// the default for embeddings that do not install a local DNS anchor and
    /// is the intended policy for future server runtimes.
    #[default]
    System,
    /// Resolve destinations through `dns.hosts` and routed `dns.servers`, then
    /// fail closed. Bootstrap itself uses only `dns.hosts`, so it cannot recurse
    /// through a tunnel-local DNS anchor. Mobile VPN integrations should use
    /// this after installing that anchor. Constructors with an explicitly
    /// injected resolver keep using it as a trusted integration dependency.
    StaticOnly,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TunRuntimeProfile {
    #[default]
    Default,
    Mobile,
    MobilePlus,
    Desktop,
    LowMemory,
    Throughput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunQueueOptions {
    pub mtu: usize,
    pub inbound_queue_depth: usize,
    pub outbound_queue_depth: usize,
}

impl TunRuntimeOptions {
    pub fn with_profile(profile: TunRuntimeProfile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }

    pub fn tun_queue_options(self) -> TunQueueOptions {
        match self.profile {
            TunRuntimeProfile::LowMemory => TunQueueOptions {
                mtu: TUN_MTU,
                inbound_queue_depth: 256,
                outbound_queue_depth: 512,
            },
            TunRuntimeProfile::Throughput => TunQueueOptions {
                mtu: TUN_MTU,
                inbound_queue_depth: 2048,
                outbound_queue_depth: 8192,
            },
            TunRuntimeProfile::MobilePlus => TunQueueOptions {
                mtu: TUN_MTU,
                inbound_queue_depth: 2048,
                outbound_queue_depth: 8192,
            },
            TunRuntimeProfile::Default | TunRuntimeProfile::Mobile | TunRuntimeProfile::Desktop => {
                TunQueueOptions {
                    mtu: TUN_MTU,
                    inbound_queue_depth: TUN_INBOUND_QUEUE_DEPTH,
                    outbound_queue_depth: TUN_OUTBOUND_QUEUE_DEPTH,
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundInbound {
    pub tag: Option<String>,
    pub addr: SocketAddr,
}

#[derive(Debug)]
struct RuntimeState {
    inbounds: Vec<BoundInbound>,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("core is already running")]
    AlreadyRunning,
    #[error("core is already stopped")]
    AlreadyStopped,
    #[error("no supported inbound found")]
    NoSupportedInbound,
    #[error("no supported outbound found")]
    NoSupportedOutbound,
    #[error("unauthenticated SOCKS/HTTP listener requires explicit LAN exposure permission")]
    UnauthenticatedLanExposure,
    #[error("outbound network is not supported")]
    UnsupportedOutboundNetwork,
    #[error("outbound security is not supported")]
    UnsupportedOutboundSecurity,
    // Reserved for future config address kinds; current VLESS TCP selection supports IP and domain servers.
    #[error("outbound server address is not supported")]
    UnsupportedOutboundServerAddress,
    #[error("outbound flow is not supported")]
    UnsupportedOutboundFlow,
    #[error("XTLS rejected UDP/443 traffic")]
    VisionUdp443Rejected,
    #[error("transport error: {0}")]
    Transport(#[from] xray_transport::TransportError),
    #[error("vless header error: {0}")]
    VlessHeader(#[from] xray_proxy::vless::WireError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("startup probe failed: {0}")]
    StartupProbe(#[from] StartupProbeError),
}

pub struct Core {
    config: CoreConfig,
    state: CoreState,
    shutdown: Shutdown,
    tun: Arc<TunEndpoint>,
    runtime: Option<RuntimeState>,
    dns_resolver: Arc<dyn DnsResolver>,
    dns_bootstrap_resolver: Option<Arc<dyn DnsResolver>>,
    managed_dns_resolver: bool,
    transport_dialer: Arc<TransportDialer>,
    tun_runtime_options: TunRuntimeOptions,
    startup_probe: Option<StartupProbeOptions>,
    runtime_logger: RuntimeLogger,
}

impl Core {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        let system_resolver = system_dns_resolver();
        let dns_resolver =
            configured_dns_resolver_for_config(&config, Arc::clone(&system_resolver));
        let dns_bootstrap_resolver = host_only_dns_resolver_for_config(&config, system_resolver);
        Self::build(
            config,
            dns_resolver,
            Some(dns_bootstrap_resolver),
            Arc::new(TransportDialer::system()?),
            TunRuntimeOptions::default(),
            true,
        )
    }

    /// Creates a core with an injected DNS resolver.
    ///
    /// The injected resolver is used as-is for deterministic tests and custom
    /// integrations. `config.dns` hosts and servers are applied by the default
    /// constructors (`new` and `with_tun_runtime_options`) instead.
    pub fn with_dns_resolver(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, CoreError> {
        Self::build(
            config,
            Arc::clone(&dns_resolver),
            Some(dns_resolver),
            Arc::new(TransportDialer::system()?),
            TunRuntimeOptions::default(),
            false,
        )
    }

    pub fn with_tun_runtime_options(
        config: CoreConfig,
        tun_runtime_options: TunRuntimeOptions,
    ) -> Result<Self, CoreError> {
        let system_resolver = system_dns_resolver();
        let (dns_resolver, dns_bootstrap_resolver) = match tun_runtime_options.dns_bootstrap {
            DnsBootstrapMode::System => (
                configured_dns_resolver_for_config(&config, Arc::clone(&system_resolver)),
                Some(host_only_dns_resolver_for_config(&config, system_resolver)),
            ),
            DnsBootstrapMode::StaticOnly => {
                let resolver = static_only_dns_resolver_for_config(&config);
                (Arc::clone(&resolver), Some(resolver))
            }
        };
        Self::build(
            config,
            dns_resolver,
            dns_bootstrap_resolver,
            Arc::new(TransportDialer::system()?),
            tun_runtime_options,
            true,
        )
    }

    /// Creates a core whose System-mode direct DNS sockets and managed TUN
    /// routed Freedom DNS sockets share the dialer's socket-protection policy.
    pub fn with_transport_dialer_and_tun_options(
        config: CoreConfig,
        transport_dialer: Arc<TransportDialer>,
        tun_runtime_options: TunRuntimeOptions,
    ) -> Result<Self, CoreError> {
        let system_resolver = system_dns_resolver();
        let (dns_resolver, dns_bootstrap_resolver) = match tun_runtime_options.dns_bootstrap {
            DnsBootstrapMode::System => (
                configured_dns_resolver_for_config_with_socket_protector(
                    &config,
                    Arc::clone(&system_resolver),
                    transport_dialer.socket_protector_arc(),
                ),
                Some(host_only_dns_resolver_for_config(&config, system_resolver)),
            ),
            DnsBootstrapMode::StaticOnly => {
                let resolver = static_only_dns_resolver_for_config(&config);
                (Arc::clone(&resolver), Some(resolver))
            }
        };
        Self::build(
            config,
            dns_resolver,
            dns_bootstrap_resolver,
            transport_dialer,
            tun_runtime_options,
            true,
        )
    }

    pub fn with_runtime_dependencies(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
    ) -> Result<Self, CoreError> {
        Self::build(
            config,
            Arc::clone(&dns_resolver),
            Some(dns_resolver),
            transport_dialer,
            TunRuntimeOptions::default(),
            false,
        )
    }

    pub fn with_runtime_dependencies_and_tun_options(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
        tun_runtime_options: TunRuntimeOptions,
    ) -> Result<Self, CoreError> {
        let dns_bootstrap_resolver = Some(Arc::clone(&dns_resolver));
        Self::build(
            config,
            dns_resolver,
            dns_bootstrap_resolver,
            transport_dialer,
            tun_runtime_options,
            false,
        )
    }

    fn build(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        dns_bootstrap_resolver: Option<Arc<dyn DnsResolver>>,
        transport_dialer: Arc<TransportDialer>,
        tun_runtime_options: TunRuntimeOptions,
        managed_dns_resolver: bool,
    ) -> Result<Self, CoreError> {
        let shutdown = Shutdown::new();
        let tun_queue_options = tun_runtime_options.tun_queue_options();
        let tun = Arc::new(TunEndpoint::new_with_queue_depths(
            TunConfig {
                mtu: tun_queue_options.mtu,
                queue_depth: tun_queue_options.inbound_queue_depth,
            },
            tun_queue_options.inbound_queue_depth,
            tun_queue_options.outbound_queue_depth,
        ));

        Ok(Self {
            config,
            state: CoreState::Created,
            shutdown,
            tun,
            runtime: None,
            dns_resolver,
            dns_bootstrap_resolver,
            managed_dns_resolver,
            transport_dialer,
            tun_runtime_options,
            startup_probe: None,
            runtime_logger: RuntimeLogger::disabled(),
        })
    }

    pub fn state(&self) -> CoreState {
        self.state
    }

    pub fn with_startup_probe(mut self, options: StartupProbeOptions) -> Self {
        self.startup_probe = Some(options);
        self
    }

    pub fn set_startup_probe(&mut self, options: Option<StartupProbeOptions>) {
        self.startup_probe = options;
    }

    pub fn set_runtime_logger(&mut self, runtime_logger: RuntimeLogger) {
        self.runtime_logger = runtime_logger;
    }

    pub fn runtime_logger(&self) -> &RuntimeLogger {
        &self.runtime_logger
    }

    fn runtime_dns_resolvers(
        &self,
        config: &Arc<CoreConfig>,
        outbound_router: &Arc<OutboundRouter>,
        inbound_tag: Option<String>,
        forbid_tun_runtime_servers: bool,
    ) -> dns::RuntimeDnsResolvers {
        let bootstrap = self
            .dns_bootstrap_resolver
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.dns_resolver));
        if !self.managed_dns_resolver {
            return dns::RuntimeDnsResolvers {
                destination: Arc::clone(&self.dns_resolver),
                bootstrap,
            };
        }

        let fallback: Arc<dyn DnsResolver> = match self.tun_runtime_options.dns_bootstrap {
            DnsBootstrapMode::System => system_dns_resolver(),
            DnsBootstrapMode::StaticOnly => Arc::new(FailClosedDnsResolver),
        };
        let forbidden_servers: Vec<SocketAddr> = if forbid_tun_runtime_servers {
            vec![
                SocketAddr::new(std::net::IpAddr::V4(tun::TUN_DNS_ANCHOR), tun::DNS_PORT),
                SocketAddr::new(std::net::IpAddr::V4(tun::TUN_CLIENT_IPV4), tun::DNS_PORT),
            ]
        } else {
            Vec::new()
        };
        let query_transport: Arc<dyn DnsQueryTransport> =
            Arc::new(dns::RoutedDnsQueryTransport::new(
                Arc::clone(outbound_router),
                inbound_tag,
                Arc::clone(&bootstrap),
                Arc::clone(&self.transport_dialer),
                forbidden_servers,
            ));
        let resolver = configured_dns_resolver_from_config_with_transport(
            config.as_ref(),
            fallback,
            None,
            true,
            Some(query_transport),
        );
        dns::RuntimeDnsResolvers {
            destination: Arc::new(CachingDnsResolver::new(resolver)),
            bootstrap,
        }
    }

    pub fn inbound_addr(&self, tag: Option<&str>) -> Option<SocketAddr> {
        self.runtime
            .as_ref()?
            .inbounds
            .iter()
            .find(|inbound| inbound.tag.as_deref() == tag)
            .map(|inbound| inbound.addr)
    }

    pub async fn start(&mut self) -> Result<(), CoreError> {
        if self.state == CoreState::Running {
            return Err(CoreError::AlreadyRunning);
        }
        if self.state == CoreState::Stopped {
            return Err(CoreError::AlreadyStopped);
        }

        let mut bound_listeners = Vec::new();
        let mut tun_inbounds = Vec::new();
        for inbound in &self.config.inbounds {
            match inbound.protocol {
                InboundProtocol::Socks | InboundProtocol::Http => {}
                InboundProtocol::Tun => {
                    tun_inbounds.push((
                        inbound.tag.clone(),
                        inbound.sniffing.clone(),
                        policy::effective_policy_for_level(&self.config, inbound.user_level),
                    ));
                    continue;
                }
            }

            if !inbound.allow_unauthenticated_lan {
                let listen = inbound
                    .listen
                    .strip_prefix('[')
                    .and_then(|address| address.strip_suffix(']'))
                    .unwrap_or(&inbound.listen);
                if listen
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| !address.is_loopback())
                {
                    return Err(CoreError::UnauthenticatedLanExposure);
                }
            }
            let listener = TcpListener::bind((inbound.listen.as_str(), inbound.port)).await?;
            let addr = listener.local_addr()?;
            if !inbound.allow_unauthenticated_lan && !addr.ip().is_loopback() {
                return Err(CoreError::UnauthenticatedLanExposure);
            }
            bound_listeners.push((
                BoundInbound {
                    tag: inbound.tag.clone(),
                    addr,
                },
                inbound.protocol.clone(),
                inbound.sniffing.clone(),
                policy::effective_policy_for_level(&self.config, inbound.user_level),
                listener,
            ));
        }

        if bound_listeners.is_empty() && tun_inbounds.is_empty() {
            return Err(CoreError::NoSupportedInbound);
        }

        let config = Arc::new(self.config.clone());
        let outbound_router = Arc::new(OutboundRouter::new(Arc::clone(&config)));
        let has_tun_inbound = !tun_inbounds.is_empty();
        let mut inbounds = Vec::with_capacity(bound_listeners.len());
        let mut tasks = Vec::with_capacity(
            bound_listeners.len() + usize::from(has_tun_inbound) + usize::from(has_tun_inbound),
        );
        for (bound, protocol, sniffing, policy, listener) in bound_listeners {
            let inbound_tag = bound.tag.clone();
            let dns_resolvers = self.runtime_dns_resolvers(
                &config,
                &outbound_router,
                inbound_tag.clone(),
                has_tun_inbound,
            );
            let transport_dialer = Arc::clone(&self.transport_dialer);
            let task = match protocol {
                InboundProtocol::Socks => tokio::spawn(socks::serve_socks_listener(
                    listener,
                    inbound_tag,
                    Arc::clone(&config),
                    Arc::clone(&outbound_router),
                    dns_resolvers,
                    transport_dialer,
                    sniffing,
                    policy,
                    self.runtime_logger.clone(),
                    self.shutdown.subscribe(),
                )),
                InboundProtocol::Http => tokio::spawn(http::serve_http_listener(
                    listener,
                    inbound_tag,
                    Arc::clone(&config),
                    Arc::clone(&outbound_router),
                    dns_resolvers,
                    transport_dialer,
                    policy,
                    self.runtime_logger.clone(),
                    self.shutdown.subscribe(),
                )),
                InboundProtocol::Tun => continue,
            };
            inbounds.push(bound);
            tasks.push(task);
        }
        if has_tun_inbound {
            let tun_inbound_tag = tun_inbounds.first().and_then(|(tag, _, _)| tag.clone());
            let tun_dns_resolvers = self.runtime_dns_resolvers(
                &config,
                &outbound_router,
                tun_inbound_tag.clone(),
                true,
            );
            let tun_runtime_options = TunRuntimeOptions {
                collect_tcp_timings: self.tun_runtime_options.collect_tcp_timings
                    || self.runtime_logger.is_enabled(),
                ..self.tun_runtime_options
            };
            tasks.push(tokio::spawn(tun::serve_tun_endpoint(
                Arc::clone(&self.tun),
                tun_inbound_tag,
                tun_inbounds
                    .first()
                    .and_then(|(_, sniffing, _)| sniffing.clone()),
                tun_inbounds
                    .first()
                    .map(|(_, _, policy)| *policy)
                    .unwrap_or_default(),
                Arc::clone(&config),
                Arc::clone(&outbound_router),
                tun_dns_resolvers.destination,
                Some(tun_dns_resolvers.bootstrap),
                Arc::clone(&self.transport_dialer),
                tun_runtime_options,
                self.runtime_logger.clone(),
                self.shutdown.subscribe(),
            )));
            if let Some(task) = runtime_stats_log::spawn_runtime_stats_logger(
                Arc::clone(&self.tun),
                self.runtime_logger.clone(),
                self.shutdown.subscribe(),
            ) {
                tasks.push(task);
            }
        }

        self.runtime = Some(RuntimeState { inbounds, tasks });
        self.state = CoreState::Running;

        if let Some(options) = self.startup_probe.clone() {
            let probe_dns_resolvers =
                self.runtime_dns_resolvers(&config, &outbound_router, None, has_tun_inbound);
            let probe_url = startup_probe::diagnostic_probe_url(&options.url);
            let probe_timeout_ms = options.timeout.as_millis();
            let probe_outbound = if options.outbound_tag.is_some() {
                "<configured>"
            } else {
                "default"
            };
            self.runtime_logger.debug(|| {
                format!(
                    "Debug startupProbe start url={probe_url} timeoutMs={probe_timeout_ms} outbound={probe_outbound}"
                )
            });
            if let Err(error) = startup_probe::run_startup_probe(
                outbound_router.as_ref(),
                options,
                probe_dns_resolvers.destination.as_ref(),
                probe_dns_resolvers.bootstrap.as_ref(),
                self.transport_dialer.as_ref(),
            )
            .await
            {
                self.runtime_logger
                    .error(|| format!("Debug startupProbe fail url={probe_url} error=<redacted>"));
                let _ = self.stop().await;
                return Err(CoreError::StartupProbe(error));
            }
            self.runtime_logger
                .debug(|| format!("Debug startupProbe success url={probe_url}"));
        }

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), CoreError> {
        self.shutdown.signal();
        if let Some(runtime) = self.runtime.take() {
            for task in runtime.tasks {
                task.abort();
                let _ = task.await;
            }
        }
        self.tun.close();
        self.state = CoreState::Stopped;
        Ok(())
    }

    pub fn tun(&self) -> &TunEndpoint {
        self.tun.as_ref()
    }

    pub fn tun_handle(&self) -> Arc<TunEndpoint> {
        Arc::clone(&self.tun)
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn system_dns_resolver() -> Arc<dyn DnsResolver> {
    Arc::new(CachingDnsResolver::new(Arc::new(SystemDnsResolver)))
}

#[derive(Debug)]
struct FailClosedDnsResolver;

#[async_trait]
impl DnsResolver for FailClosedDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
    }
}

fn static_only_dns_resolver_for_config(config: &CoreConfig) -> Arc<dyn DnsResolver> {
    host_only_dns_resolver_for_config(config, Arc::new(FailClosedDnsResolver))
}

fn host_only_dns_resolver_for_config(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_from_config(config, fallback, None, false)
}

fn configured_dns_resolver_for_config(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_for_config_with_socket_protector(config, fallback, None)
}

fn configured_dns_resolver_for_config_with_socket_protector(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_from_config(config, fallback, socket_protector, true)
}

fn configured_dns_resolver_from_config(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    include_name_servers: bool,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_from_config_with_transport(
        config,
        fallback,
        socket_protector,
        include_name_servers,
        None,
    )
}

fn configured_dns_resolver_from_config_with_transport(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    include_name_servers: bool,
    query_transport: Option<Arc<dyn DnsQueryTransport>>,
) -> Arc<dyn DnsResolver> {
    if config.dns.hosts.is_empty() && (!include_name_servers || config.dns.servers.is_empty()) {
        return fallback;
    }

    let host_rules = config
        .dns
        .hosts
        .iter()
        .map(|host| StaticHostRule {
            matcher: transport_domain_matcher(&host.matcher),
            target: match &host.target {
                DnsHostTarget::Ip(ip) => StaticHostTarget::Ip(*ip),
                DnsHostTarget::Domain(domain) => StaticHostTarget::Domain(
                    dns::normalize_dns_name(domain).unwrap_or_else(|| domain.clone()),
                ),
            },
        })
        .collect();
    let name_servers = if include_name_servers {
        config
            .dns
            .servers
            .iter()
            .filter_map(|server| match server {
                DnsServerConfig::Ip(addr) => Some(NameServer::Socket(*addr)),
                DnsServerConfig::Domain { domain, port } => {
                    dns::normalize_dns_name(domain).map(|domain| NameServer::Domain {
                        domain,
                        port: *port,
                    })
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut resolver = ConfiguredDnsResolver::new(host_rules, name_servers, fallback);
    if let Some(transport) = query_transport {
        resolver = resolver.with_query_transport(transport);
    } else if let Some(protector) = socket_protector {
        resolver = resolver.with_socket_protector(protector);
    }
    Arc::new(resolver)
}

fn transport_domain_matcher(matcher: &DomainMatcher) -> TransportDomainMatcher {
    match matcher {
        DomainMatcher::Keyword(keyword) => TransportDomainMatcher::Keyword(keyword.clone()),
        DomainMatcher::Full(domain) => TransportDomainMatcher::Full(
            dns::normalize_dns_name(domain).unwrap_or_else(|| domain.clone()),
        ),
        DomainMatcher::Suffix(suffix) => TransportDomainMatcher::Suffix(
            dns::normalize_dns_name(suffix).unwrap_or_else(|| suffix.clone()),
        ),
        DomainMatcher::Regex(regex) => TransportDomainMatcher::regex(regex.pattern())
            .expect("xray-config regex matcher should be prevalidated"),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use xray_config::parse_xray_json;
    use xray_transport::{
        DnsResolver, SocketHandle, SocketProtector, TransportDialer, TransportError,
    };

    use super::{
        configured_dns_resolver_for_config, static_only_dns_resolver_for_config, Core,
        TunRuntimeOptions,
    };

    struct StaticResolver;

    #[async_trait]
    impl DnsResolver for StaticResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            match domain {
                "alias.example" => Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                    port,
                )),
                _ => Err(TransportError::NoResolvedAddress(domain.to_owned(), port)),
            }
        }
    }

    #[tokio::test]
    async fn configured_dns_resolver_uses_config_hosts_before_fallback() {
        let raw = r#"{
            "dns": {
              "hosts": {
                "domain:service.example": "alias.example"
              }
            },
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let resolver = configured_dns_resolver_for_config(&parsed.config, Arc::new(StaticResolver));

        let addr = resolver
            .resolve("storage.service.example", 8443)
            .await
            .unwrap();

        assert_eq!(addr, SocketAddr::from(([198, 51, 100, 9], 8443)));
    }

    #[tokio::test]
    async fn static_only_dns_resolver_uses_hosts_and_rejects_other_names() {
        let raw = r#"{
            "dns": {
              "servers": ["127.0.0.1:9"],
              "hosts": {
                "full:pinned.example": "198.51.100.10"
              }
            },
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let resolver = static_only_dns_resolver_for_config(&parsed.config);

        assert_eq!(
            resolver.resolve("pinned.example", 443).await.unwrap(),
            SocketAddr::from(([198, 51, 100, 10], 443))
        );
        assert!(matches!(
            resolver.resolve("unpinned.example", 443).await,
            Err(TransportError::NoResolvedAddress(domain, 443)) if domain == "unpinned.example"
        ));
    }

    #[tokio::test]
    async fn static_only_dns_resolver_normalizes_host_alias_targets() {
        let raw = r#"{
            "dns": {
              "hosts": {
                "full:resolver.example": "BOOTSTRAP.EXAMPLE.",
                "full:bootstrap.example": "198.51.100.11"
              }
            },
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let resolver = static_only_dns_resolver_for_config(&parsed.config);

        assert_eq!(
            resolver.resolve("resolver.example", 443).await.unwrap(),
            SocketAddr::from(([198, 51, 100, 11], 443))
        );
    }

    #[derive(Default)]
    struct RejectingProtector {
        calls: AtomicUsize,
    }

    impl SocketProtector for RejectingProtector {
        fn protect(&self, _socket: SocketHandle) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test socket rejected",
            ))
        }
    }

    #[tokio::test]
    async fn transport_dialer_constructor_protects_configured_dns_sockets() {
        let raw = r#"{
            "dns": { "servers": ["127.0.0.1:9"] },
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let protector = Arc::new(RejectingProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("system dialer should initialize"),
        );
        let core = Core::with_transport_dialer_and_tun_options(
            parsed.config,
            dialer,
            TunRuntimeOptions::default(),
        )
        .expect("core should initialize");

        let addr = core
            .dns_resolver
            .resolve("localhost", 8443)
            .await
            .expect("system fallback should resolve localhost");

        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 8443);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
    }
}
