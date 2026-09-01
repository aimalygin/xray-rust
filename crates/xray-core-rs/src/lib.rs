use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use xray_config::{
    CoreConfig, DnsHostTarget, DnsIpFilter, DnsQueryStrategy as ConfigDnsQueryStrategy,
    DnsServerConfig, DnsServerEndpoint, DnsServerTransport as ConfigDnsServerTransport,
    DomainHostIndex, DomainMatcherSet, InboundProtocol,
};
use xray_runtime::Shutdown;
use xray_transport::{
    CachingDnsResolver, CompiledNameServerPolicies, ConfiguredDnsResolver,
    DnsQueryStrategy as TransportDnsQueryStrategy, DnsQueryTransport, DnsResolver, NameServer,
    NameServerPolicy, NameServerTransport, SocketProtector, SystemDnsResolver, TransportDialer,
    TransportError,
};
use xray_tun::{TunConfig, TunEndpoint};

mod connection;
mod debug_log;
mod dns;
mod dns_outbound;
mod dns_outbound_runtime;
mod fake_dns;
mod health;
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
const GENERATED_DNS_TAG_PREFIX: &str = "xray.system.";

pub use connection::{
    ConnectionCloseError, ConnectionId, ConnectionInfo, ConnectionRegistry, ConnectionSnapshot,
    ConnectionState, OutboundAccounting, OutboundAccountingSnapshot,
};
pub use dns_outbound::{
    build_refused_response, build_return_response, parse_dns_query, CompiledDnsOutboundPolicy,
    DnsHijackUnsafe, DnsOutboundDecision, DnsOutboundQuery, DnsQueryParseError,
};
pub use outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_tcp_stream,
    open_vless_tcp_stream_with_resolver, open_vless_tcp_stream_with_resolver_and_dialer,
    open_vless_udp_stream_with_resolver_and_dialer, DnsOutbound, OutboundFactory, OutboundGraph,
    OutboundHealthFailure, OutboundHealthSnapshot, OutboundHealthState,
    OutboundHealthStatusSnapshot, OutboundNode, OutboundNodeId, OutboundNodeKind,
    OutboundProxyGraphError, OutboundRouter, OutboundSelectionOverlay, OutboundSelectionSnapshot,
    OutboundSelectorGroup, OutboundSelectorGroupSnapshot, TcpOutbound, UdpOutbound,
    VlessTcpOutbound, VlessUdpFraming,
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

/// Controls bootstrap and no-configured-server fallback for managed runtime DNS.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DnsBootstrapMode {
    /// Resolve destinations through `dns.hosts` and configured `dns.servers`.
    /// With no configured servers, use the operating-system resolver. DNS
    /// upstream and outbound-server bootstrap uses `dns.hosts` plus the
    /// operating-system resolver. This is the default for embeddings that do
    /// not install a local DNS anchor and for future server runtimes.
    #[default]
    System,
    /// Resolve destinations through `dns.hosts` and configured `dns.servers`, and
    /// fail closed when neither can answer. Bootstrap itself uses only
    /// `dns.hosts`, so it cannot recurse through a tunnel-local DNS anchor.
    /// Mobile VPN integrations should use this after installing that anchor.
    /// Constructors with an explicitly injected resolver keep using it as a
    /// trusted integration dependency.
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

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
const DEFAULT_DNS_RUNTIME_PROFILE: TunRuntimeProfile = TunRuntimeProfile::Mobile;

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
const DEFAULT_DNS_RUNTIME_PROFILE: TunRuntimeProfile = TunRuntimeProfile::Desktop;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsRuntimeLimits {
    max_concurrent_operations: usize,
    idle_ttl_cap: Duration,
}

impl DnsRuntimeLimits {
    fn for_profile(profile: TunRuntimeProfile) -> Self {
        match profile {
            TunRuntimeProfile::Default => Self::for_profile(DEFAULT_DNS_RUNTIME_PROFILE),
            TunRuntimeProfile::LowMemory => Self {
                max_concurrent_operations: 8,
                idle_ttl_cap: Duration::from_secs(15),
            },
            TunRuntimeProfile::Mobile => Self {
                max_concurrent_operations: 16,
                idle_ttl_cap: Duration::from_secs(30),
            },
            TunRuntimeProfile::MobilePlus => Self {
                max_concurrent_operations: 32,
                idle_ttl_cap: Duration::from_secs(45),
            },
            TunRuntimeProfile::Desktop => Self {
                max_concurrent_operations: 32,
                idle_ttl_cap: Duration::from_secs(60),
            },
            TunRuntimeProfile::Throughput => Self {
                max_concurrent_operations: 64,
                idle_ttl_cap: Duration::from_secs(60),
            },
        }
    }
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
    #[error("outbound selector group {0:?} was not found")]
    OutboundSelectorGroupNotFound(String),
    #[error("outbound {outbound:?} is not a candidate of selector group {group:?}")]
    OutboundSelectorCandidateNotFound { group: String, outbound: String },
    #[error(transparent)]
    OutboundProxyGraph(#[from] OutboundProxyGraphError),
    #[error("outbound chaining does not support {0}")]
    UnsupportedOutboundProxyNetwork(&'static str),
    #[error("unauthenticated SOCKS/HTTP listener requires explicit LAN exposure permission")]
    UnauthenticatedLanExposure,
    #[error("invalid fake-IP configuration")]
    InvalidFakeIpConfiguration,
    #[error("invalid observatory probe URL")]
    InvalidObservatoryProbeUrl,
    #[error("outbound network is not supported")]
    UnsupportedOutboundNetwork,
    #[error("outbound security is not supported")]
    UnsupportedOutboundSecurity,
    // Reserved for future config address kinds; current VLESS TCP selection supports IP and domain servers.
    #[error("outbound server address is not supported")]
    UnsupportedOutboundServerAddress,
    #[error("outbound flow is not supported")]
    UnsupportedOutboundFlow,
    /// Carries the offending value because the other outbound-config errors
    /// above cannot: told only that "outbound network is not supported", a user
    /// whose `grpcSettings.authority` holds a `/` would conclude that
    /// `network: "grpc"` is unimplemented, which is now the wrong answer to a
    /// question about one character in one string.
    ///
    /// Names the key as well as the value, because
    /// [`Self::UnrepresentableGrpcAuthority`] is the same complaint about a
    /// value the user never wrote and the two have to be told apart from the
    /// message alone.
    ///
    /// **Debug-formatted, as are both variants below it, and for a reason all
    /// three share.** Each carries a value that arrived as free-form profile
    /// JSON, and no layer between that JSON and this message checks any of them
    /// for control characters: this one is filtered for emptiness and nothing
    /// else (`crates/xray-config/src/parser.rs:2869-2872`), and the sources
    /// [`Self::UnrepresentableGrpcAuthority`] derives from are no better off.
    /// So each value can hold a CR LF, and under `{0}` the message would render
    /// as two lines rather than one — the second of them written by the
    /// profile, wherever the error is shown. `xray-cli` prints it to stderr
    /// (`crates/xray-cli/src/main.rs:10`) and `xray-ffi` hands `to_string()` to
    /// the error struct the host app logs (`crates/xray-ffi/src/lib.rs:866` on
    /// load, `lib.rs:1542` on start). Escaping costs the message nothing:
    /// `{0:?}` also quotes the value, which is all the backticks it replaced
    /// were doing.
    #[error("grpcSettings.authority {0:?} is not a valid HTTP/2 authority")]
    InvalidGrpcAuthority(String),
    /// The rest of Xray's `:authority` chain — `tlsSettings.serverName`, the
    /// destination domain, the `host:port` last resort
    /// (`Xray-core/transport/internet/grpc/dial.go:159-167`) — resolving to
    /// something `http::uri::Authority` will not hold.
    ///
    /// Separate from [`Self::InvalidGrpcAuthority`] because the *cause* is
    /// separate. That one is a string in `grpcSettings.authority` and the user
    /// can edit the character that is wrong. This one is a value we derived on
    /// their behalf, so naming `grpcSettings.authority` would send them
    /// looking for a key their config does not contain; `key` names the one it
    /// does. Why it is still a refusal rather than a fallback is in
    /// `outbound::grpc_authority` — briefly, `h2` reads `:authority` out of an
    /// `http::Uri` and nothing else, so a value no `Authority` can hold is one
    /// no request can carry.
    ///
    /// `value` is Debug-formatted for the reason
    /// [`Self::InvalidGrpcAuthority`] gives. Deriving the value is no
    /// sanitisation of it: `tlsSettings.serverName` is copied out of the JSON
    /// unchecked (`crates/xray-config/src/parser.rs:3157-3160`) and
    /// `settings.vnext[0].address` becomes a domain verbatim whenever it does
    /// not parse as an `IpAddr` (`parser.rs:2439-2451`), so every branch of the
    /// chain can hand this variant a CR LF.
    #[error("the gRPC :authority derived from {key} {value:?} is not a valid HTTP/2 authority")]
    UnrepresentableGrpcAuthority {
        /// The config key that produced the value, so the message hands the
        /// user something to search their profile for. Names *two* keys on the
        /// last-resort branch, where the authority is composed rather than
        /// copied and neither key on its own holds `value`.
        key: &'static str,
        /// The resolved authority: the named key's value verbatim on the
        /// branches that copy one, and `address:port` on the last-resort
        /// branch, which is why `key` names the port key there too.
        value: String,
    },
    /// A `grpcSettings.user_agent` that no HTTP header can carry, refused when
    /// the outbound is built rather than on every dial for as long as the
    /// config stands. `xray_transport::stream::GrpcConfig::user_agent` has the
    /// reasoning and the measurements behind it — briefly, grpc-go's client
    /// sends the value unvalidated and a grpc-go peer then resets every stream
    /// it opens, so refusing here costs no profile that worked upstream.
    ///
    /// **Debug-formatted, as its two `:authority` neighbours now are** — but
    /// this variant came by it first, because the values it rejects are exactly
    /// the ones holding control characters. That made the exposure impossible to
    /// miss here and easy to miss next door, where a CR LF is only one of many
    /// ways to fail an `Authority` parse; [`Self::InvalidGrpcAuthority`] now
    /// states the rule for all three.
    #[error("grpcSettings.user_agent {0:?} is not a valid HTTP header value")]
    InvalidGrpcUserAgent(String),
    /// An XHTTP setting that parsed successfully but cannot be represented by
    /// the selected HTTP engine without silently changing its behavior.
    #[error("invalid or unsupported XHTTP configuration: {0:?}")]
    InvalidXhttpConfiguration(String),
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
    config: Arc<CoreConfig>,
    state: CoreState,
    shutdown: Shutdown,
    tun: Arc<TunEndpoint>,
    runtime: Option<RuntimeState>,
    dns_resolver: Arc<dyn DnsResolver>,
    dns_bootstrap_resolver: Option<Arc<dyn DnsResolver>>,
    dns_rules: DnsRules,
    managed_dns_resolver: bool,
    transport_dialer: Arc<TransportDialer>,
    outbound_router: Arc<OutboundRouter>,
    connection_registry: Arc<ConnectionRegistry>,
    tun_runtime_options: TunRuntimeOptions,
    startup_probe: Option<StartupProbeOptions>,
    runtime_logger: RuntimeLogger,
}

impl Core {
    pub fn new(mut config: CoreConfig) -> Result<Self, CoreError> {
        let system_resolver = system_dns_resolver();
        let dns_rules = DnsRules::from_config(&mut config);
        let dns_resolver = configured_dns_resolver_for_config(
            &config,
            Arc::clone(&system_resolver),
            dns_rules.clone(),
        );
        let dns_bootstrap_resolver =
            host_only_dns_resolver_for_config(&config, system_resolver, dns_rules.hosts_only());
        Self::build(
            config,
            dns_resolver,
            Some(dns_bootstrap_resolver),
            dns_rules,
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
        mut config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, CoreError> {
        let dns_rules = DnsRules::injected(&mut config);
        Self::build(
            config,
            Arc::clone(&dns_resolver),
            Some(dns_resolver),
            dns_rules,
            Arc::new(TransportDialer::system()?),
            TunRuntimeOptions::default(),
            false,
        )
    }

    pub fn with_tun_runtime_options(
        mut config: CoreConfig,
        tun_runtime_options: TunRuntimeOptions,
    ) -> Result<Self, CoreError> {
        let system_resolver = system_dns_resolver();
        let dns_rules = DnsRules::from_config(&mut config);
        let (dns_resolver, dns_bootstrap_resolver) = match tun_runtime_options.dns_bootstrap {
            DnsBootstrapMode::System => (
                configured_dns_resolver_for_config(
                    &config,
                    Arc::clone(&system_resolver),
                    dns_rules.clone(),
                ),
                Some(host_only_dns_resolver_for_config(
                    &config,
                    system_resolver,
                    dns_rules.hosts_only(),
                )),
            ),
            DnsBootstrapMode::StaticOnly => {
                let resolver = static_only_dns_resolver_for_config(
                    &config,
                    Arc::clone(&dns_rules.static_hosts),
                );
                (Arc::clone(&resolver), Some(resolver))
            }
        };
        Self::build(
            config,
            dns_resolver,
            dns_bootstrap_resolver,
            dns_rules,
            Arc::new(TransportDialer::system()?),
            tun_runtime_options,
            true,
        )
    }

    /// Creates a core whose System-mode direct DNS sockets and managed TUN
    /// routed Freedom DNS sockets share the dialer's socket-protection policy.
    pub fn with_transport_dialer_and_tun_options(
        mut config: CoreConfig,
        transport_dialer: Arc<TransportDialer>,
        tun_runtime_options: TunRuntimeOptions,
    ) -> Result<Self, CoreError> {
        let system_resolver = system_dns_resolver();
        let dns_rules = DnsRules::from_config(&mut config);
        let (dns_resolver, dns_bootstrap_resolver) = match tun_runtime_options.dns_bootstrap {
            DnsBootstrapMode::System => (
                configured_dns_resolver_for_config_with_socket_protector(
                    &config,
                    Arc::clone(&system_resolver),
                    dns_rules.clone(),
                    transport_dialer.socket_protector_arc(),
                ),
                Some(host_only_dns_resolver_for_config(
                    &config,
                    system_resolver,
                    dns_rules.hosts_only(),
                )),
            ),
            DnsBootstrapMode::StaticOnly => {
                let resolver = static_only_dns_resolver_for_config(
                    &config,
                    Arc::clone(&dns_rules.static_hosts),
                );
                (Arc::clone(&resolver), Some(resolver))
            }
        };
        Self::build(
            config,
            dns_resolver,
            dns_bootstrap_resolver,
            dns_rules,
            transport_dialer,
            tun_runtime_options,
            true,
        )
    }

    pub fn with_runtime_dependencies(
        mut config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
    ) -> Result<Self, CoreError> {
        let dns_rules = DnsRules::injected(&mut config);
        Self::build(
            config,
            Arc::clone(&dns_resolver),
            Some(dns_resolver),
            dns_rules,
            transport_dialer,
            TunRuntimeOptions::default(),
            false,
        )
    }

    pub fn with_runtime_dependencies_and_tun_options(
        mut config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
        tun_runtime_options: TunRuntimeOptions,
    ) -> Result<Self, CoreError> {
        let dns_bootstrap_resolver = Some(Arc::clone(&dns_resolver));
        let dns_rules = DnsRules::injected(&mut config);
        Self::build(
            config,
            dns_resolver,
            dns_bootstrap_resolver,
            dns_rules,
            transport_dialer,
            tun_runtime_options,
            false,
        )
    }

    fn build(
        mut config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        dns_bootstrap_resolver: Option<Arc<dyn DnsResolver>>,
        dns_rules: DnsRules,
        transport_dialer: Arc<TransportDialer>,
        tun_runtime_options: TunRuntimeOptions,
        managed_dns_resolver: bool,
    ) -> Result<Self, CoreError> {
        if config.observatory.as_ref().is_some_and(|observatory| {
            startup_probe::parse_probe_url(&observatory.probe_url).is_err()
        }) {
            return Err(CoreError::InvalidObservatoryProbeUrl);
        }
        if config.dns.fake_ip.as_ref().is_some_and(|fake_ip| {
            fake_ip.enabled
                && fake_dns::FakeIpMapper::from_config(
                    fake_ip,
                    config.dns.query_strategy,
                    &[tun::TUN_DNS_ANCHOR, tun::TUN_CLIENT_IPV4],
                )
                .is_none()
        }) {
            return Err(CoreError::InvalidFakeIpConfiguration);
        }
        ensure_effective_dns_tag(&mut config);
        let config = Arc::new(config);
        let outbound_graph = Arc::new(OutboundGraph::new(Arc::clone(&config)));
        outbound_graph.validate_proxy_chains()?;
        let outbound_factory = Arc::new(OutboundFactory::new(outbound_graph));
        let outbound_router = Arc::new(OutboundRouter::from_factory(outbound_factory));
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
            dns_rules,
            managed_dns_resolver,
            transport_dialer,
            outbound_router,
            connection_registry: Arc::new(ConnectionRegistry::new()),
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

    pub fn outbound_graph(&self) -> &OutboundGraph {
        self.outbound_router.graph()
    }

    pub fn outbound_factory(&self) -> &OutboundFactory {
        self.outbound_router.factory()
    }

    pub fn outbound_selection(&self) -> &OutboundSelectionOverlay {
        self.outbound_router.selection()
    }

    pub fn set_outbound_selector_override(
        &self,
        group_tag: &str,
        outbound_tag: &str,
    ) -> Result<u64, CoreError> {
        self.outbound_selection()
            .set_override(group_tag, outbound_tag)
    }

    pub fn clear_outbound_selector_override(&self, group_tag: &str) -> Result<u64, CoreError> {
        self.outbound_selection().clear_override(group_tag)
    }

    pub fn outbound_selection_snapshot(&self) -> OutboundSelectionSnapshot {
        self.outbound_selection().snapshot()
    }

    pub fn outbound_health_snapshot(&self) -> OutboundHealthSnapshot {
        self.outbound_selection().health_snapshot()
    }

    pub fn connection_snapshot(&self) -> ConnectionSnapshot {
        self.connection_registry.snapshot()
    }

    pub fn outbound_accounting_snapshot(&self) -> OutboundAccountingSnapshot {
        self.connection_registry.accounting_snapshot()
    }

    pub fn close_connection(&self, id: ConnectionId) -> Result<u64, ConnectionCloseError> {
        self.connection_registry.close(id)
    }

    fn runtime_dns_resolvers(
        &self,
        config: &Arc<CoreConfig>,
        outbound_router: &Arc<OutboundRouter>,
        forbid_tun_runtime_servers: bool,
    ) -> dns::RuntimeDnsResolvers {
        let bootstrap = self
            .dns_bootstrap_resolver
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.dns_resolver));
        let forbidden_servers: Vec<SocketAddr> = if forbid_tun_runtime_servers {
            vec![
                SocketAddr::new(std::net::IpAddr::V4(tun::TUN_DNS_ANCHOR), 0),
                SocketAddr::new(std::net::IpAddr::V4(tun::TUN_CLIENT_IPV4), 0),
            ]
        } else {
            Vec::new()
        };
        let dns_limits = DnsRuntimeLimits::for_profile(self.tun_runtime_options.profile);
        let direct_executor = Arc::new(dns_outbound_runtime::DnsDirectExecutor::with_pool_config(
            Arc::clone(&bootstrap),
            Arc::clone(&self.transport_dialer),
            forbidden_servers.clone(),
            dns_outbound_runtime::DnsDirectPoolConfig::from_runtime_limit(
                dns_limits.max_concurrent_operations,
                dns_limits.idle_ttl_cap,
            ),
        ));
        let fake_ip_mapper = config
            .dns
            .fake_ip
            .as_ref()
            .and_then(|fake_ip| {
                fake_dns::FakeIpMapper::from_config(
                    fake_ip,
                    config.dns.query_strategy,
                    &[tun::TUN_DNS_ANCHOR, tun::TUN_CLIENT_IPV4],
                )
            })
            .map(|mapper| Arc::new(Mutex::new(mapper)));
        let query_transport = self.managed_dns_resolver.then(|| {
            Arc::new(dns::RoutedDnsQueryTransport::with_direct_executor(
                Arc::clone(outbound_router),
                Arc::clone(&bootstrap),
                Arc::clone(&self.transport_dialer),
                forbidden_servers.clone(),
                Arc::clone(&direct_executor),
                dns_limits.max_concurrent_operations,
            )) as Arc<dyn DnsQueryTransport>
        });
        let destination = if self.managed_dns_resolver {
            let fallback: Arc<dyn DnsResolver> = match self.tun_runtime_options.dns_bootstrap {
                DnsBootstrapMode::System => system_dns_resolver(),
                DnsBootstrapMode::StaticOnly => Arc::new(FailClosedDnsResolver),
            };
            let resolver = configured_dns_resolver_from_config_with_transport(
                config.as_ref(),
                fallback,
                None,
                self.dns_rules.clone(),
                query_transport.clone(),
                transport_dns_query_strategy(config.dns.query_strategy),
            );
            Arc::new(CachingDnsResolver::new(resolver)) as Arc<dyn DnsResolver>
        } else {
            Arc::clone(&self.dns_resolver)
        };
        let outbound = Arc::new(
            dns_outbound_runtime::DnsOutboundRuntime::with_direct_executor_and_fake_ip(
                Arc::clone(&destination),
                direct_executor,
                fake_ip_mapper,
                Arc::clone(&self.dns_rules.static_hosts),
                dns_limits.max_concurrent_operations,
            ),
        );
        dns::RuntimeDnsResolvers {
            destination,
            bootstrap,
            outbound,
            query_transport,
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

        let config = Arc::clone(&self.config);
        let outbound_router = Arc::clone(&self.outbound_router);
        let has_tun_inbound = !tun_inbounds.is_empty();
        let runtime_dns_resolvers =
            self.runtime_dns_resolvers(&config, &outbound_router, has_tun_inbound);
        let mut inbounds = Vec::with_capacity(bound_listeners.len());
        let mut tasks = Vec::with_capacity(
            bound_listeners.len() + usize::from(has_tun_inbound) + usize::from(has_tun_inbound),
        );
        for (bound, protocol, sniffing, policy, listener) in bound_listeners {
            let inbound_tag = bound.tag.clone();
            let dns_resolvers = runtime_dns_resolvers.clone();
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
                    Arc::clone(&self.connection_registry),
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
                    Arc::clone(&self.connection_registry),
                    self.shutdown.subscribe(),
                )),
                InboundProtocol::Tun => continue,
            };
            inbounds.push(bound);
            tasks.push(task);
        }
        if has_tun_inbound {
            let tun_inbound_tag = tun_inbounds.first().and_then(|(tag, _, _)| tag.clone());
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
                Arc::clone(&runtime_dns_resolvers.destination),
                Some(Arc::clone(&runtime_dns_resolvers.bootstrap)),
                Arc::clone(&runtime_dns_resolvers.outbound),
                runtime_dns_resolvers.query_transport.clone(),
                Arc::clone(&self.transport_dialer),
                Arc::clone(&self.connection_registry),
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
                runtime_dns_resolvers.destination.as_ref(),
                runtime_dns_resolvers.bootstrap.as_ref(),
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

        if let Some(observatory) = config.observatory.clone() {
            let nodes = outbound_router
                .graph()
                .leaf_nodes_matching_prefixes(&observatory.subject_selectors);
            if !nodes.is_empty() {
                let runtime = health::ObservatoryRuntime::new(
                    observatory,
                    nodes,
                    Arc::clone(&outbound_router),
                    outbound_router.selection_handle(),
                    Arc::clone(&runtime_dns_resolvers.destination),
                    Arc::clone(&runtime_dns_resolvers.bootstrap),
                    Arc::clone(&self.transport_dialer),
                );
                let task =
                    tokio::spawn(health::run_observatory(runtime, self.shutdown.subscribe()));
                self.runtime
                    .as_mut()
                    .expect("running core retains runtime state")
                    .tasks
                    .push(task);
            }
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

fn static_only_dns_resolver_for_config(
    config: &CoreConfig,
    static_hosts: Arc<DomainHostIndex<DnsHostTarget>>,
) -> Arc<dyn DnsResolver> {
    host_only_dns_resolver_for_config(
        config,
        Arc::new(FailClosedDnsResolver),
        DnsRules::hosts(static_hosts),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsResolverRole {
    Destination,
    Bootstrap,
}

fn take_name_server_policy_set(config: &mut CoreConfig) -> Arc<CompiledNameServerPolicies> {
    ensure_effective_dns_tag(config);
    let global_dns_tag = config.dns.tag.clone();
    let name_servers = config
        .dns
        .servers
        .iter_mut()
        .filter_map(|server| {
            let name_server = match server.endpoint() {
                DnsServerEndpoint::Ip(addr) => NameServer::Socket(addr),
                DnsServerEndpoint::Domain { domain, port } => NameServer::Domain {
                    domain: dns::normalize_dns_name(&domain)?,
                    port,
                },
            };
            let skip_fallback = server.skip_fallback();
            let transport = match server.transport() {
                ConfigDnsServerTransport::Classic => NameServerTransport::Classic,
                ConfigDnsServerTransport::TcpRouted => NameServerTransport::TcpRouted,
                ConfigDnsServerTransport::TcpLocal => NameServerTransport::TcpLocal,
                ConfigDnsServerTransport::TlsRouted => NameServerTransport::TlsRouted,
                ConfigDnsServerTransport::HttpsRouted => NameServerTransport::HttpsRouted,
                ConfigDnsServerTransport::HttpsLocal => NameServerTransport::HttpsLocal,
                ConfigDnsServerTransport::QuicLocal => NameServerTransport::QuicLocal,
            };
            let query_strategy = transport_dns_query_strategy(server.query_strategy());
            let final_query = server.final_query();
            let timeout = Some(Duration::from_millis(server.timeout_ms()));
            let tag = server.effective_tag(&global_dns_tag).to_owned();
            let (domains, expected_ips, unexpected_ips) = match server {
                DnsServerConfig::Policy(policy) => (
                    std::mem::take(&mut policy.domains),
                    std::mem::take(&mut policy.expected_ips),
                    std::mem::take(&mut policy.unexpected_ips),
                ),
                DnsServerConfig::Ip(_) | DnsServerConfig::Domain { .. } => (
                    DomainMatcherSet::default(),
                    DnsIpFilter::default(),
                    DnsIpFilter::default(),
                ),
            };
            Some(NameServerPolicy {
                server: name_server,
                tag: Some(tag),
                transport,
                https_path: server.https_path().map(str::to_owned),
                domains,
                expected_ips,
                unexpected_ips,
                timeout,
                skip_fallback,
                query_strategy,
                final_query,
            })
        })
        .collect();
    Arc::new(CompiledNameServerPolicies::new(name_servers))
}

fn ensure_effective_dns_tag(config: &mut CoreConfig) {
    if config.dns.tag.is_empty() {
        config.dns.tag = format!("{GENERATED_DNS_TAG_PREFIX}{}", uuid::Uuid::new_v4());
    }
}

/// Converts `dns.hosts` into the transport index once; every resolver built
/// from this config shares it.
#[derive(Clone)]
struct DnsRules {
    name_servers: Option<Arc<CompiledNameServerPolicies>>,
    static_hosts: Arc<DomainHostIndex<DnsHostTarget>>,
}

impl DnsRules {
    fn from_config(config: &mut CoreConfig) -> Self {
        Self {
            name_servers: Some(take_name_server_policy_set(config)),
            static_hosts: Arc::new(std::mem::take(&mut config.dns.hosts)),
        }
    }

    fn injected(config: &mut CoreConfig) -> Self {
        Self {
            name_servers: Some(Arc::default()),
            static_hosts: Arc::new(std::mem::take(&mut config.dns.hosts)),
        }
    }

    fn hosts(static_hosts: Arc<DomainHostIndex<DnsHostTarget>>) -> Self {
        Self {
            name_servers: None,
            static_hosts,
        }
    }

    fn hosts_only(&self) -> Self {
        Self::hosts(Arc::clone(&self.static_hosts))
    }
}

#[cfg(test)]
fn static_host_index(config: &CoreConfig) -> Arc<DomainHostIndex<DnsHostTarget>> {
    Arc::new(config.dns.hosts.clone())
}

fn host_only_dns_resolver_for_config(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    dns_rules: DnsRules,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_from_config_with_transport_mode(
        config,
        fallback,
        None,
        dns_rules,
        None,
        TransportDnsQueryStrategy::UseIp,
        DnsResolverRole::Bootstrap,
    )
}

fn configured_dns_resolver_for_config(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    dns_rules: DnsRules,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_for_config_with_socket_protector(config, fallback, dns_rules, None)
}

fn configured_dns_resolver_for_config_with_socket_protector(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    dns_rules: DnsRules,
    socket_protector: Option<Arc<dyn SocketProtector>>,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_from_config(
        config,
        fallback,
        socket_protector,
        dns_rules,
        transport_dns_query_strategy(config.dns.query_strategy),
    )
}

fn configured_dns_resolver_from_config(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    dns_rules: DnsRules,
    query_strategy: TransportDnsQueryStrategy,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_from_config_with_transport(
        config,
        fallback,
        socket_protector,
        dns_rules,
        None,
        query_strategy,
    )
}

fn configured_dns_resolver_from_config_with_transport(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    dns_rules: DnsRules,
    query_transport: Option<Arc<dyn DnsQueryTransport>>,
    query_strategy: TransportDnsQueryStrategy,
) -> Arc<dyn DnsResolver> {
    configured_dns_resolver_from_config_with_transport_mode(
        config,
        fallback,
        socket_protector,
        dns_rules,
        query_transport,
        query_strategy,
        DnsResolverRole::Destination,
    )
}

fn configured_dns_resolver_from_config_with_transport_mode(
    config: &CoreConfig,
    fallback: Arc<dyn DnsResolver>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    dns_rules: DnsRules,
    query_transport: Option<Arc<dyn DnsQueryTransport>>,
    query_strategy: TransportDnsQueryStrategy,
    role: DnsResolverRole,
) -> Arc<dyn DnsResolver> {
    let mut resolver = ConfiguredDnsResolver::new(dns_rules.static_hosts, Vec::new(), fallback);
    if let Some(name_servers) = dns_rules.name_servers {
        resolver = resolver.with_name_server_policy_set(name_servers);
    }
    resolver = resolver
        .with_name_server_fallback_policy(
            config.dns.disable_fallback,
            config.dns.disable_fallback_if_match,
        )
        .with_query_strategy(query_strategy);
    if role == DnsResolverRole::Bootstrap {
        resolver = resolver.without_system_fallback_timeout();
    }
    if let Some(transport) = query_transport {
        resolver = resolver.with_query_transport(transport);
    } else if let Some(protector) = socket_protector {
        resolver = resolver.with_socket_protector(protector);
    }
    Arc::new(resolver)
}

fn transport_dns_query_strategy(
    query_strategy: ConfigDnsQueryStrategy,
) -> TransportDnsQueryStrategy {
    match query_strategy {
        ConfigDnsQueryStrategy::UseIp => TransportDnsQueryStrategy::UseIp,
        ConfigDnsQueryStrategy::UseIpv4 => TransportDnsQueryStrategy::UseIpv4,
        ConfigDnsQueryStrategy::UseIpv6 => TransportDnsQueryStrategy::UseIpv6,
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use xray_config::{parse_xray_json, DnsHostTarget, DnsServerConfig, DnsServerEndpoint};
    use xray_transport::{
        DnsLookup, DnsQueryMetadata, DnsQueryTransport, DnsQueryTransportKind, DnsResolver,
        NameServer, NameServerTransport, SocketHandle, SocketProtector, TransportDialer,
        TransportError,
    };

    use super::{
        configured_dns_resolver_for_config, configured_dns_resolver_from_config_with_transport,
        host_only_dns_resolver_for_config, static_host_index, static_only_dns_resolver_for_config,
        take_name_server_policy_set, Core, DnsRules, DnsRuntimeLimits, TransportDnsQueryStrategy,
        TunRuntimeOptions, TunRuntimeProfile,
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

    struct PendingResolver;

    #[test]
    fn dns_runtime_resources_follow_runtime_profiles() {
        for (profile, operations, idle_ttl) in [
            (TunRuntimeProfile::LowMemory, 8, Duration::from_secs(15)),
            (TunRuntimeProfile::Mobile, 16, Duration::from_secs(30)),
            (TunRuntimeProfile::MobilePlus, 32, Duration::from_secs(45)),
            (TunRuntimeProfile::Desktop, 32, Duration::from_secs(60)),
            (TunRuntimeProfile::Throughput, 64, Duration::from_secs(60)),
        ] {
            assert_eq!(
                DnsRuntimeLimits::for_profile(profile),
                DnsRuntimeLimits {
                    max_concurrent_operations: operations,
                    idle_ttl_cap: idle_ttl,
                }
            );
        }
        assert_eq!(
            DnsRuntimeLimits::for_profile(TunRuntimeProfile::Default),
            DnsRuntimeLimits::for_profile(super::DEFAULT_DNS_RUNTIME_PROFILE)
        );
    }

    #[async_trait]
    impl DnsResolver for PendingResolver {
        async fn resolve(&self, _domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
            std::future::pending().await
        }
    }

    struct DualStackResolver;

    #[async_trait]
    impl DnsResolver for DualStackResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            self.resolve_all(domain, port)
                .await?
                .socket_addrs()
                .first()
                .copied()
                .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
        }

        async fn resolve_all(&self, _domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
            Ok(DnsLookup::from_ips(
                [
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 94)),
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 94)),
                ],
                port,
                None,
            ))
        }
    }

    #[tokio::test]
    async fn configured_dns_query_strategy_filters_fallback_without_servers_or_hosts() {
        let raw = r#"{
            "dns": { "queryStrategy": "UseIPv6" },
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let resolver = configured_dns_resolver_for_config(
            &parsed.config,
            Arc::new(DualStackResolver),
            DnsRules {
                name_servers: Some(Arc::default()),
                static_hosts: static_host_index(&parsed.config),
            },
        );

        let lookup = resolver.resolve_all("family.example", 443).await.unwrap();

        assert_eq!(
            lookup.socket_addrs(),
            [SocketAddr::from((
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 94),
                443,
            ))]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_resolver_bounds_no_server_fallback_in_core_wiring() {
        let raw = r#"{
            "dns": {},
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let resolver = configured_dns_resolver_for_config(
            &parsed.config,
            Arc::new(PendingResolver),
            DnsRules {
                name_servers: Some(Arc::default()),
                static_hosts: static_host_index(&parsed.config),
            },
        );
        let started_at = tokio::time::Instant::now();

        let error = resolver.resolve("bounded.example", 443).await.unwrap_err();

        assert!(matches!(
            error,
            TransportError::Dns { source, .. }
                if source.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(started_at.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn bootstrap_dns_resolver_inherits_its_surrounding_deadline() {
        let raw = r#"{
            "dns": {},
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let resolver = host_only_dns_resolver_for_config(
            &parsed.config,
            Arc::new(PendingResolver),
            DnsRules::hosts(static_host_index(&parsed.config)),
        );
        let started_at = tokio::time::Instant::now();

        let result = tokio::time::timeout(
            Duration::from_secs(6),
            resolver.resolve("bootstrap.example", 53),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(started_at.elapsed(), Duration::from_secs(6));
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
        let resolver = configured_dns_resolver_for_config(
            &parsed.config,
            Arc::new(StaticResolver),
            DnsRules {
                name_servers: Some(Arc::default()),
                static_hosts: static_host_index(&parsed.config),
            },
        );

        let addr = resolver
            .resolve("storage.service.example", 8443)
            .await
            .unwrap();

        assert_eq!(addr, SocketAddr::from(([198, 51, 100, 9], 8443)));
    }

    #[derive(Default)]
    struct RecordingDnsQueryTransport {
        calls: Mutex<Vec<(NameServer, u16, Option<String>)>>,
    }

    #[async_trait]
    impl DnsQueryTransport for RecordingDnsQueryTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            metadata: DnsQueryMetadata<'_>,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let record_type = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            self.calls.lock().unwrap().push((
                server.clone(),
                record_type,
                metadata.inbound_tag.map(ToOwned::to_owned),
            ));
            if record_type != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "object policy test expects an A query",
                ));
            }
            let mut response = Vec::with_capacity(query.len() + 16);
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&0x8180_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&0_u16.to_be_bytes());
            response.extend_from_slice(&query[12..]);
            response.extend_from_slice(&0xC00C_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&60_u32.to_be_bytes());
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&[192, 0, 2, 75]);
            Ok(response)
        }
    }

    #[tokio::test]
    async fn configured_dns_wires_object_policy_into_managed_resolver() {
        let raw = r#"{
            "dns": {
              "tag": "dns-global",
              "queryStrategy": "UseIP",
              "disableFallbackIfMatch": true,
              "servers": [
                {
                  "address": "192.0.2.1",
                  "tag": "dns-policy",
                  "domains": ["domain:internal.test"],
                  "queryStrategy": "UseIPv4"
                },
                "192.0.2.2"
              ]
            },
            "inbounds": [],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        }"#;
        let parsed = parse_xray_json(raw).expect("object DNS policy should parse");
        let mut config = parsed.config;
        let name_servers = take_name_server_policy_set(&mut config);
        let transport = Arc::new(RecordingDnsQueryTransport::default());
        let resolver = configured_dns_resolver_from_config_with_transport(
            &config,
            Arc::new(StaticResolver),
            None,
            DnsRules {
                name_servers: Some(name_servers),
                static_hosts: static_host_index(&config),
            },
            Some(transport.clone()),
            TransportDnsQueryStrategy::UseIp,
        );

        let resolved = resolver
            .resolve("service.internal.test", 443)
            .await
            .unwrap();

        let selected = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 75], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            [(selected, 1, Some("dns-policy".to_owned()))]
        );
    }

    #[tokio::test]
    async fn configured_dns_expected_ip_rejection_advances_to_next_server() {
        let raw = r#"{
            "dns": {
              "tag": "dns-global",
              "queryStrategy": "UseIPv4",
              "servers": [
                {
                  "address": "192.0.2.1",
                  "tag": "dns-first",
                  "domains": ["full:filtered.test"],
                  "expectedIPs": ["198.51.100.0/24"]
                },
                "192.0.2.2"
              ]
            },
            "inbounds": [],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        }"#;
        let parsed = parse_xray_json(raw).expect("expectedIPs policy should parse");
        let mut config = parsed.config;
        let name_servers = take_name_server_policy_set(&mut config);
        let transport = Arc::new(RecordingDnsQueryTransport::default());
        let resolver = configured_dns_resolver_from_config_with_transport(
            &config,
            Arc::new(StaticResolver),
            None,
            DnsRules {
                name_servers: Some(name_servers),
                static_hosts: static_host_index(&config),
            },
            Some(transport.clone()),
            TransportDnsQueryStrategy::UseIpv4,
        );

        let resolved = resolver.resolve("filtered.test", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 75], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            [
                (
                    NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53))),
                    1,
                    Some("dns-first".to_owned()),
                ),
                (
                    NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53))),
                    1,
                    Some("dns-global".to_owned()),
                ),
            ]
        );
    }

    #[test]
    fn dns_rules_move_static_hosts_out_of_core_config() {
        let raw = r#"{
            "dns": { "hosts": { "one.example": "192.0.2.1", "domain:two.example": "192.0.2.2" } },
            "inbounds": [],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        }"#;
        let parsed = parse_xray_json(raw).expect("dns hosts should parse");
        let mut config = parsed.config;
        assert_eq!(config.dns.hosts.len(), 2);

        let rules = DnsRules::from_config(&mut config);

        assert_eq!(rules.static_hosts.len(), 2);
        assert!(config.dns.hosts.is_empty());
        assert_eq!(
            rules.static_hosts.lookup("one.example"),
            Some(&DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))))
        );
    }

    #[test]
    fn compiling_dns_policies_moves_large_matchers_out_of_core_config() {
        let raw = r#"{
            "dns": {
              "servers": [{
                "address": "192.0.2.53",
                "domains": ["full:one.example", "domain:two.example"],
                "expectedIPs": ["192.0.2.0/24"],
                "unexpectedIPs": ["10.0.0.0/8"],
                "timeoutMs": 37
              }]
            },
            "inbounds": [],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        }"#;
        let parsed = parse_xray_json(raw).expect("object DNS policy should parse");
        let mut config = parsed.config;

        let policies = take_name_server_policy_set(&mut config);

        assert_eq!(policies.matcher_count(), 2);
        assert!(policies.pattern_bytes() > 0);
        assert_eq!(policies.timeout(0), Some(Duration::from_millis(37)));
        let DnsServerConfig::Policy(server) = &config.dns.servers[0] else {
            panic!("object DNS server must remain available for raw endpoint planning");
        };
        assert!(server.domains.is_empty());
        assert!(server.expected_ips.is_empty());
        assert!(server.unexpected_ips.is_empty());
        assert_eq!(
            server.endpoint,
            DnsServerEndpoint::Ip(SocketAddr::from(([192, 0, 2, 53], 53)))
        );
    }

    #[test]
    fn compiling_dns_policies_preserves_tcp_dispatch_modes() {
        let raw = r#"{
            "dns": {
              "servers": [
                "192.0.2.53",
                "tcp://resolver.example:5353",
                "tcp+local://[2001:db8::53]",
                "tls://secure-resolver.example",
                "https://doh.example/dns-query",
                "https+local://192.0.2.54:8443/custom?profile=mobile",
                "quic+local://doq.example"
              ]
            },
            "inbounds": [],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        }"#;
        let parsed = parse_xray_json(raw).expect("mixed DNS transports should parse");
        let mut config = parsed.config;

        let policies = take_name_server_policy_set(&mut config);

        assert_eq!(
            (0..policies.len())
                .map(|index| policies.transport(index).unwrap())
                .collect::<Vec<_>>(),
            [
                NameServerTransport::Classic,
                NameServerTransport::TcpRouted,
                NameServerTransport::TcpLocal,
                NameServerTransport::TlsRouted,
                NameServerTransport::HttpsRouted,
                NameServerTransport::HttpsLocal,
                NameServerTransport::QuicLocal,
            ]
        );
        assert_eq!(policies.https_path(4), Some("/dns-query"));
        assert_eq!(policies.https_path(5), Some("/custom?profile=mobile"));
        assert_eq!(policies.https_path(6), None);
    }

    #[test]
    fn missing_dns_tag_is_generated_once_and_compiled_into_clients() {
        let raw = r#"{
            "dns": { "servers": ["192.0.2.53"] },
            "inbounds": [{
              "tag": "tun-in",
              "protocol": "tun"
            }],
            "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
        }"#;
        let parsed = parse_xray_json(raw).expect("DNS server should parse");
        let mut config = parsed.config;

        let policies = take_name_server_policy_set(&mut config);
        let generated = config.dns.tag.clone();
        let uuid = generated
            .strip_prefix(super::GENERATED_DNS_TAG_PREFIX)
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .expect("generated DNS tag should end in a UUID");

        assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
        assert_ne!(generated, "tun-in");
        assert_eq!(policies.tag(0), Some(generated.as_str()));

        let second = take_name_server_policy_set(&mut config);
        assert_eq!(config.dns.tag, generated);
        assert_eq!(second.tag(0), Some(generated.as_str()));
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
        let resolver =
            static_only_dns_resolver_for_config(&parsed.config, static_host_index(&parsed.config));

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
        let resolver =
            static_only_dns_resolver_for_config(&parsed.config, static_host_index(&parsed.config));

        assert_eq!(
            resolver.resolve("resolver.example", 443).await.unwrap(),
            SocketAddr::from(([198, 51, 100, 11], 443))
        );
    }

    #[tokio::test]
    async fn static_only_dns_resolver_preserves_all_host_ip_candidates() {
        let raw = r#"{
            "dns": {
              "queryStrategy": "UseIPv4",
              "hosts": {
                "full:proxy.example": ["2001:db8::10", "198.51.100.12"]
              }
            },
            "inbounds": [],
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" }
            ]
        }"#;
        let parsed = parse_xray_json(raw).expect("config should parse");
        let resolver =
            static_only_dns_resolver_for_config(&parsed.config, static_host_index(&parsed.config));

        let lookup = resolver
            .resolve_all("proxy.example", 443)
            .await
            .expect("resolve every static host address");

        assert_eq!(
            lookup.socket_addrs(),
            &[
                "[2001:db8::10]:443".parse().expect("static IPv6 address"),
                "198.51.100.12:443".parse().expect("static IPv4 address"),
            ]
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

        let error = core
            .dns_resolver
            .resolve("localhost", 8443)
            .await
            .expect_err("configured DNS exhaustion must not use the system resolver");

        assert!(matches!(
            error,
            TransportError::Dns { source, .. }
                if source.kind() == io::ErrorKind::NotConnected
        ));
        assert_eq!(protector.calls.load(Ordering::Relaxed), 2);
    }
}
