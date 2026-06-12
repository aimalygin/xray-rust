use std::{net::SocketAddr, sync::Arc};

use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use xray_config::{CoreConfig, InboundProtocol};
use xray_runtime::Shutdown;
use xray_transport::{CachingDnsResolver, DnsResolver, SystemDnsResolver, TransportDialer};
use xray_tun::{TunConfig, TunEndpoint};

mod http;
mod outbound;
mod socks;
mod tun;
mod tun_fd;

const TUN_MTU: usize = 1500;
const TUN_INBOUND_QUEUE_DEPTH: usize = 1024;
const TUN_OUTBOUND_QUEUE_DEPTH: usize = 4096;

pub use outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_tcp_stream,
    open_vless_tcp_stream_with_resolver, open_vless_tcp_stream_with_resolver_and_dialer,
    open_vless_udp_stream_with_resolver_and_dialer, select_tcp_outbound,
    select_tcp_outbound_for_session, select_udp_outbound_for_session, select_vless_tcp_outbound,
    TcpOutbound, UdpOutbound, VlessTcpOutbound, VlessUdpFraming,
};
pub use tun_fd::{TunFdClosePolicy, TunFdConfig, TunFdPacketFormat, TunFdRuntime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreState {
    Created,
    Running,
    Stopped,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunRuntimeOptions {
    pub block_quic: bool,
    pub collect_tcp_timings: bool,
    pub profile: TunRuntimeProfile,
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
}

pub struct Core {
    config: CoreConfig,
    state: CoreState,
    shutdown: Shutdown,
    tun: Arc<TunEndpoint>,
    runtime: Option<RuntimeState>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    tun_runtime_options: TunRuntimeOptions,
}

impl Core {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        Self::with_dns_resolver(
            config,
            Arc::new(CachingDnsResolver::new(Arc::new(SystemDnsResolver))),
        )
    }

    /// Creates a core with an injected DNS resolver.
    ///
    /// The resolver is currently used by runtime outbound dialers to resolve
    /// configured outbound server domains. It is not a full Xray DNS policy hook.
    pub fn with_dns_resolver(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, CoreError> {
        Self::with_runtime_dependencies(config, dns_resolver, Arc::new(TransportDialer::system()?))
    }

    pub fn with_tun_runtime_options(
        config: CoreConfig,
        tun_runtime_options: TunRuntimeOptions,
    ) -> Result<Self, CoreError> {
        Self::with_runtime_dependencies_and_tun_options(
            config,
            Arc::new(CachingDnsResolver::new(Arc::new(SystemDnsResolver))),
            Arc::new(TransportDialer::system()?),
            tun_runtime_options,
        )
    }

    pub fn with_runtime_dependencies(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
    ) -> Result<Self, CoreError> {
        Self::with_runtime_dependencies_and_tun_options(
            config,
            dns_resolver,
            transport_dialer,
            TunRuntimeOptions::default(),
        )
    }

    pub fn with_runtime_dependencies_and_tun_options(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
        tun_runtime_options: TunRuntimeOptions,
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
            transport_dialer,
            tun_runtime_options,
        })
    }

    pub fn state(&self) -> CoreState {
        self.state
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
                    tun_inbounds.push(inbound.tag.clone());
                    continue;
                }
            }

            let listener = TcpListener::bind((inbound.listen.as_str(), inbound.port)).await?;
            let addr = listener.local_addr()?;
            bound_listeners.push((
                BoundInbound {
                    tag: inbound.tag.clone(),
                    addr,
                },
                inbound.protocol.clone(),
                listener,
            ));
        }

        if bound_listeners.is_empty() && tun_inbounds.is_empty() {
            return Err(CoreError::NoSupportedInbound);
        }

        let config = Arc::new(self.config.clone());
        let mut inbounds = Vec::with_capacity(bound_listeners.len());
        let mut tasks = Vec::with_capacity(bound_listeners.len() + tun_inbounds.len().min(1));
        for (bound, protocol, listener) in bound_listeners {
            let inbound_tag = bound.tag.clone();
            let dns_resolver = Arc::clone(&self.dns_resolver);
            let transport_dialer = Arc::clone(&self.transport_dialer);
            let task = match protocol {
                InboundProtocol::Socks => tokio::spawn(socks::serve_socks_listener(
                    listener,
                    inbound_tag,
                    Arc::clone(&config),
                    dns_resolver,
                    transport_dialer,
                    self.shutdown.subscribe(),
                )),
                InboundProtocol::Http => tokio::spawn(http::serve_http_listener(
                    listener,
                    inbound_tag,
                    Arc::clone(&config),
                    dns_resolver,
                    transport_dialer,
                    self.shutdown.subscribe(),
                )),
                InboundProtocol::Tun => continue,
            };
            inbounds.push(bound);
            tasks.push(task);
        }
        if !tun_inbounds.is_empty() {
            tasks.push(tokio::spawn(tun::serve_tun_endpoint(
                Arc::clone(&self.tun),
                tun_inbounds.first().cloned().flatten(),
                Arc::clone(&config),
                Arc::clone(&self.dns_resolver),
                Arc::clone(&self.transport_dialer),
                self.tun_runtime_options,
                self.shutdown.subscribe(),
            )));
        }

        self.runtime = Some(RuntimeState { inbounds, tasks });
        self.state = CoreState::Running;
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
