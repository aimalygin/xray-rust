use std::{net::SocketAddr, sync::Arc};

use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use xray_config::{CoreConfig, InboundProtocol};
use xray_runtime::Shutdown;
use xray_transport::{DnsResolver, SystemDnsResolver, TransportDialer};
use xray_tun::{TunConfig, TunEndpoint};

mod outbound;
mod socks;

pub use outbound::{
    open_vless_tcp_stream, open_vless_tcp_stream_with_resolver,
    open_vless_tcp_stream_with_resolver_and_dialer, select_vless_tcp_outbound, VlessTcpOutbound,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreState {
    Created,
    Running,
    Stopped,
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
    tun: TunEndpoint,
    runtime: Option<RuntimeState>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
}

impl Core {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        Self::with_dns_resolver(config, Arc::new(SystemDnsResolver))
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

    pub fn with_runtime_dependencies(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
    ) -> Result<Self, CoreError> {
        let shutdown = Shutdown::new();
        let tun = TunEndpoint::new(TunConfig {
            mtu: 1500,
            queue_depth: 128,
        });

        Ok(Self {
            config,
            state: CoreState::Created,
            shutdown,
            tun,
            runtime: None,
            dns_resolver,
            transport_dialer,
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
        for inbound in &self.config.inbounds {
            if inbound.protocol != InboundProtocol::Socks {
                continue;
            }

            let listener = TcpListener::bind((inbound.listen.as_str(), inbound.port)).await?;
            let addr = listener.local_addr()?;
            bound_listeners.push((
                BoundInbound {
                    tag: inbound.tag.clone(),
                    addr,
                },
                listener,
            ));
        }

        if bound_listeners.is_empty() {
            return Err(CoreError::NoSupportedInbound);
        }

        let config = Arc::new(self.config.clone());
        let mut inbounds = Vec::with_capacity(bound_listeners.len());
        let mut tasks = Vec::with_capacity(bound_listeners.len());
        for (bound, listener) in bound_listeners {
            let dns_resolver = Arc::clone(&self.dns_resolver);
            let transport_dialer = Arc::clone(&self.transport_dialer);
            let task = tokio::spawn(socks::serve_socks_listener(
                listener,
                Arc::clone(&config),
                dns_resolver,
                transport_dialer,
                self.shutdown.subscribe(),
            ));
            inbounds.push(bound);
            tasks.push(task);
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
        &self.tun
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
