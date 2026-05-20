use thiserror::Error;
use xray_config::CoreConfig;
use xray_runtime::Shutdown;
use xray_tun::{TunConfig, TunEndpoint};

mod outbound;

pub use outbound::{open_vless_tcp_stream, select_vless_tcp_outbound, VlessTcpOutbound};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreState {
    Created,
    Running,
    Stopped,
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
    #[error("outbound server address is not supported")]
    UnsupportedOutboundServerAddress,
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
}

impl Core {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
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
        })
    }

    pub fn state(&self) -> CoreState {
        self.state
    }

    pub async fn start(&mut self) -> Result<(), CoreError> {
        if self.state == CoreState::Running {
            return Err(CoreError::AlreadyRunning);
        }
        if self.state == CoreState::Stopped {
            return Err(CoreError::AlreadyStopped);
        }

        let _configured_outbounds = self.config.outbounds.len();
        self.state = CoreState::Running;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), CoreError> {
        self.shutdown.signal();
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
