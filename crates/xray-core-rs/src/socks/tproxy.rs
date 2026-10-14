//! Linux TPROXY adapter; all application routing/relaying uses the shared handlers.
use super::*;

#[derive(Clone)]
pub(crate) struct Context {
    pub inbound_tag: Option<String>,
    pub config: Arc<CoreConfig>,
    pub router: Arc<OutboundRouter>,
    pub dns: RuntimeDnsResolvers,
    pub dialer: Arc<TransportDialer>,
    pub sniffing: Option<InboundSniffingConfig>,
    pub policy: EffectivePolicy,
    pub logger: RuntimeLogger,
    pub registry: Arc<ConnectionRegistry>,
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{bind, serve};

pub(crate) struct Bound {
    pub addr: SocketAddr,
    #[cfg(target_os = "linux")]
    tcp: Option<TcpListener>,
    #[cfg(target_os = "linux")]
    udp: Option<UdpSocket>,
    #[cfg(target_os = "linux")]
    mark: u32,
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn bind(
    _: &xray_config::InboundConfig,
    _: xray_config::TproxySettings,
) -> Result<Bound, crate::CoreError> {
    Err(crate::CoreError::UnsupportedTproxyPlatform)
}
#[cfg(not(target_os = "linux"))]
pub(crate) async fn serve(_: Bound, context: Context, _: watch::Receiver<bool>) {
    // bind always rejects this platform before any runtime task is started.
    let Context {
        inbound_tag,
        config,
        router,
        dns,
        dialer,
        sniffing,
        policy,
        logger,
        registry,
    } = context;
    drop((
        inbound_tag,
        config,
        router,
        dns,
        dialer,
        sniffing,
        policy,
        logger,
        registry,
    ));
}
