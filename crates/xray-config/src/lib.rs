mod diagnostic;
mod model;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    ConfigModelError, CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig,
    OutboundProtocol, OutboundSettings, RealitySettings, RealityShortId, StreamSecurity,
    StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
