mod diagnostic;
mod model;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundProtocol,
    RealitySettings, StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessUser,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
