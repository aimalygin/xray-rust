mod diagnostic;
mod model;
mod parser;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    ConfigModelError, CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig,
    OutboundProtocol, OutboundSettings, RealitySettings, RealityShortId, StreamSecurity,
    StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser,
};
pub use parser::{parse_xray_json, ConfigParseError, ParsedConfig};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
