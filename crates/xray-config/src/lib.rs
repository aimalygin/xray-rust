mod diagnostic;
mod model;
mod parser;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    ConfigModelError, CoreConfig, DomainMatcher, InboundConfig, InboundProtocol, IpCidr, IpMatcher,
    Network, OutboundConfig, OutboundProtocol, OutboundSettings, RealitySettings, RealityShortId,
    RoutingConfig, RoutingRule, StreamSecurity, StreamSettings, TargetAddr, TlsSettings,
    VlessOutboundSettings, VlessUser,
};
pub use parser::{parse_xray_json, ConfigParseError, ParsedConfig};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
