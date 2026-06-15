mod diagnostic;
mod geodata;
mod model;
mod parser;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    ConfigModelError, CoreConfig, DnsConfig, DnsFakeIpConfig, DomainMatcher, InboundConfig,
    InboundProtocol, IpCidr, IpMatcher, Network, OutboundConfig, OutboundProtocol,
    OutboundSettings, RealitySettings, RealityShortId, RegexMatcher, RoutingConfig, RoutingRule,
    StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser,
};
pub use parser::{
    parse_xray_json, parse_xray_json_with_geodata_dir, parse_xray_json_with_geodata_dirs,
    ConfigParseError, ParsedConfig,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
