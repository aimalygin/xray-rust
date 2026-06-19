mod diagnostic;
mod geodata;
mod model;
mod parser;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    ConfigModelError, CoreConfig, DnsConfig, DnsFakeIpConfig, DnsHostMapping, DnsHostTarget,
    DnsServerConfig, DomainMatcher, InboundConfig, InboundProtocol, InboundSniffingConfig, IpCidr,
    IpMatcher, Network, OutboundConfig, OutboundProtocol, OutboundSettings, PolicyConfig,
    PolicyLevelConfig, PolicySystemConfig, RealitySettings, RealityShortId, RegexMatcher,
    RoutingConfig, RoutingDomainStrategy, RoutingRule, SniffingDestination, StreamSecurity,
    StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser,
};
pub use parser::{
    parse_xray_json, parse_xray_json_with_geodata_dir, parse_xray_json_with_geodata_dirs,
    ConfigParseError, ParsedConfig,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
