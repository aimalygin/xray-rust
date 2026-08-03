mod diagnostic;
mod geodata;
mod model;
mod parser;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    ConfigModelError, CoreConfig, DnsConfig, DnsFakeIpConfig, DnsHostMapping, DnsHostTarget,
    DnsIpFilter, DnsNameServerConfig, DnsOutboundRule, DnsOutboundRuleAction, DnsOutboundSettings,
    DnsQTypeRange, DnsQueryStrategy, DnsServerConfig, DnsServerEndpoint, DnsServerTransport,
    DomainMatcher, HappyEyeballsSettings, InboundConfig, InboundProtocol, InboundSniffingConfig,
    IpCidr, IpMatcher, Network, OutboundConfig, OutboundProtocol, OutboundSettings, PolicyConfig,
    PolicyLevelConfig, PolicySystemConfig, RealitySettings, RealityShortId, RegexMatcher,
    RoutingConfig, RoutingDomainStrategy, RoutingPortRange, RoutingRule, SniffingDestination,
    SocketOptions, StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings,
    VlessUser, DEFAULT_DNS_SERVER_TIMEOUT_MS, MAX_DNS_SERVER_TIMEOUT_MS,
};
pub use parser::{
    parse_xray_json, parse_xray_json_with_exclusive_geodata_dirs, parse_xray_json_with_geodata_dir,
    parse_xray_json_with_geodata_dirs, ConfigParseError, ParsedConfig,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
