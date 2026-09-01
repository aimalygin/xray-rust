mod diagnostic;
mod geodata;
mod model;
mod parser;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    compile_dns_domain_matchers, compile_domain_matchers, ConfigModelError, CoreConfig, DnsConfig,
    DnsFakeIpConfig, DnsHostTarget, DnsIpFilter, DnsNameServerConfig, DnsOutboundRule,
    DnsOutboundRuleAction, DnsOutboundSettings, DnsQTypeRange, DnsQueryStrategy, DnsServerConfig,
    DnsServerEndpoint, DnsServerTransport, DomainHostIndex, DomainMatcher, DomainMatcherSet,
    DomainNameMode, GrpcSettings, HappyEyeballsSettings, HttpUpgradeSettings, InboundConfig,
    InboundProtocol, InboundSniffingConfig, IpCidr, IpMatcherSet, Network, ObservatoryConfig,
    OutboundConfig, OutboundProtocol, OutboundProxySettings, OutboundSettings, PolicyConfig,
    PolicyLevelConfig, PolicySystemConfig, QuicBbrProfile, QuicCongestion, QuicIntervalRange,
    QuicParamsSettings, QuicUdpHopSettings, RealitySettings, RealityShortId, RegexMatcher,
    RoutingBalancer, RoutingBalancerStrategy, RoutingConfig, RoutingDomainStrategy,
    RoutingLeastLoadCost, RoutingLeastLoadSettings, RoutingPortRange, RoutingRule,
    RoutingRuleTarget, SniffingDestination, SocketOptions, StreamSecurity, StreamSettings,
    StreamTransport, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser, WebSocketSettings,
    XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement, XhttpRange,
    XhttpSettings, XhttpUplinkDataPlacement, XhttpXmuxSettings, DEFAULT_DNS_SERVER_TIMEOUT_MS,
    DEFAULT_OBSERVATORY_PROBE_INTERVAL, DEFAULT_OBSERVATORY_PROBE_URL, MAX_DNS_SERVER_TIMEOUT_MS,
    OBSERVATORY_PROBE_TIMEOUT,
};
pub use parser::{
    parse_xray_json, parse_xray_json_with_exclusive_geodata_dirs, parse_xray_json_with_geodata_dir,
    parse_xray_json_with_geodata_dirs, ConfigParseError, ParsedConfig, MAX_CONFIG_DOMAIN_MATCHERS,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
