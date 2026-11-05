mod diagnostic;
mod geodata;
mod model;
mod parser;
pub mod profile_import;
mod surface;
pub mod tooling;

pub use xray_vless_encryption::Encryption as VlessEncryption;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    compile_dns_domain_matchers, compile_domain_matchers, deciding_final_rule, go_lowercase,
    AddressFamilies, ConfigModelError, ContentAttributes, CoreConfig, DnsConfig, DnsFakeIpConfig,
    DnsHostTarget, DnsIpFilter, DnsNameServerConfig, DnsOutboundRule, DnsOutboundRuleAction,
    DnsOutboundSettings, DnsQTypeRange, DnsQueryStrategy, DnsServerConfig, DnsServerEndpoint,
    DnsServerTransport, DomainHostIndex, DomainMatcher, DomainMatcherSet, DomainNameMode,
    DomainStrategy, FragmentRange, FreedomBlockDelay, FreedomFinalRule, FreedomNoise,
    FreedomNoiseFamily, FreedomNoisePacket, FreedomOutboundSettings, FreedomRedirect,
    FreedomRuleAction, GrpcSettings, HappyEyeballsSettings, HttpUpgradeSettings,
    HysteriaOutboundSettings, HysteriaSettings, InboundConfig, InboundProtocol,
    InboundSniffingConfig, IpCidr, IpMatcherSet, LoopbackOutboundSettings, MuxSettings, MuxUdp443,
    Network, ObservatoryConfig, OutboundConfig, OutboundProtocol, OutboundProxySettings,
    OutboundSettings, PolicyConfig, PolicyLevelConfig, PolicySystemConfig, ProxyProtocolVersion,
    QuicBbrProfile, QuicCongestion, QuicIntervalRange, QuicParamsSettings, QuicUdpHopSettings,
    RealitySettings, RealityShortId, RegexMatcher, RouteContext, RoutingAttributes,
    RoutingBalancer, RoutingBalancerStrategy, RoutingConfig, RoutingDomainStrategy,
    RoutingLeastLoadCost, RoutingLeastLoadSettings, RoutingOrigin, RoutingPortRange, RoutingRule,
    RoutingRuleTarget, RoutingUsers, Shadowsocks2022OutboundSettings, SniffingDestination,
    SocketOptions, StreamSecurity, StreamSettings, StreamTransport, TargetAddr,
    TcpFragmentSettings, TlsSettings, TrojanOutboundSettings, VlessOutboundSettings, VlessUser,
    VmessOutboundSettings, WebSocketSettings, WireguardDomainStrategy, WireguardOutboundSettings,
    WireguardPeerSettings, XhttpDownloadSettings, XhttpMode, XhttpPaddingMethod,
    XhttpPaddingPlacement, XhttpPlacement, XhttpRange, XhttpSettings, XhttpUplinkDataPlacement,
    XhttpXmuxSettings, DEFAULT_DNS_POLICY_KEY, DEFAULT_DNS_SERVER_TIMEOUT_MS,
    DEFAULT_OBSERVATORY_PROBE_INTERVAL, DEFAULT_OBSERVATORY_PROBE_URL, LOCAL_OS,
    MAX_DNS_SERVER_TIMEOUT_MS, MAX_DNS_SERVE_EXPIRED_TTL_SECONDS, OBSERVATORY_PROBE_TIMEOUT,
};
pub use model::{
    BlackholeOutboundSettings, BlackholeResponse, HttpInboundSettings, HttpOutboundSettings,
    SocksInboundSettings, SocksOutboundSettings, TproxySettings, UdpNoiseItem, UdpNoiseSettings,
};
pub use parser::{
    parse_xray_json, parse_xray_json_with_exclusive_geodata_dirs, parse_xray_json_with_geodata_dir,
    parse_xray_json_with_geodata_dirs, ConfigParseError, ParsedConfig, MAX_CONFIG_DOMAIN_MATCHERS,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
