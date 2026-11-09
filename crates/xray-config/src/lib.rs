mod diagnostic;
mod geodata;
mod model;
mod parser;
pub mod profile_import;
mod surface;
pub mod tooling;
mod xray_uuid;

pub use xray_vless_encryption::Encryption as VlessEncryption;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    compile_dns_domain_matchers, compile_domain_matchers, deciding_final_rule, go_lowercase,
    AddressFamilies, AddressPortRecords, AddressPortStrategy, ConfigModelError, ContentAttributes,
    CoreConfig, CustomSocketOption, DnsConfig, DnsFakeIpConfig, DnsHostTarget, DnsIpFilter,
    DnsNameServerConfig, DnsOutboundRule, DnsOutboundRuleAction, DnsOutboundSettings,
    DnsQTypeRange, DnsQueryStrategy, DnsServerConfig, DnsServerEndpoint, DnsServerTransport,
    DomainHostIndex, DomainMatcher, DomainMatcherSet, DomainNameMode, DomainStrategy,
    FragmentRange, FreedomBlockDelay, FreedomFinalRule, FreedomNoise, FreedomNoiseFamily,
    FreedomNoisePacket, FreedomOutboundSettings, FreedomRedirect, FreedomRuleAction, GrpcSettings,
    HappyEyeballsSettings, HeaderCustomArg, HeaderCustomExpr, HeaderCustomItem, HeaderCustomTcp,
    HeaderCustomUdp, HttpUpgradeSettings, HysteriaOutboundSettings, HysteriaSettings,
    InboundConfig, InboundProtocol, InboundSniffingConfig, IpCidr, IpMatcherSet, KcpHeader,
    KcpMask, KcpSettings, LoopbackOutboundSettings, MuxSettings, MuxUdp443, Network,
    ObservatoryConfig, OutboundConfig, OutboundProtocol, OutboundProxySettings, OutboundSettings,
    PolicyConfig, PolicyLevelConfig, PolicySystemConfig, ProxyProtocolVersion, QuicBbrProfile,
    QuicCongestion, QuicIntervalRange, QuicParamsSettings, QuicUdpHopSettings, RealitySettings,
    RealityShortId, RegexMatcher, RouteContext, RoutingAttributes, RoutingBalancer,
    RoutingBalancerStrategy, RoutingConfig, RoutingDomainStrategy, RoutingLeastLoadCost,
    RoutingLeastLoadSettings, RoutingOrigin, RoutingPortRange, RoutingRule, RoutingRuleTarget,
    RoutingUsers, Shadowsocks2022OutboundSettings, SniffingDestination, SocketOptions,
    StreamSecurity, StreamSettings, StreamTransport, SudokuMask, TargetAddr, TcpFragmentSettings,
    TlsSettings, TproxyMode, TrojanOutboundSettings, VlessOutboundSettings, VlessReverseSettings,
    VlessUser, VmessOutboundSettings, WebSocketSettings, WireguardOutboundSettings,
    WireguardPeerSettings, XhttpDownloadSettings, XhttpMode, XhttpPaddingMethod,
    XhttpPaddingPlacement, XhttpPlacement, XhttpRange, XhttpSettings, XhttpUplinkDataPlacement,
    XhttpXmuxSettings, DEFAULT_DNS_POLICY_KEY, DEFAULT_DNS_SERVER_TIMEOUT_MS,
    DEFAULT_OBSERVATORY_PROBE_INTERVAL, DEFAULT_OBSERVATORY_PROBE_URL, LOCAL_OS,
    MAX_DNS_SERVER_TIMEOUT_MS, MAX_DNS_SERVE_EXPIRED_TTL_SECONDS, OBSERVATORY_PROBE_TIMEOUT,
};
pub use model::{
    BlackholeOutboundSettings, BlackholeResponse, HttpInboundSettings, HttpOutboundSettings,
    RealmIpMode, RealmMask, RealmPortMapping, RealmScheme, RealmStunServer, SocksInboundSettings,
    SocksOutboundSettings, TproxySettings, UdpNoiseItem, UdpNoiseSettings, UdpSudoku, XdnsDomain,
    XdnsMask, XdnsProtocol, XdnsResolver, XicmpMask, XmcMask, XmcProfile,
};
pub use model::{MasqueOutboundSettings, MasqueSettings, MasqueWarpSettings, MASQUE_DEFAULT_XMUX};
pub use parser::{
    parse_xray_json, parse_xray_json_with_exclusive_geodata_dirs, parse_xray_json_with_geodata_dir,
    parse_xray_json_with_geodata_dirs, ConfigParseError, ParsedConfig, MAX_CONFIG_DOMAIN_MATCHERS,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
