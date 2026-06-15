use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::Regex;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigModelError {
    #[error("reality short id cannot exceed 8 bytes")]
    RealityShortIdTooLong,
    #[error("CIDR prefix length {prefix} exceeds max {max}")]
    InvalidCidrPrefix { prefix: u8, max: u8 },
    #[error("invalid domain regex `{pattern}`: {message}")]
    InvalidDomainRegex { pattern: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub default_outbound_tag: Option<String>,
    pub routing: RoutingConfig,
    pub dns: DnsConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    pub fake_ip: Option<DnsFakeIpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFakeIpConfig {
    pub enabled: bool,
    pub ipv4_pool: IpCidr,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    pub inbound_tags: Vec<String>,
    pub domain_matchers: Vec<DomainMatcher>,
    pub ip_matchers: Vec<IpMatcher>,
    pub outbound_tag: String,
}

impl RoutingRule {
    pub fn matches(
        &self,
        inbound_tag: Option<&str>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
    ) -> bool {
        self.matches_inbound(inbound_tag)
            && self.matches_domain(target_domain)
            && self.matches_ip(target_ip)
    }

    pub fn matches_inbound(&self, inbound_tag: Option<&str>) -> bool {
        if self.inbound_tags.is_empty() {
            return true;
        }

        let Some(inbound_tag) = inbound_tag else {
            return false;
        };

        self.inbound_tags
            .iter()
            .any(|candidate| candidate == inbound_tag)
    }

    pub fn matches_domain(&self, target_domain: Option<&str>) -> bool {
        if self.domain_matchers.is_empty() {
            return true;
        }

        let Some(target_domain) = target_domain else {
            return false;
        };

        self.domain_matchers
            .iter()
            .any(|matcher| matcher.matches(target_domain))
    }

    pub fn matches_ip(&self, target_ip: Option<&IpAddr>) -> bool {
        if self.ip_matchers.is_empty() {
            return true;
        }

        let Some(target_ip) = target_ip else {
            return false;
        };

        let mut has_positive = false;
        let mut positive_matched = false;
        let mut has_inverse = false;
        let mut all_inverse_matched = true;

        for matcher in &self.ip_matchers {
            if matcher.is_inverse() {
                has_inverse = true;
                if !matcher.matches(target_ip) {
                    all_inverse_matched = false;
                }
            } else {
                has_positive = true;
                if matcher.matches(target_ip) {
                    positive_matched = true;
                }
            }
        }

        (has_positive && positive_matched) || (has_inverse && all_inverse_matched)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatcher {
    Keyword(String),
    Full(String),
    Suffix(String),
    Regex(RegexMatcher),
}

impl DomainMatcher {
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Keyword(keyword) => contains_ignore_ascii_case(domain, keyword),
            Self::Full(expected) => domain.eq_ignore_ascii_case(expected),
            Self::Suffix(suffix) => domain_matches_suffix(domain, suffix),
            Self::Regex(matcher) => matcher.matches(domain),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegexMatcher {
    pattern: String,
    regex: Regex,
}

impl RegexMatcher {
    pub fn new(pattern: impl Into<String>) -> Result<Self, ConfigModelError> {
        let pattern = pattern.into();
        let regex = Regex::new(&pattern).map_err(|error| ConfigModelError::InvalidDomainRegex {
            pattern: pattern.clone(),
            message: error.to_string(),
        })?;

        Ok(Self { pattern, regex })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn matches(&self, domain: &str) -> bool {
        self.regex.is_match(&domain.to_ascii_lowercase())
    }
}

impl PartialEq for RegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for RegexMatcher {}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }

    if domain.len() <= suffix.len() {
        return false;
    }

    let boundary_index = domain.len() - suffix.len() - 1;
    let domain_bytes = domain.as_bytes();
    domain_bytes[boundary_index] == b'.'
        && domain_bytes[boundary_index + 1..].eq_ignore_ascii_case(suffix.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpMatcher {
    Cidr(IpCidr),
    Private,
    Not(Box<IpMatcher>),
}

impl IpMatcher {
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Cidr(cidr) => cidr.matches(ip),
            Self::Private => private_cidrs()
                .iter()
                .any(|private_cidr| private_cidr.matches(ip)),
            Self::Not(matcher) => !matcher.matches(ip),
        }
    }

    fn is_inverse(&self) -> bool {
        matches!(self, Self::Not(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, ConfigModelError> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(ConfigModelError::InvalidCidrPrefix { prefix, max });
        }

        Ok(Self { network, prefix })
    }

    pub fn full(ip: IpAddr) -> Self {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self {
            network: ip,
            prefix,
        }
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn matches(&self, ip: &IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => prefix_matches(
                u128::from(u32::from(network)),
                u128::from(u32::from(*ip)),
                self.prefix,
                32,
            ),
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_matches(u128::from(network), u128::from(*ip), self.prefix, 128)
            }
            _ => false,
        }
    }
}

fn prefix_matches(network: u128, ip: u128, prefix: u8, width: u8) -> bool {
    if prefix == 0 {
        return true;
    }

    let shift = u32::from(width - prefix);
    (network >> shift) == (ip >> shift)
}

fn private_cidrs() -> [IpCidr; 9] {
    [
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 8,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
            prefix: 10,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            prefix: 8,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
            prefix: 16,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            prefix: 12,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix: 16,
        },
        IpCidr {
            network: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix: 128,
        },
        IpCidr {
            network: IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 7,
        },
        IpCidr {
            network: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 10,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConfig {
    pub tag: Option<String>,
    pub protocol: InboundProtocol,
    pub listen: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundProtocol {
    Socks,
    Http,
    Tun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConfig {
    pub tag: Option<String>,
    pub stream: StreamSettings,
    pub settings: OutboundSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProtocol {
    Freedom,
    Vless,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundSettings {
    Freedom,
    Vless(VlessOutboundSettings),
}

impl OutboundSettings {
    pub fn protocol(&self) -> OutboundProtocol {
        match self {
            Self::Freedom => OutboundProtocol::Freedom,
            Self::Vless(_) => OutboundProtocol::Vless,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessOutboundSettings {
    pub server: TargetAddr,
    pub port: u16,
    pub users: Vec<VlessUser>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessUser {
    pub id: Uuid,
    pub encryption: String,
    pub flow: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSettings {
    pub network: Network,
    pub security: StreamSecurity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSecurity {
    None,
    Tls(TlsSettings),
    Reality(RealitySettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    pub allow_insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySettings {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: RealityShortId,
    pub spider_x: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityShortId {
    bytes: [u8; 8],
    len: u8,
}

impl RealityShortId {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConfigModelError> {
        if bytes.len() > 8 {
            return Err(ConfigModelError::RealityShortIdTooLong);
        }

        let mut short_id = Self {
            bytes: [0; 8],
            len: bytes.len() as u8,
        };
        short_id.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(short_id)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(std::net::IpAddr),
    Domain(String),
}
