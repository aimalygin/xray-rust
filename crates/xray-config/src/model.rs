use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigModelError {
    #[error("reality short id cannot exceed 8 bytes")]
    RealityShortIdTooLong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub default_outbound_tag: Option<String>,
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    pub inbound_tags: Vec<String>,
    pub domain_matchers: Vec<DomainMatcher>,
    pub outbound_tag: String,
}

impl RoutingRule {
    pub fn matches(&self, inbound_tag: Option<&str>, target_domain: Option<&str>) -> bool {
        self.matches_inbound(inbound_tag) && self.matches_domain(target_domain)
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatcher {
    Full(String),
    Suffix(String),
}

impl DomainMatcher {
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(expected) => domain.eq_ignore_ascii_case(expected),
            Self::Suffix(suffix) => domain_matches_suffix(domain, suffix),
        }
    }
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }

    if domain.len() <= suffix.len() {
        return false;
    }

    let boundary_index = domain.len() - suffix.len() - 1;
    domain.as_bytes()[boundary_index] == b'.'
        && domain[boundary_index + 1..].eq_ignore_ascii_case(suffix)
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
