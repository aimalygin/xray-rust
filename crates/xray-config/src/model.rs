use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub default_outbound_tag: Option<String>,
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
    pub protocol: OutboundProtocol,
    pub server: TargetAddr,
    pub port: u16,
    pub users: Vec<VlessUser>,
    pub stream: StreamSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProtocol {
    Vless,
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
    pub public_key: Vec<u8>,
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(std::net::IpAddr),
    Domain(String),
}
