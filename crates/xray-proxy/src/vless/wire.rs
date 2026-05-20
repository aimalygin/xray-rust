use prost::Message;
use thiserror::Error;
use uuid::Uuid;
use xray_routing::{Target, TargetAddr};

const VLESS_VERSION: u8 = 0;
const ADDR_IPV4: u8 = 1;
const ADDR_DOMAIN: u8 = 2;
const ADDR_IPV6: u8 = 3;
const VISION_FLOW: &str = "xtls-rprx-vision";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
    Reverse = 0x04,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub user_id: Uuid,
    pub command: VlessCommand,
    pub target: Target,
    pub flow: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("domain length {0} exceeds vless single-byte domain limit")]
    DomainTooLong(usize),
}

#[derive(Clone, PartialEq, Message)]
struct Addons {
    #[prost(string, tag = "1")]
    flow: String,
}

pub fn encode_request_header(request: &VlessRequest) -> Result<Vec<u8>, WireError> {
    let mut encoded = Vec::new();
    encoded.push(VLESS_VERSION);
    encoded.extend_from_slice(request.user_id.as_bytes());
    encode_addons(request, &mut encoded);
    encoded.push(request.command as u8);
    encoded.extend_from_slice(&request.target.port.to_be_bytes());
    encode_addr(&request.target.addr, &mut encoded)?;

    Ok(encoded)
}

fn encode_addons(request: &VlessRequest, encoded: &mut Vec<u8>) {
    if request.flow.as_deref() != Some(VISION_FLOW) {
        encoded.push(0);
        return;
    }

    let addons = Addons {
        flow: VISION_FLOW.to_owned(),
    };
    let addons_bytes = addons.encode_to_vec();
    encoded.push(addons_bytes.len() as u8);
    encoded.extend_from_slice(&addons_bytes);
}

fn encode_addr(addr: &TargetAddr, encoded: &mut Vec<u8>) -> Result<(), WireError> {
    match addr {
        TargetAddr::Ip(ip) => match ip {
            std::net::IpAddr::V4(ip) => {
                encoded.push(ADDR_IPV4);
                encoded.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                encoded.push(ADDR_IPV6);
                encoded.extend_from_slice(&ip.octets());
            }
        },
        TargetAddr::Domain(domain) => {
            let len = domain.len();
            if len > u8::MAX as usize {
                return Err(WireError::DomainTooLong(len));
            }

            encoded.push(ADDR_DOMAIN);
            encoded.push(len as u8);
            encoded.extend_from_slice(domain.as_bytes());
        }
    }

    Ok(())
}
