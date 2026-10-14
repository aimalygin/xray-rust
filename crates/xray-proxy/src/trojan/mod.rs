//! Client-side Trojan request and UDP framing, pinned to Xray-core v26.7.28.
//!
//! This module does not dial, authenticate a server, or enable a core outbound.
//! Callers must establish the configured authenticated transport before sending
//! a request. UDP decoding is stateless: retain unconsumed input between reads.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha224};
use thiserror::Error;
use xray_routing::{Network, Target, TargetAddr};
use zeroize::{Zeroize, Zeroizing};

/// Local credential work bound, in UTF-8 bytes.
pub const MAX_PASSWORD_LENGTH: usize = 4096;
/// The pinned Xray Trojan PacketReader rejects payloads above this limit.
pub const MAX_UDP_PAYLOAD_LENGTH: usize = 8192;
pub const MAX_DOMAIN_LENGTH: usize = 255;
/// One domain address, port, payload length, CRLF, and maximum payload.
pub const MAX_UDP_FRAME_LENGTH: usize =
    1 + 1 + MAX_DOMAIN_LENGTH + 2 + 2 + 2 + MAX_UDP_PAYLOAD_LENGTH;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    #[error("Trojan password must contain 1..4096 UTF-8 bytes")]
    PasswordLength,
    #[error("Trojan domain must contain 1..255 UTF-8 bytes without whitespace or controls")]
    Domain,
    #[error("Trojan target port must be nonzero")]
    Port,
    #[error("Trojan datagram requires a UDP target")]
    Network,
    #[error("incomplete Trojan UDP frame")]
    Incomplete,
    #[error("invalid Trojan address type")]
    AddressType,
    #[error("invalid Trojan CRLF delimiter")]
    Delimiter,
    #[error("Trojan UDP payload exceeds the 8192-byte peer limit")]
    PayloadLength,
}

/// The lowercase hex SHA-224 authentication token is a credential itself.
/// The password is borrowed, never retained. Its owner must clear its own copy.
pub struct TrojanAuth(Zeroizing<[u8; 56]>);

impl TrojanAuth {
    pub fn new(password: &str) -> Result<Self, WireError> {
        if password.is_empty() || password.len() > MAX_PASSWORD_LENGTH {
            return Err(WireError::PasswordLength);
        }
        let mut digest = Sha224::digest(password.as_bytes());
        let mut token = Zeroizing::new([0; 56]);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in digest.iter().enumerate() {
            token[2 * index] = HEX[(byte >> 4) as usize];
            token[2 * index + 1] = HEX[(byte & 15) as usize];
        }
        digest[..].zeroize();
        Ok(Self(token))
    }
}

impl fmt::Debug for TrojanAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrojanAuth(<redacted>)")
    }
}

/// A credential-bearing header with redacted Debug and zeroization on drop.
pub struct RequestHeader(Zeroizing<Vec<u8>>);

impl RequestHeader {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RequestHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestHeader(<redacted>)")
    }
}

pub fn encode_request_header(
    auth: &TrojanAuth,
    target: &Target,
) -> Result<RequestHeader, WireError> {
    let address_length = validate_target(target)?;
    let mut wire = Zeroizing::new(Vec::with_capacity(56 + 2 + 1 + address_length + 2));
    wire.extend_from_slice(auth.0.as_ref());
    wire.extend_from_slice(b"\r\n");
    wire.push(match target.network {
        Network::Tcp => 1,
        Network::Udp => 3,
    });
    encode_address(target, &mut wire);
    wire.extend_from_slice(b"\r\n");
    Ok(RequestHeader(wire))
}

#[derive(Clone, PartialEq, Eq)]
pub struct UdpPacket<'a> {
    /// Destination when encoding; source supplied by the server when decoding.
    pub target: Target,
    pub payload: &'a [u8],
}

impl fmt::Debug for UdpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPacket")
            .field("payload_length", &self.payload.len())
            .finish_non_exhaustive()
    }
}

pub fn encode_udp_packet(packet: &UdpPacket<'_>) -> Result<Vec<u8>, WireError> {
    if packet.target.network != Network::Udp {
        return Err(WireError::Network);
    }
    let address_length = validate_target(&packet.target)?;
    if packet.payload.len() > MAX_UDP_PAYLOAD_LENGTH {
        return Err(WireError::PayloadLength);
    }
    let mut wire = Vec::with_capacity(address_length + 4 + packet.payload.len());
    encode_address(&packet.target, &mut wire);
    wire.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(packet.payload);
    Ok(wire)
}

/// Decode one frame without consuming following frames or copying payload.
/// Incomplete input is retryable; other errors require discarding the stream.
/// The caller must bound its receive buffer by `MAX_UDP_FRAME_LENGTH` per frame.
pub fn decode_udp_packet(input: &[u8]) -> Result<(UdpPacket<'_>, usize), WireError> {
    let mut reader = Reader { input, offset: 0 };
    let address_type = reader.take(1)?[0];
    // Keep domain bytes borrowed until the entire frame has passed validation.
    let (ip, domain) = match address_type {
        1 => {
            let bytes: [u8; 4] = reader.take(4)?.try_into().expect("fixed-size slice");
            (Some(IpAddr::V4(Ipv4Addr::from(bytes))), None)
        }
        4 => {
            let bytes: [u8; 16] = reader.take(16)?.try_into().expect("fixed-size slice");
            (Some(IpAddr::V6(Ipv6Addr::from(bytes))), None)
        }
        3 => {
            let length = usize::from(reader.take(1)?[0]);
            let domain =
                std::str::from_utf8(reader.take(length)?).map_err(|_| WireError::Domain)?;
            validate_domain(domain)?;
            (None, Some(domain))
        }
        _ => return Err(WireError::AddressType),
    };
    let port = reader.u16()?;
    if port == 0 {
        return Err(WireError::Port);
    }
    let length = usize::from(reader.u16()?);
    if length > MAX_UDP_PAYLOAD_LENGTH {
        return Err(WireError::PayloadLength);
    }
    if reader.take(2)? != b"\r\n" {
        return Err(WireError::Delimiter);
    }
    let payload = reader.take(length)?;
    let addr = match ip {
        Some(ip) => TargetAddr::Ip(ip),
        None => TargetAddr::Domain(domain.expect("domain address").to_owned()),
    };
    Ok((
        UdpPacket {
            target: Target::new(addr, port, Network::Udp),
            payload,
        },
        reader.offset,
    ))
}

fn validate_domain(domain: &str) -> Result<(), WireError> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_LENGTH
        || domain.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(WireError::Domain);
    }
    Ok(())
}

/// Wire length including address type, domain length where present, and port.
fn validate_target(target: &Target) -> Result<usize, WireError> {
    if target.port == 0 {
        return Err(WireError::Port);
    }
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(_)) => Ok(7),
        TargetAddr::Ip(IpAddr::V6(_)) => Ok(19),
        TargetAddr::Domain(domain) => {
            validate_domain(domain)?;
            Ok(1 + 1 + domain.len() + 2)
        }
    }
}

fn encode_address(target: &Target, wire: &mut Vec<u8>) {
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            wire.push(1);
            wire.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            wire.push(4);
            wire.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(domain) => {
            wire.extend_from_slice(&[3, domain.len() as u8]);
            wire.extend_from_slice(domain.as_bytes());
        }
    }
    wire.extend_from_slice(&target.port.to_be_bytes());
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let bytes = self.input[self.offset..]
            .get(..length)
            .ok_or(WireError::Incomplete)?;
        self.offset += length;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}
