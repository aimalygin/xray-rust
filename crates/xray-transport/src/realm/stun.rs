//! STUN Binding as Xray-core's realm client speaks it with pion/stun
//! v3.1.7: a bare 20-byte request, and a response read the way
//! `stun.Decode`, `XORMappedAddress.GetFrom` and `MappedAddress.GetFrom`
//! read it, then `netIPPortToAddrPort`.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(super) const TRANSACTION_ID_LEN: usize = 12;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// The XOR-MAPPED-ADDRESS of draft-ietf-behave-rfc3489bis-02, which pion
/// reads as the standard one.
const ATTR_XOR_MAPPED_ADDRESS_OLD: u16 = 0x8020;
const FAMILY_IPV4: u16 = 0x01;
const FAMILY_IPV6: u16 = 0x02;

/// `stun.Build(stun.TransactionID, stun.BindingRequest)`: the header alone.
pub(super) fn binding_request(transaction_id: [u8; TRANSACTION_ID_LEN]) -> [u8; HEADER_LEN] {
    let mut request = [0u8; HEADER_LEN];
    request[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..].copy_from_slice(&transaction_id);
    request
}

/// A Binding success response's transaction and the address it reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BindingResponse {
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    pub mapped: SocketAddr,
}

/// `parseSTUNBindingResponse`: a decodable message whose type reads as
/// Binding success, with a usable XOR-MAPPED-ADDRESS or, failing that,
/// MAPPED-ADDRESS.
pub(super) fn parse_binding_response(packet: &[u8]) -> Option<BindingResponse> {
    let message = decode(packet)?;
    if !is_binding_success(message.message_type) {
        return None;
    }
    let mapped = message
        .first(ATTR_XOR_MAPPED_ADDRESS)
        .and_then(|value| xor_mapped_address(value, &message.transaction_id))
        .or_else(|| message.first(ATTR_MAPPED_ADDRESS).and_then(mapped_address))?;
    Some(BindingResponse {
        transaction_id: message.transaction_id,
        mapped: to_addr_port(mapped.0, mapped.1)?,
    })
}

struct Message<'a> {
    message_type: u16,
    transaction_id: [u8; TRANSACTION_ID_LEN],
    attributes: Vec<(u16, &'a [u8])>,
}

impl<'a> Message<'a> {
    /// `Message.Get`: the first attribute of the type, 0x8020 counting as
    /// XOR-MAPPED-ADDRESS.
    fn first(&self, kind: u16) -> Option<&'a [u8]> {
        self.attributes
            .iter()
            .find(|(attribute, _)| *attribute == kind)
            .map(|(_, value)| *value)
    }
}

/// `Message.Decode`: the cookie, a length the buffer holds, and attributes
/// whose padded values fit. Bytes past the length are ignored.
fn decode(buffer: &[u8]) -> Option<Message<'_>> {
    if buffer.len() < HEADER_LEN {
        return None;
    }
    let message_type = u16::from_be_bytes([buffer[0], buffer[1]]);
    let size = usize::from(u16::from_be_bytes([buffer[2], buffer[3]]));
    let cookie = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    if cookie != MAGIC_COOKIE || buffer.len() < HEADER_LEN + size {
        return None;
    }
    let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
    transaction_id.copy_from_slice(&buffer[8..HEADER_LEN]);
    let mut body = &buffer[HEADER_LEN..HEADER_LEN + size];
    let mut offset = 0;
    let mut attributes = Vec::new();
    while offset < size {
        if body.len() < ATTRIBUTE_HEADER_LEN {
            return None;
        }
        let mut kind = u16::from_be_bytes([body[0], body[1]]);
        if kind == ATTR_XOR_MAPPED_ADDRESS_OLD {
            kind = ATTR_XOR_MAPPED_ADDRESS;
        }
        let length = usize::from(u16::from_be_bytes([body[2], body[3]]));
        let padded = length.div_ceil(4) * 4;
        body = &body[ATTRIBUTE_HEADER_LEN..];
        offset += ATTRIBUTE_HEADER_LEN;
        if body.len() < padded {
            return None;
        }
        attributes.push((kind, &body[..length]));
        offset += padded;
        body = &body[padded..];
    }
    Some(Message {
        message_type,
        transaction_id,
        attributes,
    })
}

/// `MessageType.ReadValue` reads the method and class from the low 14 bits
/// and drops the two above them.
fn is_binding_success(value: u16) -> bool {
    let class = ((value >> 4) & 0x1) + ((value >> 7) & 0x2);
    let method = (value & 0x000F) + ((value >> 1) & 0x0070) + ((value >> 2) & 0x0F80);
    method == 0x001 && class == 0x2
}

/// The family's address length, or `None` for another family.
fn address_len(value: &[u8]) -> Option<usize> {
    if value.len() <= 4 {
        return None;
    }
    match u16::from_be_bytes([value[0], value[1]]) {
        FAMILY_IPV4 => Some(4),
        FAMILY_IPV6 => Some(16),
        _ => None,
    }
}

/// `XORMappedAddress.GetFromAs`: no more address bytes than the family
/// holds, a shorter address padded with zeros.
fn xor_mapped_address(
    value: &[u8],
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Option<(Vec<u8>, u32)> {
    let length = address_len(value)?;
    let address = &value[4..];
    if address.len() > length {
        return None;
    }
    let port = u32::from(u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16);
    let mut mask = [0u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(transaction_id);
    let mut ip = vec![0u8; length];
    for (i, byte) in address.iter().enumerate() {
        ip[i] = byte ^ mask[i];
    }
    Some((ip, port))
}

/// `MappedAddress.GetFromAs`: what fits of the address, the rest zeros.
fn mapped_address(value: &[u8]) -> Option<(Vec<u8>, u32)> {
    let length = address_len(value)?;
    let mut ip = vec![0u8; length];
    let copied = (value.len() - 4).min(length);
    ip[..copied].copy_from_slice(&value[4..4 + copied]);
    Some((ip, u32::from(u16::from_be_bytes([value[2], value[3]]))))
}

/// `netIPPortToAddrPort`: a nonzero port, and an IPv4-mapped address read
/// as IPv4, as `net.IP.To4` reads it.
fn to_addr_port(ip: Vec<u8>, port: u32) -> Option<SocketAddr> {
    let port = u16::try_from(port).ok().filter(|&port| port != 0)?;
    let ip = match ip.len() {
        4 => IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        _ => {
            let octets: [u8; 16] = ip.try_into().ok()?;
            let ip = Ipv6Addr::from(octets);
            match ip.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(ip),
            }
        }
    };
    Some(SocketAddr::new(ip, port))
}

/// A Binding success response, for tests and the local STUN server they
/// run.
#[cfg(test)]
pub(super) fn binding_success(
    transaction_id: [u8; TRANSACTION_ID_LEN],
    mapped: SocketAddr,
) -> Vec<u8> {
    let (family, ip): (u16, Vec<u8>) = match mapped.ip() {
        IpAddr::V4(ip) => (FAMILY_IPV4, ip.octets().to_vec()),
        IpAddr::V6(ip) => (FAMILY_IPV6, ip.octets().to_vec()),
    };
    let mut mask = [0u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&transaction_id);
    let mut value = Vec::new();
    value.extend_from_slice(&family.to_be_bytes());
    value.extend_from_slice(&(mapped.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    value.extend(ip.iter().zip(mask).map(|(byte, mask)| byte ^ mask));
    let mut message = Vec::new();
    message.extend_from_slice(&0x0101u16.to_be_bytes());
    message.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message.extend_from_slice(&transaction_id);
    message.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    message.extend_from_slice(&(value.len() as u16).to_be_bytes());
    message.extend_from_slice(&value);
    message
}

#[cfg(test)]
mod tests;
