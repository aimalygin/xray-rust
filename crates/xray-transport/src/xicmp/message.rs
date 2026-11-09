//! ICMP echo messages as Xray-core's xicmp client writes and reads them:
//! its `marshal`, x/net/icmp's `ParseMessage` and `checksum`, and the IPv4
//! header Go's raw socket strips.

pub(super) const ECHO_REQUEST_V4: u8 = 8;
pub(super) const ECHO_REPLY_V4: u8 = 0;
pub(super) const ECHO_REQUEST_V6: u8 = 128;
pub(super) const ECHO_REPLY_V6: u8 = 129;
/// The echo header: type, code, checksum, identifier and sequence.
pub(super) const HEADER_LEN: usize = 8;

/// x/net/icmp's `checksum`, which sums little-endian words; `marshal`
/// writes its low byte first.
pub(super) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs {
        sum += u32::from(pair[1]) << 8 | u32::from(pair[0]);
    }
    if let [last] = pairs.remainder() {
        sum += u32::from(*last);
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    !(sum as u16)
}

/// `marshal`: the echo header over `data`, its checksum for ICMPv4 only,
/// which the system computes for ICMPv6.
pub(super) fn echo(kind: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEADER_LEN + data.len());
    message.push(kind);
    message.extend_from_slice(&[0, 0, 0]);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(data);
    if matches!(kind, ECHO_REQUEST_V4 | ECHO_REPLY_V4) {
        let sum = checksum(&message);
        message[2] ^= sum as u8;
        message[3] ^= (sum >> 8) as u8;
    }
    message
}

/// An echo message as `ParseMessage` reads it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Echo<'a> {
    pub kind: u8,
    pub id: u16,
    pub seq: u16,
    pub data: &'a [u8],
}

/// `ParseMessage`, for the echo types: four bytes of header and four of
/// identifier and sequence. The checksum is not checked.
pub(super) fn parse_echo(message: &[u8], v6: bool) -> Option<Echo<'_>> {
    if message.len() < HEADER_LEN {
        return None;
    }
    let kind = message[0];
    let echo = if v6 {
        matches!(kind, ECHO_REQUEST_V6 | ECHO_REPLY_V6)
    } else {
        matches!(kind, ECHO_REQUEST_V4 | ECHO_REPLY_V4)
    };
    echo.then(|| Echo {
        kind,
        id: u16::from_be_bytes([message[4], message[5]]),
        seq: u16::from_be_bytes([message[6], message[7]]),
        data: &message[HEADER_LEN..],
    })
}

/// Go's `stripIPv4Header`, which a raw IPv4 socket's reads go through: an
/// IPv4 header of at least 20 bytes that fits is dropped.
pub(super) fn strip_ipv4_header(packet: &[u8]) -> &[u8] {
    if packet.len() < 20 {
        return packet;
    }
    let length = usize::from(packet[0] & 0x0f) << 2;
    if length < 20 || length > packet.len() || packet[0] >> 4 != 4 {
        return packet;
    }
    &packet[length..]
}

#[cfg(test)]
mod tests;
