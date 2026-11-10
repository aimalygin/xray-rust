//! CONNECT-IP capsules (RFC 9484) in the HTTP capsule protocol (RFC 9297),
//! as Xray-core v26.10.31's `connectip/capsule.go` writes and reads them.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub(crate) const CAPSULE_DATAGRAM: u64 = 0;
pub(crate) const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
pub(crate) const CAPSULE_ADDRESS_REQUEST: u64 = 2;
pub(crate) const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;

/// Xray's `maxAddressesPerCapsule` and `maxRoutesPerCapsule`.
pub(crate) const MAX_ENTRIES_PER_CAPSULE: usize = 8192;
/// The longest valid address list or route capsule: 8192 IPv6 routes of
/// 34 bytes. A longer one of those types has too many entries.
const MAX_BUFFERED_CAPSULE: usize = MAX_ENTRIES_PER_CAPSULE * 34;
/// Xray's `maxCapsulePacketSize`, after the context ID.
pub(crate) const MAX_CAPSULE_PACKET: usize = (1 << 16) - 1;
/// The longest DATAGRAM capsule worth buffering: the tunnel reads packets of
/// at most [`MAX_TUNNEL_PACKET`] bytes after a context ID of up to eight.
/// Xray buffers one up to its `maxCapsulePacketSize` and drops it on read;
/// queued whole, 128 of those hold eight times what the tunnel can deliver.
const MAX_BUFFERED_DATAGRAM: usize = 8 + super::session::MAX_TUNNEL_PACKET;

/// A capsule failure: `limit` ends the stream as Xray's `errCapsuleLimit`
/// does, with H3_EXCESSIVE_LOAD; anything else with H3_MESSAGE_ERROR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapsuleError {
    pub(crate) limit: bool,
    pub(crate) message: String,
}

impl CapsuleError {
    fn malformed(message: impl Into<String>) -> Self {
        Self {
            limit: false,
            message: message.into(),
        }
    }
    fn limit(message: impl Into<String>) -> Self {
        Self {
            limit: true,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// An IP prefix as CONNECT-IP carries it: the address and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl IpPrefix {
    pub fn new(addr: IpAddr, len: u8) -> Self {
        Self { addr, len }
    }

    pub(crate) fn bits(&self) -> u8 {
        if self.addr.is_ipv4() {
            32
        } else {
            128
        }
    }

    /// Whether `ip` is inside the prefix; another family never is.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    /// Go's `netip.Prefix.Masked`: the host bits cleared.
    pub fn masked(&self) -> Self {
        let addr = match self.addr {
            IpAddr::V4(addr) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(addr) & mask))
            }
            IpAddr::V6(addr) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(addr) & mask))
            }
        };
        Self {
            addr,
            len: self.len,
        }
    }

    /// `0.0.0.0/32` or `::/128`, which an ADDRESS_ASSIGN uses to refuse a
    /// request.
    pub fn is_rejection(&self) -> bool {
        self.addr.is_unspecified() && self.len == self.bits()
    }

    pub(crate) fn rejection(ipv4: bool) -> Self {
        if ipv4 {
            Self::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32)
        } else {
            Self::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128)
        }
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// One entry of an ADDRESS_ASSIGN or ADDRESS_REQUEST capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub prefix: IpPrefix,
}

/// One range of a ROUTE_ADVERTISEMENT capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRoute {
    pub start: IpAddr,
    pub end: IpAddr,
    pub protocol: u8,
}

/// A capsule the reader understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Capsule {
    AddressAssign(Vec<AssignedAddress>),
    AddressRequest(Vec<AssignedAddress>),
    RouteAdvertisement(Vec<IpRoute>),
    /// A DATAGRAM capsule's value: the context ID and the packet.
    Datagram(Bytes),
}

// ---- QUIC variable-length integers ----------------------------------------

pub(crate) fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

pub(crate) fn put_varint(buf: &mut impl BufMut, value: u64) {
    match varint_len(value) {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | value),
    }
}

/// Reads a varint from the front of `bytes`: the value and its length, or
/// `None` while it is incomplete.
pub(crate) fn parse_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let len = 1usize << (first >> 6);
    if bytes.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = value << 8 | u64::from(*byte);
    }
    Some((value, len))
}

// ---- Writing --------------------------------------------------------------

fn put_capsule_header(buf: &mut BytesMut, kind: u64, len: usize) {
    put_varint(buf, kind);
    put_varint(buf, len as u64);
}

fn address_len(entry: &AssignedAddress) -> usize {
    varint_len(entry.request_id) + 1 + usize::from(entry.prefix.bits() / 8) + 1
}

fn put_address(buf: &mut BytesMut, entry: &AssignedAddress) {
    put_varint(buf, entry.request_id);
    match entry.prefix.addr {
        IpAddr::V4(addr) => {
            buf.put_u8(4);
            buf.put_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            buf.put_u8(6);
            buf.put_slice(&addr.octets());
        }
    }
    buf.put_u8(entry.prefix.len);
}

/// An ADDRESS_REQUEST capsule, Xray's `addressRequestCapsule.append`.
pub(crate) fn address_request(entries: &[AssignedAddress]) -> Bytes {
    let len = entries.iter().map(address_len).sum();
    let mut buf = BytesMut::with_capacity(16 + len);
    put_capsule_header(&mut buf, CAPSULE_ADDRESS_REQUEST, len);
    for entry in entries {
        put_address(&mut buf, entry);
    }
    buf.freeze()
}

/// An ADDRESS_ASSIGN capsule, Xray's `addressAssignCapsule.append`.
pub(crate) fn address_assign(entries: &[AssignedAddress]) -> Bytes {
    let len = entries.iter().map(address_len).sum();
    let mut buf = BytesMut::with_capacity(16 + len);
    put_capsule_header(&mut buf, CAPSULE_ADDRESS_ASSIGN, len);
    for entry in entries {
        put_address(&mut buf, entry);
    }
    buf.freeze()
}

// ---- Reading --------------------------------------------------------------

/// Splits a byte stream into capsules: DATAGRAM, the three CONNECT-IP types,
/// and any other type, which is skipped without being buffered.
#[derive(Debug, Default)]
pub(crate) struct CapsuleParser {
    buf: BytesMut,
    /// Bytes of an unknown or oversized capsule still to skip.
    skip: u64,
}

/// What [`CapsuleParser::next`] found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    Capsule(Capsule),
    /// A DATAGRAM capsule longer than the tunnel reads, skipped: its length.
    OversizedDatagram(u64),
}

impl CapsuleParser {
    pub(crate) fn push(&mut self, mut data: impl Buf) {
        while data.has_remaining() {
            let chunk = data.chunk();
            if self.skip > 0 {
                let n = usize::try_from(self.skip)
                    .unwrap_or(usize::MAX)
                    .min(chunk.len());
                self.skip -= n as u64;
                data.advance(n);
                continue;
            }
            let n = chunk.len();
            self.buf.extend_from_slice(chunk);
            data.advance(n);
        }
    }

    /// Whether a capsule is partly read; the stream must not end then.
    pub(crate) fn is_mid_capsule(&self) -> bool {
        self.skip > 0 || !self.buf.is_empty()
    }

    /// The next complete capsule, if any.
    pub(crate) fn next(&mut self) -> Result<Option<Parsed>, CapsuleError> {
        loop {
            if self.skip > 0 {
                return Ok(None);
            }
            let Some((kind, kind_len)) = parse_varint(&self.buf) else {
                return Ok(None);
            };
            let Some((len, len_len)) = parse_varint(&self.buf[kind_len..]) else {
                return Ok(None);
            };
            let header = kind_len + len_len;
            let known = matches!(
                kind,
                CAPSULE_ADDRESS_ASSIGN | CAPSULE_ADDRESS_REQUEST | CAPSULE_ROUTE_ADVERTISEMENT
            );
            let oversized_datagram = kind == CAPSULE_DATAGRAM && len > MAX_BUFFERED_DATAGRAM as u64;
            if !known && kind != CAPSULE_DATAGRAM || oversized_datagram {
                // Skip what is buffered, then the rest as it arrives.
                let buffered = (self.buf.len() - header) as u64;
                let skipped = buffered.min(len);
                self.buf.advance(header + skipped as usize);
                self.skip = len - skipped;
                if oversized_datagram {
                    return Ok(Some(Parsed::OversizedDatagram(len)));
                }
                continue;
            }
            if known && len > MAX_BUFFERED_CAPSULE as u64 {
                return Err(CapsuleError::limit(format!(
                    "a {}-byte capsule holds more than {MAX_ENTRIES_PER_CAPSULE} entries",
                    len
                )));
            }
            let len = len as usize;
            if self.buf.len() < header + len {
                return Ok(None);
            }
            self.buf.advance(header);
            let value = self.buf.split_to(len).freeze();
            let capsule = match kind {
                CAPSULE_DATAGRAM => Capsule::Datagram(value),
                CAPSULE_ADDRESS_ASSIGN => Capsule::AddressAssign(parse_addresses(&value, false)?),
                CAPSULE_ADDRESS_REQUEST => Capsule::AddressRequest(parse_addresses(&value, true)?),
                _ => Capsule::RouteAdvertisement(parse_routes(&value)?),
            };
            return Ok(Some(Parsed::Capsule(capsule)));
        }
    }
}

/// Xray's `parseAddressAssignCapsule` and `parseAddressRequestCapsule`.
pub(crate) fn parse_addresses(
    mut value: &[u8],
    request: bool,
) -> Result<Vec<AssignedAddress>, CapsuleError> {
    let name = if request {
        "ADDRESS_REQUEST"
    } else {
        "ADDRESS_ASSIGN"
    };
    if request && value.is_empty() {
        return Err(CapsuleError::malformed(
            "ADDRESS_REQUEST capsule contains no addresses",
        ));
    }
    let mut entries = Vec::new();
    while !value.is_empty() {
        if entries.len() >= MAX_ENTRIES_PER_CAPSULE {
            return Err(CapsuleError::limit(format!(
                "{name} capsule contains too many addresses (maximum {MAX_ENTRIES_PER_CAPSULE})"
            )));
        }
        let (request_id, n) =
            parse_varint(value).ok_or_else(|| CapsuleError::malformed("unexpected EOF"))?;
        value = &value[n..];
        let (&version, rest) = value
            .split_first()
            .ok_or_else(|| CapsuleError::malformed("unexpected EOF"))?;
        value = rest;
        let addr = match version {
            4 => {
                let octets: [u8; 4] = take(&mut value)?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let octets: [u8; 16] = take(&mut value)?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            other => {
                return Err(CapsuleError::malformed(format!(
                    "invalid IP version: {other}"
                )))
            }
        };
        let (&len, rest) = value
            .split_first()
            .ok_or_else(|| CapsuleError::malformed("unexpected EOF"))?;
        value = rest;
        let prefix = IpPrefix::new(addr, len);
        if len > prefix.bits() {
            return Err(CapsuleError::malformed(format!(
                "prefix length {len} exceeds IP address length ({})",
                prefix.bits()
            )));
        }
        if prefix.masked() != prefix {
            return Err(CapsuleError::malformed(
                "lower bits not covered by prefix length are not all zero",
            ));
        }
        if request && request_id == 0 {
            return Err(CapsuleError::malformed(
                "ADDRESS_REQUEST capsule contains a zero request ID",
            ));
        }
        entries.push(AssignedAddress { request_id, prefix });
    }
    Ok(entries)
}

fn take<const N: usize>(value: &mut &[u8]) -> Result<[u8; N], CapsuleError> {
    if value.len() < N {
        return Err(CapsuleError::malformed("unexpected EOF"));
    }
    let (head, rest) = value.split_at(N);
    *value = rest;
    Ok(head.try_into().expect("length checked"))
}

/// Xray's `parseRouteAdvertisementCapsule`, with its ordering check.
pub(crate) fn parse_routes(mut value: &[u8]) -> Result<Vec<IpRoute>, CapsuleError> {
    let mut routes: Vec<IpRoute> = Vec::new();
    while !value.is_empty() {
        if routes.len() >= MAX_ENTRIES_PER_CAPSULE {
            return Err(CapsuleError::limit(format!(
                "ROUTE_ADVERTISEMENT capsule contains too many routes (maximum {MAX_ENTRIES_PER_CAPSULE})"
            )));
        }
        let (&version, rest) = value
            .split_first()
            .ok_or_else(|| CapsuleError::malformed("unexpected EOF"))?;
        value = rest;
        let (start, end) = match version {
            4 => {
                let start: [u8; 4] = take(&mut value)?;
                let end: [u8; 4] = take(&mut value)?;
                (IpAddr::from(start), IpAddr::from(end))
            }
            6 => {
                let start: [u8; 16] = take(&mut value)?;
                let end: [u8; 16] = take(&mut value)?;
                (IpAddr::from(start), IpAddr::from(end))
            }
            other => {
                return Err(CapsuleError::malformed(format!(
                    "invalid IP version: {other}"
                )))
            }
        };
        if start > end {
            return Err(CapsuleError::malformed("start IP is greater than end IP"));
        }
        let (&protocol, rest) = value
            .split_first()
            .ok_or_else(|| CapsuleError::malformed("unexpected EOF"))?;
        value = rest;
        let route = IpRoute {
            start,
            end,
            protocol,
        };
        if let Some(previous) = routes.last() {
            check_route_order(previous, &route)?;
        }
        routes.push(route);
    }
    Ok(routes)
}

/// Xray's `checkRouteOrder`: by IP version, then protocol, then ascending
/// ranges that do not overlap.
fn check_route_order(a: &IpRoute, b: &IpRoute) -> Result<(), CapsuleError> {
    let bits = |ip: &IpAddr| if ip.is_ipv4() { 32 } else { 128 };
    match (bits(&a.start), a.protocol).cmp(&(bits(&b.start), b.protocol)) {
        std::cmp::Ordering::Greater => Err(CapsuleError::malformed(format!(
            "routes are not ordered by IP version and IP protocol: {}-{} (protocol {}) precedes {}-{} (protocol {})",
            a.start, a.end, a.protocol, b.start, b.end, b.protocol
        ))),
        std::cmp::Ordering::Equal if a.end >= b.start => Err(CapsuleError::malformed(format!(
            "IP address ranges {}-{} and {}-{} (protocol {}) overlap or are not in ascending order",
            a.start, a.end, b.start, b.end, b.protocol
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> IpPrefix {
        let (addr, len) = text.split_once('/').unwrap();
        IpPrefix::new(addr.parse().unwrap(), len.parse().unwrap())
    }

    #[test]
    fn varints_round_trip_at_each_length() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            (1 << 62) - 1,
        ] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            assert_eq!(buf.len(), varint_len(value));
            assert_eq!(parse_varint(&buf), Some((value, buf.len())));
            assert_eq!(parse_varint(&buf[..buf.len() - 1]), None);
        }
    }

    #[test]
    fn the_client_address_request_is_xrays() {
        let request = address_request(&[
            AssignedAddress {
                request_id: 1,
                prefix: prefix("0.0.0.0/32"),
            },
            AssignedAddress {
                request_id: 2,
                prefix: prefix("::/128"),
            },
        ]);
        let mut expected = vec![0x02, 26, 1, 4, 0, 0, 0, 0, 32, 2, 6];
        expected.extend([0; 16]);
        expected.push(128);
        assert_eq!(&request[..], &expected[..]);
    }

    #[test]
    fn capsules_split_across_pushes_and_skip_unknown_types() {
        let mut parser = CapsuleParser::default();
        let assign = address_assign(&[AssignedAddress {
            request_id: 0,
            prefix: prefix("10.0.0.2/32"),
        }]);
        let mut stream = BytesMut::new();
        // An unknown capsule type 0x41 with 70 bytes, then the assignment.
        put_varint(&mut stream, 0x41);
        put_varint(&mut stream, 70);
        stream.extend_from_slice(&[7; 70]);
        stream.extend_from_slice(&assign);
        for chunk in stream.chunks(5) {
            parser.push(chunk);
        }
        assert_eq!(
            parser.next().unwrap(),
            Some(Parsed::Capsule(Capsule::AddressAssign(vec![
                AssignedAddress {
                    request_id: 0,
                    prefix: prefix("10.0.0.2/32"),
                }
            ])))
        );
        assert_eq!(parser.next().unwrap(), None);
        assert!(!parser.is_mid_capsule());
    }

    #[test]
    fn addresses_with_host_bits_or_long_prefixes_are_malformed() {
        let mut value = vec![1, 4, 10, 0, 0, 1, 24];
        assert!(parse_addresses(&value, false).is_err());
        value[6] = 33;
        assert!(parse_addresses(&value, false).is_err());
        value[6] = 32;
        assert!(parse_addresses(&value, false).is_ok());
        // A request needs a nonzero ID and at least one entry.
        assert!(parse_addresses(&[0, 4, 0, 0, 0, 0, 32], true).is_err());
        assert!(parse_addresses(&[], true).is_err());
        assert_eq!(parse_addresses(&[], false), Ok(Vec::new()));
        assert!(parse_addresses(&[1, 5, 0], false).is_err());
    }

    #[test]
    fn routes_must_be_ordered_and_disjoint() {
        let v4 = |a: [u8; 4], b: [u8; 4], p: u8| {
            let mut out = vec![4];
            out.extend(a);
            out.extend(b);
            out.push(p);
            out
        };
        let ordered = [
            v4([0, 0, 0, 0], [9, 255, 255, 255], 0),
            v4([11, 0, 0, 0], [255, 255, 255, 255], 0),
        ]
        .concat();
        assert_eq!(parse_routes(&ordered).unwrap().len(), 2);
        let overlapping = [
            v4([0, 0, 0, 0], [10, 0, 0, 0], 0),
            v4([10, 0, 0, 0], [11, 0, 0, 0], 0),
        ]
        .concat();
        assert!(parse_routes(&overlapping).is_err());
        let by_protocol = [
            v4([0, 0, 0, 0], [1, 0, 0, 0], 17),
            v4([0, 0, 0, 0], [1, 0, 0, 0], 6),
        ]
        .concat();
        assert!(parse_routes(&by_protocol).is_err());
        assert!(parse_routes(&v4([2, 0, 0, 0], [1, 0, 0, 0], 0)).is_err());
    }

    #[test]
    fn oversized_datagram_capsules_are_skipped_not_buffered() {
        let mut parser = CapsuleParser::default();
        let mut head = BytesMut::new();
        put_varint(&mut head, CAPSULE_DATAGRAM);
        put_varint(&mut head, 70_000);
        parser.push(&head[..]);
        assert_eq!(
            parser.next().unwrap(),
            Some(Parsed::OversizedDatagram(70_000))
        );
        parser.push(&vec![0u8; 70_000][..]);
        assert!(!parser.is_mid_capsule());
        assert_eq!(parser.next().unwrap(), None);
    }

    /// A DATAGRAM the tunnel would drop on read is skipped as well, though
    /// it is within what a capsule may carry.
    #[test]
    fn a_datagram_capsule_longer_than_the_tunnel_reads_is_skipped() {
        let mut parser = CapsuleParser::default();
        let longest = MAX_BUFFERED_DATAGRAM as u64;
        let mut head = BytesMut::new();
        put_varint(&mut head, CAPSULE_DATAGRAM);
        put_varint(&mut head, longest + 1);
        parser.push(&head[..]);
        assert_eq!(
            parser.next().unwrap(),
            Some(Parsed::OversizedDatagram(longest + 1))
        );
        parser.push(&vec![0u8; longest as usize + 1][..]);

        let mut whole = BytesMut::new();
        put_varint(&mut whole, CAPSULE_DATAGRAM);
        put_varint(&mut whole, longest);
        whole.extend_from_slice(&vec![0u8; longest as usize]);
        parser.push(&whole[..]);
        assert!(matches!(
            parser.next().unwrap(),
            Some(Parsed::Capsule(Capsule::Datagram(datagram))) if datagram.len() == longest as usize
        ));
    }

    #[test]
    fn a_too_long_address_capsule_is_over_the_limit() {
        let mut parser = CapsuleParser::default();
        let mut head = BytesMut::new();
        put_varint(&mut head, CAPSULE_ADDRESS_ASSIGN);
        put_varint(&mut head, (MAX_BUFFERED_CAPSULE + 1) as u64);
        parser.push(&head[..]);
        assert!(parser.next().unwrap_err().limit);
    }

    #[test]
    fn rejections_and_containment() {
        assert!(prefix("0.0.0.0/32").is_rejection());
        assert!(prefix("::/128").is_rejection());
        assert!(!prefix("0.0.0.0/0").is_rejection());
        assert!(prefix("10.0.0.0/8").contains("10.1.2.3".parse().unwrap()));
        assert!(!prefix("10.0.0.0/8").contains("11.0.0.1".parse().unwrap()));
        assert!(prefix("0.0.0.0/0").contains("1.2.3.4".parse().unwrap()));
        assert!(!prefix("0.0.0.0/0").contains("::1".parse().unwrap()));
        assert_eq!(prefix("2001:db8::7/64").masked(), prefix("2001:db8::/64"));
    }
}
