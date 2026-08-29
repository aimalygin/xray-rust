//! Sorted, merged IP range index shared by routing rules and DNS response
//! filters.
//!
//! Xray-core keeps one IPv4 and one IPv6 set per IP matcher
//! (`common/geodata/ip_matcher.go`, `HeuristicIPMatcher.matchAddr`): it unmaps
//! IPv4-mapped IPv6 addresses before the lookup (`netipx.FromStdIP`), answers
//! `Contains(ip) != reverse` inside a family that has ranges, and answers
//! `false` for an address whose family has no ranges at all, regardless of the
//! reverse flag. [`IpRangeSet`] mirrors that model: [`IpRangeSet::lookup`]
//! returns `None` when the family has no ranges and `Some(contains)` otherwise,
//! so a positive matcher is `lookup(ip) == Some(true)` (see
//! [`IpRangeSet::contains`]) and an inverse matcher is
//! `lookup(ip) == Some(false)`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{BitAnd, BitOr, Not};

pub const PRIVATE_NETWORKS: [Cidr; 9] = [
    Cidr::new_const(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    Cidr::new_const(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    Cidr::new_const(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
    Cidr::new_const(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    Cidr::new_const(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    Cidr::new_const(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    Cidr::new_const(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    Cidr::new_const(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    Cidr::new_const(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
];

pub const fn canonicalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => IpAddr::V6(address),
        },
        IpAddr::V4(_) => address,
    }
}

const fn family_width(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("CIDR prefix length {prefix_len} exceeds {max_prefix} for address {address}")]
pub struct InvalidCidrPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub max_prefix: u8,
}

/// A validated `network/prefix_len`: the network is canonicalized
/// (IPv4-mapped IPv6 counts as IPv4) and the prefix never exceeds the width
/// of the address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    pub const fn new(network: IpAddr, prefix_len: u8) -> Result<Self, InvalidCidrPrefix> {
        let network = canonicalize_ip(network);
        let max_prefix = family_width(network);
        if prefix_len > max_prefix {
            return Err(InvalidCidrPrefix {
                address: network,
                prefix_len,
                max_prefix,
            });
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Compile-time constructor for static tables; panics at compile time on
    /// an invalid prefix.
    pub const fn new_const(network: IpAddr, prefix_len: u8) -> Self {
        match Self::new(network, prefix_len) {
            Ok(cidr) => cidr,
            Err(_) => panic!("static CIDR table contains an invalid prefix length"),
        }
    }

    pub const fn host(address: IpAddr) -> Self {
        let address = canonicalize_ip(address);
        Self {
            network: address,
            prefix_len: family_width(address),
        }
    }

    pub const fn network(self) -> IpAddr {
        self.network
    }

    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, canonicalize_ip(address)) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                InclusiveRange::from_prefix(u32::from(network), self.prefix_len)
                    .contains(u32::from(address))
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                InclusiveRange::from_prefix(u128::from(network), self.prefix_len)
                    .contains(u128::from(address))
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

trait AddressBits:
    Copy + Ord + BitAnd<Output = Self> + BitOr<Output = Self> + Not<Output = Self>
{
    const WIDTH: u8;

    fn prefix_mask(prefix_len: u8) -> Self;
    fn saturating_successor(self) -> Self;
    fn to_ip(self) -> IpAddr;
}

macro_rules! impl_address_bits {
    ($($ty:ty => $addr:ty),*) => {$(
        impl AddressBits for $ty {
            const WIDTH: u8 = <$ty>::BITS as u8;

            fn prefix_mask(prefix_len: u8) -> Self {
                debug_assert!(prefix_len <= Self::WIDTH);
                if prefix_len == 0 {
                    0
                } else {
                    <$ty>::MAX << (Self::WIDTH - prefix_len)
                }
            }

            fn saturating_successor(self) -> Self {
                self.saturating_add(1)
            }

            fn to_ip(self) -> IpAddr {
                IpAddr::from(<$addr>::from(self))
            }
        }
    )*};
}

impl_address_bits!(u32 => Ipv4Addr, u128 => Ipv6Addr);

#[derive(Clone, Copy, PartialEq, Eq)]
struct InclusiveRange<T> {
    start: T,
    end: T,
}

impl<T: AddressBits> InclusiveRange<T> {
    fn from_prefix(network: T, prefix_len: u8) -> Self {
        let mask = T::prefix_mask(prefix_len);
        let start = network & mask;
        Self {
            start,
            end: start | !mask,
        }
    }

    fn contains(self, address: T) -> bool {
        self.start <= address && address <= self.end
    }
}

impl<T: AddressBits> fmt::Debug for InclusiveRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", self.start.to_ip(), self.end.to_ip())
    }
}

fn merge_ranges<T: AddressBits>(ranges: &mut Vec<InclusiveRange<T>>) {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut write = 0;
    for read in 0..ranges.len() {
        let current = ranges[read];
        if write > 0 && current.start <= ranges[write - 1].end.saturating_successor() {
            ranges[write - 1].end = ranges[write - 1].end.max(current.end);
        } else {
            ranges[write] = current;
            write += 1;
        }
    }
    ranges.truncate(write);
}

fn ranges_contain<T: AddressBits>(ranges: &[InclusiveRange<T>], address: T) -> bool {
    let insertion = ranges.partition_point(|range| range.start <= address);
    insertion > 0 && address <= ranges[insertion - 1].end
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct IpRangeSet {
    ipv4: Box<[InclusiveRange<u32>]>,
    ipv6: Box<[InclusiveRange<u128>]>,
}

impl IpRangeSet {
    pub fn builder() -> IpRangeSetBuilder {
        IpRangeSetBuilder::default()
    }

    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    pub fn range_count(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    pub fn lookup(&self, address: IpAddr) -> Option<bool> {
        match canonicalize_ip(address) {
            IpAddr::V4(address) => {
                (!self.ipv4.is_empty()).then(|| ranges_contain(&self.ipv4, u32::from(address)))
            }
            IpAddr::V6(address) => {
                (!self.ipv6.is_empty()).then(|| ranges_contain(&self.ipv6, u128::from(address)))
            }
        }
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match canonicalize_ip(address) {
            IpAddr::V4(address) => ranges_contain(&self.ipv4, u32::from(address)),
            IpAddr::V6(address) => ranges_contain(&self.ipv6, u128::from(address)),
        }
    }
}

impl fmt::Debug for IpRangeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpRangeSet")
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct IpRangeSetBuilder {
    ipv4: Vec<InclusiveRange<u32>>,
    ipv6: Vec<InclusiveRange<u128>>,
}

impl IpRangeSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_cidr(&mut self, cidr: Cidr) {
        match cidr.network {
            IpAddr::V4(network) => self.ipv4.push(InclusiveRange::from_prefix(
                u32::from(network),
                cidr.prefix_len,
            )),
            IpAddr::V6(network) => self.ipv6.push(InclusiveRange::from_prefix(
                u128::from(network),
                cidr.prefix_len,
            )),
        }
    }

    pub fn insert_ip(&mut self, address: IpAddr) {
        self.insert_cidr(Cidr::host(address));
    }

    pub fn insert_private_networks(&mut self) {
        for cidr in PRIVATE_NETWORKS {
            self.insert_cidr(cidr);
        }
    }

    pub fn build(mut self) -> IpRangeSet {
        merge_ranges(&mut self.ipv4);
        merge_ranges(&mut self.ipv6);
        IpRangeSet {
            ipv4: self.ipv4.into_boxed_slice(),
            ipv6: self.ipv6.into_boxed_slice(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpMatcherSet {
    positive: IpRangeSet,
    inverse: IpRangeSet,
}

impl IpMatcherSet {
    pub fn builder() -> IpMatcherSetBuilder {
        IpMatcherSetBuilder::default()
    }

    pub fn is_empty(&self) -> bool {
        self.positive.is_empty() && self.inverse.is_empty()
    }

    pub fn range_count(&self) -> usize {
        self.positive.range_count() + self.inverse.range_count()
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        self.positive.contains(address) || self.inverse.lookup(address) == Some(false)
    }
}

#[derive(Debug, Default)]
pub struct IpMatcherSetBuilder {
    positive: IpRangeSetBuilder,
    inverse: IpRangeSetBuilder,
    matcher_count: usize,
}

impl IpMatcherSetBuilder {
    pub fn insert_cidr(&mut self, cidr: Cidr, inverted: bool) {
        self.ranges(inverted).insert_cidr(cidr);
        self.matcher_count += 1;
    }

    pub fn insert_ip(&mut self, address: IpAddr, inverted: bool) {
        self.insert_cidr(Cidr::host(address), inverted);
    }

    pub fn insert_private_networks(&mut self, inverted: bool) {
        self.ranges(inverted).insert_private_networks();
        self.matcher_count += 1;
    }

    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    pub fn build(self) -> IpMatcherSet {
        IpMatcherSet {
            positive: self.positive.build(),
            inverse: self.inverse.build(),
        }
    }

    fn ranges(&mut self, inverted: bool) -> &mut IpRangeSetBuilder {
        if inverted {
            &mut self.inverse
        } else {
            &mut self.positive
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(segments))
    }

    fn mapped(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V6(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())
    }

    fn cidr(network: IpAddr, prefix_len: u8) -> Cidr {
        Cidr::new(network, prefix_len).unwrap()
    }

    fn build_set(cidrs: &[(IpAddr, u8)]) -> IpRangeSet {
        let mut builder = IpRangeSet::builder();
        for (network, prefix_len) in cidrs {
            builder.insert_cidr(cidr(*network, *prefix_len));
        }
        builder.build()
    }

    #[test]
    fn canonicalize_unmaps_only_ipv4_mapped_addresses() {
        assert_eq!(canonicalize_ip(mapped(10, 1, 2, 3)), v4(10, 1, 2, 3));
        assert_eq!(canonicalize_ip(v4(10, 1, 2, 3)), v4(10, 1, 2, 3));
        let native = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        assert_eq!(canonicalize_ip(native), native);
        let compatible = v6([0, 0, 0, 0, 0, 0, 0x0a01, 0x0203]);
        assert_eq!(canonicalize_ip(compatible), compatible);
    }

    #[test]
    fn cidr_rejects_invalid_prefixes_and_mixed_families() {
        assert_eq!(
            Cidr::new(v4(10, 1, 2, 3), 33),
            Err(InvalidCidrPrefix {
                address: v4(10, 1, 2, 3),
                prefix_len: 33,
                max_prefix: 32,
            })
        );
        assert_eq!(
            Cidr::new(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), 129),
            Err(InvalidCidrPrefix {
                address: v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
                prefix_len: 129,
                max_prefix: 128,
            })
        );
        assert_eq!(
            Cidr::new(mapped(10, 1, 2, 3), 120),
            Err(InvalidCidrPrefix {
                address: v4(10, 1, 2, 3),
                prefix_len: 120,
                max_prefix: 32,
            })
        );
        assert_eq!(Cidr::host(mapped(10, 1, 2, 3)), cidr(v4(10, 1, 2, 3), 32));

        assert!(cidr(v4(10, 0, 0, 0), 8).contains(v4(10, 255, 255, 255)));
        assert!(!cidr(v4(10, 0, 0, 0), 8).contains(v4(11, 0, 0, 0)));
        assert!(cidr(v4(10, 0, 0, 0), 8).contains(mapped(10, 9, 8, 7)));
        assert!(cidr(mapped(10, 0, 0, 0), 8).contains(v4(10, 9, 8, 7)));
        assert!(!cidr(v4(10, 0, 0, 0), 8).contains(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(!cidr(v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7).contains(v4(10, 0, 0, 1)));
        assert!(cidr(v4(0, 0, 0, 0), 0).contains(v4(203, 0, 113, 7)));
        assert!(cidr(v6([0; 8]), 0).contains(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(cidr(v4(10, 1, 2, 3), 32).contains(v4(10, 1, 2, 3)));
        assert!(!cidr(v4(10, 1, 2, 3), 32).contains(v4(10, 1, 2, 4)));
    }

    #[test]
    fn adjacent_and_overlapping_ranges_merge_into_one() {
        let set = build_set(&[
            (v4(10, 0, 0, 128), 25),
            (v4(10, 0, 0, 0), 25),
            (v4(10, 0, 1, 0), 24),
            (v4(10, 0, 1, 64), 26),
        ]);
        assert_eq!(set.range_count(), 1);
        assert!(set.contains(v4(10, 0, 0, 0)));
        assert!(set.contains(v4(10, 0, 0, 200)));
        assert!(set.contains(v4(10, 0, 1, 255)));
        assert!(!set.contains(v4(10, 0, 2, 0)));
        assert!(!set.contains(v4(9, 255, 255, 255)));

        let gapped = build_set(&[(v4(10, 0, 0, 0), 24), (v4(10, 0, 2, 0), 24)]);
        assert_eq!(gapped.range_count(), 2);
        assert!(!gapped.contains(v4(10, 0, 1, 7)));
        assert!(gapped.contains(v4(10, 0, 2, 7)));
    }

    #[test]
    fn prefix_zero_covers_the_whole_family_only() {
        let set = build_set(&[(v4(0, 0, 0, 0), 0)]);
        assert_eq!(set.range_count(), 1);
        assert!(set.contains(v4(0, 0, 0, 0)));
        assert!(set.contains(v4(255, 255, 255, 255)));
        assert!(set.contains(mapped(203, 0, 113, 7)));
        assert!(!set.contains(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(set.lookup(v4(1, 1, 1, 1)).is_some());
        assert_eq!(set.lookup(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])), None);

        let all_v6 = build_set(&[(v6([0; 8]), 0)]);
        assert!(all_v6.contains(v6([0xffff; 8])));
        assert!(!all_v6.contains(v4(1, 1, 1, 1)));
        assert!(!all_v6.contains(mapped(1, 1, 1, 1)));
    }

    #[test]
    fn mapped_networks_and_addresses_live_in_the_ipv4_set() {
        let mut builder = IpRangeSet::builder();
        builder.insert_cidr(cidr(mapped(192, 0, 2, 0), 24));
        builder.insert_ip(mapped(198, 51, 100, 1));
        let set = builder.build();

        assert_eq!(set.range_count(), 2);
        assert!(set.lookup(v4(1, 1, 1, 1)).is_some());
        assert_eq!(set.lookup(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])), None);
        assert!(set.contains(v4(192, 0, 2, 9)));
        assert!(set.contains(mapped(192, 0, 2, 9)));
        assert!(set.contains(v4(198, 51, 100, 1)));
        assert!(!set.contains(v4(198, 51, 100, 2)));
    }

    #[test]
    fn empty_set_supports_no_family() {
        let set = IpRangeSet::default();
        assert!(set.is_empty());
        assert_eq!(set.range_count(), 0);
        assert_eq!(set.lookup(v4(1, 1, 1, 1)), None);
        assert_eq!(set.lookup(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])), None);
        assert!(!set.contains(v4(1, 1, 1, 1)));
        assert_eq!(IpRangeSet::builder().build(), set);
    }

    #[test]
    fn private_networks_are_the_xray_geoip_private_set() {
        let mut builder = IpRangeSet::builder();
        builder.insert_private_networks();
        let set = builder.build();

        assert_eq!(PRIVATE_NETWORKS.len(), 9);
        assert_eq!(set.range_count(), 9);
        for address in [
            v4(10, 1, 2, 3),
            v4(100, 64, 0, 1),
            v4(127, 0, 0, 1),
            v4(169, 254, 1, 1),
            v4(172, 31, 255, 255),
            v4(192, 168, 0, 1),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            v6([0xfd00, 0, 0, 0, 0, 0, 0, 1]),
            v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            assert!(set.contains(address), "{address} must be private");
        }
        for address in [
            v4(8, 8, 8, 8),
            v4(172, 32, 0, 1),
            v4(100, 128, 0, 1),
            v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
        ] {
            assert!(!set.contains(address), "{address} must not be private");
        }
    }

    #[test]
    fn debug_output_prints_addresses() {
        let set = build_set(&[(v4(10, 0, 0, 0), 8), (v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7)]);
        assert_eq!(
            format!("{set:?}"),
            "IpRangeSet { ipv4: [10.0.0.0..=10.255.255.255], \
             ipv6: [fc00::..=fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff] }"
        );
    }

    #[test]
    fn matcher_set_disjunction_of_positives_or_conjunction_of_inverses() {
        let mut builder = IpMatcherSet::builder();
        builder.insert_cidr(cidr(v4(203, 0, 113, 0), 24), false);
        builder.insert_cidr(cidr(v4(10, 0, 0, 0), 8), true);
        builder.insert_cidr(cidr(v4(192, 168, 0, 0), 16), true);
        let set = builder.build();

        assert!(!set.is_empty());
        assert_eq!(set.range_count(), 3);
        assert!(set.matches(v4(203, 0, 113, 7)));
        assert!(set.matches(v4(8, 8, 8, 8)));
        assert!(!set.matches(v4(10, 1, 2, 3)));
        assert!(!set.matches(v4(192, 168, 1, 1)));
        assert!(!set.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(set.matches(mapped(203, 0, 113, 7)));
        assert!(!set.matches(mapped(10, 1, 2, 3)));

        let empty = IpMatcherSet::default();
        assert!(empty.is_empty());
        assert!(!empty.matches(v4(8, 8, 8, 8)));
        assert_eq!(IpMatcherSet::builder().build(), empty);

        let mut builder = IpMatcherSet::builder();
        builder.insert_private_networks(true);
        let not_private = builder.build();
        assert!(not_private.matches(v4(8, 8, 8, 8)));
        assert!(!not_private.matches(v4(10, 0, 0, 1)));
        assert!(!not_private.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
