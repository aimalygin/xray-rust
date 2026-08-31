use std::net::IpAddr;

use crate::ip_range_set::{IpMatcherSet, IpMatcherSetBuilder};

/// Query-ready `expectedIPs`/`unexpectedIPs` filter: custom and GeoIP matcher
/// categories are independent Xray submatchers ORed together, `soft` is the
/// `*` marker (the preferred subset is used only when it is non-empty).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsIpFilter {
    custom: IpMatcherSet,
    geoip: IpMatcherSet,
    soft: bool,
    matcher_count: usize,
}

impl DnsIpFilter {
    pub fn builder() -> DnsIpFilterBuilder {
        DnsIpFilterBuilder::default()
    }

    pub fn is_empty(&self) -> bool {
        self.custom.is_empty() && self.geoip.is_empty()
    }

    pub fn is_soft(&self) -> bool {
        self.soft
    }

    /// Returns the number of source matcher entries supplied to the filter.
    ///
    /// `Private` counts as one source entry even though compilation expands it
    /// into the nine Xray private-address networks. Inverting a matcher also
    /// does not change the source count.
    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    /// Returns the deterministic number of merged ranges retained by the
    /// query-time index across custom/GeoIP, positive/inverse, and IP-family
    /// partitions.
    pub fn compiled_range_count(&self) -> usize {
        self.custom.range_count() + self.geoip.range_count()
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        self.custom.matches(address) || self.geoip.matches(address)
    }

    /// Applies this filter as `expectedIPs` and returns false when a hard
    /// filter rejects every candidate.
    pub fn apply_expected(&self, addresses: &mut Vec<IpAddr>) -> bool {
        self.retain_preferred(addresses, true)
    }

    /// Applies this filter as `unexpectedIPs` and returns false when a hard
    /// filter rejects every candidate.
    pub fn apply_unexpected(&self, addresses: &mut Vec<IpAddr>) -> bool {
        self.retain_preferred(addresses, false)
    }

    fn retain_preferred(&self, addresses: &mut Vec<IpAddr>, keep_matches: bool) -> bool {
        if self.is_empty() {
            return true;
        }
        let preferred = |address: &IpAddr| self.matches(*address) == keep_matches;
        if self.soft && !addresses.iter().any(&preferred) {
            return true;
        }
        addresses.retain(preferred);
        !addresses.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct DnsIpFilterBuilder {
    custom: IpMatcherSetBuilder,
    geoip: IpMatcherSetBuilder,
    soft: bool,
}

impl DnsIpFilterBuilder {
    pub fn custom(&mut self) -> &mut IpMatcherSetBuilder {
        &mut self.custom
    }

    pub fn geoip(&mut self) -> &mut IpMatcherSetBuilder {
        &mut self.geoip
    }

    pub fn set_soft(&mut self, soft: bool) {
        self.soft = soft;
    }

    pub fn build(self) -> DnsIpFilter {
        DnsIpFilter {
            matcher_count: self.custom.matcher_count() + self.geoip.matcher_count(),
            custom: self.custom.build(),
            geoip: self.geoip.build(),
            soft: self.soft,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::ip_range_set::Cidr;

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

    fn filter(custom: &[(Cidr, bool)], geoip: &[(Cidr, bool)], soft: bool) -> DnsIpFilter {
        let mut builder = DnsIpFilter::builder();
        for (cidr, inverted) in custom {
            builder.custom().insert_cidr(*cidr, *inverted);
        }
        for (cidr, inverted) in geoip {
            builder.geoip().insert_cidr(*cidr, *inverted);
        }
        builder.set_soft(soft);
        builder.build()
    }

    #[test]
    fn filter_counts_source_matchers_and_merged_ranges_separately() {
        let mut builder = DnsIpFilter::builder();
        builder.custom().insert_private_networks(false);
        let private = builder.build();
        assert_eq!(private.matcher_count(), 1);
        assert_eq!(private.compiled_range_count(), 9);
        assert!(private.matches(v4(10, 1, 2, 3)));
        assert!(private.matches(v6([0xfd00, 0, 0, 0, 0, 0, 0, 1])));
        assert!(!private.matches(v4(8, 8, 8, 8)));

        let merged = filter(
            &[
                (cidr(v4(192, 0, 2, 0), 25), false),
                (cidr(v4(192, 0, 2, 128), 25), false),
            ],
            &[(cidr(v4(10, 0, 0, 0), 8), true)],
            false,
        );
        assert_eq!(merged.matcher_count(), 3);
        assert_eq!(merged.compiled_range_count(), 2);
        assert!(merged.matches(v4(192, 0, 2, 255)));

        let mut builder = DnsIpFilter::builder();
        builder.geoip().insert_ip(v4(198, 51, 100, 1), false);
        builder.geoip().insert_ip(mapped(198, 51, 100, 2), false);
        let hosts = builder.build();
        assert_eq!(hosts.matcher_count(), 2);
        assert_eq!(hosts.compiled_range_count(), 1);
        assert!(hosts.matches(v4(198, 51, 100, 2)));
        assert!(!hosts.matches(v4(198, 51, 100, 3)));
    }

    #[test]
    fn filter_ors_custom_and_geoip_categories_independently() {
        let positive = filter(
            &[(cidr(v4(192, 0, 2, 0), 24), false)],
            &[(cidr(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32), false)],
            false,
        );
        assert!(positive.matches(v4(192, 0, 2, 10)));
        assert!(positive.matches(mapped(192, 0, 2, 10)));
        assert!(positive.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 10])));
        assert!(!positive.matches(v4(198, 51, 100, 10)));

        let inverse = filter(
            &[(cidr(v4(10, 0, 0, 0), 8), true)],
            &[(cidr(v4(10, 0, 0, 0), 16), true)],
            false,
        );
        assert!(!inverse.matches(v4(10, 0, 1, 1)));
        assert!(inverse.matches(v4(10, 42, 1, 1)));
        assert!(inverse.matches(v4(192, 0, 2, 1)));
        assert!(!inverse.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));

        let disjoint_inverse = filter(
            &[(cidr(v4(10, 0, 0, 0), 8), true)],
            &[(cidr(v4(192, 168, 0, 0), 16), true)],
            false,
        );
        assert!(disjoint_inverse.matches(v4(10, 1, 2, 3)));
        assert!(disjoint_inverse.matches(v4(192, 168, 1, 2)));
        assert!(disjoint_inverse.matches(v4(203, 0, 113, 7)));
        assert!(!disjoint_inverse.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let mixed = filter(
            &[(cidr(v4(192, 0, 2, 0), 24), false)],
            &[(cidr(v4(198, 51, 100, 0), 24), true)],
            true,
        );
        assert!(mixed.is_soft());
        assert_eq!(mixed.matcher_count(), 2);
        assert!(mixed.matches(v4(192, 0, 2, 1)));
        assert!(mixed.matches(v4(203, 0, 113, 1)));
        assert!(!mixed.matches(v4(198, 51, 100, 1)));
    }

    #[test]
    fn filter_applies_expected_with_hard_and_soft_semantics() {
        let matching_v4 = v4(192, 0, 2, 10);
        let matching_v6 = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 10]);
        let rejected = v4(198, 51, 100, 10);
        let matchers = [
            (cidr(v4(192, 0, 2, 0), 24), false),
            (cidr(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32), false),
        ];
        let hard = filter(&matchers, &[], false);
        let soft = filter(&matchers, &[], true);
        assert!(!hard.is_soft());
        assert!(soft.is_soft());

        let mut hard_candidates = vec![matching_v6, rejected, matching_v4, matching_v6];
        assert!(hard.apply_expected(&mut hard_candidates));
        assert_eq!(hard_candidates, [matching_v6, matching_v4, matching_v6]);

        let mut hard_rejected = vec![rejected];
        assert!(!hard.apply_expected(&mut hard_rejected));
        assert!(hard_rejected.is_empty());

        let mut soft_preferred = vec![rejected, matching_v4];
        assert!(soft.apply_expected(&mut soft_preferred));
        assert_eq!(soft_preferred, [matching_v4]);

        let mut soft_fallback = vec![rejected, rejected];
        assert!(soft.apply_expected(&mut soft_fallback));
        assert_eq!(soft_fallback, [rejected, rejected]);
    }

    #[test]
    fn filter_applies_unexpected_with_hard_and_soft_semantics() {
        let unexpected = v4(192, 0, 2, 10);
        let preferred_v4 = v4(198, 51, 100, 10);
        let preferred_v6 = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 10]);
        let matchers = [(cidr(v4(192, 0, 2, 0), 24), false)];
        let hard = filter(&matchers, &[], false);
        let soft = filter(&matchers, &[], true);

        let mut hard_candidates = vec![unexpected, preferred_v4, preferred_v6, preferred_v4];
        assert!(hard.apply_unexpected(&mut hard_candidates));
        assert_eq!(hard_candidates, [preferred_v4, preferred_v6, preferred_v4]);

        let mut hard_rejected = vec![unexpected, unexpected];
        assert!(!hard.apply_unexpected(&mut hard_rejected));
        assert!(hard_rejected.is_empty());

        let mut soft_preferred = vec![unexpected, preferred_v4];
        assert!(soft.apply_unexpected(&mut soft_preferred));
        assert_eq!(soft_preferred, [preferred_v4]);

        let mut soft_fallback = vec![unexpected, unexpected];
        assert!(soft.apply_unexpected(&mut soft_fallback));
        assert_eq!(soft_fallback, [unexpected, unexpected]);
    }

    #[test]
    fn empty_filter_is_a_noop_even_when_hard() {
        let empty = DnsIpFilter::default();
        let original = vec![v4(192, 0, 2, 1)];
        let mut expected = original.clone();
        let mut unexpected = original.clone();

        assert!(empty.is_empty());
        assert!(!empty.is_soft());
        assert_eq!(empty.matcher_count(), 0);
        assert_eq!(empty.compiled_range_count(), 0);
        assert!(!empty.matches(v4(192, 0, 2, 1)));
        assert!(empty.apply_expected(&mut expected));
        assert!(empty.apply_unexpected(&mut unexpected));
        assert_eq!(expected, original);
        assert_eq!(unexpected, original);
        assert_eq!(DnsIpFilter::builder().build(), empty);

        let mut builder = DnsIpFilter::builder();
        builder.set_soft(true);
        let soft_empty = builder.build();
        assert!(soft_empty.is_empty());
        assert!(soft_empty.is_soft());
        assert_ne!(soft_empty, empty);
    }
}
