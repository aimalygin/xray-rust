use super::*;
use crate::realm::RealmFamily;

fn addrs(list: &[&str]) -> Vec<SocketAddr> {
    list.iter().map(|addr| addr.parse().unwrap()).collect()
}

#[test]
fn keeps_the_families_the_client_has() {
    let peers = addrs(&[
        "198.51.100.1:1000",
        "[2001:db8::1]:1000",
        "198.51.100.1:1000",
    ]);
    let v4 = addrs(&["203.0.113.1:5"]);
    assert_eq!(
        punch_candidates(&v4, &peers, RealmFamily::Dual),
        addrs(&["198.51.100.1:1000"])
    );
    let both = addrs(&["203.0.113.1:5", "[2001:db8::9]:5"]);
    assert_eq!(
        punch_candidates(&both, &peers, RealmFamily::V6),
        addrs(&["[2001:db8::1]:1000"])
    );
    // An IPv4-mapped peer is IPv6 to Go's netip.
    let mapped = addrs(&["[::ffff:198.51.100.1]:1000"]);
    assert!(punch_candidates(&v4, &mapped, RealmFamily::Dual).is_empty());
}

#[test]
fn fills_in_a_predictable_symmetric_nat() {
    let local = addrs(&["203.0.113.1:5"]);
    let peers = addrs(&["198.51.100.1:1000", "198.51.100.1:1003"]);
    let candidates = punch_candidates(&local, &peers, RealmFamily::Dual);
    let mut expected: Vec<SocketAddr> = (1000..=1007)
        .map(|port| SocketAddr::new("198.51.100.1".parse().unwrap(), port))
        .collect();
    sort_by_string(&mut expected);
    assert_eq!(candidates, expected);
    // A gap of five is no pattern.
    let peers = addrs(&["198.51.100.1:1000", "198.51.100.1:1005"]);
    assert_eq!(punch_candidates(&local, &peers, RealmFamily::Dual).len(), 2);
    // At most 32 more per host, and none past 65535.
    let peers = addrs(&["198.51.100.1:65530", "198.51.100.1:65533"]);
    assert_eq!(punch_candidates(&local, &peers, RealmFamily::Dual).len(), 6);
}

#[test]
fn one_bad_address_loses_them_all() {
    assert_eq!(
        parse_addr_ports(&["198.51.100.1:1".into(), "[2001:db8::1]:2".into()]).len(),
        2
    );
    assert!(parse_addr_ports(&["198.51.100.1:1".into(), "nope".into()]).is_empty());
}

#[test]
fn a_long_list_is_cut_to_the_first_candidates() {
    let locals = addrs(&["198.51.100.1:1000"]);
    let peers: Vec<SocketAddr> = (0..1000u32)
        .map(|i| SocketAddr::from(([203, 0, (i >> 8) as u8, i as u8], 4000)))
        .collect();
    let punched = punch_candidates(&locals, &peers, RealmFamily::Dual);
    assert_eq!(punched.len(), MAX_PUNCH_CANDIDATES);
    let mut sorted = peers.clone();
    sort_by_string(&mut sorted);
    assert_eq!(punched, sorted[..MAX_PUNCH_CANDIDATES]);
}
