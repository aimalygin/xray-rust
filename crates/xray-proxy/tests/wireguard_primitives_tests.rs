use base64::{engine::general_purpose, Engine};
use xray_proxy::wireguard::*;

#[test]
fn keys_enforce_decoded_length_alphabet_padding_and_redacted_errors() {
    for length in [0, 1, 31, 33, 48, 1024] {
        let input = general_purpose::STANDARD.encode(vec![1; length]);
        assert!(KeyMaterial::parse(&input).is_err());
    }
    let valid = general_purpose::STANDARD.encode([0xff; 32]);
    assert_eq!(
        KeyMaterial::parse(&valid).unwrap().expose_bytes(),
        &[0xff; 32]
    );
    for invalid in [
        format!(" {valid}"),
        format!("{valid}="),
        "sensitive-key-marker".into(),
        "z".repeat(64),
    ] {
        let error = KeyMaterial::parse(&invalid).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(&invalid));
    }
    let mixed = format!("_{}", &valid[1..]);
    assert!(KeyMaterial::parse(&mixed).is_err());
    let uppercase = "AB".repeat(32);
    assert_eq!(
        KeyMaterial::parse(&uppercase).unwrap().expose_bytes(),
        &[0xab; 32]
    );
}

#[test]
fn prefix_validation_masks_host_bits_and_preserves_address_family() {
    let prefix: AllowedIp = "10.42.1.99/24".parse().unwrap();
    assert_eq!(prefix.network().to_string(), "10.42.1.0");
    assert_eq!(prefix.prefix_length(), 24);
    assert!(prefix.contains("10.42.1.255".parse().unwrap()));
    assert!(!prefix.contains("10.42.2.1".parse().unwrap()));
    assert!(!prefix.contains("::ffff:10.42.1.1".parse().unwrap()));
    for invalid in [
        "10.0.0.0/33",
        "::/129",
        "10.0.0.0",
        "::/-1",
        "::/+1",
        "::/",
        "::/1/2",
        "localhost/32",
        "fe80::1%en0/64",
    ] {
        assert!(invalid.parse::<AllowedIp>().is_err(), "{invalid}");
    }
    let ipv6: AllowedIp = "2001:db8::1/128".parse().unwrap();
    assert!(ipv6.contains("2001:db8::1".parse().unwrap()));
    assert!(!ipv6.contains("2001:db8::2".parse().unwrap()));
}

#[test]
fn no_route_is_a_denial_and_identical_prefixes_follow_last_inserted_peer() {
    let prefix: AllowedIp = "10.0.0.0/8".parse().unwrap();
    let table = PeerRoutes::new(2, &[(prefix, 0), (prefix, 1)]).unwrap();
    let matched = "10.1.2.3".parse().unwrap();
    assert_eq!(table.lookup(matched), Some(1));
    assert!(table.accepts_source(1, matched));
    assert!(!table.accepts_source(0, matched));
    assert!(!table.accepts_source(2, matched));
    assert_eq!(table.lookup("203.0.113.1".parse().unwrap()), None);
    assert_eq!(PeerRoutes::new(1, &[]).unwrap().lookup(matched), None);
}

#[test]
fn configuration_budgets_precede_route_allocation() {
    let prefix: AllowedIp = "::/0".parse().unwrap();
    assert_eq!(PeerRoutes::new(0, &[]).unwrap_err(), RouteError::Budget);
    assert_eq!(
        PeerRoutes::new(MAX_PEERS + 1, &[]).unwrap_err(),
        RouteError::Budget
    );
    assert_eq!(
        PeerRoutes::new(1, &[(prefix, 1)]).unwrap_err(),
        RouteError::Peer
    );
    assert_eq!(
        PeerRoutes::new(1, &vec![(prefix, 0); MAX_ALLOWED_IPS + 1]).unwrap_err(),
        RouteError::Budget
    );
}
