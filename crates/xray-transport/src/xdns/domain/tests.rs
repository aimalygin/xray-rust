use super::*;

#[test]
fn base32_round_trips_every_length() {
    for length in 0..40 {
        let data: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
        let encoded = base32_encode(&data);
        assert_eq!(encoded.len(), encoded_len(length));
        assert_eq!(base32_decode(&encoded), Some(data));
    }
}

#[test]
fn base32_decodes_as_go_does_at_the_edges() {
    // A last group of one, three or six characters yields nothing.
    assert_eq!(base32_decode(b"M"), Some(vec![]));
    assert_eq!(base32_decode(b"MFRGGZDFM"), Some(b"abcde".to_vec()));
    assert_eq!(base32_decode(b"MFRGGZ"), Some(vec![]));
    // Line breaks are skipped, anything else outside the alphabet fails.
    assert_eq!(base32_decode(b"M\nF\rRA"), Some(b"ab".to_vec()));
    assert_eq!(base32_decode(b"MF1A"), None);
    assert_eq!(base32_decode(b"mfra"), None);
    // 0xFF near the end is padding, as Go reads byte(NoPadding).
    assert_eq!(base32_decode(b"MFRA\xFF\xFF\xFF\xFF"), Some(b"ab".to_vec()));
    assert_eq!(base32_decode(b"MFR\xFF\xFF\xFF\xFF\xFF"), None);
    assert_eq!(base32_decode(b"MFRA\xFF\xFF"), None);
    assert_eq!(base32_decode(b"MFRA\xFFX\xFF\xFF"), None);
    // Too far from the end it is just not in the alphabet.
    assert_eq!(base32_decode(b"M\xFFRGGZDFMZTWQ"), None);
}

#[test]
fn a_name_is_under_the_domain_whatever_its_case_and_labels() {
    let domain = Domain::new("t.example.com", 255, 63, &[TYPE_TXT], 0).unwrap();
    assert!(domain.is_domain(b"x.t.example.com."));
    assert!(domain.is_domain(b"X.T.Example.COM."));
    // Xray checks no label boundary.
    assert!(domain.is_domain(b"xt.example.com."));
    assert!(!domain.is_domain(b"t.example.com."));
    assert!(!domain.is_domain(b"x.t.example.org."));
}

#[test]
fn data_is_split_into_labels_of_the_limit() {
    let domain = Domain::new("t.example.com", 255, 7, &[TYPE_TXT], 0).unwrap();
    let name = domain.encode(&[0xFF; 10]);
    assert_eq!(name, b"7777777.7777777.77.t.example.com.".to_vec());
    assert_eq!(domain.decode(&name), vec![0xFF; 10]);
}

#[test]
fn a_domain_go_accepts_and_then_cannot_pack_is_refused() {
    for name in [
        "",
        ".",
        "a.",
        ".a",
        "a..b",
        &format!("{}.com", "a".repeat(64)),
    ] {
        assert!(
            Domain::new(name, 255, 63, &[TYPE_TXT], 0).is_err(),
            "{name:?}"
        );
    }
    assert!(Domain::new("t.example.com", 255, 63, &[], 0).is_err());
    assert!(Domain::new("t.example.com", 255, 63, &[15], 0).is_err());
    assert!(Domain::new("t.example.com", 255, 63, &[TYPE_TXT], 511).is_err());
    assert!(Domain::new("t.example.com", 255, 63, &[TYPE_TXT], 4097).is_err());
}
