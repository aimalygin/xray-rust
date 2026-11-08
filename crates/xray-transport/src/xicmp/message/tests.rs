use super::*;

/// The internet checksum over a message with its checksum field in place
/// is zero.
fn verifies(message: &[u8]) -> bool {
    let mut sum = 0u32;
    for pair in message.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    sum == 0xffff
}

#[test]
fn ipv4_echoes_carry_their_checksum_and_ipv6_ones_leave_it_to_the_system() {
    for length in [0, 1, 7, 8, 9, 1200, 4080] {
        let data: Vec<u8> = (0..length).map(|i| (i * 7 + 3) as u8).collect();
        let request = echo(ECHO_REQUEST_V4, 0xBEEF, 7, &data);
        assert_eq!(&request[..2], &[8, 0]);
        assert_eq!(&request[4..8], &[0xBE, 0xEF, 0, 7]);
        assert_eq!(&request[8..], &data[..]);
        assert!(verifies(&request), "{length}");
        let reply = echo(ECHO_REPLY_V4, 1, 2, &data);
        assert!(verifies(&reply), "{length}");
        let v6 = echo(ECHO_REQUEST_V6, 1, 2, &data);
        assert_eq!(&v6[..4], &[128, 0, 0, 0]);
    }
}

#[test]
fn echoes_parse_as_parse_message_reads_them() {
    let request = echo(ECHO_REQUEST_V4, 9, 10, b"abc");
    assert_eq!(
        parse_echo(&request, false),
        Some(Echo {
            kind: ECHO_REQUEST_V4,
            id: 9,
            seq: 10,
            data: b"abc"
        })
    );
    // The checksum is not checked, nor the code.
    let mut damaged = request.clone();
    damaged[1] = 9;
    damaged[2] ^= 0xFF;
    assert!(parse_echo(&damaged, false).is_some());
    assert!(parse_echo(&request[..7], false).is_none());
    assert_eq!(parse_echo(&request[..8], false).unwrap().data, b"");
    // An ICMPv4 type means nothing on ICMPv6, and other types are skipped.
    assert!(parse_echo(&request, true).is_none());
    assert!(parse_echo(&[3, 1, 0, 0, 0, 0, 0, 0], false).is_none());
    assert!(parse_echo(&echo(ECHO_REPLY_V6, 1, 1, b""), true).is_some());
}

#[test]
fn a_raw_ipv4_header_is_stripped_as_go_strips_it() {
    let mut packet = vec![0x45u8; 20];
    packet.extend_from_slice(b"icmp");
    assert_eq!(strip_ipv4_header(&packet), b"icmp");
    // Options extend the header.
    let mut options = vec![0x46u8; 24];
    options.extend_from_slice(b"icmp");
    assert_eq!(strip_ipv4_header(&options), b"icmp");
    // Too short, a header under 20 bytes, another version, or a header
    // longer than the packet: left alone.
    assert_eq!(strip_ipv4_header(&[0x45; 19]), &[0x45; 19][..]);
    let short = [0x44u8; 24];
    assert_eq!(strip_ipv4_header(&short), &short[..]);
    let v6 = [0x65u8; 24];
    assert_eq!(strip_ipv4_header(&v6), &v6[..]);
    let long = [0x4Fu8; 40];
    assert_eq!(strip_ipv4_header(&long), &long[..]);
}
