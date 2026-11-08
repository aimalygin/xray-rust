use super::*;

fn meta() -> PunchMetadata {
    PunchMetadata {
        nonce: [7; NONCE_LEN],
        obfs: [9; OBFS_KEY_LEN],
    }
}

#[test]
fn encoded_packets_decode_with_their_type_and_padding() {
    let meta = meta();
    for kind in [PacketType::Hello, PacketType::Ack] {
        for _ in 0..32 {
            let packet = encode(kind, &meta);
            let (decoded, padding) = decode(&packet, &meta).unwrap();
            assert_eq!(decoded, kind);
            assert_eq!(padding, packet.len() - MIN_WIRE_LEN);
            assert!(padding <= MAX_PADDING);
        }
    }
}

#[test]
fn another_attempt_or_a_damaged_packet_does_not_decode() {
    let meta = meta();
    let packet = encode_with(PacketType::Hello, &meta, [1; SALT_LEN], &[5; 10]);
    let mut other = meta.clone();
    other.nonce[0] ^= 1;
    assert!(decode(&packet, &other).is_none());
    let mut other = meta.clone();
    other.obfs[31] ^= 1;
    assert!(decode(&packet, &other).is_none());
    for i in 0..MIN_WIRE_LEN {
        let mut damaged = packet.clone();
        damaged[i] ^= 0x80;
        assert!(decode(&damaged, &meta).is_none(), "byte {i}");
    }
    // Padding is not checked.
    let mut padded = packet.clone();
    *padded.last_mut().unwrap() ^= 0xFF;
    assert!(decode(&padded, &meta).is_some());
    assert!(decode(&packet[..MIN_WIRE_LEN - 1], &meta).is_none());
    let long = encode_with(PacketType::Ack, &meta, [1; SALT_LEN], &[0; MAX_PADDING + 1]);
    assert!(decode(&long, &meta).is_none());
}

#[test]
fn metadata_is_lower_case_hex() {
    let meta = PunchMetadata::random();
    assert_eq!(meta.nonce_hex().len(), 32);
    assert_eq!(meta.obfs_hex().len(), 64);
    assert!(meta
        .obfs_hex()
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
}
