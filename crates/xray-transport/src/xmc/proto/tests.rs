use super::*;

#[test]
fn varints_are_canonical_and_bounded() {
    for (value, encoded) in [
        (0, vec![0x00]),
        (127, vec![0x7f]),
        (128, vec![0x80, 0x01]),
        (25565, vec![0xdd, 0xc7, 0x01]),
        (-1, vec![0xff, 0xff, 0xff, 0xff, 0x0f]),
    ] {
        let mut out = Vec::new();
        varint(&mut out, value);
        assert_eq!(out, encoded);
        assert_eq!(varint_size(value), encoded.len());
        assert_eq!(
            decode_varint(&encoded).unwrap(),
            Some((value, encoded.len()))
        );
        // Every proper prefix asks for more.
        for end in 0..encoded.len() {
            assert_eq!(decode_varint(&encoded[..end]).unwrap(), None);
        }
    }
    assert!(decode_varint(&[0x80, 0x00]).is_err(), "non-canonical");
    assert!(decode_varint(&[0xff, 0xff, 0xff, 0xff, 0x1f]).is_err());
}

#[test]
fn frames_carry_the_id_and_the_data() {
    let frame = frame(0x02, b"data").unwrap();
    assert_eq!(frame, [5, 2, b'd', b'a', b't', b'a']);
    assert_eq!(frame_length(&frame).unwrap(), Some((5, 1)));
    assert_eq!(decode_body(&frame[1..]).unwrap(), (2, &b"data"[..]));
    assert!(super::frame(0, &vec![0; MAX_DATA + 1]).is_err());
    // A body at the limit may still hold too much data after a short ID.
    assert!(decode_body(&vec![0; MAX_BODY]).is_err());
    assert!(decode_body(&[]).is_err());
    assert!(frame_length(&[0]).is_err());
    let mut over = Vec::new();
    varint(&mut over, MAX_BODY as i32 + 1);
    assert!(frame_length(&over).is_err());
}

#[test]
fn fields_read_as_go_reads_them() {
    let mut data = Vec::new();
    string(&mut data, "xmc:data");
    data.push(0xff);
    let mut fields = Fields(&data);
    assert_eq!(fields.string().unwrap(), b"xmc:data");
    assert_eq!(fields.rest(), [0xff]);

    // Go's `String` takes bytes that are not UTF-8.
    assert_eq!(Fields(&[2, 0xff, 0xfe]).string().unwrap(), [0xff, 0xfe]);
    let mut long = Vec::new();
    varint(&mut long, 4097);
    assert!(Fields(&long).string().is_err());
    let mut size = Vec::new();
    varint(&mut size, 1024);
    assert!(Fields(&size).bytes().is_err());
    assert!(Fields(&[2]).boolean().is_err());
    assert!(Fields(&[1, 2, 3]).long().is_err());
    assert_eq!(Fields(&[0, 0, 0, 0, 0, 0, 1, 2]).long().unwrap(), 258);
}

#[tokio::test]
async fn the_cipher_applies_from_where_it_turns_on() {
    let secret = [7u8; 16];
    let mut encrypted = b"after".to_vec();
    Cfb8::new(&secret, false).apply(&mut encrypted);
    let wire = [&b"plain"[..], &encrypted, &b"!"[..]].concat();
    let (mut ours, mut theirs) = tokio::io::duplex(64);
    theirs.write_all(&wire).await.unwrap();
    let mut conn = Conn::new(&mut ours);
    let mut plain = [0u8; 5];
    conn.read_exact(&mut plain).await.unwrap();
    assert_eq!(&plain, b"plain");
    conn.read_cipher = Some(Cfb8::new(&secret, true));
    let mut after = [0u8; 5];
    conn.read_exact(&mut after).await.unwrap();
    assert_eq!(&after, b"after");
    // The rest comes out of the buffer decrypted.
    let (_, rest, _, _) = conn.into_parts();
    let mut expected = encrypted.clone();
    expected.push(b'!');
    let mut cipher = Cfb8::new(&secret, true);
    cipher.apply(&mut expected);
    assert_eq!(rest, expected[5..]);
}
