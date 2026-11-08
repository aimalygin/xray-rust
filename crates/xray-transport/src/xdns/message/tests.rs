use super::*;

fn domain() -> Domain {
    Domain::new(
        "t.example.com",
        255,
        63,
        &[TYPE_A, TYPE_CNAME, TYPE_TXT, TYPE_AAAA],
        0,
    )
    .unwrap()
}

/// A response to one question for `name` and `qtype` with `answers`, each
/// a name, a type and its wire body.
fn response(name: &[u8], qtype: u16, answers: &[(&[u8], u16, Vec<u8>)]) -> Vec<u8> {
    let query = query(0x1234, name, qtype, 0);
    let mut out = query[..12].to_vec();
    out[2] |= 0x80;
    out[7] = answers.len() as u8;
    out.extend_from_slice(&query[12..]);
    for (name, rtype, body) in answers {
        for label in name[..name.len() - 1].split(|&byte| byte == b'.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

#[test]
fn a_query_packs_its_name_and_edns() {
    let packed = query(0xABCD, b"me.t.example.com.", TYPE_TXT, 1232);
    assert_eq!(
        packed,
        [
            &[0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1][..],
            b"\x02me\x01t\x07example\x03com\x00",
            &[0, 16, 0, 1],
            &[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0],
        ]
        .concat()
    );
    assert_eq!(
        question(&packed),
        Some((b"me.t.example.com.".to_vec(), TYPE_TXT, Some(1232)))
    );
}

#[test]
fn txt_answers_join_their_strings() {
    let data = frame(&[b"one", &[7; 300]]);
    let query = query(1, b"me.t.example.com.", TYPE_TXT, 0);
    match read(&txt_answer(&query, &data), &[domain()]) {
        Read::Answer { decoded, packets } => {
            assert_eq!(decoded, data);
            assert_eq!(packets, vec![b"one".to_vec(), vec![7; 300]]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn address_fragments_are_sorted_by_index() {
    let name = b"me.t.example.com.";
    let answers = [
        (&name[..], TYPE_A, vec![2, 0xBB, 0, 0]),
        (&name[..], TYPE_A, vec![0, 3, 0xC0, 0x02]),
        (&name[..], TYPE_A, vec![1, 0xAA, 9, 9]),
    ];
    assert_eq!(
        read(&response(name, TYPE_A, &answers), &[domain()]),
        Read::Answer {
            decoded: vec![0xC0, 0x02, 0xAA, 9, 9, 0xBB, 0, 0],
            packets: vec![vec![0xAA, 9]],
        }
    );
}

#[test]
fn names_follow_pointers_but_not_too_many() {
    // Eleven pointers in a chain, each to the one before.
    let mut msg = vec![0u8; 12];
    msg[4..6].copy_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(b"\x01a\x00");
    let mut target = 12;
    for _ in 0..11 {
        let here = msg.len();
        msg.extend_from_slice(&(0xC000 | target as u16).to_be_bytes());
        target = here;
    }
    // The tenth pointer leads through ten, the eleventh through eleven.
    let ten = unpack_name(&msg, msg.len() - 4).unwrap();
    assert_eq!(ten, (b"a.".to_vec(), msg.len() - 2));
    assert_eq!(unpack_name(&msg, msg.len() - 2), None);
}

#[test]
fn names_stop_short_of_254_bytes() {
    let mut msg = Vec::new();
    for _ in 0..3 {
        msg.push(63);
        msg.extend_from_slice(&[b'a'; 63]);
    }
    msg.push(61);
    msg.extend_from_slice(&[b'a'; 61]);
    msg.push(0);
    assert_eq!(unpack_name(&msg, 0).unwrap().0.len(), 254);
    msg[3 * 64] = 62;
    msg.insert(3 * 64 + 1, b'a');
    assert_eq!(unpack_name(&msg, 0), None);
}

#[test]
fn svcb_keys_must_increase_and_fill_the_record() {
    let body = |params: &[u8]| [&[0, 1][..], &[0], params].concat();
    let ok = body(&[0, 1, 0, 1, 7, 0, 3, 0, 0]);
    assert!(unpack_svcb(&ok, 0, ok.len()).is_some());
    let unordered = body(&[0, 3, 0, 0, 0, 1, 0, 0]);
    assert!(unpack_svcb(&unordered, 0, unordered.len()).is_none());
    assert!(unpack_svcb(&ok, 0, ok.len() - 1).is_none());
    assert!(unpack_svcb(&ok, 0, ok.len() + 1).is_none());
}

#[test]
fn a_last_record_may_claim_more_than_the_message_holds() {
    let name = b"me.t.example.com.";
    let mut msg = response(name, TYPE_A, &[(&name[..], TYPE_A, vec![0, 1, 0xC0, 0])]);
    let length = msg.len() - 6;
    msg[length..length + 2].copy_from_slice(&100u16.to_be_bytes());
    assert_eq!(
        read(&msg, &[domain()]),
        Read::Answer {
            decoded: vec![0xC0, 0],
            packets: vec![vec![]],
        }
    );
}
