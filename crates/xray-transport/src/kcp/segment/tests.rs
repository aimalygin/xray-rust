use super::*;

fn encoded(segment: &Segment) -> Vec<u8> {
    let mut out = Vec::new();
    segment.encode(&mut out);
    out
}

#[test]
fn every_kind_encodes_big_endian_after_conv_command_and_option() {
    let data = Segment::Data(DataSegment {
        conv: 0x0102,
        option: OPTION_CLOSE,
        timestamp: 0x0304_0506,
        number: 0x0708_090a,
        sending_next: 0x0b0c_0d0e,
        payload: b"hi".to_vec(),
    });
    assert_eq!(
        encoded(&data),
        [1, 2, 1, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 2, b'h', b'i']
    );
    let mut ack = AckSegment::new(128);
    ack.conv = 0x0102;
    ack.receiving_window = 0x10;
    ack.receiving_next = 0x20;
    ack.timestamp = 0x30;
    ack.numbers = vec![5, 0x0102_0304];
    let ack = Segment::Ack(ack);
    assert_eq!(
        encoded(&ack),
        [1, 2, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0x20, 0, 0, 0, 0x30, 2, 0, 0, 0, 5, 1, 2, 3, 4]
    );
    let ping = Segment::Cmd(CmdSegment {
        conv: 0x0102,
        cmd: CMD_PING,
        option: 0,
        sending_next: 1,
        receiving_next: 2,
        peer_rto: 3,
    });
    assert_eq!(
        encoded(&ping),
        [1, 2, 3, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]
    );
    let all = [encoded(&data), encoded(&ack), encoded(&ping)].concat();
    assert_eq!(read_segments(&all), [data, ack, ping]);
}

#[test]
fn reading_stops_at_the_first_segment_that_does_not_parse() {
    let ping = Segment::Cmd(CmdSegment {
        conv: 9,
        cmd: CMD_TERMINATE,
        option: 0,
        sending_next: 0,
        receiving_next: 0,
        peer_rto: 0,
    });
    // A truncated segment after a whole one is dropped with what follows.
    let mut datagram = encoded(&ping);
    datagram.extend_from_slice(&[0, 9, CMD_PING, 0, 1, 2, 3]);
    assert_eq!(read_segments(&datagram), std::slice::from_ref(&ping));
    // Fewer than four bytes end it too.
    assert_eq!(read_segments(&[0, 9, 3]), []);
    // Any command but data and ack reads as a command segment.
    let mut odd = encoded(&ping);
    odd[2] = 200;
    assert!(matches!(&read_segments(&odd)[..], [Segment::Cmd(cmd)] if cmd.cmd == 200));
}

#[test]
fn an_empty_data_segment_needs_a_byte_after_it() {
    let empty = Segment::Data(DataSegment {
        conv: 1,
        option: 0,
        timestamp: 0,
        number: 0,
        sending_next: 0,
        payload: Vec::new(),
    });
    let alone = encoded(&empty);
    assert_eq!(alone.len(), 18);
    assert_eq!(read_segments(&alone), []);
    let mut followed = alone.clone();
    followed.push(0);
    assert_eq!(read_segments(&followed), [empty]);
    // A length past the datagram does not parse either.
    let mut short = encoded(&Segment::Data(DataSegment {
        conv: 1,
        option: 0,
        timestamp: 0,
        number: 0,
        sending_next: 0,
        payload: b"abc".to_vec(),
    }));
    short.pop();
    assert_eq!(read_segments(&short), []);
}

#[test]
fn an_ack_reads_every_number_its_count_names() {
    let mut datagram = vec![0, 1, CMD_ACK, 0];
    datagram.extend_from_slice(&[0; 12]);
    datagram.push(200);
    datagram.extend((0..200u32).flat_map(u32::to_be_bytes));
    let [Segment::Ack(ack)] = &read_segments(&datagram)[..] else {
        panic!("not one ack");
    };
    assert_eq!(ack.numbers.len(), 200);
    datagram.truncate(datagram.len() - 1);
    assert_eq!(read_segments(&datagram), []);
}

#[test]
fn an_ack_holds_between_one_and_128_numbers() {
    assert_eq!(AckSegment::new(0).limit, 1);
    assert_eq!(AckSegment::new(-5).limit, 1);
    assert_eq!(AckSegment::new(333).limit, 128);
    // (1350 - 17) / 4
    assert_eq!(AckSegment::new(333).limit, 128);
    assert_eq!(AckSegment::new(1).limit, 1);
}

#[test]
fn an_ack_keeps_the_later_timestamp() {
    let mut ack = AckSegment::new(10);
    ack.put_timestamp(100);
    ack.put_timestamp(50);
    assert_eq!(ack.timestamp, 100);
    ack.put_timestamp(u32::MAX);
    assert_eq!(
        ack.timestamp, 100,
        "u32::MAX is earlier than 100 when wrapping"
    );
    ack.put_timestamp(0x8000_0063);
    assert_eq!(
        ack.timestamp, 100,
        "exactly half the circle away is not later"
    );
    ack.put_timestamp(0x8000_0062);
    assert_eq!(ack.timestamp, 0x8000_0062);
}
