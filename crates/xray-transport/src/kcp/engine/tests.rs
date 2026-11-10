use super::*;
use crate::kcp::segment::{read_segments, CMD_ACK, CMD_DATA};

fn config() -> Config {
    Config {
        mtu: 1350,
        tti: 50,
        uplink_capacity: 5,
        downlink_capacity: 20,
        cwnd_multiplier: 1,
        max_sending_window: 2 * 1024 * 1024,
    }
}

fn pair() -> (Engine, Engine) {
    (Engine::new(7, config()), Engine::new(7, config()))
}

/// Hands every queued datagram of `from` to `to`; returns their segments.
fn deliver(from: &mut Engine, to: &mut Engine, current: u32) -> Vec<Segment> {
    let mut all = Vec::new();
    for datagram in std::mem::take(&mut from.out) {
        let segments = read_segments(&datagram);
        all.extend(segments.iter().cloned());
        to.input(segments, current);
    }
    all
}

fn drop_out(engine: &mut Engine) -> Vec<Segment> {
    std::mem::take(&mut engine.out)
        .iter()
        .flat_map(|datagram| read_segments(datagram))
        .collect()
}

fn read_all(engine: &mut Engine) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0; 4096];
    loop {
        match engine.read(&mut buf)? {
            0 => return Some(data),
            count => data.extend_from_slice(&buf[..count]),
        }
    }
}

fn data_numbers(segments: &[Segment]) -> Vec<u32> {
    segments
        .iter()
        .filter_map(|segment| match segment {
            Segment::Data(data) => Some(data.number),
            _ => None,
        })
        .collect()
}

fn commands(segments: &[Segment]) -> Vec<u8> {
    segments
        .iter()
        .map(|segment| match segment {
            Segment::Data(_) => CMD_DATA,
            Segment::Ack(_) => CMD_ACK,
            Segment::Cmd(cmd) => cmd.cmd,
        })
        .collect()
}

#[test]
fn sizes_follow_the_config_as_xray_computes_them() {
    let config = config();
    // 5 MiB/s in 1350-byte segments over 20 flushes a second.
    assert_eq!(config.sending_in_flight_size(), 194);
    assert_eq!(config.receiving_in_flight_size(), 776);
    assert_eq!(config.sending_buffer_size(), 1553);
    // Never below 8, and the capacity multiplies as a Go uint32 does.
    let small = Config {
        uplink_capacity: 0,
        downlink_capacity: 4096,
        ..config
    };
    assert_eq!(small.sending_in_flight_size(), 8);
    assert_eq!(small.receiving_in_flight_size(), 8);
    let tti_1000 = Config {
        tti: 1000,
        ..config
    };
    assert_eq!(tti_1000.sending_in_flight_size(), 3883);
}

#[test]
fn data_arrives_in_order_and_is_acknowledged() {
    let (mut client, mut server) = pair();
    let message: Vec<u8> = (0..3000).map(|i| i as u8).collect();
    assert_eq!(client.write(&message), Ok(3000));
    assert!(client.wake_data);
    client.flush(0);
    let sent = deliver(&mut client, &mut server, 0);
    // 1332 bytes a segment: mtu less the 18-byte header.
    let sizes: Vec<usize> = sent
        .iter()
        .filter_map(|segment| match segment {
            Segment::Data(data) => Some(data.payload.len()),
            _ => None,
        })
        .collect();
    assert_eq!(sizes, [1332, 1332, 336]);
    assert!(server.input_ready);
    assert_eq!(read_all(&mut server), Some(message));
    server.flush(10);
    let acks = deliver(&mut server, &mut client, 10);
    assert_eq!(commands(&acks), [CMD_ACK]);
    let Segment::Ack(ack) = &acks[0] else {
        unreachable!()
    };
    assert_eq!(ack.numbers, [0, 1, 2]);
    assert_eq!(ack.receiving_next, 3);
    assert_eq!(ack.receiving_window, 3 + 776);
    assert!(client.sending.window.is_empty());
    assert_eq!(client.sending.first_unacknowledged, 3);
    assert!(client.output_ready);
}

#[test]
fn segments_out_of_order_wait_for_the_gap() {
    let (mut client, mut server) = pair();
    client.write(&[1; 2000]).unwrap();
    client.flush(0);
    let mut datagrams = std::mem::take(&mut client.out);
    datagrams.swap(0, 1);
    server.input(read_segments(&datagrams[0]), 0);
    assert!(!server.input_ready);
    assert_eq!(read_all(&mut server), Some(Vec::new()));
    server.input(read_segments(&datagrams[1]), 0);
    assert!(server.input_ready);
    assert_eq!(read_all(&mut server).unwrap().len(), 2000);
}

#[test]
fn a_lost_segment_is_resent_after_the_rto() {
    let (mut client, mut server) = pair();
    client.write(b"hello").unwrap();
    client.flush(0);
    assert_eq!(data_numbers(&drop_out(&mut client)), [0]);
    // The initial rto is 100 ms.
    client.flush(99);
    assert_eq!(data_numbers(&drop_out(&mut client)), Vec::<u32>::new());
    client.flush(100);
    let resent = deliver(&mut client, &mut server, 100);
    assert_eq!(data_numbers(&resent), [0]);
    assert_eq!(client.sending.window[0].transmit, 2);
    assert_eq!(read_all(&mut server), Some(b"hello".to_vec()));
}

#[test]
fn the_round_trip_sets_the_rto_as_rfc_6298_does() {
    let (mut client, mut server) = pair();
    let exchange =
        |client: &mut Engine, server: &mut Engine, data: &[u8], sent: u32, acknowledged: u32| {
            client.write(data).unwrap();
            client.flush(sent);
            deliver(client, server, sent);
            server.flush(acknowledged);
            deliver(server, client, acknowledged);
        };
    // Xray's highest acknowledged number starts at zero, so the ack of
    // segment 0 alone never samples the round trip.
    exchange(&mut client, &mut server, b"x", 1000, 1100);
    assert_eq!(client.round_trip.srtt, 0);
    assert_eq!(client.round_trip.rto, 100);
    exchange(&mut client, &mut server, b"y", 2000, 2100);
    // srtt 100, variation 50, and min_rtt (tti, 50) below 4 * 50:
    // (100 + 200) * 5 / 4.
    assert_eq!(client.round_trip.srtt, 100);
    assert_eq!(client.round_trip.variation, 50);
    assert_eq!(client.round_trip.rto, 375);
    exchange(&mut client, &mut server, b"z", 3000, 3300);
    // variation (150 + 200) / 4, srtt (700 + 300) / 8, rto (125 + 348) * 5 / 4.
    assert_eq!(client.round_trip.variation, 87);
    assert_eq!(client.round_trip.srtt, 125);
    assert_eq!(client.round_trip.rto, 591);
}

#[test]
fn a_later_ack_brings_earlier_resends_forward() {
    let (mut client, mut server) = pair();
    client.write(&[0; 1332 * 3]).unwrap();
    client.flush(0);
    let datagrams = std::mem::take(&mut client.out);
    // Only segment 2 arrives.
    server.input(read_segments(&datagrams[2]), 0);
    server.flush(10);
    deliver(&mut server, &mut client, 10);
    // Segments 0 and 1 were due at 100; the ack of 2 took rto / 3 off.
    let timeouts: Vec<u32> = client
        .sending
        .window
        .iter()
        .map(|segment| segment.timeout)
        .collect();
    let rto = client.round_trip.rto;
    assert_eq!(timeouts, [100 - 100 / 3, 100 - 100 / 3]);
    assert_ne!(rto, 100, "the ack updated the rto");
}

#[test]
fn an_unanswered_ack_repeats_after_half_the_rto() {
    let (mut client, mut server) = pair();
    client.write(b"x").unwrap();
    client.flush(0);
    deliver(&mut client, &mut server, 0);
    server.flush(0);
    assert_eq!(commands(&drop_out(&mut server)), [CMD_ACK]);
    // With the initial rto of 100 ms the ack waits 50 ms for the sender to
    // move past it.
    server.flush(49);
    assert!(server.out.is_empty());
    // Half of 30 ms is below the 20 ms floor, which the next repeat waits.
    server.round_trip.rto = 30;
    server.flush(50);
    let again = drop_out(&mut server);
    let [Segment::Ack(ack)] = &again[..] else {
        panic!("{again:?}")
    };
    assert_eq!(ack.numbers, [0]);
    server.flush(69);
    assert!(server.out.is_empty());
    server.flush(70);
    assert_eq!(commands(&drop_out(&mut server)), [CMD_ACK]);
}

#[test]
fn a_full_window_refuses_writes_until_acks_arrive() {
    let config = Config {
        max_sending_window: 1350 * 2,
        ..config()
    };
    let mut client = Engine::new(7, config);
    let mut server = Engine::new(7, config);
    assert_eq!(client.sending.window_size, 2);
    // Xray takes one segment past the window size.
    assert_eq!(client.write(&[0; 1332 * 4]), Ok(1332 * 3));
    assert_eq!(client.write(&[0; 10]), Err(WriteBlocked::Full));
    client.flush(0);
    deliver(&mut client, &mut server, 0);
    server.flush(10);
    deliver(&mut server, &mut client, 10);
    assert_eq!(client.write(&[0; 10]), Ok(10));
}

#[test]
fn the_peer_window_and_the_control_window_bound_a_flush() {
    let (mut client, _) = pair();
    // Nothing is known of the peer yet: 32 segments.
    client.write(&vec![0; 1332 * 40]).unwrap();
    client.flush(0);
    assert_eq!(data_numbers(&drop_out(&mut client)).len(), 32);
    let config = Config {
        cwnd_multiplier: 2,
        ..config()
    };
    let mut client = Engine::new(7, config);
    client.write(&vec![0; 1332 * 80]).unwrap();
    client.flush(0);
    assert_eq!(data_numbers(&drop_out(&mut client)).len(), 64);
}

#[test]
fn heavy_loss_shrinks_the_control_window() {
    let (mut client, _) = pair();
    client.sending.remote_next_number = 10_000;
    client.write(&vec![0; 1332 * 300]).unwrap();
    client.flush(0);
    assert_eq!(data_numbers(&drop_out(&mut client)).len(), 194);
    // Nothing acknowledged: every segment due again is a loss.
    client.flush(100);
    drop_out(&mut client);
    assert_eq!(client.sending.control_window, 194 * 3 / 4);
}

#[test]
fn segments_beyond_the_receive_window_are_neither_kept_nor_acknowledged() {
    let (_, mut server) = pair();
    let far = DataSegment {
        conv: 7,
        option: 0,
        timestamp: 0,
        number: 776,
        sending_next: 0,
        payload: b"late".to_vec(),
    };
    server.input(vec![Segment::Data(far.clone())], 0);
    assert!(server.receiving.window.is_empty());
    assert!(server.receiving.acks.numbers.is_empty());
    let near = DataSegment { number: 775, ..far };
    server.input(vec![Segment::Data(near)], 0);
    assert_eq!(server.receiving.acks.numbers, [775]);
}

#[test]
fn a_duplicate_is_acknowledged_again_and_read_once() {
    let (mut client, mut server) = pair();
    client.write(b"once").unwrap();
    client.flush(0);
    let datagram = std::mem::take(&mut client.out).remove(0);
    server.input(read_segments(&datagram), 0);
    server.flush(0);
    assert_ne!(server.receiving.acks.next_flush, [0], "the ack went out");
    // Listed once and due again at once, however often the peer repeats it:
    // Xray lists it again each time.
    for _ in 0..100 {
        server.input(read_segments(&datagram), 0);
    }
    assert_eq!(server.receiving.acks.numbers, [0]);
    assert_eq!(server.receiving.acks.next_flush, [0]);
    assert_eq!(read_all(&mut server), Some(b"once".to_vec()));
}

#[test]
fn a_foreign_conversation_stops_the_rest_of_the_datagram() {
    let (mut client, mut server) = pair();
    client.write(b"a").unwrap();
    client.flush(0);
    let mine = read_segments(&std::mem::take(&mut client.out)[0]);
    let mut foreign = mine.clone();
    if let Segment::Data(data) = &mut foreign[0] {
        data.conv = 8;
    }
    server.input([foreign, mine].concat(), 0);
    assert_eq!(read_all(&mut server), Some(Vec::new()));
}

#[test]
fn pings_go_out_every_three_seconds_of_flushes() {
    let (mut client, _) = pair();
    client.flush(0);
    assert!(client.out.is_empty(), "nothing to send at first");
    client.flush(2999);
    assert!(client.out.is_empty());
    client.flush(3000);
    let pings = drop_out(&mut client);
    assert_eq!(commands(&pings), [CMD_PING]);
    let Segment::Cmd(ping) = &pings[0] else {
        unreachable!()
    };
    assert_eq!(
        (ping.conv, ping.option, ping.peer_rto),
        (7, 0, 100),
        "{ping:?}"
    );
}

#[test]
fn closing_drains_then_terminates() {
    let (mut client, mut server) = pair();
    client.write(b"last words").unwrap();
    assert!(client.close(0));
    assert!(!client.close(0), "a second close reports it closed already");
    assert_eq!(client.state(), State::ReadyToClose);
    assert_eq!(client.read(&mut [0; 16]), None);
    assert_eq!(client.write(b"more"), Err(WriteBlocked::Closed));
    client.flush(0);
    let sent = deliver(&mut client, &mut server, 0);
    // The data still goes, marked as closing, and the server stops sending.
    let Segment::Data(data) = &sent[0] else {
        panic!("{sent:?}")
    };
    assert_eq!(data.option, OPTION_CLOSE);
    assert_eq!(server.state(), State::PeerClosed);
    assert_eq!(read_all(&mut server), Some(b"last words".to_vec()));
    assert_eq!(server.write(b"reply"), Err(WriteBlocked::Closed));
    server.flush(10);
    deliver(&mut server, &mut client, 10);
    assert!(client.sending.window.is_empty());
    // Drained: the next flush terminates.
    client.flush(20);
    assert_eq!(client.state(), State::Terminating);
    let terminate = deliver(&mut client, &mut server, 20);
    assert_eq!(commands(&terminate), [CMD_TERMINATE]);
    assert_eq!(server.state(), State::PeerTerminating);
    assert_eq!(server.read(&mut [0; 16]), None);
    // The server closes: it is gone at once, without a word.
    assert!(server.close(30));
    assert_eq!(server.state(), State::Terminated);
    assert!(server.out.is_empty());
    // The client keeps saying terminate until eight seconds pass.
    client.flush(8020);
    assert_eq!(commands(&drop_out(&mut client)), [CMD_TERMINATE]);
    assert_eq!(client.state(), State::Terminating);
    client.flush(8021);
    assert_eq!(commands(&drop_out(&mut client)), [CMD_TERMINATE]);
    assert_eq!(client.state(), State::Terminated);
    client.flush(9000);
    assert!(client.out.is_empty());
}

#[test]
fn the_peer_terminating_reads_to_the_end_and_terminates_after_four_seconds() {
    let (mut client, mut server) = pair();
    server.write(b"reply").unwrap();
    server.flush(0);
    deliver(&mut server, &mut client, 0);
    client.input(
        vec![Segment::Cmd(CmdSegment {
            conv: 7,
            cmd: CMD_TERMINATE,
            option: 0,
            sending_next: 1,
            receiving_next: 0,
            peer_rto: 0,
        })],
        1,
    );
    assert_eq!(client.state(), State::PeerTerminating);
    assert!(client.input_ready);
    assert_eq!(client.write(b"late"), Err(WriteBlocked::Closed));
    let mut buf = [0; 16];
    assert_eq!(client.read(&mut buf), Some(5));
    assert_eq!(client.read(&mut buf), None);
    client.flush(4001);
    assert_eq!(client.state(), State::PeerTerminating);
    client.flush(4002);
    assert_eq!(client.state(), State::Terminating);
}

/// While it drains, every segment says it is closing: data, acks and pings.
#[test]
fn a_closing_side_marks_every_segment() {
    let (mut client, mut server) = pair();
    server.write(b"to acknowledge").unwrap();
    server.flush(0);
    deliver(&mut server, &mut client, 0);
    client.write(b"unacknowledged").unwrap();
    client.close(0);
    client.flush(3000);
    let sent = drop_out(&mut client);
    assert_eq!(commands(&sent), [CMD_ACK, CMD_DATA, CMD_PING]);
    for segment in &sent {
        let option = match segment {
            Segment::Data(data) => data.option,
            Segment::Ack(ack) => ack.option,
            Segment::Cmd(cmd) => cmd.option,
        };
        assert_eq!(option, OPTION_CLOSE, "{segment:?}");
    }
}

#[test]
fn an_unanswered_close_gives_up_after_fifteen_seconds() {
    let (mut client, _) = pair();
    client.write(b"never acknowledged").unwrap();
    client.close(0);
    client.flush(15_000);
    assert_eq!(client.state(), State::ReadyToClose);
    client.flush(15_001);
    assert_eq!(client.state(), State::Terminating);
}

#[test]
fn thirty_silent_seconds_close_the_connection() {
    let (mut client, mut server) = pair();
    server.flush(3000);
    deliver(&mut server, &mut client, 1000);
    client.flush(30_999);
    assert_eq!(client.state(), State::Active);
    client.flush(31_000);
    // Closed, and with nothing left to send, terminating at once.
    assert_eq!(client.state(), State::Terminating);
}

#[test]
fn a_terminating_peer_finishes_a_local_close() {
    let (mut client, _) = pair();
    client.close(0);
    client.input(
        vec![Segment::Cmd(CmdSegment {
            conv: 7,
            cmd: CMD_PING,
            option: OPTION_CLOSE,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        })],
        5,
    );
    assert_eq!(client.state(), State::Terminating);
    client.input(
        vec![Segment::Cmd(CmdSegment {
            conv: 7,
            cmd: CMD_TERMINATE,
            option: 0,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        })],
        6,
    );
    assert_eq!(client.state(), State::Terminated);
}

#[test]
fn a_terminate_during_a_local_close_starts_terminating() {
    let (mut client, _) = pair();
    client.write(b"unacknowledged").unwrap();
    client.close(0);
    client.input(
        vec![Segment::Cmd(CmdSegment {
            conv: 7,
            cmd: CMD_TERMINATE,
            option: 0,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        })],
        5,
    );
    assert_eq!(client.state(), State::Terminating);
    // Terminating, it sends terminate commands, not the data it held.
    client.flush(6);
    assert_eq!(commands(&drop_out(&mut client)), [CMD_TERMINATE]);
}

#[test]
fn the_peer_rto_is_taken_at_most_every_three_seconds() {
    let (mut client, _) = pair();
    let ping = |peer_rto| {
        vec![Segment::Cmd(CmdSegment {
            conv: 7,
            cmd: CMD_PING,
            option: 0,
            sending_next: 0,
            receiving_next: 0,
            peer_rto,
        })]
    };
    client.input(ping(500), 2999);
    assert_eq!(client.round_trip.rto, 100);
    client.input(ping(500), 3000);
    assert_eq!(client.round_trip.rto, 500);
    client.input(ping(700), 5999);
    assert_eq!(client.round_trip.rto, 500);
}

#[test]
fn the_data_updater_runs_while_data_or_acks_wait() {
    let (mut client, mut server) = pair();
    assert!(!client.data_update_necessary());
    client.write(b"x").unwrap();
    assert!(client.data_update_necessary());
    client.flush(0);
    deliver(&mut client, &mut server, 0);
    assert!(server.data_update_necessary(), "an ack waits");
    server.flush(1);
    deliver(&mut server, &mut client, 1);
    assert!(!client.data_update_necessary());
    // The ack stays listed until the sender's next segment moves past it.
    assert!(server.data_update_necessary());
    client.close(2);
    client.flush(3);
    assert!(client.data_update_terminated());
    assert!(!client.data_update_necessary());
}
