use std::time::{Duration, Instant};
use xray_proxy::hysteria::*;

fn message(payload: &[u8]) -> UdpMessage<'_> {
    UdpMessage {
        session_id: 7,
        packet_id: 9,
        fragment_id: 0,
        fragment_count: 1,
        address: "host:53",
        payload,
    }
}

#[test]
fn tcp_decoders_reject_every_truncation_and_leave_following_data() {
    let request = TcpRequest {
        address: "[2001:db8::1]:443",
        padding: &[0; 300],
    };
    let wire = encode_tcp_request(&request).unwrap();
    for length in 0..wire.len() {
        assert_eq!(
            decode_tcp_request(&wire[..length]),
            Err(WireError::Incomplete)
        );
    }
    assert_eq!(decode_tcp_request(&wire).unwrap(), (request, wire.len()));
    let response = TcpResponse {
        status: 0,
        message: b"ok",
        padding: &[0; 130],
    };
    let wire = encode_tcp_response(&response).unwrap();
    for length in 0..wire.len() {
        assert_eq!(
            decode_tcp_response(&wire[..length]),
            Err(WireError::Incomplete)
        );
    }
    let mut combined = wire.clone();
    combined.extend_from_slice(b"payload");
    assert_eq!(
        decode_tcp_response(&combined).unwrap(),
        (response, wire.len())
    );
}

#[test]
fn quic_varints_accept_all_legal_widths_and_bound_lengths_before_payload() {
    // Non-minimal 8-byte stream type and address length; 4-byte padding length.
    let wire = [
        0xc0, 0, 0, 0, 0, 0, 4, 1, 0xc0, 0, 0, 0, 0, 0, 0, 3, b'x', b':', b'1', 0x80, 0, 0, 0,
    ];
    assert_eq!(decode_tcp_request(&wire).unwrap().0.address, "x:1");
    assert_eq!(
        decode_tcp_request(&[0x44, 1, 0xff, 255, 255, 255, 255, 255, 255, 255]),
        Err(WireError::Address)
    );
    assert_eq!(
        decode_tcp_response(&[0, 0xff, 255, 255, 255, 255, 255, 255, 255]),
        Err(WireError::MessageTooLong)
    );
    assert_eq!(
        decode_tcp_response(&[0, 0, 0xff, 255, 255, 255, 255, 255, 255, 255]),
        Err(WireError::PaddingTooLong)
    );
    assert_eq!(decode_tcp_request(&[0]), Err(WireError::FrameType));
}

#[test]
fn encoder_and_decoder_enforce_boundary_lengths() {
    let address = "a".repeat(MAX_ADDRESS_LENGTH);
    let padding = vec![0; MAX_PADDING_LENGTH];
    let request = TcpRequest {
        address: &address,
        padding: &padding,
    };
    assert!(decode_tcp_request(&encode_tcp_request(&request).unwrap()).is_ok());
    assert_eq!(
        encode_tcp_request(&TcpRequest {
            address: "",
            ..request
        }),
        Err(WireError::Address)
    );
    assert_eq!(
        encode_tcp_request(&TcpRequest {
            address: &"a".repeat(MAX_ADDRESS_LENGTH + 1),
            ..request
        }),
        Err(WireError::Address)
    );
    assert_eq!(
        encode_tcp_request(&TcpRequest {
            padding: &vec![0; MAX_PADDING_LENGTH + 1],
            ..request
        }),
        Err(WireError::PaddingTooLong)
    );
    let response = TcpResponse {
        status: 255,
        message: &vec![0; MAX_MESSAGE_LENGTH],
        padding: &padding,
    };
    let wire = encode_tcp_response(&response).unwrap();
    assert_eq!(decode_tcp_response(&wire).unwrap().0.status, 255);
    assert_eq!(
        encode_tcp_response(&TcpResponse {
            message: &vec![0; MAX_MESSAGE_LENGTH + 1],
            ..response
        }),
        Err(WireError::MessageTooLong)
    );
    // Invalid UTF-8 addresses fail; response messages remain opaque bytes.
    assert_eq!(
        decode_tcp_request(&[0x44, 1, 1, 255, 0]),
        Err(WireError::Address)
    );
    assert_eq!(
        decode_tcp_response(&[0, 1, 255, 0]).unwrap().0.message,
        &[255]
    );
}

#[test]
fn udp_metadata_and_empty_payload_follow_the_selected_contract() {
    let valid = message(b"hello");
    let wire = encode_udp_message(&valid).unwrap();
    for length in 0..valid.header_length() + 1 {
        assert!(decode_udp_message(&wire[..length]).is_err());
    }
    assert_eq!(
        encode_udp_message(&message(b"")),
        Err(WireError::PayloadLength)
    );
    assert_eq!(
        encode_udp_message(&UdpMessage {
            fragment_count: 0,
            ..valid
        }),
        Err(WireError::Fragment)
    );
    assert_eq!(
        encode_udp_message(&UdpMessage {
            fragment_count: 2,
            fragment_id: 2,
            ..valid
        }),
        Err(WireError::Fragment)
    );
    // Per Hysteria specification, fragment ID is irrelevant when count == 1.
    let standalone = UdpMessage {
        fragment_id: 255,
        packet_id: 65535,
        ..valid
    };
    assert_eq!(
        decode_udp_message(&encode_udp_message(&standalone).unwrap()).unwrap(),
        standalone
    );
    assert_eq!(
        encode_udp_message(&message(&vec![0; MAX_UDP_PAYLOAD + 1])),
        Err(WireError::PayloadLength)
    );
}

#[test]
fn fragmentation_checks_mtu_and_u8_count_without_overflow() {
    let payload = vec![7; 255];
    let full = message(&payload);
    let header = full.header_length();
    assert_eq!(
        fragment_udp_message(&full, header),
        Err(WireError::DatagramLimit)
    );
    assert_eq!(
        fragment_udp_message(&full, 0),
        Err(WireError::DatagramLimit)
    );
    let fragments = fragment_udp_message(&full, header + 1).unwrap();
    assert_eq!(fragments.len(), 255);
    assert_eq!(fragments[254].fragment_id, 254);
    assert_eq!(fragments[254].fragment_count, 255);
    let bigger = vec![7; 256];
    assert_eq!(
        fragment_udp_message(&message(&bigger), header + 1),
        Err(WireError::DatagramLimit)
    );
    assert_eq!(
        fragment_udp_message(&fragments[0], 1200),
        Err(WireError::Fragment)
    );
    let one = fragment_udp_message(&full, usize::MAX).unwrap();
    assert_eq!(one.len(), 1);
}

#[test]
fn reassembly_out_of_order_duplicates_and_completion_release_state() {
    let full = message(b"abcdefghijk");
    let fragments = fragment_udp_message(&full, full.header_length() + 4).unwrap();
    let mut assembler = Reassembler::new(7, 12, Duration::from_secs(5)).unwrap();
    let now = Instant::now();
    assert!(assembler.feed(&fragments[2], now).unwrap().is_none());
    assert!(assembler.feed(&fragments[0], now).unwrap().is_none());
    assert!(assembler.feed(&fragments[0], now).unwrap().is_none());
    assert_eq!(assembler.buffered_payload_bytes(), 7);
    let complete = assembler.feed(&fragments[1], now).unwrap().unwrap();
    assert_eq!(complete.payload, full.payload);
    assert_eq!(assembler.buffered_payload_bytes(), 0);
}

#[test]
fn reassembly_rejects_cross_session_and_conflicting_fragments() {
    let full = message(b"abcdefgh");
    let fragments = fragment_udp_message(&full, full.header_length() + 4).unwrap();
    let now = Instant::now();
    let mut assembler = Reassembler::new(7, 12, Duration::from_secs(5)).unwrap();
    assembler.feed(&fragments[0], now).unwrap();
    assert_eq!(
        assembler.feed(
            &UdpMessage {
                session_id: 8,
                ..fragments[1]
            },
            now
        ),
        Err(ReassemblyError::Session)
    );
    assert_eq!(assembler.buffered_payload_bytes(), 4);
    assert_eq!(
        assembler.feed(
            &UdpMessage {
                address: "different:53",
                ..fragments[1]
            },
            now
        ),
        Err(ReassemblyError::Conflict)
    );
    assert_eq!(assembler.buffered_payload_bytes(), 0);
    assembler.feed(&fragments[0], now).unwrap();
    assert_eq!(
        assembler.feed(
            &UdpMessage {
                fragment_count: 3,
                ..fragments[1]
            },
            now
        ),
        Err(ReassemblyError::Conflict)
    );
    assembler.feed(&fragments[0], now).unwrap();
    assert_eq!(
        assembler.feed(
            &UdpMessage {
                payload: b"xxxx",
                ..fragments[0]
            },
            now
        ),
        Err(ReassemblyError::Conflict)
    );
    assert_eq!(assembler.buffered_payload_bytes(), 0);
}

#[test]
fn reassembly_has_a_hard_byte_budget_and_non_refreshing_deadline() {
    let full = message(b"abcdefgh");
    let fragments = fragment_udp_message(&full, full.header_length() + 4).unwrap();
    let now = Instant::now();
    let mut assembler = Reassembler::new(7, 7, Duration::from_secs(5)).unwrap();
    assembler.feed(&fragments[0], now).unwrap();
    assert_eq!(
        assembler.feed(&fragments[1], now),
        Err(ReassemblyError::Budget)
    );
    assert_eq!(assembler.buffered_payload_bytes(), 0);
    assembler.feed(&fragments[0], now).unwrap();
    assembler
        .feed(&fragments[0], now + Duration::from_secs(4))
        .unwrap();
    assembler.expire(now + Duration::from_secs(5));
    assert_eq!(assembler.buffered_payload_bytes(), 0);
    assert!(assembler
        .feed(&fragments[1], now + Duration::from_secs(5))
        .unwrap()
        .is_none());
    assembler.clear();
    assert_eq!(assembler.buffered_payload_bytes(), 0);
    assert_eq!(assembler.feed(&full, now), Err(ReassemblyError::Budget));
}

#[test]
fn new_packet_id_discards_incomplete_packet_and_limits_are_validated() {
    let full = message(b"abcdefgh");
    let fragments = fragment_udp_message(&full, full.header_length() + 4).unwrap();
    let now = Instant::now();
    let mut assembler = Reassembler::new(7, 8, Duration::from_secs(1)).unwrap();
    assembler.feed(&fragments[0], now).unwrap();
    assert!(assembler
        .feed(
            &UdpMessage {
                packet_id: 10,
                ..fragments[1]
            },
            now
        )
        .unwrap()
        .is_none());
    let complete = assembler
        .feed(
            &UdpMessage {
                packet_id: 10,
                ..fragments[0]
            },
            now,
        )
        .unwrap()
        .unwrap();
    assert_eq!(complete.payload, full.payload);
    assert!(Reassembler::new(7, 0, Duration::from_secs(1)).is_err());
    assert!(Reassembler::new(7, MAX_UDP_PAYLOAD + 1, Duration::from_secs(1)).is_err());
    assert!(Reassembler::new(7, 1, Duration::ZERO).is_err());
}

#[test]
fn debug_omits_traffic_and_server_messages() {
    let marker = "sensitive-marker";
    let request = TcpRequest {
        address: marker,
        padding: marker.as_bytes(),
    };
    let response = TcpResponse {
        status: 1,
        message: marker.as_bytes(),
        padding: marker.as_bytes(),
    };
    let udp = message(marker.as_bytes());
    let complete = ReassembledDatagram {
        session_id: 7,
        address: marker.into(),
        payload: marker.as_bytes().into(),
    };
    for debug in [
        format!("{request:?}"),
        format!("{response:?}"),
        format!("{udp:?}"),
        format!("{complete:?}"),
    ] {
        assert!(!debug.contains(marker));
    }
}
