mod stream_websocket_tests {
    use xray_transport::stream::{
        encode_client_frames, FrameDecoder, FrameEvent, MAX_FRAME_PAYLOAD,
    };

    fn unmask(payload: &mut [u8], key: [u8; 4]) {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }

    /// Builds a server-to-client frame: never masked, which is what the RFC
    /// requires of a server and what the decoder insists on.
    fn server_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
        let length = payload.len();
        if length < 126 {
            out.push(length as u8);
        } else if let Ok(length) = u16::try_from(length) {
            out.push(126);
            out.extend_from_slice(&length.to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn a_small_write_is_one_masked_binary_frame() {
        let frames = encode_client_frames(b"hello");

        assert_eq!(frames[0], 0x82, "FIN set, opcode 0x2 (binary)");
        assert_eq!(frames[1], 0x80 | 5, "mask bit set, 5-byte payload");

        let key = [frames[2], frames[3], frames[4], frames[5]];
        let mut payload = frames[6..].to_vec();
        unmask(&mut payload, key);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn an_eight_kib_write_becomes_two_fragments_of_4096() {
        let payload = vec![0x41u8; 8192];
        let frames = encode_client_frames(&payload);

        // First fragment: FIN clear, opcode binary, 126 -> 16-bit length.
        assert_eq!(frames[0], 0x02, "FIN clear on the first fragment");
        assert_eq!(frames[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([frames[2], frames[3]]), 4096);

        let second = 4 + 4 + 4096;
        assert_eq!(frames[second], 0x80, "FIN set, opcode 0x0 (continuation)");
        assert_eq!(frames[second + 1], 0x80 | 126);
        assert_eq!(
            u16::from_be_bytes([frames[second + 2], frames[second + 3]]),
            4096
        );
        assert_eq!(frames.len(), second + 4 + 4 + 4096);
    }

    #[test]
    fn the_fragment_size_matches_gorillas_write_buffer() {
        assert_eq!(MAX_FRAME_PAYLOAD, 4096);
    }

    #[test]
    fn each_frame_gets_a_fresh_mask_key() {
        let first = encode_client_frames(b"same");
        let second = encode_client_frames(b"same");

        assert_ne!(
            &first[2..6],
            &second[2..6],
            "a reused mask key would be a distinguishing signal"
        );
    }

    #[test]
    fn an_empty_write_still_produces_one_frame() {
        // gorilla's WriteMessage sends an empty binary message rather than
        // nothing at all, and the boundary is observable.
        let frames = encode_client_frames(b"");

        assert_eq!(frames[0], 0x82);
        assert_eq!(frames[1], 0x80, "mask bit set, zero-length payload");
        assert_eq!(frames.len(), 6, "header plus the mask key, no payload");
    }

    #[test]
    fn message_boundaries_do_not_reach_the_layer_above() {
        // To the VLESS layer this is a byte stream: two messages, a
        // fragmented one, and an empty one all read as one run of bytes.
        let mut decoder = FrameDecoder::new();
        let mut wire = server_frame(0x2, true, b"one");
        wire.extend(server_frame(0x2, false, b"two"));
        wire.extend(server_frame(0x0, true, b"three"));
        wire.extend(server_frame(0x2, true, b""));
        wire.extend(server_frame(0x1, true, b"four"));
        decoder.extend(&wire);

        let mut payload = Vec::new();
        while let Some(event) = decoder.next_event().expect("the frames must decode") {
            match event {
                FrameEvent::Payload(bytes) => payload.extend_from_slice(&bytes),
                other => panic!("unexpected {other:?}"),
            }
        }

        assert_eq!(payload, b"onetwothreefour");
    }

    #[test]
    fn a_ping_asks_for_a_pong_echoing_its_payload() {
        let mut decoder = FrameDecoder::new();
        decoder.extend(&server_frame(0x9, true, b"ping-payload"));

        let event = decoder
            .next_event()
            .expect("the ping must decode")
            .expect("a ping produces an event");

        match event {
            FrameEvent::Pong(payload) => assert_eq!(payload, b"ping-payload"),
            other => panic!("a ping must ask for a pong, got {other:?}"),
        }
    }

    #[test]
    fn a_pong_is_ignored_and_a_close_ends_the_stream() {
        let mut decoder = FrameDecoder::new();
        let mut wire = server_frame(0xa, true, b"unsolicited");
        wire.extend(server_frame(0x8, true, &1000u16.to_be_bytes()));
        decoder.extend(&wire);

        assert!(matches!(
            decoder
                .next_event()
                .expect("the frames must decode")
                .expect("close is an event"),
            FrameEvent::Close
        ));
    }

    #[test]
    fn a_masked_frame_from_the_server_is_a_protocol_error() {
        // RFC 6455 forbids it, and accepting one would mean a server could
        // hand us payload our unmasking would silently corrupt.
        let mut decoder = FrameDecoder::new();
        decoder.extend(&[0x82, 0x80 | 3, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00]);

        decoder
            .next_event()
            .expect_err("a masked server frame must be refused");
    }

    #[test]
    fn a_reserved_bit_is_a_protocol_error() {
        // No extension was negotiated, so RSV1 set means the peer is speaking
        // a protocol we did not agree to.
        let mut decoder = FrameDecoder::new();
        decoder.extend(&[0x40 | 0x82, 0x03, b'a', b'b', b'c']);

        decoder
            .next_event()
            .expect_err("a reserved bit must be refused");
    }

    #[test]
    fn a_frame_split_across_reads_is_held_until_complete() {
        let mut decoder = FrameDecoder::new();
        let wire = server_frame(0x2, true, b"split across reads");

        for chunk in wire.chunks(3) {
            decoder.extend(chunk);
        }

        let event = decoder
            .next_event()
            .expect("the frame must decode")
            .expect("a complete frame produces an event");
        match event {
            FrameEvent::Payload(payload) => assert_eq!(&payload[..], b"split across reads"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_partial_frame_yields_no_event_yet() {
        let mut decoder = FrameDecoder::new();
        decoder.extend(&[0x82, 0x05, b'h', b'i']);

        assert!(decoder
            .next_event()
            .expect("an incomplete frame is not an error")
            .is_none());
    }
}
