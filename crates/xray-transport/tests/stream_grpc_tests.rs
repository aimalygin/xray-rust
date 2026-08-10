// Named like the sibling `stream_*_tests` files (e.g.
// `stream_websocket_tests.rs`'s `stream_websocket_handshake_tests`) rather
// than a bare `mod path`, so later gRPC test modules — framing, pool — read
// consistently in `cargo test` output alongside this one.
//
// **Why these are integration tests, and what it costs.** Being a separate
// crate is the point: the framing, the pool and the dial are driven across the
// same boundary a real caller sits on, so nothing here can reach a private and
// quietly test something a caller could not do. It is a convention, not a
// constraint — other modules in `xray-transport/src/` do test in-src — and it
// is paid for in visibility. Four names are the gRPC transport's actual API
// (`GrpcConfig`, `GrpcTransport`, `Authority`, `resolve_user_agent`);
// everything else these blocks import comes from
// `xray_transport::stream::grpc_test_only`, a `#[doc(hidden)]` module that
// exists for this file alone. Import from there rather than asking for a name
// to be re-exported beside the four. The argument for that split, and the
// modules that went in-src instead, are on `test_only` in
// `src/stream/grpc/mod.rs`.
mod stream_grpc_path_tests {
    use xray_transport::stream::grpc_test_only::{grpc_request_path, HunkMode};

    /// Vectors read off `Xray-core/transport/internet/grpc/config.go:17-59`
    /// and `encoding/customSeviceName.go:33`, which assembles the path as
    /// `"/" + getServiceName() + "/" + getTunStreamName()`.
    ///
    /// `(service_name, mode, expected_path)`
    const VECTORS: &[(&str, HunkMode, &str)] = &[
        // The proto3 default. Both halves of the join are present, so the
        // empty service name leaves a double slash.
        ("", HunkMode::Single, "//Tun"),
        ("", HunkMode::Multi, "//TunMulti"),
        // Plain names are escaped whole, stream name is a literal.
        ("hello", HunkMode::Single, "/hello/Tun"),
        ("hello", HunkMode::Multi, "/hello/TunMulti"),
        // Whole-string escaping means an inner slash is escaped, not kept.
        ("a/b", HunkMode::Single, "/a%2Fb/Tun"),
        // Go's encodePathSegment set: these pass through unescaped ...
        ("$&+:=@", HunkMode::Single, "/$&+:=@/Tun"),
        // ... and these do not. Escapes are uppercase hex.
        ("a b", HunkMode::Single, "/a%20b/Tun"),
        ("a;b", HunkMode::Single, "/a%3Bb/Tun"),
        ("a,b", HunkMode::Single, "/a%2Cb/Tun"),
        ("a?b", HunkMode::Single, "/a%3Fb/Tun"),
        ("a!b", HunkMode::Single, "/a%21b/Tun"),
        ("a*b", HunkMode::Single, "/a%2Ab/Tun"),
        // Custom paths: a leading slash switches dialects. The last segment is
        // the stream name, everything between the first and last slash is the
        // service name, escaped per segment rather than whole.
        ("/a/b", HunkMode::Single, "/a/b"),
        ("/a/b", HunkMode::Multi, "/a/b"),
        // `|` splits the last segment into tun|tunMulti, both client-side.
        ("/a/b|c", HunkMode::Single, "/a/b"),
        ("/a/b|c", HunkMode::Multi, "/a/c"),
        // Multi-segment service names keep their separators.
        ("/x/y/z", HunkMode::Single, "/x/y/z"),
        ("/x/y/z|w", HunkMode::Multi, "/x/y/w"),
        // `lastIndex < 1` is clamped to 1, so a single leading segment yields
        // an empty service name and the double slash comes back.
        ("/hello", HunkMode::Single, "//hello"),
        ("/hello|multi", HunkMode::Multi, "//multi"),
        // Everything below is ported from
        // `Xray-core/transport/internet/grpc/config_test.go`, whose table
        // tests exercise `getServiceName`/`getTunStreamName`/
        // `getTunMultiStreamName` in isolation. The full `:path` values here
        // were composed from those pieces and cross-checked by running Xray's
        // actual Go functions (`net/url.PathEscape` included), not
        // hand-traced, since `customSeviceName.go` itself has no test of its
        // own to port whole paths from.
        //
        // `TestConfig_GetServiceName`, "escape no absolute path", line 23-27:
        // whole-string escaping of two special characters at once.
        ("hello/world!", HunkMode::Single, "/hello%2Fworld%21/Tun"),
        // `TestConfig_GetServiceName`, "absolute path", line 28-32, combined
        // with the client/server `|` split.
        ("/my/sample/path/a|b", HunkMode::Single, "/my/sample/path/a"),
        ("/my/sample/path/a|b", HunkMode::Multi, "/my/sample/path/b"),
        // `TestConfig_GetServiceName`, "escape absolute path", line 33-37: a
        // *middle* service-name segment ("hello ", "world!") needs escaping,
        // not just the whole string as in the no-leading-slash dialect.
        (
            "/hello /world!/a|b",
            HunkMode::Single,
            "/hello%20/world%21/a",
        ),
        (
            "/hello /world!/a|b",
            HunkMode::Multi,
            "/hello%20/world%21/b",
        ),
        // `TestConfig_GetTunStreamName`/`GetTunMultiStreamName`, "absolute
        // path server", line 63-67 / 98-102: realistic tun|tunMulti names.
        (
            "/my/sample/path/tun_service|multi_service",
            HunkMode::Single,
            "/my/sample/path/tun_service",
        ),
        (
            "/my/sample/path/tun_service|multi_service",
            HunkMode::Multi,
            "/my/sample/path/multi_service",
        ),
        // `TestConfig_GetTunStreamName`, "escape absolute path client", line
        // 73-77: the *trailing* stream-name segment needs escaping (a
        // backslash and a `!`), not just a literal pass-through.
        (
            "/m y/sa !mple/pa\\th/tun\\_serv!ice",
            HunkMode::Single,
            "/m%20y/sa%20%21mple/pa%5Cth/tun%5C_serv%21ice",
        ),
        // `TestConfig_GetTunMultiStreamName`, "escape absolute path client",
        // line 108-112: same prefix, and a literal `%` in the input must
        // itself be escaped to `%25`.
        (
            "/m y/sa !mple/pa\\th/mu%lti\\_serv!ice",
            HunkMode::Multi,
            "/m%20y/sa%20%21mple/pa%5Cth/mu%25lti%5C_serv%21ice",
        ),
    ];

    #[test]
    fn the_request_path_matches_xrays_service_name_rules() {
        for (service_name, mode, expected) in VECTORS {
            assert_eq!(
                grpc_request_path(service_name, *mode),
                *expected,
                "serviceName {service_name:?} {mode:?}"
            );
        }
    }
}

mod stream_grpc_framing_write_tests {
    use xray_transport::stream::grpc_test_only::{encode_hunk, MAX_HUNK_PAYLOAD_LEN};

    /// gRPC's four-byte receive cap, which is both what a stock grpc-go peer
    /// holds a message to (`grpc@v1.81.0/server.go:60,191` — Xray installs no
    /// `MaxRecvMsgSize`) and what `HunkDecoder` holds one to.
    const RECEIVE_LIMIT: usize = 4 * 1024 * 1024;

    /// The clamp `GrpcStream::poll_write` holds a write to, pinned from both
    /// sides so the `- 5` in its definition cannot drift: at the limit the
    /// encoded body is exactly the receive cap, and one byte more is one byte
    /// over it.
    ///
    /// The `+ 1` case is deliberately still encoded rather than refused.
    /// `MAX_HUNK_PAYLOAD_LEN` is what a *peer* accepts, not what the framing
    /// can express — gRPC's own ceiling is the `u32` length prefix, three
    /// orders of magnitude further out — so keeping the clamp in the one place
    /// that has a caller to report a short write to is what makes it a clamp
    /// rather than a second failure mode.
    #[test]
    fn the_largest_hunk_payload_exactly_fills_the_receive_limit() {
        let at_the_limit = encode_hunk(&vec![0x41; MAX_HUNK_PAYLOAD_LEN]);
        assert_eq!(at_the_limit.len(), 5 + RECEIVE_LIMIT);
        assert_eq!(&at_the_limit[1..5], &(RECEIVE_LIMIT as u32).to_be_bytes());

        let one_over = encode_hunk(&vec![0x41; MAX_HUNK_PAYLOAD_LEN + 1]);
        assert_eq!(one_over.len(), 5 + RECEIVE_LIMIT + 1);
    }

    #[test]
    fn a_short_payload_costs_seven_bytes_of_overhead() {
        let encoded = encode_hunk(b"hello");
        assert_eq!(
            encoded,
            vec![
                0x00, // uncompressed
                0x00, 0x00, 0x00, 0x07, // length: tag + varint + payload
                0x0a, // field 1, wire type 2
                0x05, // varint length
                b'h', b'e', b'l', b'l', b'o',
            ]
        );
    }

    #[test]
    fn a_payload_over_127_bytes_uses_a_two_byte_varint() {
        let payload = vec![0x41; 200];
        let encoded = encode_hunk(&payload);

        assert_eq!(encoded[0], 0x00);
        assert_eq!(&encoded[1..5], &[0x00, 0x00, 0x00, 0xcb]); // 1 + 2 + 200
        assert_eq!(encoded[5], 0x0a);
        assert_eq!(&encoded[6..8], &[0xc8, 0x01]); // varint 200
        assert_eq!(&encoded[8..], &payload[..]);
        assert_eq!(encoded.len(), 5 + 203);
    }

    #[test]
    fn a_127_byte_payload_is_the_largest_with_a_one_byte_varint() {
        let payload = vec![0x41; 127];
        let encoded = encode_hunk(&payload);

        assert_eq!(encoded[0], 0x00);
        assert_eq!(&encoded[1..5], &[0x00, 0x00, 0x00, 0x81]); // 1 + 1 + 127
        assert_eq!(encoded[5], 0x0a);
        assert_eq!(encoded[6], 0x7f); // varint 127, one byte
        assert_eq!(&encoded[7..], &payload[..]);
        assert_eq!(encoded.len(), 5 + 129);
    }

    #[test]
    fn a_128_byte_payload_is_the_smallest_with_a_two_byte_varint() {
        let payload = vec![0x41; 128];
        let encoded = encode_hunk(&payload);

        assert_eq!(encoded[0], 0x00);
        assert_eq!(&encoded[1..5], &[0x00, 0x00, 0x00, 0x83]); // 1 + 2 + 128
        assert_eq!(encoded[5], 0x0a);
        assert_eq!(&encoded[6..8], &[0x80, 0x01]); // varint 128
        assert_eq!(&encoded[8..], &payload[..]);
        assert_eq!(encoded.len(), 5 + 131);
    }

    #[test]
    fn a_16383_byte_payload_is_the_largest_with_a_two_byte_varint() {
        let payload = vec![0x41; 16383];
        let encoded = encode_hunk(&payload);

        assert_eq!(encoded[0], 0x00);
        assert_eq!(&encoded[1..5], &[0x00, 0x00, 0x40, 0x02]); // 1 + 2 + 16383
        assert_eq!(encoded[5], 0x0a);
        assert_eq!(&encoded[6..8], &[0xff, 0x7f]); // varint 16383
        assert_eq!(&encoded[8..], &payload[..]);
        assert_eq!(encoded.len(), 5 + 16386);
    }

    #[test]
    fn a_16384_byte_payload_is_the_smallest_with_a_three_byte_varint() {
        let payload = vec![0x41; 16384];
        let encoded = encode_hunk(&payload);

        assert_eq!(encoded[0], 0x00);
        assert_eq!(&encoded[1..5], &[0x00, 0x00, 0x40, 0x04]); // 1 + 3 + 16384
        assert_eq!(encoded[5], 0x0a);
        assert_eq!(&encoded[6..9], &[0x80, 0x80, 0x01]); // varint 16384
        assert_eq!(&encoded[9..], &payload[..]);
        assert_eq!(encoded.len(), 5 + 16388);
    }

    #[test]
    fn an_empty_payload_still_produces_a_message_with_no_body() {
        // Xray writes whatever the layer above hands it (`hunkconn.go:131-140`
        // `Write` never special-cases a zero-length buffer), so a half-close
        // must still put a frame on the wire or it looks like a stall.
        //
        // But the frame's *body* is empty, not `0a 00`. Proto3 `bytes` fields
        // have implicit presence: protobuf-go's generated codec skips a field
        // whose value has length zero rather than encoding a present-but-empty
        // entry (`coderBytesNoZero` in `internal/impl/codec_tables.go:200,
        // 273-278` and `codec_gen.go:5477-5485`, selected because `Hunk.Data`
        // carries no `optional` keyword). A Go client marshalling
        // `&Hunk{Data: nil}` (or `Data: []byte{}}`, same length-zero check)
        // therefore writes a gRPC message with length 0 and nothing after it.
        assert_eq!(encode_hunk(&[]), vec![0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}

mod stream_grpc_framing_read_tests {
    use xray_transport::stream::grpc_test_only::{encode_hunk, HunkDecoder, HunkMode};

    fn drain(decoder: &mut HunkDecoder) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(payload) = decoder.next_payload().expect("well-formed stream") {
            out.push(payload);
        }
        out
    }

    /// Wraps a protobuf body in gRPC's uncompressed five-byte prefix.
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut framed = vec![0x00];
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(body);
        framed
    }

    #[test]
    fn one_whole_message_yields_its_payload() {
        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&encode_hunk(b"hello"));
        assert_eq!(drain(&mut decoder), vec![b"hello".to_vec()]);
    }

    #[test]
    fn a_message_split_at_every_byte_boundary_still_decodes() {
        // The defect this test exists for: a length varint straddling two DATA
        // frames. Feeding one byte at a time covers every split there is.
        let payload = vec![0x37; 500];
        let encoded = encode_hunk(&payload);

        let mut decoder = HunkDecoder::new(HunkMode::Single);
        let mut collected = Vec::new();
        for byte in &encoded {
            decoder.push(std::slice::from_ref(byte));
            while let Some(message) = decoder.next_payload().expect("well-formed stream") {
                collected.push(message);
            }
        }

        assert_eq!(collected, vec![payload]);
    }

    #[test]
    fn two_messages_in_one_chunk_both_come_out() {
        let mut chunk = encode_hunk(b"first");
        chunk.extend_from_slice(&encode_hunk(b"second"));

        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&chunk);
        assert_eq!(
            drain(&mut decoder),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
    }

    /// The ordinary shape of an HTTP/2 DATA frame once a stream is running:
    /// one whole message plus the head of the next. That is the only way to
    /// reach compaction with a non-empty tail, and compaction is the decoder's
    /// one piece of carried state — drop a byte too many and every *later*
    /// message is lost while this one still looks right, which is the failure
    /// mode a byte-stream tunnel notices last. Neither existing multi-message
    /// test gets there: `two_messages_in_one_chunk_both_come_out` compacts
    /// only once the buffer is already empty, and the byte-by-byte test
    /// carries a single message, so its tail is always empty too.
    ///
    /// Every split point is covered, so the tail runs from one byte (inside
    /// the gRPC header) through the whole message bar its last byte.
    #[test]
    fn a_partial_next_message_survives_compaction() {
        let second = encode_hunk(b"second");

        for split in 1..second.len() {
            let (head, tail) = second.split_at(split);
            let mut chunk = encode_hunk(b"first");
            chunk.extend_from_slice(head);

            let mut decoder = HunkDecoder::new(HunkMode::Single);
            decoder.push(&chunk);
            assert_eq!(
                drain(&mut decoder),
                vec![b"first".to_vec()],
                "split {split}"
            );
            // Compaction has run: the delivered message is gone and the head
            // of the next one is all that is left.
            assert_eq!(decoder.buffered_len(), head.len(), "split {split}");

            decoder.push(tail);
            assert_eq!(
                drain(&mut decoder),
                vec![b"second".to_vec()],
                "split {split}"
            );
            assert_eq!(decoder.buffered_len(), 0, "split {split}");
        }
    }

    /// What compaction exists for: a stream that runs for hours must not still
    /// be holding every byte it ever decoded. Nothing observes the allocation
    /// itself; `buffered_len` is the proxy, and it is an exact one between
    /// messages because `next_payload` compacts before it reports `None`.
    #[test]
    fn a_long_stream_does_not_retain_the_messages_it_handed_out() {
        let mut decoder = HunkDecoder::new(HunkMode::Single);

        for index in 0..128u8 {
            let payload = vec![index; 64];
            decoder.push(&encode_hunk(&payload));
            assert_eq!(drain(&mut decoder), vec![payload], "message {index}");
            assert_eq!(decoder.buffered_len(), 0, "message {index}");
        }
    }

    #[test]
    fn a_zero_length_hunk_is_a_message_not_an_end_of_stream() {
        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&encode_hunk(&[]));
        assert_eq!(drain(&mut decoder), vec![Vec::<u8>::new()]);
    }

    #[test]
    fn an_unknown_protobuf_field_is_skipped() {
        // field 2, wire type 0 (varint), value 1 -- then the real field 1.
        let framed = frame(&[0x10, 0x01, 0x0a, 0x02, b'h', b'i']);

        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&framed);
        assert_eq!(drain(&mut decoder), vec![b"hi".to_vec()]);
    }

    #[test]
    fn a_compressed_message_is_a_hard_error() {
        // We never advertise grpc-encoding, so a non-zero flag means the peer
        // is speaking a dialect we would silently mangle.
        let mut framed = vec![0x01];
        framed.extend_from_slice(&4u32.to_be_bytes());
        framed.extend_from_slice(&[0x0a, 0x02, b'h', b'i']);

        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&framed);
        let error = decoder
            .next_payload()
            .expect_err("compression must be refused");
        assert!(
            error.contains("compress"),
            "error should name the compression flag, got: {error}"
        );
    }

    /// grpc-go rejects a payload format it does not know before it looks at
    /// the body: `checkRecvPayload` falls through to "received unexpected
    /// payload format %d" for anything but 0 and 1
    /// (`grpc@v1.81.0/rpc_util.go:894-911`).
    #[test]
    fn an_unknown_payload_format_is_a_hard_error() {
        let mut framed = vec![0x02];
        framed.extend_from_slice(&4u32.to_be_bytes());
        framed.extend_from_slice(&[0x0a, 0x02, b'h', b'i']);

        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&framed);
        let error = decoder
            .next_payload()
            .expect_err("an unknown payload format must be refused");
        assert!(
            error.contains("payload format"),
            "error should name the payload format, got: {error}"
        );
    }

    /// `recvMsg` compares the declared length against `maxReceiveMessageSize`
    /// straight after reading the five-byte header and before
    /// `p.r.Read(int(length))` (`grpc@v1.81.0/rpc_util.go:771-794`), so an
    /// oversized declaration never reserves a buffer. Xray installs no
    /// `MaxCallRecvMsgSize` call option, so the client default of 4 MiB
    /// (`grpc@v1.81.0/clientconn.go:141`) is what a real peer is held to.
    ///
    /// Only the five-byte header is pushed here: the error has to come back
    /// from the header alone, without the decoder first waiting for — or
    /// reserving room for — the body it names.
    #[test]
    fn a_length_over_four_mib_is_refused_from_the_header_alone() {
        const CAP: u32 = 4 * 1024 * 1024;

        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&[0x00]); // uncompressed
        decoder.push(&(CAP + 1).to_be_bytes());
        let error = decoder
            .next_payload()
            .expect_err("an oversized message must be refused");
        assert!(
            error.contains("4194305"),
            "error should name the declared length, got: {error}"
        );
    }

    /// The comparison is `int(length) > maxReceiveMessageSize`
    /// (`grpc@v1.81.0/rpc_util.go:783`), so exactly 4 MiB is still legal and
    /// the decoder must go on waiting for its body rather than refuse it.
    #[test]
    fn a_length_of_exactly_four_mib_is_still_legal() {
        const CAP: u32 = 4 * 1024 * 1024;

        let mut header = vec![0x00];
        header.extend_from_slice(&CAP.to_be_bytes());

        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&header);
        assert_eq!(
            decoder.next_payload().expect("4 MiB is within the cap"),
            None
        );
    }

    /// protobuf-go routes a known field number carrying the wrong wire type to
    /// the unknown-field path rather than failing the parse: `consumeBytes`
    /// returns `errUnknown` when `wtyp != protowire.BytesType`
    /// (`protobuf@v1.36.11/internal/impl/codec_gen.go:5489-5492`) and
    /// `unmarshalPointerEager` skips it with `ConsumeFieldValue`
    /// (`internal/impl/decode.go:218-231`). Confirmed by unmarshalling these
    /// exact bytes into Xray's own `encoding.Hunk`: `Data` comes out `"hi"`.
    #[test]
    fn field_one_with_the_wrong_wire_type_is_skipped_not_refused() {
        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&frame(&[0x08, 0x01, 0x0a, 0x02, b'h', b'i']));
        assert_eq!(drain(&mut decoder), vec![b"hi".to_vec()]);

        // And on its own it leaves the field absent, which is an empty read.
        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&frame(&[0x08, 0x01]));
        assert_eq!(drain(&mut decoder), vec![Vec::<u8>::new()]);
    }

    /// The body `MultiHunk{Data: [][]byte{"hi", "yo!"}}` marshals to, which is
    /// also a legal `Hunk` body with field 1 repeated. Read as one message it
    /// carries two chunks; read as the other it carries one.
    ///
    /// Taken from Xray's own generated types rather than hand-assembled:
    /// `proto.Marshal` of that `MultiHunk` prints `0a0268690a03796f21`, and
    /// `proto.Unmarshal` of those same bytes gives `MultiHunk.Data` two
    /// elements, `["hi" "yo!"]`, and `Hunk.Data` the one value `"yo!"`.
    const TWO_CHUNKS: &[u8] = &[0x0a, 0x02, b'h', b'i', 0x0a, 0x03, b'y', b'o', b'!'];

    /// A repeated singular `bytes` field is last-one-wins, not concatenation:
    /// `consumeBytesNoZero` assigns with `append(([]byte)(nil), v...)`
    /// (`protobuf@v1.36.11/internal/impl/codec_gen.go:5497`), overwriting
    /// whatever an earlier entry left. Unmarshalling this body into Xray's
    /// `encoding.Hunk` yields `Data == "yo!"`, not `"hiyo!"`.
    ///
    /// The pair of [`every_chunk_of_a_multi_hunk_is_delivered_in_order`]: the
    /// same bytes, the other mode, the other answer. Concatenating here would
    /// put bytes into the tunnel the Go peer never sent.
    #[test]
    fn the_last_field_one_wins_when_a_hunk_repeats_it() {
        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&frame(TWO_CHUNKS));
        assert_eq!(drain(&mut decoder), vec![b"yo!".to_vec()]);
    }

    /// `MultiHunk.Data` is `repeated bytes` (`Xray-core/transport/internet/
    /// grpc/encoding/stream.proto:10-12`), so in multi mode the repetition is
    /// the message rather than a quirk of it: `forceFetch` takes the whole
    /// `[][]byte` and `ReadMultiBuffer` walks every element into the buffer it
    /// returns (`encoding/multiconn.go:71-113`).
    ///
    /// Delivering only the last one is silent data loss — no error, no log,
    /// just a tunnel that corrupts — and a one-element message round-trips
    /// identically either way, so nothing but a multi-element message can catch
    /// it.
    ///
    /// The chunks are concatenated rather than kept apart because this is a
    /// byte stream: `ReadMultiBuffer` hands its elements to a `cnc.Connection`
    /// that copies them out in order, and it drops the zero-length ones
    /// (`multiconn.go:96-99`), which concatenation does by construction.
    #[test]
    fn every_chunk_of_a_multi_hunk_is_delivered_in_order() {
        let mut decoder = HunkDecoder::new(HunkMode::Multi);
        decoder.push(&frame(TWO_CHUNKS));
        assert_eq!(drain(&mut decoder), vec![b"hiyo!".to_vec()]);
    }

    /// Why the bug survived: every message this client writes carries one
    /// element, and one element decodes the same in both modes. A round trip
    /// against our own writer therefore proves nothing about multi mode — only
    /// a peer that batches does.
    #[test]
    fn a_one_element_message_decodes_the_same_in_both_modes() {
        for mode in [HunkMode::Single, HunkMode::Multi] {
            let mut decoder = HunkDecoder::new(mode);
            decoder.push(&encode_hunk(b"hello"));
            assert_eq!(drain(&mut decoder), vec![b"hello".to_vec()], "{mode:?}");
        }
    }

    /// Every unknown wire type protobuf-go's `consumeFieldValueD` handles by
    /// length alone (`protobuf@v1.36.11/encoding/protowire/wire.go:116-129`).
    #[test]
    fn unknown_fields_of_every_skippable_wire_type_are_stepped_over() {
        let bodies: &[(&str, &[u8])] = &[
            ("varint", &[0x10, 0x96, 0x01]),
            ("fixed64", &[0x11, 1, 2, 3, 4, 5, 6, 7, 8]),
            ("bytes", &[0x12, 0x02, b'x', b'y']),
            ("fixed32", &[0x15, 1, 2, 3, 4]),
        ];

        for (name, prefix) in bodies {
            let mut body = prefix.to_vec();
            body.extend_from_slice(&[0x0a, 0x02, b'h', b'i']);

            let mut decoder = HunkDecoder::new(HunkMode::Single);
            decoder.push(&frame(&body));
            assert_eq!(drain(&mut decoder), vec![b"hi".to_vec()], "{name}");
        }
    }

    /// Bodies protobuf-go itself refuses with `errDecode`. Verified by
    /// unmarshalling each into Xray's `encoding.Hunk`: every one comes back
    /// "cannot parse invalid wire-format data".
    #[test]
    fn a_malformed_body_is_a_hard_error() {
        let bodies: &[(&str, &[u8])] = &[
            // field 1 claims five bytes with two left in the message.
            ("length past the end of the body", &[0x0a, 0x05, b'h', b'i']),
            // Eleven continuation bytes: no varint is that long.
            (
                "oversized varint",
                &[
                    0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
                ],
            ),
            // A tag with no value after it.
            ("truncated tag", &[0x0a]),
            // Wire type 4 with no group open: `unmarshalPointerEager` fails
            // it because `num != groupTag` (`internal/impl/decode.go:159-163`).
            ("stray end group", &[0x14]),
            // Wire types 6 and 7 are reserved; `consumeFieldValueD` returns
            // `errCodeReserved` (`protowire/wire.go:156-157`).
            ("reserved wire type 6", &[0x16, 0x00]),
            ("reserved wire type 7", &[0x17, 0x00]),
            // Field number 0 is below `MinValidNumber` (`protowire/wire.go:24`).
            ("field number zero", &[0x00, 0x01]),
        ];

        for (name, body) in bodies {
            let mut decoder = HunkDecoder::new(HunkMode::Single);
            decoder.push(&frame(body));
            let decoded = decoder.next_payload();
            assert!(
                decoded.is_err(),
                "{name} should be refused, got {decoded:?}"
            );
        }
    }

    /// The field-number ceiling, both sides of it.
    ///
    /// The range is `MinValidNumber..=MaxValidNumber`, `1..=1<<29 - 1`
    /// (`protobuf@v1.36.11/encoding/protowire/wire.go:24-27`), and the code
    /// that enforces it for a `Hunk` is the decoder itself:
    /// `unmarshalPointerEager` parses each tag inline and refuses anything
    /// outside that range with `errDecode`
    /// (`internal/impl/decode.go:153-158`).
    ///
    /// `protowire.ConsumeTag` is the more permissive reading and the wrong one
    /// to match — it checks only `num < MinValidNumber`, and `DecodeTag` cuts
    /// at `MaxInt32` rather than at `MaxValidNumber`
    /// (`wire.go:168-178,525-531`), so it passes everything below `1<<31`.
    /// Nothing on `proto.Unmarshal`'s path calls it.
    ///
    /// Both bodies below are the ones a Go program built with
    /// `protowire.AppendTag` and handed to `proto.Unmarshal`: at `1<<29 - 1`
    /// both `encoding.Hunk` and `encoding.MultiHunk` come back with `"hi"` and
    /// no error, and at `1<<29` both come back "cannot parse invalid
    /// wire-format data".
    #[test]
    fn the_field_number_ceiling_is_the_one_protobuf_gos_decoder_enforces() {
        // `0a 02 "hi"`, then an unknown bytes field carrying `"x"` whose
        // number is `1<<29 - 1` and then `1<<29`.
        let largest_valid: &[u8] = &[
            0x0a, 0x02, b'h', b'i', 0xfa, 0xff, 0xff, 0xff, 0x0f, 0x01, b'x',
        ];
        let first_invalid: &[u8] = &[
            0x0a, 0x02, b'h', b'i', 0x82, 0x80, 0x80, 0x80, 0x10, 0x01, b'x',
        ];

        for mode in [HunkMode::Single, HunkMode::Multi] {
            let mut decoder = HunkDecoder::new(mode);
            decoder.push(&frame(largest_valid));
            assert_eq!(
                drain(&mut decoder),
                vec![b"hi".to_vec()],
                "{mode:?}: field 1<<29 - 1 is a skippable unknown field"
            );

            let mut decoder = HunkDecoder::new(mode);
            decoder.push(&frame(first_invalid));
            let decoded = decoder.next_payload();
            assert!(
                decoded.is_err(),
                "{mode:?}: field 1<<29 should be refused, got {decoded:?}"
            );
        }
    }

    /// A deliberate divergence, tested so it stays deliberate. protobuf-go
    /// walks an unknown group to its `EndGroupType` and skips it
    /// (`protowire/wire.go:130-153`), so Go reads `"hi"` out of this body. A
    /// `Hunk` has one field and no groups, so rather than carry a recursive
    /// skipper with its own depth limit for a shape the wire never holds, we
    /// refuse it.
    #[test]
    fn an_unknown_group_is_refused_where_protobuf_go_would_skip_it() {
        let mut decoder = HunkDecoder::new(HunkMode::Single);
        decoder.push(&frame(&[0x13, 0x18, 0x01, 0x14, 0x0a, 0x02, b'h', b'i']));
        assert!(decoder.next_payload().is_err());
    }
}

/// The `Hunk` stream on a real HTTP/2 POST, against an in-process peer shaped
/// like xray-core's gRPC inbound.
mod stream_grpc_h2_tests {
    use std::future::{poll_fn, Future};
    use std::pin::Pin;
    use std::task::Poll;
    use std::time::Duration;

    use bytes::Bytes;
    use h2::server::{self, SendResponse};
    use h2::{RecvStream, SendStream};
    use http::{HeaderMap, HeaderValue, Method, Response};
    use tokio::io::{duplex, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
    use tokio::sync::oneshot;
    use xray_transport::stream::grpc_test_only::{
        encode_hunk, open_grpc_h2_stream, GrpcStream, MAX_HUNK_PAYLOAD_LEN,
    };
    use xray_transport::stream::GrpcConfig;
    use xray_transport::BoxedTransportStream;

    /// `grpcSettings.authority` when it is set; the tests never exercise the
    /// fallbacks (`Xray-core/transport/internet/grpc/dial.go:159-167`), which
    /// are the caller's job to resolve.
    const AUTHORITY: &str = "grpc.example.com";
    /// `grpc_request_path(SERVICE_NAME, HunkMode::Single)`, which is what the
    /// dial derives for the config below.
    const PATH: &str = "/xray.grpc/Tun";
    /// The same for `HunkMode::Multi`. Asserted on the peer's side of a
    /// multi-mode call, so a mode that reached the decoder without reaching the
    /// `:path` — or the other way round — fails rather than passes quietly.
    const MULTI_PATH: &str = "/xray.grpc/TunMulti";
    const SERVICE_NAME: &str = "xray.grpc";
    /// A literal user agent, so it survives `resolve_user_agent` untouched.
    /// This block only cares that whatever value is dialled with reaches the
    /// request unchanged; the table itself is
    /// `stream_grpc_request_headers_tests`'.
    const USER_AGENT: &str = "grpc-go/1.81.0";

    /// Every test here can stall rather than fail — an unreleased window, a
    /// read waiting on a message the peer will not send, an EOF that never
    /// arrives — and a stalled `#[tokio::test]` hangs the whole run. Each one
    /// is therefore fenced by a deadline that turns the stall into a failure.
    const DEADLINE: Duration = Duration::from_secs(10);

    async fn within_deadline<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(DEADLINE, future)
            .await
            .expect("the exchange completes rather than stalling")
    }

    async fn open(io: DuplexStream) -> GrpcStream {
        open_with_user_agent(io, USER_AGENT).await
    }

    async fn open_with_user_agent(io: DuplexStream, user_agent: &str) -> GrpcStream {
        open_dialling(io, user_agent, false).await
    }

    /// A dial with `grpcSettings.multiMode` set, which is `rpc TunMulti` and
    /// `MultiHunk` rather than `rpc Tun` and `Hunk`.
    async fn open_in_multi_mode(io: DuplexStream) -> GrpcStream {
        open_dialling(io, USER_AGENT, true).await
    }

    async fn open_dialling(io: DuplexStream, user_agent: &str, multi_mode: bool) -> GrpcStream {
        let config = GrpcConfig {
            service_name: SERVICE_NAME.to_owned(),
            multi_mode,
            authority: AUTHORITY.parse().expect("a literal authority"),
            user_agent: HeaderValue::from_str(user_agent).expect("a sendable user agent"),
            idle_timeout_secs: 0,
            health_check_timeout_secs: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
        };
        open_grpc_h2_stream(Box::new(io) as BoxedTransportStream, &config)
            .await
            .expect("the POST opens")
    }

    fn trailers(status: &str) -> HeaderMap {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", status.parse().expect("a legal header value"));
        trailers
    }

    /// What the in-process peer does once the client's HEADERS arrive.
    enum Script {
        /// Send every `Hunk` straight back, then close with `grpc-status: 0`
        /// when the client half-closes.
        Echo,
        /// Write these DATA payloads — already framed by the test — and close
        /// with these trailers.
        Say(Vec<Bytes>, HeaderMap),
        /// Answer with one HEADERS block — `:status 200`, `content-type`,
        /// these fields — carrying END_STREAM, and no DATA and no trailers
        /// behind it.
        ///
        /// gRPC's Trailers-Only response, and not a pathological shape at all:
        /// `writeStatus` emits exactly this whenever it finds no headers sent
        /// yet (`grpc@v1.81.0/internal/transport/http2_server.go:1082-1093`),
        /// which is every RPC a grpc-go handler ends having written nothing.
        /// For an Xray inbound that is `Tun` returning on a tunnel whose remote
        /// said not one byte, and every call to a `serviceName` it does not
        /// serve.
        ///
        /// This is the half of that shape a client which has *already
        /// half-closed* sees. [`Script::TrailersOnlyThenReset`] is the other
        /// half, and the one a relay reaches.
        TrailersOnly(HeaderMap),
        /// [`Script::TrailersOnly`] with the `RST_STREAM(NO_ERROR)` grpc-go
        /// puts behind the block whenever the client has not half-closed —
        /// `rst := s.getState() == streamActive` in `writeStatus`
        /// (`grpc@v1.81.0/internal/transport/http2_server.go:1127-1129`).
        ///
        /// A relay's uplink is open for the whole call, so this, not the quiet
        /// one, is what a real Xray inbound sends *us*. The two look nothing
        /// alike by the time they reach the client adapter — h2 folds the
        /// reset over the state that recorded the END_STREAM
        /// (`h2-0.4.15/src/proto/streams/state.rs:252-289`) — which is why
        /// every Trailers-Only test here runs against both.
        TrailersOnlyThenReset(HeaderMap),
        /// Write these DATA payloads and then END_STREAM on an empty DATA
        /// frame, with no trailing HEADERS at all. grpc-go's server never does
        /// this — `writeStatus` is the only way it ends an RPC — so it stands
        /// in for a peer that is not one, or for one that died mid-response.
        SayAndEndTheDataStream(Vec<Bytes>),
        /// [`Script::Say`], and then reset the stream the way grpc-go's server
        /// does when it ends the RPC before the client half-closes.
        SayThenReset(Vec<Bytes>, HeaderMap),
        /// [`Script::SayThenReset`] against a client left mid-frame, which is
        /// where a real uplink is when an Xray inbound ends a call: a peer
        /// that has stopped reading has stopped opening the window too.
        ///
        /// One DATA frame is taken and the client's flow-control window is
        /// never released, so whatever the client queued past 65535 bytes
        /// stays queued. `reached` reports that first frame and `resume` waits
        /// for the client's word before the call ends — both halves are load
        /// bearing. Without the report the client cannot know its window is
        /// spent; without the wait the reset can land while the client is
        /// still inside the flush that spent it, which tests the drained case
        /// over again.
        StallThenSayThenReset {
            reached: oneshot::Sender<()>,
            resume: oneshot::Receiver<()>,
            chunks: Vec<Bytes>,
            trailers: HeaderMap,
        },
        /// Accept the call and answer nothing at all.
        Silent,
        /// Accept the call, answer nothing, and report how the client's
        /// request body ended.
        ReportHowTheUplinkEnded(oneshot::Sender<Result<(), h2::Error>>),
    }

    impl Script {
        /// Whether the peer ends the call by dropping its stream handles,
        /// which is what h2 turns into `RST_STREAM`. Those scripts need the
        /// connection held open until the handler has returned; see
        /// [`serve_one_call`].
        fn ends_with_a_reset(&self) -> bool {
            matches!(
                self,
                Script::SayThenReset(..)
                    | Script::StallThenSayThenReset { .. }
                    | Script::TrailersOnlyThenReset(..)
            )
        }
    }

    /// Serves one gRPC call over `io`.
    ///
    /// The accept loop keeps running while the call is handled: h2's server
    /// `Connection` is the connection, and nothing moves on the socket unless
    /// `accept` is being polled.
    async fn serve_one_call(io: DuplexStream, script: Script) {
        serve_one_call_expecting(io, script, PATH, USER_AGENT).await;
    }

    /// [`serve_one_call`] for a test that dials with a `:path` or a
    /// `user-agent` other than the [`PATH`] and [`USER_AGENT`] every request
    /// assertion runs against.
    async fn serve_one_call_expecting(
        io: DuplexStream,
        script: Script,
        expected_path: &'static str,
        expected_user_agent: &'static str,
    ) {
        let mut connection = server::handshake(io).await.expect("server handshake");
        let mut script = Some(script);
        while let Some(accepted) = connection.accept().await {
            let (request, respond) = accepted.expect("a well-formed request");
            let script = script
                .take()
                .expect("the tests open one call per connection");

            // The resetting scripts are the ones the connection must not move
            // on from until the handler has returned. h2 puts `RST_STREAM` on
            // the wire when the last handle to a stream is dropped, so the
            // reset happens as `handle_call` returns; the graceful shutdown
            // behind it is what turns "the reset has been queued" into
            // something the client can wait for, since a client whose driver
            // has finished has necessarily parsed every frame ahead of the
            // `GOAWAY`.
            //
            // The handler still runs on its own task rather than inline,
            // because `accept` is the only thing that polls this connection
            // and `StallThenSayThenReset` waits on a DATA frame that will
            // never arrive if nothing is reading the socket.
            if script.ends_with_a_reset() {
                let call = tokio::spawn(handle_call(
                    request,
                    respond,
                    script,
                    expected_path,
                    expected_user_agent,
                ));
                tokio::select! {
                    accepted = connection.accept() => {
                        assert!(accepted.is_none(), "the tests open one call per connection");
                    }
                    finished = call => finished.expect("the call handler does not panic"),
                }
                connection.graceful_shutdown();
                while connection.accept().await.is_some() {}
                return;
            }

            tokio::spawn(handle_call(
                request,
                respond,
                script,
                expected_path,
                expected_user_agent,
            ));
        }
    }

    /// The response HEADERS are withheld until the handler has something to
    /// send, exactly as grpc-go does: `http2Server.write` calls `writeHeader`
    /// only on the first data write
    /// (`grpc@v1.81.0/internal/transport/http2_server.go:1142-1146`). A client
    /// that waited for the response while dialling would deadlock against a
    /// real Xray inbound, which says nothing until the tunnel it opened has
    /// spoken.
    async fn handle_call(
        request: http::Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        script: Script,
        expected_path: &str,
        expected_user_agent: &str,
    ) {
        let (head, mut body) = request.into_parts();
        assert_request_line(&head, expected_path, expected_user_agent);

        match script {
            Script::Silent => {
                // Hold both halves so the stream stays open and unanswered.
                let _held = (body, respond);
                std::future::pending::<()>().await;
            }
            Script::SayThenReset(chunks, trailers) => {
                say_then_reset(respond, body, chunks, trailers).await;
            }
            Script::StallThenSayThenReset {
                reached,
                resume,
                chunks,
                trailers,
            } => {
                body.data()
                    .await
                    .expect("the client writes before the peer ends the call")
                    .expect("client data");
                reached.send(()).expect("the client is still waiting");
                resume.await.expect("the client hands the call back");
                say_then_reset(respond, body, chunks, trailers).await;
            }
            Script::ReportHowTheUplinkEnded(report) => {
                // The first `Hunk` is echoed so the client can tell the call is
                // established in both directions before it drops anything.
                // Without that the dial could be dropped before its HEADERS
                // ever left the socket, and there would be no call to reset.
                let mut echo = None;
                let outcome = loop {
                    match body.data().await {
                        Some(Ok(chunk)) => {
                            body.flow_control()
                                .release_capacity(chunk.len())
                                .expect("release the client's window");
                            if echo.is_none() {
                                let mut send = respond
                                    .send_response(grpc_response(), false)
                                    .expect("respond");
                                send_all(&mut send, chunk).await;
                                echo = Some(send);
                            }
                        }
                        Some(Err(error)) => break Err(error),
                        None => break Ok(()),
                    }
                };
                let _ = report.send(outcome);
            }
            Script::Say(chunks, trailers) => {
                let mut send = respond
                    .send_response(grpc_response(), false)
                    .expect("respond");
                for chunk in chunks {
                    send_all(&mut send, chunk).await;
                }
                send.send_trailers(trailers).expect("trailers");
                drain_the_client(body).await;
            }
            Script::TrailersOnly(fields) => {
                let send = respond_trailers_only(&mut respond, fields);
                // Both handles are held rather than dropped, because dropping
                // them is what makes h2 reset the stream and this script is
                // the shape that carries no reset. Having nothing left to say
                // is *not* what withholds it on grpc-go's side: `rst :=
                // s.getState() == streamActive` (`http2_server.go:1127-1129`)
                // asks whether the client has sent END_STREAM, and the client
                // this serves never does. So a real grpc-go server in this
                // position would send one — this is the shape it sends only to
                // a client that closed its request body first, and
                // `TrailersOnlyThenReset` is the shape it sends to every other.
                let _held = (send, body);
                std::future::pending::<()>().await;
            }
            Script::TrailersOnlyThenReset(fields) => {
                let send = respond_trailers_only(&mut respond, fields);
                // Dropping every handle is how the reset is asked of h2 — see
                // `say_then_reset` for why not `send_reset` — and h2 picks
                // NO_ERROR for exactly this state, a server whose send half is
                // closed while the client's is still streaming
                // (`h2-0.4.15/src/proto/streams/streams.rs:1601-1619`), which
                // is the code `writeStatus` uses too.
                drop((send, body, respond));
            }
            Script::SayAndEndTheDataStream(chunks) => {
                let mut send = respond
                    .send_response(grpc_response(), false)
                    .expect("respond");
                for chunk in chunks {
                    send_all(&mut send, chunk).await;
                }
                // The END_STREAM goes on a DATA frame of its own rather than on
                // the last payload, so the client is certain to have taken the
                // payload as data before it sees the end.
                send.send_data(Bytes::new(), true)
                    .expect("end the data stream");
                drain_the_client(body).await;
            }
            Script::Echo => {
                let mut send = None;
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("client data");
                    body.flow_control()
                        .release_capacity(chunk.len())
                        .expect("release the client's window");
                    let send = match send {
                        Some(ref mut send) => send,
                        None => send.insert(
                            respond
                                .send_response(grpc_response(), false)
                                .expect("respond"),
                        ),
                    };
                    send_all(send, chunk).await;
                }
                let mut send = match send {
                    Some(send) => send,
                    None => respond
                        .send_response(grpc_response(), false)
                        .expect("respond"),
                };
                send.send_trailers(trailers("0")).expect("trailers");
            }
        }
    }

    /// The one END_STREAM header block a Trailers-Only response consists of:
    /// `:status 200`, `content-type`, and whatever `fields` carries.
    fn respond_trailers_only(
        respond: &mut SendResponse<Bytes>,
        fields: HeaderMap,
    ) -> SendStream<Bytes> {
        let mut response = grpc_response();
        response.headers_mut().extend(fields);
        respond
            .send_response(response, true)
            .expect("a trailers-only response")
    }

    /// Keeps reading the client's request body after the peer has said its
    /// piece, so the client's flow-control window never closes under a relay
    /// that is still writing.
    async fn drain_the_client(mut body: RecvStream) {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("client data");
            body.flow_control()
                .release_capacity(chunk.len())
                .expect("release the client's window");
        }
    }

    /// The trailers, and the reset right behind them.
    ///
    /// `writeStatus` puts a RST_STREAM(NO_ERROR) behind the trailing HEADERS
    /// whenever the client has not half-closed first — `rst := s.getState() ==
    /// streamActive` (`grpc@v1.81.0/internal/transport/http2_server.go:
    /// 1127-1129`). Dropping the handles is how that is asked of h2, *not*
    /// `send_reset`: a `send_reset` here discards the response and trailers
    /// already queued behind it, and the client sees a bare reset with no call
    /// in front of it.
    async fn say_then_reset(
        mut respond: SendResponse<Bytes>,
        body: RecvStream,
        chunks: Vec<Bytes>,
        trailers: HeaderMap,
    ) {
        let mut send = respond
            .send_response(grpc_response(), false)
            .expect("respond");
        for chunk in chunks {
            send_all(&mut send, chunk).await;
        }
        send.send_trailers(trailers).expect("trailers");
        drop((send, body, respond));
    }

    /// The request every script is served over, checked once where all of them
    /// pass through.
    ///
    /// Without this the whole block runs on `into_parts().1` and never looks at
    /// the head, so a `:path` mangled by the URI, a GET, or a dropped `te:
    /// trailers` would sail through every test here: h2 needs none of them, and
    /// neither does this peer. Nor, for `te`, does a stock grpc-go inbound —
    /// v1.81.0's server checks only `content-type`
    /// (`grpc@v1.81.0/internal/transport/http2_server.go:417-427,495-497`) —
    /// which is exactly why nothing else would catch it going missing. The
    /// client sends it on every call regardless (`http2_client.go:573-579`
    /// builds `:method`, `:scheme`, `:path`, `:authority`, `content-type`,
    /// `user-agent`, `te` in that order and none of them conditionally), so it
    /// is part of what a censor sees, and any middlebox on the path holding to
    /// the gRPC HTTP/2 spec is entitled to refuse a call without it.
    ///
    /// Which values are *right*, and which fields are absent on purpose, is
    /// `stream_grpc_request_headers_tests`'s question. This pins only that the
    /// request builder put a well-formed call on the wire, so the scripts below
    /// are reading one.
    fn assert_request_line(
        head: &http::request::Parts,
        expected_path: &str,
        expected_user_agent: &str,
    ) {
        assert_eq!(head.method, Method::POST, "gRPC calls are POSTs");
        // `:scheme` stays `http`: Xray dials gRPC with
        // `insecure.NewCredentials()` and wraps the connection itself
        // (`Xray-core/transport/internet/grpc/dial.go:103-157`), so grpc-go
        // believes the transport is plaintext.
        assert_eq!(head.uri.scheme_str(), Some("http"), "scheme");
        assert_eq!(
            head.uri.authority().map(|authority| authority.as_str()),
            Some(AUTHORITY),
            ":authority"
        );
        assert_eq!(head.uri.path(), expected_path, ":path");
        assert_eq!(head.uri.query(), None, "the :path carries no query");

        for (name, expected) in [
            ("content-type", "application/grpc"),
            ("te", "trailers"),
            ("user-agent", expected_user_agent),
        ] {
            assert_eq!(
                head.headers.get(name).map(|value| value.to_str().unwrap()),
                Some(expected),
                "{name}"
            );
        }
    }

    fn grpc_response() -> Response<()> {
        Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .expect("a well-formed response")
    }

    /// The server-side mirror of the client's uplink loop: reserve, wait for
    /// capacity, send at most what was granted.
    async fn send_all(send: &mut SendStream<Bytes>, mut chunk: Bytes) {
        while !chunk.is_empty() {
            send.reserve_capacity(chunk.len());
            let granted = poll_fn(|cx| send.poll_capacity(cx))
                .await
                .expect("the send half is still streaming")
                .expect("capacity, not an error");
            let take = granted.min(chunk.len());
            send.send_data(chunk.split_to(take), false)
                .expect("send data");
        }
    }

    /// Frames each payload as its own `Hunk`, the way the peer's writes arrive.
    fn hunks(payloads: &[&[u8]]) -> Vec<Bytes> {
        payloads
            .iter()
            .map(|payload| Bytes::from(encode_hunk(payload)))
            .collect()
    }

    #[tokio::test]
    async fn a_bidirectional_post_carries_bytes_both_ways() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(server_io, Script::Echo));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            // Two round trips, not one: the second write is the first to
            // re-reserve capacity on a stream that has already spent some, and
            // h2's reservation is a running total rather than an increment.
            for message in [b"ping", b"pong"] {
                stream.write_all(message).await.expect("uplink write");
                stream.flush().await.expect("uplink flush");

                let mut echoed = [0u8; 4];
                stream.read_exact(&mut echoed).await.expect("downlink read");
                assert_eq!(&echoed, message);
            }

            // The half-close is what makes the peer's handler finish and send
            // its trailers, which is the only clean end of a gRPC call.
            stream.shutdown().await.expect("half-close");
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.expect("read to eof");
            assert!(rest.is_empty(), "unexpected trailing bytes: {rest:?}");
        })
        .await;
    }

    /// A write reaches the peer even when the caller never writes again and
    /// never flushes.
    ///
    /// Every other test here writes in pairs or flushes, and either hides this:
    /// a second `poll_write` drains what the first one left, and so does
    /// `poll_flush`. What neither covers is the caller that writes once and
    /// then only reads, which is the shape of every tunnel whose peer speaks
    /// first — SSH, SMTP, IMAP, FTP — and of the VLESS request header itself,
    /// which `open_vless_tcp_stream_with_resolver_and_dialer` writes before the
    /// relay starts (`crates/xray-core-rs/src/outbound.rs`). The Xray inbound
    /// dials the target off that header, so a header still in this adapter is a
    /// server with nothing to answer and a client waiting for the answer.
    ///
    /// It stalls rather than corrupts, because h2 grants stream capacity from
    /// the connection task and the grant lands after `poll_write` has already
    /// returned: the encoded `Hunk` is left queued, and without the read path
    /// draining it too, nothing polls the uplink again.
    #[tokio::test]
    async fn a_lone_write_reaches_the_peer_without_a_second_write_or_a_flush() {
        const GREETING: &[u8] = b"220 ready";

        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(server_io, Script::Echo));
        let mut stream = within_deadline(open(client_io)).await;

        stream.write_all(GREETING).await.expect("uplink write");

        within_deadline(async {
            let mut echoed = [0u8; GREETING.len()];
            stream.read_exact(&mut echoed).await.expect("downlink read");
            assert_eq!(&echoed, GREETING);
        })
        .await;
    }

    /// A write that parked and was then drained by a flush is reported to its
    /// caller, not encoded a second time.
    ///
    /// The parked write leaves its frame in `pending_write` and its count in
    /// `accepted`. A flush or a half-close hands that frame to h2 and empties
    /// the queue, and the count then has to be *reported* on the retry — a
    /// retry that reads the empty queue as "no frame outstanding" builds a
    /// second copy of the caller's buffer and puts it on the wire behind the
    /// first. Duplicated bytes are the worst failure a tunnel has: nothing
    /// errors, and the far end acts on the same request twice.
    ///
    /// No caller in this workspace reaches it today, which is exactly why it
    /// is worth a test. `copy_direction` awaits `write_all` inside the read
    /// arm's *body* rather than as a select arm
    /// (`crates/xray-core-rs/src/policy.rs:203`), so its flush deadline cannot
    /// fire while a write is parked; the tun loop breaks on a failed send. In
    /// both, nothing else drains the uplink between a parked write and its
    /// retry. That is a property of today's two callers, not of the public
    /// `AsyncWrite` this type offers.
    ///
    /// The first write on a fresh stream is the one that parks, and does so
    /// every time rather than by luck: h2 assigns the capacity `poll_write`
    /// reserves from the connection task, so the grant cannot arrive inside
    /// the poll that asked for it.
    #[tokio::test]
    async fn a_parked_write_a_flush_drained_is_reported_rather_than_re_encoded() {
        const MESSAGE: &[u8] = b"exactly once";

        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(server_io, Script::Echo));
        let mut stream = within_deadline(open(client_io)).await;

        let parked = poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_write(cx, MESSAGE))).await;
        assert!(
            parked.is_pending(),
            "the first write did not park, so this test is no longer reproducing the retry"
        );

        within_deadline(stream.flush()).await.expect("uplink flush");

        // The retry an `AsyncWrite` caller makes: same buffer, because it was
        // never told any of it was taken.
        let written = within_deadline(poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, MESSAGE)))
            .await
            .expect("the retried write");
        assert_eq!(
            written,
            MESSAGE.len(),
            "the retry reports the frame the flush sent"
        );

        within_deadline(async {
            stream.shutdown().await.expect("half-close");
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.expect("read to eof");
            assert_eq!(
                echoed,
                MESSAGE,
                "the peer received {} bytes for one {}-byte write",
                echoed.len(),
                MESSAGE.len()
            );
        })
        .await;
    }

    /// The connection and stream windows both start at 65535 bytes. Neither
    /// side gets past that without giving the window back, so this is the test
    /// that fails — by stalling until the deadline — if the read path forgets
    /// `release_capacity`.
    #[tokio::test]
    async fn a_payload_past_the_default_window_still_completes() {
        const SIZE: usize = 512 * 1024;

        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(server_io, Script::Echo));
        let stream = within_deadline(open(client_io)).await;

        let payload: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let sent = payload.clone();
        let uplink = tokio::spawn(async move {
            writer.write_all(&sent).await.expect("uplink write");
            writer.flush().await.expect("uplink flush");
        });

        within_deadline(async {
            let mut echoed = vec![0u8; SIZE];
            reader.read_exact(&mut echoed).await.expect("downlink read");
            assert_eq!(echoed, payload);
        })
        .await;
        uplink.await.expect("the uplink task finishes");
    }

    /// A write bigger than one `Hunk` may carry is a short write, not a panic
    /// and not a message the peer would refuse.
    ///
    /// `AsyncWrite` allows a short write and `write_all` loops on one, so the
    /// caller loses nothing and nothing has to thread a `Result` back through
    /// the framing. The alternative the write path had was to encode it anyway,
    /// which puts a message on the wire past the 4 MiB a stock grpc-go peer
    /// receives (`grpc@v1.81.0/server.go:60,191`) — and past what our own
    /// `HunkDecoder` accepts, which is why the echo below fails outright
    /// without the clamp rather than merely returning the wrong count.
    ///
    /// Unreachable from this crate's relay, whose buffer is capped at 1 MiB
    /// (`crates/xray-core-rs/src/policy.rs:15`). But `poll_write` is public
    /// surface, and how big a caller's buffer is must not be a question of
    /// whether a proxy stays up.
    #[tokio::test]
    async fn a_write_past_the_hunk_limit_is_short_and_the_rest_follows() {
        let payload = vec![0x7e; MAX_HUNK_PAYLOAD_LEN + 1];

        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(server_io, Script::Echo));
        let stream = within_deadline(open(client_io)).await;

        // Read concurrently or the echo deadlocks: the peer stops reading the
        // request body while its own send is blocked on a window this side is
        // not reopening.
        let (mut reader, mut writer) = tokio::io::split(stream);
        let expected = payload.clone();
        let downlink = tokio::spawn(async move {
            let mut echoed = vec![0u8; expected.len()];
            reader.read_exact(&mut echoed).await.expect("downlink read");
            assert_eq!(echoed, expected, "the payload arrives whole");
        });

        within_deadline(async {
            // `write_all` would hide the short count by looping over it, so
            // the first write is driven by hand.
            let taken = poll_fn(|cx| Pin::new(&mut writer).poll_write(cx, &payload))
                .await
                .expect("the write is accepted");
            assert_eq!(
                taken, MAX_HUNK_PAYLOAD_LEN,
                "an over-long write is clamped, not framed whole"
            );

            writer
                .write_all(&payload[taken..])
                .await
                .expect("the tail follows in a second Hunk");
            writer.flush().await.expect("uplink flush");
        })
        .await;

        within_deadline(downlink)
            .await
            .expect("the downlink task finishes");
    }

    /// The read path's leftover buffer, which nothing else here reaches even
    /// though production takes that branch on almost every read:
    /// `copy_direction` starts with a 4 KiB buffer
    /// (`crates/xray-core-rs/src/policy.rs:13,187`) and a peer's `Hunk` may be
    /// up to 4 MiB, while every other test in this block sizes its buffer to
    /// the whole payload, so `pending_read_pos` never advances without also
    /// resetting.
    ///
    /// The byte pattern's period is 251, which divides neither the payload nor
    /// the buffer, so an offset the delivery loop got wrong by any amount
    /// shows up as a mismatch rather than as plausible-looking bytes.
    #[tokio::test]
    async fn a_hunk_larger_than_the_read_buffer_is_delivered_across_reads() {
        const SIZE: usize = 96 * 1024;
        const BUFFER: usize = 8 * 1024;

        let payload: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::Say(hunks(&[&payload]), trailers("0")),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            let mut buffer = vec![0u8; BUFFER];
            let mut reads = 0;
            loop {
                let len = stream.read(&mut buffer).await.expect("downlink read");
                if len == 0 {
                    break;
                }
                reads += 1;
                received.extend_from_slice(&buffer[..len]);
            }

            assert_eq!(received, payload);
            // One buffer-full per pass, so the payload really was carried
            // across reads rather than arriving as several smaller `Hunk`s.
            assert_eq!(reads, SIZE / BUFFER, "reads to drain one Hunk");
        })
        .await;
    }

    /// The header goes out even when the value is empty, which is not an edge
    /// case but Xray's default: `grpcSettings.user_agent` of `"golang"` maps to
    /// `""` (`Xray-core/transport/internet/grpc/dial.go:202-203`), and grpc-go
    /// appends the header unconditionally
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:578`). Dropping it
    /// instead is the obvious cleanup and changes what a censor sees, so it is
    /// pinned: `Some("")` is the header present and empty, `None` is it gone.
    #[tokio::test]
    async fn an_empty_user_agent_is_still_sent_as_a_header() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call_expecting(server_io, Script::Echo, PATH, ""));
        let mut stream = within_deadline(open_with_user_agent(client_io, "")).await;

        // The peer asserts the request line, so the call has to get far enough
        // for its handler to run and for a failed assertion to reach this test
        // as a stall or a broken stream rather than passing unnoticed.
        within_deadline(async {
            stream.write_all(b"ping").await.expect("uplink write");
            stream.flush().await.expect("uplink flush");
            let mut echoed = [0u8; 4];
            stream.read_exact(&mut echoed).await.expect("downlink read");
            assert_eq!(&echoed, b"ping");
        })
        .await;
    }

    /// The trap `HunkDecoder`'s doc comment names: a zero-length `Hunk` is a
    /// legal zero-byte write on Xray's side
    /// (`Xray-core/transport/internet/grpc/encoding/hunkconn.go:91-105`
    /// returns `(0, nil)` for it), but `Ok(0)` out of an `AsyncRead` means EOF.
    /// An adapter that forwards the empty payload loses everything after it.
    #[tokio::test]
    async fn an_empty_hunk_mid_stream_does_not_end_it() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::Say(hunks(&[b"before", b"", b"after"]), trailers("0")),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            stream
                .read_to_end(&mut received)
                .await
                .expect("read to eof");
            assert_eq!(received, b"beforeafter");
        })
        .await;
    }

    /// One `MultiHunk` message carrying `payloads` as its elements.
    ///
    /// `encode_hunk` frames one element and there is deliberately no encoder
    /// that frames several — our writer never batches, see its doc — so a
    /// batching peer has to be built here. The body is the elements' `0a
    /// <varint> <bytes>` groups back to back, which is what protobuf-go's
    /// `coderBytesSlice` emits and what `proto.Marshal` of Xray's own
    /// `encoding.MultiHunk` was checked to produce.
    fn multi_hunk(payloads: &[&[u8]]) -> Bytes {
        let mut body = Vec::new();
        for payload in payloads {
            body.extend_from_slice(&encode_hunk(payload)[5..]);
        }

        let mut message = vec![0x00];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes());
        message.extend_from_slice(&body);
        Bytes::from(message)
    }

    /// The bug a one-element writer cannot find. `multiMode` is not a different
    /// `:path` with the same payload behind it — `rpc TunMulti` carries
    /// `MultiHunk`, whose `data` is `repeated bytes`, and
    /// `MultiHunkReaderWriter.forceFetch` hands every element of it to
    /// `ReadMultiBuffer` (`Xray-core/transport/internet/grpc/encoding/
    /// multiconn.go:71-113`). A decoder still reading `Hunk` keeps only the
    /// last element of each message and drops the rest with no error, which on
    /// a tunnel is corruption the user finds somewhere else entirely.
    ///
    /// It has to be an end-to-end dial rather than a decoder test:
    /// `stream_grpc_framing_read_tests` pins what each mode does with the
    /// bytes, and this pins that `grpcSettings.multiMode` is what chooses the
    /// mode. The peer asserts the `:path` too, so the RPC named on the wire and
    /// the message read off it are checked to be the same choice.
    #[tokio::test]
    async fn multi_mode_delivers_every_element_of_a_multi_hunk() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call_expecting(
            server_io,
            Script::Say(
                vec![multi_hunk(&[b"first", b"second", b"third"])],
                trailers("0"),
            ),
            MULTI_PATH,
            USER_AGENT,
        ));
        let mut stream = within_deadline(open_in_multi_mode(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            stream
                .read_to_end(&mut received)
                .await
                .expect("read to eof");
            assert_eq!(received, b"firstsecondthird");
        })
        .await;
    }

    /// A gRPC call ends with a HEADERS frame carrying `grpc-status`, not with
    /// END_STREAM on a DATA frame. h2 reports that as `data()` yielding `None`
    /// while `is_end_stream()` is still false, so an adapter that watches
    /// `is_end_stream()` never sees the end and hangs here.
    #[tokio::test]
    async fn trailers_are_the_end_of_the_downlink() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::Say(hunks(&[b"tail"]), trailers("0")),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            stream
                .read_to_end(&mut received)
                .await
                .expect("read to eof");
            assert_eq!(received, b"tail");

            // EOF is sticky: a second read must not resurrect the stream.
            let mut after = [0u8; 8];
            assert_eq!(stream.read(&mut after).await.expect("read after eof"), 0);
        })
        .await;
    }

    /// grpc-go's server writes its response HEADERS only on the first message
    /// (`internal/transport/http2_server.go:1142-1146`), and Xray's inbound has
    /// nothing to say until the tunnel it opened does. So the dial must return
    /// with the response still outstanding — awaiting it would deadlock every
    /// connection against a real server.
    #[tokio::test]
    async fn the_dial_does_not_wait_for_the_response_headers() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(server_io, Script::Silent));

        let stream = within_deadline(open(client_io)).await;
        drop(stream);
    }

    /// Xray's reader separates the two: `Recv` returning `io.EOF` — which is
    /// what grpc-go gives for `grpc-status: 0` — is a clean end, and anything
    /// else becomes "failed to fetch hunk from gRPC tunnel"
    /// (`hunkconn.go:75-89`). Reporting a failed call as EOF would silently
    /// truncate a tunnel.
    #[tokio::test]
    async fn a_failed_grpc_status_is_an_error_not_an_eof() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::Say(hunks(&[b"partial"]), trailers("14")),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            let error = stream
                .read_to_end(&mut received)
                .await
                .expect_err("a failed call must not read as a clean eof");
            assert_eq!(received, b"partial");
            assert!(
                error.to_string().contains("14"),
                "the error should name the grpc-status, got: {error}"
            );
        })
        .await;
    }

    /// Reading again after a failed call reaches the same verdict, and says
    /// the same thing.
    ///
    /// A failed call leaves `eof` unset on purpose, so a caller that reads
    /// again comes back through the same decision — which is only worth doing
    /// if the decision survives. `poll_trailers` yields the block once and
    /// `None` for ever after (`h2-0.4.15/src/share.rs:425-436`), so a verdict
    /// read straight off that call is gone by the second read and the status
    /// the peer actually sent decays into "closed the stream without sending
    /// trailers" — a different complaint about a different fault, pointing a
    /// reader at the peer's framing instead of at the `grpc-status` it was
    /// handed.
    ///
    /// The Trailers-Only shapes are already immune, because the block they
    /// end on is the response head and `GrpcStream` keeps that. This is the
    /// ordinary shape: a peer that answered, sent something, and then failed.
    #[tokio::test]
    async fn a_second_read_after_a_failed_call_repeats_its_verdict() {
        const MESSAGE: &str = "the tunnel failed";

        let mut fields = trailers("13");
        fields.insert("grpc-message", MESSAGE.parse().expect("a legal header"));

        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::Say(hunks(&[b"partial"]), fields),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut buffer = [0u8; 16];
            let read = stream.read(&mut buffer).await.expect("the peer's message");
            assert_eq!(&buffer[..read], b"partial");

            let first = stream
                .read(&mut buffer)
                .await
                .expect_err("a failed call must not read as a clean eof");
            assert!(
                first.to_string().contains("13") && first.to_string().contains(MESSAGE),
                "the first read should carry the peer's status and message, got: {first}"
            );

            let second = stream
                .read(&mut buffer)
                .await
                .expect_err("a failed call is still failed on the second read");
            assert_eq!(
                second.to_string(),
                first.to_string(),
                "the second read reported a different fault than the first"
            );
        })
        .await;
    }

    /// Trailers that carry no `grpc-status` are a failed call, not a clean end.
    ///
    /// grpc-go opens the trailing header block at `grpcStatusCode =
    /// codes.Unknown` and builds the call's final status from whatever it still
    /// holds once the block is parsed
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:1481,1622`), so a
    /// status-less trailer is a non-OK status; `RecvMsg` then returns it in
    /// place of `io.EOF` (`stream.go:1174-1184`) and Xray turns that into
    /// "failed to fetch hunk from gRPC tunnel" (`hunkconn.go:75-89`). Reading
    /// it as EOF would hand a truncated response to the relay as a complete
    /// one.
    #[tokio::test]
    async fn trailers_without_a_grpc_status_are_an_error() {
        let mut unrelated = HeaderMap::new();
        unrelated.insert("x-note", "done".parse().expect("a legal header value"));

        for (name, trailers) in [("empty", HeaderMap::new()), ("unrelated", unrelated)] {
            let (client_io, server_io) = duplex(64 * 1024);
            tokio::spawn(serve_one_call(
                server_io,
                Script::Say(hunks(&[b"partial"]), trailers),
            ));
            let mut stream = within_deadline(open(client_io)).await;

            within_deadline(async {
                let mut received = Vec::new();
                let error = stream
                    .read_to_end(&mut received)
                    .await
                    .expect_err("a status-less call must not read as a clean eof");
                assert_eq!(received, b"partial", "{name} trailers");
                assert!(
                    error.to_string().contains("grpc-status"),
                    "{name} trailers: the error should name the missing status, got: {error}"
                );
            })
            .await;
        }
    }

    /// END_STREAM on a DATA frame with no trailing HEADERS behind it at all,
    /// which is the same class and equally not an EOF: grpc-go closes such a
    /// stream with `codes.Internal`, "server closed the stream without sending
    /// trailers" (`grpc@v1.81.0/internal/transport/http2_client.go:1244`).
    ///
    /// A real grpc-go peer always sends trailers, so this is the pathological
    /// path. It is still the one that matters: a truncated response we call
    /// success and xray-core calls an error is exactly the divergence that
    /// costs an afternoon of debugging someone else's server.
    #[tokio::test]
    async fn a_stream_that_ends_without_any_trailers_is_an_error() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::SayAndEndTheDataStream(hunks(&[b"partial"])),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            let error = stream
                .read_to_end(&mut received)
                .await
                .expect_err("a stream that ends without trailers must not read as a clean eof");
            assert_eq!(received, b"partial");
            // Not merely "trailers": the sibling complaint about trailers that
            // arrived without a status contains that word too, and this test
            // is only meaningful if it pins the branch that has none at all.
            assert!(
                error.to_string().contains("without sending trailers"),
                "the error should name the missing trailers, got: {error}"
            );
        })
        .await;
    }

    /// One entry of [`TRAILERS_ONLY_SHAPES`]: what to call it in a failure
    /// message, and the [`Script`] that puts it on the wire.
    type TrailersOnlyShape = (&'static str, fn(HeaderMap) -> Script);

    /// The two wire shapes a Trailers-Only response comes in, which every test
    /// of one runs against.
    ///
    /// They differ only in the `RST_STREAM(NO_ERROR)` grpc-go's server puts
    /// behind the header block whenever the client has not half-closed — see
    /// [`Script::TrailersOnlyThenReset`] — and a relay's uplink is open for
    /// the whole call, so the reset is the shape a real Xray inbound sends us.
    /// A grpc-go *client* reaches the same verdict for both, because
    /// `operateHeaders` has already closed the stream with the block's status
    /// by the time the reset is parsed
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:1618-1627`); h2 hands
    /// us the two looking nothing alike, so ours is the code that has to.
    const TRAILERS_ONLY_SHAPES: [TrailersOnlyShape; 2] = [
        ("the client half-closed first", Script::TrailersOnly),
        ("the client is still active", Script::TrailersOnlyThenReset),
    ];

    /// The sibling of the two above that must *not* be an error, and the one a
    /// real peer reaches: a Trailers-Only response saying the call went fine.
    ///
    /// grpc-go's server ends every RPC whose handler wrote nothing with a
    /// single END_STREAM header block — `:status 200`, `content-type`,
    /// `grpc-status` — and no DATA (`writeStatus`,
    /// `grpc@v1.81.0/internal/transport/http2_server.go:1082-1093`). Its client
    /// reads the status straight out of that block, since `operateHeaders`
    /// builds the call's status from whichever block carried END_STREAM
    /// (`http2_client.go:1487-1503,1617-1626`), so `RecvMsg` returns plain
    /// `io.EOF` (`stream.go:1174-1184`) and Xray passes it through as the end
    /// of the read (`hunkconn.go:75-89`).
    ///
    /// h2 gives us that block as the response head with no trailers behind it,
    /// so a client that only ever looked at `poll_trailers` would call a
    /// successful call broken. Reachable in a relay: the local side closes its
    /// write half, the uplink half-closes, and `Tun` returns having never seen
    /// a byte from the remote.
    ///
    /// Run against both shapes, because the verdict must not depend on the
    /// reset — see [`TRAILERS_ONLY_SHAPES`].
    #[tokio::test]
    async fn a_trailers_only_response_with_status_zero_is_a_clean_eof() {
        for (shape, script) in TRAILERS_ONLY_SHAPES {
            let (client_io, server_io) = duplex(64 * 1024);
            tokio::spawn(serve_one_call(server_io, script(trailers("0"))));
            let mut stream = within_deadline(open(client_io)).await;

            within_deadline(async {
                let mut received = Vec::new();
                if let Err(error) = stream.read_to_end(&mut received).await {
                    panic!("{shape}: a trailers-only success is the end of a call, not a broken one: {error}");
                }
                assert!(
                    received.is_empty(),
                    "{shape}: the peer sent no message, got: {received:?}"
                );

                let mut after = [0u8; 8];
                assert_eq!(
                    stream.read(&mut after).await.expect("read after eof"),
                    0,
                    "{shape}"
                );
            })
            .await;
        }
    }

    /// The same shape carrying a failure, which is how a `serviceName` typo
    /// surfaces: grpc-go's mux answers a service or method it does not serve
    /// with `codes.Unimplemented` and "unknown service …" or "unknown method …
    /// for service …" (`grpc@v1.81.0/server.go:1864-1879`), written through
    /// `WriteStatus` with nothing sent before it — a Trailers-Only response.
    /// The status the peer *did* send has to reach the user, or a mistyped
    /// `serviceName` reads as a server that hung up.
    ///
    /// The reset shape is the only one a typo actually produces — the client
    /// has not written a byte, let alone half-closed, when the mux answers —
    /// so a diagnostic that only survives the quiet shape is no diagnostic.
    #[tokio::test]
    async fn a_trailers_only_response_reports_the_status_it_carries() {
        const MESSAGE: &str = "unknown method Tun for service xray.grpc";

        for (shape, script) in TRAILERS_ONLY_SHAPES {
            let mut fields = trailers("12");
            fields.insert("grpc-message", MESSAGE.parse().expect("a legal header"));

            let (client_io, server_io) = duplex(64 * 1024);
            tokio::spawn(serve_one_call(server_io, script(fields)));
            let mut stream = within_deadline(open(client_io)).await;

            within_deadline(async {
                let mut received = Vec::new();
                let error = stream
                    .read_to_end(&mut received)
                    .await
                    .expect_err("a failed call must not read as a clean eof");
                assert!(
                    error.to_string().contains("12") && error.to_string().contains(MESSAGE),
                    "{shape}: the error should carry the peer's status and message, got: {error}"
                );
            })
            .await;
        }
    }

    /// And the same shape with no status in it at all, which grpc-go reads as
    /// `codes.Unknown` like any other status-less end (`grpcStatusCode =
    /// codes.Unknown`, `http2_client.go:1481`) rather than as the clean EOF the
    /// `grpc-status: 0` case is. Confirmed against a real grpc-go client, which
    /// answers this exact frame sequence with `Unknown` and an empty message.
    ///
    /// Both shapes fail, and this is the one place they say different things.
    /// A `grpc-status` is what tells the adapter that a reset-truncated head
    /// was a trailers block — see
    /// `GrpcStream::the_reset_behind_a_trailers_only_response` — so a head
    /// without one is indistinguishable from a peer that answered and then
    /// took the stream away, and the reset is what gets reported.
    #[tokio::test]
    async fn a_trailers_only_response_without_a_status_is_an_error() {
        let complaints = ["grpc-status", "downlink failed"];

        for ((shape, script), expected) in TRAILERS_ONLY_SHAPES.into_iter().zip(complaints) {
            let (client_io, server_io) = duplex(64 * 1024);
            tokio::spawn(serve_one_call(server_io, script(HeaderMap::new())));
            let mut stream = within_deadline(open(client_io)).await;

            within_deadline(async {
                let mut received = Vec::new();
                let error = stream
                    .read_to_end(&mut received)
                    .await
                    .expect_err("a status-less call must not read as a clean eof");
                assert!(
                    error.to_string().contains(expected),
                    "{shape}: the error should say {expected:?}, got: {error}"
                );
            })
            .await;
        }
    }

    /// A call the *server* ends first, which is the ordinary shape of one: an
    /// Xray inbound whose tunnel finished writes its trailers and, because the
    /// client has not half-closed yet, a `RST_STREAM(NO_ERROR)` right behind
    /// them (`rst := s.getState() == streamActive`,
    /// `grpc@v1.81.0/internal/transport/http2_server.go:1127-1129`). There is
    /// then no stream left to half-close, and h2 answers `send_data` on it with
    /// `UserError::InactiveStreamId`.
    ///
    /// That must not surface. `CloseSend` returns nil unconditionally
    /// (`grpc@v1.81.0/stream.go:1039-1052`), so Xray's own `Close` cannot fail
    /// here, and `relay_bidirectional` shuts the writer down on EOF and
    /// propagates whatever it returns — a completed tunnel would be reported as
    /// a failed relay, and the error aborting the select would drop a downlink
    /// still draining into the local socket.
    #[tokio::test]
    async fn a_half_close_after_the_peer_reset_the_stream_succeeds() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::SayThenReset(hunks(&[b"done"]), trailers("0")),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            stream
                .read_to_end(&mut received)
                .await
                .expect("read to eof");
            assert_eq!(received, b"done");

            // Reading to EOF only proves the trailers arrived, and the reset
            // is queued behind them — half-closing here would race it and pass
            // for the wrong reason. The driver finishing is the barrier that
            // does not race: the peer sends the reset before the `GOAWAY` that
            // ends the driver, and the driver parses frames in order.
            while !stream.connection_is_finished() {
                tokio::task::yield_now().await;
            }

            stream
                .shutdown()
                .await
                .expect("a peer that ended the call first is not a failed relay");
        })
        .await;
    }

    /// The same ending, reached from the state the uplink is actually in when
    /// it happens: mid-frame.
    ///
    /// A peer that has finished the RPC stopped reading the request body a
    /// while ago, so its flow-control window is shut and whatever the relay
    /// wrote last is still queued here — a write the relay gave up on, since a
    /// write that returned is a frame already handed over. Every path out of
    /// the call then runs
    /// the uplink drain before it gets anywhere near the half-close, and
    /// `poll_capacity` on a stream the peer took away reports the send half is
    /// no longer streaming (`h2-0.4.15/src/proto/streams/send.rs:366-369`). So
    /// the exemption has to cover the drain and not just the empty END_STREAM
    /// DATA frame, or it never runs: `copy_direction` reaches the shutdown
    /// through `writer.flush()` (`crates/xray-core-rs/src/policy.rs:196-200`)
    /// and both propagate.
    ///
    /// What must still fail is a *write*. `hc.Send` on a finished stream is an
    /// error on Xray's side too, and quietly accepting bytes no peer will ever
    /// read would lose them with nothing said.
    #[tokio::test]
    async fn a_half_close_over_a_frame_the_peer_will_never_take_succeeds() {
        // Four times the 65535-byte stream window, which the peer never
        // reopens, so the write is certain to leave a partial frame behind.
        const SIZE: usize = 256 * 1024;

        let (client_io, server_io) = duplex(64 * 1024);
        let (reached, arrived) = oneshot::channel();
        let (resume, awaited) = oneshot::channel();
        tokio::spawn(serve_one_call(
            server_io,
            Script::StallThenSayThenReset {
                reached,
                resume: awaited,
                chunks: hunks(&[b"done"]),
                trailers: trailers("0"),
            },
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            // The write itself is what cannot finish, and dropping it is what
            // leaves the frame half-delivered. `poll_write` hands the window's
            // worth over and parks for the rest — it reports a write only once
            // the whole `Hunk` is h2's — and the peer reads one frame and never
            // reopens the window, so it parks for good. Racing it against the
            // peer's report and then dropping it is the only way into this
            // state that does not require a peer that reopens.
            let payload = vec![0x5a; SIZE];
            tokio::select! {
                arrived = arrived => arrived.expect("the peer reports the first Hunk"),
                written = stream.write_all(&payload) => {
                    panic!("the peer never reopens the window, so this cannot finish: {written:?}")
                }
            }
            // Only now, with that write dropped and the rest of the frame
            // still queued, may the peer end the call.
            resume.send(()).expect("the peer is still waiting");

            let mut received = Vec::new();
            stream
                .read_to_end(&mut received)
                .await
                .expect("read to eof");
            assert_eq!(received, b"done");

            // The same barrier as the drained case: the reset is queued behind
            // the trailers, and the driver finishing is what proves it has
            // been parsed rather than raced.
            while !stream.connection_is_finished() {
                tokio::task::yield_now().await;
            }

            stream
                .flush()
                .await
                .expect("a peer that ended the call first is not a failed relay");
            stream
                .shutdown()
                .await
                .expect("a peer that ended the call first is not a failed relay");

            stream
                .write_all(b"late")
                .await
                .expect_err("bytes no peer will read must not be swallowed");
        })
        .await;
    }

    /// What `GrpcStream` owning both halves of the h2 stream buys, asserted
    /// from the peer's side rather than assumed.
    ///
    /// h2 emits `RST_STREAM` only once every reference to a stream is gone, so
    /// a refactor that parked the `RecvStream` somewhere else — a pool owning
    /// connections makes that plausible — would leave abandoned calls open on
    /// the server with nothing in this file failing. Dropping the stream is
    /// how a cancelled dial or a torn-down outbound tells the peer the call is
    /// over.
    #[tokio::test]
    async fn dropping_the_stream_tells_the_peer_the_call_is_over() {
        let (client_io, server_io) = duplex(64 * 1024);
        let (report, observed) = oneshot::channel();
        tokio::spawn(serve_one_call(
            server_io,
            Script::ReportHowTheUplinkEnded(report),
        ));

        let mut stream = within_deadline(open(client_io)).await;
        within_deadline(async {
            // The call has to be live in both directions first, or there is
            // nothing for the peer to have reset.
            stream.write_all(b"open").await.expect("uplink write");
            stream.flush().await.expect("uplink flush");
            let mut echoed = [0u8; 4];
            stream.read_exact(&mut echoed).await.expect("downlink read");
        })
        .await;
        drop(stream);

        let outcome = within_deadline(observed)
            .await
            .expect("the peer reports how the body ended");
        let error = outcome.expect_err("an abandoned call must be reset, not left half-open");
        assert_eq!(
            error.reason(),
            Some(h2::Reason::CANCEL),
            "the peer should see a cancellation, got: {error}"
        );
    }

    /// "Has the connection ended" is what the pool retires on, and the obvious
    /// question gives the wrong answer: h2 resolves its connection future as
    /// `Ok(())` after a graceful `GOAWAY`
    /// (`h2-0.4.15/src/proto/connection.rs:216-235`), so a pool that retired a
    /// connection only when the driver returned `Err` would keep handing out a
    /// dead one.
    ///
    /// `GrpcStream::connection_is_finished` is this block's window onto the
    /// same `JoinHandle` the pool reads through `H2Connection::is_live`; the
    /// pool's own view of it is `stream_grpc_pool_tests`'.
    #[tokio::test]
    async fn a_connection_whose_peer_went_away_reports_itself_finished() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(serve_one_call(server_io, Script::Silent));
        let stream = within_deadline(open(client_io)).await;
        assert!(
            !stream.connection_is_finished(),
            "a connection with a live call on it is not finished"
        );

        // Takes the peer's whole connection down, not just the call — the
        // driver ends either way, and this is the case a pool must not miss.
        server.abort();

        within_deadline(async {
            while !stream.connection_is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    /// The other half of the same distinction: a message the stream ended in
    /// the middle of. grpc-go turns an EOF inside a gRPC header into
    /// `io.ErrUnexpectedEOF` (`internal/transport/transport.go:360-380`), so a
    /// half-arrived `Hunk` must not read as a clean end either.
    #[tokio::test]
    async fn a_hunk_cut_short_by_the_end_of_the_stream_is_an_error() {
        let whole = encode_hunk(b"truncated");
        let cut = Bytes::from(whole[..whole.len() - 3].to_vec());

        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(serve_one_call(
            server_io,
            Script::Say(vec![cut], trailers("0")),
        ));
        let mut stream = within_deadline(open(client_io)).await;

        within_deadline(async {
            let mut received = Vec::new();
            stream
                .read_to_end(&mut received)
                .await
                .expect_err("a truncated message must not read as a clean eof");
        })
        .await;
    }
}

/// What one gRPC dial puts in its HEADERS frame.
///
/// Every value here was read back off a real grpc-go v1.81.0 client — Xray's
/// exact dial options, `insecure.NewCredentials()` and `WithAuthority`, against
/// a raw HTTP/2 framer that decodes the block and prints it — rather than
/// traced through `createHeaderFields`. That run emitted these seven fields in
/// this order and nothing else:
///
/// ```text
/// :method       "POST"
/// :scheme       "http"
/// :path         "/xray.grpc/Tun"
/// :authority    "grpc.example.com"
/// content-type  "application/grpc"
/// user-agent    "Mozilla/5.0 the-user-agent"
/// te            "trailers"
/// ```
///
/// **Only two of them are load-bearing for the server.** grpc-go's checks that
/// `:method` is POST (`internal/transport/http2_server.go:548-556`) and that
/// `content-type` is exactly `application/grpc` or continues with `+` or `;`
/// (`http2_server.go:420-427,495-497`, through
/// `internal/grpcutil/method.go:61-78`) — `application/grpc-web` shares the
/// prefix and is refused by the `switch` on the byte after it. `te` is never
/// looked at. Everything else is here to fit the population a censor sees,
/// not to interoperate, so none of it is dead weight to be optimised away.
///
/// **The order above is grpc-go's, and ours is not.** Nothing in this block can
/// see that — `http::request::Parts` has thrown the order away by the time a
/// test reads it — so it is recorded here. Captured off the wire from both
/// clients, same authority, same user agent, same seven fields, the two HEADERS
/// payloads come to 65 bytes each and differ in exactly three places:
///
/// ```text
/// grpc-go  83 86 45 8b <path> 41 8c <authority> 5f 8b <type> 7a 8a <ua> 40 02 7465 86 <trailers>
/// ours     83 86 41 8c <authority> 04 8b <path> 5f 8b <type> 7a 8a <ua> 40 82 497f 86 <trailers>
/// ```
///
/// * `:authority` before `:path`. h2 emits the pseudo-headers from a fixed
///   iterator — method, scheme, authority, path
///   (`h2-0.4.15/src/frame/headers.rs:707-721`) — while grpc-go appends them
///   method, scheme, path, authority
///   (`grpc@v1.81.0/internal/transport/http2_client.go:573-579`).
/// * grpc-go indexes `:path` (`45`: literal *with* incremental indexing, off
///   static name 5), so it also lands in the dynamic table. h2 hard-codes
///   `Header::Path(..) => true` in `skip_value_index`
///   (`h2-0.4.15/src/hpack/header.rs:189-207`), so ours is always `04`,
///   literal *without* indexing off static name 4, and the table never sees
///   it — which will make the divergence grow, not shrink, on the second call
///   over a pooled connection.
/// * grpc-go writes the literal name `te` raw (`02 74 65`), because
///   `appendHpackString` Huffman-codes only a string the coding shortens and
///   at two bytes it does not (`x/net@v0.53.0/http2/hpack/encode.go:218-230`).
///   h2 Huffman-codes it regardless (`82 49 7f`).
///
/// None of the three is ours to change — they are h2's frame writer and HPACK
/// encoder, not this file's — so they are written down rather than asserted.
/// Task 11's byte fixtures should expect them instead of reading them as a
/// regression.
mod stream_grpc_request_headers_tests {
    use std::time::Duration;

    use h2::server;
    use http::Method;
    use tokio::io::{duplex, DuplexStream};
    use tokio::sync::oneshot;
    use xray_transport::stream::grpc_test_only::{
        grpc_request_path, open_grpc_h2_stream, HunkMode,
    };
    use xray_transport::stream::{
        apply_masquerade, resolve_user_agent, Authority, GrpcConfig, HeaderMap, HeaderValue,
    };
    use xray_transport::BoxedTransportStream;

    const DEADLINE: Duration = Duration::from_secs(10);
    /// A literal, so `resolve_user_agent` hands it back untouched and the case
    /// under test is never the user agent unless a test says so.
    const USER_AGENT: &str = "grpc-go/1.81.0";

    /// The four fields this block varies. The keepalive triple and
    /// `initial_windows_size` are left at zero throughout: nothing on the dial
    /// path reads them yet, and a value that changed no byte of the request
    /// would only suggest one did.
    ///
    /// Neither `expect` is a shortcut around an error path. `authority` is an
    /// [`Authority`] and `user_agent` is a [`HeaderValue`], so a value that is
    /// not one cannot be built into a config here or anywhere else — which is
    /// the whole of [`an_authority_that_is_not_an_authority_never_reaches_a_dial`],
    /// and, for the user agent, of
    /// [`super::stream_grpc_user_agent_validity_tests`].
    fn config(authority: &str) -> GrpcConfig {
        GrpcConfig {
            service_name: "xray.grpc".to_owned(),
            multi_mode: false,
            authority: authority.parse().expect("a literal authority"),
            user_agent: resolve_user_agent(Some(USER_AGENT)).expect("a sendable user agent"),
            idle_timeout_secs: 0,
            health_check_timeout_secs: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
        }
    }

    /// The head of the one call `config` opens.
    ///
    /// Nothing is answered: the dial does not wait for a response
    /// (`h2client.rs`), so the HEADERS frame is on the wire by the time
    /// `open_grpc_h2_stream` returns, and the stream is dropped straight after.
    async fn captured_head(config: &GrpcConfig) -> http::request::Parts {
        let (client_io, server_io) = duplex(64 * 1024);
        let (send_head, head) = oneshot::channel();
        tokio::spawn(capture_one_head(server_io, send_head));

        let dial = async {
            let stream = open_grpc_h2_stream(Box::new(client_io) as BoxedTransportStream, config)
                .await
                .expect("the POST opens");
            let head = head.await.expect("the peer captured the request head");
            drop(stream);
            head
        };
        tokio::time::timeout(DEADLINE, dial)
            .await
            .expect("the dial completes rather than stalling")
    }

    /// Reports the first request's head and then keeps the connection polled.
    ///
    /// h2's server `Connection` is the connection — no frame is read unless
    /// `accept` is being polled — so the loop at the end is what lets the
    /// client's RST_STREAM and GOAWAY land instead of stalling the duplex.
    async fn capture_one_head(io: DuplexStream, send_head: oneshot::Sender<http::request::Parts>) {
        let mut connection = server::handshake(io).await.expect("server handshake");
        let (request, respond) = connection
            .accept()
            .await
            .expect("a call arrives")
            .expect("a well-formed request");
        let (head, body) = request.into_parts();
        send_head.send(head).expect("the test is still waiting");

        // Held rather than dropped so the call stays open while the client
        // decides it is done with it.
        let _held = (body, respond);
        while connection.accept().await.is_some() {}
    }

    /// The `User-Agent` the masquerade block puts on a WebSocket request for
    /// this profile, which is the value the gRPC table must agree with.
    ///
    /// Asserting against that rather than against a copy of the format string
    /// is the point of the test: `utils.ChromeUA` and the UA
    /// `applyMasqueradedHeaders` writes are the same Go variable
    /// (`Xray-core/common/utils/browser.go:123,136`), so a gRPC dial and a
    /// WebSocket dial out of one install have to claim the same browser
    /// version. Two Chrome majors from one process is a stronger signal than
    /// either user agent alone.
    fn masqueraded_user_agent(keyword: Option<&str>) -> String {
        let mut headers = HeaderMap::new();
        if let Some(keyword) = keyword {
            headers.set("User-Agent", keyword);
        }
        apply_masquerade(&mut headers, "ws");
        headers
            .get("User-Agent")
            .expect("the profile sets a User-Agent")
            .to_owned()
    }

    /// [`resolve_user_agent`], with its "this arm cannot fail" claim checked
    /// rather than unwrapped past.
    ///
    /// Three of the table's arms hand back a value the masquerade draw
    /// produced, and nothing in `resolve_user_agent` proves a draw is a
    /// sendable header value — its doc points here for exactly that. Routing
    /// every keyword through this means a template that ever grew a control
    /// character fails the test that says it cannot, rather than an outbound
    /// build months later.
    fn resolved(keyword: Option<&str>) -> HeaderValue {
        resolve_user_agent(keyword).unwrap_or_else(|error| {
            panic!("the table resolved {keyword:?} to a value no header can carry: {error}")
        })
    }

    fn header<'a>(head: &'a http::request::Parts, name: &str) -> Option<&'a str> {
        head.headers
            .get(name)
            .map(|value| value.to_str().expect("a printable header value"))
    }

    #[tokio::test]
    async fn the_request_head_carries_exactly_what_grpc_go_sends() {
        let head = captured_head(&config("grpc.example.com")).await;

        assert_eq!(head.method, Method::POST, ":method");
        // `:scheme` is `http` even when the connection underneath is TLS, and
        // this transport has no way to learn otherwise: Xray dials gRPC with
        // `insecure.NewCredentials()` and wraps the socket itself in the dial
        // option's `WithContextDialer`
        // (`Xray-core/transport/internet/grpc/dial.go:103-157`), so grpc-go
        // believes it is speaking plaintext and says so in the pseudo-header.
        // `open_grpc_h2_stream` takes an already-secured stream and hard-codes
        // the same `http`, which is why a TLS variant of this test would prove
        // nothing there is not a knob for.
        assert_eq!(head.uri.scheme_str(), Some("http"), ":scheme");
        assert_eq!(head.uri.path(), "/xray.grpc/Tun", ":path");
        assert_eq!(
            head.uri.authority().map(|authority| authority.as_str()),
            Some("grpc.example.com"),
            ":authority"
        );

        assert_eq!(header(&head, "content-type"), Some("application/grpc"));
        assert_eq!(header(&head, "user-agent"), Some(USER_AGENT));
        assert_eq!(header(&head, "te"), Some("trailers"));

        // The three above are *all* the ordinary headers there are. Counting
        // them is what makes this test say "exactly": the absences below are
        // the three worth naming, but a fourth header nobody thought of is
        // just as visible to a censor comparing us against grpc-go.
        assert_eq!(
            head.headers.len(),
            3,
            "an unexpected header joined the request: {:?}",
            head.headers
        );

        // Absent on purpose, all three:
        //
        // * `grpc-accept-encoding` carries grpc-go's compressor registry and is
        //   skipped when that is empty (`internal/transport/http2_client.go:
        //   556,597-599`, over `grpcutil.RegisteredCompressorNames`, which only
        //   `encoding.RegisterCompressor` ever appends to). Nothing under
        //   `Xray-core/transport/internet/grpc/` imports a compressor, so it is
        //   empty and the header is never built. Confirmed in the run above:
        //   `encoding.GetCompressor("gzip")` was nil and no such field arrived.
        // * `grpc-timeout` is written only for a context with a deadline
        //   (`http2_client.go:600-608`), and nothing on Xray's outbound dial
        //   path installs one — there is no `context.WithTimeout` between the
        //   proxy handler and `internet.Dial`.
        // * `content-length` is never sent for a streaming RPC, and would be a
        //   lie for a tunnel whose length is not known when it opens.
        for absent in ["grpc-accept-encoding", "grpc-timeout", "content-length"] {
            assert_eq!(header(&head, absent), None, "{absent} must not be sent");
        }
    }

    /// `multiMode` picks a different stream name, so the `:path` is derived per
    /// dial from the config rather than resolved once when it is built
    /// (`Xray-core/transport/internet/grpc/dial.go:59-72`).
    #[tokio::test]
    async fn multi_mode_changes_the_path_the_dial_derives() {
        let mut config = config("grpc.example.com");
        config.multi_mode = true;

        let head = captured_head(&config).await;
        assert_eq!(
            head.uri.path(),
            grpc_request_path("xray.grpc", HunkMode::Multi),
            ":path"
        );
        assert_eq!(head.uri.path(), "/xray.grpc/TunMulti", ":path");
    }

    /// A `:path` that needs escaping has to survive the URI assembly.
    ///
    /// `stream_grpc_path_tests` pins around thirty escaped paths and every one
    /// of them stops at the string. The dial does not send a string: it hands
    /// the path to `path_and_query`, which parses it, and h2 rebuilds a `Uri`
    /// from the pseudo-headers on the far side. That seam is where a `%2F`
    /// could be decoded back into a separator or a leading `//` could be
    /// folded, and neither block would notice.
    ///
    /// An empty `serviceName` is the case that matters most: it is proto3's
    /// default, so `//Tun` is the common shape and not an exotic one. `$&+:=@`
    /// is the other end — Go's `encodePathSegment` keeps all six unescaped, and
    /// `@` and `:` are exactly what a parser handed the whole URI as one string
    /// would try to read as userinfo and a port.
    #[tokio::test]
    async fn a_path_that_needs_escaping_reaches_the_wire_intact() {
        for (service_name, mode, expected) in [
            ("", HunkMode::Single, "//Tun"),
            ("", HunkMode::Multi, "//TunMulti"),
            ("a/b", HunkMode::Single, "/a%2Fb/Tun"),
            ("$&+:=@", HunkMode::Single, "/$&+:=@/Tun"),
            (
                "/m y/sa !mple/pa\\th/tun\\_serv!ice",
                HunkMode::Single,
                "/m%20y/sa%20%21mple/pa%5Cth/tun%5C_serv%21ice",
            ),
        ] {
            let mut config = config("grpc.example.com");
            config.service_name = service_name.to_owned();
            config.multi_mode = mode == HunkMode::Multi;

            let head = captured_head(&config).await;
            assert_eq!(
                head.uri.path(),
                expected,
                ":path for serviceName {service_name:?} {mode:?}"
            );
            // The literal above is the wire; this is the claim that the wire is
            // what `grpc_request_path` said, so the two cannot drift apart
            // without one of them failing.
            assert_eq!(
                head.uri.path(),
                grpc_request_path(service_name, mode),
                "serviceName {service_name:?} {mode:?}"
            );
        }
    }

    /// Xray's switch, `dial.go:193-205`.
    ///
    /// The two easy inversions are both here. An **unset** user agent is not
    /// the empty case — `case "chrome", ""` maps it to the Chrome persona, so
    /// the default gRPC dial claims to be a browser. The one value that empties
    /// the header is `golang`. Xray's own comment above the switch says setting
    /// a browser UA on gRPC is not recommended, because browsers cannot
    /// initiate gRPC; we match the behaviour anyway, because parity with the
    /// population is the goal rather than defensible taste.
    #[test]
    fn the_user_agent_table_resolves_the_way_xrays_switch_does() {
        assert_eq!(resolved(None), masqueraded_user_agent(None));
        assert_eq!(
            resolved(Some("chrome")),
            masqueraded_user_agent(Some("chrome"))
        );
        // Xray cannot tell an absent `user_agent` from an empty one — both
        // leave the Go string `""` and hit the same `case "chrome", ""` — so
        // the empty string is Chrome too, not an empty header.
        assert_eq!(resolved(Some("")), masqueraded_user_agent(None));
        assert_eq!(
            resolved(Some("firefox")),
            masqueraded_user_agent(Some("firefox"))
        );
        assert_eq!(resolved(Some("edge")), masqueraded_user_agent(Some("edge")));
        assert_eq!(resolved(Some("golang")), "");

        // Everything else falls off the switch untouched, `safari` and `curl`
        // included: those are masquerade keywords, and the gRPC table does not
        // know them.
        for verbatim in ["safari", "curl", "grpc-go/1.81.0", "Chrome", " chrome"] {
            assert_eq!(resolved(Some(verbatim)), verbatim);
        }
    }

    /// Every arm of the table, end to end.
    ///
    /// `golang` is the one worth the wire trip: it resolves to the empty
    /// string, and the header still goes out, because grpc-go appends it
    /// unconditionally (`http2_client.go:578`). `Some("")` below is the header
    /// present and empty; `None` would be it gone.
    #[tokio::test]
    async fn every_resolved_user_agent_reaches_the_wire_verbatim() {
        for configured in [
            None,
            Some("chrome"),
            Some("firefox"),
            Some("edge"),
            Some("golang"),
            Some("grpc-go/1.81.0"),
        ] {
            let expected = resolved(configured);
            let mut config = config("grpc.example.com");
            config.user_agent = expected.clone();

            let head = captured_head(&config).await;
            assert_eq!(
                header(&head, "user-agent"),
                Some(expected.to_str().expect("a printable user agent")),
                "user_agent {configured:?}"
            );
        }
    }

    /// The authority is already resolved by the time it reaches the dial — the
    /// precedence chain is `build_transport_layer`'s — so all this side owes it
    /// is to send it untouched.
    ///
    /// A port and a bracketed IPv6 literal both survive on grpc-go's side:
    /// `initAuthority` takes a `WithAuthority` verbatim, with no escaping at
    /// all (`grpc@v1.81.0/clientconn.go:1977-1978`), and the `host:port`
    /// fallback it drops to when Xray configures no authority — which is where
    /// a bracketed literal actually comes from, via `net.JoinHostPort` at
    /// `dial.go:181-189` — goes through `encodeAuthority`, whose escape set
    /// spares `:`, `[`, `]` and `@` (`clientconn.go:1889-1942`). Both were
    /// confirmed against a real client: `[2001:db8::1]:443` arrives as itself.
    #[tokio::test]
    async fn a_resolved_authority_reaches_the_wire_untouched() {
        for authority in [
            "grpc.example.com",
            "example.com:443",
            "[2001:db8::1]:443",
            "127.0.0.1:443",
        ] {
            let head = captured_head(&config(authority)).await;
            assert_eq!(
                head.uri.authority().map(|value| value.as_str()),
                Some(authority),
                ":authority"
            );
        }
    }

    /// The other half of that: an authority that is not one has to be refused
    /// rather than quietly reshape the request.
    ///
    /// It is refused by the type, which is why this is a parse test and not a
    /// dial test. `grpcSettings.authority` is free-form JSON that the config
    /// layer only drops when empty
    /// (`crates/xray-config/src/parser.rs:2869-2872`), but it is also static —
    /// resolved once, when the outbound is built — so `GrpcConfig::authority`
    /// is an [`Authority`] and none of the vectors below can be built into a
    /// config at all. Reporting that refusal is `build_transport_layer`'s, and
    /// so is its test; what this pins is that the type is still the boundary
    /// that makes the bug unrepresentable.
    ///
    /// **Three of the four are the regression.** Interpolated into one URI
    /// string, `example.com/api` re-partitions into authority `example.com`
    /// with path `/api/xray.grpc/Tun`; `example.com?q=1` leaves the path a bare
    /// `/` and carries the gRPC method off in a query, `q=1/xray.grpc/Tun`; and
    /// `example.com#frag` leaves the path a bare `/` with the method gone
    /// entirely. Each is a call to a method nobody configured, answered by an
    /// UNIMPLEMENTED that names nothing. `exa mple.com` never had that problem:
    /// `"http://exa mple.com/xray.grpc/Tun"` is not a URI either, so the old
    /// interpolation already failed it. It is here as the edge of the same
    /// check, not as a case that ever silently reshaped anything.
    ///
    /// A divergence from grpc-go, deliberately: it validates a `WithAuthority`
    /// not at all (`grpc@v1.81.0/clientconn.go:1976-1978`) and, confirmed on
    /// the wire, sends `:authority: example.com/api` verbatim with the `:path`
    /// intact. `Authority` cannot hold a `/`, so copying that is not on the
    /// table; refusing the config is the option that remains.
    #[test]
    fn an_authority_that_is_not_an_authority_never_reaches_a_dial() {
        for authority in [
            "example.com/api",
            "example.com?q=1",
            "example.com#frag",
            "exa mple.com",
        ] {
            assert!(
                authority.parse::<Authority>().is_err(),
                "{authority:?} must not be representable as a dialled authority"
            );
        }
    }
}

/// Our wire against the Go oracle's, one committed fixture at a time.
///
/// Every test here reads `tests/fixtures/grpc/`, which
/// `tools/reality-oracle/grpc/grpc_wire.go` captures off one live grpc-go dial
/// and `scripts/verify-oracle-fixtures.py` regenerates in CI's `go-oracles`
/// job. Reading the committed copy rather than spawning `go run` is what lets
/// these run in the plain `cargo test --workspace` job instead of behind
/// `#[ignore]`; the regeneration is what stops the committed copy drifting
/// away from what grpc-go now emits. Neither half can move alone, which is the
/// same split `reality_rustls_tests` runs on.
///
/// **Three of the four artefacts are byte-exact and one is not**, and the test
/// names say which. The preamble and both framing sets are compared byte for
/// byte. The HEADERS block cannot be: `h2` and grpc-go disagree twice over on
/// how to *encode* the same seven fields, so the field list is the bar and our
/// own encoding is pinned separately — see
/// [`the_first_headers_block_carries_the_oracles_fields_but_not_its_bytes`]
/// and [`our_pseudo_header_order_is_pinned_where_it_diverges_from_grpc_gos`].
mod stream_grpc_oracle_tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use h2::server;
    use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::sync::oneshot;
    use xray_transport::stream::grpc_test_only::{
        encode_hunk, grpc_request_path, open_grpc_h2_stream, HunkDecoder, HunkMode,
    };
    use xray_transport::stream::{GrpcConfig, HeaderValue};
    use xray_transport::BoxedTransportStream;

    const CONNECTION_PREAMBLE_JSON: &str =
        include_str!("../../../tests/fixtures/grpc/connection_preamble.json");
    const REQUEST_HEADERS_JSON: &str =
        include_str!("../../../tests/fixtures/grpc/request_headers.json");
    const HUNK_FRAMING_JSON: &str = include_str!("../../../tests/fixtures/grpc/hunk_framing.json");
    const MULTI_HUNK_FRAMING_JSON: &str =
        include_str!("../../../tests/fixtures/grpc/multi_hunk_framing.json");

    /// A dial that stalls hangs the whole run, so each one is fenced the way
    /// `stream_grpc_h2_tests` fences its exchanges.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// RFC 9113 section 3.4, and `grpc@v1.81.0/internal/transport/
    /// http_util.go:53`. Held as a constant so the frame reader can step over
    /// it; the fixture's own copy is what
    /// [`the_connection_preamble_matches_the_go_oracle_byte_for_byte`]
    /// compares against.
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    const FRAME_HEADERS: u8 = 0x1;
    const FRAME_SETTINGS: u8 = 0x4;
    const FRAME_WINDOW_UPDATE: u8 = 0x8;
    const FLAG_ACK: u8 = 0x1;
    const FLAG_END_HEADERS: u8 = 0x4;
    const FLAG_PADDED: u8 = 0x8;
    const FLAG_PRIORITY: u8 = 0x20;
    const FRAME_HEADER_LEN: usize = 9;

    /// The first index HPACK's dynamic table occupies: entries 1 through 61
    /// are the static table, and 62 upwards are whatever this connection has
    /// already sent (RFC 7541 sections 2.3.3 and 6).
    const FIRST_DYNAMIC_TABLE_INDEX: u64 = 62;

    /// `payload_rule` as `grpc_wire.go:157` states it. The vectors record no
    /// payload bytes — they are a literal suffix of `message_hex` — so this
    /// string is the whole of the contract for rebuilding them, and a rule
    /// that changed under us would otherwise be compared against silently
    /// wrong input.
    const PAYLOAD_RULE: &str = "payload[i] = i mod 256";
    /// The same for `MultiHunk` (`grpc_wire.go:196`). The element index is in
    /// the rule so that two elements of one length are not the same bytes.
    const MULTI_PAYLOAD_RULE: &str = "payload[element][i] = (i + element) mod 256";

    /// The increment on the one frame our opening burst carries and grpc-go's
    /// does not: the 16 MiB connection window `h2client.rs` opens with, less
    /// HTTP/2's own default of 65535, which is the window already granted
    /// (RFC 9113 6.9.2).
    ///
    /// Spelled out rather than read off `CONNECTION_WINDOW_SIZE`, because an
    /// expectation derived from the value under test asserts nothing: this has
    /// to fail if that constant moves, which is the whole point of declaring
    /// the divergence rather than exempting it.
    const OUR_CONNECTION_WINDOW_INCREMENT: u32 = 16 * 1024 * 1024 - 65535;

    #[derive(serde::Deserialize)]
    struct PreambleFixture {
        preface_hex: String,
        preface_text: String,
        settings_frame_hex: String,
        frames_before_first_headers: Vec<FrameDescriptor>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
    struct FrameDescriptor {
        r#type: String,
        flags: Vec<String>,
        stream_id: u32,
        payload_len: usize,
    }

    impl FrameDescriptor {
        fn is_settings_ack(&self) -> bool {
            self.r#type == "SETTINGS" && self.flags.iter().any(|flag| flag == "ACK")
        }
    }

    #[derive(serde::Deserialize)]
    struct HeadersFixture {
        call: CallShape,
        headers: Vec<HeaderField>,
    }

    #[derive(serde::Deserialize)]
    struct CallShape {
        service_name: String,
        stream_name: String,
        authority: String,
        user_agent: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
    struct HeaderField {
        name: String,
        value: String,
    }

    #[derive(serde::Deserialize)]
    struct FramingFixture {
        payload_rule: String,
        vectors: Vec<HunkVector>,
    }

    #[derive(serde::Deserialize)]
    struct HunkVector {
        payload_len: usize,
        message_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct MultiFramingFixture {
        call: MultiCallShape,
        payload_rule: String,
        vectors: Vec<MultiHunkVector>,
    }

    #[derive(serde::Deserialize)]
    struct MultiCallShape {
        service_name: String,
        stream_name: String,
        path: String,
    }

    #[derive(serde::Deserialize)]
    struct MultiHunkVector {
        element_lens: Vec<usize>,
        message_hex: String,
    }

    fn request_headers_fixture() -> HeadersFixture {
        serde_json::from_str(REQUEST_HEADERS_JSON).expect("the request headers fixture decodes")
    }

    /// The dial the oracle made, as this side's configuration.
    ///
    /// `user_agent` is the fixture's literal, put into the config as it stands
    /// rather than through [`resolve_user_agent`](xray_transport::stream::resolve_user_agent).
    /// That is the claim this block is allowed to make: the transport sends
    /// the string it is handed. Xray's default resolves to a date-derived,
    /// CPU-seeded Chrome UA that no fixture can pin without the version-drift
    /// classifier the masquerade family carries, so the oracle dials a literal
    /// on purpose (`grpc_wire.go:79-89`) and the table that maps `chrome`,
    /// `golang` and the rest stays where it is already pinned, in
    /// `stream_grpc_request_headers_tests`'
    /// `the_user_agent_table_resolves_the_way_xrays_switch_does`.
    fn oracle_config(call: &CallShape) -> GrpcConfig {
        GrpcConfig {
            service_name: call.service_name.clone(),
            multi_mode: false,
            authority: call
                .authority
                .parse()
                .expect("the oracle dialled an authority"),
            user_agent: HeaderValue::from_str(&call.user_agent)
                .expect("the oracle dialled a sendable user agent"),
            idle_timeout_secs: 0,
            health_check_timeout_secs: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
        }
    }

    /// The peer's end of a connection, and every byte the client sent it.
    ///
    /// The oracle taps the client's socket for the same reason
    /// (`grpc_wire.go`, `recordingConn`): all four artefacts are about what a
    /// client *writes*, and taking both the raw bytes and the decoded request
    /// off one dial means recording on the way past. Only reads are recorded,
    /// because a read on this end is a write on the client's.
    struct RecordingIo {
        peer: DuplexStream,
        recorded: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for RecordingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let outcome = Pin::new(&mut this.peer).poll_read(cx, buf);
            if outcome.is_ready() {
                this.recorded
                    .lock()
                    .expect("the recording mutex is not poisoned")
                    .extend_from_slice(&buf.filled()[before..]);
            }
            outcome
        }
    }

    impl AsyncWrite for RecordingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.peer).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.peer).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.peer).poll_shutdown(cx)
        }
    }

    /// One dial's opening bytes and the request the peer decoded out of them.
    struct FirstCall {
        written: Vec<u8>,
        head: http::request::Parts,
    }

    /// Dials `config` on a connection of its own and returns its first call.
    ///
    /// **This harness never pools, and that is the point.** Only the first
    /// stream on a connection has a virgin HPACK table: by stream 3 the
    /// dynamic table holds `:authority`, `content-type`, `user-agent` and
    /// `te`, and the block is mostly back-references. Comparing one of those
    /// with the oracle's first block would be comparing two different things
    /// and passing while asserting nothing.
    /// [`open_grpc_h2_stream`] is the unpooled dial — it drops its
    /// `SendRequest` so the connection dies with the one call — so a fresh
    /// table is structural here rather than a matter of test ordering, and
    /// [`the_compared_headers_block_is_the_first_one_on_the_connection`]
    /// asserts it outright anyway.
    async fn capture_the_first_call(config: &GrpcConfig) -> FirstCall {
        let (client_io, peer_io) = duplex(64 * 1024);
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let (send_head, head) = oneshot::channel();
        tokio::spawn(serve_one_head(
            RecordingIo {
                peer: peer_io,
                recorded: Arc::clone(&recorded),
            },
            send_head,
        ));

        let dial = async {
            let stream = open_grpc_h2_stream(Box::new(client_io) as BoxedTransportStream, config)
                .await
                .expect("the POST opens");
            let head = head.await.expect("the peer captured the request head");
            drop(stream);
            head
        };
        let head = tokio::time::timeout(DEADLINE, dial)
            .await
            .expect("the dial completes rather than stalling");

        // Taken after the head arrived, which is what makes the bytes
        // complete: the peer cannot have decoded the HEADERS block before
        // `poll_read` handed it — and so recorded — every byte of it.
        let written = recorded
            .lock()
            .expect("the recording mutex is not poisoned")
            .clone();
        FirstCall { written, head }
    }

    /// Reports the first request's head and then keeps the connection polled,
    /// so the client's RST_STREAM and GOAWAY land instead of stalling.
    async fn serve_one_head(io: RecordingIo, send_head: oneshot::Sender<http::request::Parts>) {
        let mut connection = server::handshake(io).await.expect("server handshake");
        let (request, respond) = connection
            .accept()
            .await
            .expect("a call arrives")
            .expect("a well-formed request");
        let (head, body) = request.into_parts();
        send_head.send(head).expect("the test is still waiting");

        let _held = (body, respond);
        while connection.accept().await.is_some() {}
    }

    /// One HTTP/2 frame, read the way the oracle's `readFrame` reads one.
    struct Http2Frame<'a> {
        kind: u8,
        flags: u8,
        stream_id: u32,
        payload: &'a [u8],
        raw: &'a [u8],
    }

    impl Http2Frame<'_> {
        fn is_settings_ack(&self) -> bool {
            self.kind == FRAME_SETTINGS && self.flags & FLAG_ACK != 0
        }

        fn describe(&self) -> FrameDescriptor {
            FrameDescriptor {
                r#type: frame_type_name(self.kind),
                flags: describe_flags(self.kind, self.flags),
                stream_id: self.stream_id,
                payload_len: self.payload.len(),
            }
        }
    }

    /// RFC 9113 section 11.2. Anything unregistered is printed as its number
    /// rather than guessed at, so a frame `h2` starts sending shows up as a
    /// diff instead of a plausible-looking name — `frameTypeName` in the
    /// oracle, for the same reason.
    fn frame_type_name(kind: u8) -> String {
        match kind {
            0x0 => "DATA".to_owned(),
            0x1 => "HEADERS".to_owned(),
            0x2 => "PRIORITY".to_owned(),
            0x3 => "RST_STREAM".to_owned(),
            0x4 => "SETTINGS".to_owned(),
            0x5 => "PUSH_PROMISE".to_owned(),
            0x6 => "PING".to_owned(),
            0x7 => "GOAWAY".to_owned(),
            0x8 => "WINDOW_UPDATE".to_owned(),
            0x9 => "CONTINUATION".to_owned(),
            other => format!("UNKNOWN(0x{other:02x})"),
        }
    }

    /// The oracle's `describeFlags`: only the one flag an opening burst can
    /// carry is named, and any other bit is printed raw.
    fn describe_flags(kind: u8, flags: u8) -> Vec<String> {
        let mut named = Vec::new();
        let mut remaining = flags;
        if kind == FRAME_SETTINGS && flags & FLAG_ACK != 0 {
            named.push("ACK".to_owned());
            remaining &= !FLAG_ACK;
        }
        if remaining != 0 {
            named.push(format!("0x{remaining:02x}"));
        }
        named
    }

    /// Every whole frame the client wrote after the preface.
    ///
    /// A frame still in flight when the tap was read is dropped rather than
    /// reported, exactly as `parseCapture` drops one: everything asserted on
    /// here is at or before the first HEADERS, which the peer had already
    /// decoded.
    fn frames_after_the_preface(written: &[u8]) -> Vec<Http2Frame<'_>> {
        let mut rest = written
            .strip_prefix(PREFACE)
            .expect("the client opens with the HTTP/2 connection preface");
        let mut frames = Vec::new();
        while rest.len() >= FRAME_HEADER_LEN {
            let length =
                (usize::from(rest[0]) << 16) | (usize::from(rest[1]) << 8) | usize::from(rest[2]);
            let total = FRAME_HEADER_LEN + length;
            if rest.len() < total {
                break;
            }
            frames.push(Http2Frame {
                kind: rest[3],
                flags: rest[4],
                stream_id: u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]) & !(1 << 31),
                payload: &rest[FRAME_HEADER_LEN..total],
                raw: &rest[..total],
            });
            rest = &rest[total..];
        }
        frames
    }

    /// The call's HEADERS frame: its stream id and its HPACK block.
    fn first_headers_frame(written: &[u8]) -> (u32, &[u8]) {
        let frames = frames_after_the_preface(written);
        let headers = frames
            .iter()
            .find(|frame| frame.kind == FRAME_HEADERS)
            .expect("the client opened a call");
        assert_ne!(
            headers.flags & FLAG_END_HEADERS,
            0,
            "the block spans CONTINUATION frames, which this test does not join"
        );
        assert_eq!(
            headers.flags & (FLAG_PADDED | FLAG_PRIORITY),
            0,
            "the frame is padded or carries a priority section, which this test does not strip"
        );
        (headers.stream_id, headers.payload)
    }

    /// One HPACK representation, reduced to what these tests read off it.
    ///
    /// The names are never decoded, and do not need to be: `h2` huffman-codes
    /// every literal string it writes (`h2-0.4.15/src/hpack/encoder.rs:
    /// 216-224`), but it takes every *name* from the table by index, because
    /// all seven fields of a gRPC request have their name there. So the field
    /// a representation names is an index, and an index is all that
    /// [`our_pseudo_header_order_is_pinned_where_it_diverges_from_grpc_gos`]
    /// and [`the_compared_headers_block_is_the_first_one_on_the_connection`]
    /// need. Values are stepped over by their length prefix.
    #[derive(Debug)]
    enum Representation {
        /// `1xxxxxxx`: name and value both from the table.
        Indexed { index: u64 },
        /// A literal value, its name either from the table or spelled out.
        Literal { name_index: Option<u64> },
        /// `001xxxxx`: an instruction to the decoder's table that names no
        /// field at all.
        TableSizeUpdate,
    }

    impl Representation {
        /// The table entry this representation names, if it names one.
        fn table_index(&self) -> Option<u64> {
            match self {
                Representation::Indexed { index } => Some(*index),
                Representation::Literal { name_index } => *name_index,
                Representation::TableSizeUpdate => None,
            }
        }

        /// The pseudo-header this representation names, if it names one.
        ///
        /// Static entries 1 through 7 are the request pseudo-headers, two of
        /// them twice over: `:method` is 2 (`GET`) and 3 (`POST`), `:path` is
        /// 4 (`/`) and 5 (`/index.html`), `:scheme` is 6 (`http`) and 7
        /// (`https`) (RFC 7541 appendix A).
        fn pseudo_header_name(&self) -> Option<&'static str> {
            match self.table_index()? {
                1 => Some(":authority"),
                2 | 3 => Some(":method"),
                4 | 5 => Some(":path"),
                6 | 7 => Some(":scheme"),
                _ => None,
            }
        }
    }

    /// Walks a HEADERS block into its representations, in order.
    fn read_hpack_representations(block: &[u8]) -> Vec<Representation> {
        let mut rest = block;
        let mut representations = Vec::new();
        while let Some(&first) = rest.first() {
            // RFC 7541 section 6. Each form's index shares its first byte with
            // the bits that pick the form, so the prefix width goes with it.
            // `0000xxxx` (without indexing) and `0001xxxx` (never indexed) are
            // two instructions to the decoder's table and one shape here.
            let (literal, prefix_bits) = if first & 0b1000_0000 != 0 {
                (false, 7)
            } else if first & 0b1100_0000 == 0b0100_0000 {
                (true, 6)
            } else if first & 0b1110_0000 == 0b0010_0000 {
                representations.push(Representation::TableSizeUpdate);
                rest = read_hpack_integer(rest, 5).1;
                continue;
            } else {
                (true, 4)
            };

            let (index, after_index) = read_hpack_integer(rest, prefix_bits);
            rest = after_index;
            if !literal {
                representations.push(Representation::Indexed { index });
                continue;
            }

            if index == 0 {
                rest = skip_hpack_string(rest);
            }
            rest = skip_hpack_string(rest);
            representations.push(Representation::Literal {
                name_index: (index != 0).then_some(index),
            });
        }
        representations
    }

    /// RFC 7541 section 5.1: a value that fills the prefix continues into as
    /// many seven-bit groups as it needs.
    fn read_hpack_integer(bytes: &[u8], prefix_bits: u32) -> (u64, &[u8]) {
        assert!(
            !bytes.is_empty(),
            "an HPACK integer starts past the end of the block"
        );
        let mask = (1u64 << prefix_bits) - 1;
        let mut value = u64::from(bytes[0]) & mask;
        let mut rest = &bytes[1..];
        if value != mask {
            return (value, rest);
        }

        let mut shift = 0;
        loop {
            let (&byte, tail) = rest
                .split_first()
                .expect("an HPACK integer runs past the end of the block");
            rest = tail;
            value += u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return (value, rest);
            }
        }
    }

    /// Steps over one string literal, huffman-coded or not: the top bit of the
    /// length byte says which, and the length is a seven-bit prefix integer
    /// either way (RFC 7541 section 5.2).
    fn skip_hpack_string(bytes: &[u8]) -> &[u8] {
        let (length, rest) = read_hpack_integer(bytes, 7);
        let length = usize::try_from(length).expect("an HPACK string length fits a usize");
        assert!(
            rest.len() >= length,
            "an HPACK string runs past the end of the block"
        );
        &rest[length..]
    }

    /// The request the peer decoded, as the oracle records a field list: the
    /// four pseudo-headers first because that is where HTTP/2 puts them, then
    /// the ordinary ones.
    fn decoded_fields(head: &http::request::Parts) -> Vec<HeaderField> {
        let field = |name: &str, value: &str| HeaderField {
            name: name.to_owned(),
            value: value.to_owned(),
        };
        let mut fields = vec![
            field(":method", head.method.as_str()),
            field(
                ":scheme",
                head.uri.scheme_str().expect("the request carries a scheme"),
            ),
            field(
                ":authority",
                head.uri
                    .authority()
                    .expect("the request carries an authority")
                    .as_str(),
            ),
            field(
                ":path",
                head.uri
                    .path_and_query()
                    .expect("the request carries a path")
                    .as_str(),
            ),
        ];
        for (name, value) in &head.headers {
            fields.push(field(
                name.as_str(),
                value.to_str().expect("a printable header value"),
            ));
        }
        fields
    }

    /// The fields that are not pseudo-headers, in the order they were given.
    ///
    /// HTTP/2 puts the pseudo-headers first and forbids one after an ordinary
    /// field (RFC 9113 8.3), so this is the tail of the block on either side.
    /// For [`decoded_fields`] it is the peer's decode order, and so `h2`'s
    /// write order: `HeaderMap` iterates in insertion order, h2's server
    /// inserts as it decodes, and h2's client encodes what it iterates.
    fn ordinary_tail(fields: &[HeaderField]) -> Vec<&HeaderField> {
        fields
            .iter()
            .filter(|field| !field.name.starts_with(':'))
            .collect()
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(
            hex.len().is_multiple_of(2),
            "a fixture hex string of odd length {}",
            hex.len()
        );
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&hex[index..index + 2], 16).expect("a fixture hex byte")
            })
            .collect()
    }

    /// [`PAYLOAD_RULE`], as `payloadOf` applies it.
    fn payload_of(length: usize) -> Vec<u8> {
        (0..length).map(|index| index as u8).collect()
    }

    /// [`MULTI_PAYLOAD_RULE`], as `multiPayloadOf` applies it.
    fn multi_payload_of(element: usize, length: usize) -> Vec<u8> {
        (0..length).map(|index| (index + element) as u8).collect()
    }

    /// Reads `tests/fixtures/grpc/connection_preamble.json`, which
    /// `grpc_wire.go -wire connection_preamble` regenerates against live
    /// grpc-go.
    ///
    /// **The preface and the SETTINGS frame agree to the byte; the burst
    /// carries one frame more than grpc-go's.** Under Xray's defaults
    /// grpc-go's opening burst is the 24-byte preface and an *empty*
    /// SETTINGS frame: `initialWindowSize` reaches the wire only above
    /// grpc-go's own default and `MaxHeaderListSize` only when a dial option
    /// sets it (`grpc@v1.81.0/internal/transport/http2_client.go:433-451`),
    /// and Xray configures neither by default. A default `h2` client writes
    /// the same nine bytes, because `Settings::default()` leaves every field
    /// `None` (`h2-0.4.15/src/frame/settings.rs:6-17`) and `handshake2`
    /// buffers exactly that frame (`src/client.rs:1322-1325`). Nine bytes of
    /// agreement is worth pinning precisely because it is so easy to lose: one
    /// `Builder` knob applied unconditionally and the connection announces
    /// itself.
    ///
    /// **The SETTINGS ACK the fixture also records is filtered out of both
    /// sides.** It is a reply to the *server's* SETTINGS, not an initiative,
    /// and where it falls relative to the call's HEADERS is timing rather than
    /// shaping: grpc-go queues it before `newHTTP2Client` returns and so always
    /// sends it first, while `h2`'s handshake deliberately does not wait for
    /// the peer's SETTINGS (`h2-0.4.15/src/client.rs:1165-1166`), which leaves
    /// our ACK racing the request. Comparing the burst without it still fails
    /// on the thing worth catching — a PRIORITY, a second SETTINGS, a second
    /// WINDOW_UPDATE — while the byte comparison above covers the frame's
    /// contents.
    ///
    /// **The `WINDOW_UPDATE(stream 0)` is ours, declared here rather than
    /// excused.** It is the cost of `CONNECTION_WINDOW_SIZE` in `h2client.rs`
    /// — the connection window opened so that one flow which stops reading
    /// cannot hold the window every other flow on the outbound shares; see
    /// `stream_grpc_flow_control_tests`. The fixture is left alone, because it
    /// is the record of what grpc-go emits and should go on telling the truth
    /// about upstream; the *expectation* is the fixture's burst plus this one
    /// frame. So a second divergence, or a change to this one's stream, length
    /// or increment, still fails.
    #[tokio::test]
    async fn the_connection_preamble_matches_the_go_oracle_byte_for_byte() {
        let fixture: PreambleFixture =
            serde_json::from_str(CONNECTION_PREAMBLE_JSON).expect("the preamble fixture decodes");
        let call = capture_the_first_call(&oracle_config(&request_headers_fixture().call)).await;

        let preface = decode_hex(&fixture.preface_hex);
        assert_eq!(
            preface,
            fixture.preface_text.as_bytes(),
            "the fixture's two spellings of the preface disagree"
        );
        assert_eq!(
            call.written.get(..preface.len()),
            Some(&preface[..]),
            "the HTTP/2 connection preface"
        );

        let frames = frames_after_the_preface(&call.written);
        let settings = frames
            .first()
            .expect("the client writes a frame after the preface");
        assert_eq!(
            settings.raw,
            decode_hex(&fixture.settings_frame_hex),
            "the client's own SETTINGS frame"
        );

        assert!(
            frames.iter().any(|frame| frame.kind == FRAME_HEADERS),
            "the capture never reached the call's HEADERS frame, so there is no burst to bound"
        );
        let ours: Vec<FrameDescriptor> = frames
            .iter()
            .take_while(|frame| frame.kind != FRAME_HEADERS)
            .filter(|frame| !frame.is_settings_ack())
            .map(Http2Frame::describe)
            .collect();
        let mut expected: Vec<FrameDescriptor> = fixture
            .frames_before_first_headers
            .iter()
            .filter(|frame| !frame.is_settings_ack())
            .cloned()
            .collect();
        // Appended rather than folded into the fixture, and appended is also
        // where it belongs on the wire: h2 raises the connection window on the
        // `Connection` before its first poll (`h2-0.4.15/src/client.rs:
        // 1345-1348`), so the frame follows the SETTINGS the handshake already
        // flushed.
        expected.push(FrameDescriptor {
            r#type: "WINDOW_UPDATE".to_owned(),
            flags: Vec::new(),
            stream_id: 0,
            payload_len: 4,
        });
        assert_eq!(
            ours, expected,
            "grpc-go's opening burst plus our one declared extra frame, ACKs aside"
        );

        let window_update = frames
            .iter()
            .find(|frame| frame.kind == FRAME_WINDOW_UPDATE)
            .expect("the burst the assertion above matched carries a WINDOW_UPDATE");
        assert_eq!(
            window_update.payload,
            OUR_CONNECTION_WINDOW_INCREMENT.to_be_bytes(),
            "the connection-window increment (RFC 9113 6.9)"
        );
    }

    /// Reads `tests/fixtures/grpc/request_headers.json`, which
    /// `grpc_wire.go -wire request_headers` regenerates against live grpc-go.
    ///
    /// **The fields and their values, not the bytes**, and the fixture is the
    /// decoded field list for that reason. Our HPACK block differs from
    /// grpc-go's twice over, and neither divergence is reachable without
    /// forking `h2`:
    ///
    /// * it writes the pseudo-headers in the order its own `Pseudo` iterator
    ///   yields them, method, scheme, authority, path
    ///   (`h2-0.4.15/src/frame/headers.rs:704-731`), where grpc-go puts
    ///   `:path` before `:authority`; and
    /// * it encodes `:path` as a literal *without* indexing, because
    ///   `skip_value_index` returns true for `Header::Path`
    ///   (`h2-0.4.15/src/hpack/header.rs:189-208`, logic borrowed from
    ///   nghttp2), where grpc-go indexes it incrementally.
    ///
    /// Both were measured against a live client when the header block was
    /// written. What stops them drifting into a third shape that is neither
    /// ours nor grpc-go's is
    /// [`our_pseudo_header_order_is_pinned_where_it_diverges_from_grpc_gos`],
    /// not this test.
    ///
    /// **Past the pseudo-headers the two clients agree, so that tail is
    /// compared in order rather than as a set.** grpc-go appends
    /// `content-type`, `user-agent`, `te`
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:577-579`) and so do
    /// we, but only because `build_grpc_call`
    /// (`crates/xray-transport/src/stream/grpc/h2client.rs:291-293`) makes
    /// three `.header()` calls in that order: `HeaderMap` iterates in insertion
    /// order and `h2` encodes what it iterates, so swapping two of those lines
    /// changes the bytes on the wire *and* the dynamic-table insertion order
    /// every later stream on the connection back-references. Unlike the
    /// pseudo-headers there is no divergence here to excuse, which is exactly
    /// why sorting it away would be wrong: this is an order we chose and can
    /// lose.
    ///
    /// `user-agent` is the oracle's literal on both sides, which is the claim
    /// this makes about it: the transport sends the string it is handed. See
    /// [`oracle_config`] for why the fixture cannot carry Xray's default.
    #[tokio::test]
    async fn the_first_headers_block_carries_the_oracles_fields_but_not_its_bytes() {
        let fixture = request_headers_fixture();
        assert_eq!(
            fixture.call.stream_name, "Tun",
            "this test dials single mode, so the fixture has to be the `Tun` capture"
        );
        let recorded_path = fixture
            .headers
            .iter()
            .find(|field| field.name == ":path")
            .expect("the fixture records a :path")
            .value
            .clone();
        assert_eq!(
            recorded_path,
            grpc_request_path(&fixture.call.service_name, HunkMode::Single),
            "the RPC grpc-go named and the one our path builder derives"
        );

        let call = capture_the_first_call(&oracle_config(&fixture.call)).await;
        let mut ours = decoded_fields(&call.head);
        let mut theirs = fixture.headers;

        assert_eq!(
            ordinary_tail(&ours),
            ordinary_tail(&theirs),
            "the order the ordinary headers go out in"
        );

        // Only now sorted: the pseudo-header order is the one thing here that
        // legitimately differs, and it is asserted on its own.
        ours.sort();
        theirs.sort();
        assert_eq!(ours, theirs, "the decoded field list grpc-go sends");
    }

    /// Reads `tests/fixtures/grpc/request_headers.json`, regenerated by
    /// `grpc_wire.go -wire request_headers`.
    ///
    /// **Not a comparison — a pin on each side separately.** The two orders
    /// are known to differ, so comparing them would only restate that. What a
    /// set comparison cannot catch is our order drifting to a third one that
    /// neither client emits, which an `h2` bump reordering the `Pseudo`
    /// iterator (`h2-0.4.15/src/frame/headers.rs:704-731`) would do silently:
    /// the fields would still all be there with the right values, and
    /// [`the_first_headers_block_carries_the_oracles_fields_but_not_its_bytes`]
    /// would still pass. The grpc-go side is pinned off the fixture for the
    /// same reason the oracle bothers to record the order at all — a
    /// divergence excused as known has to stay the one that was measured.
    #[tokio::test]
    async fn our_pseudo_header_order_is_pinned_where_it_diverges_from_grpc_gos() {
        let fixture = request_headers_fixture();
        let call = capture_the_first_call(&oracle_config(&fixture.call)).await;

        let (_stream_id, block) = first_headers_frame(&call.written);
        let ours: Vec<&str> = read_hpack_representations(block)
            .iter()
            .filter_map(Representation::pseudo_header_name)
            .collect();
        assert_eq!(
            ours,
            [":method", ":scheme", ":authority", ":path"],
            "the order `h2` writes the pseudo-headers in"
        );

        let theirs: Vec<&str> = fixture
            .headers
            .iter()
            .map(|field| field.name.as_str())
            .filter(|name| name.starts_with(':'))
            .collect();
        assert_eq!(
            theirs,
            [":method", ":scheme", ":path", ":authority"],
            "the order grpc-go writes them in, as the oracle recorded it"
        );
    }

    /// The invariant the two header tests above stand on: the block they
    /// compare is the *first* on its connection.
    ///
    /// Only a virgin HPACK table makes our block and the oracle's comparable.
    /// The oracle's is stream 1 of a fresh connection, and a warmed one would
    /// answer with something else entirely: `h2` indexes `:authority`,
    /// `content-type`, `user-agent` and `te` incrementally, so by stream 3
    /// most of the block is back-references into the dynamic table and the
    /// field *set* is unchanged while the bytes are unrecognisable. A test
    /// that let a pooled connection supply the block would pass while
    /// comparing two different things.
    ///
    /// Both halves are asserted rather than assumed: the stream id is 1, and
    /// every table index in the block is inside the static table, so the block
    /// is decodable with no connection history at all.
    #[tokio::test]
    async fn the_compared_headers_block_is_the_first_one_on_the_connection() {
        let call = capture_the_first_call(&oracle_config(&request_headers_fixture().call)).await;

        let (stream_id, block) = first_headers_frame(&call.written);
        assert_eq!(
            stream_id, 1,
            "the compared block has to be the connection's first stream"
        );

        let representations = read_hpack_representations(block);
        // A dynamic-table size update is legal at the head of a block and names
        // no field, so it is filtered out rather than counted: `h2` emitting
        // one on some future bump should not be reported as a field appearing.
        let fields = representations
            .iter()
            .filter(|representation| !matches!(representation, Representation::TableSizeUpdate))
            .count();
        assert_eq!(
            fields, 7,
            "the block should hold one representation per field: {representations:?}"
        );
        for representation in &representations {
            assert!(
                representation
                    .table_index()
                    .is_none_or(|index| index < FIRST_DYNAMIC_TABLE_INDEX),
                "the block reaches into the dynamic table, so it is not a fresh \
                 connection's: {representation:?}"
            );
        }
    }

    /// Reads `tests/fixtures/grpc/hunk_framing.json`, which
    /// `grpc_wire.go -wire hunk_framing` regenerates against live grpc-go.
    ///
    /// Each vector is one `hc.Send(&Hunk{Data: ...})` as it left the wire,
    /// reassembled from the call's DATA frames, so the 16 KiB vector is one
    /// message across two frames rather than two messages — which is why the
    /// read side is asserted from the same bytes: a decoder that split on
    /// frames rather than on the length prefix would come apart there and
    /// nowhere else.
    #[test]
    fn the_hunk_framing_vectors_match_the_go_oracle_byte_for_byte() {
        let fixture: FramingFixture =
            serde_json::from_str(HUNK_FRAMING_JSON).expect("the hunk framing fixture decodes");
        assert_eq!(
            fixture.payload_rule, PAYLOAD_RULE,
            "the oracle changed how it builds the payloads it does not record"
        );

        for vector in &fixture.vectors {
            let payload = payload_of(vector.payload_len);
            let expected = decode_hex(&vector.message_hex);

            assert_eq!(
                encode_hunk(&payload),
                expected,
                "the message for a {} byte payload",
                vector.payload_len
            );

            let mut decoder = HunkDecoder::new(HunkMode::Single);
            decoder.push(&expected);
            assert_eq!(
                decoder.next_payload().expect("a legal Hunk"),
                Some(payload),
                "the payload read back out of a {} byte message",
                vector.payload_len
            );
            assert_eq!(decoder.buffered_len(), 0, "the message was consumed whole");
        }
    }

    /// Reads `tests/fixtures/grpc/multi_hunk_framing.json`, which
    /// `grpc_wire.go -wire multi_hunk_framing` regenerates against live
    /// grpc-go.
    ///
    /// **The read side is the whole point of this fixture.** A `MultiHunk`
    /// carrying one element marshals to the bytes a `Hunk` of that payload
    /// does, so the write side has nothing new to say and only the vectors of
    /// one element or none have a write counterpart at all: [`encode_hunk`]
    /// emits one element per message by design, because `poll_write` is handed
    /// one contiguous slice per call and holding a write back for a sibling
    /// that may never come would buy a few bytes of protobuf overhead at the
    /// cost of latency. What only the multi-element vectors can show is that
    /// every element reaches the caller — and, in the same bytes, what a
    /// single-mode decoder would silently do with them instead.
    #[test]
    fn the_multi_hunk_framing_vectors_are_read_and_reproduced_as_the_go_oracle_wrote_them() {
        let fixture: MultiFramingFixture = serde_json::from_str(MULTI_HUNK_FRAMING_JSON)
            .expect("the multi hunk framing fixture decodes");
        assert_eq!(
            fixture.payload_rule, MULTI_PAYLOAD_RULE,
            "the oracle changed how it builds the elements it does not record"
        );
        assert_eq!(
            fixture.call.stream_name, "TunMulti",
            "these vectors have to be the `TunMulti` capture"
        );
        assert_eq!(
            fixture.call.path,
            grpc_request_path(&fixture.call.service_name, HunkMode::Multi),
            "the RPC grpc-go named and the one our path builder derives"
        );

        for vector in &fixture.vectors {
            let elements: Vec<Vec<u8>> = vector
                .element_lens
                .iter()
                .enumerate()
                .map(|(element, length)| multi_payload_of(element, *length))
                .collect();
            let expected = decode_hex(&vector.message_hex);
            let lengths = &vector.element_lens;

            let mut decoder = HunkDecoder::new(HunkMode::Multi);
            decoder.push(&expected);
            assert_eq!(
                decoder.next_payload().expect("a legal MultiHunk"),
                Some(elements.concat()),
                "every element of a MultiHunk of {lengths:?} reaches the caller, in order"
            );
            assert_eq!(decoder.buffered_len(), 0, "the message was consumed whole");

            if elements.len() > 1 {
                // The cost of getting the mode wrong, in grpc-go's own bytes:
                // `Hunk.data` is a singular `bytes`, so protobuf-go assigns
                // each occurrence over the last rather than appending
                // (`protobuf@v1.36.11/internal/impl/codec_gen.go:5489-5500`),
                // and a single-mode decoder on a `TunMulti` call hands the
                // caller the tail of every message with nothing logged.
                let mut wrong_mode = HunkDecoder::new(HunkMode::Single);
                wrong_mode.push(&expected);
                assert_eq!(
                    wrong_mode.next_payload().expect("a legal Hunk"),
                    elements.last().cloned(),
                    "single mode over a MultiHunk of {lengths:?} keeps only the last element"
                );
            } else {
                assert_eq!(
                    encode_hunk(elements.first().map_or(&[][..], Vec::as_slice)),
                    expected,
                    "the message for a MultiHunk of {lengths:?}"
                );
            }
        }
    }
}

/// The `grpcSettings.user_agent` boundary: which values this transport will
/// carry, held against which values a real grpc-go peer will accept.
///
/// [`xray_transport::stream::GrpcConfig::user_agent`] is a [`HeaderValue`] so
/// that an unsendable user agent is refused once, when the outbound is built,
/// instead of on every dial for as long as the config stands. The whole
/// justification for refusing rather than passing the string through is that
/// the value was unusable anyway — that the set `HeaderValue` rejects is the
/// set a grpc-go peer rejects. That is a claim about two predicates in two
/// languages, in two dependencies that move independently, and nothing else in
/// this repository would notice if either changed its mind.
///
/// This block is what notices. It is the only Rust-side reader of
/// `tests/fixtures/grpc/user_agent_validity.json`, which
/// `tools/reality-oracle/grpc/grpc_user_agent.go` regenerates from sixteen real
/// grpc-go dials — one per case, because the user agent is fixed when the
/// connection is built and sixteen values mean sixteen connections.
mod stream_grpc_user_agent_validity_tests {
    use xray_transport::stream::{resolve_user_agent, HeaderValue};

    const USER_AGENT_VALIDITY_JSON: &str =
        include_str!("../../../tests/fixtures/grpc/user_agent_validity.json");

    #[derive(serde::Deserialize)]
    struct ValidityFixture {
        cases: Vec<ValidityCase>,
    }

    #[derive(serde::Deserialize)]
    struct ValidityCase {
        name: String,
        /// Hex, not a string: `high_byte_0x80` is a lone `0x80`, which is not
        /// valid UTF-8 and so not representable in JSON at all.
        user_agent_hex: String,
        /// Whether grpc-go's client encoded the configured bytes into its
        /// HEADERS block unchanged.
        sent_verbatim: bool,
        /// Whether the peer's handler received the tunnel's first message.
        /// False means the stream was reset before the handler was entered.
        peer_received_message: bool,
    }

    fn fixture() -> ValidityFixture {
        serde_json::from_str(USER_AGENT_VALIDITY_JSON).expect("the committed validity fixture")
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(
            hex.len().is_multiple_of(2),
            "a fixture hex string of odd length {}",
            hex.len()
        );
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&hex[index..index + 2], 16).expect("a fixture hex byte")
            })
            .collect()
    }

    /// The claim the type rests on: `HeaderValue` accepts a user agent exactly
    /// when a grpc-go peer does.
    ///
    /// Both directions matter and they fail differently. A value `HeaderValue`
    /// rejects and the peer accepts is a profile that runs on xray-core and not
    /// here — a parity gap. A value `HeaderValue` accepts and the peer rejects
    /// is worse: a config we called fine that fails every flow at the far end,
    /// which is the failure this whole change exists to stop reporting one dial
    /// at a time.
    #[test]
    fn the_header_value_boundary_is_the_peers_boundary() {
        let fixture = fixture();
        assert_eq!(
            fixture.cases.len(),
            16,
            "the fixture covers every transition of the predicate"
        );

        for case in fixture.cases {
            let bytes = decode_hex(&case.user_agent_hex);
            assert_eq!(
                HeaderValue::from_bytes(&bytes).is_ok(),
                case.peer_received_message,
                "{}: `http` and grpc-go disagree about {:?}",
                case.name,
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    /// grpc-go's client does not validate what `WithUserAgent` was given.
    ///
    /// Recorded and asserted because it is what makes the case above a
    /// *boundary* rather than a coincidence. If the client sanitised the string
    /// instead, the peer would be judging a value the config never named, and
    /// agreeing with `HeaderValue` about it would mean nothing.
    #[test]
    fn grpc_go_sends_every_user_agent_it_is_given_verbatim() {
        for case in fixture().cases {
            assert!(
                case.sent_verbatim,
                "{}: grpc-go no longer sends the configured user agent unchanged",
                case.name
            );
        }
    }

    /// Every case the peer refuses is a case this transport refuses to build a
    /// config from, and every case it accepts is one we will dial with.
    ///
    /// The test above is about `HeaderValue`; this one is about the function
    /// the outbound actually calls, which is the thing a regression would go
    /// through. The two are only the same while `resolve_user_agent`'s verbatim
    /// arm stays verbatim — which is the arm Xray's switch defines
    /// (`dial.go:193-205`) and the arm every case here lands on, none of them
    /// being a keyword.
    ///
    /// `high_byte_0x80` is skipped, and only that one: a lone `0x80` is not
    /// valid UTF-8, so it cannot survive JSON parsing into a `String` and no
    /// profile can express it. It stays in the fixture because grpc-go's
    /// verdict on it is what places the top of the accepted range.
    #[test]
    fn resolve_user_agent_refuses_exactly_what_the_peer_refuses() {
        for case in fixture().cases {
            let bytes = decode_hex(&case.user_agent_hex);
            let Ok(configured) = String::from_utf8(bytes) else {
                assert_eq!(
                    case.name, "high_byte_0x80",
                    "a new case is unrepresentable in a config and says nothing about why"
                );
                continue;
            };

            assert_eq!(
                resolve_user_agent(Some(&configured)).is_ok(),
                case.peer_received_message,
                "{}: the resolved user agent disagrees with the peer",
                case.name
            );
        }
    }
}

/// The pool and the dial seam: where a gRPC connection comes from, and what
/// the connection-level settings put on the wire.
///
/// These run over a loopback `TcpListener` rather than a `duplex` pair,
/// because the thing under test is `TransportDialer::connect_stream` — the one
/// seam every transport shares, and the only one that reaches Android's
/// `VpnService.protect(fd)`. A test that handed the pool a socket directly
/// would prove nothing about where the socket came from.
mod stream_grpc_pool_tests {
    use std::future::poll_fn;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use h2::server::{self, SendResponse};
    use h2::{Reason, RecvStream, SendStream};
    use http::{HeaderMap, HeaderValue, Response};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::{TcpListener, TcpStream};
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::stream::grpc_test_only::{open_grpc_h2_stream, resolve_keepalive};
    use xray_transport::stream::{GrpcConfig, GrpcTransport, TransportLayer};
    use xray_transport::{BoxedTransportStream, ConnectorConfig, TransportDialer};

    /// Every test here can stall rather than fail, so each is fenced by a
    /// deadline the way `stream_grpc_h2_tests` is.
    const DEADLINE: Duration = Duration::from_secs(10);
    /// The same fence for the `start_paused` tests, which wait out keepalive
    /// intervals measured in tens of seconds: it has to clear those rather
    /// than race them, and under paused time the extra minutes cost nothing —
    /// the runtime jumps to whichever timer is nearest, so a test that stops
    /// making progress hits this immediately in wall-clock terms.
    const PAUSED_DEADLINE: Duration = Duration::from_secs(600);
    /// RFC 9113 3.4.
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    /// RFC 9113 6.5.2.
    const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
    const SETTINGS_FRAME: u8 = 0x4;
    const PING_FRAME: u8 = 0x6;
    /// RFC 9113 6.7.
    const PING_ACK: u8 = 0x1;
    /// A SETTINGS frame with no entries: length 0, type SETTINGS, no flags,
    /// stream 0 (RFC 9113 4.1, 6.5).
    const EMPTY_SETTINGS_FRAME: &[u8] = &[0, 0, 0, SETTINGS_FRAME, 0, 0, 0, 0, 0];
    /// Six intervals at grpc-go's ten-second floor — long enough that a
    /// keepalive which was ever going to fire has, and free under paused time.
    const SEVERAL_INTERVALS: Duration = Duration::from_secs(60);

    async fn within_deadline<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(DEADLINE, future)
            .await
            .expect("the exchange completes rather than stalling")
    }

    async fn within_paused_deadline<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(PAUSED_DEADLINE, future)
            .await
            .expect("the exchange completes rather than stalling")
    }

    fn config() -> GrpcConfig {
        GrpcConfig {
            service_name: "xray.grpc".to_owned(),
            multi_mode: false,
            authority: "grpc.example.com".parse().expect("a literal authority"),
            user_agent: HeaderValue::from_static("grpc-go/1.81.0"),
            idle_timeout_secs: 0,
            health_check_timeout_secs: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
        }
    }

    /// A dialer with no REALITY engine, because every dial here is
    /// `ConnectorConfig::Tcp`: the pool's job is to reach `connect_resolved`,
    /// and which security layer that picks is not this block's question.
    fn dialer() -> TransportDialer {
        TransportDialer::system().expect("a system dialer")
    }

    async fn open_flow(
        dialer: &TransportDialer,
        transport: &TransportLayer,
        addr: SocketAddr,
    ) -> BoxedTransportStream {
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        dialer
            .connect_stream(&ConnectorConfig::Tcp, transport, &target, &[addr], None)
            .await
            .expect("the flow opens")
    }

    /// Writes `payload` and reads exactly that many bytes back off the echo.
    ///
    /// The flush is not decoration: `poll_write` hands h2 whatever the
    /// flow-control window will take and leaves the rest queued for the next
    /// poll, and the first write on a fresh stream is granted no capacity at
    /// all until the connection has been polled once. The relay flushes for
    /// the same reason (`crates/xray-core-rs/src/policy.rs:196-220`).
    async fn round_trip(stream: &mut BoxedTransportStream, payload: &[u8]) {
        stream.write_all(payload).await.expect("the flow writes");
        stream.flush().await.expect("the flow flushes");
        let mut echoed = vec![0; payload.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .expect("the flow reads its echo back");
        assert_eq!(echoed, payload, "a flow reads back its own bytes");
    }

    /// Ends a flow the way a relay does: half-close, drain, drop.
    async fn end_flow(mut stream: BoxedTransportStream) {
        stream.shutdown().await.expect("the flow half-closes");
        let mut rest = Vec::new();
        stream
            .read_to_end(&mut rest)
            .await
            .expect("the call ends cleanly");
    }

    /// What the peer does about the first call it accepts.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum AfterFirstCall {
        KeepServing,
        /// The `GOAWAY(NO_ERROR)` of a graceful shutdown, sent once the call
        /// has ended — which h2 resolves the client's connection future as
        /// `Ok(())` for.
        GoAwayGracefully,
        /// `GOAWAY(INTERNAL_ERROR)`, which the client's driver reports as an
        /// error instead.
        GoAwayWithAnError,
        /// The same graceful `GOAWAY(NO_ERROR)`, sent while the call is still
        /// open. h2 keeps the client's driver running until the last stream
        /// has drained, so this is the one shape in which a pooled connection
        /// is live and unusable at once.
        GoAwayUnderAnOpenCall,
    }

    impl AfterFirstCall {
        fn reason(self) -> Option<Reason> {
            match self {
                Self::KeepServing => None,
                Self::GoAwayGracefully | Self::GoAwayUnderAnOpenCall => Some(Reason::NO_ERROR),
                Self::GoAwayWithAnError => Some(Reason::INTERNAL_ERROR),
            }
        }

        /// Whether the `GOAWAY` waits for the first call to end.
        fn waits_for_the_call(self) -> bool {
            self != Self::GoAwayUnderAnOpenCall
        }
    }

    /// A loopback gRPC peer that counts the TCP connections it accepts.
    ///
    /// The count is the whole point: it is the number of times the pool
    /// decided it had nothing to hand out, and it is observable only because
    /// the dial goes through a real socket.
    ///
    /// Only the *first* connection is walked away from. The replacement the
    /// pool dials serves normally, so a test that ends on it is asserting the
    /// recovery rather than the failure over again.
    struct GrpcPeer {
        addr: SocketAddr,
        accepted: Arc<AtomicUsize>,
    }

    impl GrpcPeer {
        async fn spawn(after_first_call: AfterFirstCall) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("a loopback listener");
            let addr = listener.local_addr().expect("the listener's address");
            let accepted = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&accepted);
            tokio::spawn(async move {
                let mut behaviour = after_first_call;
                while let Ok((socket, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve_grpc_connection(socket, behaviour));
                    behaviour = AfterFirstCall::KeepServing;
                }
            });
            Self { addr, accepted }
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
    }

    /// Serves every call the connection carries, echoing each `Hunk` back.
    async fn serve_grpc_connection(socket: TcpStream, after_first_call: AfterFirstCall) {
        let mut connection = server::handshake(socket).await.expect("server handshake");
        let mut served_one = false;
        while let Some(accepted) = connection.accept().await {
            let (request, respond) = accepted.expect("a well-formed request");
            let call = tokio::spawn(echo_call(request.into_body(), respond));

            let shutdown = if served_one {
                None
            } else {
                after_first_call.reason()
            };
            served_one = true;
            let Some(shutdown) = shutdown else { continue };

            if after_first_call.waits_for_the_call() {
                // `accept` is the only thing that polls this connection, so
                // the call has to be raced against it rather than awaited
                // inline.
                tokio::select! {
                    accepted = connection.accept() => {
                        assert!(accepted.is_none(), "a shutting-down peer serves one call");
                    }
                    finished = call => finished.expect("the call handler does not panic"),
                }
            }
            // Nothing has awaited since the call was spawned, so on the
            // mid-call arm this queues the `GOAWAY` before the echo's response
            // has been written — and h2 flushes a pending `GOAWAY` ahead of
            // any stream frame (`h2-0.4.15/src/proto/connection.rs:317-329`),
            // so the client is guaranteed to see it first.
            if shutdown == Reason::NO_ERROR {
                connection.graceful_shutdown();
            } else {
                connection.abrupt_shutdown(shutdown);
            }
            while connection.accept().await.is_some() {}
            return;
        }
    }

    /// Sends every DATA frame straight back, then closes with `grpc-status: 0`.
    async fn echo_call(mut body: RecvStream, mut respond: SendResponse<Bytes>) {
        let mut send = None;
        while let Some(chunk) = body.data().await {
            let Ok(chunk) = chunk else { return };
            body.flow_control()
                .release_capacity(chunk.len())
                .expect("release the client's window");
            let send = match send {
                Some(ref mut send) => send,
                None => send.insert(
                    respond
                        .send_response(grpc_response(), false)
                        .expect("respond"),
                ),
            };
            send_all(send, chunk).await;
        }

        let mut send = match send {
            Some(send) => send,
            None => respond
                .send_response(grpc_response(), false)
                .expect("respond"),
        };
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().expect("a legal header value"));
        let _ = send.send_trailers(trailers);
    }

    fn grpc_response() -> Response<()> {
        Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .expect("a well-formed response")
    }

    async fn send_all(send: &mut SendStream<Bytes>, mut chunk: Bytes) {
        while !chunk.is_empty() {
            send.reserve_capacity(chunk.len());
            let Some(Ok(granted)) = poll_fn(|cx| send.poll_capacity(cx)).await else {
                return;
            };
            let take = granted.min(chunk.len());
            send.send_data(chunk.split_to(take), false)
                .expect("send data");
        }
    }

    /// Spins until the pool has nothing to hand out.
    ///
    /// A `GOAWAY` reaches the client asynchronously: the driver task has to be
    /// scheduled, parse the frame and resolve before `is_finished` flips.
    /// Without this the next flow races that and reuses a connection the peer
    /// has already walked away from.
    async fn until_the_pool_is_empty(transport: &GrpcTransport) {
        within_deadline(async {
            while transport.holds_a_live_connection().await {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    /// Eight flows arrive together, one connection carries them all.
    ///
    /// Without single-flighting each of the eight misses the empty pool, dials,
    /// and pays its own handshake — and seven of the eight connections then
    /// leak, because only one can be the pooled one. That is the exact cost
    /// pooling exists to remove, so the count is the test.
    #[tokio::test]
    async fn eight_concurrent_first_flows_open_exactly_one_connection() {
        let peer = GrpcPeer::spawn(AfterFirstCall::KeepServing).await;
        let dialer = dialer();
        let transport = TransportLayer::Grpc(GrpcTransport::new(config()));

        let flows: Vec<_> = (0..8u8)
            .map(|index| {
                let dialer = dialer.clone();
                let transport = transport.clone();
                let addr = peer.addr;
                tokio::spawn(async move {
                    let mut flow = open_flow(&dialer, &transport, addr).await;
                    round_trip(&mut flow, &vec![index; 4096]).await;
                    end_flow(flow).await;
                })
            })
            .collect();

        within_deadline(async {
            for flow in flows {
                flow.await.expect("no flow panics");
            }
        })
        .await;

        assert_eq!(peer.accepted(), 1, "one connection carries every flow");
    }

    /// Two calls at once on the pooled connection, neither reading the other's
    /// bytes.
    #[tokio::test]
    async fn two_concurrent_flows_multiplex_without_interleaving() {
        let peer = GrpcPeer::spawn(AfterFirstCall::KeepServing).await;
        let dialer = dialer();
        let transport = TransportLayer::Grpc(GrpcTransport::new(config()));

        within_deadline(async {
            let mut first = open_flow(&dialer, &transport, peer.addr).await;
            let mut second = open_flow(&dialer, &transport, peer.addr).await;

            let ones = vec![1u8; 8192];
            let twos = vec![2u8; 8192];
            first.write_all(&ones).await.expect("the first flow writes");
            second
                .write_all(&twos)
                .await
                .expect("the second flow writes");
            first.flush().await.expect("the first flow flushes");
            second.flush().await.expect("the second flow flushes");

            let mut from_first = vec![0; ones.len()];
            let mut from_second = vec![0; twos.len()];
            first
                .read_exact(&mut from_first)
                .await
                .expect("the first flow reads");
            second
                .read_exact(&mut from_second)
                .await
                .expect("the second flow reads");

            assert_eq!(from_first, ones, "the first flow's own bytes");
            assert_eq!(from_second, twos, "the second flow's own bytes");
        })
        .await;

        assert_eq!(peer.accepted(), 1, "both calls ran on one connection");
    }

    /// A `GOAWAY(NO_ERROR)` is the case a pool gets wrong by checking only for
    /// errors: h2 resolves the driver as `Ok(())`
    /// (`h2-0.4.15/src/proto/connection.rs:216-235`), and a pool that reads
    /// that as health hands out a connection the peer has closed.
    #[tokio::test]
    async fn a_graceful_goaway_retires_the_pooled_connection() {
        let peer = GrpcPeer::spawn(AfterFirstCall::GoAwayGracefully).await;
        let dialer = dialer();
        let transport = TransportLayer::Grpc(GrpcTransport::new(config()));
        let TransportLayer::Grpc(grpc) = &transport else {
            panic!("the transport under test is gRPC");
        };

        within_deadline(async {
            let mut first = open_flow(&dialer, &transport, peer.addr).await;
            round_trip(&mut first, b"first").await;
            end_flow(first).await;
        })
        .await;

        until_the_pool_is_empty(grpc).await;

        within_deadline(async {
            let mut second = open_flow(&dialer, &transport, peer.addr).await;
            round_trip(&mut second, b"second").await;
            end_flow(second).await;
        })
        .await;

        assert_eq!(peer.accepted(), 2, "the retired connection was replaced");
    }

    /// The other half of the same rule: a driver that ends in `Err` is retired
    /// too.
    #[tokio::test]
    async fn a_driver_that_errored_retires_the_pooled_connection() {
        let peer = GrpcPeer::spawn(AfterFirstCall::GoAwayWithAnError).await;
        let dialer = dialer();
        let transport = TransportLayer::Grpc(GrpcTransport::new(config()));
        let TransportLayer::Grpc(grpc) = &transport else {
            panic!("the transport under test is gRPC");
        };

        within_deadline(async {
            let mut first = open_flow(&dialer, &transport, peer.addr).await;
            round_trip(&mut first, b"first").await;
            // Dropped rather than half-closed and drained, because an abrupt
            // `GOAWAY` discards whatever was queued behind it — the peer's
            // trailers included — so there is no clean end of call to wait
            // for. That is the shape of a peer that went away mid-connection,
            // which is what this test is about.
            drop(first);
        })
        .await;

        until_the_pool_is_empty(grpc).await;

        within_deadline(async {
            let mut second = open_flow(&dialer, &transport, peer.addr).await;
            round_trip(&mut second, b"second").await;
            end_flow(second).await;
        })
        .await;

        assert_eq!(peer.accepted(), 2, "the retired connection was replaced");
    }

    /// The third retirement, and the only one the pool cannot reach by finding
    /// its slot empty: a connection that is live and unusable at once.
    ///
    /// A `GOAWAY` arriving under a still-open call does not end the client's
    /// driver — h2 keeps the connection future running until the last stream
    /// has drained — so `holds_a_live_connection` says yes for as long as that
    /// tunnel lasts, which on a proxy is as long as the user's download.
    /// `recv_go_away` meanwhile records a connection error for *every* reason,
    /// `NO_ERROR` included
    /// (`h2-0.4.15/src/proto/streams/streams.rs:762`), and that is what
    /// `SendRequest::ready` is checked against (`streams.rs:1004,1722-1728`),
    /// so every new call on it fails. Only noticing that from the failed call
    /// and redialling keeps the outbound working; grpc-go answers the same
    /// frame by building a fresh transport under the same `ClientConn`.
    ///
    /// The two retirement tests above cannot reach this branch: both wait for
    /// [`until_the_pool_is_empty`] first, which is precisely the state in
    /// which it is skipped.
    #[tokio::test]
    async fn a_goaway_under_an_open_call_redials_rather_than_failing_the_flow() {
        let peer = GrpcPeer::spawn(AfterFirstCall::GoAwayUnderAnOpenCall).await;
        let dialer = dialer();
        let transport = TransportLayer::Grpc(GrpcTransport::new(config()));
        let TransportLayer::Grpc(grpc) = &transport else {
            panic!("the transport under test is gRPC");
        };

        within_deadline(async {
            // Held open for the rest of the test. The `GOAWAY` goes out ahead
            // of this echo, so reading the echo back is proof the client's
            // driver has already processed it — no spin needed, unlike the
            // retirements that wait for the driver to *end*.
            let mut draining = open_flow(&dialer, &transport, peer.addr).await;
            round_trip(&mut draining, b"first").await;

            assert!(
                grpc.holds_a_live_connection().await,
                "the open call keeps the driver alive, so the pool still holds the connection"
            );

            let mut second = open_flow(&dialer, &transport, peer.addr).await;
            round_trip(&mut second, b"second").await;

            // Retiring the slot must not take the draining tunnel down with
            // it: dropping the pool's `H2Connection` drops a `SendRequest`,
            // and h2 closes a connection only once no stream is left either.
            round_trip(&mut draining, b"still here").await;

            end_flow(second).await;
            end_flow(draining).await;
        })
        .await;

        assert_eq!(peer.accepted(), 2, "the unusable connection was replaced");
    }

    // There is no test here for a request that cannot be built, and its
    // absence is the point. The one reachable way to reach that error was a
    // control character in `grpcSettings.user_agent`, which made the HEADERS
    // block unbuildable on every flow for as long as the config stood.
    // `GrpcConfig::user_agent` is now a `HeaderValue`, so such a config cannot
    // be constructed to dial with — the refusal happens once, in
    // `xray_core_rs`'s `grpc_user_agent`, and is tested there. What is left of
    // `build_grpc_call`'s error is the derived `:path`, which
    // `grpc_request_path` escapes and no config can make invalid.

    /// `initialWindowsSize` passes three independent gates in grpc-go before a
    /// byte of it reaches the wire, and only the third is about the wire.
    ///
    /// The dial option is attached above zero
    /// (`Xray-core/transport/internet/grpc/dial.go:177-179`); the transport
    /// adopts the value only at `defaultWindowSize` or more
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:383-385`, with
    /// `defaultWindowSize = 65535` at `internal/transport/defaults.go:28`);
    /// and a `SETTINGS_INITIAL_WINDOW_SIZE` entry is written only when the
    /// adopted value differs from that default (`http2_client.go:435-447`).
    /// 30000 is stopped by the second gate and 65535 by the third, so the three
    /// collapse to one condition: 65536 or more.
    ///
    /// The frame is read off the socket rather than the builder inspected,
    /// because the builder is not what a censor sees.
    #[tokio::test]
    async fn only_a_window_of_65536_or_more_puts_a_settings_entry_on_the_wire() {
        for (window, expected) in [
            (0u32, Vec::new()),
            (30_000, Vec::new()),
            (65_535, Vec::new()),
            (
                1_048_576,
                vec![(SETTINGS_INITIAL_WINDOW_SIZE, 1_048_576u32)],
            ),
        ] {
            let settings = within_deadline(client_settings_for_window(window)).await;
            assert_eq!(settings, expected, "initialWindowsSize {window}");
        }
    }

    /// The SETTINGS frame the client opens `window` with.
    async fn client_settings_for_window(window: u32) -> Vec<(u16, u32)> {
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut config = config();
        config.initial_windows_size = window;

        // Nothing answers the dial, and nothing has to: h2 flushes the preface
        // and its SETTINGS without waiting for the peer's
        // (`h2-0.4.15/src/client.rs:1305-1350`). The dial is held rather than
        // dropped so the connection is not torn down mid-read.
        let dial = tokio::spawn(async move {
            let _held = open_grpc_h2_stream(Box::new(client_io) as BoxedTransportStream, &config)
                .await
                .expect("the POST opens");
            std::future::pending::<()>().await;
        });

        let mut preface = [0u8; PREFACE.len()];
        server_io
            .read_exact(&mut preface)
            .await
            .expect("the client preface");
        assert_eq!(preface, PREFACE, "the connection preface");

        let frame = read_frame(&mut server_io).await;
        assert_eq!(frame.kind, SETTINGS_FRAME, "the frame behind the preface");
        assert_eq!(frame.stream, 0, "SETTINGS is a connection-level frame");
        dial.abort();

        parse_settings(&frame.payload)
    }

    struct Frame {
        kind: u8,
        flags: u8,
        stream: u32,
        payload: Vec<u8>,
    }

    /// One HTTP/2 frame off the wire (RFC 9113 4.1).
    async fn read_frame<R: tokio::io::AsyncRead + Unpin>(io: &mut R) -> Frame {
        let mut header = [0u8; 9];
        io.read_exact(&mut header).await.expect("a frame header");
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; length];
        io.read_exact(&mut payload).await.expect("a frame payload");
        Frame {
            kind: header[3],
            flags: header[4],
            stream: u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]),
            payload,
        }
    }

    /// Reads the client's connection preface, after which every byte the peer
    /// sees is part of a frame.
    async fn read_the_preface<R: tokio::io::AsyncRead + Unpin>(io: &mut R) {
        let mut preface = [0u8; PREFACE.len()];
        io.read_exact(&mut preface)
            .await
            .expect("the client preface");
        assert_eq!(preface, PREFACE, "the connection preface");
    }

    fn parse_settings(payload: &[u8]) -> Vec<(u16, u32)> {
        assert_eq!(payload.len() % 6, 0, "SETTINGS carries six-byte entries");
        payload
            .chunks_exact(6)
            .map(|entry| {
                (
                    u16::from_be_bytes([entry[0], entry[1]]),
                    u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
                )
            })
            .collect()
    }

    /// Keepalive is off under Xray's defaults and on if *any* of the three
    /// settings is set — a three-way OR at
    /// `Xray-core/transport/internet/grpc/dial.go:169-175`, which is why
    /// `permitWithoutStream` alone turns it on with both durations left at
    /// zero.
    #[test]
    fn keepalive_is_off_only_while_all_three_settings_are() {
        assert_eq!(
            resolve_keepalive(&config()),
            None,
            "Xray's defaults ask for no keepalive"
        );

        for (idle, health, permit) in [(1, 0, false), (0, 1, false), (0, 0, true)] {
            let mut config = config();
            config.idle_timeout_secs = idle;
            config.health_check_timeout_secs = health;
            config.permit_without_stream = permit;
            assert!(
                resolve_keepalive(&config).is_some(),
                "idleTimeout {idle}, healthCheckTimeout {health}, permitWithoutStream {permit}"
            );
        }
    }

    /// `WithKeepaliveParams` raises anything under ten seconds to ten before
    /// the transport ever sees it (`grpc@v1.81.0/dialoptions.go:561-569`,
    /// `internal/internal.go:40-42`), so a zero `idleTimeout` that only got
    /// here because `permitWithoutStream` opened the gate pings every ten
    /// seconds rather than never.
    #[test]
    fn a_keepalive_time_under_ten_seconds_is_raised_to_ten() {
        for (idle, expected) in [
            (0u32, 10u64),
            (1, 10),
            (9, 10),
            (10, 10),
            (11, 11),
            (600, 600),
        ] {
            let mut config = config();
            config.idle_timeout_secs = idle;
            config.permit_without_stream = true;
            let keepalive = resolve_keepalive(&config).expect("the gate is open");
            assert_eq!(
                keepalive.time,
                Duration::from_secs(expected),
                "idleTimeout {idle}"
            );
        }
    }

    /// An unset `healthCheckTimeout` is grpc-go's twenty seconds, not zero:
    /// the transport fills a zero `Timeout` in with
    /// `defaultClientKeepaliveTimeout`
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:268-270`,
    /// `internal/transport/defaults.go:33`). A zero here would fail every
    /// ping the instant it was sent.
    #[test]
    fn an_unset_health_check_timeout_is_grpc_gos_twenty_seconds() {
        let mut config = config();
        config.permit_without_stream = true;
        assert_eq!(
            resolve_keepalive(&config)
                .expect("the gate is open")
                .timeout,
            Duration::from_secs(20)
        );

        config.health_check_timeout_secs = 7;
        assert_eq!(
            resolve_keepalive(&config)
                .expect("the gate is open")
                .timeout,
            Duration::from_secs(7)
        );
    }

    /// The resolved interval reaches the wire, and it is the clamped one.
    ///
    /// `idleTimeout: 1` asks for a ping a second; grpc-go's floor makes it ten,
    /// so the first PING must arrive at ten seconds — not before, and not
    /// after. Time is paused, so the ten seconds cost nothing: the runtime
    /// jumps the clock to the nearest timer once every task is parked, which
    /// is exactly why the *upper* bound is the load-bearing half. A lower
    /// bound alone passes just as happily on twenty seconds
    /// (`healthCheckTimeout` wired to the wrong field) or on the unclamped six
    /// hundred, because the clock simply jumps to whatever was asked for.
    ///
    /// The fence is [`PAUSED_DEADLINE`] rather than [`DEADLINE`] for the same
    /// reason: a ten-second deadline would be racing the ping it is waiting
    /// for. Without any fence a regression that stops keepalive leaves no
    /// timer pending at all and hangs the run instead of failing it.
    #[tokio::test(start_paused = true)]
    async fn a_keepalive_connection_pings_at_the_clamped_interval() {
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut config = config();
        config.idle_timeout_secs = 1;

        let dial = tokio::spawn(async move {
            let _held = open_grpc_h2_stream(Box::new(client_io) as BoxedTransportStream, &config)
                .await
                .expect("the POST opens");
            std::future::pending::<()>().await;
        });

        let started = tokio::time::Instant::now();
        let waited = within_paused_deadline(async {
            read_until_the_first_ping(&mut server_io).await;
            started.elapsed()
        })
        .await;
        dial.abort();

        assert_eq!(
            waited,
            Duration::from_secs(10),
            "the first ping waited {waited:?}, not the ten seconds grpc-go clamps to"
        );
    }

    /// A ping nobody answers has to end the connection, because ending is the
    /// only thing the pool retires on.
    ///
    /// grpc-go calls an unacknowledged keepalive a connection error —
    /// "keepalive ping failed to receive ACK within timeout"
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:1754-1757`) — and
    /// `drive`'s `select!` is that: the ping loop returning drops the
    /// `Connection`. Nothing above it would notice on its own, so a keepalive
    /// that quietly gave up would leave the pool handing out a connection to a
    /// peer that has stopped answering, which is the failure keepalive exists
    /// to catch.
    ///
    /// The peer is a bare duplex rather than [`GrpcPeer`] because it has to
    /// read the PING and send no PONG, and no h2 server does that — h2
    /// acknowledges pings itself, below the API. That is also why this reaches
    /// the driver through `GrpcStream::connection_is_finished` instead of
    /// [`until_the_pool_is_empty`]: it is the same `JoinHandle` either way,
    /// and the pooled path cannot be given a peer this rude.
    #[tokio::test(start_paused = true)]
    async fn a_ping_that_is_never_acknowledged_ends_the_connection() {
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut config = config();
        // Ten seconds after the clamp, then five to be answered in.
        config.idle_timeout_secs = 1;
        config.health_check_timeout_secs = 5;

        let stream = within_paused_deadline(open_grpc_h2_stream(
            Box::new(client_io) as BoxedTransportStream,
            &config,
        ))
        .await
        .expect("the POST opens");

        within_paused_deadline(read_until_the_first_ping(&mut server_io)).await;
        assert!(
            !stream.connection_is_finished(),
            "the ping has only just gone out"
        );

        // Past the five seconds it had to be answered in. `server_io` is held
        // rather than dropped, so the connection ends on the keepalive giving
        // up and not on an EOF underneath it.
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(
            stream.connection_is_finished(),
            "an unacknowledged ping has to take the connection with it"
        );
    }

    /// Reads frames off `io` until a PING arrives, discarding the rest.
    async fn read_until_the_first_ping(io: &mut DuplexStream) {
        read_the_preface(io).await;
        while read_frame(io).await.kind != PING_FRAME {}
    }

    /// A peer that finishes the TCP handshake and then says nothing.
    ///
    /// The three dormancy tests below need the *pool* rather than
    /// [`open_grpc_h2_stream`], because the state they are about is a live
    /// connection with no call open on it and only the pool holds one. That
    /// rules out [`GrpcPeer`]: `h2::server` acknowledges pings below its own
    /// API, so a PING is invisible from behind it, and the pool dials a real
    /// socket rather than taking one. Nothing has to answer — h2 flushes its
    /// preface and SETTINGS without waiting for the peer's, and
    /// `open_grpc_call` does not await the response.
    async fn silent_peer() -> TcpListener {
        TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback listener")
    }

    /// Opens one flow through `transport`, ends it, and hands back the socket
    /// the peer sees — a pooled connection with no call on it, on a clock that
    /// has been stopped at the moment it became one.
    ///
    /// **The flow is dropped before the accept**, with nothing awaited in
    /// between, so that no interval can pass while a call is still open on the
    /// connection: a keepalive that pinged then would be doing its job, and
    /// the test would be measuring the wrong thing.
    ///
    /// **The clock is paused here rather than by `start_paused` on the test**
    /// for the same reason. Everything above is real I/O on a real socket, and
    /// under a paused clock every await in it is a chance for the runtime to
    /// idle and jump straight to the keepalive's ten-second deadline — which
    /// spends the first interval before the test has said anything about it.
    /// The setup costs microseconds of real time, so running it on the real
    /// clock costs nothing.
    async fn a_pooled_connection_with_no_call_on_it(
        dialer: &TransportDialer,
        transport: &TransportLayer,
        listener: &TcpListener,
    ) -> TcpStream {
        let addr = listener.local_addr().expect("the listener's address");
        let flow = open_flow(dialer, transport, addr).await;
        drop(flow);

        let (mut peer, _) = listener.accept().await.expect("the client's connection");
        read_the_preface(&mut peer).await;
        tokio::time::pause();
        peer
    }

    /// Whether a keepalive PING reaches the peer inside `window`, reading past
    /// whatever else the client sends.
    ///
    /// A PING carrying ACK is the client answering one of *ours* and is not a
    /// keepalive, so the flag is part of the question (RFC 9113 6.7).
    ///
    /// Under paused time the window costs nothing: the runtime steps the clock
    /// to the nearest timer once every task is parked, so it reaches the
    /// keepalive's own deadline before it reaches this one.
    async fn pinged_within(io: &mut TcpStream, window: Duration) -> bool {
        tokio::time::timeout(window, async {
            loop {
                let frame = read_frame(io).await;
                if frame.kind == PING_FRAME && frame.flags & PING_ACK == 0 {
                    return;
                }
            }
        })
        .await
        .is_ok()
    }

    /// grpc-go's keepalive goroutine parks on `kpDormancyCond` for as long as
    /// `len(t.activeStreams) < 1 && !kp.PermitWithoutStream`
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:1769-1778`), so the
    /// likeliest keepalive a config can ask for — `idleTimeout` on its own —
    /// puts nothing on the wire while no call is open. Measured against a real
    /// grpc-go v1.81.0 client under Xray's dial options: zero PINGs in
    /// twenty-five seconds.
    ///
    /// That state is an edge case in an ordinary client and the *steady state*
    /// here, because the pool deliberately holds a connection open between
    /// flows. A ping every ten seconds on an idle connection would be a
    /// heartbeat no member of the population we hide in sends.
    #[tokio::test]
    async fn an_idle_pooled_connection_is_not_pinged() {
        let listener = silent_peer().await;
        let dialer = dialer();
        let mut config = config();
        // Ten seconds after grpc-go's floor, and `permitWithoutStream` left
        // false — the config the doc above is about.
        config.idle_timeout_secs = 1;
        let transport = TransportLayer::Grpc(GrpcTransport::new(config));

        let mut peer = a_pooled_connection_with_no_call_on_it(&dialer, &transport, &listener).await;

        assert!(
            !pinged_within(&mut peer, SEVERAL_INTERVALS).await,
            "a pooled connection with no call on it was pinged where grpc-go goes dormant"
        );
    }

    /// The other half of dormancy: a call is what lifts it, and grpc-go pings
    /// the moment it does rather than waiting out another interval — the
    /// `if !outstandingPing` send sits directly under the `Wait()`, and the
    /// comment between them says both ways in are the same
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:1779-1792`).
    #[tokio::test]
    async fn a_call_brings_the_keepalive_back_to_a_dormant_connection() {
        let listener = silent_peer().await;
        let addr = listener.local_addr().expect("the listener's address");
        let dialer = dialer();
        let mut config = config();
        config.idle_timeout_secs = 1;
        let transport = TransportLayer::Grpc(GrpcTransport::new(config));

        let mut peer = a_pooled_connection_with_no_call_on_it(&dialer, &transport, &listener).await;
        assert!(
            !pinged_within(&mut peer, SEVERAL_INTERVALS).await,
            "the connection has to be dormant before a call can be what wakes it"
        );

        let second = open_flow(&dialer, &transport, addr).await;
        assert!(
            pinged_within(&mut peer, SEVERAL_INTERVALS).await,
            "a call on the pooled connection has to bring the keepalive back"
        );
        drop(second);
    }

    /// `permitWithoutStream` exists to switch the dormancy off, and switching
    /// it off is the whole of what it does here: the same idle connection, and
    /// now it is pinged. Measured against grpc-go: PINGs at ten and twenty
    /// seconds.
    #[tokio::test]
    async fn permit_without_stream_pings_a_connection_with_no_call_on_it() {
        let listener = silent_peer().await;
        let dialer = dialer();
        let mut config = config();
        config.permit_without_stream = true;
        let transport = TransportLayer::Grpc(GrpcTransport::new(config));

        let mut peer = a_pooled_connection_with_no_call_on_it(&dialer, &transport, &listener).await;

        assert!(
            pinged_within(&mut peer, SEVERAL_INTERVALS).await,
            "permitWithoutStream asks for pings with no call open, and got none"
        );
    }

    /// grpc-go skips a ping whenever the socket has been read since the last
    /// pass, and rearms its timer for `lastRead + kp.Time` rather than for a
    /// fresh interval (`http2_client.go:1745-1752`), so a connection carrying
    /// traffic is never pinged at all.
    ///
    /// Worth the clock the read path has to keep for the same reason the
    /// dormancy is: a heartbeat that appears only on a *quiet* connection is a
    /// sharper signal than one that appears always.
    ///
    /// **The rearm target is what makes the assertion exact.** A peer speaking
    /// one second before the ping was due buys ten more seconds and not
    /// twenty; a port that slept a whole fresh interval on hearing something
    /// would answer nineteen here too but would drift up to a full interval
    /// away from grpc-go on any other schedule, so nineteen is checked rather
    /// than "later than ten".
    ///
    /// A duplex rather than the pooled path over a socket, and one call left
    /// open rather than `permitWithoutStream`, because this is the one
    /// keepalive test whose verdict is a *time*: a write into a duplex makes
    /// the reader runnable there and then, while a loopback socket has to go
    /// through the io driver — and a paused clock jumps to the next timer
    /// whenever the runtime finds nothing runnable, which is exactly the gap a
    /// socket leaves.
    ///
    /// An empty SETTINGS frame is what the peer speaks with: the cheapest
    /// legal thing a server can say at any point in a connection. What it says
    /// does not matter — grpc-go stamps `t.lastRead` on every frame it reads,
    /// whatever the frame is (`http2_client.go:1663,1671`).
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_speaks_pushes_the_ping_out_to_ten_seconds_past_it() {
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut config = config();
        config.idle_timeout_secs = 1;

        let dial = tokio::spawn(async move {
            let _held = open_grpc_h2_stream(Box::new(client_io) as BoxedTransportStream, &config)
                .await
                .expect("the POST opens");
            std::future::pending::<()>().await;
        });

        let started = tokio::time::Instant::now();
        let waited = within_paused_deadline(async {
            // One second before the ping was due.
            tokio::time::sleep(Duration::from_secs(9)).await;
            server_io
                .write_all(EMPTY_SETTINGS_FRAME)
                .await
                .expect("the peer speaks");
            read_until_the_first_ping(&mut server_io).await;
            started.elapsed()
        })
        .await;
        dial.abort();

        assert_eq!(
            waited,
            Duration::from_secs(19),
            "the ping waited {waited:?}, not the ten seconds past the peer's last word"
        );
    }
}

/// Connection-level flow control: what one flow that stops reading costs the
/// other flows sharing its outbound's connection.
///
/// Over a loopback `TcpListener` and the real pool, for the same reason
/// `stream_grpc_pool_tests` is: the whole subject is what happens when several
/// flows are HTTP/2 streams on *one* connection, which the unpooled
/// `open_grpc_h2_stream` cannot produce.
mod stream_grpc_flow_control_tests {
    use std::future::poll_fn;
    use std::net::SocketAddr;
    use std::time::Duration;

    use bytes::Bytes;
    use h2::server::{self, SendResponse};
    use h2::SendStream;
    use http::{HeaderValue, Response};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::stream::grpc_test_only::encode_hunk;
    use xray_transport::stream::{GrpcConfig, GrpcTransport, TransportLayer};
    use xray_transport::{BoxedTransportStream, ConnectorConfig, TransportDialer};

    /// A starved flow stalls rather than fails, so the deadline is what turns
    /// the bug into a test failure — the same fence the sibling blocks use.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// HTTP/2's default flow-control window (RFC 9113 6.9.2): the stream
    /// window each side starts every stream with here, since neither sends a
    /// `SETTINGS_INITIAL_WINDOW_SIZE` entry.
    const DEFAULT_WINDOW: usize = 65535;

    /// A payload whose `Hunk` is exactly [`DEFAULT_WINDOW`] bytes on the wire:
    /// five bytes of gRPC prefix, the protobuf tag, and the three-byte varint
    /// a length this size takes. One of them spends the stalled flow's entire
    /// stream window, which is the point — the flow can take no more, and the
    /// question is whether it has also taken the connection's.
    const STALLING_PAYLOAD_LEN: usize = DEFAULT_WINDOW - 5 - 1 - 3;

    /// What the second flow is waiting for. Short on purpose: the claim is
    /// that it gets *anything*, not that it gets a lot.
    const VICTIM_PAYLOAD: &[u8] = b"the second flow's bytes";

    fn config() -> GrpcConfig {
        GrpcConfig {
            service_name: "xray.grpc".to_owned(),
            multi_mode: false,
            authority: "grpc.example.com".parse().expect("a literal authority"),
            user_agent: HeaderValue::from_static("grpc-go/1.81.0"),
            idle_timeout_secs: 0,
            health_check_timeout_secs: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
        }
    }

    async fn open_flow(
        dialer: &TransportDialer,
        transport: &TransportLayer,
        addr: SocketAddr,
    ) -> BoxedTransportStream {
        let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        dialer
            .connect_stream(&ConnectorConfig::Tcp, transport, &target, &[addr], None)
            .await
            .expect("the flow opens")
    }

    fn grpc_response() -> Response<()> {
        Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .expect("a well-formed response")
    }

    /// Reserve, wait for capacity, send at most what was granted — the same
    /// loop the client's uplink runs, and the reason this peer is the one that
    /// knows when the client's window is spent: `poll_capacity` reports the
    /// capacity h2 has assigned out of the *connection's* send window, so a
    /// send that completes is a window that was there.
    async fn send_all(send: &mut SendStream<Bytes>, mut chunk: Bytes) {
        while !chunk.is_empty() {
            send.reserve_capacity(chunk.len());
            let granted = poll_fn(|cx| send.poll_capacity(cx))
                .await
                .expect("the send half is still streaming")
                .expect("capacity, not an error");
            let take = granted.min(chunk.len());
            send.send_data(chunk.split_to(take), false)
                .expect("send data");
        }
    }

    /// A loopback peer that serves exactly two calls on one connection.
    async fn spawn_peer() -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("the listener's address");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("the client dials");
            serve_the_stall_and_the_victim(socket).await;
        });
        addr
    }

    /// The first call fills the client's window and says so; the second waits
    /// for that word and then speaks.
    ///
    /// The order is the whole experiment, and it is enforced from this side
    /// because this is the side that can observe it: the client cannot tell
    /// when bytes it never reads have arrived. Both handlers run on tasks of
    /// their own because `accept` is the only thing polling this connection,
    /// and both of them park.
    async fn serve_the_stall_and_the_victim(socket: TcpStream) {
        let mut connection = server::handshake(socket).await.expect("server handshake");
        let (window_is_spent, wait_for_the_window) = oneshot::channel();
        let mut window_is_spent = Some(window_is_spent);
        let mut wait_for_the_window = Some(wait_for_the_window);

        while let Some(accepted) = connection.accept().await {
            let (_request, respond) = accepted.expect("a well-formed request");
            match window_is_spent.take() {
                Some(report) => {
                    tokio::spawn(fill_the_window(respond, report));
                }
                None => {
                    let wait = wait_for_the_window
                        .take()
                        .expect("the test opens two calls on one connection");
                    tokio::spawn(speak_once_the_window_is_spent(respond, wait));
                }
            }
        }
    }

    /// Writes one window's worth on the first call and reports it, then holds
    /// the call open. Nothing on the client ever reads this flow, so nothing
    /// ever hands the window back.
    async fn fill_the_window(mut respond: SendResponse<Bytes>, report: oneshot::Sender<()>) {
        let mut send = respond
            .send_response(grpc_response(), false)
            .expect("respond");
        send_all(
            &mut send,
            Bytes::from(encode_hunk(&vec![0xa5; STALLING_PAYLOAD_LEN])),
        )
        .await;
        report.send(()).expect("the second call is still waiting");
        // Held rather than dropped: dropping every handle is what makes h2
        // reset the stream, and a reset would hand the window back.
        let _held = send;
        std::future::pending::<()>().await;
    }

    async fn speak_once_the_window_is_spent(
        mut respond: SendResponse<Bytes>,
        wait: oneshot::Receiver<()>,
    ) {
        wait.await.expect("the first call filled the window");
        let mut send = respond
            .send_response(grpc_response(), false)
            .expect("respond");
        send_all(&mut send, Bytes::from(encode_hunk(VICTIM_PAYLOAD))).await;
        let _held = send;
        std::future::pending::<()>().await;
    }

    /// A flow whose consumer has stopped reading must not stop the flows
    /// beside it.
    ///
    /// h2 releases the stream and connection windows together — the only
    /// `release_capacity` in the crate is on the read path
    /// (`crates/xray-transport/src/stream/grpc/stream.rs`, `poll_read`) — and
    /// its connection receive window is pinned at 65535 whatever SETTINGS say
    /// (`h2-0.4.15/src/proto/streams/recv.rs:92-97`). The pool puts every flow
    /// of an outbound on one connection, so one flow that stops reading holds
    /// the shared window and every other flow on the outbound stops with it,
    /// until the 300 s idle timeout takes them.
    ///
    /// Both production relays reach it. `crates/xray-core-rs/src/tun.rs`
    /// stops polling the remote reader while a send into a backed-up TUN stack
    /// is pending, and `copy_direction` in
    /// `crates/xray-core-rs/src/policy.rs` stops polling the read half while a
    /// write to a slow local socket is pending.
    ///
    /// grpc-go decouples exactly this, and says why: *"Decoupling the
    /// connection flow control will prevent other active(fast) streams from
    /// starving in presence of slow or inactive streams"*
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:1183-1203`).
    #[tokio::test]
    async fn a_flow_that_stops_reading_does_not_starve_the_others_on_its_connection() {
        let addr = spawn_peer().await;
        let dialer = TransportDialer::system().expect("a system dialer");
        let transport = TransportLayer::Grpc(GrpcTransport::new(config()));

        // Never read from, and never dropped: a dropped flow resets its stream
        // and h2 hands the window back, which is the bug curing itself.
        let _stalled = open_flow(&dialer, &transport, addr).await;
        let mut victim = open_flow(&dialer, &transport, addr).await;

        let mut received = vec![0u8; VICTIM_PAYLOAD.len()];
        tokio::time::timeout(DEADLINE, victim.read_exact(&mut received))
            .await
            .expect(
                "the second flow never received a byte: the first flow is holding the whole \
                 connection-level window",
            )
            .expect("the second flow reads");
        assert_eq!(received, VICTIM_PAYLOAD, "the second flow's own bytes");
    }
}
