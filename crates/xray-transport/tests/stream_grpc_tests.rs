// Named like the sibling `stream_*_tests` files (e.g.
// `stream_websocket_tests.rs`'s `stream_websocket_handshake_tests`) rather
// than a bare `mod path`, so later gRPC test modules — framing, pool — read
// consistently in `cargo test` output alongside this one.
mod stream_grpc_path_tests {
    use xray_transport::stream::grpc_request_path;

    /// Vectors read off `Xray-core/transport/internet/grpc/config.go:17-59`
    /// and `encoding/customSeviceName.go:33`, which assembles the path as
    /// `"/" + getServiceName() + "/" + getTunStreamName()`.
    ///
    /// `(service_name, multi_mode, expected_path)`
    const VECTORS: &[(&str, bool, &str)] = &[
        // The proto3 default. Both halves of the join are present, so the
        // empty service name leaves a double slash.
        ("", false, "//Tun"),
        ("", true, "//TunMulti"),
        // Plain names are escaped whole, stream name is a literal.
        ("hello", false, "/hello/Tun"),
        ("hello", true, "/hello/TunMulti"),
        // Whole-string escaping means an inner slash is escaped, not kept.
        ("a/b", false, "/a%2Fb/Tun"),
        // Go's encodePathSegment set: these pass through unescaped ...
        ("$&+:=@", false, "/$&+:=@/Tun"),
        // ... and these do not. Escapes are uppercase hex.
        ("a b", false, "/a%20b/Tun"),
        ("a;b", false, "/a%3Bb/Tun"),
        ("a,b", false, "/a%2Cb/Tun"),
        ("a?b", false, "/a%3Fb/Tun"),
        ("a!b", false, "/a%21b/Tun"),
        ("a*b", false, "/a%2Ab/Tun"),
        // Custom paths: a leading slash switches dialects. The last segment is
        // the stream name, everything between the first and last slash is the
        // service name, escaped per segment rather than whole.
        ("/a/b", false, "/a/b"),
        ("/a/b", true, "/a/b"),
        // `|` splits the last segment into tun|tunMulti, both client-side.
        ("/a/b|c", false, "/a/b"),
        ("/a/b|c", true, "/a/c"),
        // Multi-segment service names keep their separators.
        ("/x/y/z", false, "/x/y/z"),
        ("/x/y/z|w", true, "/x/y/w"),
        // `lastIndex < 1` is clamped to 1, so a single leading segment yields
        // an empty service name and the double slash comes back.
        ("/hello", false, "//hello"),
        ("/hello|multi", true, "//multi"),
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
        ("hello/world!", false, "/hello%2Fworld%21/Tun"),
        // `TestConfig_GetServiceName`, "absolute path", line 28-32, combined
        // with the client/server `|` split.
        ("/my/sample/path/a|b", false, "/my/sample/path/a"),
        ("/my/sample/path/a|b", true, "/my/sample/path/b"),
        // `TestConfig_GetServiceName`, "escape absolute path", line 33-37: a
        // *middle* service-name segment ("hello ", "world!") needs escaping,
        // not just the whole string as in the no-leading-slash dialect.
        ("/hello /world!/a|b", false, "/hello%20/world%21/a"),
        ("/hello /world!/a|b", true, "/hello%20/world%21/b"),
        // `TestConfig_GetTunStreamName`/`GetTunMultiStreamName`, "absolute
        // path server", line 63-67 / 98-102: realistic tun|tunMulti names.
        (
            "/my/sample/path/tun_service|multi_service",
            false,
            "/my/sample/path/tun_service",
        ),
        (
            "/my/sample/path/tun_service|multi_service",
            true,
            "/my/sample/path/multi_service",
        ),
        // `TestConfig_GetTunStreamName`, "escape absolute path client", line
        // 73-77: the *trailing* stream-name segment needs escaping (a
        // backslash and a `!`), not just a literal pass-through.
        (
            "/m y/sa !mple/pa\\th/tun\\_serv!ice",
            false,
            "/m%20y/sa%20%21mple/pa%5Cth/tun%5C_serv%21ice",
        ),
        // `TestConfig_GetTunMultiStreamName`, "escape absolute path client",
        // line 108-112: same prefix, and a literal `%` in the input must
        // itself be escaped to `%25`.
        (
            "/m y/sa !mple/pa\\th/mu%lti\\_serv!ice",
            true,
            "/m%20y/sa%20%21mple/pa%5Cth/mu%25lti%5C_serv%21ice",
        ),
    ];

    #[test]
    fn the_request_path_matches_xrays_service_name_rules() {
        for (service_name, multi_mode, expected) in VECTORS {
            assert_eq!(
                grpc_request_path(service_name, *multi_mode),
                *expected,
                "serviceName {service_name:?} multiMode {multi_mode}"
            );
        }
    }
}

mod stream_grpc_framing_write_tests {
    use xray_transport::stream::encode_hunk;

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
    use xray_transport::stream::{encode_hunk, HunkDecoder};

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
        let mut decoder = HunkDecoder::new();
        decoder.push(&encode_hunk(b"hello"));
        assert_eq!(drain(&mut decoder), vec![b"hello".to_vec()]);
    }

    #[test]
    fn a_message_split_at_every_byte_boundary_still_decodes() {
        // The defect this test exists for: a length varint straddling two DATA
        // frames. Feeding one byte at a time covers every split there is.
        let payload = vec![0x37; 500];
        let encoded = encode_hunk(&payload);

        let mut decoder = HunkDecoder::new();
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

        let mut decoder = HunkDecoder::new();
        decoder.push(&chunk);
        assert_eq!(
            drain(&mut decoder),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn a_zero_length_hunk_is_a_message_not_an_end_of_stream() {
        let mut decoder = HunkDecoder::new();
        decoder.push(&encode_hunk(&[]));
        assert_eq!(drain(&mut decoder), vec![Vec::<u8>::new()]);
    }

    #[test]
    fn an_unknown_protobuf_field_is_skipped() {
        // field 2, wire type 0 (varint), value 1 -- then the real field 1.
        let framed = frame(&[0x10, 0x01, 0x0a, 0x02, b'h', b'i']);

        let mut decoder = HunkDecoder::new();
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

        let mut decoder = HunkDecoder::new();
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

        let mut decoder = HunkDecoder::new();
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

        let mut decoder = HunkDecoder::new();
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

        let mut decoder = HunkDecoder::new();
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
        let mut decoder = HunkDecoder::new();
        decoder.push(&frame(&[0x08, 0x01, 0x0a, 0x02, b'h', b'i']));
        assert_eq!(drain(&mut decoder), vec![b"hi".to_vec()]);

        // And on its own it leaves the field absent, which is an empty read.
        let mut decoder = HunkDecoder::new();
        decoder.push(&frame(&[0x08, 0x01]));
        assert_eq!(drain(&mut decoder), vec![Vec::<u8>::new()]);
    }

    /// A repeated singular `bytes` field is last-one-wins, not concatenation:
    /// `consumeBytesNoZero` assigns with `append(([]byte)(nil), v...)`
    /// (`protobuf@v1.36.11/internal/impl/codec_gen.go:5497`), overwriting
    /// whatever an earlier entry left. Unmarshalling this body into Xray's
    /// `encoding.Hunk` yields `Data == "yo!"`, not `"hiyo!"`.
    #[test]
    fn the_last_field_one_wins_when_a_hunk_repeats_it() {
        let mut decoder = HunkDecoder::new();
        decoder.push(&frame(&[
            0x0a, 0x02, b'h', b'i', 0x0a, 0x03, b'y', b'o', b'!',
        ]));
        assert_eq!(drain(&mut decoder), vec![b"yo!".to_vec()]);
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

            let mut decoder = HunkDecoder::new();
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
            let mut decoder = HunkDecoder::new();
            decoder.push(&frame(body));
            let decoded = decoder.next_payload();
            assert!(
                decoded.is_err(),
                "{name} should be refused, got {decoded:?}"
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
        let mut decoder = HunkDecoder::new();
        decoder.push(&frame(&[0x13, 0x18, 0x01, 0x14, 0x0a, 0x02, b'h', b'i']));
        assert!(decoder.next_payload().is_err());
    }
}
