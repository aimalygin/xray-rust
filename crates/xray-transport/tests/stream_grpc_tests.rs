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

            let mut decoder = HunkDecoder::new();
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
        let mut decoder = HunkDecoder::new();

        for index in 0..128u8 {
            let payload = vec![index; 64];
            decoder.push(&encode_hunk(&payload));
            assert_eq!(drain(&mut decoder), vec![payload], "message {index}");
            assert_eq!(decoder.buffered_len(), 0, "message {index}");
        }
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

/// The `Hunk` stream on a real HTTP/2 POST, against an in-process peer shaped
/// like xray-core's gRPC inbound.
mod stream_grpc_h2_tests {
    use std::future::{poll_fn, Future};
    use std::time::Duration;

    use bytes::Bytes;
    use h2::server::{self, SendResponse};
    use h2::{RecvStream, SendStream};
    use http::{HeaderMap, Method, Response};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::oneshot;
    use xray_transport::stream::{encode_hunk, open_grpc_h2_stream, GrpcStream};
    use xray_transport::BoxedTransportStream;

    /// `grpcSettings.authority` when it is set; the tests never exercise the
    /// fallbacks (`Xray-core/transport/internet/grpc/dial.go:159-167`), which
    /// are the caller's job to resolve.
    const AUTHORITY: &str = "grpc.example.com";
    /// `grpc_request_path("xray.grpc", false)`.
    const PATH: &str = "/xray.grpc/Tun";
    /// `utils.ChromeUA` stands in for whatever Task 7 settles on; this block
    /// only cares that a value reaches the request.
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
        open_grpc_h2_stream(
            Box::new(io) as BoxedTransportStream,
            AUTHORITY,
            PATH,
            USER_AGENT,
        )
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
                Script::SayThenReset(..) | Script::StallThenSayThenReset { .. }
            )
        }
    }

    /// Serves one gRPC call over `io`.
    ///
    /// The accept loop keeps running while the call is handled: h2's server
    /// `Connection` is the connection, and nothing moves on the socket unless
    /// `accept` is being polled.
    async fn serve_one_call(io: DuplexStream, script: Script) {
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
                let call = tokio::spawn(handle_call(request, respond, script));
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

            tokio::spawn(handle_call(request, respond, script));
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
    ) {
        let (head, mut body) = request.into_parts();
        assert_request_line(&head);

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
                // The client may still be writing; keep reading so its window
                // never closes under it.
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("client data");
                    body.flow_control()
                        .release_capacity(chunk.len())
                        .expect("release the client's window");
                }
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
    /// Which values are *right* is Task 7's question. This pins only the fields
    /// the request builder itself puts on the wire.
    fn assert_request_line(head: &http::request::Parts) {
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
        assert_eq!(head.uri.path(), PATH, ":path");
        assert_eq!(head.uri.query(), None, "the :path carries no query");

        for (name, expected) in [
            ("content-type", "application/grpc"),
            ("te", "trailers"),
            ("user-agent", USER_AGENT),
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
    /// wrote last is still queued here. Every path out of the call then runs
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
            stream
                .write_all(&vec![0x5a; SIZE])
                .await
                .expect("the write is accepted while the call is live");

            // `write_all` returns with the frame only *queued*: `poll_capacity`
            // is edge-triggered and grants nothing until the connection has
            // run (`h2-0.4.15/src/proto/streams/send.rs:371-374`), so the first
            // drain reserves and parks. This flush is what pushes the window's
            // worth onto the wire, and it can never finish — the peer reads one
            // frame and never reopens the window — so it is raced against the
            // peer saying it has the bytes rather than awaited.
            tokio::select! {
                arrived = arrived => arrived.expect("the peer reports the first Hunk"),
                flushed = stream.flush() => {
                    panic!("the peer never reopens the window, so this cannot finish: {flushed:?}")
                }
            }
            // Only now, with that flush dropped and the rest of the frame
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

    /// `connection_is_finished` is what Task 8's pool has to ask, because the
    /// obvious question gives the wrong answer: h2 resolves its connection
    /// future as `Ok(())` after a graceful `GOAWAY`
    /// (`h2-0.4.15/src/proto/connection.rs:216-235`), so a pool that retired a
    /// connection only when the driver returned `Err` would keep handing out a
    /// dead one.
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
