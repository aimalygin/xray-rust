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
