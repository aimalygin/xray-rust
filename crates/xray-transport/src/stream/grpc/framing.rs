//! The gRPC message framing Xray's `Hunk` rides in.
//!
//! `message Hunk { bytes data = 1; }` (`Xray-core/transport/internet/grpc/
//! encoding/stream.proto:6-8`) behind gRPC's own five-byte prefix, so one
//! write of N bytes is: a compression flag, a big-endian u32 length, the
//! protobuf tag `0x0a`, a varint length, and the payload. Overhead is seven
//! bytes below 128 and eight below 16384.
//!
//! Xray's write side (`encoding/hunkconn.go:131-140`, `Write`) hands the
//! whole buffer straight to `hc.Send(&Hunk{Data: buf[:]})` for every write,
//! including a zero-length one — nothing on that path special-cases an empty
//! slice. But proto3 `bytes` fields have *implicit* presence: a value of
//! length zero is the field's default and generated marshalling code skips
//! it rather than emitting an empty entry. The generated `Hunk` field has no
//! `optional` keyword (`stream.pb.go:26`, tag `protobuf:"bytes,1,opt,name=
//! data,proto3"` — proto3's plain `opt`, not `oneof`-backed presence), so
//! protobuf-go's field-coder table selects the "NoZero" coder for it:
//! `!fd.HasPresence()` routes `BytesKind` to `coderBytesNoZero`
//! (`google.golang.org/protobuf@v1.36.11/internal/impl/codec_tables.go:
//! 200,273-278`), whose `appendBytesNoZero` returns the buffer untouched
//! when `len(v) == 0` (`codec_gen.go:5477-5485`), never writing the tag byte.
//! So an empty write serializes to a *zero-length* Hunk message: still a real
//! gRPC frame (length 0 in the five-byte prefix), just with no protobuf body
//! after it — not `0a 00`, which would claim a present-but-empty field.

fn put_varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Encodes one write as a single uncompressed `Hunk` message.
///
/// The length prefix is filled in *after* the tag, varint and payload are
/// already in `out`, by patching `out[1..5]` from `out.len() - 5`, rather
/// than computed up front from a second walk of `payload.len()`. Two
/// independent derivations of "how many bytes will the varint take" — one
/// sizing the prefix, one driving what `put_varint` actually emits — would
/// only need to disagree once, after an edit to either, to make the length
/// prefix lie about the body it precedes. That corrupts the wire silently:
/// Task 3's decoder trusts this prefix to know where the message ends.
/// Reading the length back from what was actually written makes it true by
/// construction instead of by two functions agreeing.
pub fn encode_hunk(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        // No tag, no varint: proto3 drops a zero-length `bytes` field
        // entirely (see module doc), so the message body is empty and only
        // the five-byte gRPC prefix (with length 0) goes on the wire.
        return vec![0x00, 0x00, 0x00, 0x00, 0x00];
    }

    // Capacity is a safe upper bound, not a byte-exact count: 5 for the
    // prefix and 1 for the tag are fixed, and no varint of a `usize` needs
    // more than 10 bytes, so `+ 16` never triggers a reallocation without
    // computing a second, independent varint length just to size the `Vec`.
    let mut out = Vec::with_capacity(payload.len() + 16);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]); // compression flag + length placeholder
    out.push(0x0a);
    put_varint(&mut out, payload.len());
    out.extend_from_slice(payload);

    let body_len = out.len() - 5;
    debug_assert!(
        u32::try_from(body_len).is_ok(),
        "gRPC message body exceeds gRPC's own u32 length prefix"
    );
    out[1..5].copy_from_slice(&(body_len as u32).to_be_bytes());

    out
}
