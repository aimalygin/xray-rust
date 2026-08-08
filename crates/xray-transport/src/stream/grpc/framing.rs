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

/// `payloadLen + sizeLen` (`grpc@v1.81.0/rpc_util.go:858-860`).
const GRPC_HEADER_LEN: usize = 5;

/// grpc-go's `defaultClientMaxReceiveMessageSize`
/// (`grpc@v1.81.0/clientconn.go:141`). Xray installs no `MaxCallRecvMsgSize`
/// call option anywhere under `transport/internet/grpc/`, so the stock client
/// default is what a real Xray peer holds itself to and what we hold it to.
const MAX_RECEIVE_MESSAGE_SIZE: usize = 1024 * 1024 * 4;

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
/// already in `out`, by patching the four length bytes from `out.len() -
/// GRPC_HEADER_LEN`, rather than computed up front from a second walk of
/// `payload.len()`. Two
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
        return vec![0x00; GRPC_HEADER_LEN];
    }

    // Capacity is a safe upper bound, not a byte-exact count: the header and
    // the one-byte tag are fixed, and no varint of a `usize` needs more than
    // ten bytes, so this never reallocates and never needs a second,
    // independent varint length computed just to size the `Vec`.
    let mut out = Vec::with_capacity(payload.len() + GRPC_HEADER_LEN + 1 + 10);
    out.extend_from_slice(&[0x00; GRPC_HEADER_LEN]); // compression flag + length placeholder
    out.push(0x0a);
    put_varint(&mut out, payload.len());
    out.extend_from_slice(payload);

    let body_len = out.len() - GRPC_HEADER_LEN;
    debug_assert!(
        u32::try_from(body_len).is_ok(),
        "gRPC message body exceeds gRPC's own u32 length prefix"
    );
    out[1..GRPC_HEADER_LEN].copy_from_slice(&(body_len as u32).to_be_bytes());

    out
}

/// Reassembles `Hunk` messages from however the HTTP/2 layer chops the stream.
///
/// **An empty payload is not end of stream.** `encode_hunk(&[])` puts a real
/// five-byte, zero-body message on the wire (see the module doc), and Xray's
/// own reader treats it as a legal zero-byte read: `HunkReaderWriter.Read`
/// fetches the hunk, `copy(buf, h.buf[0:])` copies nothing and it returns
/// `(0, nil)` (`Xray-core/transport/internet/grpc/encoding/hunkconn.go:
/// 91-105`). In Rust `Ok(0)` out of an `AsyncRead` means EOF instead, so
/// whatever wrapper sits above this decoder must *not* forward an empty
/// payload to its caller as a completed read — it has to loop and ask for the
/// next message. Translating one into EOF would tear down a live tunnel the
/// moment a peer flushed an empty write.
#[derive(Debug, Default)]
pub struct HunkDecoder {
    buffer: Vec<u8>,
    consumed: usize,
}

impl HunkDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next complete message's payload, or `None` when more bytes are
    /// needed. `Err` means the stream is unusable, not that it stalled.
    ///
    /// The error stays a `String` rather than becoming
    /// `TransportError::Grpc`, which now exists: this decoder is pure framing
    /// with nothing transport-shaped to say, and `GrpcStream` is where the
    /// message picks up its `io::Error` wrapper anyway. The sibling decoder
    /// returns `TransportError::WebSocketProtocol`
    /// (`websocket_frame.rs:next_event`) only because it was written before
    /// there was a caller to hold that concern.
    pub fn next_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some((payload, length)) = self.parse_message()? else {
            self.compact();
            return Ok(None);
        };
        self.consumed += length;
        Ok(Some(payload))
    }

    /// How many bytes of a message that has not finished arriving the decoder
    /// is holding.
    ///
    /// `Ok(None)` alone cannot tell "the peer has sent whole messages and
    /// stopped" from "a Hunk arrived cut in half": both stall identically, so
    /// an `AsyncRead` wrapper that only watched `next_payload` would report a
    /// clean EOF over a truncated message and silently drop it. grpc-go draws
    /// the line — an `io.EOF` landing part-way through the five-byte header
    /// becomes `io.ErrUnexpectedEOF`
    /// (`grpc@v1.81.0/internal/transport/transport.go:360-380`), and so does
    /// one landing inside a body the header already promised
    /// (`rpc_util.go:787-792`). `GrpcStream` draws it the same way: a non-zero
    /// count when the h2 stream ends is truncation, not EOF.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len() - self.consumed
    }

    /// Drops the bytes already handed out, so a long-lived stream does not
    /// grow its buffer without bound.
    fn compact(&mut self) {
        if self.consumed == 0 {
            return;
        }
        self.buffer.drain(..self.consumed);
        self.consumed = 0;
    }

    fn parse_message(&self) -> Result<Option<(Vec<u8>, usize)>, String> {
        let bytes = &self.buffer[self.consumed..];
        if bytes.len() < GRPC_HEADER_LEN {
            return Ok(None);
        }

        // Both checks below run off the header alone, before the body is
        // waited for, mirroring `recvMsg`: it reads the five bytes, rejects an
        // over-long length, and only then calls `p.r.Read(int(length))`
        // (`grpc@v1.81.0/rpc_util.go:771-794`). Deferring either to "once the
        // body arrives" would let a peer make us hold an arbitrary buffer by
        // declaring a length it never sends.
        match bytes[0] {
            0 => {}
            // `checkRecvPayload` refuses `compressionMade` outright when the
            // response carried no `grpc-encoding`, which ours never does:
            // "compressed flag set with identity or empty encoding"
            // (`grpc@v1.81.0/rpc_util.go:894-906`).
            1 => {
                return Err(
                    "gRPC message has the compressed flag set but no grpc-encoding was \
                     negotiated"
                        .to_owned(),
                )
            }
            format => return Err(format!("unexpected gRPC payload format {format}")),
        }

        let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if length > MAX_RECEIVE_MESSAGE_SIZE {
            return Err(format!(
                "gRPC message of {length} bytes exceeds the {MAX_RECEIVE_MESSAGE_SIZE} byte \
                 receive limit"
            ));
        }

        let total = GRPC_HEADER_LEN + length;
        if bytes.len() < total {
            return Ok(None);
        }

        Ok(Some((parse_hunk(&bytes[GRPC_HEADER_LEN..total])?, total)))
    }
}

/// The `Hunk` body: field 1 is the payload, everything else is skipped.
///
/// Two protobuf-go behaviours this reproduces rather than improves on, both
/// checked by unmarshalling the same bytes into Xray's own `encoding.Hunk`:
///
/// * **A repeated field 1 is last-one-wins, not concatenation.**
///   `consumeBytesNoZero` assigns — `*p.Bytes() = append(([]byte)(nil), v...)`
///   (`protobuf@v1.36.11/internal/impl/codec_gen.go:5489-5500`) — so the
///   earlier entry is overwritten, and `0a 02 "hi" 0a 03 "yo!"` decodes to
///   `"yo!"`. Concatenating would put bytes into the tunnel that the Go peer
///   on the other end never put there, which for a byte stream is worse than
///   matching a quirk: Xray only ever marshals one `Data`, so any second entry
///   already means we and the peer disagree about the message.
/// * **A wire-type mismatch on field 1 is not a parse error.** The field coder
///   returns `errUnknown` for `wtyp != BytesType` (`codec_gen.go:5490-5492`),
///   and `unmarshalPointerEager` then skips the value as an unknown field
///   instead of failing (`internal/impl/decode.go:218-231`). So it is handled
///   here by the same skip path as an unrecognised field number.
///
/// One deliberate divergence: wire type 3 (start group). protobuf-go walks the
/// group to its `EndGroupType` and skips it (`protowire/wire.go:130-153`),
/// which needs a recursive skipper and its own depth limit. `Hunk` has a
/// single `bytes` field and no groups, so a group here means the peer is not
/// sending a `Hunk`, and refusing is safer than recursing on its say-so.
fn parse_hunk(body: &[u8]) -> Result<Vec<u8>, String> {
    // protowire's valid field-number range (`protowire/wire.go:24-27`).
    const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;

    let mut data: &[u8] = &[];
    let mut cursor = 0;

    while cursor < body.len() {
        let (tag, width) = read_varint(&body[cursor..])?;
        cursor += width;

        let field = tag >> 3;
        if field == 0 || field > MAX_FIELD_NUMBER {
            return Err(format!("protobuf field number {field} is out of range"));
        }

        let wire_type = tag & 7;
        if wire_type == 2 {
            let (length, width) = read_varint(&body[cursor..])?;
            let start = cursor + width; // `read_varint` already proved it fits
            let end = usize::try_from(length)
                .ok()
                .and_then(|length| start.checked_add(length))
                .filter(|end| *end <= body.len())
                .ok_or_else(|| {
                    format!("protobuf field {field} declares {length} bytes, past the end of the gRPC message")
                })?;

            if field == 1 {
                data = &body[start..end];
            }
            cursor = end;
            continue;
        }

        let value_width = match wire_type {
            // The varint's own bounds check is `read_varint`'s.
            0 => read_varint(&body[cursor..])?.1,
            1 => 8,
            5 => 4,
            other => return Err(format!("unsupported protobuf wire type {other}")),
        };
        cursor = cursor
            .checked_add(value_width)
            .filter(|end| *end <= body.len())
            .ok_or_else(|| {
                format!("protobuf field {field} runs past the end of the gRPC message")
            })?;
    }

    Ok(data.to_vec())
}

/// protowire's `ConsumeVarint` (`protobuf@v1.36.11/encoding/protowire/
/// wire.go:267-365`): at most ten bytes, and the tenth carries one bit, so a
/// value wider than 64 bits is an overflow rather than a wrapped number.
/// Non-minimal encodings pass, as they do there.
///
/// The loop cannot fall through with ten bytes in hand — byte ten either has
/// no continuation bit, and returns, or exceeds 1, and overflows — so reaching
/// the end means the varint was truncated by the end of the message.
fn read_varint(bytes: &[u8]) -> Result<(u64, usize), String> {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().take(10).enumerate() {
        if index == 9 && *byte > 1 {
            return Err("protobuf varint overflows 64 bits".to_owned());
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }

    Err("protobuf varint runs past the end of the gRPC message".to_owned())
}
