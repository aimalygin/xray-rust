# gRPC Stream Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dial VLESS over Xray-core's gRPC stream transport, so a `"network": "grpc"` profile imports and works instead of being refused at parse time.

**Architecture:** A hand-rolled gRPC codec (5-byte prefix plus a one-field protobuf message) over the `h2` crate, with one HTTP/2 connection pooled per outbound and one H2 stream per proxied flow. The pool is the reason this stage also grows the dial seam: `TransportLayer::wrap(stream) -> stream` is one socket in and one stream out, which gRPC violates. Everything below the transport — TLS shaping, ALPN, REALITY, Happy Eyeballs, `VpnService.protect(fd)` — is inherited unchanged by routing every dial through `TransportDialer::connect_resolved`.

**Tech Stack:** Rust 2021, `h2` 0.4.15 (new), `tokio`, the existing `xray-transport` / `xray-config` / `xray-core-rs` crates, a Go oracle module for fixtures.

**Design of record:** `docs/superpowers/specs/2026-08-06-vless-stream-transports-design.md`, Stage 2 and the 2026-08-08 amendment. Read both before Task 1. Where this plan and the spec disagree, stop and reconcile rather than picking.

---

## What already exists

Stage 1 (`ws` + `httpupgrade` + plain-TLS uTLS shaping) shipped on this branch and is the pattern to copy:

- A transport is one private module under `crates/xray-transport/src/stream/`, exposing a `#[derive(Debug, Clone)]` config struct with owned, fully-resolved `pub` fields and a free `pub async fn connect_<name>(stream, &config) -> Result<BoxedTransportStream, TransportError>`.
- There are **no `#[cfg(test)]` unit tests** in the stream module. Every test is an integration test in `crates/xray-transport/tests/stream_<name>_tests.rs`, organised into `mod` blocks, standing up a real `TcpListener` on `127.0.0.1:0`. Those blocks are named `stream_<transport>_<aspect>_tests`, matching the sibling files — the task texts below sometimes write the bare aspect (`mod path`, `mod framing_write`); use the convention rather than the literal.
- Errors are flat `thiserror` variants on `TransportError` (`crates/xray-transport/src/lib.rs:108`), lowercase, no trailing period, one `String` per transport.
- Doc comments explain *why*, usually by naming the Xray-core behaviour being matched.

Three facts that shape this plan, all verified:

1. `TransportLayer::wrap` has exactly one caller in the workspace — `crates/xray-transport/src/dialer.rs:114`. Confirm with `grep -rn "\.wrap(" crates/` before changing it.
2. `crates/xray-config/src/parser.rs:2571` rejects REALITY for any network that is not `Raw`, while its own message reads *"REALITY only supports RAW, XHTTP and gRPC for now"*. Xray permits `tcp`, `splithttp` and `grpc` (`Xray-core/infra/conf/transport_internet.go:1989`). Until this becomes an allow-list, REALITY + gRPC — a real deployment — stays unreachable.
3. **There is no `gunSettings` alias in v26.5.9.** A grep for `gun` across the vendored tree returns only toolchain noise. Do not add one; it would accept a config xray-core rejects, which is the exact failure this project exists to avoid.

## File structure

| File | Responsibility |
| --- | --- |
| `crates/xray-transport/src/stream/grpc/path.rs` | `serviceName` → `:path`. Pure, no deps. |
| `crates/xray-transport/src/stream/grpc/framing.rs` | Hunk encode + a decoder that reassembles across DATA frames. Pure, no deps. |
| `crates/xray-transport/src/stream/grpc/stream.rs` | The `TransportStream` adapter over one H2 stream. |
| `crates/xray-transport/src/stream/grpc/pool.rs` | One `h2::client::SendRequest` per outbound, single-flighted, retired on driver exit. |
| `crates/xray-transport/src/stream/grpc/mod.rs` | `GrpcConfig`, `GrpcTransport`, `open_stream`. |
| `crates/xray-transport/src/stream/mod.rs` | New `TransportLayer::Grpc` variant; `wrap` deleted. |
| `crates/xray-transport/src/dialer.rs` | One branch in `connect_stream`. |
| `crates/xray-config/src/{model,parser}.rs` | `GrpcSettings`, `StreamTransport::Grpc`, `StreamNetwork::Grpc`, `parse_grpc_settings`, the REALITY allow-list. |
| `crates/xray-core-rs/src/outbound.rs` | `build_transport_layer` arm; the freedom/DNS guard asymmetry. |
| `tools/reality-oracle/grpc/` | New nested Go module producing the wire fixtures. |
| `tests/fixtures/grpc/` | Committed oracle output. |

Everything in `grpc/` is `pub(crate)` except what `mod.rs` re-exports, matching how `websocket_frame` is exposed today.

---

### Task 1: `serviceName` → `:path`

Xray builds the request path as `"/" + serviceName + "/" + streamName`
(`Xray-core/transport/internet/grpc/encoding/customSeviceName.go:33`), where both halves come from
`Xray-core/transport/internet/grpc/config.go:17-59`. A mis-escaped path returns an opaque
`UNIMPLEMENTED` from the server rather than a config error, so this is table-tested against the Go
source directly.

**Files:**
- Create: `crates/xray-transport/src/stream/grpc/path.rs`
- Create: `crates/xray-transport/src/stream/grpc/mod.rs`
- Modify: `crates/xray-transport/src/stream/mod.rs`
- Test: `crates/xray-transport/tests/stream_grpc_tests.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/xray-transport/tests/stream_grpc_tests.rs`:

```rust
mod path {
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p xray-transport --test stream_grpc_tests`
Expected: FAIL to compile — `unresolved import xray_transport::stream::grpc_request_path`.

- [ ] **Step 3: Write the implementation**

Create `crates/xray-transport/src/stream/grpc/path.rs`:

```rust
//! `serviceName` to `:path`, following Xray's two dialects.
//!
//! Xray reads a name without a leading `/` as an old-school service name and
//! escapes it whole, so an inner `/` becomes `%2F`. A name *with* a leading `/`
//! is a custom path: everything between the first and last `/` is the service
//! name escaped segment by segment, and the last segment is the stream name,
//! optionally split on `|` into the plain and multi-mode names.
//! `Xray-core/transport/internet/grpc/config.go:17-59`.

/// Go's `url.PathEscape`, i.e. `escape(s, encodePathSegment)`.
///
/// Alphanumerics and `-_.~` pass; of the reserved set, `encodePathSegment`
/// keeps `$ & + : = @` and escapes `/ ; , ?`; everything else is escaped.
/// Go writes the hex digits in upper case.
fn path_escape(input: &str) -> String {
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        let keep = matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || matches!(byte, b'$' | b'&' | b'+' | b':' | b'=' | b'@');
        if keep {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(UPPER_HEX[usize::from(byte >> 4)] as char);
            out.push(UPPER_HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

fn service_name(configured: &str) -> String {
    if !configured.starts_with('/') {
        return path_escape(configured);
    }

    // `lastIndex < 1` is clamped to 1 upstream, which turns `/hello` into an
    // empty service name rather than panicking on an empty slice.
    let last_slash = configured.rfind('/').unwrap_or(0).max(1);
    configured[1..last_slash]
        .split('/')
        .map(path_escape)
        .collect::<Vec<_>>()
        .join("/")
}

fn stream_name(configured: &str, multi_mode: bool) -> String {
    if !configured.starts_with('/') {
        return if multi_mode { "TunMulti" } else { "Tun" }.to_owned();
    }

    let last_slash = configured.rfind('/').expect("checked for a leading slash");
    let ending = &configured[last_slash + 1..];
    let mut parts = ending.split('|');
    let first = parts.next().unwrap_or_default();

    if !multi_mode {
        return path_escape(first);
    }

    // One part means the whole ending path is the multi name; two means the
    // second part is. Upstream calls these the client and server spellings,
    // but the client honours both.
    match parts.next() {
        Some(second) => path_escape(second),
        None => path_escape(first),
    }
}

/// The `:path` pseudo-header for one gRPC dial.
pub fn grpc_request_path(configured_service_name: &str, multi_mode: bool) -> String {
    format!(
        "/{}/{}",
        service_name(configured_service_name),
        stream_name(configured_service_name, multi_mode)
    )
}
```

Create `crates/xray-transport/src/stream/grpc/mod.rs`:

```rust
//! Xray's gRPC stream transport: VLESS bytes inside `Hunk` messages on one
//! bidirectional HTTP/2 stream.

mod path;

pub use path::grpc_request_path;
```

In `crates/xray-transport/src/stream/mod.rs`, add the module beside the others and re-export:

```rust
mod grpc;
```

```rust
pub use grpc::grpc_request_path;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p xray-transport --test stream_grpc_tests`
Expected: PASS, 1 test.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/stream/grpc crates/xray-transport/src/stream/mod.rs crates/xray-transport/tests/stream_grpc_tests.rs
git commit -m "feat(transport): build the gRPC request path from serviceName"
```

---

### Task 2: Hunk framing, write side

One write becomes one gRPC message: a compression flag, a big-endian length, then a `Hunk`
protobuf whose only field is `bytes data = 1`.

**Files:**
- Create: `crates/xray-transport/src/stream/grpc/framing.rs`
- Modify: `crates/xray-transport/src/stream/grpc/mod.rs`
- Test: `crates/xray-transport/tests/stream_grpc_tests.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/xray-transport/tests/stream_grpc_tests.rs`:

```rust
mod framing_write {
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
    fn an_empty_payload_produces_a_message_with_an_empty_body() {
        // Proto3 implicit presence: `bytes data = 1` is not serialized at all
        // when empty, so the tag never reaches the wire. What goes out is the
        // five-byte prefix with length zero -- a message, not nothing, so a
        // zero-length write still does not look like a stall.
        // `encoding/stream.pb.go:26` (no `optional`), and protobuf-go's
        // `appendBytesNoZero`, which returns the buffer untouched at length 0.
        assert_eq!(encode_hunk(&[]), vec![0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p xray-transport --test stream_grpc_tests framing_write`
Expected: FAIL to compile — `unresolved import`.

- [ ] **Step 3: Write the implementation**

Create `crates/xray-transport/src/stream/grpc/framing.rs`:

```rust
//! The gRPC message framing Xray's `Hunk` rides in.
//!
//! `message Hunk { bytes data = 1; }` behind gRPC's own five-byte prefix, so
//! one write of N bytes is: a compression flag, a big-endian u32 length, the
//! protobuf tag `0x0a`, a varint length, and the payload. Overhead is seven
//! bytes below 128 and eight below 16384.

/// Number of bytes a protobuf varint needs for `value`.
fn varint_len(value: usize) -> usize {
    let mut len = 1;
    let mut remaining = value >> 7;
    while remaining > 0 {
        len += 1;
        remaining >>= 7;
    }
    len
}

fn put_varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Encodes one write as a single uncompressed `Hunk` message.
pub fn encode_hunk(payload: &[u8]) -> Vec<u8> {
    let body_len = 1 + varint_len(payload.len()) + payload.len();
    let mut out = Vec::with_capacity(5 + body_len);

    out.push(0x00);
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out.push(0x0a);
    put_varint(&mut out, payload.len());
    out.extend_from_slice(payload);

    out
}
```

Add to `crates/xray-transport/src/stream/grpc/mod.rs`:

```rust
mod framing;

pub use framing::encode_hunk;
```

and re-export `encode_hunk` from `crates/xray-transport/src/stream/mod.rs` beside `grpc_request_path`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p xray-transport --test stream_grpc_tests framing_write`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/stream/grpc crates/xray-transport/src/stream/mod.rs crates/xray-transport/tests/stream_grpc_tests.rs
git commit -m "feat(transport): encode gRPC Hunk messages"
```

---

### Task 3: Hunk framing, read side

This is where the known prior-art bug lives: clash-rs assumes the five-byte prefix and the first
varint byte arrive contiguously, so a length split across two DATA frames misparses. The decoder
below is fed arbitrary chunk boundaries by construction.

**Files:**
- Modify: `crates/xray-transport/src/stream/grpc/framing.rs`
- Test: `crates/xray-transport/tests/stream_grpc_tests.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/xray-transport/tests/stream_grpc_tests.rs`:

```rust
mod framing_read {
    use xray_transport::stream::{encode_hunk, HunkDecoder};

    fn drain(decoder: &mut HunkDecoder) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(payload) = decoder.next_payload().expect("well-formed stream") {
            out.push(payload);
        }
        out
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
        let body = [0x10, 0x01, 0x0a, 0x02, b'h', b'i'];
        let mut framed = vec![0x00];
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);

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
        let error = decoder.next_payload().expect_err("compression must be refused");
        assert!(
            error.contains("compress"),
            "error should name the compression flag, got: {error}"
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p xray-transport --test stream_grpc_tests framing_read`
Expected: FAIL to compile — `HunkDecoder` not found.

- [ ] **Step 3: Write the implementation**

Append to `crates/xray-transport/src/stream/grpc/framing.rs`:

```rust
/// Reassembles `Hunk` messages from arbitrary HTTP/2 DATA chunk boundaries.
///
/// Nothing guarantees a frame boundary lines up with a message boundary, and a
/// decoder that assumes the five-byte prefix and the first varint byte arrive
/// together misparses a length split across two DATA frames.
#[derive(Debug, Default)]
pub struct HunkDecoder {
    buffer: Vec<u8>,
    consumed: usize,
}

impl HunkDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Returns the next complete payload, or `None` when more bytes are needed.
    pub fn next_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        let available = &self.buffer[self.consumed..];
        if available.len() < 5 {
            self.compact();
            return Ok(None);
        }

        if available[0] != 0 {
            return Err(format!(
                "gRPC message declares compression flag {}, and we advertise no encoding",
                available[0]
            ));
        }

        let body_len = u32::from_be_bytes([available[1], available[2], available[3], available[4]])
            as usize;
        if available.len() < 5 + body_len {
            self.compact();
            return Ok(None);
        }

        let body = &available[5..5 + body_len];
        let payload = hunk_data(body)?;
        self.consumed += 5 + body_len;
        self.compact();

        Ok(Some(payload))
    }

    /// Drops the consumed prefix once it dominates the buffer, so a long-lived
    /// stream does not grow without bound.
    fn compact(&mut self) {
        if self.consumed == 0 {
            return;
        }
        if self.consumed == self.buffer.len() {
            self.buffer.clear();
            self.consumed = 0;
            return;
        }
        if self.consumed >= 8 * 1024 {
            self.buffer.drain(..self.consumed);
            self.consumed = 0;
        }
    }
}

fn read_varint(body: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *body
            .get(*cursor)
            .ok_or_else(|| "gRPC message ends inside a varint".to_owned())?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err("gRPC message carries an oversized varint".to_owned());
        }
    }
}

/// Reads field 1 out of a `Hunk`, skipping anything else the peer sent.
fn hunk_data(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = 0;
    let mut data = Vec::new();

    while cursor < body.len() {
        let tag = read_varint(body, &mut cursor)?;
        let field = tag >> 3;
        let wire_type = tag & 0x07;

        match (field, wire_type) {
            (1, 2) => {
                let len = read_varint(body, &mut cursor)? as usize;
                let end = cursor
                    .checked_add(len)
                    .filter(|end| *end <= body.len())
                    .ok_or_else(|| "gRPC Hunk declares more data than it carries".to_owned())?;
                data.extend_from_slice(&body[cursor..end]);
                cursor = end;
            }
            (_, 0) => {
                read_varint(body, &mut cursor)?;
            }
            (_, 2) => {
                let len = read_varint(body, &mut cursor)? as usize;
                cursor = cursor
                    .checked_add(len)
                    .filter(|end| *end <= body.len())
                    .ok_or_else(|| "gRPC message declares more data than it carries".to_owned())?;
            }
            (_, 5) => cursor += 4,
            (_, 1) => cursor += 8,
            (_, other) => {
                return Err(format!("gRPC message uses unsupported wire type {other}"));
            }
        }
    }

    Ok(data)
}
```

Export `HunkDecoder` from `grpc/mod.rs` and `stream/mod.rs` beside `encode_hunk`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p xray-transport --test stream_grpc_tests framing_read`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/stream/grpc/framing.rs crates/xray-transport/src/stream/grpc/mod.rs crates/xray-transport/src/stream/mod.rs crates/xray-transport/tests/stream_grpc_tests.rs
git commit -m "feat(transport): decode gRPC Hunk messages across frame boundaries"
```

---

### Task 4: `grpcSettings` in the config layer

Eight keys, four of them snake_case upstream and four not. Copy the spelling verbatim: a camelCase
`idleTimeout` would be silently ignored by xray-core, so accepting it here would let a config work
that does not work there.

Read `Xray-core/infra/conf/grpc.go` before writing this task. The only validations upstream performs
are three negative-to-zero clamps; `serviceName` and `user_agent` are passed through untouched, so
our parser must not reject an arbitrary `user_agent` string.

**Files:**
- Modify: `crates/xray-config/src/model.rs`
- Modify: `crates/xray-config/src/parser.rs`
- Modify: `crates/xray-config/src/lib.rs`
- Test: `crates/xray-config/tests/parser_tests.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/xray-config/tests/parser_tests.rs`, mirroring the existing `wsSettings` positive
tests:

```rust
#[test]
fn parses_grpc_settings_with_every_key() {
    let raw = r#"{
      "outbounds": [{
        "protocol": "vless",
        "settings": { "vnext": [{ "address": "example.com", "port": 443,
          "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }] },
        "streamSettings": {
          "network": "grpc",
          "security": "tls",
          "grpcSettings": {
            "serviceName": "hello",
            "multiMode": true,
            "authority": "cdn.example.com",
            "user_agent": "chrome",
            "idle_timeout": 30,
            "health_check_timeout": 40,
            "permit_without_stream": true,
            "initial_windows_size": 65536
          }
        }
      }]
    }"#;

    let config = parse_xray_json(raw).expect("a full grpcSettings block should parse");
    let StreamTransport::Grpc(grpc) = &config.outbounds[0].stream.transport else {
        panic!("expected the grpc transport");
    };

    assert_eq!(grpc.service_name, "hello");
    assert!(grpc.multi_mode);
    assert_eq!(grpc.authority.as_deref(), Some("cdn.example.com"));
    assert_eq!(grpc.user_agent.as_deref(), Some("chrome"));
    assert_eq!(grpc.idle_timeout_secs, 30);
    assert_eq!(grpc.health_check_timeout_secs, 40);
    assert!(grpc.permit_without_stream);
    assert_eq!(grpc.initial_windows_size, 65536);
}

#[test]
fn grpc_settings_are_optional() {
    // `StreamConfig.GetTransportSettingsFor` falls back to an empty config, so
    // `"network": "grpc"` alone is valid upstream and dials `//Tun`.
    let raw = vless_stream_config(r#""network": "grpc""#);
    let config = parse_xray_json(&raw).expect("grpc without settings should parse");
    let StreamTransport::Grpc(grpc) = &config.outbounds[0].stream.transport else {
        panic!("expected the grpc transport");
    };
    assert_eq!(grpc.service_name, "");
    assert!(!grpc.multi_mode);
}

#[test]
fn negative_grpc_timeouts_clamp_to_zero() {
    // The only validation `infra/conf/grpc.go` performs: negative becomes zero.
    let raw = vless_stream_config(
        r#""network": "grpc", "grpcSettings": { "idle_timeout": -5, "health_check_timeout": -1, "initial_windows_size": -1 }"#,
    );
    let config = parse_xray_json(&raw).expect("negative timeouts clamp rather than fail");
    let StreamTransport::Grpc(grpc) = &config.outbounds[0].stream.transport else {
        panic!("expected the grpc transport");
    };
    assert_eq!(grpc.idle_timeout_secs, 0);
    assert_eq!(grpc.health_check_timeout_secs, 0);
    assert_eq!(grpc.initial_windows_size, 0);
}

#[test]
fn a_non_string_grpc_service_name_is_refused() {
    let raw = vless_stream_config(r#""network": "grpc", "grpcSettings": { "serviceName": 5 }"#);
    let error = parse_xray_json(&raw).expect_err("a numeric serviceName must not parse");
    assert!(
        error.to_string().contains("serviceName"),
        "error should name the offending key: {error}"
    );
}

#[test]
fn gun_settings_are_not_an_alias() {
    // v26.5.9 has no `gunSettings` and no `gun` network. Accepting either
    // would let a profile run here that xray-core refuses.
    let raw = vless_stream_config(r#""network": "gun""#);
    parse_xray_json(&raw).expect_err("`gun` is not a network xray-core knows");
}
```

If `vless_stream_config` does not already exist as a helper in that file, add it next to
`vless_raw_with_network` following the same shape — do not inline the JSON five times.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p xray-config --test parser_tests grpc`
Expected: FAIL — `StreamTransport::Grpc` does not exist, and the parse calls error with
`unsupported stream network `grpc``.

- [ ] **Step 3: Write the implementation**

In `crates/xray-config/src/model.rs`, beside `WebSocketSettings`:

```rust
/// `grpcSettings`. Key spellings are Xray's, inconsistencies included: four of
/// the eight are snake_case upstream and renaming them here would accept a
/// config xray-core ignores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcSettings {
    pub service_name: String,
    pub multi_mode: bool,
    pub authority: Option<String>,
    pub user_agent: Option<String>,
    pub idle_timeout_secs: u32,
    pub health_check_timeout_secs: u32,
    pub permit_without_stream: bool,
    pub initial_windows_size: u32,
}
```

Add `Grpc(GrpcSettings)` to `enum StreamTransport` and export `GrpcSettings` from `lib.rs`.

In `crates/xray-config/src/parser.rs`:

1. Add `Grpc` to the parser-local `enum StreamNetwork` (line 42).
2. In `parse_network`, add `"grpc" => Some(StreamNetwork::Grpc),` beside the ws arm.
3. In `parse_stream_transport`, add
   `StreamNetwork::Grpc => self.parse_grpc_settings(stream, index).map(StreamTransport::Grpc),`.
4. In `validate_unconsumed_transport_settings`, add `StreamNetwork::Grpc => &["grpcSettings"]` to
   the consumed match and `"grpcSettings"` to the known-keys list.
5. Add `"grpcSettings"` to the `streamSettings` key allow-list.
6. Write `parse_grpc_settings` next to `parse_websocket_settings`, using the same optional-value
   helpers. Negative integers clamp to zero rather than erroring; a non-string `serviceName`,
   `authority` or `user_agent` errors naming the key; a non-boolean `multiMode` or
   `permit_without_stream` errors naming the key.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p xray-config`
Expected: PASS. `rejects_other_stream_network_with_path` will now fail — it uses `grpc` as its
negative example. Repoint it to `"kcp"` and leave a comment saying why the example moved.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-config
git commit -m "feat(config): parse grpcSettings"
```

---

### Task 5: Let REALITY reach gRPC, and fix the guard that disagrees with its twin

Two independent bugs in the same neighbourhood, both fixed here because the next task depends on the
first and the second is a one-line asymmetry that will otherwise outlive this branch.

**Files:**
- Modify: `crates/xray-config/src/parser.rs:2571`
- Modify: `crates/xray-core-rs/src/outbound.rs` (`compile_udp_outbound`'s freedom arm)
- Test: `crates/xray-config/tests/parser_tests.rs`, `crates/xray-core-rs/src/outbound.rs` tests

- [ ] **Step 1: Write the failing tests**

In `crates/xray-config/tests/parser_tests.rs`:

```rust
#[test]
fn reality_is_accepted_on_grpc() {
    // `Xray-core/infra/conf/transport_internet.go:1989` permits tcp, splithttp
    // and grpc. Our guard's own message has always said so.
    let raw = vless_raw_with_network("grpc", None);
    parse_xray_json(&raw).expect("REALITY + gRPC is a configuration xray-core builds");
}

#[test]
fn reality_is_still_refused_on_websocket() {
    let raw = vless_raw_with_network("ws", Some("/path"));
    let error = parse_xray_json(&raw).expect_err("REALITY + ws must stay refused");
    assert!(error.to_string().contains("REALITY only supports"));
}
```

In `crates/xray-core-rs/src/outbound.rs`, beside the existing cached-router tests:

```rust
#[test]
fn a_cached_udp_freedom_outbound_refuses_a_stream_transport() {
    // `build_udp_outbound` refuses this; the cached router's UDP arm did not,
    // so one config got two verdicts depending on whether the cache was live.
    let config = freedom_config_with_network("ws");
    let router = OutboundRouter::new(config.clone());

    assert!(matches!(
        router.select_udp_outbound(),
        Err(CoreError::UnsupportedOutboundNetwork)
    ));
    assert!(matches!(
        build_udp_outbound(&config.outbounds[0]),
        Err(CoreError::UnsupportedOutboundNetwork)
    ));
}
```

Write `freedom_config_with_network` next to the other test-config helpers in that file if it does
not exist. Match the receiver name the router's UDP selector actually uses — read the file rather
than assuming `select_udp_outbound`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p xray-config --test parser_tests reality_is_accepted_on_grpc` and
`cargo test -p xray-core-rs a_cached_udp_freedom_outbound_refuses_a_stream_transport`
Expected: the first fails with the REALITY message, the second fails because the cached router
returns `Ok`.

- [ ] **Step 3: Write the implementation**

`crates/xray-config/src/parser.rs:2571` becomes an allow-list:

```rust
        // Xray permits REALITY on tcp, splithttp and grpc
        // (`infra/conf/transport_internet.go:1989`). The message below has
        // always quoted that rule; the condition now matches it.
        if matches!(security, StreamSecurity::Reality(_))
            && !matches!(stream_network, StreamNetwork::Raw | StreamNetwork::Grpc)
        {
```

In `crates/xray-core-rs/src/outbound.rs`, add the missing guard to `compile_udp_outbound`'s
`OutboundSettings::Freedom` arm so it reads exactly like `build_udp_outbound`'s:

```rust
            OutboundSettings::Freedom => {
                if !stream_transport_is_dialable(&outbound.stream) {
                    return Err(CachedOutboundError::UnsupportedOutboundNetwork);
                }
                if outbound.stream.security != StreamSecurity::None {
                    return Err(CachedOutboundError::UnsupportedOutboundSecurity);
                }
                Ok(UdpOutbound::Freedom)
            }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p xray-config && cargo test -p xray-core-rs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-config/src/parser.rs crates/xray-config/tests/parser_tests.rs crates/xray-core-rs/src/outbound.rs
git commit -m "fix(config): let REALITY reach gRPC and align the cached UDP freedom guard"
```

---

### Task 6: The `h2` dependency and a bidirectional POST

The probe below was compiled and run against an in-process `h2::server` before this plan was
written. Lift it rather than re-deriving it — several of its lines exist because the naive version
deadlocks.

**Files:**
- Modify: `Cargo.toml`, `crates/xray-transport/Cargo.toml`
- Create: `crates/xray-transport/src/stream/grpc/h2client.rs`
- Test: `crates/xray-transport/tests/stream_grpc_tests.rs`

- [ ] **Step 1: Add the dependency**

In the root `Cargo.toml` `[workspace.dependencies]`:

```toml
h2 = "0.4.15"
http = "1"
```

In `crates/xray-transport/Cargo.toml`:

```toml
h2.workspace = true
http.workspace = true
```

Run: `cargo tree -p xray-transport -i h2`
Expected: exactly seven new crates in `Cargo.lock` — `atomic-waker`, `fnv`, `futures-sink`, `h2`,
`http`, `tokio-util`, `tracing`, `tracing-core`. All licences are already on the `deny.toml`
allow-list; `THIRD_PARTY_NOTICES.md` needs no edit.

Run: `cargo deny --locked check advisories bans licenses sources`
Expected: no new findings.

- [ ] **Step 2: Write the failing test**

Append to `crates/xray-transport/tests/stream_grpc_tests.rs`:

```rust
mod h2_client {
    use bytes::Bytes;
    use http::{HeaderMap, Response};
    use xray_transport::stream::open_grpc_h2_stream;

    /// An in-process gRPC-shaped server: echoes DATA back and closes with
    /// `grpc-status: 0` trailers, the way xray-core's inbound does.
    async fn echo_server(io: tokio::io::DuplexStream) {
        let mut connection = h2::server::handshake(io).await.expect("server handshake");
        while let Some(accepted) = connection.accept().await {
            let (request, mut respond) = accepted.expect("accept");
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/hello/Tun");
            assert_eq!(
                request.headers().get("content-type").expect("content type"),
                "application/grpc"
            );

            tokio::spawn(async move {
                let mut body = request.into_body();
                let response = Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .expect("response");
                let mut send = respond.send_response(response, false).expect("send response");

                let mut flow = body.flow_control().clone();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("data");
                    flow.release_capacity(chunk.len()).expect("release");
                    send.send_data(chunk, false).expect("echo");
                }

                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().expect("status"));
                send.send_trailers(trailers).expect("trailers");
            });
        }
    }

    #[tokio::test]
    async fn a_bidirectional_post_carries_bytes_both_ways() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(echo_server(server_io));

        let mut stream = open_grpc_h2_stream(client_io, "example.com", "/hello/Tun", None)
            .await
            .expect("the stream should open");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"ping").await.expect("write");
        stream.flush().await.expect("flush");

        let mut received = vec![0u8; 4];
        stream.read_exact(&mut received).await.expect("read");
        assert_eq!(&received, b"ping");

        drop(stream);
        server.abort();
    }

    #[tokio::test]
    async fn a_payload_larger_than_the_default_window_still_completes() {
        // Without release_capacity on the read side the peer stalls at 64 KiB.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(echo_server(server_io));

        let mut stream = open_grpc_h2_stream(client_io, "example.com", "/hello/Tun", None)
            .await
            .expect("the stream should open");

        let payload = vec![0x5a; 512 * 1024];
        let writer = {
            let mut stream_writer = payload.clone();
            tokio::spawn(async move {
                let _ = &mut stream_writer;
            })
        };
        drop(writer);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let echo = tokio::spawn(async move {
            let mut sink = vec![0u8; payload.len()];
            read_half.read_exact(&mut sink).await.expect("read back");
            sink
        });
        write_half.write_all(&vec![0x5a; 512 * 1024]).await.expect("write");
        write_half.flush().await.expect("flush");

        assert_eq!(echo.await.expect("join"), vec![0x5a; 512 * 1024]);
        server.abort();
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p xray-transport --test stream_grpc_tests h2_client`
Expected: FAIL to compile — `open_grpc_h2_stream` not found.

- [ ] **Step 4: Write the implementation**

Create `crates/xray-transport/src/stream/grpc/h2client.rs`. The five things below are not
negotiable; each was observed failing in the other order:

1. The `Connection` future *is* the connection — spawn it and keep the handle. Dropping it kills
   every in-flight stream.
2. `send_request(request, false)` keeps the request body open. `true` makes `send_data` an error.
3. The uplink must `reserve_capacity` then await `poll_capacity` before `send_data`;
   `poll_capacity` is edge-triggered.
4. The downlink must `release_capacity` for every chunk or the peer stalls after 64 KiB.
5. `RST_STREAM` is emitted only when **all** stream references drop, so the adapter must own both
   the `SendStream` and the `RecvStream`.

```rust
//! One bidirectional HTTP/2 POST, shaped the way gRPC wants it.

use std::future::poll_fn;

use bytes::Bytes;
use h2::client::{self, SendRequest};
use http::{Method, Request, Version};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::TransportError;

/// Opens the connection and returns the handle streams are spawned from,
/// together with the driver task's join handle.
pub(crate) async fn handshake<T>(
    io: T,
) -> Result<(SendRequest<Bytes>, tokio::task::JoinHandle<Result<(), h2::Error>>), TransportError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // No builder knobs: a default client puts the 24-byte preface and an empty
    // SETTINGS frame on the wire, which is what grpc-go emits under Xray's
    // defaults. Setting initial_connection_window_size would additionally emit
    // a WINDOW_UPDATE at handshake time, which grpc-go does not.
    let (send_request, connection) = client::handshake::<T, Bytes>(io)
        .await
        .map_err(|error| TransportError::Grpc(format!("http/2 handshake failed: {error}")))?;

    let driver = tokio::spawn(async move { connection.await });

    Ok((send_request, driver))
}
```

Then the request itself, in the same file:

```rust
/// Sends the POST and returns its two halves.
///
/// The URI must be absolute: with `Version::HTTP_2` and no scheme plus
/// authority, h2 rejects the request with `MissingUriSchemeAndAuthority`.
/// The scheme stays `http` even over TLS, because xray-core dials gRPC with
/// `insecure.NewCredentials()` and applies TLS itself.
pub(crate) async fn send_grpc_request(
    send_request: &mut SendRequest<Bytes>,
    authority: &str,
    path: &str,
    user_agent: Option<&str>,
) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>), TransportError> {
    let mut builder = Request::builder()
        .version(Version::HTTP_2)
        .method(Method::POST)
        .uri(format!("http://{authority}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers");

    if let Some(user_agent) = user_agent {
        builder = builder.header("user-agent", user_agent);
    }

    let request = builder
        .body(())
        .map_err(|error| TransportError::Grpc(format!("building the request failed: {error}")))?;

    let ready = send_request
        .ready()
        .await
        .map_err(|error| TransportError::Grpc(format!("connection not ready: {error}")))?;

    let _ = ready;
    send_request
        .send_request(request, false)
        .map_err(|error| TransportError::Grpc(format!("opening the stream failed: {error}")))
}
```

Add the error variant to `crates/xray-transport/src/lib.rs`, beside `WebSocketProtocol`:

```rust
    #[error("grpc transport error: {0}")]
    Grpc(String),
```

Then write the adapter in `crates/xray-transport/src/stream/grpc/stream.rs`, implementing
`AsyncRead`, `AsyncWrite` and `TransportStream` over the `(SendStream, RecvStream)` pair. Two
requirements specific to this adapter:

- `RecvStream::poll_data` yields whole `Bytes` chunks that will routinely exceed the caller's
  `ReadBuf`. Keep a leftover buffer and drain it first — copy the shape of `PrefixedStream` in
  `crates/xray-transport/src/stream/httpupgrade.rs:231-248`.
- `is_end_stream()` is **false** when the stream ended with trailers. EOF is `data()` returning
  `None`, never `is_end_stream()`.

Writes go through `encode_hunk` before `send_data`; reads feed `HunkDecoder` and hand up the
decoded payloads. `poll_shutdown` sends the empty DATA with END_STREAM that `CloseSend` produces
upstream, and does **not** reset the stream — Xray's own client builds its hunk connection with a
nil cancel function, so its ordinary close is the quiet one.

Finally `open_grpc_h2_stream(io, authority, path, user_agent)` ties the three together for the test
above: handshake, send the request, wrap the halves. Mark it `pub` and re-export it; Task 8 replaces
its internals with a pool lookup but keeps the signature for the tests.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p xray-transport --test stream_grpc_tests h2_client`
Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/xray-transport
git commit -m "feat(transport): carry a gRPC stream over an http/2 POST"
```

---

### Task 7: Headers that match grpc-go

Everything the spec's Stage 2 section pins: the pseudo-header set, `:authority` precedence, the
`user-agent` table, and the two teardown shapes.

**Files:**
- Modify: `crates/xray-transport/src/stream/grpc/mod.rs`
- Test: `crates/xray-transport/tests/stream_grpc_tests.rs`

- [ ] **Step 1: Write the failing test**

The `echo_server` from Task 6 already captures the request. Extend it to return the observed
`http::Request` parts through a channel, then assert:

```rust
#[tokio::test]
async fn the_request_carries_grpc_gos_header_set() {
    let (observed, request) = spawn_capturing_server().await;
    // Resolution already happened in `build_transport_layer`; `GrpcConfig`
    // carries the resolved values, never the fallback chain.
    let config = GrpcConfig {
        service_name: "hello".to_owned(),
        multi_mode: false,
        authority: "example.com".to_owned(),
        user_agent: CHROME_USER_AGENT.to_owned(),
        idle_timeout_secs: 0,
        health_check_timeout_secs: 0,
        permit_without_stream: false,
        initial_windows_size: 0,
    };
    open_and_drop(request, &config).await;

    let parts = observed.await.expect("the server should observe a request");
    assert_eq!(parts.method, http::Method::POST);
    assert_eq!(parts.uri.scheme_str(), Some("http"));
    assert_eq!(parts.uri.authority().map(|a| a.as_str()), Some("example.com"));
    assert_eq!(parts.uri.path(), "/hello/Tun");
    assert_eq!(parts.headers.get("content-type").unwrap(), "application/grpc");
    assert_eq!(parts.headers.get("te").unwrap(), "trailers");
    // Absent on purpose: grpc-go sends none of these under Xray's options.
    assert!(parts.headers.get("grpc-accept-encoding").is_none());
    assert!(parts.headers.get("grpc-timeout").is_none());
    assert!(parts.headers.get("content-length").is_none());
}

#[tokio::test]
async fn the_user_agent_table_matches_xrays() {
    // dial.go:188-205. `golang` empties the header rather than falling back.
    for (configured, expected) in [
        (None, CHROME_USER_AGENT),
        (Some("chrome"), CHROME_USER_AGENT),
        (Some(""), CHROME_USER_AGENT),
        (Some("golang"), ""),
        (Some("my-client/1.0"), "my-client/1.0"),
    ] {
        let observed = user_agent_for(configured).await;
        assert_eq!(observed.as_deref(), Some(expected), "user_agent {configured:?}");
    }
}

#[tokio::test]
async fn a_resolved_authority_reaches_the_wire_verbatim() {
    // The precedence chain itself is resolved in `build_transport_layer` and
    // is tested there (Task 9). This asserts only that the transport does not
    // second-guess the value it was handed -- including a bracketed IPv6
    // authority, which grpc's own `encodeAuthority` leaves intact.
    for authority in ["cdn.example.com", "example.com:443", "[2001:db8::1]:443"] {
        let observed = authority_on_the_wire(authority).await;
        assert_eq!(observed.as_deref(), Some(authority));
    }
}
```

Read `Xray-core/transport/internet/grpc/dial.go:188-218` before writing `CHROME_USER_AGENT`; take
the literal string from `common/utils`, do not invent one.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p xray-transport --test stream_grpc_tests`
Expected: FAIL — `GrpcConfig` has no such fields yet.

- [ ] **Step 3: Implement `GrpcConfig` and the resolution rules**

```rust
/// Everything the gRPC dial needs, resolved from config plus the security
/// layer's server name.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Raw `serviceName`; the `:path` is derived per dial because `multiMode`
    /// picks a different stream name.
    pub service_name: String,
    pub multi_mode: bool,
    /// `:authority`: config `authority`, else the TLS server name, else — only
    /// when REALITY is absent — the destination domain. When all three are
    /// empty grpc-go falls back to `host:port`, port included.
    pub authority: String,
    /// Already resolved through Xray's table, so `golang` has become the empty
    /// string by the time it lands here.
    pub user_agent: String,
    pub idle_timeout_secs: u32,
    pub health_check_timeout_secs: u32,
    pub permit_without_stream: bool,
    pub initial_windows_size: u32,
}
```

An empty `user_agent` still emits the header with an empty value: the transport copies the field
verbatim and appends the header unconditionally.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p xray-transport --test stream_grpc_tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport
git commit -m "feat(transport): match grpc-go's request headers"
```

---

### Task 8: The connection pool and the dial seam

The riskiest task, deliberately last among the transport tasks: everything above already works over
a single connection, so this changes where a connection comes from and nothing else.

**Files:**
- Create: `crates/xray-transport/src/stream/grpc/pool.rs`
- Modify: `crates/xray-transport/src/stream/mod.rs`, `crates/xray-transport/src/dialer.rs`
- Test: `crates/xray-transport/tests/stream_grpc_tests.rs`

Four constraints, each verified:

- The pool must be `Arc<_>` inside the `TransportLayer` variant. `TransportLayer` is `Clone`, and
  `cached_vless_outbound` clones an outbound out of its `OnceLock` on every session; a deep-copying
  pool would give every flow its own.
- Use `tokio::sync::Mutex`, not `std::sync::Mutex`. The lock is held across the TLS/REALITY
  handshake — that is the single-flighting — and a `std` guard held across `.await` makes both
  `connect_stream` call sites `!Send`.
- Without single-flighting the pool is a pessimization at startup: N concurrent first flows each
  miss, each dial, and you pay N handshakes. That is precisely the cost pooling exists to avoid.
- Retire on **any** driver completion, not only on `Err`. A graceful `GOAWAY(NO_ERROR)` resolves the
  driver future as `Ok(())`, and a pool that checks only for errors hands out a dead connection.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn concurrent_first_flows_share_one_connection() {
    let (handshakes, transport) = grpc_transport_over_counting_dialer().await;

    let flows = (0..8).map(|_| transport.open_stream_for_test()).collect::<Vec<_>>();
    let opened = futures::future::join_all(flows).await;

    assert!(opened.iter().all(Result::is_ok), "every flow should open");
    assert_eq!(
        handshakes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "eight concurrent first flows must not each dial"
    );
}

#[tokio::test]
async fn a_graceful_goaway_retires_the_connection() {
    let (handshakes, transport) = grpc_transport_over_counting_dialer().await;
    transport.open_stream_for_test().await.expect("first flow");

    send_graceful_goaway().await;
    wait_for_driver_exit().await;

    transport.open_stream_for_test().await.expect("second flow");
    assert_eq!(
        handshakes.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "a GOAWAY(NO_ERROR) resolves the driver as Ok and must still retire"
    );
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p xray-transport --test stream_grpc_tests pool`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the pool and change the seam**

`pool.rs` holds `tokio::sync::Mutex<Option<PooledConnection>>` where `PooledConnection` is the
`SendRequest<Bytes>` plus the driver `JoinHandle`. A lookup takes the lock, returns the handle if
the driver has not finished, otherwise dials through the passed-in `TransportDialer` and stores the
result.

In `crates/xray-transport/src/stream/mod.rs`, add the variant and **delete** `wrap`, moving its
match into `connect_stream`. `wrap` is `pub` with a single caller, and its contract — one socket in,
one stream out — is exactly what gRPC cannot honour; leaving it with an unreachable `Grpc` arm
preserves a lie. Confirm the caller count first:

Run: `grep -rn "\.wrap(" crates/`
Expected: one hit, `crates/xray-transport/src/dialer.rs:114`.

`connect_stream` keeps its exact signature:

```rust
    pub async fn connect_stream(
        &self,
        config: &ConnectorConfig,
        transport: &TransportLayer,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        // gRPC multiplexes: the pool decides whether this flow needs a socket
        // at all. Everything else is one socket in, one stream out.
        if let TransportLayer::Grpc(grpc) = transport {
            return grpc
                .open_stream(self, config, original_target, candidates, happy_eyeballs)
                .await;
        }

        let stream = self
            .connect_resolved(config, original_target, candidates, happy_eyeballs)
            .await?;

        match transport {
            TransportLayer::Raw => Ok(stream),
            TransportLayer::WebSocket(config) => connect_websocket(stream, config).await,
            TransportLayer::HttpUpgrade(config) => connect_httpupgrade(stream, config).await,
            TransportLayer::Grpc(_) => unreachable!("handled above"),
        }
    }
```

On a miss, `open_stream` calls `dialer.connect_resolved(...)` — the same method the other transports
use, so REALITY preconnect, Happy Eyeballs and `VpnService.protect(fd)` are inherited rather than
reimplemented. Any socket opened outside the dialer bypasses socket protection on Android and routes
back into the tunnel.

- [ ] **Step 4: Write the failing test for the connection-level settings**

These are connection properties, so they belong to the pool rather than the stream. Both were left
out of the transport tasks on purpose — implementing them before a connection had an owner would
have put them in the wrong place.

```rust
#[tokio::test]
async fn initial_windows_size_reaches_the_wire_through_all_three_gates() {
    // grpc-go attaches the dial option only above zero, adopts the value only
    // at 65535 or more, and writes a SETTINGS entry only when the adopted
    // value differs from 65535. So only the last case below is visible.
    for (configured, expected_entry) in [
        (0u32, None),
        (30_000, None),      // below the adoption floor
        (65_535, None),      // adopted, but equal to the default
        (1_048_576, Some(1_048_576u32)),
    ] {
        let settings = observed_client_settings(configured).await;
        assert_eq!(
            settings.initial_window_size(),
            expected_entry,
            "initial_windows_size {configured}"
        );
    }
}

#[tokio::test]
async fn keepalive_pings_follow_the_three_way_gate() {
    // dial.go:165 activates keepalive when ANY of the three is set, and
    // `permit_without_stream: true` alone means Time=0/Timeout=0, which
    // grpc-go reads as "use the library defaults".
    assert!(!keepalive_enabled(0, 0, false));
    assert!(keepalive_enabled(30, 0, false));
    assert!(keepalive_enabled(0, 40, false));
    assert!(keepalive_enabled(0, 0, true));

    // grpc-go clamps a configured time up to a 10 second floor.
    assert_eq!(keepalive_interval(5), std::time::Duration::from_secs(10));
    assert_eq!(keepalive_interval(30), std::time::Duration::from_secs(30));
}
```

- [ ] **Step 5: Implement the settings and the keepalive**

`initial_windows_size` maps to `h2::client::Builder::initial_window_size`, applied only when the
configured value is 65536 or more — the three gates collapse to that one condition, and applying it
at exactly 65535 would emit a SETTINGS entry grpc-go does not. Leave
`initial_connection_window_size` alone: setting it emits a WINDOW_UPDATE right after SETTINGS, which
grpc-go does not send.

Keepalive lives in the pool's driver task: when any of the three knobs is set, ping the peer every
`max(idle_timeout, 10s)` using the `PingPong` handle taken from the connection before it is spawned.
Note that `PingPong` can be taken only once per connection.

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test -p xray-transport && cargo clippy -p xray-transport --all-targets -- -D warnings`
Expected: PASS, no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/xray-transport
git commit -m "feat(transport): pool one http/2 connection per gRPC outbound"
```

---

### Task 9: Wire the transport into the outbound

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs` (`build_transport_layer`)
- Test: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write the failing test**

This is where the `:authority` precedence is tested, because this is where it is resolved.

```rust
/// `(configured_authority, tls_server_name, reality, expected_authority)`
/// from `Xray-core/transport/internet/grpc/dial.go`. The destination-domain
/// step is skipped under REALITY, and an empty result makes grpc-go fall back
/// to its resolver endpoint -- `host:port`, port included.
const AUTHORITY_VECTORS: &[(Option<&str>, Option<&str>, bool, &str)] = &[
    (Some("cdn.example.com"), Some("sni.example.com"), false, "cdn.example.com"),
    (Some("cdn.example.com"), None, true, "cdn.example.com"),
    (None, Some("sni.example.com"), false, "sni.example.com"),
    (None, None, false, "dest.example.com"),
    (None, None, true, "dest.example.com:443"),
];

#[test]
fn the_grpc_authority_follows_xrays_precedence() {
    for (authority, server_name, reality, expected) in AUTHORITY_VECTORS {
        let config = grpc_outbound_config(*authority, *server_name, *reality);
        let outbound = build_vless_tcp_outbound(&config.outbounds[0]).expect("outbound builds");
        let TransportLayer::Grpc(grpc) = outbound.transport_layer() else {
            panic!("expected the grpc transport layer");
        };
        assert_eq!(
            grpc.config().authority,
            *expected,
            "authority {authority:?} sni {server_name:?} reality {reality}"
        );
    }
}

#[test]
fn one_outbound_shares_one_grpc_pool_across_selections() {
    // Mirrors `outbound_router_reuses_vless_arc_across_tcp_and_udp_selections`:
    // the pool is only a pool if the Arc is shared, and the cached router is
    // the only thing that memoizes it.
    let router = OutboundRouter::new(grpc_outbound_config(None, None, false));
    let first = router.select_tcp_outbound().expect("tcp selection");
    let second = router.select_tcp_outbound().expect("second tcp selection");

    let (TcpOutbound::Vless(first), TcpOutbound::Vless(second)) = (first, second) else {
        panic!("expected vless outbounds");
    };
    let (TransportLayer::Grpc(first), TransportLayer::Grpc(second)) =
        (first.transport_layer(), second.transport_layer())
    else {
        panic!("expected the grpc transport layer");
    };
    assert!(
        Arc::ptr_eq(first.pool(), second.pool()),
        "two selections of one outbound must share the pool"
    );
}
```

Write `grpc_outbound_config` beside the other config helpers in that file. Add `pool()` and
`config()` accessors to `GrpcTransport` if they do not exist — `pub(crate)` is not enough here,
since the test lives in another crate; make them `pub` and document them as inspection accessors.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p xray-core-rs --test runtime_data_path_tests grpc`
Expected: FAIL — non-exhaustive match in `build_transport_layer`.

- [ ] **Step 3: Add the arm**

```rust
        StreamTransport::Grpc(grpc) => TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
            service_name: grpc.service_name.clone(),
            multi_mode: grpc.multi_mode,
            authority: grpc
                .authority
                .clone()
                .unwrap_or_else(|| authority_fallback(connector, settings)),
            user_agent: resolve_grpc_user_agent(grpc.user_agent.as_deref()),
            idle_timeout_secs: grpc.idle_timeout_secs,
            health_check_timeout_secs: grpc.health_check_timeout_secs,
            permit_without_stream: grpc.permit_without_stream,
            initial_windows_size: grpc.initial_windows_size,
        })),
```

`authority_fallback` is the existing `host_fallback` closure with one change: under
`ConnectorConfig::Reality` it must **not** fall through to the destination domain, and must append
the port. Do not reuse `host_fallback` verbatim — it never carries a port, which is right for a
`Host` header and wrong for this.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-core-rs
git commit -m "feat(core): dial VLESS through the gRPC transport"
```

---

### Task 10: The Go oracle

**Files:**
- Create: `tools/reality-oracle/grpc/{go.mod,go.sum,grpc_request.go}`
- Create: `tests/fixtures/grpc/*.json`
- Modify: `scripts/verify-oracle-fixtures.py`, `.github/workflows/ci.yml`

Five harness rules, all load-bearing:

1. `FIXTURE_DIRECTORIES` is a hard-coded tuple and `discover_fixtures` raises if a listed directory
   is missing, so `tests/fixtures/grpc` must be added **and** committed in the same change.
2. An `ORACLES` entry with no matching fixture fails the whole run — add the fixture first or in the
   same commit.
3. Two oracles claiming one fixture is a hard failure. `claims_masquerade_headers` fires on
   `"variant" in document and "headers" in document`, so a gRPC fixture carrying a `headers` array
   must **not** also carry a key named `variant`.
4. `tolerates_version_drift=True` is masquerade-only; setting it here routes mismatches through a
   classifier that reads fields a gRPC fixture does not have.
5. CI's `cache-dependency-path` lists each module's `go.sum` explicitly — a third module needs a
   third line.

The nested module exists so that importing `google.golang.org/grpc` does not disturb the root
module's uTLS pins. Do not add its dependencies to the root `go.mod`, and do not copy `x/crypto`
entries into its `go.sum`; module-graph pruning keeps that file minimal on purpose.

- [ ] **Step 1: Write the oracle**

A `package main` behind `//go:build reality_oracle_grpc_request`, which dials a recording listener
with xray-core's own gRPC transport, captures the client's bytes, and emits JSON with
`json.MarshalIndent(v, "", "  ")` plus a trailing newline. Support `-check <path>` for byte
comparison exactly as `masquerade_headers.go` does. Emit three fixtures: the connection preamble,
the decoded first HEADERS block, and a set of Hunk framing vectors.

- [ ] **Step 2: Generate and inspect the preamble fixture**

Run the oracle and **read the SETTINGS frame it captured before committing anything.** The spec
states Xray sends an empty SETTINGS frame under its defaults, and a default `h2` client does too.
One research pass disagreed and claimed grpc-go sends a populated frame. This fixture is the
arbiter: if it shows entries, stop and reconcile the spec before continuing — do not adjust the
Rust side to match a fixture you have not explained.

- [ ] **Step 3: Register the oracle**

The fixture shape, keyed so that no other oracle's `claims` predicate can fire on it — in
particular it must not carry `variant`, which `claims_masquerade_headers` reads together with
`headers`:

```json
{
  "grpc_request": "headers",
  "service_name": "hello",
  "multi_mode": false,
  "grpc_go_version": "v1.81.0",
  "x_net_version": "v0.53.0",
  "pseudo_headers": [
    { "name": ":method", "value": "POST" },
    { "name": ":scheme", "value": "http" },
    { "name": ":path", "value": "/hello/Tun" },
    { "name": ":authority", "value": "127.0.0.1:8443" }
  ],
  "headers": [
    { "name": "content-type", "value": "application/grpc" },
    { "name": "user-agent", "value": "..." },
    { "name": "te", "value": "trailers" }
  ],
  "hpack_block": "83864188..."
}
```

The `ORACLES` entry, mirroring the masquerade one but **without** `tolerates_version_drift`:

```python
    Oracle(
        name="grpc_request",
        command=grpc_oracle("reality_oracle_grpc_request"),
        claims=claims_grpc_request,
        flags=grpc_request_flags,
    ),
```

```python
def claims_grpc_request(document: Any) -> bool:
    return isinstance(document, dict) and "grpc_request" in document
```

Add `FIXTURE_ROOT / "grpc"` to `FIXTURE_DIRECTORIES`. Record the grpc-go and
`x/net/http2` versions inside each fixture: `http::HeaderMap` documents that iteration order may
change without a semver bump, and an unexplained mismatch after a routine dependency bump is the
failure this repository already lived through with `x/crypto`.

- [ ] **Step 4: Verify**

Run: `bash scripts/verify-oracle-fixtures.sh`
Expected: every fixture verifies, no idle oracle, no unclaimed fixture.

Run: `python3 scripts/tests/check-json-fixture-safety.py`
Expected: pass. No path carve-out is needed, but the globally-routable-IP rule applies — use
`127.0.0.1` or a documentation domain in the captured authority.

- [ ] **Step 5: Commit**

```bash
git add tools/reality-oracle/grpc tests/fixtures/grpc scripts/verify-oracle-fixtures.py .github/workflows/ci.yml
git commit -m "test: pin the gRPC wire shape to a Go oracle"
```

---

### Task 11: Assert our bytes against the fixtures

**Files:**
- Modify: `crates/xray-transport/tests/stream_grpc_tests.rs`

- [ ] **Step 1: Write the test**

Compare our preamble and first HEADERS block against the committed fixtures. **The comparison must
open a fresh connection**: with a pool, only the first stream on a new connection has a virgin HPACK
table, and streams 3, 5, 7 emit a mostly-indexed block. A test that reuses a warmed pool compares
two different things and passes while asserting nothing. Assert the invariant explicitly rather
than relying on test ordering.

Expect one known divergence and encode it as such: `h2` emits `:method, :scheme, :authority, :path`
where grpc-go emits `:path` before `:authority`. Compare the pseudo-header **set** and the regular
header block byte-for-byte, and let the test name say which half is exact.

- [ ] **Step 2: Run**

Run: `cargo test -p xray-transport --test stream_grpc_tests oracle`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/xray-transport/tests/stream_grpc_tests.rs
git commit -m "test: compare the gRPC request against the Go oracle"
```

---

### Task 12: Live interoperability

**Files:**
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

Four scenarios: gRPC plaintext, gRPC + TLS, gRPC + REALITY, gRPC + `multiMode`. Four things that
will otherwise cost an afternoon each:

- **gRPC over TLS fails unless the client offers ALPN `h2`.** The suite's pinned rustls config sets
  no `alpn_protocols` and `TlsConnector::with_pinned_client_config` passes it through untouched.
- The doc comment on `XrayInboundTransport` says REALITY is absent "on purpose: Xray refuses it for
  anything but raw". That is wrong for gRPC — fix the comment along with the variant.
- REALITY + gRPC cannot reuse `rust_reality_vision_core_config`, which hard-codes
  `xtls-rprx-vision`, nor `warm_up_reality_server_detector`, which builds a Vision config
  internally. Both need a flow-less variant.
- Xray logs its gRPC deprecation warning at the suite's `warning` level, so a gRPC server's stderr
  is never empty. Do not add an assertion that the log is clean.

Vision + gRPC passes `xray -test` but cannot work — the inbound errors with *"XTLS only supports TLS
and REALITY directly for now"*. Our parser already refuses the pairing; add a test asserting the
refusal rather than an interop scenario exercising it.

Note in the commit message that this suite is not run by CI: `cargo test --workspace --all-targets`
compiles `#[ignore]`d tests without executing them. And per the known flake, do not read a REALITY
failure in a full sequential `--ignored` run as a regression before reproducing it in isolation.

- [ ] **Step 1: Add the inbound variant and its server config**

The Go server config for the plaintext scenario, to be produced by a builder beside the existing ws
one. `grpcSettings` is genuinely optional upstream — a `"network": "grpc"` inbound with no settings
block serves `//Tun` — but pin `serviceName` so the path assertion has something to check:

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": PORT,
    "listen": "127.0.0.1",
    "protocol": "vless",
    "settings": { "clients": [{ "id": "TEST_UUID" }], "decryption": "none" },
    "streamSettings": {
      "network": "grpc",
      "security": "none",
      "grpcSettings": { "serviceName": "interop" }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

For the TLS scenario add `"security": "tls"` with the suite's generated identity **and give the
Rust client ALPN `h2`** — `generate_tls_identity` sets no `alpn_protocols` and
`TlsConnector::with_pinned_client_config` passes the config through untouched, so without this the
handshake completes and the gRPC server rejects the stream.

For the REALITY scenario, note that the gRPC server gets no TLS credentials at all: REALITY
terminates in the listener wrapper, so there is no ALPN enforcement on that path.

- [ ] **Step 2: Fix the stale doc comment**

`XrayInboundTransport` claims REALITY "is absent on purpose: Xray refuses it for anything but raw".
That is wrong for gRPC. Correct it in the same commit that adds the variant.

- [ ] **Step 3: Add a parser test for the refused pairing**

Vision + gRPC passes `xray -test` but cannot work — the inbound errors with *"XTLS only supports TLS
and REALITY directly for now"*. Assert our parser refuses it rather than adding an interop scenario
that exercises a broken combination.

- [ ] **Step 4: Run each scenario against a local xray-core, commit per scenario**

Run: `cargo test -p xray-core-rs --test local_xray_interop_tests grpc -- --ignored --nocapture`
Expected: each scenario passes with a real Go server. Expect the deprecation warning in the server's
stderr; it is not a failure.

---

### Task 13: One benchmark workload

**Files:**
- Modify: `crates/xray-bench/src/lib.rs`, `crates/xray-bench/src/chart.rs`, `docs/benchmarks.md`

Adding a `WorkloadKind` breaks exactly five exhaustive matches — verified by adding a probe variant
and counting: `as_str` (`lib.rs:217`), `WorkloadFixture::start` (`:918`), `xray_rust_config`
(`:5864`), `engine_config_with_dns_upstream` (`:5952`), `run_engine_once` (`:9210`). Six further
sites fail silently:

- `WorkloadKind::parse` (`:241`) has a catch-all, so forgetting it is a runtime "unsupported
  workload" rather than a build break.
- **`sing_box_config` (`:5906`) is not exhaustive.** If the variant is added to
  `supports_sing_box_process_engine` (`:282`) without a matching arm here, `run_compare` skips the
  sing-box leg with an `eprintln` and still exits 0 — a two-way comparison presented as three-way.

Two things that must reach `docs/benchmarks.md` or the numbers mislead:

- sing-box uses the **lite** gRPC client, not grpc-go, because `SING_BOX_BUILD_TAGS` omits
  `with_grpc`. Adding that tag would invalidate every previously published number.
- Throughput is computed over the transfer window, not the whole run, so the pool's first dial —
  HTTP/2 preface plus TLS — lands outside the rate. Say so, or the gRPC bar reads as free setup.

Do not reuse the REALITY+Vision fixtures: `xtls-rprx-vision` cannot be combined with gRPC. If the
fixture uses plain TLS, delete the eight-second warm-up sleep copied from the REALITY server helper —
it exists only because REALITY must first handshake its cover origin.

- [ ] **Step 1: Add the variant and let the compiler enumerate the sites**

Run: `cargo build -p xray-bench`
Expected: exactly 5 `E0004` errors at the lines above.

- [ ] **Step 2: Fill each arm, then check the silent sites by grep**

Run: `grep -n "supports_sing_box_process_engine\|fn sing_box_config\|fn parse" crates/xray-bench/src/lib.rs`

- [ ] **Step 3: Run the workload**

Run: `cargo run -p xray-bench --release -- compare --workload grpc-bulk-throughput --engines xray-rust,xray-core`
Expected: three status=ok rows, no engine skipped silently.

- [ ] **Step 4: Commit**

```bash
git add crates/xray-bench docs/benchmarks.md
git commit -m "bench: measure bulk throughput through the gRPC transport"
```

---

### Task 14: Documentation

**Files:**
- Modify: `docs/config-compatibility.md`, `docs/status.md`, `docs/verification.md`, `CHANGELOG.md`

- [ ] **Step 1: Write the compatibility section**

A `### gRPC` section beside the WebSocket/HTTPUpgrade one, covering: every accepted key with its
Xray spelling; that `serviceName` has two dialects and what each produces, including the default
`//Tun`; that `multiMode` must match the server because nothing negotiates it; the `:authority`
precedence including the REALITY branch; and that REALITY is accepted here while Vision is not.

- [ ] **Step 2: Record the known divergence**

In `docs/status.md`: `h2` emits `:authority` before `:path` where grpc-go emits `:path` first, and
we take the crate as published. State the bar — the preamble and the first HEADERS block — and that
nothing past the first request on a connection carries a parity claim.

- [ ] **Step 3: Extend the verification doc**

Add the gRPC oracle to the Go-oracle section, and the four interop scenarios with their command.

- [ ] **Step 4: Write the changelog entry**

`"network": "grpc"` now parses and dials; REALITY is now accepted with gRPC where it was refused
before; one new dependency.

- [ ] **Step 5: Full verification and commit**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -W clippy::perf -W clippy::suspicious
cargo test --workspace --all-targets --locked
bash scripts/verify-oracle-fixtures.sh
bash scripts/tests/check-public-fixtures.test.sh
```

```bash
git add docs CHANGELOG.md
git commit -m "docs: document the gRPC stream transport"
```

---

## Out of scope, and refused rather than ignored

- **XHTTP.** Stage 3, its own plan, and its first task is choosing which Xray-core revision to
  target.
- **HTTP/3, the server side, `downloadSettings`, the browser dialer.** Already out of scope in the
  spec; keep them refused with a specific message.
- **The Swift `vless://` importer.** It accepts only `type ∈ {tcp, raw}` with `security=reality`, so
  it already refuses the ws and httpupgrade profiles the engine dials. That is a pre-existing gap
  for all five transports and needs a source of truth for share-link parameters that this repository
  does not contain.
- **BDP-estimation PINGs, HPACK dynamic-table fidelity, WINDOW_UPDATE cadence.** Outside the parity
  bar by decision, recorded in `docs/status.md` rather than left implicit.
