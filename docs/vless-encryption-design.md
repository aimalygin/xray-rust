# VLESS encryption: sessions, carriers, and Vision

Implementation/review date: 2026-09-04. This is a development increment of
Milestone B and has received adversarial implementation review, but not an
independent security audit.

## Contract and boundaries

The reference is the clean Xray-core `v26.7.28` checkout at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, specifically
`proxy/vless/encryption/{client,server,common,xor}.go` and
`infra/conf/vless.go`. The Go oracle imports those files from that checkout;
it does not substitute a Rust-shaped server implementation.

Accepted JSON shape:

```text
none
mlkem768x25519plus.{native|xorpub|random}.{1rtt|0rtt}.[padding.]<public-key>[.<public-key>...]
```

Each public key is the canonical unpadded base64url encoding of either 32
X25519 bytes or 1,184 ML-KEM-768 bytes. One to eight mixed keys form an ordered
relay chain. An absent field defaults to `none`; explicit non-string values are
errors. Strings longer than 16 KiB fail before key decoding.
X25519 low-order points are rejected before dialing; peer ECDH also rejects a
noncontributory shared secret. ML-KEM keys are checked for canonical 12-bit
coefficients below 3,329 before the AWS-LC constructor. Review found that the
raw AWS-LC constructor checks length, deferring modulus validation until
encapsulation; the explicit check now rejects malformed keys before dialing.

Encryption composes with raw TCP, WebSocket, HTTPUpgrade, gRPC (Hunk and
MultiHunk), and XHTTP, with or without Vision. Existing carrier/security
constraints still apply: REALITY accepts raw, gRPC, and XHTTP; WebSocket and
HTTPUpgrade accept none or TLS. Encryption wraps the established carrier
before VLESS headers or application bytes are written. TCP, length-prefixed
UDP, and XUDP share that boundary. The `none` branch returns the original
stream without crypto state or buffers. Invalid flows still fail before I/O.

For a negotiated Vision Direct command, only the VLESS encryption record layer
is removed. The outer TLS/REALITY or HTTP carrier remains in place, matching
Xray's `UnwrapRawConn` rule against double penetration. Random mode retains
continuous XorConn header masking on inner TLS records. Read and write
transitions are independent: authenticated buffered plaintext drains before
carrier bytes, and pending encrypted output flushes before direct output.
Direct-mode payload authentication belongs to the inner TLS connection.
Ordinary non-Vision transport calls continue through authenticated records.
The regular Vision flow rejects UDP/443 before DNS/dialing; the `-udp443`
variant uses XUDP and advertises the canonical Vision flow to the server.

Swift/Kotlin share-link importers support the same bounded session, chain,
and padding shape on their existing raw/TCP and XHTTP/SplitHTTP carriers,
including both Vision flows with none, TLS, or REALITY security. They validate
canonical key encoding, reject low-order X25519 points and invalid ML-KEM
coefficients, and preserve encryption and flow in the generated config.
Encrypted links reject insecure TLS verification. WebSocket/HTTPUpgrade/gRPC
URL projection is still outside these importers; SDK JSON uses Rust's wider
carrier support. Rejected encryption values remain redacted. Existing `none`
imports retain their previous raw/REALITY and flowless XHTTP behavior.

Shared key/projection fixtures in `tests/fixtures/vless-encryption/imports.json`
are consumed by all three languages. Mobile low-order checks include the
ignored high-bit aliases described in RFC 7748 and the seven encodings in
[libsodium's reference implementation](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c).
Rust independently validates X25519 points with Dalek key agreement. Android's
strict base64url decoder also works on the supported API 24/25 devices.

## Wire and key ownership

1. Generate a fresh random 16-byte IV and a fresh NFS exchange for every key:
   ephemeral X25519 ECDH or ML-KEM-768 encapsulation. Between relays, encrypt
   the next configured key's BLAKE3 hash and the first 32 bytes of the next
   relay with one continuous CTR stream derived from the previous shared key.
   The final shared key is the connection's NFS key.
2. For `xorpub`/`random`, independently mask each NFS public key/ciphertext
   with AES-256 CTR derived from that configured public key and the IV.
3. Derive the NFS AEAD with the IV as context. Send authenticated length 1,232,
   the fresh ML-KEM public key plus X25519 public key, padding length, and
   padding, with increment-before-use nonces 1 through 4.
4. Verify the server's 1,136-byte PFS reply with the reserved all-ones nonce
   **before** decapsulation/ECDH. All failures stop the handshake; the upstream
   client's unchecked `Open` return is not copied.
5. Form `united = ML-KEM shared[32] || X25519 shared[32] || NFS shared[32]`.
   Derive each direction's record key with its own public exchange message:
   client 1,216 bytes, server 1,120 bytes. Authenticate the ticket (nonce 1)
   and padding length (nonce 2). A `1rtt` client discards the ticket.
6. Consume/authenticate the server padding lazily (nonce 3), preserving the
   pinned server's ability to send padding slowly after handshake completion.
   Client data begins at nonce 1; server data begins at nonce 4.
7. In `random`, mask only record headers, with separate continuous CTR state
   in each direction. The client IV and authenticated server ticket provide
   the respective CTR IVs. Ciphertext bodies and pending peer padding are not
   masked. Buffering complete headers avoids partial-I/O mask duplication.

For `0rtt`, the first connection deliberately uses the authenticated 1-RTT
path. A positive-lifetime ticket is published only after the server padding
tag verifies. One persistent `Client` retains at most one 64-byte PFS key and
16-byte ticket in memory for its exact endpoint/user/key-chain/security
identity; it is neither serialized nor shared across separately constructed
clients. Core outbound clones share that one client. Replacing the config
constructs a new client, and callers can explicitly clear the cache when an
outer security identity changes.

A resumed connection creates a fresh IV and NFS exchange, then prefixes the
first encrypted application record with authenticated length 32 and the cached
ticket. The server returns a fresh 16-byte random context; the first valid
server record authenticates the resumption and releases its cache lease. An
expired/rejected ticket, malformed response, EOF, cancellation, or drop before
that record invalidates the ticket immediately. The next connection is cold.
The client never resends early application bytes automatically: a request can
be lost when resumption is rejected, so callers must apply their own
application-level retry and idempotency policy. The pinned server rejects an
exact replay through its per-session NFS-key set; the client also retains all
directional record-context and reflection protections from 1-RTT.

Both AES-256-GCM and ChaCha20-Poly1305 use AWS-LC, already present through
rustls. Hardware detection chooses AES on the relevant supported CPUs and
ChaCha otherwise. The pinned server detects the client's AEAD by authenticating
the first encrypted length; both variants are covered explicitly in interop.
ML-KEM-768 uses AWS-LC 1.17.0, X25519 uses the existing zeroizing Dalek library,
and CTR uses the existing AES/CTR RustCrypto primitives with zeroize enabled.

BLAKE3 1.8.5 is vendored with one API addition for byte contexts. Xray's Go
conversion preserves arbitrary binary bytes; the normal Rust `&str` API cannot
represent them. The added method uses the original BLAKE3 context/material
flags and unchanged compression/tree implementation, corresponding to the
upstream C raw-context API. No UTF-8 coercion, custom KDF, or unsafe `str` is
used. Source archive checksum, upstream commit, and patch scope are in
[`vendor/blake3/XRAY-PATCH.md`](../vendor/blake3/XRAY-PATCH.md). The official
[BLAKE3 API source](https://docs.rs/blake3/1.8.5/src/blake3/lib.rs.html) documents
the original string API.

`VlessUser.encryption` is now a typed `VlessEncryption`; it retains no raw
key-bearing string. Debug output reveals only the scheme/mode and redaction
marker. Parser and wire errors contain no key/ciphertext bytes. Public key
buffers, KDF hash/XOF state, derived key arrays, the ticket buffer, and retained
plaintext buffers use `Zeroizing`. Dalek and AWS-LC own and clear their private
keys/shared secrets/key schedules. Compiler-generated temporary copies and
the caller's original JSON string are outside this ownership guarantee.

## Bounds, cancellation, and failure behavior

- The handshake runs inline and owns its carrier. Cancellation, error, or the
  30-second ceiling drops the carrier and ephemeral state. Existing shorter
  runtime deadlines still win. There are no spawned handshake tasks. A
  cancelled resumed stream invalidates its leased ticket.
- Default client padding matches Xray's upper-exclusive draws: first fragment
  111–1,110 bytes, optional second 0–3,332 bytes, gap 0–110 ms. Configured
  padding has at most 32 alternating length/gap parts. The first length is
  mandatory with probability 100 and a lower bound of at least 35 bytes; the
  sum of length maxima is at most 65,553 bytes. Each gap maximum is at most one
  second and their sum is at most five seconds. Reversed endpoints are
  normalized as upstream does. Padding is sent in fragments and flushed.
- An authenticated server padding length must be 17–65,535 bytes. It is never
  used to allocate before the length tag is verified. The retained read buffer
  is bounded by this maximum; data-record ciphertext must be 17–16,640 bytes.
- Writes accept at most 8,192 plaintext bytes per record. One 8,213-byte output
  buffer retains pending ciphertext/position across cancellation and partial
  writes. Nonces advance once when that input is accepted, not on each poll.
  Reads also attempt to drain writes but never block receiving solely on
  write backpressure; simultaneous bidirectional traffic is covered.
- The five-byte clear header is AEAD additional data. Tags are verified before
  exposing plaintext. Header/body truncation, invalid lengths, replayed records,
  wrong directional context, and authentication failures poison both directions.
  A zero-length caller read/write does not generate a record.
- At the 96-bit counter wrap, the nonce-zero record still belongs to the old
  key; its clear header plus ciphertext becomes the next KDF context. The read
  key is replaced only after successful authentication. The test forces this
  otherwise unreachable boundary, including random-mode masking.
- Half-close flushes queued ciphertext and closes only the write side. As in
  the pinned protocol, EOF at a record boundary has no authenticated close
  notification; it is not a cryptographic proof of complete application data.

## Verification and remaining work

Run `bash scripts/check-vless-encryption-oracle.sh`. It verifies a clean exact
Go commit, regenerates/diffs deterministic KDF/AEAD/CTR fixtures, and runs the
Rust library (including fuzz-driver smoke tests) and live localhost interop
tests. It also builds the complete Xray binary from that checkout and checks
18 original mode/key/security combinations, a 168-profile carrier/Vision
matrix with 414 TCP/inner-TLS/XUDP application flows, and 18 length-prefixed
UDP/Vision-UDP443 cases through actual inbound authentication and Freedom
dispatch. The 168 profiles combine 28 compatible carrier/security shapes,
three masking modes, and both flowless/Vision operation. Shapes include both
gRPC encodings, all three XHTTP modes on H1/H2/H3. Native uses
X25519, xorpub uses ML-KEM-768, and random uses a mixed three-key chain; the
original 18 cases independently cross every mode with both single-key kinds.
The new profiles use bounded custom padding and one shared 0-RTT client for
sequential application opens. The separate oracle's byte accounting is the
proof of actual resumption; application success alone is not used as that proof.
The H3 profiles retain QUIC while removing the VLESS record layer for Vision
Direct. The REALITY cover origin is a local TLS 1.3/H2 server with
X25519MLKEM768; no public cover service is required. CI runs it on ordinary PRs and
pushes. Go process keys are generated per test and never printed; public test
configuration is passed directly to the local client. No external endpoints
are used. The record tests additionally exercise tiny duplex buffers, cancelled
reads/flushes, simultaneous bidirectional pressure, half-close, and nonce wrap.

Earlier validation on 2026-09-04, before the Vision/carrier increment:

| Check | Result |
| --- | --- |
| Workspace, excluding unbounded fuzz binaries, all targets, locked dependencies | 2,151 passed; 42 explicitly ignored; no failures |
| Focused encryption library tests, with fuzzing feature | 15 passed, including session lease/expiry/clear coverage, 11 binary KDF contexts, and both AEAD fixture variants |
| Pinned Go live interop gate | 95 scenarios passed: 68 original library/runtime cases, 18 full-Xray mode/key/security cases, six cold/resumed chain/padding cases, two negative resumption cases, and one runtime-session reuse case |
| Shared Rust/Swift/Kotlin fixtures | 38 key encodings and 58 profile projections/rejections passed in all three languages |
| Bounded ASan fuzz smoke, 61 seconds per target | Handshake: 29,324 executions, coverage counter 2,947; records: 59,665 executions, coverage counter 1,681; no crashes/timeouts |
| Workspace Clippy, all targets/features, warnings denied | Passed |
| SwiftPM with rebuilt local macOS arm64 Rust XCFramework | 299 passed |
| Kotlin JVM adapter tests, JDK 17 | 81 passed |
| Formatting, diff whitespace, fixture safety, mobile/workflow guards | Passed |

All ten ignored encryption integration test functions in the current tree
are explicitly executed by the Go gate. No ignored release
campaign is represented as having run. Those dated results came from an uncommitted
development tree with only a macOS test slice, while the distribution
repository was still pinned to `v0.5.0`. The later published core/mobile
`v0.6.0-rc.1` gates and physical/performance coverage are recorded separately
in [release evidence](v06-release-evidence.md#published-v060-rc1).

Two dedicated fuzz targets now exercise records and the actual client
handshake using bounded, fragmented in-memory I/O. They generate authenticated
messages before applying corruption/truncation, also feed raw bytes, and
exercise header masking, rekey, malformed peer keys and padding lengths.
ThinLTO is disabled for fuzzing and symbols are retained. On the pinned local
toolchain, the initial ThinLTO build registered only 1,505 counters and stayed
at coverage 15; the corrected build registers 58,039 counters and reaches the
library paths reported above. The initial run is not used as crypto fuzz
evidence. The host-hardening script and its guard preserve these settings.
Coverage counters are not a percentage or proof of exhaustive testing.

The handshake driver uses an X25519 NFS peer; both NFS key kinds, mixed relay
chains, configured padding, and real cold/resumed paths are covered by the
pinned Go matrix. The oracle measures bytes consumed at the handshake boundary
so a second cold handshake cannot pass as 0-RTT. Expiry and cancellation cases
prove ticket invalidation and a cold third connection. The helper API exists
only under the `fuzzing` feature.

Remaining Milestone B work includes independent review and exact-candidate
mobile/performance evidence. Full release sanitizer/fuzz campaigns have not
been claimed by these bounded development checks.

## Vision/carrier increment (2026-09-04)

The matrix now contains 540 full-Xray application flows (204 server profiles)
and the complete Go gate contains 617 scenarios. Unit regressions exercise
one-byte I/O, cancelled flushes, the authenticated plaintext tail, independent
directions, poisoned/incomplete-record transitions, and pre-DNS UDP/443
rejection. The record fuzz driver now also exercises Vision transitions and
fragmented inner-TLS header masking; its bounded driver smoke runs in the gate.
The earlier ASan execution counts above predate this extension.

Shared fixtures now contain 38 key cases and 96 profile projections/rejections,
including raw/XHTTP Vision across all modes/security choices, unknown flows,
and insecure encrypted XHTTP TLS. This increment does not publish new mobile
artifacts or claim physical-device/performance evidence.

Current increment validation:

| Check | Result |
| --- | --- |
| Rust workspace, all targets, locked, excluding fuzz binaries | 2,154 passed; 44 explicitly ignored; no failures |
| Pinned encryption gate | 17 library/fuzz-driver tests and 617 live scenarios passed; all ten ignored encryption test functions executed |
| Full-Xray portion of the gate | 540 application flows / 204 server profiles passed, including all XHTTP H1/H2/H3 modes |
| Workspace Clippy, all targets/features, warnings denied | Passed |
| SwiftPM tests | 299 passed; uses the existing local macOS test XCFramework, no new distribution artifact |
| Kotlin JVM tests, JDK 17 | 81 passed |
| Shared fixtures | 38 key cases and 96 profile cases verified by Rust, Swift, and Kotlin |
| Formatting, diff whitespace, JSON fixture safety | Passed |
