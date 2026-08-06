# VLESS Stream Transports: WebSocket, HTTPUpgrade, gRPC, XHTTP

## Decision

xray-rust gains four outbound stream transports — `ws`/`websocket`,
`httpupgrade`, `grpc`, and `xhttp`/`splithttp` — reaching wire parity with
Xray-core v26.5.9 (local checkout `Xray-core/`, commit `1bdb488c`). Today only
`tcp`/`raw` is accepted; every other `streamSettings.network` is rejected at
config parse time (`crates/xray-config/src/parser.rs:2650`), so no VLESS profile
using a web transport can be imported at all.

Out of scope: `mkcp`/`kcp` and `hysteria` (both UDP-based with their own
congestion protocols — each is comparable in size to this entire work), HTTP/3
for XHTTP (needs a full QUIC stack), and the server side of any transport
(xray-rust has no VLESS inbound; `InboundProtocol` is socks/http/tun only).

Parity target is byte-exact for the contents of every request and response we
emit or accept, including the browser-masquerade header block and Go's header
serialization order. One thing falls outside that target: XHTTP's `xmux`
connection-reuse scheduler, which no single request reveals, is parsed but not
implemented — it remains observable as a pattern of connection timing, and that
gap is stated plainly rather than claimed as parity.

## Rationale

- **Compatibility is the product.** xray-rust exists to consume Xray-core
  profiles. A profile using `ws` behind a CDN is not an exotic configuration;
  it is one of the two or three most common VLESS deployments. Rejecting it at
  import is a hard interop failure, not a missing optimization.
- **The web subset covers the field.** Of Xray-core's seven live transports,
  `raw` plus these four are every TCP/HTTP-based option. `mkcp` and `hysteria`
  are UDP transports serving a different niche and can follow later without
  reworking anything built here.
- **Fingerprint parity is not decoration.** Xray-core sends a Chrome persona on
  every ws/httpupgrade/XHTTP request (`common/utils/browser.go`) and a
  distinctively empty HTTP/2 SETTINGS frame on gRPC. A client that speaks the
  protocol correctly but sends bare RFC headers is trivially separable from the
  xray population it is trying to blend into. This project already holds that
  bar for the REALITY ClientHello; HTTP headers get the same treatment.

## Architecture

### The transport layer sits above security, not inside it

`ConnectorConfig` (`crates/xray-transport/src/lib.rs:48`) stays what it is: the
**security** layer, `{ Tcp, Tls, Reality }`. Stream transports are an orthogonal
axis and get their own type in a new `crates/xray-transport/src/stream/` module:

```rust
pub enum StreamTransport {
    Raw,
    WebSocket(WebSocketSettings),
    HttpUpgrade(HttpUpgradeSettings),
    Grpc(GrpcSettings),
    Xhttp(XhttpSettings),
}
```

`TransportDialer` gains one method:

```rust
pub async fn connect_stream(
    &self,
    security: &ConnectorConfig,
    transport: &StreamTransport,
    server: &Target,
    candidates: &[SocketAddr],
    happy_eyeballs: Option<&HappyEyeballsConfig>,
) -> Result<BoxedTransportStream, TransportError>
```

It calls the existing `connect_resolved` to obtain a secured stream — the Happy
Eyeballs race and the REALITY `prepare_preconnected` path are untouched — and
then applies the transport's framing, returning a `BoxedTransportStream` again.
Everything above (VLESS header encoding, Vision, XUDP) is unchanged; it already
operates on `BoxedTransportStream` and does not care what produced it.

This mirrors Xray-core, where each transport dialer calls `DialSystem` and
applies security itself (`transport/internet/dialer.go:48`), and it avoids
threading transport variants through `connect_resolved`, whose candidate-race
and REALITY-preconnect logic is the most delicate code in the crate.

Rejected alternatives: making `ConnectorConfig` recursive
(`WebSocket { inner: Box<ConnectorConfig> }`) conflates two concepts in one enum
and forces `connect_resolved` to recurse; a name-keyed dialer registry mirroring
Go's `RegisterTransportDialer` adds indirection with no payoff for four
statically known transports in a client.

### Each transport is a `TransportStream`

Every wrapper implements `AsyncRead + AsyncWrite` plus the `TransportStream`
trait (`crates/xray-transport/src/lib.rs:129`), forwarding `poll_read_direct` /
`poll_write_direct` to the plain poll methods. `release_record_alignment` is a
no-op for all four: record alignment exists only to let Vision unwrap into
direct mode, and Vision cannot run over a non-raw transport (see below).

### Shared HTTP request builder

ws, httpupgrade, and XHTTP all serialize an HTTP/1.1 request or an H2 header
block with the same persona rules, so they share one module,
`stream/http_headers.rs`, with two responsibilities:

1. **The masquerade block.** A port of `TryDefaultHeadersWith`
   (`Xray-core/common/utils/browser.go:232`): when the config supplies no
   `User-Agent`, or supplies one of the magic keywords
   `chrome|firefox|safari|edge|curl|golang`, the corresponding persona is
   applied; any other UA value suppresses the entire block. The `ws` variant
   (ws + httpupgrade) and the `fetch` variant (XHTTP) differ in `Sec-Fetch-*`
   and `Priority`. `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`, `DNT`,
   `User-Agent`, and `Accept-Language` overwrite user values; `Accept`,
   `Cache-Control`, `Pragma` only fill gaps. The Chrome major version is
   date-derived and the brand list is GREASEd — both are reproduced, seeded so
   tests are deterministic.
2. **Go-compatible serialization.** Go writes the request line, then `Host`,
   then `User-Agent`, then every remaining header sorted **case-sensitively by
   the literal map key** (`net/http/header.go`, `strings.Compare`). That places
   `Sec-CH-UA` before `Sec-Fetch-*` and `Upgrade` last. Header names are
   emitted in their literal, often non-canonical casing (`Sec-WebSocket-Key`,
   `DNT`, `Sec-CH-UA`). A Rust HTTP stack that lowercases names or preserves
   insertion order produces a different fingerprint, which is why this is a
   hand-written serializer rather than the `http` crate's writer.

For H2 (gRPC, XHTTP over TLS) the same persona feeds the header block, with
pseudo-headers in Go's order: `:method`, `:scheme`, `:path`, `:authority`.

### Compatibility matrix

Xray-core restricts which combinations are legal, and the restrictions are
enforced at config-build time. xray-rust must reject the same combinations,
with messages that echo Xray-core's so a user recognizes them:

| transport | `none` | `tls` | `reality` | `xtls-rprx-vision` |
|---|---|---|---|---|
| `raw`/`tcp` | yes | yes | yes | yes (needs tls/reality) |
| `ws`, `httpupgrade` | yes | yes | **no** | **no** |
| `grpc`, `xhttp` | yes | yes | yes | **no** |

- REALITY is rejected for ws and httpupgrade by
  `Xray-core/infra/conf/transport_internet.go:1989` — *"REALITY only supports
  RAW, XHTTP and gRPC for now."*
- Vision requires a raw transport. `Xray-core/proxy/vless/outbound/outbound.go:284`
  reaches into the TLS connection's private `input`/`rawInput` fields via
  `unsafe` and fails with *"XTLS only supports TLS and REALITY directly for
  now."* when anything sits between. Our `validate_connector_flow`
  (`crates/xray-core-rs/src/outbound.rs:1625`) currently inspects only the
  security layer and must also take the transport, or a `ws` + Vision profile
  will build cleanly and then fail on the wire.
- The DNS outbound's `streamSettings` (`crates/xray-core-rs/src/outbound.rs:397`)
  stays raw-only, rejecting the four new transports explicitly. Xray-core does
  not offer DoT over a web transport either.

### ALPN becomes a first-class setting

gRPC and XHTTP-over-H2 require ALPN `h2`, and xray-rust supports no ALPN at all
today: the parser rejects a non-empty `tlsSettings.alpn`
(`crates/xray-config/src/parser.rs:2762`) and `TlsConnector` holds two
pre-built `rustls::ClientConfig`s with no ALPN
(`crates/xray-transport/src/tls.rs:23`). Three changes follow:

- `TlsClientConfig` gains `alpn: Vec<String>`.
- `TlsConnector` builds configs on demand, memoized by
  `(allow_insecure, alpn)`; `rustls::ClientConfig` is immutable behind an `Arc`,
  so a small map replaces the two fixed instances.
- The parser accepts `tlsSettings.alpn`. When the user leaves it empty, each
  transport supplies the default Xray-core uses for that transport's client:
  ws and httpupgrade offer `["http/1.1"]` alone (not the usual pair), gRPC
  offers `["h2"]`, and XHTTP offers `["h2", "http/1.1"]`. When the user sets
  `alpn` explicitly it is passed through verbatim — and for XHTTP it also
  selects the HTTP version (see Stage 3).

REALITY needs nothing here: ALPN is baked into the uTLS fingerprint profile and
already offers `h2`/`http/1.1` (`crates/xray-transport/src/reality_utls_profiles.rs`).

## Configuration surface

`StreamSettings` (`crates/xray-config/src/model.rs:866`) gains a
`transport: StreamTransport` field beside `network`. The parser accepts
Xray-core's aliases exactly as `transport_internet.go:995` does:

| JSON `network` | resolves to | settings key |
|---|---|---|
| `tcp`, `raw` | raw | `tcpSettings` / `rawSettings` |
| `ws`, `websocket` | websocket | `wsSettings` |
| `httpupgrade` | httpupgrade | `httpupgradeSettings` |
| `grpc` | gRPC | `grpcSettings` |
| `xhttp`, `splithttp` | XHTTP | `xhttpSettings` / `splithttpSettings` |

`h2`, `h3`, `http`, and `quic` were **removed** from Xray-core, not merely
unimplemented; they must produce the same "removed, use XHTTP" guidance rather
than a generic "unsupported network". `kcp`/`mkcp` and `hysteria` produce an
explicit "not supported by xray-rust" error.

Where both spellings of a settings key exist, `xhttpSettings` wins over
`splithttpSettings`, matching Xray-core. `streamSettings`'s allowlist
(`parser.rs:2719`) grows the five new keys.

## Stage 1 — transport layer, WebSocket, HTTPUpgrade

New dependency: `sha1` 0.10 (same RustCrypto generation as our `sha2`), needed
only to validate `Sec-WebSocket-Accept`.

### Shared config handling

Both transports take `host`, `path`, `headers`, and both encode early data as a
**query parameter of the path**, which Xray-core strips at config-build time:

```go
if q.Get("ed") != "" {
    Ed, _ := strconv.Atoi(q.Get("ed"))
    ed = uint32(Ed); q.Del("ed"); u.RawQuery = q.Encode(); path = u.String()
}
```

So `"path": "/x?ed=2048"` produces requests to `/x` — emitting `?ed=2048` gives
a path mismatch and a 404. The remaining query is re-encoded through
`url.Values.Encode()`, which **sorts parameters alphabetically** and
percent-encodes them; our parser reproduces that normalization. A non-numeric
`ed` yields 0 and is still stripped.

Host precedence for both: `host` → `tlsSettings.serverName` → destination
address. SNI is computed independently (`serverName` → destination address), so
setting only `host` deliberately leaves `Host` and SNI different. The port is
never appended to `Host`.

`headers.Host` is a deprecated alias folded into `host` for ws; for httpupgrade
it is a hard error.

### WebSocket

Dial builds `GET <normalized-path>[?query] HTTP/1.1` with the masquerade block,
`Host`, and gorilla's fixed quartet written in literal casing: `Upgrade:
websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key` (16 crypto-random bytes,
**standard padded base64**), `Sec-WebSocket-Version: 13`.

Early data, when `ed > 0`: no network activity happens until the upper layer's
first write. If that write is `<= ed` bytes it goes entirely into
`Sec-WebSocket-Protocol` as **base64url without padding** and no WebSocket frame
is sent for it; if it is larger, early data is disabled for the connection
(the header is omitted) rather than truncated. The boundary is inclusive.

Response validation: status 101, `Upgrade` token list contains `websocket`,
`Connection` token list contains `upgrade`, and `Sec-WebSocket-Accept` equals
`base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`. Handshake
deadline 8 s.

Framing: every write is one binary message; client frames are always masked;
messages are fragmented at exactly 4096 payload bytes, matching gorilla's
`WriteBufferSize: 4*1024`. Reads are a pure byte stream — message boundaries
carry no meaning, empty messages are skipped, and masked server frames are a
protocol error. Optional `heartbeatPeriod` (seconds) sends empty-payload pings;
incoming pings are answered with an echoing pong; there is no pong watchdog.
Close sends a close frame (code 1000, empty reason) before the socket closes.

### HTTPUpgrade

A fake upgrade with no RFC 6455 machinery: `GET <path> HTTP/1.1` with the same
masquerade block plus `Connection: Upgrade` and `Upgrade: websocket`, and no
`Sec-WebSocket-*` header anywhere. After a 101 the connection is raw bytes in
both directions — no framing, no keepalive, no close handshake.

Response validation is **stricter** than WebSocket's: the status is compared as
the exact string `"101 Switching Protocols"` and `Connection` must equal
`upgrade` exactly after lowercasing (no token-list parsing). Bytes the server
sent immediately after the response headers must be preserved and delivered to
the first read.

`ed` here does **not** carry a payload; it only means "do not block waiting for
the 101" (0-RTT), and any positive value behaves identically.

One deliberate divergence in path encoding: Xray-core assigns the path to
`URL.Path`, so Go escapes `?` and httpupgrade emits `GET /ws%3Ffoo=bar` where
WebSocket, for the identical configured path, emits `GET /ws?foo=bar`. We
reproduce this, because the Xray-core server compares against the unescaped
path and the round-trip only works if both sides agree.

Config keys the user's config may set (`headers` casing is preserved verbatim
for httpupgrade, canonicalized for ws): `host`, `path`, `headers`, plus ws-only
`heartbeatPeriod`. `acceptProxyProtocol` is inbound-only and is accepted and
ignored.

## Stage 2 — ALPN and gRPC

New dependency: `h2` (bare, without `hyper` or `tonic`). No protobuf codegen is
needed — `prost` is already in the tree but the gRPC message is small enough to
hand-encode.

### Framing

The `.proto` is `message Hunk { bytes data = 1; }`, so one write of N bytes is:

```
00                 compression flag (0 = uncompressed)
LL LL LL LL        u32 big-endian: 1 + varint_len(N) + N
0A                 protobuf tag: field 1, wire type 2
<varint N>
<N payload bytes>
```

Overhead is 7 bytes for N < 128 and 8 for N < 16384, which covers our buffer
sizes. One write is one message; the decoder must reassemble across HTTP/2 DATA
frames, tolerate zero-length messages, skip unknown fields, and treat a non-zero
compression flag as a hard error. Keep messages under the server's 4 MiB
default. `multiMode` switches to `MultiHunk { repeated bytes data = 1; }` and
the `TunMulti` stream name — supported, since it must match the server.

### HTTP/2 request

`:path` is built from `serviceName`: a name without a leading `/` is
`PathEscape`d whole and the stream name is literally `Tun`/`TunMulti`
(`"hello"` → `/hello/Tun`); a name with a leading `/` splits into a path prefix
and a trailing stream segment.

Headers, in Go's order: `:method POST`, `:scheme http` (Xray-core dials gRPC
with `insecure.NewCredentials()` and applies TLS itself, so the scheme stays
`http` even over TLS), `:path`, `:authority`, `content-type: application/grpc`,
`user-agent` (Chrome persona by default, with `grpc-go/x.y.z` stripped), `te:
trailers`. Notably absent: `grpc-accept-encoding`, `grpc-timeout`,
`content-length`.

`:authority` precedence: `authority` → SNI → destination domain → `host:port`.

Half-close on the write side; a trailers HEADERS frame with END_STREAM is EOF.

### Connection reuse is required, not an optimization

Xray-core caches one `ClientConn` per (destination, stream settings) and opens
one HTTP/2 stream per proxied connection. Without this, every flow would perform
its own TLS handshake — unacceptable on mobile for both latency and memory. The
gRPC transport therefore owns a small pool: one H2 connection per
(server, settings), streams multiplexed over it, reconnect on GOAWAY or
transport error.

By default Xray-core sends **no SETTINGS entries at all** (an empty SETTINGS
frame after the preface) and never sends a PING unless `idle_timeout`,
`health_check_timeout`, or `permit_without_stream` is configured. We match both,
since an empty SETTINGS frame is itself a strong signal of the grpc-go
population.

Config keys: `authority`, `serviceName`, `multiMode`, `idle_timeout` (seconds,
clamped up to a 10 s floor as grpc-go does), `health_check_timeout` (default
20 s), `permit_without_stream`, `initial_windows_size` (applied only when
>= 65535), `user_agent`.

## Stage 3 — XHTTP

### Mode and HTTP version selection

`auto` resolves differently depending on security, so all three concrete modes
are required:

- no REALITY → `packet-up`
- REALITY, no `downloadSettings` → `stream-one`
- REALITY with `downloadSettings` → `stream-up`

HTTP version (`splithttp/dialer.go:85`): REALITY → H2; no TLS → **H1 only**
(the stock client never attempts h2c); `alpn: ["http/1.1"]` → H1; ALPN unset or
multi-valued → H2; `alpn: ["h3"]` → H3, which xray-rust rejects with an explicit
error rather than attempting.

A session id is generated for every mode except `stream-one`: a v4 UUID in
lowercase dashed form.

### Padding is mandatory

The server returns 400 for absent or out-of-range padding
(`splithttp/hub.go:144`), so this is not optional cover. Default placement is
`queryInHeader`: the `Referer` header carries the **base URL computed before the
session id and sequence number are appended**, with its entire query replaced by
`x_padding=<pad>`. Length is drawn from `xPaddingBytes`, default range 100–1000,
with Go's `RandBetween` semantics — the upper bound is exclusive.

The trap to encode in tests: a `Referer` **without** `x_padding` is an instant
400 even when the request URL carries a valid `x_padding`, because the server
checks the Referer branch first and never falls through
(`splithttp/xpadding.go:256`).

### Per-mode flow

**packet-up.** A `GET <base>/<uuid>` opens first and its response body is the
downlink stream. Uplink is chunked into `POST <base>/<uuid>/<seq>` requests:
`seq` is decimal from 0 and must be contiguous (the server reorders with a heap
and tears down after `scMaxBufferedPosts`, default 30, out-of-order posts). The
per-POST size cap is drawn **once per connection** from `scMaxEachPostBytes`
(default exactly 1,000,000), and each POST carries an explicit `Content-Length`.
Between posts the client sleeps `rand(scMinPostsIntervalMs)` (default 30 ms)
minus elapsed time, with one POST in flight at a time. Only status 200 is
accepted.

**stream-up.** `GET <base>/<uuid>` for the downlink plus a single streaming
`POST <base>/<uuid>` for the uplink, with no `Content-Length` (H2 DATA frames or
H1 chunked). The POST carries `Content-Type: application/grpc` unless
`noGRPCHeader` — an anti-buffering hint for CDNs, with no gRPC framing applied.
The upload response is drained and discarded; the server may inject runs of `X`
into it as keep-alive.

**stream-one.** One full-duplex `POST <base>/` with no session id and no
sequence: request body is the uplink, response body the downlink. H2 or H3 only.

### xmux: parsed, not implemented

`xmux` is a client-side connection-reuse scheduler (`maxConcurrency`,
`maxConnections`, `cMaxReuseTimes`, `hMaxRequestTimes`, `hMaxReusableSecs`,
`hKeepAlivePeriod`) with nothing identifying it on the wire. Real profiles set
it, so the keys are accepted and validated (including the mutual exclusion of
`maxConcurrency` and `maxConnections`), but the scheduler is not built; XHTTP
uses straightforward per-connection reuse. This is the one place where the spec
deliberately stops short of behavioral parity, and it is revisited only if
profiling shows connection churn matters.

`downloadSettings` — a separate full stream config that sends the download
request to a different host or over a different transport — is parsed and, if
actually populated, rejected with a clear message, since supporting it means
running two independent transport stacks per connection. This does not remove
the `stream-up` mode: `mode: "stream-up"` is fully implemented and runs both
directions against the same host. It only means that under `mode: "auto"` with
REALITY, the resolution `downloadSettings present → stream-up` is unreachable,
so `auto` + REALITY always resolves to `stream-one`, exactly as Xray-core does
when `downloadSettings` is absent.

Other config keys are accepted per Xray-core's table: `host`, `path`, `mode`,
`headers`, the `xPadding*` family (including `xPaddingObfsMode` and its
placement/key/header/method knobs), `uplinkHTTPMethod`, `sessionPlacement` /
`sessionKey`, `seqPlacement` / `seqKey`, `uplinkDataPlacement` / `uplinkDataKey`
/ `uplinkChunkSize`, `noGRPCHeader`, `noSSEHeader`, `scMaxEachPostBytes`,
`scMinPostsIntervalMs`, `scMaxBufferedPosts`, `scStreamUpServerSecs`,
`serverMaxHeaderBytes`, and the `extra` blob (which replaces the outer config
except for `host`, `path`, and `mode`). Range values accept `5`, `"5"`, and
`"100-1000"` forms.

Header/cookie uplink data placement (base64url chunks in `X-Data-<i>` headers or
`x_data_<i>` cookies) is implemented for packet-up, since it is reachable from
`uplinkDataPlacement: "auto"`.

## Error handling

`TransportError` gains one variant group per transport, distinguishing the
failures an operator can act on: handshake rejection with the observed status,
response-validation failure naming the specific check, HTTP/2 connection loss,
and XHTTP sequence or padding rejection with the server's status code. Transport
setup failures surface as connection failures to the VLESS layer, which already
handles them.

Config-level errors mirror Xray-core's wording where a user is likely to have
seen it there: the REALITY transport restriction, the removed `h2`/`quic`
transports, and the `headers.Host` rules.

## Testing

Three layers, each catching what the others cannot.

**Wire-format unit tests.** Golden byte vectors for: the header serializer's
Go-compatible ordering and literal casing; the masquerade block for each persona
and both variants; early-data base64url encoding and the inclusive `<= ed`
boundary; `?ed=N` stripping with alphabetical query re-encoding; the httpupgrade
`%3F` divergence; gRPC length-prefix plus protobuf framing including
split-across-frames reassembly; XHTTP path/session/seq composition and padding
placement in the pre-session Referer.

**Interop against a live Xray-core.** `crates/xray-core-rs/tests/local_xray_interop_tests.rs`
already spawns a real Go xray-core from the local checkout with a generated
config; the matrix extends to each new transport across its legal security
combinations, with XHTTP's three modes as separate cases. Each stage lands with
its own slice of this matrix green.

**Byte-parity oracle.** Drive the Go xray-core *client* against a recording
listener, capture the exact request it emits, and assert our client emits the
same bytes for the same config. This is the only mechanism that catches
divergences like header ordering or the `%3F` escaping, which interop tests pass
straight through. It follows the pattern already used for the REALITY
ClientHello oracle.

## Staging

1. **Transport layer, WebSocket, HTTPUpgrade.** The `stream/` module,
   `connect_stream`, the compatibility-matrix validation (including the Vision
   and REALITY restrictions), the shared header builder, and the two simplest
   transports. New dependency: `sha1`.
2. **ALPN and gRPC.** `TlsClientConfig.alpn` with memoized rustls configs,
   `tlsSettings.alpn` parsing, the hand-rolled gRPC codec, and the H2 connection
   pool. New dependency: `h2`.
3. **XHTTP.** All three modes over H1 and H2, mandatory padding, the full
   config surface with `xmux` parsed-only, and H3 rejected explicitly.

Each stage is independently shippable and independently verifiable against a
live Xray-core.

## Documentation

`docs/config-compatibility.md:76-95` currently states that only the TCP
transport is supported and that "WebSocket, HTTP/2, gRPC, QUIC, KCP, and other
stream transports are not supported", and that non-empty ALPN lists are
rejected. Both statements are rewritten per stage, including the compatibility
matrix and the explicit non-goals (mkcp, hysteria, HTTP/3, `downloadSettings`,
xmux scheduling).
