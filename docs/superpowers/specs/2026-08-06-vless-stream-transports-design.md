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
serialization order. It extends one layer down: `security: "tls"` gains uTLS
ClientHello shaping with a `chrome` default, matching what Xray-core does on
every transport including `raw` today. One thing falls outside the target:
XHTTP's `xmux` connection-reuse scheduler, which no single request reveals, is
parsed but not implemented — it remains observable as a pattern of connection
timing, and that gap is stated plainly rather than claimed as parity.

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
- **The TLS hello matters more than the headers.** Xray-core shapes the
  ClientHello with uTLS on every TLS connection. xray-rust shapes it only under
  REALITY, and ws and httpupgrade cannot use REALITY at all — so those two would
  ship entirely unshaped, on the CDN-fronted deployments where the hello is what
  gets read. Closing this is a prerequisite for these transports, not a
  follow-up, and it lifts machinery already written for REALITY rather than
  building new.

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

### uTLS ClientHello shaping extends to plain TLS

Xray-core does **not** use stock crypto/tls for `security: "tls"`. Every
transport — including `raw` — resolves a uTLS fingerprint and wraps the
connection with `tls.UClient`:

```go
if fingerprint := tls.GetFingerprint(tConfig.Fingerprint); fingerprint != nil {
    conn = tls.UClient(pconn, tlsConfig, fingerprint)
}
```

and `GetFingerprint("")` returns `&utls.HelloChrome_Auto`
(`Xray-core/transport/internet/tls/tls.go:186`). `fingerprint` is a documented
field of `tlsSettings` — `TLSConfig.Fingerprint`
(`infra/conf/transport_internet.go:653`), validated at config-build time,
carried as `fingerprint = 11` in `transport/internet/tls/config.proto`.

`GetFingerprint` returns nil in two cases: an unrecognized name, which the
config builder has already rejected, and the deliberate value `"unsafe"`, whose
map entry is permanently nil (`tls.go:214`) and which the config builder
explicitly waves through (`transport_internet.go:700`). `"random"`,
`"randomized"`, and `"randomizednoalpn"` look nil in the same map but are filled
with real profiles by `init()` at startup. So the stock `tls.Client` path
(`transport/internet/tcp/dialer.go:84`) is a deliberate escape hatch reached
only by asking for it by name. Absent that one word, **every Xray-core TLS
connection carries a shaped, Chrome-by-default ClientHello.**

xray-rust supports fingerprints on exactly one of its two TLS paths. Under
`security: "reality"` the support is complete: `realitySettings.fingerprint`
accepts all 61 Xray names, defaults to `chrome` on an empty value
(`xray-utls/src/lib.rs:134`), additionally rejects profiles with no
X25519-compatible key share, and reaches the wire through the shaped-rustls
fork. Under `security: "tls"` it is refused twice — the parser errors with
"tls fingerprint is unsupported" (`crates/xray-config/src/parser.rs:2752`), and
`build_connector` returns `UnsupportedOutboundSecurity` for any non-empty
fingerprint (`crates/xray-core-rs/src/outbound.rs:1498`). `TlsClientConfig` has
no fingerprint field at all; plain TLS gets rustls' own ClientHello.

That is already a divergence on `raw` + `tls`, independent of this work. What
makes it blocking here is the compatibility matrix above: **ws and httpupgrade
cannot use REALITY** — Xray-core rejects that combination outright. For those
two transports plain TLS is the *only* available security, so they would ship
with no shaping whatsoever, on precisely the CDN-fronted deployments where a
middlebox reads the ClientHello long before it sees an HTTP request, and often
never sees the request at all. Byte-exact browser headers behind a ClientHello
no Chrome ever sent is not parity; it is a more precise way to stand out.
gRPC and XHTTP are shaped today whenever REALITY is configured, and unshaped
whenever it is not.

The machinery already exists and is generic — it is only bound to REALITY by
module visibility. Our rustls fork exposes `ClientConfig.client_hello_customizer`
as a plain field (`crates/xray-transport/src/reality_rustls.rs:1147`),
`ClientHelloPlan` is transport-agnostic, and `apply_utls_profile` plus the
profile table already translate a uTLS profile into that plan: `xray-utls`
accepts 61 fingerprint names and every one of them resolves to a shaping profile
(43 distinct profiles, the rest aliases). 14 of those names are REALITY-incapable
for want of an X25519 key share and are rejected today; under plain TLS they
have no such constraint and become usable for the first time. The REALITY
customizer adds exactly three REALITY-specific things on top: a fixed hello
random, a session id carrying the auth key, and a fixed X25519 key share
(`reality_rustls.rs:338`). A plain-TLS customizer is the same call without them.

So the work is a lift, not a build:

- Move `profile_for_fingerprint`, `apply_utls_profile`, and the profile table
  out of the REALITY-private module (`pub(super)` today) into a shared
  `utls_profiles` module, dropping the `reality_` prefix. No logic changes.
- Add a `UtlsClientHelloCustomizer` that applies only the profile.
- `TlsClientConfig` gains `fingerprint: Option<String>` and `alpn: Vec<String>`.
  `TlsConnector` builds configs on demand memoized by
  `(allow_insecure, alpn, fingerprint)` — `rustls::ClientConfig` is immutable
  behind an `Arc`, so a small map replaces the two fixed instances
  (`crates/xray-transport/src/tls.rs:23`).
- The parser stops rejecting `tlsSettings.fingerprint`, validates it against the
  same table `realitySettings.fingerprint` already uses, and defaults it to
  `chrome` when absent, matching `GetFingerprint("")`. The extra
  X25519-key-share requirement stays REALITY-only — plain TLS has no such
  constraint, so `normalize_reality_supported_fingerprint` is not applied here.
- `fingerprint: "unsafe"` is accepted as Xray-core's escape hatch and means no
  shaping: rustls' own ClientHello, i.e. exactly today's behavior. It is the
  only way to get an unshaped hello, and it must be spelled out to get it.
- `build_connector` (`crates/xray-core-rs/src/outbound.rs:1498`) stops returning
  `UnsupportedOutboundSecurity` for a non-empty TLS fingerprint and passes it
  through to `TlsClientConfig` instead. The same change applies at the second
  site (`outbound.rs:1552`, the DNS outbound's connector).

### ALPN comes from the fingerprint, not from the config

The obvious reading — that `tlsSettings.alpn` decides what the ClientHello
advertises — is backwards. uTLS applies the extension in the fingerprint spec
and **overwrites the config** with it
(`utls/u_tls_extensions.go:613`):

```go
func (e *ALPNExtension) writeToUConn(uc *UConn) error {
    if uc.config.EncryptedClientHelloConfigList == nil {
        uc.config.NextProtos = e.AlpnProtocols
        uc.HandshakeState.Hello.AlpnProtocols = e.AlpnProtocols
    }
    return nil
}
```

The one escape is `WebsocketHandshakeContext`
(`transport/internet/tls/tls.go:96`), which rebuilds the hello *after*
`BuildHandshakeState` and forces the ALPN extension to `http/1.1` — or leaves
`h2, http/1.1` if exactly that pair was configured for camouflage. Which
handshake each transport uses gives the actual rule:

| transport | handshake | ALPN advertised in the ClientHello |
|---|---|---|
| ws, httpupgrade | `WebsocketHandshakeContext` | `["http/1.1"]`, or `["h2","http/1.1"]` if exactly that was configured |
| raw, `alpn: ["http/1.1"]` | `WebsocketHandshakeContext` | same as above |
| raw otherwise, grpc, xhttp | `HandshakeContext` | the fingerprint profile's list (Chrome: `["h2","http/1.1"]`) |

So for gRPC and XHTTP, setting `tlsSettings.alpn` does not change the
ClientHello at all — the profile wins. It still has an effect client-side:
XHTTP's `decideHTTPVersion` reads the *configured* list to pick H1 vs H2
(Stage 3), and that decision is independent of what was advertised.

Our REALITY path already implements the general rule correctly, since
`apply_utls_profile` applies `profile.alpn_protocols`. The new work is the
`WebsocketHandshakeContext` override — a post-profile ALPN replacement in the
plan — and applying the same rule on the plain-TLS path.

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

Inside `tlsSettings`, two keys change from rejected to supported:
`fingerprint` (validated against the uTLS profile table, defaulting to `chrome`
when absent) and `alpn` (accepted, with the caveat that it reaches the wire only
through the `WebsocketHandshakeContext` path — see above). `TlsSettings`
(`model.rs:910`) already carries a `fingerprint` field that the parser fills and
then errors on; the field stays and the error goes.

## Stage 1 — transport layer, TLS shaping, WebSocket, HTTPUpgrade

New dependency: `sha1` 0.10 (same RustCrypto generation as our `sha2`), needed
only to validate `Sec-WebSocket-Accept`.

TLS shaping lands here rather than with gRPC, because ws and httpupgrade are the
CDN-fronted transports where the ClientHello matters most; shipping them before
the shaping seam would ship a fingerprinting hole in the exact deployment they
serve. This stage therefore also carries the `utls_profiles` module lift, the
`UtlsClientHelloCustomizer`, `TlsClientConfig.{fingerprint, alpn}` with memoized
rustls configs, the `WebsocketHandshakeContext` ALPN override, and lifting the
parser's rejection of `tlsSettings.fingerprint` and `tlsSettings.alpn`. It fixes
the pre-existing `raw` + `tls` divergence as a side effect.

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

## Stage 2 — gRPC

New dependency: `h2` (bare, without `hyper` or `tonic`). No protobuf codegen is
needed — `prost` is already in the tree but the gRPC message is small enough to
hand-encode. TLS shaping and ALPN arrived in Stage 1, so this stage inherits a
Chrome ClientHello advertising the profile's `h2, http/1.1` and needs no TLS
work of its own.

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
ClientHello oracle, and it now covers two surfaces per connection: the shaped
ClientHello and the HTTP request that follows it.

The existing REALITY ClientHello oracle extends to plain TLS with the same
fixtures (`tests/fixtures/reality/clienthello_*.json`), asserting that a
`security: "tls"` connection with a given `fingerprint` produces the same hello
Xray-core produces — including the `WebsocketHandshakeContext` ALPN override for
ws and httpupgrade, which is the one case where the advertised ALPN differs from
the profile's own list.

## Staging

1. **Transport layer, TLS shaping, WebSocket, HTTPUpgrade.** The `stream/`
   module, `connect_stream`, the compatibility-matrix validation (including the
   Vision and REALITY restrictions), the shared header builder, the
   `utls_profiles` lift with a plain-TLS ClientHello customizer,
   `TlsClientConfig.{fingerprint, alpn}`, and the two simplest transports.
   New dependency: `sha1`.
2. **gRPC.** The hand-rolled gRPC codec and the H2 connection pool.
   New dependency: `h2`.
3. **XHTTP.** All three modes over H1 and H2, mandatory padding, the full
   config surface with `xmux` parsed-only, and H3 rejected explicitly.

Each stage is independently shippable and independently verifiable against a
live Xray-core.

## Documentation

`docs/config-compatibility.md:76-95` currently states that only the TCP
transport is supported, that "WebSocket, HTTP/2, gRPC, QUIC, KCP, and other
stream transports are not supported", and that "TLS fingerprint shaping and
non-empty custom ALPN lists are not supported". All three statements are
rewritten per stage, including the compatibility matrix, the supported
fingerprint list with its `chrome` default, the rule that ALPN comes from the
fingerprint profile rather than the config, and the explicit non-goals (mkcp,
hysteria, HTTP/3, `downloadSettings`, xmux scheduling).
