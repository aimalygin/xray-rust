# VLESS Stream Transports: WebSocket, HTTPUpgrade, gRPC, XHTTP

> **On the line numbers below.** Citations into `Xray-core/` are to the vendored
> v26.5.9 checkout and do not move. Citations into `crates/` are of two kinds,
> and they are not interchangeable. Ones in the planning sections describe the
> tree this document was written against and are pinned to it — resolve them
> with `git show 2a51d52^:<path>`, not against `main`, where Stages 1 and 2 have
> moved them. Ones that describe what *shipped*, including everything added by
> an amendment, are to the current tree. The same split applies to counts of
> things in this repository: Stage 1 narrowed the uTLS fingerprint table from
> the 61 names the planning sections quote to the 58 it accepts today
> (`crates/xray-utls/src/lib.rs`, `fingerprint_table_matches_xrays_map_union`),
> and `docs/config-compatibility.md` is the count to trust.

## Decision

xray-rust gains four outbound stream transports — `ws`/`websocket`,
`httpupgrade`, `grpc`, and `xhttp`/`splithttp` — reaching wire parity with
Xray-core v26.5.9 (local checkout `Xray-core/`, commit `1bdb488c`). At the time
of writing only `tcp`/`raw` was accepted; every other `streamSettings.network`
was rejected at config parse time (`crates/xray-config/src/parser.rs:2650`), so
no VLESS profile using a web transport could be imported at all.

Out of scope: `mkcp`/`kcp` and `hysteria` (both UDP-based with their own
congestion protocols — each is comparable in size to this entire work), HTTP/3
for XHTTP (needs a full QUIC stack), and the server side of any transport
(xray-rust has no VLESS inbound; `InboundProtocol` is socks/http/tun only).

Parity target is byte-exact for the contents of every request and response we
emit or accept, including the browser-masquerade header block and Go's header
serialization order. It extends one layer down: `security: "tls"` gains uTLS
ClientHello shaping with a `chrome` default, matching what Xray-core does on
every transport including `raw` today. Three things fall outside the target, and
each is stated plainly rather than claimed as parity.

XHTTP's `xmux` connection-reuse scheduler, which no single request reveals, is
parsed but not implemented — it remains observable as a pattern of connection
timing.

On HTTP/2 the target is the connection preamble, plus the *contents* of the
first HEADERS block — not its bytes, and not the whole connection. `h2` is taken
as published rather than forked, and it differs from grpc-go's encoder in three
places, each measured against a live client rather than reasoned about. The
pseudo-header order is one swap off: the crate hardcodes `:method, :scheme,
:authority, :path` where grpc-go sends `:path` before `:authority`. The HPACK
representation differs even where the fields agree — `h2` writes `:path` as a
literal without indexing where grpc-go indexes incrementally. And the two
disagree on when to Huffman-code a string: grpc-go codes a header name only when
that shortens it, so `te` goes out raw, while `h2` codes unconditionally. Any
one of the three defeats a byte comparison, so the gRPC oracle asserts the field
set and the pseudo-header order, never the encoded block. Past that first
request there is no claim at all: HPACK dynamic-table evolution across pooled
streams, BDP-estimation PINGs, WINDOW_UPDATE cadence. For XHTTP over HTTP/2 a
byte-exact claim is not merely expensive but unavailable: `x/net/http2` iterates
`req.Header` as a Go map, so Xray's own bytes differ between two runs of one
config.

And one class of gRPC destination cannot be dialled here at all, which is a
narrower claim than the two above: not "we send different bytes" but "we send
nothing and refuse the profile". `h2` reads `:authority` out of the request's
`http::Uri` and nowhere else, and a `Uri`'s authority *is* an
`http::uri::Authority` — a type that refuses every byte above `0x7f` and `%`
anywhere in a host. So an internationalized destination such as `例え.jp`, which
xray-core dials either verbatim or through grpc-go's own percent-escaped
`host:port` fallback, is refused when the outbound is built. The A-label
(`xn--r8jz45g.jp`) is accepted and is the workaround; nothing here converts one
for the user, because no IDNA implementation is in the dependency graph and
converting silently would put an authority on the wire that xray-core does not
send. `docs/config-compatibility.md` carries the two error messages and which
config key each names.

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

`ConnectorConfig` (`crates/xray-transport/src/lib.rs:52`) stays what it is: the
**security** layer, `{ Tcp, Tls, Reality }`. Stream transports are an orthogonal
axis and get their own type in a new `crates/xray-transport/src/stream/` module.
What shipped, with Stage 3's variant still to come:

```rust
pub enum TransportLayer {
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(HttpUpgradeConfig),
    Grpc(GrpcTransport),
}
```

Two things about that differ from the sketch this section originally carried,
and both are deliberate. The type is **not** called `StreamTransport`:
`xray_config::StreamTransport` is the parsed config shape and this is the
dial-ready one, and two types with one name across two crates in the same call
chain is how the wrong one gets imported. And the gRPC variant carries a
`GrpcTransport` — a live, `Arc`-backed connection pool — rather than settings,
because its flows share one HTTP/2 connection; the other three carry plain
settings because each of them wraps one socket.

`TransportDialer` gains one method:

```rust
pub async fn connect_stream(
    &self,
    config: &ConnectorConfig,
    transport: &TransportLayer,
    original_target: &Target,
    candidates: &[SocketAddr],
    happy_eyeballs: Option<&HappyEyeballsConfig>,
) -> Result<BoxedTransportStream, TransportError>
```

For three of the four it calls the existing `connect_resolved` to obtain a
secured stream — the Happy Eyeballs race and the REALITY `prepare_preconnected`
path are untouched — and then applies the transport's framing, returning a
`BoxedTransportStream` again. gRPC is the arm that does not dial first: whether
the call needs a socket at all is a question only its pool can answer, so the
pool is handed `connect_resolved` to ask with rather than calling it here.
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
trait (`crates/xray-transport/src/lib.rs:158`), forwarding `poll_read_direct` /
`poll_write_direct` to the plain poll methods. `release_record_alignment` is
left at its default no-op on all four wrappers: record alignment exists only to
let Vision unwrap into direct mode, and Vision cannot run over a non-raw
transport (see below).

That is not the same as the alignment never being released, and gRPC is where
the difference shows. Its handshake moves the secured stream into h2's
`Connection`, so an outbound's `release_record_alignment` reaches only
`GrpcStream` and its no-op — by then nothing else holds the socket. The call is
therefore made once on the secured stream immediately before the handshake
(`crates/xray-transport/src/stream/grpc/h2client.rs`, `h2_handshake`), which is
the last point at which anything can. Unconditional is sound for the reason
above, and not making it would cost two socket reads per TLS record for the
tunnel's whole life.

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

Two new dependencies: `h2` (bare, without `hyper` or `tonic`) and `http`, whose
request, URI and header types `h2` takes. `http` is not an implementation
detail — `GrpcConfig::authority` is a re-exported `http::uri::Authority`, so the
type is in this crate's public API, and the divergence in the Decision section
is a property of it. No protobuf codegen is needed — `prost` is already in the
tree but the gRPC message is small enough to hand-encode. TLS shaping and ALPN
arrived in Stage 1, so this stage inherits a Chrome ClientHello advertising the
profile's `h2, http/1.1` and needs no TLS work of its own.

### Framing

The `.proto` is `message Hunk { bytes data = 1; }`, so one write of N > 0 bytes
is:

```
00                 compression flag (0 = uncompressed)
LL LL LL LL        u32 big-endian: 1 + varint_len(N) + N
0A                 protobuf tag: field 1, wire type 2
<varint N>
<N payload bytes>
```

Overhead is 7 bytes for 0 < N < 128 and 8 for N < 16384, which covers our buffer
sizes.

**N = 0 is a different shape, not that one with the payload omitted.** proto3
`bytes` has implicit presence, so a zero-length value is the field's default and
the generated marshaller drops the field rather than emitting `0a 00`. An empty
write is therefore the bare five-byte prefix with length 0 and no body at all —
five bytes of overhead, not seven. Xray's write side does not special-case it
(`hc.Send(&Hunk{Data: buf[:]})` runs for every write), so this is a message a
peer really sends, and the reader must treat it as a legal zero-byte read rather
than as end of stream — which in Rust means a wrapper must loop for the next
message instead of returning `Ok(0)`.

One write is one message; the decoder must reassemble across HTTP/2 DATA
frames, tolerate zero-length messages, skip unknown fields, and treat a non-zero
compression flag as a hard error. Keep messages under the server's 4 MiB
default. `multiMode` switches to `MultiHunk { repeated bytes data = 1; }` and
the `TunMulti` stream name — supported, since it must match the server.

### HTTP/2 request

`:path` is built from `serviceName`: a name without a leading `/` is
`PathEscape`d whole and the stream name is literally `Tun`/`TunMulti`
(`"hello"` → `/hello/Tun`); a name with a leading `/` splits into a path prefix
and a trailing stream segment. A `|` splits it once more, into
`tunName|tunMultiName` — both halves client-side, the first used with
`multiMode` off and the second with it on, so `/a/b|c` dials `/a/b` or `/a/c`.
The default `serviceName` is the empty string, which makes the default request
line `POST //Tun`, double slash included. A mis-escaped path returns an opaque
UNIMPLEMENTED rather than a config error, so the escaping table is ported
wholesale from `config_test.go` rather than re-derived.

Headers, in Go's order: `:method POST`, `:scheme http` (Xray-core dials gRPC
with `insecure.NewCredentials()` and applies TLS itself, so the scheme stays
`http` even over TLS), `:path`, `:authority`, `content-type: application/grpc`,
`user-agent`, `te: trailers`. Notably absent: `grpc-accept-encoding`,
`grpc-timeout`, `content-length`. Only two of them are load-bearing for the
server: `:method POST`, and a content type that is exactly `application/grpc` or
continues with `+` or `;` — `application/grpc-web` shares the prefix and is
refused. `te: trailers` is not validated at all; a request omitting it reaches
the handler. The rest are sent to fit the population, not to interoperate.

`user-agent` is not grpc-go's default with a suffix appended. `WithUserAgent` is
the call that appends one, and Xray never makes it — it reaches into the built
connection by reflection and overwrites the field. An unset `user_agent` is not
the empty case: it maps to the Chrome persona, same as `chrome`. The one value
that empties it is `golang`, and because the transport copies the field verbatim
and emits the header unconditionally, that produces `user-agent` with an empty
value on the wire rather than a fallback to `grpc-go/x.y.z`.

`:authority` precedence: `authority` → `tlsSettings.serverName` → the
destination domain **only when REALITY is absent** → otherwise empty. An empty
one is not an omitted header: grpc-go falls back to its resolver endpoint, so
what goes out is `host:port` with the port included, escaped by grpc's own
`encodeAuthority` rather than Go's URL escaping, which is why an IPv6
destination keeps its brackets. Under REALITY that fallback is the default path,
not an edge case.

Half-close on the write side; a trailers HEADERS frame with END_STREAM is EOF.
Teardown has two shapes with two different triggers, and conflating them puts
the wrong frames on the wire. `CloseSend` writes an empty DATA with END_STREAM.
Cancelling the RPC context writes RST_STREAM(CANCEL) and no DATA at all. Xray's
own client constructs its hunk connection with a nil cancel function, so its
ordinary close is the quiet one, and the RST appears only when the surrounding
context is separately cancelled.

### Connection reuse is required, not an optimization

Xray-core caches one `ClientConn` per (destination, stream settings) and opens
one HTTP/2 stream per proxied connection. Without this, every flow would perform
its own TLS handshake — unacceptable on mobile for both latency and memory. The
gRPC transport therefore owns a small pool: one H2 connection per
(server, settings), streams multiplexed over it, reconnect on GOAWAY or
transport error.

The pool does not fit the seam this project has. `TransportLayer::wrap(stream)
-> stream` is one socket in, one stream out; gRPC is N flows over one
connection. The pool therefore hangs off `VlessTcpOutboundPayload`, which is
already `Arc`-backed and memoized per outbound index by the cached router, and
dials keep going through `TransportDialer` — that last part is not stylistic. A
socket opened anywhere else misses Android's `VpnService.protect(fd)` and routes
straight back into the tunnel it is meant to leave. One hazard to keep in view:
the free `select_tcp_outbound*` functions rebuild the outbound on every call, so
a pool hung off the payload would be a fresh pool per flow through them. Every
runtime path is safe today — SOCKS holds an `Arc<OutboundRouter>`, and the TUN
and DNS paths call the router's methods — so those free functions are reached
only from tests and one bench call site. The consequence is not a live defect
but a rule for whoever adds the next call site, and a test that would pass while
measuring nothing.

Two upstream defects are deliberately not reproduced. Xray keys its pool on a
raw `*MemoryStreamConfig` pointer, so two outbounds with byte-identical
`grpcSettings` never share a connection. And it writes the map even when the
dial failed: that nil entry poisons the key for the process lifetime, because
the next lookup calls `GetState()` on a nil receiver and panics rather than
retrying. The map is never pruned either. A third apparent defect — replacing a
connection in `Shutdown` without closing it — is dead code, since nothing in the
gRPC transport ever closes a pooled connection, and is not a lesson to carry.

By default Xray-core sends **no SETTINGS entries at all** (an empty SETTINGS
frame after the preface) and never sends a PING unless `idle_timeout`,
`health_check_timeout`, or `permit_without_stream` is configured. We match both,
since an empty SETTINGS frame is itself a strong signal of the grpc-go
population. `initial_windows_size` reaches the wire through three independent
gates — the dial option attaches only above zero, the transport adopts the value
only at 65535 or more, and the SETTINGS entry is written only when the adopted
value differs from 65535 — so a config asking for `30000` still produces an
empty SETTINGS frame. It does also disable BDP estimation, but through a
separate mechanism worth not conflating with the gates: setting the dial option
at all marks the window static, and the estimator is built only when it is not.

Config keys: `authority`, `serviceName`, `multiMode`, `idle_timeout` (seconds,
clamped up to a 10 s floor as grpc-go does), `health_check_timeout` (default
20 s), `permit_without_stream`, `initial_windows_size` (applied only *above*
65535, strictly — the three gates above stop 65535 itself, and applying it there
would put a `SETTINGS_INITIAL_WINDOW_SIZE` entry on the wire that grpc-go never
writes, which is the exact fingerprint those gates exist to protect),
`user_agent`.

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

The gap is narrower than that framing suggests. With `xmux` omitted,
`maxConcurrency` defaults to `1-1`, so Xray-core itself opens a new connection
per concurrent flow — straightforward per-connection reuse *is* the upstream
default, and the divergence appears only once a profile sets `xmux` explicitly.
Note also that `maxConnections: 0` means the pool never grows for that reason,
not that it is unlimited; unlimited is what `maxConcurrency: 0` says.

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

`TransportError` gains variants distinguishing the failures an operator can act
on: handshake rejection with the observed status, response-validation failure
naming the specific check, HTTP/2 connection loss, and XHTTP sequence or padding
rejection with the server's status code. Transport setup failures surface as
connection failures to the VLESS layer, which already handles them.

What shipped is one variant per transport rather than a group per transport —
`HttpUpgradeRejected(String)`, `WebSocketProtocol(String)`, `Grpc(String)` —
with the distinctions carried in the message. This section over-promised: the
distinctions are worth making, but nothing in the chain branches on *which*
gRPC failure it was, and a variant nobody matches on is a wider enum for the
same information. gRPC's single `Grpc(String)` is consistent with what Stage 1
had already settled on.

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

What that oracle can assert differs by transport, and promising one bar for all
four would write an acceptance criterion nobody can meet:

- **HTTP/1.1 transports (ws, httpupgrade, XHTTP over h1).** Byte-exact, as
  today. Go's `Request.Write` emits a deterministic order.
- **gRPC.** Byte-exact for the preface and for the client's own SETTINGS frame,
  and the frames written before the first HEADERS compared as decoded
  descriptors so that an added frame fails the check. The first HEADERS block
  itself is **not** byte-exact: `h2`'s HPACK encoder diverges from grpc-go's in
  three places, listed in the Decision section, and any one of them defeats a
  byte comparison. It is asserted as a decoded field list in order instead.
  Later HEADERS blocks are not asserted at all — the dynamic table has evolved
  by then.
- **XHTTP over HTTP/2.** Normalized shape only: ordered pseudo-headers, then the
  regular header set compared as a set. `x/net/http2` ranges over `req.Header`,
  a Go map, so no byte sequence exists to pin — Xray disagrees with itself
  between runs.

Two operational rules the fixtures live under. The Go oracle for gRPC goes in
its own nested module beside `tools/reality-oracle/masquerade`, never the root
module: the root builds against uTLS, and pulling xray-core in there lifts
`x/crypto` and moves every committed ClientHello fixture. And each fixture
records the grpc-go and `x/net/http2` version it was generated under, because
`http::HeaderMap` documents that iteration order may change without a semver
bump, and an unexplained mismatch after a routine dependency bump is exactly the
failure this repository has already lived through with `x/crypto`.

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
2. **gRPC.** The hand-rolled gRPC codec, the H2 connection pool, and the dial
   seam both remaining transports need — a second dial shape on
   `TransportDialer` with connection state on the outbound payload. The seam is
   built here rather than as a standalone refactor, because a refactor with no
   consumer cannot be validated. New dependencies: `h2` and `http`.
3. **XHTTP.** All three modes over H1 and H2, mandatory padding, the full
   config surface with `xmux` parsed-only, and H3 rejected explicitly. Its first
   task is deciding which Xray-core revision it targets: the wire moved after
   the vendored v26.5.9 and the protocol has no version negotiation left.

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

## Amendment, 2026-08-08 — before Stage 2

Stage 1 shipped. Rereading this document against the vendored v26.5.9 before
starting gRPC turned up claims that were wrong rather than merely incomplete,
and three decisions it had left open. Corrections are folded into the sections
above, where the wrong sentence was, rather than collected here — a correction
filed at the end of a document is a correction nobody reads. This section
records what moved and why.

Every wire claim in Stage 2 was then rechecked against the vendored source, the
grpc-go module in the build cache, and — where the question was behaviour rather
than code — captures from a real grpc-go client driven against a raw HTTP/2
framer. Four of the claims written during this pass were themselves wrong and
are corrected above; the pseudo-header swap, the three `initial_windows_size`
gates, the `|` split, the empty `serviceName` double slash, and the Go map
iteration behind the XHTTP-over-h2 carve-out all survived.

### Decisions taken

- **HTTP/2 fidelity bar: the preamble and the first HEADERS block.** `h2` is a
  normal dependency, not a second fork alongside shaped-rustls. The residual
  pseudo-header swap against grpc-go is recorded as a known divergence when the
  stage lands — in `docs/status.md`, not in an acceptance criterion. Revisit only if an oracle demands it; the fix is
  a small patch to a vendored copy, not a redesign.
- **The dial seam.** A second dial shape on `TransportDialer` with connection
  state on the `Arc`-backed outbound payload, built inside the gRPC stage. The
  two rejected options are worth recording: one connection per flow pays a
  TLS/REALITY handshake per flow and is visibly not a gRPC client, and inverting
  the model so every transport owns its dial rewrites Happy Eyeballs and the
  REALITY preconnect for no benefit available today.
- **Config strictness.** Accept the whole documented key surface, implement the
  defaults, and reject what is unimplemented with a specific message. Never
  silently ignore: a key accepted and dropped is discovered on the wire. This
  follows from the goal being importability — a profile that runs on xray-core
  runs here, or is refused where xray-core refuses it and for the same reason.

### On upstream's deprecation notices

`TransportProtocol.Build` prints a deprecation warning for gRPC, pointing at
"XHTTP stream-up H2". It prints the same kind of warning for WebSocket and for
HTTPUpgrade, pointing at "XHTTP H2 & H3". Three of the four transports in this
document are deprecated upstream, including the two that already shipped.

The call is `PrintNonRemovalDeprecatedFeatureWarning`, and the name is the
point. The same `match` uses `PrintRemovedFeatureError` for `h2`/`h3`/`http` and
`quic`, which are hard errors — Xray draws the line explicitly between what it
discourages and what it has removed. All three of ours are on the discouraged
side, and a profile written against any of them still runs.

So the notices do not bear on whether we implement gRPC. This project consumes
profiles other people already deployed, and a deployed gRPC profile does not
stop existing because new deployments are steered elsewhere. What the notices
do say is worth carrying: XHTTP is where upstream is consolidating and the only
one of the four not deprecated, which argues against deferring it indefinitely —
and it argues against spending fidelity effort on gRPC beyond the bar set above,
since the surface a censor studies next is XHTTP's, not gRPC's.

### Corrections folded into the sections above

1. The parity target promised byte-exact output for *every* request. Unreachable
   for XHTTP over HTTP/2 at any price, because `x/net/http2` iterates a Go map.
   The Testing section now states what each transport family can assert.
2. Stage 2 described `user-agent` as the grpc-go default with the suffix
   stripped. Xray overwrites the field outright, and there is no fallback to
   strip a suffix from: the one value that clears the persona, `golang`, puts an
   empty header value on the wire.
3. Stage 2's `:authority` precedence omitted that the destination-domain step is
   skipped under REALITY, and that the empty case falls back to `host:port`
   under grpc's own escaping rather than Go's.
4. Stage 2 described teardown as a half-close and stopped there. There are two
   shapes with two triggers — `CloseSend` produces the empty DATA, context
   cancellation produces RST_STREAM(CANCEL) and no DATA — and Xray's own client
   normally takes the quiet one.
5. Stage 2 left `:path` incomplete: the `|` split, the double slash the default
   empty `serviceName` produces, and the three gates on `initial_windows_size`.
6. Stage 3 called `xmux` the one deliberate parity gap without noting that
   upstream's own default is no multiplexing, which makes the gap much smaller
   than the paragraph implied.

### Implementation findings that belong in the plan, not here

Recorded as of this amendment, before Stage 2 started. The first two describe
code that Stage 2 then changed — Task 5 turned the REALITY condition into an
allowlist and gave the two `stream_transport_is_dialable` sites the same
verdict — so read them as the reason those tasks exist, not as a description of
the tree today.

- `crates/xray-config/src/parser.rs:2571` refuses REALITY on everything but
  `Raw`, with a message that already reads *"REALITY only supports RAW, XHTTP
  and gRPC for now"*. The text describes Xray's rule; the condition does not.
  Both transports are unreachable in their flagship deployment until that
  becomes an allowlist.
- `stream_transport_is_dialable` guards freedom and DNS outbounds. The cached
  router applies it on the TCP path (`outbound.rs:1153`) and omits it on the UDP
  path, where the uncached twin (`outbound.rs:1371`) applies it — so one config
  gets two verdicts depending on whether the router cache is live. The guard
  list has to grow for grpc and xhttp anyway; it is fixed there.
- gRPC gets the repository's first benchmark workload that measures transport
  framing. There is still none for ws or httpupgrade.
- The Swift `vless://` importer stays out of scope, and not because gRPC changed
  anything: it accepts only `type ∈ {tcp, raw}` with `security=reality`, so it
  already refuses the ws and httpupgrade profiles the engine dials. Fixing it is
  one job for all five transports, and it needs a source of truth for share-link
  parameters that this repository does not contain.

## Amendment, 2026-08-09 — one deliberate step outside grpc-go's preamble

Stage 2's fidelity bar was "the preamble and the first HEADERS block", and the
preamble was the half we could hold to the byte. We are giving up one frame of
it on purpose, and this records the decision so that a later reader does not
read the extra frame as drift.

**What changed.** The h2 client is built with a 16 MiB connection-level receive
window, so a `WINDOW_UPDATE(stream 0)` with an increment of `16 MiB − 65535`
goes out immediately behind SETTINGS. A grpc-go client under Xray writes no such
frame: it writes one only when `InitialConnWindowSize` exceeds the default
(`grpc@v1.81.0/internal/transport/http2_client.go:315-317,452-458`), and nothing
under `Xray-core/transport/internet/grpc/` sets it.

**Why.** `h2` pins its connection-level receive window at 65535 whatever
SETTINGS say (`h2-0.4.15/src/proto/streams/recv.rs:92-97`) and releases the
stream and connection windows together, from the application's read path. The
pool puts every flow of an outbound on one connection. So at the default, one
flow whose consumer has stopped reading holds the window every other flow on
that outbound needs, and those flows wait out the 300 s idle timeout; and the
outbound's whole downlink is capped at 65535 bytes per round trip, roughly
10 Mbit/s at 50 ms. Both relays in this repository stop reading under
backpressure — the TUN loop while a send into a backed-up stack is pending, and
`copy_direction` while a write to a slow local socket is pending — so the
triggering state is ordinary. grpc-go decouples exactly this, and the comment
that does it says why: *"Decoupling the connection flow control will prevent
other active(fast) streams from starving in presence of slow or inactive
streams"* (`http2_client.go:1183-1203`).

**Why 16 MiB.** It is grpc-go's own `bdpLimit`
(`internal/transport/bdp_estimator.go:27-30`), the ceiling its estimator grows a
window to, so the number is upstream's rather than ours. It costs no memory:
what a peer can make us buffer is bounded by the sum of the per-stream windows,
still 65535 each, and this only stops the connection window being the binding
constraint. It takes 256 simultaneously stalled flows to bind it again.

**What this is not.** It is not a divergence traded for parity. Under Xray's
default `grpcSettings` no window option is set, `StaticWindowSize` stays false,
and grpc-go's BDP estimator grows both the connection and stream windows
mid-connection up to that same 16 MiB (`updateFlowControl`,
`http2_client.go:1162-1181`). A connection window that never moves is therefore
also unlike the client we are imitating — just later, and only under load. The
decision is to take an earlier, smaller, constant divergence in exchange for
removing a starvation bug and a per-outbound throughput ceiling.

**What holds the line.** The oracle fixture is unchanged and still records what
grpc-go emits. The preamble test compares our burst against that fixture *plus*
this one declared frame, and separately asserts the frame's increment, so a
second divergence or a change to this one fails the test rather than being
absorbed by it. `docs/status.md` lists it beside the three HPACK divergences.

## Amendment, 2026-08-09 — the document read against what shipped

Stage 2 is done. Reading this document line by line against the code it
produced turned up eight places where it describes something other than what
was built. All eight are corrected in the sections above, in the sentence that
was wrong, per this document's standing convention; they are listed here so
that a reader who remembers the old text can find out what happened to it.

1. **The Testing section still set a byte-exact bar for the first HEADERS
   block** — the bar the Decision section abandoned two amendments ago and the
   shipped oracle deliberately does not meet. `ead0993` fixed one of the two
   sites and missed this one. Both now say the same thing.
2. **`initial_windows_size` was described as applying at `>= 65535`** where the
   code, and this section's own three-gate paragraph, say strictly above.
   Following the bullet would have emitted a SETTINGS entry grpc-go never
   writes — the fingerprint the gates exist to protect.
3. **The Decision section counted two things outside parity; there are three.**
   `http::uri::Authority` refuses every byte above `0x7f` and `%` in a host, so
   an IDN destination cannot be dialled where xray-core dials it. It was
   documented honestly for users in `docs/config-compatibility.md` and missing
   from the spec.
4. **The Hunk layout was wrong at N = 0.** proto3 implicit presence drops a
   zero-length `bytes` field, so an empty write is a bare five-byte message and
   "overhead is 7 bytes" does not hold there.
5. **Stage 2 claimed one new dependency where two shipped**, and `http` is in
   the public API rather than behind it. The CHANGELOG was corrected in
   `8641580`; this was not.
6. **The Architecture sketch named `StreamTransport(GrpcSettings)`.** Shipped is
   `TransportLayer::Grpc(GrpcTransport)`, and both halves of that are
   deliberate — the rename avoids colliding with `xray_config::StreamTransport`,
   and the variant carries a live pool rather than settings because gRPC's Nth
   flow wants no socket. The `connect_stream` sketch had drifted too, and it
   claimed every arm dials first, which the gRPC arm does not.
7. **`release_record_alignment` was called a no-op for all four** without
   noting that the gRPC path calls it, unconditionally, on the secured stream
   just before the h2 handshake — the last point at which anything can reach
   the socket.
8. **Error handling promised a variant group per transport.** gRPC shipped a
   single `Grpc(String)`, consistent with Stage 1 and defensible; the promise
   was the wrong shape, not the implementation.

Two smaller things went with them. The Decision section's HTTP/2 paragraph had
a prose seam left by an earlier amendment and now joins cleanly. And the
document acquired a note about its own citations: the ones in the planning
sections are pinned to the tree it was written against, because Stages 1 and 2
have moved almost every line they name, and a citation that has moved is worse
than no citation — it looks verified.
