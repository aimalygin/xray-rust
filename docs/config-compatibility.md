# Configuration compatibility

`xray-rust` reads Xray-style JSON, but only the subset described here. It is not
a schema-compatible replacement for Xray-core. Unsupported modeled fields
normally fail parsing with a JSON path instead of being silently approximated.

## Minimal loopback example

This config exposes unauthenticated SOCKS5 only on loopback and routes through
the host network:

```json
{
  "inbounds": [
    {
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 1080,
      "settings": {
        "auth": "noauth",
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
```

Keep local inbounds on loopback. A non-loopback SOCKS/HTTP listener is rejected
unless `settings.allowUnauthenticatedLan` is explicitly `true`; enabling it
exposes an unauthenticated proxy to the network.

## Top-level objects

| Key | Status |
| --- | --- |
| `inbounds` | Supported subset below |
| `outbounds` | Supported subset below |
| `routing` | Ordered `field` rules and selector-group subset below |
| `observatory` | Bounded periodic HTTP(S) URL probes for tagged outbounds |
| `dns` | Hosts, string/object servers with managed selection policy, global `queryStrategy`, and `fakeIp` subset |
| `policy` | Level/system fields are parsed; runtime timeout/buffer behavior is a subset |
| `log` | Accepted for input compatibility, but runtime file logging is configured through the embedding API |

Other top-level keys are rejected.

## Inbounds

| Protocol | Supported behavior | Unsupported or constrained behavior |
| --- | --- | --- |
| `socks` | SOCKS5 no-auth `CONNECT`, `UDP ASSOCIATE`, `userLevel`, sniffing | Authentication/accounts |
| `http` | HTTP `CONNECT`, timeout-shaped policy, `userLevel`, sniffing | Accounts and transparent proxy mode |
| `tun` | Platform packet boundary or registered fd; port may be omitted | Platform interface creation and routes are host responsibilities |

Common fields are `tag`, `protocol`, `listen`, `port`, `settings`, and
`sniffing`. Sniffing supports `enabled`, `destOverride` values `http`, `tls`,
and `quic`, plus `metadataOnly` and `routeOnly`. This is a routing-oriented
subset rather than full Xray sniffing behavior.

## Outbounds and streams

`freedom`, `vless`, and `dns` are supported. DNS outbound settings are described
below. VLESS accepts one `vnext` server with one or more UUID users, but the
runtime currently selects the first user.
`encryption: "none"`, optional `level`, and these flow values are accepted:

- empty/no flow;
- `xtls-rprx-vision`;
- `xtls-rprx-vision-udp443`.

`streamSettings.method` (preferred in v26.7.28) and its `network` alias accept
`tcp`/`raw`, `ws`/`websocket`, `httpupgrade`, `grpc`, and
`xhttp`/`splithttp`; `method` wins when both are populated. Xray renamed the
TCP transport to `raw` and XHTTP from `splithttp`; both pairs are accepted aliases, as are `ws` and
`websocket`. `gun` is not an accepted alias for `grpc`, because v26.7.28's
`TransportProtocol.Build` has no such arm either. Security values are:

- `none`;
- `tls`, with `serverName`, `fingerprint`, `alpn`, and
  `pinnedPeerCertSha256` and `verifyPeerCertByName`; `allowInsecure` may be
  absent, `null`, or `false`, while `true` is a hard error matching Xray-core
  v26.7.28;
- `reality`, with `serverName`, a supported `fingerprint`, base64url
  `publicKey`, hexadecimal `shortId`, optional `spiderX`, and optional
  `mldsa65Verify`.

`tcpSettings.header.type` — equally `rawSettings.header.type` — may be absent,
empty, or `none`. Generic HTTP/2, QUIC, KCP and other stream transports are not
supported; HTTP/2 and QUIC v1 are available only as XHTTP's selected wire
engines. Outbound mux, `sendThrough`, multiple VLESS servers, and
protocol-layer chaining remain unsupported. The supported chaining subset
uses Xray's outbound `proxySettings` with a non-empty `tag` and an explicit
`"transportLayer": true`:

```json
{
  "tag": "entry",
  "protocol": "vless",
  "proxySettings": { "tag": "exit", "transportLayer": true }
}
```

The referenced tag is resolved through the immutable outbound graph before the
core starts. Missing targets, self-cycles, and multi-node cycles fail closed.
TCP Freedom and VLESS chains can use raw, TLS, WebSocket, HTTPUpgrade, gRPC,
and TCP-backed XHTTP carriers. Chained UDP/DNS, protocol-layer
`transportLayer: false`, REALITY inside a chain, and XHTTP HTTP/3 inside a
chain remain rejected rather than bypassing the configured edge. When a VLESS
hop can carry the next domain target, the target stays unresolved until that
hop; only terminal Freedom carriers use local destination resolution.

VLESS with `encryption: "none"` and no stream security fails closed for a
public server address. This adopts Xray-core v26.7.28's policy but deliberately
closes an upstream legacy-schema gap: Xray invokes the guard for simplified
top-level VLESS settings, while its legacy `vnext` shape bypasses it.
xray-rust supports `vnext` and applies the guard there as an intentional
security hardening, so this one unsafe legacy profile is rejected even though
the pinned Xray binary accepts it. Such a server must use TLS or REALITY unless
its IP is in Xray's exemption set (`0.0.0.0/8`, `10/8`,
`100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`,
`192.0.2/24`, `192.88.99/24`, `192.168/16`, `198.18/15`,
`198.51.100/24`, `203.0.113/24`, `224/3`, `::/127`, `fc00::/7`,
`fe80::/10`, or `ff00::/8`). Domain exemptions are `lan`, `localdomain`,
`example`, `invalid`, `localhost`, `test`, `local`, `home.arpa`, and
`internal`, including their subdomains, plus a valid dotless ASCII hostname
label. Domain matching lowercases the name and removes one trailing dot.
Bracketed address parsing removes the brackets before trimming surrounding
space, matching Xray address normalization. TLS and REALITY outbounds are
unaffected.

VLESS UDP is carried over the supported TCP transport using VLESS datagram or
XUDP framing; it does not make `streamSettings.network: "udp"` valid.

`pinnedPeerCertSha256` is one comma-separated string. Entries are trimmed,
empty entries are ignored, every `:` is removed, and each remaining value must
be a 32-byte hexadecimal SHA-256 digest. The digest covers the complete DER
certificate, not its SPKI. A matching leaf certificate is accepted immediately,
as in Xray, without chain, time, or name verification. Otherwise the first
matching CA in the peer-presented chain becomes the sole root and rustls still
verifies the leaf chain, validity period, and effective TLS server name. An
absent or empty `serverName` uses the VLESS/DNS destination, including an IP
literal; IP names verify the IP SAN and are not emitted as SNI.

`verifyPeerCertByName` is also one comma-separated string. Entries are trimmed,
empty entries are ignored, and the resulting DNS/IP names are ORed: one SAN
match succeeds. The list changes certificate verification only; explicit or
destination-derived `serverName` remains the handshake SNI. Without pins the
ordinary system roots, chain, and time checks remain active. With a CA pin the
pinned CA is the sole root and the same OR list is checked. A matching leaf pin
still short-circuits every PKI and name check before the list is considered.
IP literals match IP SANs rather than DNS SANs.

The TLS slice deliberately does not implement the `fromMitm` sentinel, ECH,
custom certificate stores, or removed chain/SPKI pin fields. They are rejected
with a path-aware error instead of being ignored. The programmatic
`allow_insecure` model field exists only for hermetic local tests and cannot be
produced by canonical JSON parsing.

### WebSocket and HTTPUpgrade

Both transports carry VLESS over an HTTP/1.1 upgrade and share Xray's
browser-masquerade header block, so a request from either looks like a
browser's. Their requests are serialized the way Go writes an `http.Request`:
request line, `Host`, `User-Agent`, then every remaining header sorted
case-sensitively by its literal key. Header CR/LF is replaced with spaces,
invalid field names are dropped, IDN hosts are written as Punycode, and an
absent `User-Agent` becomes Go's `Go-http-client/1.1` default. Those details
matter for both wire parity and request-smuggling resistance.

`wsSettings` accepts `path`, `host`, `headers`, `heartbeatPeriod` and
`acceptProxyProtocol`; `httpupgradeSettings` accepts the same less
`heartbeatPeriod`. A settings block belonging to another network is validated
but ignored, with a warning — Xray builds every block that is present and only
picks between them at dial time, which is how a copy-pasted `wsSettings`
silently downgrades a profile to plain TCP.

The `Host` header is the transport's own `host`, else `tlsSettings.serverName`,
else the destination address, and never carries a port. WebSocket also accepts
a `Host` inside `headers`, folding it into `host` with a deprecation warning;
HTTPUpgrade rejects it, because Xray reads its `Host` from `host` alone. The
two also disagree on header casing, deliberately: WebSocket feeds `headers`
through Go's `header.Add`, which MIME-canonicalizes the key, so `accept`
reaches the wire as `Accept`; HTTPUpgrade assigns into the map directly and
keeps whatever casing was written.

**`?ed=N` in the path means different things on the two transports**, despite
the shared spelling. On both it is stripped from the path and the remaining
query is re-encoded the way Go's `url.Values.Encode` does. On WebSocket it is
an early-data budget: nothing touches the network until the first write, and
if that write is at most `N` bytes it travels inside `Sec-WebSocket-Protocol`
as unpadded base64url with no frame sent for it. A larger first write disables
early data for the whole connection rather than being truncated — the boundary
is inclusive. On HTTPUpgrade it carries no payload at all. The client still
waits for and validates the `101`: Xray's inbound handler can otherwise leave
application bytes coalesced behind the request in its buffered reader, causing
silent loss. A configured HTTPUpgrade `ed` therefore produces a warning.

One more asymmetry worth knowing before writing a path: HTTPUpgrade assigns the
path to Go's decoded `URL.Path`, which escapes `?`, `%`, `#`, whitespace and
non-ASCII bytes, so a configured `/ws?foo=bar` goes out as
`GET /ws%3Ffoo=bar`. When `?ed=` triggered a config rewrite the path was
already escaped once by `URL.String`, and HTTPUpgrade escapes that `%` again,
matching Xray's double-escaped wire form. WebSocket reparses a URI instead: it
keeps valid existing path escapes, sends a real raw query, and omits fragments.
The Xray server unescapes the transport path back, so both round-trip.

`heartbeatPeriod` is in seconds and applies to WebSocket only. It sends an
empty ping every period, the first one a full period after connect. Closing
writes a close frame with code 1000 and no reason before the socket closes.

#### The masqueraded browser version is redrawn on every start

A **known divergence**, and the one place the header block differs from Xray's.
Xray derives the Chrome, Firefox, Safari and curl versions in its `User-Agent`
and `Sec-CH-UA` headers from the calendar minus a random offset seeded with the
host CPU's identity, so one install reports the same versions until its
hardware changes. Ours draws that offset from the OS CSPRNG once per process,
which reproduces the spread across Xray's installs — on 2026-08-07, 55% of them
said Chrome 148 and the rest 145 to 147 — but not its stability per machine.

Within a process the versions never move: a client whose `User-Agent` changed
between connections would stand out more than one that never changes. What an
observer can see is a client whose claimed browser version changes across
restarts, which is ordinary for a browser on a 35-day release cadence and the
better side of the trade against a whole user base frozen on one version.

Setting a `User-Agent` in `headers` opts out of all of it. Any value other than
the magic keywords `chrome`, `firefox`, `safari`, `edge`, `curl` and `golang`
suppresses the entire masquerade block — about ten headers — which is Xray's
behavior too, and rarely what the author intended.

#### What these transports cannot be combined with

Xray refuses both pairings too, so refusing them here only moves the failure
earlier — the two land in different places, but neither reaches the wire:

- **REALITY is rejected** at parse time, matching Xray's "REALITY only supports
  RAW, XHTTP and gRPC for now", which Xray raises while building the stream
  config (`infra/conf/transport_internet.go:1989`). Plain TLS is the only
  security these transports take.
- **`xtls-rprx-vision` is rejected** when the stream is opened, not when the
  outbound is built: the pairing is a property of the dialer, so the profile
  parses and the outbound builds, and the guard the connect path runs before it
  dials is what refuses. Vision splices itself into the security connection's
  internals, and both transports wrap that connection rather than handing it
  back, so Vision has nothing to splice into. Xray refuses later still — it
  gets as far as a successful dial and then fails the flow with "XTLS only
  supports TLS and REALITY directly for now". That is a property of these two
  dialers, not a rule about transports in general — see the gRPC section below
  for the test Xray actually applies.

A `freedom` outbound is also refused these transports, and `grpc` with them.
Xray would dial the destination itself through them; here they are implemented
for VLESS only, and refusing is better than silently dialling plain TCP.

### XHTTP

`network: "xhttp"` and the legacy `"splithttp"` spelling select the same
client transport. Their settings blocks are `xhttpSettings` and
`splithttpSettings`; when both non-null blocks are present, Xray gives
`xhttpSettings` unconditional priority and so do we. The ignored legacy block
must still have JSON-decodable field types, but its mode and cross-field
semantics cannot affect the selected block. A missing or null selected block
is the ordinary zero-valued Xray config, not an error.

The configured security and ALPN list choose the wire engine before dialing:

| Stream security and configured ALPN | XHTTP engine |
| --- | --- |
| `none` | HTTP/1.1 |
| TLS with exactly `["http/1.1"]` | HTTP/1.1 |
| TLS with exactly `["h3"]` | HTTP/3 over QUIC v1 |
| TLS with any other list, including empty or multi-valued | HTTP/2 |
| REALITY | HTTP/2 |

This follows Xray's configured-list decision; it is not an ALPN fallback
ladder. In particular, the H3 branch requires TLS, advertises exactly `h3`, and
never retries over H2/H1. REALITY is supported on H2. Vision is not: as with
gRPC, XHTTP returns an HTTP stream wrapper rather than the TLS/REALITY
connection Vision needs to inspect directly, and xray-core refuses the same
shape later in its VLESS outbound.

`host` resolves the HTTP authority ahead of `tlsSettings.serverName` or
`realitySettings.serverName`, then the VLESS server address. The native client
path does not append the VLESS destination port; a port is sent only when it
was written explicitly in `host`. IPv6 authorities are bracketed and domain
names are normalized through IDNA. A `Host` entry inside `headers` is rejected
because it conflicts with the independent field. Other valid header names are
MIME-canonicalized as Xray's `http.Header.Add` does.

All three modes are active on HTTP/1.1, HTTP/2, and HTTP/3:

- `packet-up` opens one session downlink and sends numbered, bounded uplink
  requests. HTTP/1.1 waits for and drains each response before safely reusing
  that upload socket; H2/H3 may monitor bounded responses concurrently after
  the corresponding request body has uploaded.
- `stream-up` opens a separate session downlink and streaming uplink. H1 uses
  chunked transfer encoding; H2/H3 use streaming DATA. The upload response is
  drained in the background and participates in cancellation/error teardown.
- `stream-one` uses one full-duplex request with no session or sequence.

`mode: "auto"` becomes `packet-up` without REALITY and `stream-one` with
REALITY. `stream-up` remains available explicitly. The two split modes generate
one fresh logical-session ID per flow and reuse it across that flow's downlink
and uplink requests; `stream-one` has no session ID. Path, cookie, header, and
query placements, mandatory padding, sequence numbers, packet pacing, and
half-close/EOF behavior are all handled by the shared request composer.

The HTTP clients also match Go's transparent gzip policy. Stream requests and
H2/H3 packet requests add `Accept-Encoding: gzip` only when the caller did not
select another encoding or a non-empty Range and the method is not HEAD; an
explicit empty encoding has Go's same auto-gzip meaning. Responses are decoded
only when the transport added that header itself. H1/H2 accept case-insensitive
`Content-Encoding: gzip`, while H3 keeps quic-go's exact lowercase check. The
raw H1 packet uploader bypasses both injection and decoding, as Xray's direct
`Request.Write` path does.

The accepted `xhttpSettings` surface is:

- routing/request identity: `host`, `path`, `mode`, and `headers`;
- padding: `xPaddingBytes`, `xPaddingObfsMode`, `xPaddingKey`,
  `xPaddingHeader`, `xPaddingPlacement`, and `xPaddingMethod`;
- uplink metadata: `uplinkHTTPMethod`, `sessionIDPlacement`, `sessionIDKey`,
  `sessionIDTable`, `sessionIDLength`, `seqPlacement`, `seqKey`,
  `uplinkDataPlacement`, `uplinkDataKey`, and `uplinkChunkSize`;
- packet/stream controls: `noGRPCHeader`, `noSSEHeader`,
  `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `scMaxBufferedPosts`,
  `scStreamUpServerSecs`, and `serverMaxHeaderBytes`;
- `xmux`, with `maxConcurrency`, `maxConnections`, `cMaxReuseTimes`,
  `hMaxRequestTimes`, `hMaxReusableSecs`, and `hKeepAlivePeriod`.

An empty `sessionIDTable` selects Xray's lowercase UUID v4 fallback. A non-empty
table selects target-compatible custom IDs after Xray's ASCII, positive-length,
and entropy validation. The nine upstream aliases (`ALPHABET`, `Alphabet`,
`BASE36`, `Base62`, `HEX`, `alphabet`, `base36`, `hex`, and `number`) expand to
their exact alphabets; any other ASCII string is used literally, including
duplicate bytes. Equal length bounds are exact, while unequal bounds are drawn
from Xray's half-open `[from, to)` range after ordering. A valid table in an
unselected transport block remains inert, as it does in Xray.

Range fields accept a JSON integer or Xray's string form such as
`"100-1000"`; null scalar/range/xmux values retain Go's zero-value semantics.
`uplinkHTTPMethod` must be an HTTP token and `GET` is allowed only in
`packet-up`; cookie/header uplink-data placement is also packet-up-only.
`noSSEHeader` and `serverMaxHeaderBytes` are accepted but have no client-side
effect because they configure Xray's inbound response/listener. A null
`downloadSettings` is equivalent to absent; a populated effective value is
rejected because it requires a second independent transport stack. `extra`
follows Xray's one-level `SplitHTTPConfig.Build` replacement: its object (or a
zero-valued config for JSON null) replaces every outer field except `host`,
`path`, and `mode`, which always come from the outer object. A nested `extra`
is inert because Xray does not invoke `Build` recursively. The removed legacy
`scMaxConcurrentPosts` key is accepted with a compatibility warning and
ignored, matching current Xray; it is not reinterpreted as the server-only
`scMaxBufferedPosts` setting.

An XHTTP share link must carry server-specific settings through `extra`.
In particular, `xPaddingBytes` contributes to the peer's request-size budget:
omitting it selects the client default `100-1000`, which is not compatible
with an inbound constrained to an exact smaller value such as `64`. The peer
can close the logical stream before returning target bytes even though
REALITY and HTTP/2 both opened successfully. Importers therefore preserve
`extra` exactly; they cannot infer a non-default inbound padding range from
the address, path, or security fields. Producers of VLESS URLs are responsible
for including the effective non-default value.

The xmux scheduler is implemented rather than merely parsed. Its random ranges
bound logical concurrency, client-slot count, connection reuse, HTTP request
count, and reusable lifetime. Enabling positive `maxConnections` together with
positive `maxConcurrency` is rejected as Xray rejects it. An explicit default
settings block (`"xhttpSettings": {}`) uses v26.7.28's three-client-slot
`maxConnections` pool. If both settings pointers are absent or null, Xray
skips `SplitHTTPConfig.Build` and leaves XMUX zero-valued; xray-rust preserves
that distinction. H2/H3 keep capacity-aware reusable connection pools; H1
reuses only packet-upload sockets whose response was fully consumed. The
scheduler is shared by every cached selection of one outbound, including TCP
and UDP sessions, rather than being cloned per flow.

#### HTTP/3 phase-one QUIC surface

The H3 path uses a protected UDP socket and the same resolved-candidate Happy
Eyeballs policy as the other outbounds. Its stock TLS 1.3 config ignores
`tlsSettings.fingerprint` and the configured ALPN payload after the exact
`["h3"]` branch is selected, then advertises exactly `h3`; that is the same
separation Xray makes between its QUIC TLS path and uTLS TCP callback.

`streamSettings.finalmask.quicParams` is parsed for every stream but applied
only to H3. The phase-one engine implements QUIC v1, Reno, the default/standard
BBR selection, initial receive windows, equal explicit maximum windows,
`maxIdleTimeout`, `keepAlivePeriod`, `disablePathMTUDiscovery`, and
`maxIncomingStreams`. With no overrides it uses Xray's 2 MiB stream and 3 MiB
connection initial windows, a 300-second idle timeout, and a ten-second H3
keepalive.

Receive-window growth is deliberately not claimed: Quinn holds those windows
static, while quic-go adapts them toward 6 MiB per stream and 15 MiB per
connection. Standard BBR is likewise a Quinn-BBR approximation with Xray's
initial congestion window, not quic-go's exact controller. Distinct
`maxStreamReceiveWindow`/`maxConnectionReceiveWindow` values, QUIC v2 through
the transport API, conservative/aggressive BBR profiles, Brutal and
force-Brutal, non-empty `udpHop`, and `debug: true` fail closed before opening
a socket. Nonempty `finalmask.tcp` or `finalmask.udp` masks also remain
unsupported. H3 has hermetic mode, wire, pool, lifecycle, TLS, and protected
UDP tests, and the ignored live Xray-core `packet-up`, `stream-up`, and
`stream-one` interoperability cases pass. The current pool conservatively
allows one active HTTP request per QUIC connection and opens another
connection for concurrent work. That functional evidence does not establish
performance parity; release throughput plus controlled RTT/loss runs remain
required for the static-window, pool, and Quinn-BBR differences.

### gRPC

`network: "grpc"` carries VLESS inside `Hunk` messages on one bidirectional
HTTP/2 POST, and it is shaped unlike the other two transports because of it:
ws and httpupgrade take a socket and give back a stream, while every gRPC flow
to one server becomes one more stream on a *shared* HTTP/2 connection. The
first flow opens that connection and it is held between flows, as Xray holds
its `*grpc.ClientConn` in `globalDialerMap`.

Upstream marks the transport deprecated — building a `grpc` stream prints a
non-removal deprecation warning pointing at XHTTP stream-up H2
(`Xray-core/infra/conf/transport_internet.go:1003-1005`) — so it still works
and still interoperates, but it is not where xray-core is going. We do not
print that warning.

`grpcSettings` accepts eight keys and no others. There is no `path`, no `host`,
no `headers` and no `?ed=`, because `GRPCConfig` has none of them
(`Xray-core/infra/conf/grpc.go:8-17`). Their spelling is inconsistent, and the
inconsistency is Xray's: five are snake_case, two are camelCase, and one is
neither.

| Key | Type | Meaning |
| --- | --- | --- |
| `serviceName` | string | The `:path`, in one of two dialects; see below |
| `multiMode` | bool | Selects the `TunMulti` RPC and the `MultiHunk` message |
| `authority` | string | `:authority` outright, ahead of the whole chain below |
| `user_agent` | string | `chrome`, `firefox`, `edge`, `golang`, or a literal |
| `idle_timeout` | int32 | Keepalive ping interval, in seconds |
| `health_check_timeout` | int32 | How long a ping may go unacknowledged, in seconds |
| `permit_without_stream` | bool | Ping a connection with no call open on it |
| `initial_windows_size` | int32 | `SETTINGS_INITIAL_WINDOW_SIZE` for the connection |

**A camelCase `idleTimeout` is rejected**, and that is a deliberate refusal of
something xray-core tolerates. Go matches on the struct tag, so upstream reads
`idleTimeout` as an unknown key and drops it in silence — the profile loads and
dials with no keepalive at all. Accepting it here would let a config work that
does nothing against a real server. The three `int32` values are clamped
negative-to-zero as `GRPCConfig.Build` clamps them, and a value past `i32::MAX`
is rejected, as Go's own decoder rejects it.

`user_agent` follows Xray's switch (`transport/internet/grpc/dial.go:193-205`).
An absent or empty value is *not* the empty case: it shares an arm with
`chrome` and sends a Chrome user agent, so the default gRPC dial claims to be a
browser. `golang` is the one value that empties the header, and the header is
still sent, because grpc-go appends it unconditionally. Anything else is a
literal and goes out verbatim — `safari` and `curl` included, which are
masquerade keywords the gRPC table does not know. The `chrome`, `firefox` and
`edge` strings come from the same table the WebSocket masquerade uses, so the
redrawn-browser-version divergence described above applies to them too. Xray's
own comment is worth repeating: a browser UA on gRPC is **not recommended**,
because browsers cannot initiate gRPC. We match the behaviour anyway. A literal
that no HTTP header can carry is the one value refused rather than sent; see
[below](#a-user_agent-no-http-header-can-carry-is-refused-at-startup).

#### `serviceName` has two dialects

The leading `/` picks between them
(`Xray-core/transport/internet/grpc/config.go:17-59`).

A name **without** a leading `/` is an old-school service name. It is escaped
whole with Go's `url.PathEscape`, so an inner `/` becomes `%2F` and the result
is a single path segment; the stream name is then `Tun`, or `TunMulti` under
`multiMode`. `xray.grpc` dials `/xray.grpc/Tun`.

**The default is the empty string, and it dials `//Tun`** — an empty service
name between two slashes, not a single slash. A `grpcSettings` block that is
absent altogether resolves the same way, because Xray falls through to a
zero-valued transport config rather than treating the block as mandatory. An
Xray inbound with no `serviceName` registers the same empty name, so the two
ends agree; a server expecting `/Tun` is a different configuration.

A name **with** a leading `/` is a custom path. Everything between the first
and the last `/` is the service name, escaped segment by segment so its inner
slashes survive as separators, and the last segment is the stream name. That
last segment may carry a `|`: the part before it is the `Tun` name and the part
after it the `TunMulti` name, so `/a/b/Tun|TunMulti` dials `/a/b/Tun` normally
and `/a/b/TunMulti` under `multiMode`. With no `|`, the one part is used for
whichever RPC the mode selects. Upstream calls the one-part form the client
spelling and the two-part form the server spelling; the client honours both.

#### `multiMode` selects a different message

Not merely a different stream name. `Tun` streams `Hunk`, whose `data` is a
singular `bytes`; `TunMulti` streams `MultiHunk`, whose `data` is
`repeated bytes` (`transport/internet/grpc/encoding/stream.proto:6-17`). One
multi-mode message therefore carries a whole batch of payload chunks
(`encoding/multiconn.go:115-134` packs one per buffer), and a `Hunk` reader
handed one of those keeps only the last element — silently, with no error and
nothing logged. Reaching that state takes a particular `serviceName` spelling,
and only that one; see below.

**Only the client reads the flag.** `MultiMode` is consulted on the dial path
(`transport/internet/grpc/dial.go:59`) and nowhere else in the transport. The
listener never looks at it: it registers *both* RPCs on one service descriptor
whatever its own setting (`hub.go:127-128`,
`encoding/customSeviceName.go:9-30,57-60`), and the two stream names it
registers them under come from `serviceName` (`config.go:36-59`). So for any
`serviceName` without a leading `/` — the default empty one included, where the
names are the constants `Tun` and `TunMulti` — a client in either mode reaches
the handler that matches it, and the server's own `multiMode` is inert. Our
`multiMode: true` bulk interop scenario runs against an xray-core inbound whose
only gRPC setting is a `serviceName`.

The one spelling that constrains the client is a **one-part custom path** such
as `/a/b/Name`. There `getTunStreamName` and `getTunMultiStreamName` both
return `Name`, the descriptor carries that name twice, and grpc-go keeps the
last entry when it builds its stream map
(`google.golang.org/grpc@v1.81.0/server.go:788-791`), so `TunMulti` is the
handler installed. A single-mode client then talks `Hunk` to a `MultiHunk`
handler: its own writes survive, because one `bytes` decodes as a one-element
`repeated bytes`, but a reply that batched several buffers into one message
loses all but the last. Use the two-part `/a/b/Tun|TunMulti` form, or no
leading `/` at all, and the mode stays a client-side choice.

#### The `:authority` chain is not the `Host` chain

Xray resolves `:authority` as `grpcSettings.authority`, else
`tlsSettings.serverName`, else the destination address **but only when it is a
domain and REALITY is not configured**, else the empty string
(`transport/internet/grpc/dial.go:159-167`). Under REALITY the third branch is
skipped rather than answered with `realitySettings.serverName`, and the second
has nothing to read either, because `tls.ConfigFromStreamSettings` returns nil
for a REALITY stream.

**The empty string is not an omitted header.** grpc-go then walks its own
precedence to the dial target, which Xray builds as `passthrough:///host:port`,
so what reaches the wire is the destination *with its port*:
`example.com:443`, `198.51.100.7:443`, `[2001:db8::1]:443`. That is the default
under REALITY and under any configuration whose destination is an IP literal,
rather than a corner case. We resolve the same chain, once, when the outbound
is built rather than on every dial.

#### REALITY yes, `xtls-rprx-vision` no

REALITY is accepted with gRPC, matching Xray's "REALITY only supports RAW,
XHTTP and gRPC for now" — gRPC is on that list where ws and httpupgrade are
not.

`xtls-rprx-vision` is rejected, and both ends refuse it in different places —
on neither end at config time. Here the profile parses and the outbound builds;
what refuses is the guard the connect path runs before it dials, because this
client admits Vision only on the raw transport under `tls` or `reality`. On
xray-core the transport dial *succeeds* and the refusal comes later still, from
the VLESS outbound's `Process`, which accepts exactly two shapes
(`proxy/vless/outbound/outbound.go:268-285`): a `*encryption.CommonConn` —
VLESS `encryption` is on — which is tested first and does not care what the
network is; or, failing that, an `iConn` that is a `*tls.Conn`, `*tls.UConn`
or `*reality.UConn`. Everything else gets "XTLS only supports TLS and REALITY
directly for now."

Neither shape is reachable over gRPC here. `conn` becomes a
`*encryption.CommonConn` whenever `h.encryption != nil`
(`outbound.go:211-216`), and this client accepts `encryption: "none"` alone,
so the first branch is out for every profile we parse. The second asks whether
the transport dialer handed the security conn straight back as `iConn`, which
is a property of the dialer and not of `network` or of `security`: the gRPC
dialer feeds that conn to grpc's `ContextDialer`
(`transport/internet/grpc/dial.go:138-151`) and returns a `HunkConn` or
`MultiHunkConn` wrapper instead (`dial.go:65,74`). Adding `security: tls` does
not change that; the wrapper is what the dialer returns either way, and ws,
httpupgrade and xhttp wrap their TLS conn the same way.

Resist restating that as a list of networks; every such shortcut written here
so far has been wrong. mKCP carries Vision, because its dialer ends
`iConn = tls.Client(iConn, ...); return iConn`
(`transport/internet/kcp/dialer.go:99-103`), and RAW stops carrying it as soon
as a `tcpSettings.header.type` authenticator wraps the conn on the way out
(`transport/internet/tcp/dialer.go:105-115`). `docs/benchmarks.md` records the
four configurations this was measured with against the vendored 26.5.9 binary.

#### Keepalive is three knobs behind one gate

`idle_timeout`, `health_check_timeout` and `permit_without_stream` are one
setting in three parts, and the gate over them is a **three-way OR** rather
than a check on the durations: keepalive is attached when any of
`idle_timeout > 0`, `health_check_timeout > 0`, or `permit_without_stream`
holds (`dial.go:169-175`).

So `permit_without_stream: true` on its own turns pings on, with both durations
at zero — and zero is not "no pings". grpc-go's `WithKeepaliveParams` raises a
zero or small interval to its ten-second floor, and the transport substitutes
twenty seconds for a zero timeout, so that config pings every ten seconds and
gives up on a ping unanswered for twenty.

`permit_without_stream` is then read a second time for an unrelated decision:
with it false, the ping loop goes **dormant** while no call is open on the
connection. Because this transport holds its connection between flows, "no call
open" is the ordinary state here and not an edge case — `idle_timeout` on its
own therefore turns keepalive on and leaves it asleep for as long as no flow is
using the connection, exactly as grpc-go does. A flow arriving on a dormant
connection takes a ping out alongside its first request.

This keepalive field is separate from grpc-go's `ClientConn` idleness manager.
Xray does not override that manager's 30-minute default, so the pooled HTTP/2
connection here is also retired after thirty minutes with no open call. The
timer starts when the last call closes; retirement drops the pool's reusable
handle without aborting a stream that was already opened, and the next flow
performs a fresh bounded dial.

`initial_windows_size` reaches the wire only *above* grpc-go's own default of
65535. At or below it, no `SETTINGS_INITIAL_WINDOW_SIZE` entry is written and
the connection runs on the default — which is also what grpc-go does, so the
opening bytes match.

#### An authority `http::uri::Authority` cannot hold is refused

**One class of configuration xray-core dials and this client does not.** The
`h2` crate reads `:authority` out of the request's `http::Uri` and nowhere
else, and a `Uri`'s authority *is* an `http::uri::Authority`, so a value that
type rejects is one no request can carry. Two whole classes fall in there and
grpc-go sends both: any byte above `0x7f`, which makes an
internationalized name such as `例え.jp` unsendable, and `%` anywhere in a host,
which rules out grpc-go's own percent-escaped `host:port` fallback for such a
destination. Both were checked on the wire against grpc-go v1.81.0.

Such a name reaches the chain either as `grpcSettings.authority` or as the
destination address a later branch derives the authority from, and the refusal
happens when the outbound is built. Which of two messages you see depends on
whose value it was:

```text
grpcSettings.authority `例え.jp` is not a valid HTTP/2 authority
the gRPC :authority derived from settings.vnext[0].address `例え.jp` is not a valid HTTP/2 authority
```

The first is a string in the profile, which can be edited. The second is a
value derived on the profile's behalf, so the message names the key that
produced it rather than a key the config does not contain; the other two keys
it can name are `streamSettings.tlsSettings.serverName` and the composed
`settings.vnext[0].address and settings.vnext[0].port`.

Writing the IDNA A-label (`xn--r8jz45g.jp`) instead is accepted, and is the
workaround. Nothing here converts one for you: no IDNA implementation is in
this workspace's dependency graph, and converting silently would put an
authority on the wire that xray-core does not send.

#### A `user_agent` no HTTP header can carry is refused at startup

**This one refuses a configuration xray-core loads, and loses nothing by it.**
A literal `user_agent` holding a control character — a `\r`, a `\n`, a NUL, a
DEL — is rejected when the outbound is built:

```text
grpcSettings.user_agent "grpc-go/1.81.0\r\nx-injected: 1" is not a valid HTTP header value
```

xray-core accepts the same profile and dials with it. What it does *not* do is
carry a single byte of traffic: grpc-go's client never validates the string, so
it puts it on the wire verbatim, and the gRPC server at the far end then resets
every stream with `PROTOCOL_ERROR` before the handler sees it. The connection
is established and cached; each flow opened on it dies. So the profile is dead
upstream too — the difference is only that upstream reports it once per flow,
forever, with a message naming neither the key nor the character.

The two rules turn out to be the same rule. `http::HeaderValue` accepts a byte
when `b >= 32 && b != 127 || b == b'\t'`; Go's `httpguts.ValidHeaderFieldValue`
accepts one when it is not a control byte other than space or tab, which is the
same set. Both therefore accept a tab, a leading or trailing space, and any
byte above `0x7f` — so a non-ASCII user agent such as `Mozilla/5.0 (例え)` is
fine here, unlike a non-ASCII *authority*. Sixteen values were measured against
a real grpc-go v1.81.0 client and server, one dial each, and the results are
committed in `tests/fixtures/grpc/user_agent_validity.json`.

The residual gap is narrower than that rule. RFC 9113 §8.2.1 forbids only NUL,
CR and LF in a field value; Go rejects DEL and the rest of C0 as well. A gRPC
server that is not grpc-go could therefore accept a `\x7f` this client refuses.
An Xray gRPC inbound is grpc-go, so in practice there is no such peer.

Note that the injected-looking case is not header injection. HTTP/2 header
blocks are length-prefixed, so `\r\n` inside a value stays inside that value and
no second header appears; what kills the stream is the peer validating the
field, not parsing a forged one.

### TLS ClientHello shaping

`security: "tls"` sends a uTLS-shaped ClientHello, as Xray-core does on every
TLS connection. `tlsSettings.fingerprint` selects the shape from the same 61
names Xray accepts. An absent or empty value means `chrome`, matching Xray's
`GetFingerprint("")`, so shaping is the default rather than an opt-in; an
unknown name is rejected at parse time with a JSON path and the offending
value. Unlike `realitySettings.fingerprint`, no X25519 key share is required,
so eleven of the fourteen names REALITY rejects are usable here; the other
three — `hello360_7_5` and its aliases `360` and `hello360_auto`, one profile
under three names — are refused for a separate reason given below.

Those 61 are the union of the three maps Xray's `GetFingerprint` consults --
`PresetFingerprints`, `ModernFingerprints`, `OtherFingerprints` -- less
`unsafe`, described below, and `hellogolang`.

That second exclusion is a **known divergence**, and the one place this set is
narrower than Xray's: `tlsSettings.fingerprint: "hellogolang"` parses on
xray-core and is rejected here. It is not a browser shape. In uTLS the name
means *emit Go's own `crypto/tls` ClientHello and apply no shaping at all*, so
the nearest thing this implementation can send is `unsafe` -- the same intent
through a different TLS stack. The divergence is confined to plain TLS; on the
REALITY path we and Xray agree, because Xray rejects `hellogolang` and `unsafe`
alike there. Tracked in
`docs/superpowers/plans/2026-08-07-hellogolang-divergence.md`.

The set is otherwise deliberately not a superset of Xray's: uTLS itself
knows further `ClientHelloID`s that Xray has never mapped, and accepting one
would let a profile parse here and then fail on xray-core with
`unknown "fingerprint"`, which is a break the user only discovers after moving
the profile. Nothing is given up by matching Xray exactly, because every such
name is a shape an accepted name already reaches.

`fingerprint: "unsafe"` is Xray's own escape hatch, spelled the same way: it
disables shaping and sends the TLS stack's own ClientHello.

`tlsSettings.alpn` is an array of strings; a non-string entry is rejected with
an indexed path. Where the configured list lands follows Xray rather than
approximating it: uTLS takes ALPN from the fingerprint profile and overwrites
the configured list, so on this transport the configured list reaches the
ClientHello only when it is exactly `["http/1.1"]`, the one case Xray rebuilds
the hello for. Every other list is ignored, leaving whatever ALPN the profile
itself declares — for some profiles, none at all. With `fingerprint: "unsafe"`
there is no profile, so a nonempty configured list is sent as-is.

A shaped connection runs on the aws-lc-rs crypto backend rather than ring, and
offers the post-quantum key share its profile plans — X25519MLKEM768 for
`chrome`, none at all for a TLS-1.2-era profile. That is what matching a
current browser requires, but it is a real change both in what goes on the wire
and in which backend performs the handshake. Session resumption is also
disabled while shaping, because a resumed handshake emits a second ClientHello
carrying `pre_shared_key`, an extension the fingerprint never described.
`fingerprint: "unsafe"` keeps the previous ring path, resumption included.

Fourteen of the 61 names are TLS-1.2-era, which is exactly the set REALITY
rejects. Eleven of those are shaped but not byte-exact; the other three, the
`360` aliases refused below, build no ClientHello at all. The uTLS hello behind
the eleven declares no `supported_versions` extension, while the TLS stack
emits that extension on every ClientHello it builds — a TLS-1.2-only
configuration included, where it carries just `0x0303` — and nothing in the
shaping API can suppress it. The extension order is pinned so uTLS's own order
survives as an exact prefix and the one extra extension sits last. The
remaining names declare the extension themselves, so nothing is appended to
their hellos.

Those hellos go out under a TLS-1.2-only configuration, as uTLS's do: uTLS
reads the missing extension as a TLS 1.0–1.2 range and caps its own config
there. Offering TLS 1.3 behind a hello that never mentions it cannot work —
the server answers with TLS 1.2, its ServerHello carries the RFC 8446 §4.1.3
downgrade sentinel, and the client is obliged to treat that as an attack.

`hello360_7_5` — with its aliases `360` and `hello360_auto` — is **refused
before the handshake** rather than dialled. Its twenty cipher suites are CBC,
RC4 or 3DES, not an AEAD among them, and this client implements none of them,
so whichever the server picks is one it cannot speak. xray-core completes that
handshake, because Go still ships the legacy suites; here the fingerprint
simply cannot be offered on plain TLS. The refusal happens where the rustls
config is built, which is on each connection attempt rather than at parse time:
the TCP socket is still opened, but no ClientHello is sent, and the error names
the fingerprint and the reason instead of arriving a round trip later as a TLS
alert. It stays refused on REALITY too, as it always was.

An IP-literal `serverName` is supported. As in uTLS, the SNI extension is
elided and the rest of the shape shifts to match, rather than the handshake
failing.

#### What `random` and `randomized` resolve to

`fingerprint: "random"` matches Xray: one of the eleven names in Xray's
`ModernFingerprints` table is drawn from the OS CSPRNG the first time the name
is used, and that draw stands for the rest of the process. Two installs
therefore send different hellos, while a single install never changes its hello
between connections — a client whose fingerprint moves from one connection to
the next is easier to pick out than one that never moves, so both halves
matter. `randomized` behaves the same way, from its own independent draw.

`randomized` is where we diverge from Xray, and a user picking it should know
which behaviour they get. Xray hands `randomized` to uTLS's randomized-spec
generator, which synthesizes a novel ClientHello from a fresh PRNG seed and a
weight table. We have no port of that generator, so we draw a **real browser
fingerprint** instead of synthesizing one. The practical difference: a
synthesized hello is unique to the install but belongs to no real client — its
JA3 is one no browser produces — whereas a drawn one is shared with every real
user of that browser version and with every Xray user whose `random` landed on
the same name. Against a detector asking "is this a shape a browser sends", the
drawn fingerprint is strictly better; against one asking "have I seen this exact
shape before", eleven buckets shared with the Xray population is the crowd we
would rather be in than a bucket of one.

`randomizednoalpn` is the one name still pinned to a fixed shape. Every entry in
`ModernFingerprints` carries ALPN, so resolving it by the same draw would add
the extension the name exists to suppress; the honest fix for it is the
generator port, not an alias. `hellorandomized`, `hellorandomizedalpn` and
`hellorandomizednoalpn` are likewise fixed. In Xray those three come from the
`OtherFingerprints` table with no seed pinned, which makes uTLS synthesize a
*fresh* spec on every connection — a shape that changes per connection, which is
worse than a fixed one for the reason above. Ours is a recorded snapshot of one
such spec.

#### ECH GREASE

Six of the profiles carry an `encrypted_client_hello` extension. It is GREASE —
a decoy outer hello, not real Encrypted Client Hello — because that is what the
browsers being imitated send by default, and omitting it would itself be the
tell. We build the whole structure: outer type, HPKE cipher suite, config id, a
real X25519 encapsulated key, and a random payload of the right length. The
config id, key and payload are drawn per connection, as uTLS draws them.

uTLS varies two further fields per connection, and we match one of them:

| Field | uTLS | xray-rust |
| --- | --- | --- |
| HPKE AEAD, Firefox profiles | draws AES-128-GCM or ChaCha20-Poly1305 | drawn per connection |
| HPKE AEAD, Chrome profiles | AES-128-GCM only (`BoringGREASEECH` declares one suite) | fixed, matching |
| Payload length, Firefox | 223, fixed | fixed, matching |
| Payload length, Chrome | draws 128, 160, 192 or 224 | **pinned to 128** |

The last row is a known divergence. Real Chrome spreads its ClientHello across
four lengths — and because the ML-KEM key share already pushes the hello past
BoringSSL's 512-byte padding target, that spread is visible in the total hello
length rather than absorbed by padding. We send the shortest every time, so a
censor watching several connections from one client sees a length distribution
Chrome does not produce.

It is pinned because both the raw-hello and shape fixtures record one length per
fingerprint, and the Go oracle that generates them runs under a zeroed
`crypto/rand`, which always picks the first candidate. Drawing per connection
would fail those byte-exact comparisons three runs in four. Lifting it means
teaching `clienthello_shape.go` to force a candidate index and committing a
fixture per candidate, so the comparison can assert the hello matches one of the
four uTLS can produce rather than dropping to a weaker check.

### Happy Eyeballs socket option

`streamSettings.sockopt` currently supports only the Xray-compatible
`happyEyeballs` object:

```json
{
  "streamSettings": {
    "network": "tcp",
    "sockopt": {
      "happyEyeballs": {
        "prioritizeIPv6": false,
        "interleave": 1,
        "tryDelayMs": 250,
        "maxConcurrentTry": 4
      }
    }
  }
}
```

The modeled Xray defaults are `prioritizeIPv6: false`, `interleave: 1`,
`tryDelayMs: 0`, and `maxConcurrentTry: 4`. An absent object, zero
`tryDelayMs`, or zero `maxConcurrentTry` disables the candidate race; an empty
object is therefore disabled by default. `interleave: 0` is not a disable
sentinel: it tries the preferred address family in resolver order before the
alternate family. Positive `interleave` values alternate stable chunks of that
size, and `prioritizeIPv6: true` makes IPv6 the preferred family.

When enabled and DNS supplies at least two socket-address candidates, the first
raw TCP attempt starts immediately. Pending attempts are staggered by
`tryDelayMs`, a fast TCP failure accelerates the next candidate, and no more
than `maxConcurrentTry` connects are active together. The race covers Freedom
and the TCP carrier used by VLESS, including VLESS UDP/XUDP. For TLS and
REALITY, only raw TCP is raced; exactly one handshake is performed on the
winning socket. Every launched socket passes through the configured platform
protector before connect. Protection failure is fatal, and success, failure,
caller cancellation, or dropping the dial future drops all losing attempts;
the scheduler does not leave detached connection tasks running.

## Routing

Supported routing configuration:

- `domainStrategy`: `AsIs` or `IPIfNonMatch`;
- rule `type`: `field`;
- selectors: `inboundTag`, `domain`/`domains`, `ip`, `network`, and `port`;
- destination: exactly one of `outboundTag` or `balancerTag`;
- `routing.balancers` with `tag`, prefix-based `selector`, optional
  `fallbackTag`, and `random` (the default), `roundRobin`, `leastPing`, or the
  bounded `leastLoad` strategy.

`network` accepts Xray-compatible `tcp`/`udp` strings or arrays, including a
comma-separated string. `port` accepts a number or comma/range string over
`0..=65535`. Rules are evaluated in declaration order, and every populated
selector field inside one rule is ANDed; alternatives belong in arrays/ranges
or separate ordered rules.

Balancer selectors use Xray's prefix semantics and accept either one string or
an array. Tagged outbound candidates are deduplicated through the same
first-tag index used by direct routing and sorted lexicographically before a
strategy sees them. An empty prefix selects every tagged outbound. At most 256
balancers and 4,096 selector prefixes are accepted per configuration.

`random` selects a candidate independently for each new flow. `roundRobin`
uses one atomic cursor shared by every router backed by the core's factory.
Both treat unknown health as eligible and skip candidates known to be
unhealthy. `leastPing` requires a successful observation and deterministically
chooses the lowest delay, using lexicographic candidate order to break ties.
`leastLoad` retains the latest 16 probe outcomes per outbound and orders healthy
candidates by RTT deviation, average RTT, failures, sample count, and tag. It
accepts `expected` from 0 through 16, `maxRTT` up to the 5-second probe timeout,
`tolerance` from 0 through 1, at most 16 positive duration `baselines`, and at
most 64 positive literal-substring `costs`. The cost multiplier is applied to
the squared deviation, which is ordering-equivalent to Xray's
`deviation * sqrt(cost)`. New flows are randomly distributed inside the
resulting bounded top-N. Regex costs and the undocumented zero-value automatic
cost coefficient fail closed.

If no eligible candidate remains, `fallbackTag` is used; without a valid
fallback the route fails closed. The core API can install or clear a validated
per-group override atomically. An explicit override is authoritative even when
that member is currently unhealthy. It affects only new flows, while already
opened flows and lazy handler/transport pools remain intact. Non-empty strategy
`settings` remain unsupported outside `leastLoad`.

ABI 1.4 can reparse and atomically publish a scoped top-level `routing` object
for new flows. Ordered rules, `domainStrategy`, and their compiled
`geosite`/`geoip` matchers change together as one revision; a selection that
awaits an `IPIfNonMatch` lookup retains its original revision. Direct targets
must name loaded outbounds. Balancer targets may be reused only with the exact
loaded balancer definitions because group membership, strategies, fallback
edges, and handler pools remain part of the immutable graph. Other top-level
config fields and full topology replacement require a new core handle.

## Observatory and outbound health

The top-level `observatory` object accepts Xray's `subjectSelector`, `probeURL`,
`probeInterval`, and `enableConcurrency` fields. `subjectSelector` is an array
of outbound-tag prefixes; matching tagged leaves are deduplicated and sorted.
An empty selector array disables the observer. An omitted or empty `probeURL`
uses Xray's `https://www.google.com/generate_204` default. Only safe HTTP and
HTTPS URLs accepted by the startup-probe parser are allowed.

`probeInterval` uses Xray/Go duration syntax such as `10s`, `1m30s`, or
`1.5s`. Missing, empty, or `0s` selects the 10-second Xray default; explicit
values are bounded to 1 second through 24 hours. Each probe has a fixed
5-second timeout and considers HTTP 2xx/3xx healthy. Sequential mode sleeps
for the interval after each outbound, matching Xray's pacing. Concurrent mode
probes at most four outbounds at once, then sleeps for the interval after the
full round.

The observer starts only after the core and any configured startup probe have
started successfully. It dials each leaf directly by tag, so routing rules and
selector state cannot redirect its measurement. Stop cancels the observer with
the rest of the core runtime. Rust health snapshots expose unknown/healthy/
unhealthy state, delay, last-try and last-success timestamps, consecutive
failure count, and a typed redacted failure category; raw URLs and transport
error strings are not retained.

Domain matchers:

- bare string or `keyword:value`;
- `domain:value`, `full:value`, `regexp:value`;
- `geosite:code` and `geosite:code@attribute`;
- `ext:file.dat:code` and `ext-domain:file.dat:code`.

IP matchers:

- IPv4/IPv6 address or CIDR;
- `geoip:private`;
- `geoip:code`;
- `ext:file.dat:code` and `ext-ip:file.dat:code`;
- the supported inverse `!` forms.

IP matchers are compiled once at load time into merged address-range sets, so a
rule's lookup cost is logarithmic in the number of distinct ranges and does not
grow with the size of a `geoip:` list. Matching follows Xray-core's
`HeuristicIPMatcher`:

- an IPv4-mapped IPv6 target (`::ffff:a.b.c.d`) is unmapped and matched as
  IPv4, so it hits IPv4 CIDR and `geoip:private` rules;
- a positive matcher matches when the target is inside any of its networks; an
  inverse matcher matches when the target is outside every negated network
  **of the same address family** — a rule whose negated networks are all IPv4
  never matches an IPv6 target, and vice versa;
- a CIDR prefix longer than the address family allows (for example `/33` for
  IPv4) is rejected at load time rather than clamped.

Balancers and non-`field` rules are unsupported. If no rule matches, the first
outbound tag is used as the default.

## DNS

Global `dns.queryStrategy` supports Xray-compatible `UseIP` (the default),
`UseIPv4`, and `UseIPv6` spellings and aliases. It controls configured wire
queries, destination-facing static `dns.hosts` results, and the final
destination resolver used when no `dns.servers` are configured. Bootstrap
resolution intentionally keeps every pinned/system candidate regardless of
this policy, matching Xray's separation
between its DNS feature and the default system carrier dialer. A destination
static mapping that contains no address from the selected family returns
terminal NODATA instead of leaking to another resolver. IPv4-mapped IPv6 values
count as IPv4 at the TCP dial boundary and are discarded when received in an
AAAA answer. `UseSystem` is rejected until the universal core has an injectable
platform route-capability provider; it is not silently treated as `UseIP`.

`dns.servers` accepts at most eight string or object entries. String shorthand
accepts IP addresses, socket addresses, domain names with an optional nonzero
port, `tcp://host[:port]` / `tcp+local://host[:port]`, routed
`tls://host[:port]`, and `https://host[:port][/path][?query]` /
`https+local://host[:port][/path][?query]`, plus provider-local
`quic+local://host[:port]`. Schemes are case-insensitive, TCP defaults to port
`53`, TLS and DoQ to `853`, and HTTPS to `443`; bracketed IPv6
literals are supported, and these transports are used from the first query
rather than as a truncation retry. `tcp://`, `tls://`, and `https://` enter
normal outbound routing; the `+local` forms bypass routing and open protected
direct sockets. DoT and DoH wrap the selected carrier in certificate-verified
TLS and derive SNI/verification identity from the configured domain or IP
literal. DoH negotiates HTTP/2 and sends bounded RFC 8484 POST messages; an
omitted path becomes `/`, while a query-only suffix is attached to that path.
DoQ uses a protected provider-local UDP socket, QUIC v1, exact ALPN `doq`, and
one RFC 9250 bidirectional stream per connection and query. Routed DoQ and DoQ
connection pooling are not implemented. TCP/TLS/DoQ URLs are authority-only.
HTTPS permits an ASCII path/query but rejects
userinfo, fragments, backslashes, whitespace/control characters, scoped or
unbracketed IPv6, and zero ports. In an object entry, the port embedded in the
stream URI is authoritative and the separate `port` field is ignored after validation,
matching Xray-core's effective behavior. The Xray object subset requires `address`, supports
`port` (`0` or omission means `53`), `domains`, `skipFallback`, per-server
`queryStrategy`, `finalQuery`, `tag`, and `timeoutMs`. `domains` may be an array or one
comma-separated string and supports bare keyword, `keyword:`, `domain:`,
`full:`, `regexp:`, `dotless:`, `geosite:`, `ext:`, and `ext-domain:` rules.
Top-level `disableFallback`, `disableFallbackIfMatch`, `disableCache`,
`serveStale`, and `serveExpiredTTL` are also supported. `serveStale: true`
requires caching plus an explicit `serveExpiredTTL` from 1 through 86400
seconds. Xray treats zero as an unbounded stale lifetime; this mobile-oriented
core rejects that value rather than silently retaining records forever.
Per-server cache/stale overrides remain unsupported because the current cache
is owned once per Core rather than once per upstream. Special
`localhost`/`fakedns` clients, routed DoQ, `clientIp`, and parallel queries are rejected until their
runtime semantics exist; they are not silently approximated as classic UDP.

Object servers support Xray's `expectedIPs`, legacy `expectIPs` alias, and
`unexpectedIPs`. Each accepts an array, one comma-separated string, or `null`.
`expectedIPs` wins when nonempty; otherwise `expectIPs` is used. Rules support
IP/CIDR, `geoip:`, `ext:`, `ext-ip:`, repeated `!`, and the `*` soft-preference
marker. As in Xray DNS, GeoIP asset `reverse_match` metadata is ignored and
`geoip:private` is loaded from the configured `geoip.dat` rather than replaced
with a built-in approximation.

Managed selection follows Xray: every matching object entry is tried in
configuration order, followed by unmatched entries in configuration order.
`skipFallback` removes an entry only from the latter phase;
`disableFallback` always removes that phase and `disableFallbackIfMatch`
removes it after any match. `finalQuery` truncates the plan where encountered.
If these rules otherwise produce an empty plan, the first configured entry is
still tried. Duplicate endpoints in separate policy objects remain separate
managed clients. A per-server family policy intersects the global policy and
cannot widen it.

Top-level `dns.tag` is the default synthetic inbound tag for configured DNS
clients. A nonempty object-server `tag` overrides it; an omitted, `null`, or
empty object value inherits the global value. If the global value is omitted,
`null`, or empty, the core creates one `xray.system.<uuid>` value for that core,
matching Xray's isolation from application inbounds. Whitespace in a nonempty
tag is preserved. This is routing input, not an outbound tag: rules may map
`inboundTag: ["dns-route"]` to an outbound, and the DNS exchange does not
inherit the SOCKS, HTTP, TUN, or startup-probe inbound tag that triggered the
lookup. Ordered failover may therefore change both server and routing tag.

Each candidate filters its merged A/AAAA answer before it can win. The exact
Xray order is hard expected, hard unexpected, soft expected, then soft
unexpected. A hard filter that leaves no addresses advances to the next
selected server using the original query name. A soft filter narrows the
answer only when its preferred subset is nonempty. Candidate order, address
order, and the already computed minimum TTL are otherwise preserved.

An object server's `timeoutMs` is one absolute wall-clock budget for that
managed client attempt. Omission, `null`, or `0` selects Xray's 4000 ms
default. Other values must be integer milliseconds from 1 through
4,611,686,018,427. Values above that boundary are rejected because Xray-core's
cached parallel-query context doubles its signed-nanosecond duration and may
overflow into an unintended deadline. This is an intentional fail-safe
divergence for a practically unreachable timeout. With `UseIP`, A and AAAA
share the deadline. UDP-to-TCP retry and the Rust CNAME continuation extension
also consume only its remaining time. IP response filters run after the timed
query. Failure advances to the next selected server with the original name and
a fresh full per-server budget.

The core consumes these policy matchers once during construction. Exact rules
are indexed by hash and suffix rules by reversed domain labels, following
Xray-core's Compact mobile matcher trade-off; keyword and regex rules remain
linear. DNS IP filters compile into merged IPv4/IPv6 ranges with logarithmic
membership checks instead of scanning expanded GeoIP CIDRs. The resulting
immutable set is shared across SOCKS, HTTP, TUN, and startup-probe routing
contexts. Policy domain and IP matchers are released from the retained runtime
config after compilation, while endpoints and flags remain available to the
raw DNS proxy planner.

The TUN-local `198.18.0.1:53` anchor and
`198.18.0.2:53` client address cannot be configured as upstreams, including as
IPv4-mapped IPv6 literals. With `UseIP`, the resolver sends A and AAAA
concurrently and retains all usable answers in DNS order (A before AAAA);
single-family strategies send only their selected query. All modes validate
A/AAAA records plus CNAME chains in `xray-transport`; a CNAME-only follow stays
on the server that supplied the alias. If that continuation fails, the next
selected server is retried with the original name; after the plan is exhausted,
the alias is not sent to any other resolver. Classic delivery starts with UDP
and retries the same server over TCP only after a valid truncated response.
TCP URI clients start with TCP, and a truncated TCP response is invalid rather
than retried. The delivery transport
is replaceable, so TUN resolution sends them through the outbound router
rather than duplicating the DNS parser. A valid UDP response with `TC=1`
retries over TCP to the same server. UDP transports ignore responses with an unrelated
transaction ID, opcode, name, type, or class until the attempt deadline.
Managed destination results use a bounded 256-entry LRU cache. Authoritative
answer TTLs are floored at one second and the minimum TTL across the answer
chain controls expiry; values above 300 seconds are preserved, matching
Xray-core v26.7.28. Static `dns.hosts` IPs use 10 seconds, while resolvers
without TTL metadata use the 300-second policy cap. Cache hits expose the
remaining TTL rather than extending it. ASCII case is canonicalized, and
overflow evicts one least-recently-used entry rather than flushing the whole
cache. Concurrent misses for the same normalized
`(domain, port, queryStrategy)` share one cancellation-safe lookup and the same
typed outcome instead of opening duplicate routed DNS/VLESS sessions. One
managed destination cache and single-flight table is shared by every
SOCKS/HTTP listener, TUN consumer, and startup probe in a `Core` runtime; a
separate `Core` owns a separate cache.
Authoritative NXDOMAIN and NODATA outcomes use a separate fixed 30-second
negative TTL. Transport, timeout, malformed-response, and aggregate upstream
unavailability errors are never cached. When bounded stale service is enabled,
an expired positive result is returned with no remaining authoritative TTL
while exactly one background refresh owns that key's existing single-flight
slot. Refresh success atomically replaces the entry; failure retains it only
until the configured stale deadline. Negative outcomes are never served stale.
`disableCache: true` bypasses this Core-owned destination cache but does not
change the platform/system bootstrap resolver, matching Xray's `localhost`
exception.

For managed runtimes, including TUN, SOCKS, HTTP, and startup probes, `System`
resolution is `dns.hosts` → configured `dns.servers`: classic, `tcp://`, and
`tls://` clients are routed, while `tcp+local://` clients intentionally dial directly.
When no `dns.servers` are
configured, unresolved names use the cached operating-system resolver by
default. A Rust embedding can replace that platform boundary through
`Core::with_platform_dns_resolver` (or its TUN-options variant) without losing
managed hosts, servers, routing, or cache ownership. Authoritative
NXDOMAIN and A+AAAA NODATA advance to the next configured server, matching
Xray-core's ordered failover. If no later server succeeds, an authoritative
negative result is terminal and does not leak into the operating-system
fallback. SERVFAIL, malformed replies, and transport failures also move to the
next server. Exhausting a nonempty configured server plan is terminal and never
sends the original qname to the operating-system resolver. Configured servers
have no hidden aggregate five-second cap: serial failover may consume the sum
of their individual budgets, as in Xray-core. The no-server operating-system
fallback for a destination lookup remains bounded by five seconds. Resolving a
domain-valued upstream is a bootstrap sub-operation and inherits the enclosing
server candidate's `timeoutMs` instead of being silently clipped at five
seconds. Embedders and tests may opt into an explicit whole-resolution cap
through the transport API when their surrounding operation has a stricter
deadline.
`StaticOnly` uses the same routed path and then fails closed; its separate
bootstrap resolver never uses `dns.servers` or the operating-system resolver.
In managed `System` mode, a platform resolver injected through the dedicated
constructor remains a trusted integration dependency: `dns.hosts` runs first,
the no-server destination call retains its five-second deadline, and endpoint
bootstrap inherits its enclosing operation deadline. Managed `StaticOnly`
ignores that dependency. The lower-level `with_dns_resolver` and
`with_runtime_dependencies*` constructors instead inject a complete resolver
as-is and deliberately bypass managed `dns.servers`; they remain useful for
deterministic tests and integrations that own the entire DNS policy.
The two `disableFallback*` fields control Xray's fallback phase within the
configured name-server list. They are independent from endpoint bootstrap: in
`System` mode a domain-valued DNS upstream may still use the operating-system
resolver to find the upstream itself, but never to retry the original qname.

When fake-IP is disabled and at least one usable server is present, TUN clients
can use `198.18.0.1:53` as a local UDP/TCP DNS proxy. The proxy keeps
server order and removes duplicates by endpoint, effective tag, and transport.
Classic, `tcp://`, and `tls://` attempts enter the normal outbound router, so Freedom
sockets retain platform socket protection and VLESS routes do not gain a
hidden direct-DNS bypass. `tcp+local://` deliberately skips route selection and
uses the same protected, non-recursive direct dialer as managed DNS. DNS
sessions route on their original IP/domain metadata and the selected server's
effective DNS tag. As in Xray's internal DNS context, upstream routing never
runs the `IPIfNonMatch` DNS second pass; domain/tag rules apply to a domain
upstream without recursively resolving the server needed to perform that
lookup. UDP requests have
bounded per-attempt and total timeouts; unrelated replies from the selected
peer are ignored, while invalid/unavailable upstreams return
SERVFAIL. The maximum UDP reply is the smaller of the IPv4 tunnel-path payload
limit and the client's valid EDNS(0) advertised size. A request without a
well-formed root OPT record uses the legacy 512-byte limit, and advertised
values below 512 are treated as 512. An oversized reply is converted to a
matching minimal response with `TC=1` so the client can retry over TCP; valid
EDNS requests retain the required response OPT record.
When a UDP client selects a TCP URI upstream, the
proxy adds/removes RFC 7766 length framing, validates the returned DNS envelope,
and preserves the same bounded failover behavior. Successful streams are reused
with one in-flight request per connection. A stale reused stream is retired and
retried once through the same protected/routed dial path; cancellation or timeout
also retires the lease so a partially consumed frame cannot re-enter the pool.
The per-upstream/runtime-wide connection limits are `1/8` for `LowMemory`, `2/16`
for `Mobile`, `4/32` for `MobilePlus` and `Desktop`, and `8/64` for `Throughput`;
`Default` selects the mobile limits on Apple/Android mobile targets and desktop
limits elsewhere. Idle connections count toward the global limit and expire
after 15 seconds (`LowMemory`), 30 seconds (`Mobile`), 45 seconds (`MobilePlus`),
or 60 seconds (`Desktop`/`Throughput`), as well as being released with the TUN
runtime. TCP is byte-transparent only when its first DNS message requires
transparent semantics (AXFR, IXFR, a non-QUERY opcode, multiple questions, or
an unsupported/malformed envelope). Ordinary single-question QUERY messages
use a bounded hybrid session with up to 16 combined pending questions and
128 KiB of decoded input. Individual DNS/TCP messages may use the full
65,535-byte wire length; the combined limit remains shared across pipelined
frames. A strict IN A/AAAA query without AD/CD and either no OPT or an empty
EDNS(0) OPT with DO clear is answered through the managed destination resolver.
It therefore applies `dns.hosts`, global and per-server
`queryStrategy`, `domains`, IP response filters, `timeoutMs`, fallback policy,
effective DNS tags, and the TTL cache. Family selection occurs before wire I/O
and before cache/single-flight: A and AAAA cannot trigger or reuse one another's
upstream query. The synthesized response preserves the request ID and question,
emits all selected-family addresses with the remaining minimum TTL, and maps
authoritative negative results to NXDOMAIN or NODATA; transport exhaustion is a
bounded SERVFAIL. Managed UDP and TCP answers retain a minimal empty EDNS(0)
OPT; UDP also honors the same EDNS/path-MTU truncation limit as the raw adapter.
DNSSEC- and option-sensitive requests remain raw because the managed resolver
does not yet return complete RRsets/RRSIGs or EDNS option state. This is an
intentional standards-safe extension over Xray-core's DNS outbound, which drops
OPT on a Hijack response.

Other ordinary question types, DNSSEC-sensitive A/AAAA requests, non-empty EDNS
options, and unsupported EDNS versions keep their original wire message and use
the raw plan. Raw responses are matched by transaction ID, opcode, and question;
post-open EOF/I/O/timeout/protocol failures and `TC=1`/SERVFAIL retry only
unanswered queries on the next configured server. NXDOMAIN, NOERROR/NODATA,
and other matching RCODEs are returned without fallback. Exhaustion emits a
framed SERVFAIL for each unresolved raw query while keeping the client
connection open. Managed answers are delivered independently of a concurrent
raw dial/write, may complete out of order, and share the same 16-question and
128-KiB admission boundary. Their owned lookup tasks are aborted with the
client flow. Raw, fake, and explicit DNS-outbound TCP flows through TUN share a
dedicated limit of up to 32 flows. The client session uses inbound `connIdle`;
individual raw-DNS operations remain bounded by the smaller of `connIdle` and
five seconds.

For raw questions, object entries contribute their endpoint, transport, and
effective DNS tag to the wire exchange. The tag drives outbound routing for
routed transports and is intentionally inert for `tcp+local://`. The
declaration-order plan deduplicates by endpoint, transport, and effective tag,
so two clients aimed at the same endpoint with different tags remain distinct.
Raw selection does not apply managed `queryStrategy`, `domains`, IP response
filters, `timeoutMs`, `skipFallback`, or `disableFallback*`; its own bounded
transport failover walks that declaration-order plan. DNSSEC/EDNS clients that
depend on split-DNS privacy must therefore ensure every raw candidate the plan
may reach is appropriate whenever no explicit DNS outbound route is selected.
This is the raw-message equivalent of Xray DNS outbound `Direct`; the TCP
adapter interprets only enough of ordinary QUERY envelopes to provide safe
correlation and failover. The fixed A/AAAA managed path models the core of Xray
DNS outbound `Hijack`. It remains the compatibility fallback and is not
silently changed by the configurable outbound described below.
The raw path retains its own transport-aware per-attempt and five-second
per-query budget; those protect the TUN adapter rather than model a managed
Xray DNS client.

### DNS outbound

`outbounds[].protocol: "dns"` accepts Xray's canonical settings:

```json
{
  "tag": "dns-out",
  "protocol": "dns",
  "settings": {
    "rewriteNetwork": "tcp",
    "rewriteAddress": "1.1.1.1",
    "rewritePort": 53,
    "userLevel": 0,
    "rules": [
      {
        "action": "return",
        "qType": "64-65",
        "rCode": 3,
        "domain": ["domain:example.com", "geosite:private"]
      }
    ]
  }
}
```

The compatibility aliases `network`/`address`/`port` override their
`rewrite*` counterparts exactly as in Xray; a zero port preserves the original
port. `action` is case-insensitive and must be Direct, Drop, Return, or Hijack.
`qType` accepts a number or comma/range string over `0..=65535`; ranges stay
compact and are normalized instead of being eagerly expanded. `rCode` accepts
`0..=65535`, defaults to zero, and is used by Return and by Hijack when the
selected query is not A/AAAA. Domain accepts a string or array and supports the
same `keyword`, `domain`, `full`, `regexp`, `dotless`, `geosite`, and `ext`
grammar as other DNS matchers. Bare values are keywords. Rules are ordered,
selectors inside a rule are ANDed, and empty QTYPE/domain selectors are
wildcards. A miss Hijacks A/AAAA and Returns an empty NOERROR response for
other types.

Lower-case `qtype` remains an input-only compatibility alias and emits a
warning; supplying non-null `qType` and `qtype` together is rejected as
ambiguous. The former `Reject` action is also accepted with a warning and maps
to Return with `rCode: 5` unless an explicit `rCode` overrides it. Canonical
configuration and normalized runtime state use `qType`, Return, and `rCode`.

Deprecated `nonIPQuery`/`blockTypes` are normalized to ordered modern rules and
emit a warning. They cannot be mixed with non-null `rules`. Config parsing caps
the whole configuration at 4,096 DNS rules, 65,536 compact QTYPE selectors,
and the existing shared domain/geodata matcher budget. Routing field rules now
accept Xray `network` strings/arrays and numeric or range-string `port`, so a
typical TUN route is:

```json
{
  "type": "field",
  "network": "udp,tcp",
  "port": 53,
  "outboundTag": "dns-out"
}
```

At runtime one per-Core handler is shared by TUN UDP/TCP, SOCKS5 `CONNECT` and
`UDP ASSOCIATE`, and HTTP `CONNECT`. Direct preserves complete query and
response wire messages while applying network/address/port rewrite
independently; UDP/TCP framing conversion is supported. The outbound's TCP
`streamSettings` are honored, including TLS (with target-derived SNI when
omitted), REALITY, and Happy Eyeballs socket policy. Security configured for a
UDP rewrite fails closed instead of silently sending plaintext. A domain
rewrite uses the non-recursive bootstrap resolver and all direct sockets retain
platform protection. The direct exchange is capped at eight candidates and
five seconds and rejects tunnel-local endpoints. UDP clients rewritten to
TCP/TLS, managed `dns.servers` selected through the DNS outbound, and ordinary
TCP clients share one Core-wide keyed session pool. Ordinary TCP clients check
out and recycle an upstream session for each message, so idle client flows do
not reserve DNS sockets or query permits. The named pool policy derives from
the runtime concurrency profile: per-key/global connections and maximum keys
are `1/8/128` for `LowMemory`, `2/16/256` for `Mobile`, `4/32/512` for
`MobilePlus` and `Desktop`, and `8/64/1024` for `Throughput`; `Default` selects
Mobile on Apple/Android mobile targets and Desktop elsewhere. An idle stream
lives for the smaller of the profile cap (15/30/45/60 seconds) and the outbound
policy's `connIdle`. A stale stream is retried
once only for a fully parsed standard QUERY; UPDATE and opaque messages are
never replayed. Cancellation, timeout, and protocol failure retire the
connection. UDP-source AXFR/IXFR returns REFUSED before dialing because one UDP
reply cannot represent a multi-message transfer. TCP AXFR/IXFR instead use a
dedicated non-pooled response-only handoff so every upstream transfer frame is
preserved. Its managed session carries an ingress operation permit on TUN,
SOCKS, and HTTP alike; cancellation releases that permit together with the TCP
pool lease. The older raw TUN DNS TCP-URI pool remains adapter-local. Together,
it and the keyed Direct pool can own at most 16 pooled TCP sockets for
`LowMemory`, 32 for `Mobile`, 64 for `MobilePlus`/`Desktop`, and 128 for
`Throughput`. This is a ceiling for those two pooled subsets, not a maximum for
every DNS/TCP socket in the Core: standalone routed/local managed
`dns.servers` exchanges are instead bounded by the operation cap below. A TUN
anchor Direct rule therefore needs a real rewrite target; otherwise it returns
SERVFAIL rather than recursing into `198.18.0.1:53`.

All managed `dns.servers` exchanges have a separate Core-wide operation cap of
8/16/32/32/64 for `LowMemory`/`Mobile`/`MobilePlus`/`Desktop`/`Throughput`.
It applies uniformly to routed and local TCP, VLESS UDP/TCP, Freedom UDP, and a
selected DNS outbound; saturation fails closed without an unbounded waiter
queue. Direct DNS-outbound UDP and managed Freedom UDP also share a protected
UDP-socket cap with the same profile values. These budgets are separate from
the ingress DNS policy semaphore and from TCP pool permits, so a Hijack that
performs a managed lookup cannot self-deadlock by reacquiring its own permit.

Drop sends no response. Return synthesizes an empty response with the selected
`rCode` while preserving the query ID and question. Hijack uses the shared
destination resolver or the per-Core FakeIP mapper when configured and remains
family-specific. A mapping allocated
through any supported ingress is available to every other ingress in that
`Core`. Unlike Xray's
lossy synthesis, a Hijack that would discard AD/CD, DNSSEC DO, EDNS options or
unsupported structural semantics is typed as unsafe and returns REFUSED; it is
never converted to Direct. An effective managed DNS-client tag routed back to
the handler takes the own-link Direct escape before parsing, but only from the
trusted managed transport call site, preventing an application tag collision
from bypassing policy.

The compiled policy, protected Direct exchange, FakeIP state, and bounded
runtime budgets are core-owned and do not depend on TUN packet parsing. This is
also the integration boundary for future server-protocol inbounds; selecting a
DNS outbound never degrades to Freedom merely because the ingress is not TUN.

A domain upstream selected through VLESS stays a domain and is resolved
by the remote endpoint. A domain selected through Freedom uses the separate
bootstrap policy. Non-intercepting `System` embeddings may use the operating
system there. Destination DNS and this non-recursive outer-endpoint bootstrap
remain distinct core roles for desktop and future server embeddings as well as
mobile clients. The generic C ABI defaults to `System`; the Apple Packet Tunnel
and Android reference VPN integration pre-populate exact bootstrap host rules
before installing their DNS anchor, then explicitly select `StaticOnly`. Mobile
preflight lookups share a five-second start deadline, execute on bounded
workers, and cannot publish after stop, timeout, or supersession. Blocking
platform resolver calls themselves may outlive the deadline, so the adapters
bound worker admission and fail closed rather than accumulating work. In any
custom `StaticOnly` embedding, a domain upstream's `dns.hosts` alias chain must
end in an IP or nonempty IP array or that candidate fails over (and ultimately
returns SERVFAIL).
If an `IPIfNonMatch` lookup itself fails, routing follows Xray-core and selects
the default outbound; it does not discard the original domain or fail the
session at the routing layer.

`dns.hosts` maps supported domain matchers to a single IP string, an alias
domain string, or a nonempty ordered array containing only IP strings. Every IP
in an array is retained as a resolution candidate. Names are canonicalized to
lowercase without a terminal dot at the managed resolver boundary. As in
Xray-core, an unprefixed `dns.hosts` key is an exact/full matcher rather than a
routing-style keyword; explicit `full:` mappings have the same exact semantics
and take precedence over broader matching rules. Alias
resolution is bounded to eight hops; static IP candidates use the shared
10-second hosts TTL. If that bound is reached, the terminal alias still uses
the configured DNS-server plan; only a configuration without DNS servers may
send it to the operating-system fallback.
`dns.fakeIp` supports `enabled`, an IPv4 `ipv4Pool`, optional positive
`poolSize`, and a positive `ttl` for the core-wide DNS runtime. `poolSize`
defaults to the smaller of 32768 and the usable pool capacity. The bounded
mapping table retains each address lease until the TTL most recently advertised
for that domain has elapsed. At capacity, a new domain fails closed until the
earliest lease expires; the address is then safe to reuse. An ordered deadline
index keeps allocation O(log `poolSize`) and total state O(`poolSize`).
`198.18.0.1` and `198.18.0.2` are always reserved for the DNS anchor and TUN
client address. The fixed TUN FakeDNS mode synthesizes A records over UDP and
length-prefixed TCP for both the anchor and hard-coded port-53 destinations;
DNS-outbound Hijack uses the same mapper from TUN, SOCKS, or HTTP. With
`UseIPv6`, its IPv4-only pool returns NODATA for A without allocating a mapping.
AAAA returns NODATA on both paths; other valid single-question types return
NODATA at the anchor and over TCP, while non-anchor UDP continues through the
normal UDP path. Fake-IP takes precedence over raw proxying. When a later TUN,
SOCKS, or HTTP TCP/UDP flow targets a mapped fake address, the original domain
is restored before routing. VLESS carries that domain for remote resolution;
Freedom resolves it through the managed routed resolver, including in mobile
`StaticOnly` mode. Managed `dns.servers` routed DoQ transport, per-server cache
policy, `clientIp`, and the broader
Xray DNS feature set are not implemented. This does not limit the DNS
outbound's documented TLS/REALITY `streamSettings`. The public resolver result
carries every candidate and TTL metadata. An explicitly enabled
`sockopt.happyEyeballs` policy consumes those candidates through the bounded
raw-TCP race described above; its Xray-compatible zero-delay default leaves the
race disabled.

A fake-IP profile does not inherently need `dns.servers` when its restored
domains always use VLESS, because VLESS preserves them for remote resolution.
Freedom cannot do that: in `StaticOnly`, a default or domain-routed Freedom
path needs usable `dns.servers` (or a sufficient terminal `dns.hosts` mapping)
and otherwise fails closed. Conservatively, the Apple and Android reference VPN
adapters require nonempty `dns.servers` for such fake-only/Freedom topologies
before installing the tunnel; they never substitute a public resolver. IP-only
Freedom split rules remain valid with a default VLESS because an unresolved
`IPIfNonMatch` pass falls back to that VLESS outbound.

## Policy

Level objects parse `handshake`, `connIdle`, `uplinkOnly`, `downlinkOnly`,
`bufferSize`, `statsUserUplink`, and `statsUserDownlink`. Runtime connection
timeouts and relay buffer size use the applicable inbound/VLESS user level.
System statistics flags are modeled for config compatibility, but this is not
the Xray statistics service.

## Geodata

The parser can expand Xray-style protobuf `geosite.dat`, `geoip.dat`, and named
`ext:` files. Binary databases are not distributed by this repository. Supply
files whose source and license you have verified.

For the Apple sample, `scripts/fetch-geodata.sh` downloads pinned assets,
verifies their hard-coded SHA-256 digests, and installs them into the sample
resource directory. Review [third-party notices](../THIRD_PARTY_NOTICES.md)
before redistributing those files.

For the CLI, lookup starts with the config directory, then the current working
directory and executable directory. Embedders should set a resource directory
with `xray_core_set_geodata_search_dir` before loading the config.

File names must be relative and cannot escape a configured search directory.
Parsing enforces file, entry, matcher, rule, attribute, domain, and CIDR budgets
to bound untrusted input.

## Diagnostics

Parser errors include JSON paths. Warnings do not fail a load; callers should
display them. The C ABI exposes warnings through
`xray_core_config_warnings`, and the checked-in Swift/Kotlin adapters surface
them through their platform logging paths.

Current aggregate limits include 4,096 routing rules, 250,000 domain matchers,
300,000 IP matchers, and 500,000 matchers total per config. These limits are
implementation safeguards and may change across major ABI or documented
configuration revisions.
