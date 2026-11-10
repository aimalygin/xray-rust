# Configuration compatibility

`xray-rust` reads Xray-style JSON, but only the subset described here. It is not
a schema-compatible replacement for Xray-core. Unsupported modeled fields
normally fail parsing with a JSON path instead of being silently approximated.

Use `xray-rust config check --config client.json --json` for exact parser
validation without starting the core. [Configuration tooling](config-tooling.md)
documents the generated [machine-readable contract](config-contract.json),
canonical examples, geodata lookup and the boundary between parser acceptance
and later runtime validation.

See [Xray-core differences and verification gaps](xray-core-differences.md)
for the reference revision, deliberate SOCKS restrictions, mobile integration
gaps, and pending HTTP decisions from issues #79 and #81.

The active compatibility reference is **Xray-core v26.11.9**; see the
[migration record](xray-core-v26.11.9-migration.md) for checks and limitations.
References to earlier versions below describe the origin of unchanged behavior.

## v0.8 Hysteria carrier additions

Hysteria accepts one Salamander mask and the v26.10.21 UDP-hop mask:

```json
"finalmask": {
  "udp": [
    {"type": "salamander", "settings": {"password": "synthetic-example-password"}},
    {"type": "udphop", "settings": {
      "mode": "intervalLocal,intervalRemote", "remotePorts": "443,8443-8445", "interval": "5-10"
    }}
  ]
}
```

Both masks are optional. UDP-hop must be last: Xray-core reverses the list
and dials only an outermost UDP-hop, so a mask after it fails every dial with
`incorrect index`, though `xray run -test` accepts it. XHTTP with exact `h3`
ALPN accepts the same UDP-hop mask (see the XHTTP H3 section). Its `mode` is
a comma-separated mix of Xray-core v26.10.31's modes, read as Xray reads
them: case-insensitive, without trimming, and refusing an empty or unknown
part.

- `intervalLocal` moves the connection to a fresh protected local socket at
  every interval, still aimed at the same remote address.
- `intervalRemote` aims it at a new remote address at every interval: a port
  among `remotePorts` and an IP in `remoteIPs`. Unlike Xray-core, which keeps
  its socket for a remote-only hop, a remote hop also takes a fresh local
  socket.
- `perConnRemote` draws the first remote address once per connection and
  never hops on its own.

With `intervalRemote` or `perConnRemote` the first packet already goes to a
drawn address, and every address must reach the same server; otherwise it
goes to the configured server. `remotePorts` preserves order and duplicate
weights, with at most 65535 expanded entries. `remoteIPs` holds IPs or
prefixes, read as Go's `netip` reads them; a drawn IP takes random host bits
within a prefix, as Xray's `randPrefix` draws them. Only entries of the
server address's family are drawn, since the QUIC endpoint keeps its socket
family, where Xray-core dials any family. An omitted/zero interval defaults
to 30 seconds; other bounds must both be at least five seconds. Each
scheduled remote hop draws among the ports other than the current one,
keeping duplicate weights, so every hop changes the port. Xray draws with
replacement, so with two ports half of its hops keep the same port.
The old `quicParams.udpHop` spelling remains accepted with a migration warning;
combining both spellings fails. Profile import emits the new mask form.

Salamander passwords contain 4..4096 UTF-8 bytes and remain redacted/zeroized.
One noise mask may accompany Salamander, after UDP-hop; unknown and duplicate
masks fail.

A Salamander `packetSize` with a positive upper bound selects Gecko, as in
Xray-core and Hysteria 2.9.2+. It is an Xray integer range: a number, or a
string holding one number or a `from-to` range in either order. Gecko needs
`1 <= from <= to <= 2048`; an upper bound of zero or less (absent, null, `0`,
`""`, negative) keeps plain Salamander. Gecko sends each QUIC long-header
(handshake) datagram as two to eight fragments, each its own Salamander
datagram with a random salt. Padding brings each fragment to a random size in
the range when its chunk leaves room; a larger chunk travels unpadded.
Short-header datagrams, everything after the handshake, pass through as plain
Salamander. Incoming fragments are reassembled per message: like Gecko, at most
eight incomplete messages are held, each for eight seconds, and duplicates or
chunks whose count disagrees are dropped. A reassembled message is capped at
64 KiB.

One difference from the references: padding stops at 1,452 bytes, the largest
datagram the carrier otherwise sends. Xray and Hysteria pad up to 2,048 bytes.
Xray's masked socket never gets the don't-fragment flag, so larger datagrams
leave IP-fragmented. Hysteria sets the flag, as Quinn does here, so a fragment
past the path MTU is lost and the handshake stalls. A range above 1,452 bytes
therefore pads to at most 1,452 bytes. Gecko and plain Salamander cannot talk
to each other, so the server must use the same mode; its sizes need not match.

Salamander is not Hysteria's alone: Xray-core applies it to any UDP dial.
XHTTP with exact `h3` ALPN and MASQUE over HTTP/3 take it, Gecko included,
exactly as Hysteria does, at its place among their noise, `header-custom` and
`sudoku` masks; MTU discovery reserves its salt there too. On
[mKCP](#mkcp) it is a header mask, as Xray-core groups it: it joins the
`mkcp-legacy` masks next to it under one 4096-byte limit. Gecko is refused
on mKCP for now. A TCP carrier refuses Salamander, which has no datagrams to
mask. `scripts/check-hysteria-interop.sh`, `check-kcp-interop.sh` and
`check-masque-interop.sh` run each carrier under it against Xray-core's own
servers, and the mKCP vectors record what Xray-core reads out of salted
datagrams.

Each hop binds and protects a fresh socket while retaining the authenticated
QUIC session and its TCP/UDP leases. Quinn retains at most one previous socket
until an authenticated packet arrives on the new path. A scheduled hop whose
bind/protection fails keeps the old protected path; a failed host-requested
network rebind closes the stale session. Stop/free aborts the timer. Salamander
reserves its eight-byte salt in MTU discovery and handles receive GRO segments
individually. Its bounded receive scratch is 64 KiB per live carrier; send
scratch is reused. Profiles without either option use the existing UDP path.
Hysteria shapes its QUIC handshake like Chrome's, as Xray-core's
ChromeParrot does, unless `quicParams.disableChromeParrot` is true; see
[ChromeParrot](#chromeparrot). QUIC v2 transport and socket overrides remain
unsupported.

### Hysteria bandwidth and the other QUIC parameters

Hysteria reads the rest of `finalmask.quicParams` as Xray's Hysteria dialer
does:

```json
"quicParams": {"brutalUp": "100 mbps", "brutalDown": "200 mbps"}
```

Bandwidths use Xray's binary units: one `mbps` is 2^20 bits per second.
`brutalDown` is announced to the server as `Hysteria-CC-RX`, so a server with
its own Brutal rate sends at the lower of its `brutalUp` and this value; zero
leaves the server on BBR. With the default congestion or `brutal`, the client
sends with Brutal at the lower of `brutalUp` and the rate the server announces
once both are nonzero, and otherwise with the BBR of its `bbrProfile` (see
[BBR profiles](#bbr-profiles)). `force-brutal` sends at `brutalUp` whatever the
server announces; `bbr` and `reno` ignore the rates.

Brutal is ported from Xray-core's sender. It paces at its rate, which loss does
not lower, and lets twice the rate's bandwidth-delay product be in flight.
Unless `brutalDisableLossCompensation` is set, both are divided by the share of
packets acknowledged over the last five seconds, never by less than 0.8, once
those seconds hold 50 packets. quinn reports lost packets to it through a
callback added to the vendored `quinn-proto`. quinn sends a packet only while
the bytes in flight plus the packet stay below the window, where quic-go sends
while the bytes in flight are at most the window, so the window quinn sees is
Xray's plus one datagram and one byte.

The idle timeout defaults to 30 seconds and, as in Xray, there is no keepalive
unless `keepAlivePeriod` sets one. quic-go grows the receive windows from their
initial value to the maximum, while quinn keeps a Hysteria connection's windows
fixed, so the larger of the two is the window. Without either, the 2 MiB stream
and 3 MiB connection windows remain; Xray's Hysteria dialer defaults to 8 MiB
and 20 MiB. `disableGSO` turns off segmentation offload. `maxIncomingStreams`
has no effect, as in Xray's dialer, and `disableStatelessReset` only affects
Xray-core's servers. `debug: true` fails before the outbound starts.

An ignored interop test transfers 3 MiB each way through pinned Xray-core with
server rates `brutalUp: "100 mbps"` and `brutalDown: "8 mbps"`. A client with
`brutalUp: "100 mbps"` uploads at the negotiated 8 Mbps, and announcing
8 Mbps makes the server pace the download: each takes about 3 seconds, against
20 to 60 ms with BBR. The test fails if the client keeps BBR or announces zero.
These are loopback checks, not throughput or fairness measurements on real
paths.

The transport tests exercise TCP, inner TLS, fragmented UDP, automatic hopping,
manual rebind and rejected socket protection against pinned Xray-core and
independent official Hysteria v2.12.2. This is client carrier support, not a
change to the congestion-control parity or published v0.7 artifacts.

### BBR profiles

`quicParams.bbrProfile` takes `conservative`, `standard` and `aggressive` in
any case, as Xray-core v26.10.31 does, on Hysteria and XHTTP H3 alike; any
other value fails to parse. `conservative` and `aggressive` run a port of
Xray-core's own BBR sender (`transport/internet/hysteria/congestion/bbr`) with
the profile's settings:

| Profile | STARTUP pacing / window gain | PROBE_BW window gain | Rounds without 25% growth that end STARTUP | Options |
| --- | --- | --- | --- | --- |
| `conservative` | 2.25 / 1.75 | 1.75 | 2 | stays in the low gain until the flight drains to the target; slows an overshooting STARTUP once loss shows it; avoids overestimating bandwidth from compressed ACKs; recalculates the ACK aggregation it adds to the window on a new bandwidth maximum |
| `standard` | 2.885 / 2.0 | 2.0 | 3 | none |
| `aggressive` | 3.0 / 2.25 | 2.5 | 4 | adds the latest ACK aggregation to the STARTUP window and forgets older aggregation when bandwidth grows |

`standard`, which an absent or empty `bbrProfile` also means, still runs
Quinn's BBR with Xray's initial window, as before this release. The port runs
`standard` too and replays Xray's sender for it like the others, but switching
the default moves every Hysteria and XHTTP H3 connection to another
congestion controller, so that waits for a separate decision.

As in Xray, the controller takes over from quic-go's default sender, Reno,
only once the connection is up: on XHTTP H3 right after the handshake, and on
Hysteria after the server's authentication reply, which also decides whether
Brutal runs instead. Until then the connection runs Quinn's NewReno.
`force-brutal` switches at the same points, and `reno` keeps NewReno. Quinn's
BBR for `standard` runs from the first packet.

What differs from Xray, deliberately:

- Pacing. Quinn paces from the sender's rate with its own token bucket. Like
  Xray's pacer it keeps four milliseconds of credit and at least ten
  datagrams, but caps a burst at 256 datagrams, which only binds above about
  600 Mbit/s.
- quic-go never lowers a connection's datagram size, and Xray's sender panics
  if asked to. Quinn lowers it after detecting a black hole; the port then
  scales its windows down as it scales them up.
- The startup sender. quic-go's is its cubic sender in Reno mode with a
  32-datagram window; Quinn's NewReno starts at the same 32 datagrams of the
  initial size (1,250 bytes with ChromeParrot), but runs Quinn's Reno rules.
  It only carries the handshake, plus the authentication request on
  Hysteria.
- The window rule. quic-go sends while the bytes in flight are below the
  window; Quinn sends a packet while the bytes in flight plus that packet stay
  below it, so the window Quinn sees is Xray's plus one datagram.

The sender starts with the smaller of Quinn's initial datagram size and 1,280
bytes, as Xray seeds it from quic-go's, and with the connection's minimum RTT
so far, as quic-go hands it the connection's RTT statistics. It sees what
quic-go would hand it: every sent packet with its packet number, ACK-only
packets included, and one congestion event per ACK frame or loss timeout
listing the packets acknowledged and lost, MTU probes included, with the
bytes in flight before it. Callbacks added to the vendored `quinn-proto`
report these.

`tools/bbr-oracle` drives Xray-core's own sender over fifteen simulated paths,
five per profile, with drop-tail queues, random loss, ACK aggregation, idle
periods answered by ACK-only packets, a rate change and a larger datagram, and
records every call it received with a digest of 54 state values after each of
its 4,399 congestion events and three datagram-size changes. The port replays the calls and reaches the same
state at every one, PROBE_BW gain-cycle draws included; the run is
deterministic, and `scripts/check-bbr-interop.sh` regenerates the trace and
requires it to match the fixture. The same script runs each profile live
against Xray-core's servers: Hysteria, also with `brutal` falling back to the
profile's BBR and with Brutal once the server announces a rate, and XHTTP H3
through the core with every congestion mode.

### ChromeParrot

Xray-core v26.10.31 dials Hysteria and XHTTP over HTTP/3 with the apernet
quic-go fork's `ChromeParrot` on, so that the client's handshake looks like
Google Chrome's, unless `finalmask.quicParams.disableChromeParrot` is true.
This client does the same:

```json
"quicParams": {"disableChromeParrot": true}
```

`disableChromeParrot` is read as Xray reads a Go `bool`: `true` turns
ChromeParrot off; `false`, `null`, or no `quicParams` or `finalmask` at all
leave it on; any other JSON type fails the configuration on every transport,
as it fails Xray's. Hysteria and XHTTP with exact `h3` ALPN dial with it.
XDRIVE's storages over HTTP/3, which Xray dials with it too, do not yet: they
keep Quinn's own handshake, and the configuration warns unless
`disableChromeParrot` is true (see [XDRIVE](#xdrive)). MASQUE never parrots
Chrome, as Xray's MASQUE dial never does, and other transports do not read
the field.

With ChromeParrot on, a dial:

- sends uTLS's Chrome QUIC ClientHello (quic-go's
  `chromeQUICClientHelloSpec`): no GREASE value, TLS 1.3 alone, AES-128-GCM,
  AES-256-GCM and ChaCha20-Poly1305, groups X25519MLKEM768, X25519, P-256
  and P-384 with key shares for the first two, Chrome's nine signature
  algorithms, brotli certificate compression, `psk_dhe_ke`, ALPN and ALPS
  (the newer codepoint) for `h3`, and a GREASE ECH extension whose payload
  takes one of BoringSSL's four lengths, with the extensions in a new random
  order on every connection, drawn as uTLS draws it. Resumption and 0-RTT
  stay off. `tlsSettings.fingerprint` does not reach QUIC either way;
- encodes its transport parameters as Chrome does: in a random order, with
  `version_information` (QUIC v1, then v1 and a GREASE version in random
  order), `google_connection_options` "ORIG" and a GREASE parameter with an
  8-byte identifier, without `ack_delay_exponent`, `max_ack_delay`,
  `disable_active_migration` and `active_connection_id_limit`, whose defaults
  are what the client then does;
- pins quic-go's values: a 30-second idle timeout, 6 MiB stream and 15 MiB
  connection windows, 100 bidirectional and 103 unidirectional streams,
  1,472-byte UDP payloads and 65,536-byte DATAGRAM frames. These replace
  `maxIdleTimeout`, `initStreamReceiveWindow`, `initConnectionReceiveWindow`
  and `maxIncomingStreams`, and a configured window maximum below the pinned
  start is raised to it. Hysteria advertises 65,536-byte DATAGRAM frames
  instead of its usual 1,200, as Xray's client then does. A constrained host,
  which otherwise holds the windows at their start, starts them at 6 and 15 MiB
  too;
- packs its Initial packets as quic-go's ChromeParrot does: 1,250-byte
  datagrams numbered from 1, from zero-length source connection IDs to an
  8-byte first destination ID, a ClientHello too large for one packet sent
  with its head and its tail first and its middle next, and each packet's
  CRYPTO frames cut at random and shuffled among PING frames and runs of
  padding (Chromium's chaos protection), with quic-go's own generator.
  Packet numbers take Chrome's lengths from the congestion window, and until
  the handshake is confirmed every datagram carries one packet: the Initial
  ACK alone and padded, then a Handshake ACK apart from the Finished.

Two consequences, the same as with Xray's own client:

- Many parallel XHTTP H3 downloads cost memory. The 6 MiB and 15 MiB windows
  apply on constrained devices too, and a reader that falls behind lets the
  server fill them: with 32 parallel downloads the client's peak memory grew
  by about 30–40 MiB in a Linux measurement, while 8 or fewer, and Hysteria,
  showed no difference. `disableChromeParrot: true` brings back the previous
  windows (on XHTTP H3, 2 and 3 MiB to start, held there on a constrained
  host).
- Hysteria loses large UDP replies from Xray-core v26.5.9 … v26.7.28 servers.
  Their quic-go fork (`6c6cc9bcb716`) drops every fragment of a UDP reply it
  has to split once the client advertises 65,536-byte DATAGRAM frames, so a
  4 KiB reply never arrives, while TCP and small datagrams work. Xray-core's
  own client meets the same. Update the server to v26.9.9 or newer, or set
  `disableChromeParrot: true`. Servers v26.1.31 … v26.4.25 were not checked.

`tools/chrome-parrot-oracle` runs Xray-core's own Hysteria dialer under a
deterministic `crypto/rand` and records its first four Initial datagrams,
the first flight and its retransmission, with every random read behind them.
Given the same reads, the client produces the same transport parameters and
the same encrypted datagrams byte for byte, and the same ClientHello but for
the key material in its key shares. `scripts/check-chrome-parrot-interop.sh`
regenerates the oracle's fixture and requires it to match, rechecks the
`disableChromeParrot` verdicts against `xray run -test`, and runs Hysteria
(also under Salamander) and XHTTP H3 against Xray-core's servers with
ChromeParrot on and off, checking the first flight on the wire.

What differs from Xray:

- A prebuilt rustls configuration from an embedding application keeps its own
  ClientHello, as it does under a fingerprint; the packet shaping still
  applies.
- After the handshake, packet number lengths follow the running congestion
  controller's window, which differs from Xray's where the controller does
  (`standard` runs Quinn's BBR).
- quic-go also shuffles the frames of every other packet with the same
  generator, and starts its loss timer from a 100 ms RTT estimate rather than
  Quinn's 333 ms, so a lost first flight is retransmitted later here. Neither
  is ChromeParrot's own.
- `disableChromeParrot: true` gives Quinn's own handshake, which is not
  quic-go's either: its connection ID lengths, transport parameters, packet
  layout and rustls's ClientHello differ from Xray's stock QUIC client.

## WireGuard destination DNS

`settings.remoteDNS` accepts up to eight usable IP literals. Missing, null or
empty values select the upstream defaults `1.1.1.1`, `1.0.0.1`,
`2606:4700:4700::1111`, `2606:4700:4700::1001`. Destination queries use UDP/53
inside the WireGuard device, with TCP fallback for truncated replies. A failed
tunnel query never falls back to host DNS. Only when no `remoteDNS` server is
routable through the tunnel (covered by a peer's `allowedIPs`, with a local
`address` of its family) are destinations resolved by the caller's resolver
instead, as wg-quick sends DNS outside a split tunnel; otherwise every domain
would fail with no route. The parser warns at `remoteDNS` when this applies. The
device owns a 256-entry single-flight cache: answer TTL is capped at 300
seconds, negatives last 30 seconds, and stale answers are never returned.
Closing the outbound cancels pending queries. Its peer endpoint continues to use
the separate bootstrap resolver and protected outer socket, and
`streamSettings.sockopt.domainStrategy` picks which of a domain endpoint's
addresses it dials ([details](#domain-strategy-socket-option)).

Destination lookups ask for the families the device has a local `address`
of, and put IPv6 answers first when it has an IPv6 one, as Xray-core's device
resolver does. `settings.domainStrategy` is not read, of any value, since
Xray-core v26.10.31 has no such setting; the parser warns at it. `allowedIPs`
still bounds DNS-server and destination routing. WireGuard profile import
preserves explicitly supplied DNS addresses in both the profile DNS
configuration and `remoteDNS`; it never substitutes public resolvers during
import. Port-qualified/hostname DNS, DoH and DoT are outside this field's contract.

## v0.8 TLS ClientHello fragmentation

TCP TLS/REALITY carriers accept one `tlshello` FinalMask, after socket
protection and after the TLS/REALITY handshake bytes have been finalized:

```json
"finalmask": {
  "tcp": [{"type": "fragment", "settings": {
    "packets": "tlshello", "length": "100-200", "delay": "1-2", "maxSplit": 32
  }}]
}
```

`lengths` and `delays` optionally override the scalar ranges with sequences of
at most 16 entries; subsequent fragments reuse the last entry. Ranges accept
integers or inclusive `min-max` strings and normalize reversed bounds as Xray
does. This bounded subset requires lengths 1..16384 bytes, delays 0..1000 ms,
and `maxSplit` 0..4096 (zero means no explicit split limit). Before sending,
each actual randomized plan must fit 4096 records and ten seconds of total
delay; exceeding either limit fails the connection. `maxSplit` makes the last
record contain the remainder, even when it exceeds the configured length.
Zero lengths, other mask types and unknown fields are rejected. FinalMask
spells the delay `delay`, not `interval`.

`packets` can also select whole writes, which then go out as raw pieces, as
Xray-core cuts them: empty or absent selects every write, one number or a
`from-to` range the writes so numbered, counting from 1. A `tlshello` in any
case keeps the record split above. Each piece of a selected write is its own
socket write, followed by its delay, even the last; `maxSplit` makes the
piece so numbered take the rest of the write. The pieces need no TLS, so raw
pieces go on any TCP carrier of a proxy, encrypted or not, and on a raw
freedom outbound:

```json
"finalmask": {
  "tcp": [{"type": "fragment", "settings": {
    "packets": "1-3", "length": "30-50", "delay": "2-3"
  }}]
}
```

A write is what the layer above hands the carrier in one call, as one `Write`
is in Go; a call that leaves part of its input for the next one continues the
same write. A selected write stages at most 64 KiB, 4096 pieces or ten
seconds of delays at once, and its next call continues it where it stopped,
so a long write is cut whole without unbounded buffering. Once no later write
can be selected, the mask steps aside. Reads never wait for staged pieces, as
Go's reads never wait on its writer's sleeps. A zero, a negative or a
reversed range, which Xray-core either refuses or accepts and never applies,
is refused. Every write cut with delays slows the whole connection; Xray-core
does the same. With freedom's `proxyProtocol`, the PROXY header goes beneath
the mask and is not counted, where Xray-core's FinalMask counts it as the
first write. `scripts/check-v08-carrier-interop.sh` runs a TLS carrier with
`"1-3"` and a plaintext one with every write cut against Xray-core's server.

Existing mobile profiles may instead put
`{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-2","maxSplit":32}}`,
or the same with a write selector such as `"packets": "1-3"`,
in a dedicated `freedom` outbound's `settings`, then reference its tag with
`streamSettings.sockopt.dialerProxy`. That handler must use raw TCP with no
security, socket overrides, mux or proxy chain. The parser normalizes its sole
fragment transform into the caller's stream. As in Xray-core, where the
handler opens the socket, the caller's own socket options such as `mark` or
`interface` do not apply to it. Ordinary `dialerProxy` chaining
is supported separately below. Combining two fragment masks, QUIC/H3 fragmentation and split XHTTP
downloads remain unsupported. A raw freedom outbound can also fragment an
application's first complete TLS record directly.

As in pinned Xray-core v26.7.28, only the first write's complete handshake
record is fragmented; an incomplete or non-TLS first write passes through.
TLS record envelopes change, while the concatenated handshake bytes, including
REALITY authentication, remain identical. Later writes pass through unchanged.
One zero delay entry coalesces the new records into one write; it does not
promise separate IP packets. Nonzero delays use cancellable async timers.
Dropping the handshake drops its bounded buffer and timer without a background
sender. The option is disabled by default and adds no fragment wrapper to
existing profiles. Configured delays intentionally increase handshake latency.

## v0.8 UDP noise

Hysteria2, [mKCP](#mkcp), XHTTP with exact TLS `alpn: ["h3"]` and MASQUE over
HTTP/3 accept one FinalMask UDP noise mask, in Xray-core's format:

```json
"finalmask": {"udp": [{"type": "noise", "settings": {
  "reset": 0,
  "noise": [
    {"rand": "16-32", "delay": "1-3"},
    {"type": "str", "packet": "synthetic-example", "delay": 1},
    {"type": "base64", "packet": "AAEC", "delay": 0}
  ]
}}]}
```

Ranges are inclusive and reversed bounds normalize. Up to 16 items, 4096 bytes
per datagram, 1000 ms delay per item and 10 seconds total are accepted. Random
length is `rand`; optional `randRange` bounds byte values (default 0..255).
Literal encodings are `str` (UTF-8 without trimming), `hex`, standard padded
`base64`, or a byte array with absent/`array` type. Random and literal packets
cannot be combined. These are FinalMask spellings; the legacy `type: "rand"`
with `packet: "16-32"` is read only in freedom's `settings.noises` (see
[Freedom outbound](#freedom-outbound)).

`type: "exp"`, in any case, reads `packet` as a string of segments, as
Xray-core v26.10.31 does, built anew for every send:

```json
{"type": "exp", "packet": "<b 16 fe ff> <t> <c> <rc 3-5> <rd 2> <n> <r 4-8>", "delay": 1}
```

- `<b hex>` is these bytes; whitespace inside and a leading `0x` are dropped.
- `<r n>`, `<rc n>` and `<rd n>` are that many random bytes, ASCII letters or
  decimal digits; `n` is a size or a `from-to` range, both ends included, up
  to 65535.
- `<t>` is the Unix time in seconds and `<c>` the connection's count of `<c>`
  segments, from 1, each four big-endian bytes; `<n>` is eight random bytes.

Only whitespace may stand between segments. The packet's largest size must
fit 4096 bytes here; Xray-core lets a segment take up to 65535. The counter
runs across items, resets and socket rebinds of one connection, as Xray-core's
does on its masked socket. `tools/noise-exp-oracle` records how Xray-core's own
configuration reads a corpus of expressions and what its mask sends for them,
which `scripts/check-hysteria-interop.sh` regenerates and compares. A
nonempty `script`, which Xray-core runs in Lua instead of the items, is
refused until Lua is supported.

Each delay follows its noise packet, including the last packet before the
first QUIC datagram. No wrapper is installed when absent. With `reset: 0`,
later application datagrams pass unchanged; a positive range sets a sliding
idle interval in seconds after each successful send, as in pinned Xray-core.
Hop/rebind preserves the prelude progress and idle deadline of the logical
QUIC connection, matching Xray's mask outside its hopping socket. A new QUIC
connection starts a fresh prelude. Noise before a
Salamander entry is obfuscated; noise after Salamander is raw. Neither changes
the QUIC payload. All sends occur after host socket protection, timers are
asynchronous, and cancellation drops the state without a background sender.
Configured delays count against the existing connection deadline.

## v0.8 Linux TPROXY inbound

```json
{
  "inbounds": [{
    "tag": "transparent", "protocol": "dokodemo-door",
    "listen": "0.0.0.0", "port": 12345,
    "settings": {"network": "tcp,udp", "followRedirect": true},
    "streamSettings": {"sockopt": {"tproxy": "tproxy"}}
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
```

This is Linux transparent interception, requiring socket privileges
(`CAP_NET_ADMIN` or appropriate `CAP_NET_RAW`). The operator supplies TPROXY
firewall rules, fwmark policy routes, and an exclusion for the core's own
upstream traffic (for example by its dedicated UID). The core does not install
or change firewall rules, interfaces or routes. Optional nonnegative i32
`sockopt.mark` applies to the inbound and source-preserving UDP reply sockets;
it is not a general outbound socket-mark configuration.

Xray's newer protocol name `tunnel` is accepted as an alias of `dokodemo-door`.
Use separate IPv4/IPv6 inbounds; IPv6 listeners are v6-only. `network` accepts
`tcp`, `udp`, comma-separated values or arrays; `allowedNetwork` is the alias
and `network` takes precedence. Default is TCP. TCP uses the accepted socket's
original local address; UDP uses kernel original-destination ancillary data,
never the listener address as a substitute. Truncated/missing metadata is
rejected. UDP flows include both source and original destination in their key,
and replies retain the original destination address/port even after DNS or
sniffing rewrites. A connection directly to the local interception listener is
rejected to avoid self-dial loops.

Routing, sniffing, DNS/FakeDNS, protocol sessions, connection accounting and
close handling reuse the existing handlers. TCP is capped at 1024 concurrent
connections per listener. UDP uses the shared 1024-flow/64-pending-open global
budgets, at most 128 flows per listener and four queued packets per flow
(at most 256 KiB); idle expiry is 60 seconds and all tasks close on core stop.
Destination rewriting, `portMap`, REDIRECT mode, UNIX sockets and arbitrary
inbound stream/socket overrides are unsupported. Apple, Android and Windows
reject this inbound at start; mobile applications continue to use their TUN
adapter. UDP noise is available through their ordinary JSON configuration.

## v0.8 development client protocols

The current development tree adds Trojan, Shadowsocks 2022 and VMess AEAD.
These additions are not part of the published 0.7 artifacts. See the
[implementation evidence](v08-implementation-plan.md) for verified combinations,
resource bounds and remaining release gates. The active reference is Xray-core v26.11.9; unsupported options fail closed.

| Outbound | Settings | Import |
| --- | --- | --- |
| `trojan` | Flat `address`, `port`, `password`, optional `level`; or exactly one entry in `servers` | `trojan://password@host:port` with supported stream/security parameters; TLS default |
| `shadowsocks` | Flat `address`, `port`, `method`, `password`, optional `level`; or exactly one entry in `servers`. sing-box `uot`/`UoTVersion` are ignored, as in Xray-core, with a warning when `uot` is `true` | SIP002 `ss://` base64url or percent-encoded plain userinfo, SS2022 and AEAD methods; no SIP003 plugins or legacy all-base64 form |
| `vmess` | Flat `address`, `port`, `id`, optional `security`, `alterId`, `experiments`, `level`, `email`; or one `vnext` server with exactly one `users` entry | Common v2 base64 JSON and UUID-authority `vmess://` URI |

`trojan://` and URI-form `vmess://` links share one stream mapping. Besides
`type`, `security`, `host`, `path`, `serviceName`, `authority` and XHTTP `mode`,
it reads the parameters panels such as Remnawave write on every link:

| Parameter | Maps to | Accepted values |
| --- | --- | --- |
| gRPC `mode` | `grpcSettings.multiMode` | `gun` (default) or `multi`; others fail with an error naming `mode` |
| RAW `headerType` | none | absent, empty or `none`; `http` fails with an error naming `headerType` |
| WebSocket `heartbeatPeriod` | `wsSettings.heartbeatPeriod` | decimal seconds, 0..4294967295 |
| XHTTP `extra` | `xhttpSettings.extra` | a JSON object, validated like canonical JSON |
| TLS `alpn` | `tlsSettings.alpn` | comma-separated protocol names; an empty value, an empty entry or whitespace fails with an error naming `alpn`, because a TLS protocol name is 1..255 bytes |
| TLS `pcs` | `tlsSettings.pinnedPeerCertSha256` | Xray's comma-separated SHA-256 hex, with or without colons |
| TLS `vcn` | `tlsSettings.verifyPeerCertByName` | Xray's comma-separated names |
| TLS `cs` | none | always fails with an error naming `cs`: `cipherSuites` is not supported |
| `fm` | `streamSettings.finalmask` | the percent-encoded JSON object Remnawave writes from the host's `finalMask`, validated like canonical JSON; masks the core does not implement fail with an error naming `fm`. Empty means absent |

The base64 JSON `vmess://` form keeps the gRPC mode in `type`, as v2rayN
writes it; for other carriers `type` must be absent, empty or `none`. Any other
query parameter still fails the import.

Flat and legacy settings cannot be mixed. Trojan passwords are 1–4096 UTF-8
bytes, with no nonempty `flow`; public plaintext servers are rejected. SS2022
supports `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` and
`2022-blake3-chacha20-poly1305`. AES accepts up to eight colon-separated identity
keys; ChaCha accepts one. The encoded key string is bounded by 8192 bytes.
The classic AEAD ("AEAD-2017") methods use the same outbound, exactly as
Xray-core v26.10.21 names them: `aes-128-gcm` (`aead_aes_128_gcm`),
`aes-256-gcm` (`aead_aes_256_gcm`), `chacha20-poly1305`
(`aead_chacha20_poly1305`, `chacha20-ietf-poly1305`) and `xchacha20-poly1305`
(`aead_xchacha20_poly1305`, `xchacha20-ietf-poly1305`). Method names are
case-insensitive for both families, as upstream lowercases them. AEAD
passwords are any nonempty text, turned into a key with EVP_BytesToKey(MD5)
and per-connection subkeys with HKDF-SHA1. Like the reference, `none`/`plain`
and stream ciphers (`rc4-md5`, `aes-*-cfb`, `chacha20-ietf`, ...) are rejected
with an error at `method`; SIP003 plugins are excluded.

Classic AEAD streams send the salt and a record holding only the target
address, then payload records of at most 8158 bytes, as Xray's writer does. The
reader refuses records above the SIP004 0x3FFF limit (upstream's reader does not
check it, but no conforming server sends them) and ends the stream at an empty
record, as upstream does. Classic UDP packets carry a fresh salt each, so there
is no session, response binding or replay window; replies are authenticated
and the address type's high nibble is ignored, matching the reference client.
Salts are not replay-filtered on the client, as upstream's client does not.

VMess requires a UUID and `alterId` absent/zero. Body encryption is `auto`
(default), `aes-128-gcm` or `chacha20-poly1305`; `none`, `zero`, CFB and legacy
VMess authentication are unsupported. `experiments` recognizes the exact names
`AuthenticatedLength` and `NoTerminationSignal`, separated by `|`, without
duplicates. Unknown explicit encryption modes fail instead of falling back.
VMess record counters stop before nonce reuse; see the record-count bound in
the implementation evidence. No server-side proxy or response-command support
is implied by these client additions.

All three use the shared raw/WS/HTTPUpgrade/gRPC/XHTTP stream carrier and core
routing, accounting, SOCKS/HTTP/TUN and DNS paths. SS2022 ordinary UDP uses a
separate native UDP socket, independently of its TCP carrier; classic AEAD
does the same. Either family's datagram is limited to 8192 bytes including
framing, the pinned peer's receive buffer; a larger one is dropped alone and
the flow stays up, as on other UDP paths. VMess ordinary
UDP uses per-association XUDP except destinations on ports 53/443. Outer TLS
verification cannot be disabled. Live tests cover REALITY over raw/gRPC/XHTTP,
XHTTP H1/H2/H3 with independent downloads, and transport-layer chains among
the three protocols. REALITY over a chained stream, chained split downloads
and QUIC chaining retain the existing explicit graph restrictions.

Both pinned SS2022 reference servers retain a UDP session's first return
address. A network change that changes the client's external UDP port requires
a fresh association (for example, through the host's runtime reconnect).
Keeping the old cryptographic session does not provide seamless NAT rebinding.
Server restart with unchanged keys is verified on an existing client session;
forged, misbound and replayed replies remain rejected.

`mux.enabled: true` activates bounded shared Mux for these three outbounds and
for VLESS ([below](#vless-mux)). Both concurrencies are 16-bit integers, as in
Xray-core. TCP `concurrency` from zero up to 128 runs as 128 children per
parent, as Xray-core v26.11.9 runs it, a larger value stays, and a negative
value disables TCP multiplexing. `xudpConcurrency: 0` shares the TCP pool, a
positive value creates a separate UDP pool with that many children per
parent, and a negative value uses the native protocol UDP path.
`xudpProxyUDP443` is `reject` by default,
or `allow`/`skip`; `skip` bypasses Mux for UDP/443. Each pool opens children
on at most four parents, with 1024 lifetime child IDs per parent, Xray-core
v26.11.9's `maxReuseTimes`. A parent that
has used all 1024 IDs keeps serving its remaining children without counting
toward the four, so a long-lived child does not block new connections; a pool
holds at most 16 parents in all. Per-child queues are bounded (eight frames, at
most 64 KiB, per direction) and an empty parent times out after 30 seconds.
A child whose receive queue is full pauses its parent's reader until the child
drains, ends or is closed, as Xray-core's Mux client blocks on the session
pipe. A slow child is therefore never reset, but, as in Xray-core, it delays
its siblings' downloads on the same parent. Parent failure terminates its
children without replay. This Mux is distinct from XHTTP's existing `xmux`
transport pooling.

The pinned Xray XHTTP inbound permits only UDP Mux children. XHTTP therefore
requires `mux.concurrency: -1`; use positive `xudpConcurrency` for UDP pooling.
Enabling TCP Mux on XHTTP is rejected before dialing, including configurations
built through the Rust API. Ordinary TCP still uses XHTTP's own transport pool.

<a id="vless-mux"></a>
VLESS uses the same pools and limits. As in Xray-core's outbound handler, a
parent is the VLESS Mux command to `v1.mux.cool:9527`, carrying the user's flow
and VLESS encryption, over any supported carrier and security (raw,
WebSocket, HTTPUpgrade, gRPC, XHTTP; none, TLS or REALITY). UDP follows the
handler's order: `xudpProxyUDP443` first, then the XUDP pool, then the TCP
pool; only a flow no pool takes uses the VLESS UDP command, and only that
flow is subject to Vision's UDP/443 refusal. A pooled UDP/443 flow under
`allow` therefore reaches the server even with `xtls-rprx-vision`, exactly as
in Xray.

The pinned VLESS inbound restricts a Vision account's Mux connection to UDP
children and drops the whole connection on the first TCP child — the same
rule its XHTTP inbound applies. Xray's client still sends TCP children there;
xray-rust refuses the combination up front instead: with
`xtls-rprx-vision` or `xtls-rprx-vision-udp443`, `mux.concurrency` must be
negative (`$.outbounds[i].mux.concurrency` otherwise), and
`xudpConcurrency` pools XUDP while every TCP stream keeps its own Vision
connection. Without a flow, VLESS encryption pools both. Share links carry no
Mux settings, so the importer is unchanged.

The shared Rust importer, protocol capability discovery introduced in C ABI 1.8,
Swift adapter and Kotlin adapter expose all three formats. Host applications still own secure
profile persistence. Imports preserve credentials in the returned JSON, while
Debug/error descriptions redact them.

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
| `dns` | Hosts, string/object servers with managed selection policy, global and per-server `queryStrategy` including `UseSystem`, and `fakeIp` subset |
| `policy` | Level/system fields are parsed; runtime timeout/buffer behavior is a subset |
| `log` | Accepted for input compatibility, but runtime file logging is configured through the embedding API |
| `reverse` | The legacy reverse proxy, refused unless `null` with Xray-core's message: upstream removed it for the [VLESS reverse proxy](#vless-reverse-proxy) |
| `remarks`, `meta` | Subscription labels, such as those in Remnawave's XRAY_JSON format; `remarks` must be a string and `meta` an object (or null), and both are ignored, as in Xray-core |

Other top-level keys are rejected.

## Inbounds

| Protocol | Supported behavior | Unsupported or constrained behavior |
| --- | --- | --- |
| `socks` (alias `mixed`) | SOCKS5 `CONNECT` (and Tor's `RESOLVE`, as `CONNECT`), `UDP ASSOCIATE` unless `"udp": false`, SOCKS 4/4a `CONNECT`, HTTP `CONNECT` and plain HTTP forwarding on the same port, `userLevel`, sniffing; `auth` `noauth` or `password` with RFC 1929 `accounts` (or `users`) | GSSAPI; SOCKS5 and SOCKS 4 `BIND`; `accounts` with `noauth`; an `auth` other than `noauth` or `password`; an absent `udp` keeps `UDP ASSOCIATE` enabled, unlike Xray-core |
| `http` | HTTP `CONNECT` and plain HTTP forwarding, `accounts` (Basic), timeout-shaped policy, `userLevel`, sniffing | Transparent proxy mode |
| `tun` | Platform packet boundary or registered fd; port may be omitted | Platform interface creation and routes are host responsibilities |

`"auth": "password"` requires 1–64 `accounts` entries of `{"user", "pass"}`,
and makes the inbound offer only RFC 1929 username/password; a client offering
only no-auth receives `0xFF`. As in Xray-core v26.10.31, `users` is another
name for `accounts`, which replaces it unless `null`; each value holds at most
255 UTF-8 bytes, an absent or `null` one is empty, and a later account
replaces an earlier one of the same `user`. A failed login gets status `0xFF`,
as from Xray-core, and the version byte of the login is not checked.
Credentials are compared in constant time and redacted from `Debug` output and
diagnostics. Xray-core reads an `auth` other than `password` as `noauth`; it
is refused here, so that a misspelled `password` cannot leave the inbound
open.
RFC 1929 authenticates only the TCP control connection, so a password-protected
`UDP ASSOCIATE` accepts datagrams only from the client endpoint declared in the
request. A request that leaves the port unset, such as `0.0.0.0:0`, is refused
with a general failure reply and no relay socket: every local process shares the
loopback IP, so nothing would tie the first sender to the login. This differs
from Xray-core, which pins such an association to the first sender from the
control connection's IP. Xray-core
only consults `accounts` under `password`, so `accounts` with `noauth` is
rejected rather than leaving an inbound unauthenticated by accident. The loopback-only listener
rule and `allowUnauthenticatedLan` are unchanged.

The pinned Xray-core v26.7.28 SOCKS client itself sends `0.0.0.0:0` for UDP
association, so it cannot use this password-protected UDP path. See the
[compatibility consequence and evidence](xray-core-differences.md#password-protected-socks-udp-deliberate-restriction).

`"udp": false` refuses `UDP ASSOCIATE` as Xray-core does: the reply is
`REP = 0x07` (command not supported) with a `0.0.0.0:0` bind address, no relay
socket is created, nothing is dialed, and the control connection is closed.
Under `password` the refusal follows a successful login. `CONNECT` is
unaffected. An absent `udp` still accepts `UDP ASSOCIATE`, while Xray-core
treats it as `false`; set `udp` explicitly in profiles shared with Xray-core.
Whether to adopt Xray-core's default is an
[open compatibility question](xray-core-differences.md#socks-inbound-udp-false-and-the-absent-default).

A SOCKS5 request is read as Xray-core v26.10.31 reads it, within one
handshake timeout from the first byte of the greeting to the end of the
request:

- Only the command byte is checked, not the version or reserved byte. Tor's
  `RESOLVE` (`0xF0`) and `RESOLVE_PTR` (`0xF1`) connect, as `CONNECT` does.
  `BIND`, an unknown command, and `UDP ASSOCIATE` while `udp` is false get
  `REP = 0x07` before the address is read.
- A domain that starts with a digit or `[` and is an IP literal to Go's
  `net.ParseAddress` is that IP, so `ip` rules match it: `127.0.0.1`,
  `[::1]` and `127.0.0.1 ` are addresses. The brackets go, and white space
  around a name that starts or ends with neither a letter nor a digit is
  trimmed. An IPv4-mapped IPv6 address, as a domain or an IPv6 field, is IPv4.
- Any other domain may hold only ASCII letters, digits, `-`, `.` and `_`.
  Another one, an unknown address type, or a request cut short closes the
  connection without a reply, as in Xray-core. These used to get a general
  failure reply.
- UDP datagrams follow the same address rules; one that breaks them is
  dropped, as is a datagram without a payload. Their reserved bytes are not
  checked. A SOCKS outbound reads its server's replies by the same rules.

As in Xray-core, the first byte of a connection selects the protocol, and
`mixed` is only another name for `socks`:

- `5` is SOCKS5 as above.
- `4` is SOCKS 4 or 4a `CONNECT`. The user ID is ignored, an address whose
  first byte is zero is followed by a domain (4a), and the grant
  (`0x00 0x5A`, zero port and address) is sent before dispatch. The 4a domain
  is read with Go's `net.ParseAddress`, as above, but its characters are not
  checked. Other commands, a user ID or domain over 255 bytes, and any SOCKS 4
  request while the inbound requires a password are refused with `0x5B`; Xray
  refuses the last for the same reason, and allows user IDs up to 8 KiB. An
  empty or non-UTF-8 4a domain is also refused, where Xray-core grants it and
  then fails to dial.
- Anything else is an HTTP request, served as on the HTTP inbound below.
  Under `password`, it needs `Proxy-Authorization: Basic` with one of the
  `accounts`.

The HTTP inbound, and HTTP on a SOCKS port, answer as Xray-core's HTTP
server does:

- The request head is read as Go's `http.ReadRequest` reads it. The request
  line is three parts split at single spaces, ending in an HTTP version such
  as `HTTP/1.1` or `HTTP/2.0`. Every header line holds a colon after a name of
  token characters, or spaces, and at most one `Host` is given. A request
  that does not parse is closed without a reply.
- With accounts, `Proxy-Authorization: Basic` must name one, decoded as Go's
  `parseBasicAuth` does (case-sensitive `Basic `, padded base64, split at the
  first colon) and compared in constant time. Only the first
  `Proxy-Authorization` counts, as Go's `Header.Get` reads it. Otherwise the
  reply is Xray's `407 Proxy Authentication Required` with
  `Proxy-Authenticate: Basic realm="proxy"`.
- `CONNECT` is answered with `HTTP/1.1 200 Connection established` before
  routing, so a tunnel that then cannot open only closes. The tunnel routes
  and sniffs like a SOCKS `CONNECT`, under the user its credentials name.
  Bytes sent after the request head are its first bytes.
- A `CONNECT` target without a port, or with an empty one, goes to port 80,
  as Go's `ParseHost` reads it. A port is decimal digits, cut to 16 bits as
  Xray-core does, so `70000` is port 4464; port 0 is kept and fails when
  dialed, and other text closes the request. A host with a colon needs
  brackets.
- Any other request with an absolute target, such as
  `GET http://example.com/`, is forwarded as Xray-core's `handlePlainHTTP`
  forwards it. Each request is routed on its own, as protocol `http/1.1` and
  without sniffing, since Xray-core gives it a context without the inbound's
  sniffing settings. A target without a port goes to port 443 for `https`
  and 80 otherwise.
- The request goes on as Go's `Request.Write` writes it: the target's path
  and query, `Host` from the target in Punycode, any `User-Agent`, the
  body's length or chunking, `Connection: close`, and the other headers in
  name order, without hop-by-hop headers or those `Connection` names.
- The response comes back as Go's `Response.Write` writes it, without
  hop-by-hop headers. One of known length sets `Connection`,
  `Proxy-Connection` and `Keep-Alive` to keep the connection, which takes
  another request when this one sent `Proxy-Connection: keep-alive`;
  otherwise the connection closes after the response. One informational
  (`1xx`) head goes on as it came. A response that does not come or does not
  parse gets Xray's `503 Service Unavailable`, as does a request routed to a
  DNS outbound; a blackhole's reply is the response.
- A request that names no host, such as `GET / HTTP/1.1`, gets Xray's
  `400 Bad Request` with `Connection: close` and `Proxy-Connection: close`.
- Chunked bodies are decoded and chunked again. Go merges chunks whose
  headers it has already buffered, so chunk boundaries can differ from
  Xray-core's; the bytes they carry do not.

The HTTP inbound reads `accounts` as Xray-core does, or `users` when
`accounts` is absent or `null`, so an empty `accounts` requires nothing. Each
account is an object of a `user` and a `pass`, any strings, an absent or
`null` field reading as empty. A later account replaces an earlier one with
the same `user`. xray-rust takes at most 64 accounts, as for SOCKS; Xray-core
has no limit.

Common fields are `tag`, `protocol`, `listen`, `port`, `settings`, and
`sniffing`. Sniffing reads `enabled`, `destOverride`, `metadataOnly`,
`routeOnly`, `domainsExcluded` and `ipsExcluded` as Xray-core v26.10.31 builds
them, checking every field even while sniffing is off; a `null` object is no
sniffing. This is a routing-oriented subset rather than full Xray sniffing
behavior.

- `destOverride` is Xray's `StringList`: an array, or one string split at
  commas without trimming. It names `http`, `tls` (also spelled `https` or
  `ssl`) and `quic`, case-insensitively. `fakedns` and `fakedns+others` are
  accepted and add nothing: a fake IP is turned back into its domain whenever
  `dns.fakeIp` is enabled, with or without them. Any other name, including a
  `null` entry, is an error.
- `domainsExcluded` is a `StringList` of domain rules, read as a routing
  rule's `domain` is: plain text is a substring, matched against the sniffed
  name case-insensitively. A sniffed domain it matches never replaces the
  destination, for routing or for dialing.
- `ipsExcluded` is a `StringList` of IP rules, read as a routing rule's `ip`
  is. When the destination is an IP it matches, a sniffed domain never
  replaces it. A destination given as a name is not checked against it.

QUIC sniffing reads the SNI from a client's Initial packets (QUIC v1, v2 and
draft-29). A ClientHello larger than one datagram, such as Chrome's with a
post-quantum key share, is reassembled from the CRYPTO frames of several
Initial packets, coalesced or in later datagrams, as Xray-core does. While the
ClientHello is incomplete the flow waits for more datagrams, at most 200 ms and
32,767 bytes in total; then it is routed on its original destination. Every
datagram read meanwhile is forwarded in order. Other UDP traffic, and a
complete ClientHello without a server name, never wait. Unlike Xray-core, which
parses a zero-filled buffer, only the gap-free start of the CRYPTO stream is
parsed, so a missing piece is never read as part of a name.

## Outbounds and streams

`freedom` (alias `direct`), `vless`, `dns`, `blackhole` (alias `block`),
`loopback`, `socks`, and `http` are supported. DNS
outbound settings are described below, and [freedom](#freedom-outbound),
[blackhole](#blackhole-outbound), [loopback](#loopback-outbound),
[SOCKS](#socks-outbound) and [HTTP](#http-outbound) after the TLS notes.

VLESS and VMess settings are read as Xray-core v26.10.31 reads them:

- A non-null `address` is the simplified form. The server and its one user are
  fields of `settings` itself, and `vnext` is not read, though it must still
  decode.
- Otherwise there is one `vnext` server. VLESS accepts one or more users there
  and selects the first, where Xray-core wants exactly one; VMess wants exactly
  one, as Xray-core does.
- `id` is a UUID: 32 to 36 hex digits in Xray-core's groups, or 1 to 30 bytes
  of any text, which name the UUID Xray-core's `uuid.ParseString` makes of
  them. A server configured with the same text accepts it.

A VLESS user takes `encryption` (`none` when absent, where Xray-core requires
it), optional `level` and these flow values:

- empty/no flow;
- `xtls-rprx-vision`;
- `xtls-rprx-vision-udp443`.

`testseed` sets Vision's padding parameters, the first four numbers when there
are at least four, Xray-core's `[900, 500, 900, 256]` otherwise. `seed` is
ignored, and so is `email` except for a reverse proxy. VLESS `reverse` makes
the outbound the bridge of a [VLESS reverse proxy](#vless-reverse-proxy).

`testpre` keeps carrier connections opened ahead of the requests that take
them, as Xray-core's VLESS outbound does, at most 64 here:

- On the first request the outbound starts `testpre` dialers. Each opens a
  carrier connection, with TLS or REALITY and the transport's handshake done,
  and holds it until a request takes it. Then it waits 200 ms and opens the
  next.
- Every request takes a held connection: TCP and UDP requests, and Mux
  connections. One held for two minutes is closed and the next taken.
- A dialer dials where the latest request would: its server and download
  addresses, after `addressPortStrategy`, and its chain.
- Closing the outbound, as stopping the core does, closes the connections
  held.

On the raw transport, Vision switches each direction to direct mode on its own,
as Xray-core does. After the peer's `Direct` command the downlink is read from
the connection beneath TLS or REALITY — the socket, or the chained carrier
under `proxySettings` — while the uplink stays inside the session until this
side sends its own `Direct`. Until then, reads beneath a Vision flow stop at
TLS record boundaries so the outer session never consumes the cleartext that
follows its last record; a flow without Vision, or one that resolves to
`End`, drops that alignment.

The development `0.6` line also accepts bounded
`mlkem768x25519plus.{native|xorpub|random}.{1rtt|0rtt}` configurations with one
to eight ordered canonical unpadded base64url X25519 (32-byte) or ML-KEM-768
(1,184-byte) public keys. Optional padding uses the upstream alternating
length/gap syntax, capped at 32 parts, 65,553 bytes, one second per gap and five
seconds total. Encryption composes with raw, WebSocket, HTTPUpgrade, gRPC,
and XHTTP, including both Vision flows. Existing carrier/security constraints
still apply; REALITY remains unavailable on WebSocket/HTTPUpgrade. A missing encryption field defaults to `none`; explicit
non-string values fail. Malformed ML-KEM coefficients and low-order X25519
keys fail before dialing. Swift/Kotlin share-link import supports the same
bounded shape over `tcp`/`raw` and XHTTP/SplitHTTP with none/TLS/REALITY security,
including both Vision flows, and over WS/HTTPUpgrade/gRPC with none or TLS
security (gRPC also REALITY).
Encrypted links reject irrelevant transport/security fields and insecure TLS
verification; unsupported encryption errors redact the value. A 0-RTT ticket
is memory-only, is invalidated on rejected/cancelled resumption, and never
causes automatic early-data replay. See the
[wire/lifecycle design](vless-encryption-design.md) for limits and validation.

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
  `mldsa65Verify`. `spiderX` is the path crawled when the server answers
  with a real certificate instead of a REALITY one: empty means `/`, and any
  other value must start with `/`, as in Xray-core; its `p`, `c`, `t`, `i` and
  `r` query parameters set padding, concurrency, repeats, interval and return
  delay as in Xray-core, within the bounds listed in
  [REALITY real-certificate crawl](xray-core-differences.md#reality-real-certificate-crawl).

`tcpSettings.header.type` — equally `rawSettings.header.type` — may be absent,
empty, or `none`. Generic HTTP/2 and QUIC transports are not supported; HTTP/2
and QUIC v1 are available only as XHTTP's selected wire engines. [mKCP](#mkcp)
is described below. VLESS supports the shared [Mux](#vless-mux); `sendThrough`, multiple
VLESS servers, and protocol-layer chaining remain unsupported. The supported chaining subset
uses `streamSettings.sockopt.dialerProxy` with a nonempty outbound tag:

```json
{
  "tag": "entry",
  "protocol": "vless",
  "streamSettings": { "sockopt": { "dialerProxy": "exit" } }
}
```

Legacy `proxySettings` with `tag` and `transportLayer: true` is retained with
a migration warning; Xray v26.10.21 rejects that removed field. Both forms
cannot be combined. The referenced tag is resolved through the outbound graph before the
core starts. Missing targets, self-cycles, and multi-node cycles fail closed.
TCP Freedom and VLESS chains can use raw, TLS, WebSocket, HTTPUpgrade, gRPC,
and TCP-backed XHTTP carriers. Chained UDP/DNS, protocol-layer
`transportLayer: false`, REALITY inside a chain, and XHTTP HTTP/3 inside a
chain remain rejected rather than bypassing the configured edge. When a VLESS
hop can carry the next domain target, the target stays unresolved until that
hop; only terminal Freedom carriers use local destination resolution.

VLESS whose first selected user has `encryption: "none"` and no stream security fails closed for a
public server address, in the simplified form and in `vnext` alike, as
Xray-core v26.10.31 does. Such a server must use TLS, REALITY, or the
supported VLESS encryption subset unless
its IP is private, loopback or link-local as Go's `IsPrivate`, `IsLoopback`
and `IsLinkLocalUnicast` define them (`10/8`, `172.16/12`, `192.168/16`,
`fc00::/7`, `127/8`, `::1`, `169.254/16`, `fe80::/10`), which is Xray-core
v26.10.31's set; v26.10.21 also exempted the shared, benchmarking,
documentation, reserved, multicast and unspecified ranges. Domain exemptions
are `lan`, `localdomain`,
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

### Freedom outbound

`freedom` (alias `direct`) dials destinations itself. Its `settings` take
Xray-core v26.10.31's `redirect`, `userLevel`, `proxyProtocol` and
`finalRules`, the deprecated `domainStrategy` and `targetStrategy` (see the
[domain strategy socket option](#domain-strategy-socket-option)), and the
legacy `fragment` (see [TLS ClientHello
fragmentation](#v08-tls-clienthello-fragmentation)). As in Xray-core, the
removed `ipsBlocked` is accepted with a warning and ignored. The deprecated
`noises`, below, work, also with a warning.

`redirect` sends every connection and UDP flow to another destination. It is
`host:port`, read as Xray-core reads it with Go's `net.SplitHostPort`: an IPv6
host goes in brackets, and the port is decimal up to 65535.

- An empty host, `0.0.0.0` or `::` keeps the destination's address, and port 0
  keeps its port. So `"127.0.0.1:0"` changes only the address, and `":53"`
  only the port.
- A domain host resolves like any other destination, with freedom's domain
  strategy.
- Replies of a redirected UDP flow come from the destination the client
  addressed. Xray-core does the same, since its freedom stops attributing
  replies to their senders once it redirects.
- When freedom carries another outbound through `dialerProxy`, the redirect
  rewrites that outbound's server address as it rewrites any destination. If
  it replaces the address, the original server name is never resolved.

`userLevel` selects the policy level of freedom's own idle timer. As in
Xray-core, that timer runs beside the inbound's, so a connection closes after
the shorter of the two `connIdle` values. Without `userLevel`, freedom uses
level 0. The time allowed to open the connection still comes from the inbound's
`handshake`, and the relay buffer from its `bufferSize`. UDP flows keep their
fixed 60-second idle timeout.

`proxyProtocol` set to 1 or 2 makes freedom write a PROXY protocol header of
that version before anything else, built as go-proxyproto v0.16.0 builds it
for Xray-core; other values are ignored. The header names the inbound's client
(for TUN, the app's address) and the address freedom actually connected to.

- The family is IPv4 only when both ends are; otherwise an IPv4 end is written
  mapped into IPv6. Version 1 has no UDP form and writes `PROXY UNKNOWN`.
- A connection with no known client, such as the startup probe's, gets the
  unspecified header: `PROXY UNKNOWN`, or a version 2 `LOCAL`.
- The header goes on the raw connection beneath freedom's `fragment`, which
  therefore still sees the TLS hello as its first write and fragments it.
- A UDP flow sends the header as a datagram of its own before its first
  payload.
- When freedom carries another outbound through `dialerProxy`, the header goes
  first to that outbound's server and names the client of the connection it
  carries. When freedom itself dials through `dialerProxy`, there is no direct
  peer, and the header names `0.0.0.0:0`, as Xray-core's chained connection
  reports it.

`finalRules` decide, in order, which addresses freedom may reach. Each rule has
an `action`, `allow` or `block`, and optional `network`, `port` and `ip`
conditions. The first rule whose conditions all hold decides, and an address
that no rule matches is allowed.

- `network` is a comma-separated string or an array. Xray-core keeps a name
  other than `tcp` and `udp` as a network nothing travels over, so `"tcp, udp"`
  covers only TCP. An absent or empty list covers both.
- `port` and `ip` read as in routing rules. Unlike a routing rule, a final
  rule checks ports only once its list has a range, so `"port": 0` covers
  every port, while a reversed range such as `"2-1"` alone covers none.
- Rules check the destination after `redirect` rewrites it. A domain is
  checked by every address it resolves to with freedom's domain strategy, and
  the connection is blocked when any one of them is.
- A blocked TCP connection is held open, as in Xray-core: the client sees
  success, what it sends is discarded, and the connection closes once the
  client finishes or after `delay`. That is whole seconds drawn from an
  integer or a `min-max` range, 30 to 90 by default. `blockDelay`, its name
  before Xray-core v26.11.9, still works with a deprecation warning and wins
  over `delay` when both are set.
- `logLevel` is the severity at which Xray-core logs a rule's blocked
  connections: `none`, `debug`, `info` (the default, also empty), `warning`
  or `error`, matched without case; any other value is refused. xray-rust
  writes no log line for a blocked connection, so the level is checked and
  has no other effect.
- `delay`, `blockDelay` and a nonempty `logLevel` belong to block rules. An
  allow rule with any of them is refused, as Xray-core v26.11.9 refuses it.
- A blocked UDP flow discards its datagrams for the block delay. An open flow
  drops each reply whose source a rule blocks.
- When freedom carries another outbound through `dialerProxy`, the rules check
  that outbound's server. When freedom itself dials through `dialerProxy`, it
  is not the last hop, and Xray-core ignores its rules; the parser warns and
  drops them.
- Xray-core's default rules, which block private addresses for connections
  from its server inbounds, do not arise: xray-rust has only client inbounds.
  Its default for the connections a [VLESS reverse proxy](#vless-reverse-proxy)'s
  portal opens does: after the rules, every address is blocked.

Each item of `noises` is a datagram sent before a UDP flow's first payload,
after any PROXY protocol header, as Xray-core's freedom sends it. Xray-core
deprecates `noises` for the FinalMask noise mask and refuses the removed
`noise` object; so does the parser.

```json
"noises": [
  {"type": "rand", "packet": "16-32", "delay": "10-20", "applyTo": "ipv4"},
  {"type": "base64", "packet": "AAEC"}
]
```

- `type`, case-sensitive, says how the trimmed `packet` reads: `rand` a length
  or `min-max` range of random bytes, `str` the text itself, `hex` hex digits,
  and `base64` either alphabet, with or without padding. A range is drawn as
  Xray-core draws it, from its lower bound up to, but not including, its upper.
- `delay` is milliseconds, a number or range drawn the same way, waited after
  the item is sent.
- `applyTo`, case-insensitive, is `ip` (also `all`, or empty) for any
  destination, or `ipv4` or `ipv6` for one family. The family is that of the
  address the flow goes to, after `redirect`, which also receives the noises.
- Nothing is sent when `redirect` names port 53, as in Xray-core. A flow to
  port 53 still sends them when no redirect names that port. TCP is
  unaffected.

Differences from Xray-core:

- Queries that the built-in DNS client or the TUN DNS proxy route to a freedom
  outbound go to their DNS server even when that outbound has a `redirect`,
  `proxyProtocol`, `finalRules` or `noises`. Xray-core's DNS client dispatches
  them through freedom.
- A host that trims to nothing, such as `" :53"`, is rejected. Xray-core
  accepts it as an empty domain that never resolves.
- Xray-core's UDP is full cone: one freedom flow serves every destination a
  client source sends to, so only the first destination gets the PROXY protocol
  header and the noises. Here each destination is a flow of its own and gets
  both.
- With a FinalMask fragment instead of freedom's own `fragment`, Xray-core
  writes the header through the fragmenter, which then leaves the TLS hello
  unfragmented. Here the header always goes beneath the fragmenter.
- A domain is checked against what the managed resolver returns, as for
  dialing. Without a domain strategy, Xray-core checks it against the system
  resolver's answer.
- In a final rule, a numeric port above 65535 is rejected, as in routing
  rules. A negative `delay` or `blockDelay`, or one outside 32-bit integers,
  is rejected;
  Xray-core accepts both, wraps the latter, and on a negative delay later
  panics or closes at once. An unknown field in a rule is rejected rather than
  ignored.
- `noises` takes at most 16 items, 4096 bytes per packet and 1000 ms per
  delay, and refuses a negative delay and an unknown field. Xray-core sets no
  bounds and ignores unknown fields.

### Blackhole outbound

`blackhole` follows Xray-core v26.10.31 and is commonly the `block` target of
deny rules (ads, QUIC on UDP/443, other traffic a profile refuses):

```json
{ "tag": "block", "protocol": "blackhole", "settings": { "response": { "type": "http" } } }
```

Xray's protocol name `block` is an alias, as `direct` is for `freedom`.
`settings` may be absent, `null`, or an object with an optional `response`. A
present `response` must be an object whose case-insensitive `type` is `none`
(the default), `http` or `custom`. `custom` sends the bytes of
`customResponseData`, which must be padded standard base64 as Go's
`StdEncoding` decodes it; an absent or `null` value sends nothing, and other
types ignore the field, as Xray does. xray-rust also limits the decoded reply
to 65,535 bytes, so that a UDP flow can receive it in one datagram; Xray sets
no limit. As in Xray, a `null` or non-object response, a missing or `null`
type, and any other type fail parsing; unknown keys also fail here, where Go
would ignore them. `sendThrough`, enabled `mux`, and `streamSettings`
keep the generic outbound validation, but nothing in `streamSettings` is used
because nothing is dialed.

The handler never resolves a destination, dials, or opens a socket:

- SOCKS and HTTP `CONNECT` are acknowledged first (SOCKS success, HTTP
  `200 Connection established`), as Xray's inbounds do before dispatching.
  `none` then closes the connection. `http` writes Xray's reply
  byte-for-byte, as Go's `http.Response.Write` builds it (`HTTP/1.1 403
  Forbidden`, `Cache-Control: max-age=3600, public`, `Connection: close`,
  `Content-Length: 0`, with CRLF line endings), and half-closes; `custom` writes its bytes the same way. Xray holds the link for one second after that
  reply; xray-rust instead discards late client bytes for at most one second,
  so unread input does not turn the close into a reset.
- TUN TCP completes the client handshake in the userspace stack, as Xray's TUN
  inbound does, then sends FIN, preceded by the reply for `http`. Client
  upload is discarded during the one-second grace after an `http` reply;
  upload after that, or any upload with `none`, resets the flow, as when Xray
  interrupts the link. It is not counted as a TCP open error.
- UDP from SOCKS `UDP ASSOCIATE` and TUN is dispatched once per flow (client
  address and destination), as Xray dispatches a link once. `http` and a
  nonempty `custom` return their reply once, as a datagram from the
  destination the client addressed;
  `none` returns nothing, and nothing answers with an ICMP error. Later
  datagrams of the flow are discarded rather than routed again, until the
  flow has been idle for the 60-second UDP idle timeout (Xray waits for 30 to
  90 seconds of inactivity), the host closes it, or the SOCKS association
  ends. Unlike xray-rust, Xray keeps one SOCKS UDP link per client source
  address, routed by its first destination, and that link also carries the
  client's datagrams to later destinations.

A blackhole can be a rule `outboundTag`, the default first outbound, a balancer
candidate, or a balancer `fallbackTag`. Connection inventory and per-outbound
accounting record each blocked session, including a whole UDP flow, once and
with zero bytes. Paths that need a dialable transport fail closed with
`CoreError::BlackholeOutbound` instead: a DNS server or TUN DNS upstream whose
queries route to it, and a startup probe of it, fail without dialing;
observatory probes record it as unhealthy. `proxySettings` chains to or from a
blackhole are rejected by core compilation.

### Loopback outbound

`loopback` routes a connection again, as if it came from an inbound with the
tag it names, as Xray-core v26.10.31's loopback does:

```json
{ "tag": "again", "protocol": "loopback", "settings": { "inboundTag": "loopback-in" } }
```

A rule can then match `"inboundTag": ["loopback-in"]` to send the connection
on, for example after a first set of rules chose to treat it apart.

- `settings` may be absent or `null`, and `inboundTag` a string or `null`; an
  absent or `null` tag is empty, as in Xray-core. Unknown fields are refused.
- Routing again keeps the connection's source, local address and user, but
  not the protocol or `attrs` that sniffing found, since Xray-core's loopback
  starts a new session content.
- It checks the address the connection goes to, which differs from the one
  routing checked when sniffing with `routeOnly` found a domain: routing
  again then sees the IP.
- It makes none of the DNS lookups of `IPIfNonMatch` and `IPOnDemand`, as
  Xray-core skips DNS resolution for a loopback's connections.
- TCP and UDP from SOCKS, HTTP and TUN go through loopbacks, as do DNS
  queries that rules route to one. A loopback can be a rule's `outboundTag`,
  the default first outbound, or a balancer candidate. Connection inventory
  and accounting record the outbound the connection ends at.
- Paths with nothing to route again, such as a probe of the loopback itself,
  fail with `CoreError::LoopbackOutbound`. `proxySettings` chains to or from a
  loopback are rejected by core compilation.

Differences from Xray-core:

- A connection may pass at most 8 loopbacks in a row; a longer chain, such as
  a loopback that routes back to itself, fails it. Xray-core sets no limit
  and, on a loop, recurses until it runs out of stack and exits.
- The loopback's own `sniffing` is read as an inbound's, but enabling it is
  refused for now; Xray-core sniffs the connection again with it.

### VLESS reverse proxy

A VLESS outbound in the simplified form takes `reverse`, which makes it the
bridge of Xray-core v26.10.31's VLESS reverse proxy. The bridge keeps tunnels
open to its server; the server, the portal, opens TCP and UDP connections back
through them to the services the bridge's routing lets it reach:

```json
{
  "outbounds": [
    {"tag": "portal", "protocol": "vless",
     "settings": {"address": "portal.example.com", "port": 443,
       "id": "<uuid>", "encryption": "none", "flow": "xtls-rprx-vision",
       "email": "home", "reverse": {"tag": "from-portal"}},
     "streamSettings": {"security": "reality", "realitySettings": {}}},
    {"tag": "home", "protocol": "freedom",
     "settings": {"finalRules": [{"action": "allow", "network": "tcp",
       "ip": ["192.168.1.10"], "port": "22,443"}]}}
  ],
  "routing": {"rules": [{"inboundTag": ["from-portal"], "outboundTag": "home"}]}
}
```

- `tag` must not be empty. `sniffing` reads as an inbound's `sniffing`. The
  `vnext` form refuses `reverse`, and unknown fields in it fail parsing.
- Each connection is routed as if an inbound tagged `tag` had accepted it:
  `source` and `sourcePort` match the portal's client, `localIP` and
  `localPort` the address that client reached on the portal, `user` the
  outbound's `email`, and `protocol` and `attrs` what `reverse.sniffing`
  finds. Access logs name the portal's client.
- A freedom outbound refuses these connections unless its `finalRules` allow
  them, as Xray-core's freedom gives connections from a reverse proxy a final
  rule that blocks every address: a refused TCP connection is held and
  discarded as a blocked final rule holds it, a refused UDP flow drops its
  datagrams. Write an `allow` rule for each service the portal may reach.
- The freedom a `dialerProxy` chain ends on refuses them too, unless its
  `finalRules` allow the hop before it: routed to a `vless` outbound with
  `dialerProxy: "direct"`, a connection opens only when `direct` allows the
  VLESS server, as Xray-core hands each link of a chain the connection's
  context. A freedom that itself dials through `dialerProxy` applies no rule.
  Under a link whose connections other flows share, a `mux` or `testpre` one
  or a gRPC carrier, the chain is left as it is: Xray-core opens those
  connections without the connection's context, and a refused shared
  connection would stall every flow on it. Under an XHTTP link the connection
  is refused before anything is dialed unless the freedom the chain ends on
  allows the link's server, and so through a dedicated freedom fragment
  outbound that `dialerProxy` names, which this implementation folds into the
  outbound, unless that freedom's `finalRules` allow the server, for UDP flows
  as well; Xray-core refuses these only on the dials that carry them
  ([difference](xray-core-differences.md#vless-reverse-proxy)). UDP does not
  go through other `dialerProxy` chains here at all.
- Other outbounds take what routing sends them: another proxy, `blackhole`,
  `dns`. Without a matching rule the first outbound does; when that is the
  bridge itself, its server refuses the request, as a user with `reverse` may
  not proxy forward.
- A tunnel is a VLESS request with the reverse command, which names no
  address, over the outbound's whole carrier: every transport and security,
  VLESS `encryption`, Vision, the TCP masks, `sockopt` and `dialerProxy`. Its
  header waits 500 ms for a payload, as any VLESS request's does, and then
  goes alone, Vision padding an empty frame; the carrier is dialed up to five
  times. Inside it the portal is a Mux.Cool client and the bridge its server.
  `testpre` is not used and the outbound's `mux` applies only to connections
  routed to it, as in Xray-core. Through `dialerProxy`, the freedom the chain
  ends on refuses the tunnel unless its `finalRules` allow the portal's
  address, as Xray-core's bridge then never connects. Over an XHTTP carrier,
  and through a folded freedom fragment outbound, the tunnel is refused before
  it dials unless that freedom allows the portal; over gRPC the chain is left
  as it is.
- Two seconds after the start, and every two seconds after that, the bridge
  opens a tunnel when none is active or the active ones hold more than 16
  sessions each. A tunnel stops being active when it closes or when the
  portal's control session asks it to drain, which Xray-core's portal does
  once more than 256 sessions, its control session included, were opened on it. A draining tunnel finishes its sessions
  and, like any tunnel, closes once it held none for a whole minute.
- A core with a bridge starts without an inbound.
- The legacy `reverse` at the root of the configuration, with `bridges` and
  `portals`, fails parsing with Xray-core's message: upstream removed it in
  v26.4.25 for this proxy. The portal's side, a VLESS inbound whose user has
  `reverse`, is not supported, as no VLESS inbound is.

Security: the portal chooses the destinations; the bridge's routing and
freedom's final rules decide which it opens, and nothing else does. A freedom
`allow` rule without conditions opens everything the bridge reaches, its own
loopback and local network included, to every client of the portal. Route the
reverse tag explicitly and allow only the services meant to be reached.

Mobile platforms: the tunnel is a long-lived outbound connection.

- On iOS it lives in the Network Extension, which runs in the background while
  the VPN is connected. A host running the core in its app process loses the
  tunnel when iOS suspends the app, and the monitor opens a new one once it
  runs again. On Android the VPN service keeps it; Doze may hold the network
  back, and the tunnel is replaced once the network returns.
- A network change usually leaves the tunnel's socket dead without an error,
  and the bridge writes only in answer to the portal. The loss shows when the
  carrier reports it, or when nothing crossed the tunnel for the `connIdle` of
  the outbound user's policy level: 300 seconds by default, while the portal
  sends a control message every 10 seconds. A `connIdle` of 30 seconds for
  that level brings the tunnel back sooner. The Hysteria and WireGuard rebind
  calls do not touch it.
- While the portal is unreachable the bridge dials up to five times every two
  seconds or so, as Xray-core does, with no longer backoff.

Differences from Xray-core:

- A tunnel holds at most 512 sessions at once and a bridge at most 16
  tunnels, draining ones included; a session past the bound is refused with an
  End that carries the error flag. Xray-core sets no bound.
- Each destination of a UDP session is a flow of its own, routed and relayed
  as a SOCKS association's flows are, and the session ends once its flows went
  idle, after 60 seconds. Xray-core routes the session once, by its target,
  and sends every datagram through that route to the address it names.
- With `dns.fakeIp` on, a fake IP in a session's target turns back into its
  domain, as for every inbound here; Xray-core does so only when sniffing names
  `fakedns`.
- A bridge whose outbound cannot be built, such as one with Vision but neither
  TLS nor REALITY, fails the core's start; Xray-core starts and fails every
  dial of the tunnel.
- A frame of more than 8 KiB, metadata that Xray-core's portal never writes, or
  a session ID used twice on a tunnel closes the tunnel.

### SOCKS outbound

`socks` is a SOCKS5 client for an upstream proxy and accepts both settings
shapes of Xray-core v26.7.28, the flat form and the legacy `servers` form:

```json
{ "tag": "upstream", "protocol": "socks",
  "settings": { "address": "192.0.2.10", "port": 1080,
                "user": "synthetic-user", "pass": "synthetic-pass" } }
```

```json
{ "tag": "upstream", "protocol": "socks",
  "settings": { "servers": [{ "address": "192.0.2.10", "port": 1080,
    "users": [{ "user": "synthetic-user", "pass": "synthetic-pass" }] }] } }
```

The two forms cannot be mixed: Xray silently prefers the flat `address` when
both are present, while xray-rust rejects the combination. `servers` must hold
exactly one entry and `users` at most one, as in Xray. The address is an IP
literal (brackets allowed) or a domain of 1–255 characters without whitespace
or control characters, and the port must be nonzero (Xray accepts zero).
`level` (0–255) selects the policy level and applies with or without
credentials, whereas Xray drops a flat `level` that has no `user`. `email` is
type-checked and ignored. Unknown keys fail parsing.

Credentials are optional. `user` and `pass` are both absent, which offers only
the no-authentication method, or both strings of 1–255 UTF-8 bytes, which
offers only RFC 1929 username/password authentication. Xray silently drops a
`pass` without `user` and sends empty credentials for `users: [{}]`; xray-rust
fails closed on a lone `user` or `pass`, an empty or oversized value, and a
`users` entry without credentials. Credentials are redacted from the parsed
model's debug output and are never echoed in diagnostics.

- TCP uses `CONNECT`. UDP from SOCKS, TUN and DNS flows uses `UDP ASSOCIATE`
  (RFC 1928 section 7), one association per flow, with the same flow limits
  and idle timeout as the other UDP outbounds. The control connection goes
  through `streamSettings`, so its transport and `tls` or `reality` apply to
  it, while the datagrams travel over a plain UDP socket to the relay,
  protected like the other native UDP outbounds. As in Xray, they are never
  encrypted and never take the transport.
- The request declares the relay socket's real port with an unspecified IP,
  where Xray always sends `0.0.0.0:0`. Servers that admit only the declared
  client endpoint, such as a password-protected xray-rust SOCKS inbound, pair
  that port with the control connection's source IP, and Xray-core's own
  SOCKS server admits datagrams only from that IP; the control connection and
  the socket therefore use the same address family, trying the server's
  resolved families in order. A relay of the other family moves on to the
  next family, since a gRPC or XHTTP connection shared between flows may
  carry the control connection over either. A relay address of `0.0.0.0` or
  `::` names the server: on `raw` without REALITY the connected TCP peer,
  which with Happy Eyeballs may be a later DNS candidate; over the other
  transports and REALITY, which do not expose their peer, the server's first
  address of the socket's family, as Xray names the configured server
  address. IPv4-mapped IPv6 proxy literals use an IPv4 UDP socket, matching
  TCP dialing and mobile carrier exclusions. A bound domain is accepted only
  as an IP literal, and a relay of the other family when no family is left, a
  zero relay port or a rejected request fails the flow.
- The flow ends when the server closes the control connection; Xray does not
  notice that and waits for its idle timer. Received datagrams that are
  malformed, fragmented (`FRAG` ≠ 0) or not from the relay are dropped one by
  one, while Xray ends the whole association on the first bad datagram. A
  datagram whose header and payload exceed 8 KiB, the buffer Xray reads relay
  datagrams into, is refused with an error that ends the flow, instead of the
  empty datagram Xray sends.
- Enabled `mux` fails parsing; SOCKS is not a Mux carrier.
- `streamSettings` may select any transport, as in Xray: `raw`/`tcp`,
  WebSocket, HTTPUpgrade, gRPC or XHTTP, with `security` `none`, `tls`, or
  `reality` on `raw`, gRPC and XHTTP.
- Unlike Trojan and VLESS, a plaintext public server is accepted, because SOCKS5
  proxies are usually plaintext, and so is a plaintext XHTTP `downloadSettings`
  leg to one. Without `tls` or `reality`, RFC 1929 sends the username and
  password in cleartext, so anyone on the path can read and replay them. Use
  `tls` or `reality`, or keep a credentialed proxy on loopback or a trusted
  network.
- Chaining uses `sockopt.dialerProxy` (or the warned legacy `proxySettings` form).
  A SOCKS outbound can be the hop that carries another TCP outbound, and it can
  itself be carried over another outbound's TCP carrier. Chained UDP/DNS,
  including UDP through a chained SOCKS outbound, and REALITY inside a chain
  stay rejected. Dedicated fragment handlers still use the normalization described above.

`scripts/check-socks-interop.sh` verifies this subset against pinned Xray-core
v26.7.28: both settings forms, TCP authentication over plain TCP and UDP
authentication over plain or TLS control connections, wrong/missing credentials,
UDP IPv4/IPv6/domain destinations and the 8 KiB framing boundary,
socket protection, connection close, and
TUN UDP/DNS with `StaticOnly` bootstrap. Destination names are resolved by the
proxy, not the local bootstrap resolver. The reverse-direction test verifies
that the Go client authenticates for TCP but its undeclared UDP port remains
refused by our password-protected inbound. Tests use loopback; they do not
establish physical-device VPN routing, NAT behavior, an IPv6 proxy carrier,
TCP chaining, or `probeOutboundUrl` interoperability.

`scripts/check-v08-carrier-interop.sh` runs TCP, with a server-first greeting
and a 128 KiB echo, and UDP at 1, 1200 and 4096 bytes through Xray-core
v26.10.31's password-protected SOCKS inbound over WebSocket, HTTPUpgrade, gRPC
and XHTTP (`packet-up`) in plaintext, the same four over TLS (XHTTP
`stream-up` over HTTP/2), and REALITY over `raw`, gRPC and XHTTP
(`stream-one`).

Mobile carrier preparation is tracked separately in
[PR #86](https://github.com/aimalygin/xray-rust/pull/86). UDP support does not
remove the requirement to pin proxy hostnames before entering `StaticOnly`
mode or to install Apple carrier exclusions. The HTTP outbound from #79 is
described [below](#http-outbound).

### HTTP outbound

`http` asks an upstream HTTP proxy for a `CONNECT` tunnel (RFC 9110
section 9.3.6), optionally with Basic authentication (RFC 7617): over
HTTP/1.1, or over [HTTP/2](#http2-connect) when the proxy's TLS picks `h2`, as
Xray-core does. It accepts both settings shapes of Xray-core v26.7.28:

```json
{ "tag": "upstream", "protocol": "http",
  "settings": { "address": "192.0.2.20", "port": 3128,
                "user": "synthetic-user", "pass": "synthetic-pass" },
  "streamSettings": { "security": "tls",
                      "tlsSettings": { "serverName": "proxy.example" } } }
```

```json
{ "tag": "upstream", "protocol": "http",
  "settings": { "servers": [{ "address": "192.0.2.20", "port": 3128,
    "users": [{ "user": "synthetic-user", "pass": "synthetic-pass" }] }] } }
```

Server rules match the [SOCKS outbound](#socks-outbound): the forms cannot be
mixed, `servers` holds exactly one entry and `users` at most one, the address
is an IP literal (brackets allowed) or a 1–255 character domain without
whitespace or control characters, the port is nonzero, `level` (0–255) selects
the policy level with or without credentials, and `email` is type-checked and
ignored. Unknown keys fail parsing.

Credentials are absent, which sends no `Proxy-Authorization`, or a `user` of
1–1024 bytes without `:` and an optional `pass` of at most 1024 bytes; neither
may contain control characters, which RFC 7617 excludes. A missing `pass` is
the empty password, so a token-only proxy works as in Xray. Xray silently drops
a flat `pass` without `user`, ignores an empty `user`, and sends empty Basic
credentials for `users: [{}]`; xray-rust rejects all three. Credentials are
redacted from the parsed model's debug output and never echoed in diagnostics.

`headers` adds request headers, set on each `CONNECT` as Xray-core v26.10.31
sets them:

```json
"headers": { "X-Forwarded-For": "{{.Source.Address}}", "X-Target": "{{.Target}}" }
```

- They are set after the credentials, so a `Proxy-Authorization` among them
  replaces the account's, and before Xray's masquerade block, which a custom
  `User-Agent` other than a browser keyword (`chrome`, `firefox`, `safari`,
  `edge`, `curl`, `golang`) leaves out. `Host` and `Proxy-Connection` come
  from the request itself, as in Xray-core, so theirs are ignored.
- Names are canonicalized as Go's `Header.Set` does, so `x-target` is sent as
  `X-Target`, and a later name that canonicalizes alike replaces an earlier
  one. A `null` value is empty. Line breaks in a value become spaces, and
  surrounding spaces and tabs are trimmed, as Go writes it.
- Each value is a Go template. `{{.Target}}` is the destination the tunnel
  goes to, as Xray-core prints it (`tcp:192.0.2.7:443`, `tcp:[2001:db8::1]:443`
  or `tcp:example.com:443`), and `{{.Source}}` the client the connection came
  from (`tcp:0.0.0.0:0` for one no inbound made, such as a probe). Each has
  `.Address`, `.Port`, `.Network` (`TCP`) and `.NetAddr`. Comments and the
  `{{-` and `-}}` trim markers are read as Go reads them. On a `dialerProxy`
  hop, `{{.Target}}` is the next server.

Unlike Xray-core, other template actions (functions, pipelines, conditions,
other fields), a name that is not an HTTP token, which Go would drop, and a
control character other than a tab or line break, which Go would send as it
is, are refused when the configuration is read, where Xray-core would fail or
send them on each connection. A profile takes at most 64 headers of at most
8 KiB each.

The `CONNECT` request is otherwise byte-for-byte the one the pinned Go client
writes: `Host`, then `User-Agent`, then the remaining headers
sorted by name, with `Proxy-Authorization`, `Proxy-Connection: Keep-Alive` and
Xray's Chrome navigation masquerade block, whose browser versions are drawn as
described [for WebSocket](#the-masqueraded-browser-version-is-redrawn-on-every-start).
The request target is `host:port`, with IPv6 in brackets and IPv4-mapped IPv6
sent as IPv4. Domains are passed to the proxy unresolved; a domain outside the
RFC 3986 `reg-name` characters, including a non-ASCII name, fails the flow
rather than being converted to Punycode as Go does.

- Only status 200 opens the tunnel, as in the pinned Xray client, although RFC
  9110 allows any 2xx; 407 and every other status fail the flow without echoing
  the proxy's reason phrase. Xray-core tries a failed tunnel five times, each
  retry 100 ms later than the one before, a refusal included; xray-rust tries
  once. The status line must be `HTTP/1.0` or `HTTP/1.1`,
  header lines must be well formed (bare `LF` line ends and obs-fold are
  accepted), and `Content-Length` or `Transfer-Encoding` on the 200 are ignored
  as RFC 9110 requires.
- The response head, plus any tunnel bytes read with it, is limited to 16 KiB;
  Go reads it without a limit. Bytes that arrive after the head in the same
  read are delivered to the client first. Xray reads the head through a
  `bufio.Reader` it then discards, so it loses them.
- `streamSettings` may select any transport, as in Xray: `raw`/`tcp`,
  WebSocket, HTTPUpgrade, gRPC or XHTTP, with `security` `none`, `tls`, or
  `reality` on `raw`, gRPC and XHTTP. On `raw`, TLS offers what Xray-core
  offers: a shaped hello (`chrome` unless `fingerprint` names another) sends
  its profile's ALPN, `h2` and `http/1.1` for `chrome`, unless `alpn` is
  exactly `["http/1.1"]`; `fingerprint: "unsafe"` sends the configured list as
  it is, and none when it is empty, where Xray-core sends `h2` and `http/1.1`.
  The proxy's pick decides the tunnel: HTTP/2 for `h2`, HTTP/1.1 for
  `http/1.1` or no pick, and any other protocol fails the flow, as in
  Xray-core. Every other transport, and REALITY, carries HTTP/1.1 whatever
  was negotiated, as there: Xray-core reads the protocol only from the raw
  transport's TLS. Its own REALITY server negotiates none.
- Only TCP is supported. UDP routed to an HTTP outbound is refused without
  dialing the proxy, and DNS queries over UDP through it fail, so use `tcp://`
  DNS servers on such a route. Enabled `mux` fails parsing.
- A plaintext public server is accepted, because HTTP proxies are usually
  plaintext, and so is a plaintext XHTTP `downloadSettings` leg to one.
  Without `tls` or `reality`, the Basic credentials and the destination of
  every tunnel travel in cleartext; use `tls` or `reality`, or keep a
  credentialed proxy on loopback or a trusted network.
- Chaining uses `sockopt.dialerProxy` (or the warned legacy `proxySettings` form)
  in both directions: an HTTP outbound can carry another TCP outbound, and it
  can ride another outbound's TCP carrier. `probeOutboundUrl` works through it.

#### HTTP/2 CONNECT

When the proxy's TLS picks `h2`, the tunnel is an HTTP/2 stream (RFC 9113
section 8.5), opened as Xray-core v26.10.31 opens it with Go's HTTP/2 client:

- The connection opens with Go's SETTINGS: push disabled, a 4 MiB stream
  window, a 1 MiB frame and a 10 MiB header list. It grants 16 MiB of
  connection receive credit, as XHTTP does, where Go grants 1 GiB.
- The request carries `:method` and `:authority` only, and the fields of the
  HTTP/1.1 request under Go's HTTP/2 rules. Names are lowercase. `Host`,
  `Content-Length`, `Proxy-Connection` and the other connection-specific fields
  are not sent. `Cookie` is split at each `;`. An empty `User-Agent` is left out,
  and a missing one, as with `golang`, is `Go-http-client/2.0`.
  `accept-encoding: gzip` follows unless the request has an `Accept-Encoding`
  or a `Range`, which the masquerade block does not set.
- Custom values are sent as their templates fill them in, untrimmed. A value
  with a line break fails the tunnel, as do an `Upgrade`, `Transfer-Encoding` or
  `Connection` that Go refuses. A `TE` other than `trailers` fails too, where Go
  sends it although HTTP/2 forbids it. `Proxy-Authorization` is never indexed
  by HPACK.
- Later tunnels share the connection while it is up and below the proxy's
  concurrent stream limit, as Xray-core keeps one connection per proxy. At the
  limit, or once the proxy sends GOAWAY, the next tunnel dials a new connection,
  which is kept instead. Stopping the core lets the connection close once its
  tunnels end; Xray-core keeps it for the life of the process.
- A refused tunnel fails alone. Xray-core closes the shared connection with it,
  and every tunnel on it.
- The client's end of a tunnel reaches the proxy as `END_STREAM`, the HTTP/2
  form of its FIN. Xray-core resets the stream with `CANCEL` when the tunnel
  closes.
- The tunnel's first bytes follow the proxy's 200; Xray-core sends them right
  after the request.

Xray-core's own HTTP inbound reads HTTP/1.1 only. Behind TLS it needs
`"alpn": ["http/1.1"]`: otherwise it picks `h2`, and Xray-core's HTTP outbound
fails on it as this one does. Imported `https://` links offer `http/1.1` alone.

`scripts/check-http-interop.sh` verifies this subset against the pinned
Xray-core v26.7.28 HTTP inbound: both settings forms, Basic and no-auth tunnels
to IPv4 and Xray-resolved domain targets over plain TCP and TLS with a `chrome`
fingerprint, and refused wrong or missing credentials. It also captures the
pinned Go client's `CONNECT` and compares it with ours. Its TLS inbound sets
`alpn: ["http/1.1"]`, as that inbound needs. In-process tests cover IPv6
targets, early tunnel bytes, every refused status, HTTP/2 tunnels with `chrome`
and `firefox` hellos against a proxy that prefers `h2`, refusals and shared
connections over HTTP/2, HTTP/1.1 against an HTTP/1.1-only proxy, with
`alpn: ["http/1.1"]` and with `unsafe`, UDP refusal, chaining both ways and
outbound probes. Android and Apple prepare the
proxy's carrier hostname like a SOCKS server's. Tests use loopback; they do not
establish physical-device VPN routing.

`scripts/check-v08-carrier-interop.sh` runs the same server-first TCP flow as
for [SOCKS](#socks-outbound) through Xray-core v26.10.31's HTTP inbound, with
Basic credentials, over the same eleven transports and securities.

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

HTTPUpgrade now sends a fresh 16-byte base64 `Sec-Websocket-Key` and
`Sec-Websocket-Version: 13`, matching v26.10.21. Explicit canonical spellings
in the header map override those defaults; arbitrary header key casing keeps
the existing Go-map compatibility behavior. This still carries a raw upgraded
stream, without WebSocket data-frame encoding.

The pinned independent sing-box 1.13.20 server rejects a nonempty WebSocket key
with HTTP 404. For that server, set
`httpupgradeSettings.headers: {"Sec-Websocket-Key": ""}` explicitly (including
that spelling). The independent Trojan/VMess matrix uses this override; a
separate negative check verifies rejection of the new default. Xray-core
v26.10.21 interop retains the default nonempty key.

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

With `encryption: "none"`, Xray refuses both pairings too, so refusing them
here only moves the failure earlier — the two land in different places, but neither reaches the wire:

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
never retries over H2/H1. REALITY is supported on H2. Without VLESS encryption,
Vision is refused: as with
gRPC, XHTTP returns an HTTP stream wrapper rather than the TLS/REALITY
connection Vision needs to inspect directly, and xray-core refuses the same
shape later in its VLESS outbound. Enabling VLESS encryption provides the
protected layer required by Vision, including on XHTTP.

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
  `scStreamUpServerSecs`, `serverMaxHeaderBytes` and `h2Params`;
- Rust-specific H2 receive credit: `h2StreamReceiveWindow`;
- `xmux`, with `maxConcurrency`, `maxConnections`, `cMaxReuseTimes`,
  `hMaxRequestTimes`, `hMaxReusableSecs`, and `hKeepAlivePeriod`.

`h2StreamReceiveWindow` is an optional **xray-rust extension**, in bytes.
It accepts an integer from **65,535 through 16,777,216** inclusive. An absent
field or `null` selects **4,194,304 bytes (4 MiB)**; zero, fractional numbers,
strings and ranges are rejected. It controls the receive window of each
HTTP/2 stream opened by this XHTTP carrier, in all XHTTP modes, including
reused, rotated and replacement connections. It does not change upload
credit, H1, H3, gRPC or the fixed **16 MiB connection receive window**.
Go Xray-core does not implement this extension.

For example, the following is a `streamSettings` fragment:

```json
{
  "network": "xhttp",
  "security": "tls",
  "tlsSettings": { "serverName": "proxy.example", "alpn": ["h2"] },
  "xhttpSettings": {
    "path": "/split/",
    "mode": "packet-up",
    "h2StreamReceiveWindow": 4194304
  }
}
```

The same field is accepted under the legacy `splithttpSettings` alias.
When `extra` is present, put the field **inside `extra`**: the usual
replacement semantics apply and an outer value is discarded. An independent
`downloadSettings` carrier uses its own `xhttpSettings.h2StreamReceiveWindow`;
it does not inherit the upload carrier's override. H1/H3 carriers accept a
valid value but do not use it.

Larger values permit more unread data per stream; they do not eagerly
allocate the entire window. At 8 MiB, two entirely unread streams can exhaust
the 16 MiB connection credit; at 16 MiB, one can. This setting is not a
process-memory budget, and separate H2 connections have separate limits.
The 4 MiB default retains the issue #28 policy. See the
[window audit](transport-window-audit.md) for measured tradeoffs and the
[deferred protocol decisions](transport-window-followups.md).

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
`noSSEHeader`, `serverMaxHeaderBytes` and `h2Params` (added in Xray-core
v26.10.31; any JSON value) are accepted but have no client-side effect because
they configure Xray's inbound response/listener. A null
`downloadSettings` is equivalent to absent. A populated effective value selects
one independent XHTTP download stack, requiring explicit `address`, `port`, and
`network: "xhttp"` (or `splithttp`, including the `method` alias). It has its own
TLS/REALITY identity, HTTP version, XHTTP settings, QUIC policy and XMUX pool.
The download request uses the upload's session ID. Upload modes are `packet-up`
and `stream-up`; REALITY `auto` becomes `stream-up` when downloadSettings exists.
`stream-one`, effective nested downloads, protected-upload/plaintext-download
combinations, and transport-layer chaining with downloads are refused. Without
VLESS encryption the independent plaintext destination must satisfy the same
private/test address exemption as the upload. Unknown fields and `allowInsecure`
remain errors. The endpoints must converge on the same server session namespace.
See [download design](xhttp-download-design.md) for ownership and evidence.
Canonical JSON is supported; Swift/Kotlin share-link import does not yet project
populated downloadSettings. `extra` follows Xray's one-level `SplitHTTPConfig.Build` replacement: its object (or a
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
separation between QUIC TLS and the TCP uTLS callback. Unless
`quicParams.disableChromeParrot` is true, the handshake is shaped like
Chrome's instead, as Xray-core's ChromeParrot shapes it; see
[ChromeParrot](#chromeparrot). `disableGSO` turns off
segmentation offload, `brutalDisableLossCompensation` applies to
`force-brutal`, and `disableStatelessReset`, which only Xray-core's servers
read, is accepted without effect.

`streamSettings.finalmask.quicParams` is parsed for every stream but applied
only to H3. The phase-one engine implements QUIC v1, Reno, BBR with each
`bbrProfile` (see [BBR profiles](#bbr-profiles)), `force-brutal` (the Brutal
sender described in the Hysteria section, at `brutalUp`), initial and maximum
receive windows,
`maxIdleTimeout`, `keepAlivePeriod`, `disablePathMTUDiscovery`,
`maxIncomingStreams` and `disableGSO`. With no overrides it uses Xray's 2 MiB
stream and 3 MiB connection initial windows, a 300-second idle timeout, and a
ten-second H3 keepalive.

XHTTP downloads grow their receive windows from the initial values toward the
maxima, by default 6 MiB per stream and 15 MiB per connection, as quic-go does;
a constrained host keeps the initial windows. The standard BBR profile is a
Quinn-BBR approximation with Xray's initial congestion window; conservative and
aggressive run the port of Xray's sender. A maximum below its initial window,
QUIC v2 through the transport API and `debug: true` fail closed before opening
a socket. Plain `brutal` fails to parse: it follows the rate a Hysteria server
announces, and Xray-core's XHTTP dialer has no case for it and panics when
dialing. H3 accepts the
UDP-hop mask, or the legacy `quicParams.udpHop`, with
the Hysteria rules above: with a remote mode the first Initial already goes
to a drawn address, and each interval of an interval mode moves the
connection to a fresh protected socket, aimed with `intervalRemote` at
another address, while QUIC migrates the path. The timer starts once the
connection exists and stops with it; a failed hop keeps the current path until
the next interval, as in Xray. Each pooled QUIC connection hops independently.
H3 takes every UDP mask: noise, `header-custom`, Salamander with Gecko,
`sudoku`, `xdns`, `realm` and `xicmp`, each in its own section. It rejects TCP
masks, and the TCP fragment mask does not apply to it. H3 has hermetic mode, wire, pool, lifecycle, TLS, and protected
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

With `encryption: "none"`, `xtls-rprx-vision` is refused by the pre-dial
runtime guard on gRPC. The profile still parses and builds, matching Xray's
configuration acceptance. Xray's VLESS `Process` first accepts an
`*encryption.CommonConn`; otherwise it requires the dialer to return a TLS or
REALITY connection directly (`proxy/vless/outbound/outbound.go:268-285`).
gRPC returns a Hunk/MultiHunk wrapper, so the latter branch cannot work.

With VLESS encryption enabled, the CommonConn branch is available on every
implemented carrier. Vision Direct removes that encryption layer alone,
retaining the gRPC wrapper and its TLS/REALITY protection; random mode also
retains header masking. The same rule enables encrypted Vision on WebSocket,
HTTPUpgrade, and XHTTP. See the [encryption design](vless-encryption-design.md)
for the full-Xray application matrix and remaining evidence boundaries.

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

### mKCP

`network: "kcp"`, or `"mkcp"`, carries VLESS, VMess, Trojan, Shadowsocks,
SOCKS or HTTP over mKCP, Xray-core v26.10.31's reliable stream over UDP. Each
connection opens its own UDP socket, as Xray's dialer does, and takes replies
from any address on it. Nothing is sent before the first write. `security` is
`none` or `tls`; REALITY is refused, as by Xray-core. Vision works under TLS,
because Xray's mKCP dialer hands back the TLS connection itself. SOCKS has no
Xray-core server over mKCP: its SOCKS inbound panics there.

`kcpSettings` reads Xray's fields with Xray's defaults. Absent or null, the
block and each field keep the default.

| Field | Default | Meaning |
| --- | --- | --- |
| `mtu` | 1350 | Bytes in a segment, its 18-byte header included; 21 to 8192 |
| `tti` | 50 | Milliseconds between flushes while data or acks wait; 10 to 1000 |
| `uplinkCapacity` | 5 | Megabytes a second the sender keeps in flight |
| `downlinkCapacity` | 20 | Megabytes a second the receiver offers the sender |
| `cwndMultiplier` | 1 | Multiplies what one flush may send; at least 1 |
| `maxSendingWindow` | 2 MiB | Bytes waiting for acks before writes wait; at least `mtu` |

`header` and `seed` are read and ignored, as Xray-core v26 ignores them, with a
warning when they ask for something: since v26 the old header and seed are
`mkcp-legacy` masks. Both ends need the same masks, in the same order:

```json
"finalmask": {"udp": [
  {"type": "mkcp-legacy", "settings": {"value": "the old seed"}},
  {"type": "mkcp-legacy", "settings": {"header": "wechat"}}
]}
```

An `mkcp-legacy` mask is one of these, by its settings:

- neither `header` nor `value`: the original obfuscation, an FNV-1a checksum
  and a forward XOR;
- `value` alone: AES-128-GCM keyed by the value's SHA-256, the old `seed`;
- a `header`, case-insensitive: `dns`, a DNS query for `value` or
  `www.baidu.com`, or `dtls`, `srtp`, `utp`, `wechat` or `wireguard`, the old
  header types.

Masks apply in array order, so the last one is outermost on the wire: the old
header with a seed is the seed mask first, then the header. Consecutive
`mkcp-legacy` masks drop a datagram that grows past 4096 bytes, as Xray's do.
One `noise` mask may stand anywhere among them, and its packets go out through
the masks after it. One `salamander` mask is a header mask like them, as in
Xray-core: it joins the `mkcp-legacy` masks next to it under the same limit,
an eight-byte salt ahead of what it XORs. Gecko, its `packetSize`, is refused
on mKCP for now. `header-custom`, `sudoku`, `xdns`, `realm` and `xicmp` have
their own sections below; `udphop`, TCP masks and chaining through another
outbound are refused on mKCP.

The connection runs as Xray's does. It resends a segment once its
retransmission timeout passes, estimated as RFC 6298 does, and sooner when a
later segment is acknowledged first. It flushes every `tti` milliseconds while
data or acks wait, at once on a write, a read or an arriving segment, and every
five seconds regardless, pinging when three seconds passed without one. Thirty
seconds without a datagram from the server close it. Closing sends what is
left, marked as closing, then a terminate command until the server answers or
eight seconds pass. mKCP has no half close: the stream stays open after its
write side shuts down, and when either side closes the other drops what it has
not delivered yet.

The deliberate differences from Xray-core and the evidence behind this are in
[mKCP](xray-core-differences.md#mkcp).

### header-custom TCP mask

A `header-custom` entry in `finalmask.tcp` is a handshake every TCP carrier
sends and checks before any other byte, as Xray-core v26.10.31's runs: raw,
WebSocket, HTTPUpgrade, gRPC and XHTTP over TCP, under none, TLS or REALITY,
for VLESS, VMess, Trojan, Shadowsocks, SOCKS and HTTP.

```json
"finalmask": {"tcp": [{"type": "header-custom", "settings": {
  "clients": [[{"type": "str", "packet": "HELLO"}, {"rand": 8, "capture": "nonce"}]],
  "servers": [[{"reuse": "nonce"}, {"type": "str", "packet": "OK"}]]
}}]}
```

The client writes `clients[0]`, reads `servers[0]`, writes `clients[1]`, and so
on, then reads the server sequences left. Every byte the server sends must be
what its item expects, or the dial fails. `errors` is read and never sent by a
client.

An item is at most one of these:

- `packet`, decoded by `type`: `array` or empty (a byte array, or a string Go
  reads as base64), `str`, `hex` or `base64`;
- `rand` random bytes within `randRange`, by default 0 to 255, at most 65536;
- `reuse`, the bytes captured under that name;
- a `transform`.

`capture` saves the item's bytes under a name of letters, digits and
underscores. `delay` waits a random number of milliseconds before the item,
sending what came before it first, when its upper bound is positive.

A transform is an `op` over `args`, each exactly one of `bytes`, `u64`,
`reuse`, `metadata` or another `transform`:

- bytes: `concat`, `slice`, `pad`, `truncate`;
- numbers packed into bytes: `be16`, `be32`, `le16`, `le32`, `le64`;
- numbers: `add`, `sub`, `and`, `or`, `shl`, `shr`, `xor16`, `xor32`.

Overflows, a short source and an unknown op fail the dial, as in Xray-core. An
item sent or read, and a `pad`, is at most 1 MiB here.
`metadata` reads the carrier's own addresses: `local_port` and `remote_port`,
`local_ip4_u32` and `remote_ip4_u32` for IPv4, and the aliases `src_*` for the
remote end and `dst_*` for the local one. Each side reads its own, so a
client's `remote_port` is the server's `local_port`. A carrier through another
outbound reads `0.0.0.0:0` for both, as Xray's chained connection does.

The handshake runs as soon as TCP connects, before the fragment mask, TLS and
REALITY. A `fragment` mask may stand before it in the array; after it, Xray-core
fragments the handshake rather than the TLS ClientHello, so that order is
refused. The TCP `header-custom` form is refused on mKCP, XHTTP over HTTP/3,
a split XHTTP download and outbounds that dial directly. The UDP form is
supported on mKCP, Hysteria, XHTTP over HTTP/3 and MASQUE over HTTP/3, as
described below.
Deliberate differences and the evidence are in
[header-custom TCP](xray-core-differences.md#header-custom-tcp).

### header-custom UDP mask

One `header-custom` entry in `streamSettings.finalmask.udp` is supported on
mKCP, Hysteria, XHTTP with exact `h3` ALPN and MASQUE over HTTP/3, at its
position among the
`noise`, `salamander` and `mkcp-legacy` entries:

```json
"streamSettings": {
  "network": "kcp",
  "finalmask": {"udp": [{"type": "header-custom", "settings": {
    "mode": "standalone",
    "client": [{"type": "str", "packet": "hello", "capture": "greeting"}],
    "server": [{"reuse": "greeting"}]
  }}]}
}
```

`mode` is case-sensitive: absent, empty or `prefix` puts the concatenated
`client` items before each outgoing datagram and matches/removes `server`
items from incoming datagrams. `standalone` sends the client sequence as its
own datagram, waits for the matching server sequence from that peer, and
then sends the original datagram unchanged. A standalone reply must have
exactly the measured length. Subsequent writes reuse the completed handshake
for five seconds; the first write after expiry repeats it. Ordinary traffic
does not extend that standalone expiry. Even empty sequences exchange empty
datagrams. Closing the stream cancels a pending handshake.

`client` and `server` are flat arrays, unlike TCP's arrays of sequences. Items
support the same packet encodings, random bytes, `capture`, `reuse` and
`transform`, without TCP's `delay`. Metadata is available when writing, but
not when matching a received header, as in Xray-core. mKCP's local address
has a port and no IPv4 address there, as Xray-core's dual-stack wildcard
socket reports it. A prefix client sequence must be measurable when the
connection opens; a standalone one is only evaluated, so a computed `pad`,
`slice` or `truncate` length works there, as with Xray-core's client.
Prefix captures expire five seconds after their last successful read or
write; writes also use Xray-core's fallback to the last successfully
received variables.

Mask array order is preserved: handshake and noise packets pass through
only the masks after the mask that generated them, and a custom header
listed before Salamander is obfuscated with the datagram. Standalone mode
uses Xray-core's 4096-byte receive buffer. Prefix mode uses the carrier's
receive buffer, and a transmitted prefix plus payload must fit 4096 bytes.
Headers themselves are limited to 4096 bytes here; oversized headers fail or
drop a write instead of panicking or allocating an unbounded buffer. A
standalone request unanswered for a second goes out again; Xray-core waits
for its reply for good.

On Hysteria and XHTTP over HTTP/3, the QUIC connection sends one datagram per
system call while the mask is set, as quic-go does on Xray's masked conn,
and path MTU discovery keeps a prefix within the usual 1452-byte budget
where it can. A standalone handshake holds every QUIC packet until its reply
arrives, as Xray-core's write does. The mask is refused with `udphop`:
Xray-core writes to `0.0.0.0:0` under it but reads from the hop's address,
so its standalone reply never completes and its captures never match.

Other UDP carriers, duplicate custom masks and TCP-only item fields are
rejected. `scripts/check-header-custom-interop.sh` checks the recorded UDP
exchanges and both modes against Xray-core v26.10.31's servers.

### sudoku mask

`sudoku` hides every byte as four clues of a 4x4 sudoku grid, the grids
shuffled by the password, with padding bytes between clues. It has no
handshake. It is supported as a TCP mask on every TCP carrier (raw, TLS,
REALITY, WebSocket, HTTPUpgrade, gRPC and XHTTP over TCP) and as a UDP mask
on mKCP, Hysteria and XHTTP over HTTP/3:

```json
"finalmask": {"tcp": [{"type": "sudoku", "settings": {
  "password": "synthetic-example-password",
  "ascii": "prefer_entropy",
  "customTables": ["xppvvvvx", "vvxpvxpv"],
  "paddingMin": 5, "paddingMax": 25
}}]}
```

- `password` picks the grids, through Go's `math/rand` seeded from its
  SHA-256, which this implementation reproduces.
- `ascii` is empty, `entropy` or `prefer_entropy` for clue bytes with
  bits `0x90` clear, or `ascii` or `prefer_ascii` for printable ones,
  case-insensitive and trimmed.
- `customTable`, or a list in `customTables` that the bytes take in turn,
  places the clue bits in a byte: 8 characters of two `x` (always set), two
  `p` and four `v`, case-insensitive, spaces ignored. ASCII mode ignores
  them.
- `paddingMin` and `paddingMax` are percentages, each capped at 100; one
  chance between them is drawn per connection or datagram and decides each
  padding byte.
- `custom_table`, `custom_tables`, `padding_min` and `padding_max` apply when
  their camelCase field is empty or zero, as in Xray-core.

Over TCP the client writes classic sudoku, at least four bytes per byte,
and reads the server's packed form, four bytes per three. The TCP mask must
be the last one in `finalmask.tcp`: the `fragment` and `header-custom` masks
before it go through it, so the `header-custom` handshake is encoded too.
On mKCP each datagram is encoded on its own, at least four times its size;
a legacy mask after it drops mKCP's datagrams past 4096 bytes, as in
Xray-core, so put legacy masks before it. On Hysteria and XHTTP over HTTP/3
each QUIC packet is encoded the same way, so a 1200-byte packet becomes a
datagram of about 5 KB. The carrier lets the system fragment it and turns
path MTU discovery off, as quic-go is on Xray-core's masked conn. Put
Salamander before sudoku: after it, Xray-core's server drops every reply
longer than 4096 bytes, which is all of them. An unknown `ascii` mode or a
malformed table is refused when the configuration is read; Xray-core fails
every dial with it.
`scripts/check-sudoku-interop.sh` decodes fresh output of Xray-core's own
mask and runs every carrier against its servers.

### xmc mask

`xmc` makes every TCP carrier look like a Minecraft 26.1.2 login. It is
supported as a TCP mask on raw, TLS, WebSocket, HTTPUpgrade, gRPC and XHTTP
over TCP, but not under REALITY:

```json
"finalmask": {"tcp": [{"type": "xmc", "settings": {
  "hostname": "mc.example.com",
  "password": "synthetic-example-password",
  "profiles": [{"username": "Steve",
    "uuid": "8667ba71-b85a-4004-af54-457a9734eed7",
    "texturesValue": "<the session server's value>",
    "texturesSignature": "<its signature>"}]
}}]}
```

- `hostname` is the server address the handshake names. Empty names the
  server's IP address, or `0.0.0.0` through a `dialerProxy` chain, whose
  connection reports no address, as in Xray-core.
- `password` derives the server's RSA key and goes to the server encrypted.
  It is 1 to 113 bytes here; Xray-core accepts a longer one and fails every
  login.
- `profiles` are signed profiles the server holds too; each connection picks
  one. `username` is 3 to 16 ASCII letters, digits or underscores, `uuid` is
  any form `github.com/google/uuid` reads, and `texturesValue` and
  `texturesSignature` are required.

The client sends a handshake for protocol 775 and a Login Start, checks that
the server's key is the one the password derives, and sends a shared secret
and the password under that key. Both sides then switch to AES-128-CFB8. Once
the server confirms the profile, they exchange about a second of padding
that copies the lengths and write boundaries of a real login, then carry the
proxied bytes in configuration-state custom payload packets of at most
24 KiB; the client answers the server's keep-alives. The mask must be the
last one in `finalmask.tcp`, so the `fragment` and `header-custom` masks
before it run inside the login. REALITY is refused over it: Xray-core's
REALITY server panics on every connection through xmc.
`scripts/check-xmc-interop.sh` compares the keys Xray-core derives and runs
every carrier against its server.

### xdns mask

`xdns` carries a UDP carrier in DNS: mKCP, Hysteria or XHTTP with exact `h3`
ALPN. The server answers as the domain's authoritative DNS server, so its
inbound listens where the domain's NS records point, and the client sends
its queries to recursive resolvers:

```json
"finalmask": {"udp": [{"type": "xdns", "settings": {
  "domains": [{"names": ["t.example.com"], "types": [16, 1, 28],
    "edns0": 1232}],
  "resolvers": [{"addrs": ["1.1.1.1", "tcp://9.9.9.9"]}],
  "extraPoll": 1
}}]}
```

- `domains`: each name is its own entry. `lenLimit` (0 reads 255) bounds a
  query's name and `labelLimit` (0 reads 63) its data labels; together they
  must leave at least 17 bytes per query. `types` are the record types to
  ask for, one drawn for each packet: A (1), CNAME (5), TXT (16) or AAAA
  (28), TXT when empty. `edns0` is 0 or 512 to 4096, the UDP size an OPT
  record advertises. Sizes and types keep their low 16 bits, as Go converts
  them.
- `resolvers`: `udp://` (the default) or `tcp://` with an IP address and an
  optional port, 53 by default. The client picks the next resolver that has
  sent fewer queries since it last answered, as Xray-core does. `worker` is
  read and only DNS over HTTPS would use it.
- `extraPoll`: 0 to 3 polls after each packet and each poll.

Every datagram goes out in base32 in the names of queries: the client's
8-byte id, three bytes of padding and the packet, or fragments of a larger
one. Polls, eight bytes of padding after the id, start with the first answer
and keep queries waiting at the server, which answers each with the packets
it has, after up to a second. A QUIC packet takes several queries; an answer
carries whole packets, so on QUIC carriers `edns0` must leave room for one,
and resolvers that cut EDNS to 1232 bytes are too small.

The mask must be the last UDP mask: its client opens its own sockets to the
resolvers, and Xray-core dials the masks listed after it for nothing. The
masks listed before it work inside it. It cannot run with udphop, nor with
sudoku on QUIC carriers, whose datagrams exceed the 4096 bytes one xdns
packet takes. Not supported yet: resolver names, DNS over HTTPS and its
`tlsConfig` and `quicConfig`. DNS over TCP sends each message after its
two-byte length; Xray-core's client fails to write the length, so its TCP
resolvers reach no real resolver. `scripts/check-xdns-interop.sh` compares
the encoding with Xray-core's own code and runs each carrier against its
server.

### MASQUE

The `masque` outbound reaches a MASQUE proxy, such as Xray-core's own
`masque` inbound, through a CONNECT-IP tunnel (RFC 9484), as Xray-core
v26.10.31's client does. It requires `network: "masque"`, `security: "tls"`
and no chaining; the `masque` network takes no other outbound.

```json
{"protocol": "masque",
 "settings": {"address": "masque.example", "port": 443,
   "remoteDNS": ["1.1.1.1", "2606:4700:4700::1111"]},
 "streamSettings": {"network": "masque", "security": "tls",
   "tlsSettings": {"serverName": "masque.example"},
   "masqueSettings": {"path": "/masque/{target}/{ipproto}/",
     "user": "alice", "pass": "secret"}}}
```

- `settings`: a nonempty `address` and a nonzero `port`, as Xray-core
  requires. `remoteDNS` takes up to 8 IP addresses, scoped IPv6 ones
  refused; absent, null or empty means Cloudflare's `1.1.1.1`, `1.0.0.1`,
  `2606:4700:4700::1111` and `2606:4700:4700::1001`.
- `masqueSettings.host` is the request authority and must be what Go's
  `url.Parse` reads back as the host; empty takes the TLS server name, with
  the port unless it is 443. `path` defaults to `/.well-known/masque/ip/*/*/`;
  `{target}` and `{ipproto}` and their query forms become `*`, as the client
  asks for all traffic, and any other brace fails.
- `user` and `pass` send `Authorization: Basic`; `user` takes no colon.
  `headers` are Go header fields: at most 64, values of at most 8 KiB, no
  `Host` or `Capsule-Protocol`, and no `Authorization` beside `user` or
  `pass`. `User-Agent` defaults to Chrome's; `chrome`, `firefox`, `safari`,
  `edge` and `curl` are presets, `golang` leaves the HTTP library's own
  (`quic-go HTTP/3`, or `Go-http-client/2.0` over HTTP/2) and empty sends
  none. `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`,
  `Upgrade` and `Content-Length` are accepted and not sent, as in Xray-core.
- `xmux` reuses tunnels as Xray-core's `XmuxManager` does. An all-zero
  `xmux` means one tunnel, retired after 1800 to 3000 seconds; an absent
  `masqueSettings` keeps the one tunnel for good. `maxConcurrency` bounds a
  tunnel's flows, `cMaxReuseTimes` counts the flows that take a tunnel, and
  `hMaxRequestTimes` changes nothing. A retired tunnel closes with its last
  flow. After a failed dial, flows take a working tunnel or the same error
  for a second before the next dial.

The client uses HTTP/3 unless `tlsSettings.alpn` names `h2` and not `h3`,
which selects HTTP/2, below; `warp` selects Cloudflare WARP, further below.
Over HTTP/3 the TLS ALPN is `h3` alone and the fingerprint is
not used: Xray-core's MASQUE dial shapes neither its TLS nor its QUIC
handshake. The QUIC connection starts with 1350-byte packets and never goes
below them, issues 4-byte connection IDs, refuses incoming streams, and
keeps `finalmask.quicParams` and the UDP masks; quic-go's receive windows,
a 30-second idle timeout and a 10-second keepalive apply where
`quicParams` is silent, and `xmux.hKeepAlivePeriod` sets the keepalive when
nonzero, negative turning it off. Congestion `brutal` runs BBR with
`bbrProfile`, as in Xray-core, and `force-brutal` runs Brutal; as on XHTTP
over HTTP/3, a profile's BBR and Brutal take over from NewReno once the
handshake completes, where Xray-core's dial installs them (see
[BBR profiles](#bbr-profiles)). Every UDP mask applies as on XHTTP over
HTTP/3, [realm](#realm-mask) and [xicmp](#xicmp-mask) included, since
Xray-core's dial opens the QUIC socket through the same `finalmask` path: a
realm introduction counts toward the ten seconds a tunnel dial may take, as
it runs under Xray-core's dial context, and an xicmp outbound whose address
is a name needs `ips`. TCP masks fail on MASQUE over HTTP/3, the fragment
mask in the configuration and the others when the core starts, as XHTTP
over HTTP/3 refuses them; Xray-core's HTTP/3 dial ignores them. `sockopt` applies
to the QUIC socket, and `addressPortStrategy` and `domainStrategy` choose
the server's address, as Xray-core's system dialer does.

Over HTTP/2 the client dials TCP and TLS as the stream settings ask, as for
a raw TCP transport: the configured ALPN, the uTLS `fingerprint`, `sockopt`
and the TCP masks, the server's candidates after `addressPortStrategy`. The
server must negotiate `h2`. The connection then runs Xray-core's own HTTP/2
client: SETTINGS with a 65536-byte header table, no push, a 6 MiB stream
window and a 256 KiB header list, the connection window raised to 15 MiB,
and the stream's window opened again in 1 MiB steps as the tunnel reads.
The request goes out after the server's first SETTINGS, which must enable
extended CONNECT (RFC 8441), with Xray-core's header block byte for byte:
`:method`, `:authority`, `:scheme`, `:path`, `:protocol`, then the default
User-Agent if any, then the fields by their canonical names, without an HPACK
dynamic table. A PING goes out after 45 seconds without a frame from the
server, or `xmux.hKeepAlivePeriod` seconds when it is positive (negative
sends none), and the connection closes when nothing arrives within 15
seconds of it. UDP masks fail the configuration over HTTP/2, as on XHTTP
over HTTP/2, and so does a `TE` header other than `trailers`, which this
HTTP/2 client refuses to send; Xray-core sends it and ignores the masks.

A tunnel is one QUIC or TCP connection with one extended CONNECT whose
`:protocol` is `connect-ip`, sent once the server's SETTINGS allow extended
CONNECT, and over HTTP/3 HTTP datagrams. The client asks for one address of each family
and waits up to ten seconds, with the dial, for an assignment; it closes the
tunnel when the proxy withdraws an address, and refuses the proxy's own
address requests. Packets travel in QUIC DATAGRAM frames with context ID 0,
or over HTTP/2 in DATAGRAM capsules on the request stream, up to 65535
bytes, their TTL or hop limit lowered by one; a packet too big for the path
comes back to its sender as an ICMP Packet Too Big, and the tunnel must carry
at least 1280-byte packets. Over HTTP/2 a packet waits while 32 KiB of
capsules are queued for the stream, and the stream is read no further while
128 packets wait for the stack, as in Xray-core.

Each tunnel runs the WireGuard outbound's userspace TCP/IP stack, MTU 1280,
on the assigned addresses: 16 TCP and 512 UDP flows at once, the stack's
bounds. TCP and UDP flows from SOCKS, HTTP and TUN go to their destination
through it; a name resolves through the tunnel, with the `remoteDNS`
servers of the families the tunnel has an address of (all of them when none
matches), for those families, IPv6 first when there is one. A TCP flow tries
up to eight of its addresses, three seconds each and ten for the last; a UDP
flow goes to the first. A flow's open deadline is the handshake timeout plus
the ten seconds a tunnel dial may take, which goes on for the next flows if
the one that started it gives up.

`warp` reaches Cloudflare WARP, as Xray-core v26.10.31 does:

```json
"masqueSettings": {"warp": {"privateKey": "<device key>",
  "publicKey": "<endpoint key>", "address": ["172.16.0.2/32", "fd00::2/128"]}}
```

`privateKey` is the device's ECDSA P-256 key, PKCS #8 or SEC 1, in PEM or
standard base64; `publicKey` the endpoint's SubjectPublicKeyInfo in the same
forms, any key Go's `x509.ParsePKIXPublicKey` takes; `address` at most one
prefix or address of each family, read as Go's `netip` reads them (a zone is
dropped, `::ffff:` addresses count as IPv6). `user` and `pass` cannot be
used with it; `host` defaults to `cloudflareaccess.com` and `path` to `/`.
Each dial presents a certificate made for the device key, as Xray-core's
`warpCertificate` makes it, and checks the endpoint by its key alone, unless
`pinnedPeerCertSha256`, `verifyPeerCertByName` or `allowInsecure` already
decide how it is verified. Over HTTP/3 the QUIC connection issues 20-byte
connection IDs, announces the draft-00 datagram setting, and sends
`cf-connect-ip` without needing extended CONNECT, taking draft or RFC 9297
datagrams. Over HTTP/2 the TLS negotiates `h2` or no protocol; the request
is a plain CONNECT to the authority with port 443, with `Cf-Connect-Proto`
and `Pq-Enabled: false` instead of `Capsule-Protocol`, and the packets ride
bare DATAGRAM capsules. The tunnel takes the configured addresses without
asking for any, and a WARP TLS session is never resumed.

`scripts/check-masque-interop.sh` compares
the capsules, packets, WARP keys and addresses and the HTTP/2 client's
frames with Xray-core's own code, rechecks the configuration verdicts with
`xray run -test` and runs the client against Xray-core's server over HTTP/3
and HTTP/2, and against a WARP stand-in built from Xray-core's warp tests.
It never connects to Cloudflare.

### XDRIVE

The `xdrive` transport carries a VLESS connection as objects in a storage
both ends reach, as Xray-core v26.10.31's client does. Nothing connects to
the VLESS server address: the client and Xray-core's server meet in the
storage, and the address is never looked up. This release reaches all four
services: `local`, a folder; `google-drive`, a Google Drive folder, its
sessions in rings of slots; `s3`, a bucket; and `template`, an HTTP storage a
JSON template describes.

```json
{"protocol": "vless",
 "settings": {"address": "127.0.0.1", "port": 443,
   "id": "27848739-7e62-4138-9fd3-098a63964b6b",
   "encryption": "mlkem768x25519plus.native.0rtt.<client key>"},
 "streamSettings": {"network": "xdrive",
   "xdriveSettings": {"service": "local", "remoteFolder": "/srv/xdrive"}},
 "mux": {"enabled": true}}
```

The outbound must be VLESS with `encryption` (`xray vlessenc` makes a
pair), without `flow` or `testpre`, and Mux must be on with no negative
`concurrency` or `xudpConcurrency` and no `xudpProxyUDP443: "skip"`: every
TCP and UDP connection rides Mux.Cool, as Xray-core requires. VLESS
`reverse`, which Xray-core lets open its own Mux instead, is refused here,
as on every VLESS outbound.

`xdriveSettings` is read as Xray-core's `XDriveConfig.Build` reads it:

- `service`: `local`, `google-drive` (`Google Drive` is the deprecated
  spelling, with a warning), `template` or `s3`, case-sensitive; any other
  value, an empty one included, fails. `google-drive` needs exactly three
  `secrets`, `template` a `template` value (any JSON, `null` included) and
  `s3` an `s3` object. Without `xdriveSettings` the core refuses to start,
  where Xray-core's registered default fails every dial.
- `remoteFolder`: the folder of `local`, made with its parents, readable by
  this user only, when a session opens. An empty one fails when the core
  starts, where Xray-core fails every dial.
- `secrets` is an array of strings, `null` entries read as empty.
- The numbers are unsigned 32-bit integers, `null` keeping zero, and zero
  takes Xray-core's default: `segmentBytes` 512 KiB (at most 16 MiB),
  `flushIntervalMs` 20, `pollIntervalMs` 50, `maxPollIntervalMs` 500 (never
  below the poll interval), `eagerWindowMs` 2000, `holeTimeoutMs` 30000,
  `sessionTtlSeconds` 300 (a server's setting) and `concurrency` 8 (at most
  256 since Xray-core v26.11.9).
- `xmux` is read as XHTTP's; an all-zero one means one connection reused for
  1800 to 3000 seconds, four for `google-drive` unless `tlsSettings.alpn` is
  exactly `["h3"]`. It shapes the HTTP storages' connections; `local` has
  none.
- `template` is kept as the JSON written and read only when a connection
  dials, as Xray-core reads it: a template it cannot use fails each dial,
  not the configuration.
- `s3` is checked as Xray-core's `ValidateS3Config` checks it when the
  service is `s3`: `endpoint` an `http` or `https` URL without user
  information, query (a bare `?` included) or fragment; `region` a header
  value without `/`, `,`, space or tab, empty meaning `us-east-1`; `bucket`
  without path separators, empty, `.` or `..`; `pathStyle` true unless
  `false`, and virtual-hosted addressing needs a DNS endpoint and a lowercase
  DNS-compatible bucket; `remoteFolder` a relative key prefix, one trailing
  `/` allowed; `secrets` the AccessKeyID, SecretAccessKey and an optional
  SessionToken, header values, the key ID without `/`, `,`, space or tab.

Over `tlsSettings.alpn` exactly `["h3"]`, `google-drive` takes only the
`noise` UDP mask and no service takes `brutal` or `force-brutal`
congestion, as in Xray-core. The UDP masks, Salamander among them, follow
the rules of the other QUIC carriers (XDRIVE over HTTP/3 counts as one);
`security`, `sockopt` and the masks shape the HTTP storages' connections
and play no part with `local`.

Over `alpn` exactly `["h3"]`, an `https` storage is reached over HTTP/3:
one QUIC connection a host, set up as XHTTP's HTTP/3 connections are, with
the stream's `quicParams`, its UDP masks, BBR (or Reno), udphop and the
storage's server name and certificate rules, and a keepalive only when
`quicParams.keepAlivePeriod` or a positive `xmux.hKeepAlivePeriod` asks
for one, as Xray-core configures quic-go for it. Xray-core shapes that
connection as Chrome unless `disableChromeParrot` is set; this client's
QUIC is Quinn's own for now, unlike its Hysteria and XHTTP H3 dials, and the
configuration warns about it unless `disableChromeParrot` is true. A storage
over HTTP/3 cannot go through another outbound (`dialerProxy`).

`streamSettings.address` and `port`, which Xray-core reads for every stream
and only XDRIVE uses, name where every connection to an HTTP storage goes:
the URL's host still names the TLS server and the `Host`, and its port is
kept when `port` is zero. `address` is an IP or a name, brackets and
surrounding spaces trimmed, `port` an integer from 0 to 65535, `null`
leaving either unset; a `port` without an `address` changes nothing. An
`env:` address, which Xray-core reads from the environment, is refused,
and so are both fields under any other transport, which Xray-core ignores.

The HTTP storages are reached as Xray-core's Go client reaches them. With
`security: "tls"` each connection takes the stream's TLS settings, the
server name the URL's host unless `serverName` names one; without them, a
Chrome hello offering `h2` and `http/1.1`. The server's ALPN picks HTTP/2
or HTTP/1.1; a host keeps one connection until it answers over HTTP/1.1,
then takes up to the storage's concurrency. HTTP/2 opens with Go's
SETTINGS (no push, 4 MiB stream window, 1 MiB frames, 10 MiB header
lists), a 1 GiB connection window, Go's HPACK choices and its
pseudo-header order (`:authority`, `:method`, `:path`, `:scheme`), and
PINGs a quiet connection every 45 seconds, or every `hKeepAlivePeriod`
seconds of `xmux`, never when that is negative. Requests carry Chrome's
`fetch` headers unless they name a user agent of their own, Go's
`Accept-Encoding: gzip` (decoded on the way back) unless they ask for
another encoding or a range, and Go's `Content-Length` rules. A request
that makes no progress for 60 seconds fails. Each session takes its
connections from XMUX until it ends, and the sessions of one outbound share
them; a connection closes once XMUX drops it and its requests are done.
Connections go through the outbound's `sockopt`, chain and TCP masks.

`s3` signs every request with SigV4 (`X-Amz-Date`,
`X-Amz-Content-Sha256`, `Content-Type` on a put, `X-Amz-Security-Token`
with a third secret), path-style `https://endpoint/bucket/key` or
virtual-hosted `https://bucket.endpoint/key`, keys under `remoteFolder`.
A listing asks for up to 1000 keys a page with `/` as delimiter and goes on
with continuation tokens, refusing keys outside its prefix or a token that
does not advance. Deleting an object deletes what lies under it too. A
request is tried up to eight times, after a network failure, a stall, 429,
500, 502, 503 or 504, waiting 200 ms doubled each time up to 8 seconds,
jittered, or as long as `Retry-After` asks, up to 8 seconds. A redirect is
an answer, as in Xray-core, so a signature never goes to another host.

`google-drive` keeps each object as a file in the folder `remoteFolder`
names by id, reached with Google Drive's v3 API and the client id, client
secret and refresh token of `secrets`: an access token from
`oauth2.googleapis.com/token`, kept for its lifetime less a minute and
fetched again after a 401; names flat, their `/` written as `~`; an object
of up to 12000 bytes as base64 in the file's description and a larger one
uploaded as its body; files found by a query on their name, page after
page, their ids remembered for every session of the outbound; and every
request tried up to eight times as with `s3`, also after a 403 that names
one of Drive's rate limits. A session announces a ring of slots: two to
eight files a direction (`concurrency`, at most eight) and a watermark, made
when the session opens. Segment `n` goes into slot `n` modulo the depth,
its frame (`XDRVSL01`, the number, a mode, the size and CRC-32, and up to 14
KiB of segment inline) in the description and a larger segment in the body
of the same request. The writer cuts 14 KiB segments, doubling the size up
to `segmentBytes` after eight full ones in a row and sending a burst of more
than 56 KiB at once, and writes a slot only once the reader's watermark
says it took what the slot held a lap before. The reader asks for the head
often, from 50 ms up to 200 ms (or `maxPollIntervalMs` once idle), and for
up to six segments behind it at the pace they come, writes its watermark as
the head moves, takes a body only once it matches its frame, and fails when
the writer marks a segment it could not store or a slot stays gone for a
minute. When the ring cannot be made, the session goes in segments, as in
Xray-core.

`template` sends the requests its operations describe:

```json
"template": {
  "flatten": true,
  "auth": {"type": "oauth2", "tokenUrl": "https://oauth.example/token",
    "form": {"grant_type": "refresh_token", "refresh_token": "{secret0}",
      "client_id": "{secret1}"},
    "header": {"Authorization": "Bearer {token}"}},
  "put": {"method": "PUT", "url": "https://store.example/v1/{folder}/{name}"},
  "get": {"url": "https://store.example/v1/{folder}/{name}?link",
    "hrefPath": "href"},
  "delete": {"method": "DELETE", "url": "https://store.example/v1/{folder}/{name}"},
  "list": {"url": "https://store.example/v1/{folder}/",
    "namesRegex": "\"name\":\"([^\"]+)\""},
  "retry": {"status": [429], "rateReason": "error.reason"}
}
```

The template is read as Go's `encoding/json` reads it into Xray-core's
types: field names in any case, `null` as nothing, whole numbers only.
`put`, `get`, `delete` and `list` need a `url` and `list` a `namesRegex`
with a group; `concurrency` caps requests in flight a session, 64 when not
positive (Xray-core's `driveMaxInflight`, 32 before v26.11.9) and at most 256. In URLs, headers and bodies `{folder}` is
`remoteFolder`, `{secretN}` the Nth secret, `{name}` and `{prefix}` the
object's name (with `flatten`, its `/` written as `~`), `{data}` the
object in base64 when `put` has a `body`, which then replaces the raw
object, and `{token}` the OAuth 2 token. `auth` is `none`, `static` (its
`header`), `basic` (`username` and `password`) or `oauth2`: a `POST` of
`form` to `tokenUrl`, written unescaped as Xray-core writes it, the token
at `tokenPath` (`access_token`) kept for the seconds at `expiryPath` (an
hour) less a minute, fetched again after a 401. With `hrefPath` an
operation takes two steps: the first answer's JSON names a URL at that
path, then called with `hrefMethod` (`GET`), without auth or headers,
carrying the object. A listing's names are the first group of every match
of `namesRegex` (Go's RE2 syntax) in the answer; with `flatten` only the
names under the prefix count, cut at the next `~`. A 404 is a missing
object, an empty listing, or a done delete. A request is tried up to eight
times, with the pauses of `s3` but no `Retry-After`, after any request that
failed, a 401 with `oauth2`, a status in `retry.status` or a 403 whose JSON
has a value at `rateReason`; no status is retried unless listed. Redirects
are followed as Go's `http.Client` follows them: up to ten requests, `GET` after 301, 302 or
303 for any method but `HEAD`, the method and body kept after 307 and 308,
auth and cookie headers left behind on another domain, a `Referer`, and
Basic auth from a URL's user information.

A session works as Xray-core's does. The client announces it with an empty
object `sessions/<Unix nanoseconds>-<32 hex digits>`, then writes its
direction under `streams/<session>/c2s` and reads the server's under
`streams/<session>/s2c`. A direction is a run of objects named by a
zero-padded number, `%09d.seg` with up to `segmentBytes` of data, then
`.end` after the last; a segment that could not be stored leaves `.err` in
its place and fails the connection. The writer cuts a segment whenever its
buffer holds a full one, and otherwise each flush interval once the buffer
stopped growing or grew for eight ticks; at most `concurrency` segments are
stored at a time, and once twice that many wait the writer holds the sender
back, where Xray-core keeps cutting. The reader lists its direction every
`pollIntervalMs` while data moves and for `eagerWindowMs` after, then twice
as seldom each time up to `maxPollIntervalMs`, and at once after the client
wrote; it fetches up to `concurrency` segments that follow in order, deletes
what it read, and fails when a segment stays missing for `holeTimeoutMs`
while later ones arrived. Shutting a stream down stores the rest of its
buffer and its `.end`; the server's direction is read until its own
`.end`. A stream dropped without a shutdown does the same in the background
for up to two minutes. The `local` service writes each object to a
temporary `.xdrive-tmp-` file beside it and renames it into place, so a
reader never sees half an object.

`scripts/check-xdrive-interop.sh` compares the tuning, names, the local
folder's name resolution and step-by-step replays of the segment writer and
reader with Xray-core's own code; S3 URLs and signatures, S3 answers,
templates, substitution, JSON paths, `namesRegex` matches, URL resolution,
redirects, slot frames, rings and Drive requests with what Xray-core and Go
make of them, and Go's HTTP/2 request frames; rechecks the configuration
verdicts with `xray run -test`; and runs VLESS over XDRIVE against
Xray-core's server through a shared folder, an S3 bucket, a template's REST
store and Xray-core's own fake Drive, in slots, over HTTP/2 and over HTTP/3.

### realm mask

`realm` reaches a server behind NAT through a rendezvous, as Hysteria's
Realms do, on mKCP, Hysteria, XHTTP with exact `h3` ALPN or MASQUE over
HTTP/3. The server's inbound registers its public addresses with the
rendezvous under a realm name; the client finds its own, asks the
rendezvous to introduce it, and both send punch packets until one arrives.
The rendezvous carries no traffic.

```json
"finalmask": {"udp": [{"type": "realm", "settings": {
  "url": "realm://public@realm.hy2.io/my-long-random-name",
  "stunServers": ["stun.nextcloud.com:3478", "stun.sip.us:3478",
    "global.stun.twilio.com:3478"],
  "ipMode": "dual"
}}]}
```

- `url`: `realm://token@host[:port]/name` over HTTPS, port 443 by default,
  or `realm+http://` over HTTP, port 80. It is read with Go's `url.Parse`,
  as Xray-core reads it: the user information, unescaped, is the bearer
  token, the path without its first slash, unescaped, is the name, and the
  query and fragment are ignored. The outbound's own address and port are
  not used; the address must still resolve.
- `stunServers`: one or more `host:port` entries, each port 1 to 65535. Each
  is resolved to one address, the first of the family `ipMode` and the
  socket allow that no earlier server took. The client waits up to four
  seconds for their answers. Several servers expose a predictable symmetric
  NAT, whose neighbouring ports are then punched too.
- `tlsConfig`: `tlsSettings`' fields for an HTTPS rendezvous. `serverName`
  defaults to the URL's host; `pinnedPeerCertSha256` and
  `verifyPeerCertByName` apply as they do there. `fingerprint` is checked
  and not used, as in Xray-core, whose HTTP client sends Go's own
  ClientHello; this one sends rustls's. `alpn` is read and not used: the
  rendezvous is spoken over HTTP/1.1.
- `ipMode`: `dual` (the default, a dual-stack socket), `v4` or `v6`,
  case-insensitive. Xray-core reads any other value as `dual`.
- `portMapping`: `enabled`, `timeout` and `lifetime` (seconds) are read as
  Xray-core reads them, but no UPnP or NAT-PMP mapping is made yet, as when
  Xray-core finds no gateway, so the gateway's address is never offered.

An attempt sends Binding requests to the STUN servers over the carrier's
socket, then `POST /v1/{name}/connect` to the rendezvous with the addresses
they reported and the attempt's 16-byte nonce and 32-byte key, then hello
packets every 100 ms, for up to ten seconds, to the server's addresses in
the families the client has addresses in. The first punch packet of the
attempt names the peer, and a hello is answered. With the rendezvous's
ten-second wait for the server, an attempt takes up to about 35 seconds,
which Hysteria's dial deadline allows for.

The mask must be the last UDP mask. Xray-core sends its STUN and punch
packets through the masks listed after it, which mangle them or, for noise,
announce them; list noise before realm. The masks listed before it run on
the carrier's datagrams inside it. It cannot run with udphop or xdns, which
send elsewhere, nor with header-custom, whose state Xray-core keys by the
server's address while replies come from the peer's. The names of the
rendezvous and of the STUN servers are resolved like the outbound's server
address. A Hysteria connection whose network changes closes, and the next
dial is introduced again; XHTTP introduces every QUIC connection it opens.
`scripts/check-realm-interop.sh` replays what Xray-core's own realm code
does and runs each carrier against its server through a local rendezvous.

### xicmp mask

`xicmp` carries a UDP carrier in ICMP echo messages: mKCP, Hysteria, XHTTP
with exact `h3` ALPN or MASQUE over HTTP/3. The server reads echo requests
on raw ICMP sockets and answers in echo replies; the client sends echo
requests:

```json
"finalmask": {"udp": [{"type": "xicmp", "settings": {
  "dgram": true,
  "ips": ["203.0.113.5"]
}}]}
```

- `dgram`: datagram ICMP sockets, which need no privilege where the system
  grants them (below). Without it the sockets are raw, which need root or
  `CAP_NET_RAW`.
- `ips`: the server addresses, read with Go's `netip.ParseAddr`; one is
  drawn for each packet. A zone on an IPv6 address is dropped, as Xray-core
  drops it, and an IPv4-mapped address is the IPv4 one. Empty sends to the
  outbound's address, which must then be an IP address, else the core
  refuses to start: Xray-core never resolves it. With `ips`, the outbound's
  address is not used, but a name there must still resolve.

Every datagram goes out as an echo request: a random identifier for the
connection, a sequence number counting from one, then the client's random
8-byte id and the packet, at most 4080 bytes; a larger one is dropped. The
server answers with the identifier and sequence of the client's last request
and the packet alone. The server's own system echoes each request back as
well; the client drops a reply that starts with its id. On a raw socket,
and on an Apple datagram socket, which keeps the identifier and receives
every reply from its address, it also drops replies with another
identifier; a Linux datagram socket gets only its own.

Where the sockets come from:

| System | `dgram: true` | `dgram: false` |
|---|---|---|
| macOS | Granted to any process (checked) | Root only |
| Linux | Granted to the groups in `net.ipv4.ping_group_range`: the kernel's default `1 0` refuses everyone, systemd and Docker set `0 2147483647` (both checked in a container) | `CAP_NET_RAW` |
| Android | Granted to apps: `init.rc` sets `ping_group_range` to `0 2147483647`; the sockets take the VPN's protection like the core's others (not checked on a device) | Not granted to apps |
| iOS | Granted without entitlements, as Apple's SimplePing uses them; inside a Network Extension Apple's forum reports `bind` and reads on an unconnected socket failing with `EPERM`, which the client avoids (not checked on a device) | Not granted |

Each server address gets its own socket, never bound and connected to it: an
unbound socket is bound on its first send, and replies come only from the
address each packet went to, as Xray-core's Linux server makes them. Linux
datagram sockets put their own identifier in the request, and the server's
replies with it reach them. On macOS and iOS an IPv4 datagram socket would
return the IP header, which the client switches off as Go does.

The mask must be the last UDP mask: Xray-core fails every dial with it
anywhere else. The masks listed before it run inside it. It cannot run with
udphop, xdns or realm, which send elsewhere, nor with header-custom, whose
state Xray-core keys by the server's address and port while replies come
without a port, nor on QUIC with sudoku, whose datagrams exceed what an echo
carries. A QUIC carrier keeps its path MTU discovery off, as quic-go's is on
a masked conn. `scripts/check-xicmp-interop.sh` compares the messages with
Xray-core's own code and, on Linux, runs each carrier against its server.

### TLS ClientHello shaping

`security: "tls"` sends a uTLS-shaped ClientHello, as Xray-core does on every
TLS connection. `tlsSettings.fingerprint` selects the shape from the same 61
names Xray accepts. An absent or empty value means `chrome`, matching Xray's
`GetFingerprint("")`, so shaping is the default rather than an opt-in; an
unknown name is rejected at parse time with a JSON path and the offending
value. Unlike `realitySettings.fingerprint`, no X25519 key share is required,
so ten of the thirteen names REALITY rejects are usable here; the other
three — `hello360_7_5` and its aliases `360` and `hello360_auto`, one profile
under three names — are refused for a separate reason given below. The
X25519MLKEM768 requirement of REALITY v26.10.21 servers does not apply here
either.

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

`tlsSettings.enableSessionResumption` is a boolean (or null). A shaped
handshake never resumes a session, whatever its value: a resumed ClientHello
would carry `pre_shared_key` outside the profile's shape. Xray-core behaves the
same, because its uTLS path does not pass the session cache on to uTLS. With
`fingerprint: "unsafe"`, and on the QUIC paths (XHTTP HTTP/3, Hysteria), stock
rustls keeps its session cache whatever the value, while Xray-core resumes
there only when the value is `true`.

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

Thirteen of the 61 names are TLS-1.2-era, which is exactly the set REALITY
rejects. Ten of those are shaped but not byte-exact; the other three, the
`360` aliases refused below, build no ClientHello at all. The uTLS hello behind
the ten declares no `supported_versions` extension, while the TLS stack
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

#### REALITY v26.10.21 profile requirements

The REALITY server shipped with Xray-core v26.10.21 requires an
X25519MLKEM768 key share (group `0x11ec`, 1216 bytes) before any ordinary
X25519 key share, and treats any other ClientHello as an unauthenticated
visitor. Profiles that meet this are Chrome 131/133, Firefox 148 and
Safari 26.3, including their current `chrome`, `firefox`, `safari` and `_auto`
aliases, plus the frozen `randomizednoalpn` and `hellorandomized` snapshots
(`XRAY_REALITY_HYBRID_FINGERPRINTS`).

Xray-core's client did not narrow `realitySettings.fingerprint` with that
change, and neither do we. A profile without the X25519MLKEM768 share — `ios`,
`edge`, `qq`, older Chrome and Firefox, and the draft Kyber profiles — still
parses and still dials, because servers older than v26.10.21 accept it.
Parsing adds a warning at the `fingerprint` JSON path that names the new
requirement, so a profile that stops working after a server upgrade has an
explanation before the first dial. The thirteen TLS-1.2-era names with no
X25519 key share at all remain a parse error, as before.

For REALITY, `random` and `randomized` each choose independently from the four
fixed hybrid profiles above, once per process. This is a deliberate
restriction of the upstream random pool, which can still pick a profile the
new server rejects. The ordinary TLS random pool is unchanged. `randomized` remains a
browser-profile draw rather than a port of uTLS's randomized-spec generator.

#### What `random` and `randomized` resolve to

For plain TLS, `fingerprint: "random"` draws one of the eleven names in Xray's
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
generator port, not an alias. The snapshot follows Xray's preset, not the bare
uTLS ID: Xray-core's `init()` runs `HelloRandomizedNoALPN` on uTLS's default
weights with TLS 1.3 forced and the legacy P-256 first key share turned off, so
every install offers TLS 1.3 with an X25519 key share and REALITY accepts the
name. Ours is the spec the uTLS oracle builds from those weights with a zero
seed: TLS 1.3 and 1.2, key shares X25519MLKEM768, X25519 and P-256, no ALPN.
Xray seeds the preset once per process, and uTLS adds the X25519MLKEM768 share
on a 0.5-weighted coin, so on xray-core about half of installs send a
`randomizednoalpn` hello that REALITY v26.10.21 servers refuse; ours always
leads with the hybrid share.

`hellorandomized`, `hellorandomizedalpn` and `hellorandomizednoalpn` are
likewise fixed. In Xray those three come from the `OtherFingerprints` table
with no seed pinned and uTLS's default weights, which makes uTLS synthesize a
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

`streamSettings.sockopt` supports the Xray-compatible `happyEyeballs` object,
along with `dialerProxy` (see chaining), `domainStrategy` (below) and the
[socket options](#socket-options) set on each socket:

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

Without the race, two or more candidates are dialed as Go's `net.Dialer` dials
them, which is what Xray-core does when `happyEyeballs` is off. Candidates of
the first address's family are tried one after another, each with an even
share of what remains of 16 seconds (Xray's dial timeout) but at least two
seconds. The other family starts 300 ms after the first attempt, or as soon as
the first family has failed, and the first connection wins. A dual-stack host
whose first address is unreachable, such as `localhost` served on IPv4 only or
a server behind broken IPv6, therefore still connects. One candidate is dialed
directly, as before. The same rules cover Freedom, proxy carriers and REALITY;
socket protection is still fatal.

### Domain strategy socket option

`streamSettings.sockopt.domainStrategy` takes Xray-core's names, ignoring
case: `AsIs` (the default, as are `""` and null), `UseIP`, `UseIPv4`,
`UseIPv6`, `UseIPv4v6`, `UseIPv6v4`, and the same five with `Force` in place
of `Use`. On a `freedom` outbound it decides which addresses a domain
destination may resolve to:

- `IPv4` and `IPv6` ask for that family only; `IP` asks for both.
- `IPv4v6` asks for IPv4, and for IPv6 if that finds nothing; `IPv6v4` is the
  reverse.
- If nothing is found, `Use` looks the domain up again for both families, as
  `AsIs` does, and `Force` fails the connection.

The permitted addresses are then dialed like any other candidates, through
`happyEyeballs` or the sequential rules above. Under `UseIP` and `ForceIP`, a
UDP flow whose destination was an IP address before sniffing or a fake IP
named it prefers that address's family, as Xray-core's `GetDynamicStrategy`
does. When a freedom outbound carries another outbound through `dialerProxy`,
that outbound's server address resolves with freedom's strategy, since
Xray-core hands it to freedom as the destination.

On a WireGuard outbound it picks the address dialed for a peer endpoint that
is a domain, as Xray-core's `MakeResolveLocal` does. The bootstrap resolver
looks the domain up for both families, and the strategy keeps:

- every address under `AsIs`, `UseIP` and `ForceIP`;
- that family's under `IPv4` and `IPv6`;
- under `IPv4v6`, the IPv4 addresses, or the IPv6 ones when there is no IPv4
  address; `IPv6v4` is the reverse.

`Use` and `Force` do not differ there: with no address kept, the connection
fails. An endpoint written as an IP address is dialed as it is.

Xray-core v26.10.31 deprecates freedom's own `settings.domainStrategy` (and
`settings.targetStrategy`, which wins when nonempty), as well as an outbound
`targetStrategy` on freedom, and migrates them into `sockopt.domainStrategy`.
xray-rust migrates them the same way, with equivalent notices: the
outbound `targetStrategy` wins, then the freedom setting, and either one
replaces a `sockopt` value. On freedom, config verdicts for these fields match
`xray run -test`.

Differences from Xray-core:

- Xray-core resolves with its DNS client, and when a `Use` strategy finds
  nothing it hands the domain to the system resolver. xray-rust's freedom
  resolves through the managed resolver in both cases, as it already does for
  `AsIs`, where Xray-core uses the system resolver. A name known only to
  `dns.hosts` therefore still connects after a `Use` fallback.
- Xray-core dials one random permitted address per attempt and retries up to
  five times. xray-rust tries the permitted addresses in order, as for any
  other candidates, and a UDP flow takes the first one.
- Xray-core's WireGuard picks one of the addresses kept at random.
  xray-rust's takes the first. MASQUE reads it for its server's address the
  same way.
- Outbounds other than freedom accept only `AsIs` in `targetStrategy`, and
  those other than freedom, WireGuard and MASQUE only `AsIs` in
  `sockopt.domainStrategy`. A different value on VLESS, Trojan and the other
  proxies fails parsing, because their server lookup and target resolution do
  not read a strategy yet. For the same reason, `dialerProxy` refuses a
  dedicated freedom fragment handler that has a strategy, since inlining it
  would drop the strategy.

### Socket options

The rest of `streamSettings.sockopt` is read as Xray-core v26.10.31 reads it
and set on every socket the outbound opens:

- the TCP carrier of VLESS, Trojan, VMess, Shadowsocks, SOCKS and HTTP, over
  every transport;
- freedom's TCP and UDP sockets, including those of DNS queries routed
  through it;
- the SOCKS and Shadowsocks UDP sockets;
- the QUIC socket of Hysteria and of XHTTP over HTTP/3;
- the UDP sockets WireGuard sends from.

```json
{
  "streamSettings": {
    "sockopt": {
      "mark": 255,
      "interface": "eth0",
      "tcpKeepAliveIdle": 60,
      "tcpCongestion": "bbr",
      "customSockopt": [
        {"system": "linux", "network": "tcp", "level": "6", "opt": "13", "value": "reno", "type": "str"}
      ]
    }
  }
}
```

Values decode as Go decodes them: integer fields take 32-bit integers, text
and booleans take only text and booleans, and null is the zero value.
`tcpFastOpen` takes `true`, `false` or a number, which is truncated and
capped at the 32-bit range.

**Keepalive.** Every outbound TCP socket, with or without `sockopt`, turns
keepalive on after 45 seconds idle and probes every 45 seconds, as
Xray-core's system dialer does. The number of probes is the system's.

- `tcpKeepAliveIdle` and `tcpKeepAliveInterval` set other numbers of
  seconds.
- A negative value turns keepalive off.
- A positive value with a negative one fails every TCP dial of that outbound,
  as in Xray-core. The two are multiplied as 32-bit integers, so a product
  that overflows to a negative number fails too.

**Linux and Android**, in this order:

1. `mark`, the socket's `SO_MARK`;
2. `interface`, the device the socket is bound to;
3. on TCP sockets, `tcpFastOpen` (`TCP_FASTOPEN_CONNECT`: `true` or a
   positive number turns it on, `false` or a negative one off), then
   `tcpCongestion`, `tcpWindowClamp`, `tcpUserTimeout` in milliseconds and
   `tcpMaxSeg`, each when set;
4. `customSockopt`;
5. `tproxy` set to `tproxy` or `redirect`, which sets `IP_TRANSPARENT`.

`tcpMptcp` opens a Multipath TCP socket and dials plain TCP after any
failure, as Go's dialer does.

**Apple platforms**, in this order:

1. on TCP sockets, `tcpFastOpen`, then the keepalive times;
2. `interface`, bound by index;
3. `customSockopt`.

`mark`, `tcpCongestion`, `tcpWindowClamp`, `tcpUserTimeout`, `tcpMaxSeg`,
`tcpMptcp` and `tproxy` do nothing there, as in Xray-core. Apple kernels take
`TCP_FASTOPEN` only on a listening socket. A configured `tcpFastOpen`
therefore fails on every outbound TCP socket and, as in Xray-core, stops the
options after it: such an outbound dials TCP without binding its
`interface`. Keepalive still applies.

**Failures.** The first option that fails stops the ones after it. It is
logged at debug level as "failed to apply socket options", and the dial goes
on. The exception is `interface`: a device that does not exist or cannot be
bound fails the dial. Android apps lack the privilege binding to a device
needs, so there `interface` fails every dial, and `mark` stops the options
after it, as in Xray-core.

**`customSockopt`** entries are text read when a socket is set up:

- An entry applies when `system` is empty or names the platform as Go's
  `runtime.GOOS` does (`linux`, `android`, `darwin` or `ios`), and `network`
  is a prefix of `tcp4`, `tcp6`, `udp4` or `udp6`.
- `level` (6, TCP, when empty), `opt` and an `int` value are decimal
  integers, and other text reads as 0.
- `type` `int` sets an integer, `str` sets the bytes of `value`.
- An empty `opt` or another `type` fails, which stops the options after it.

**`penetrate`** makes an XHTTP `downloadSettings` leg dial with the
outbound's own `sockopt`, chaining included. Without it, the download leg
dials with its own `sockopt` and never chains. The outbound's `dialerProxy`
carries only the upload leg, as in Xray-core. A `dialerProxy`, or a
`domainStrategy` other than `AsIs`, inside `downloadSettings` fails parsing.

**`addressPortStrategy`** replaces a domain server's address, its port or
both with what a DNS lookup of its name finds, before each dial, as
Xray-core's `DialSystem` does. The names ignore case:

- `SrvPortOnly`, `SrvAddressOnly` and `SrvPortAndAddress` cut the name in
  three at its first two dots, drop the first character of the first two
  parts, and look up the SRV records of `_service._proto.name`. The first
  record, by priority and then drawn by weight, gives the target and port.
- `TxtPortOnly`, `TxtAddressOnly` and `TxtPortAndAddress` look up the TXT
  records of the name. The first one that reads as `host:port`, with a
  decimal port up to 65535, gives them.
- `none` and an empty value look nothing up.

The lookup goes where Go's resolver sends it for Xray-core, not to the
platform's resolver: to the nameservers of `/etc/resolv.conf`, over UDP and
then over TCP when an answer is truncated, with the file's search list and
its `ndots`, `timeout`, `attempts`, `rotate`, `use-vc` and `trust-ad`
options. Without the file, as on Android, it asks `127.0.0.1:53` and
`[::1]:53`. Its sockets take the platform's socket protection, not the
outbound's options.

- A failed lookup, or one without a usable record, dials the configured
  server. A server given as an IP address looks nothing up.
- TLS server names, `Host` headers and gRPC authorities keep the configured
  server's name, as there.
- An address found is dialed as a configured one would be: a domain resolves
  as the server's name does.
- The plaintext guard checks the configured server, as Xray-core's does, and
  not the address a lookup finds.

Every proxy outbound reads it for its server, over every transport and UDP
included, and an XHTTP download leg reads the one of the `sockopt` it dials
with. Freedom refuses it, as Xray-core does. WireGuard finds its peer
endpoints with its own lookup, so the strategy changes nothing there, as in
Xray-core.

`acceptProxyProtocol`, `v6only` and `trustedXForwardedFor` are inbound
options. They are type-checked and ignored, as Xray-core ignores them on an
outbound.

Not supported yet:

- `addressPortStrategy` on an outbound that chains through `dialerProxy`
  fails parsing. Xray-core hands the address and port it finds to the
  `dialerProxy` outbound as its destination. A dedicated freedom fragment
  handler is inlined, not chained, and keeps the strategy.
- WireGuard reads no `streamSettings` field other than `sockopt`. The others
  fail parsing, its UDP `finalmask` among them, and so does a `dialerProxy`.
  Xray-core ignores the transport settings, masks the UDP with `finalmask`,
  and carries it through the `dialerProxy` outbound.

## Routing

Supported routing configuration:

- `domainStrategy`: `AsIs`, `IPIfNonMatch`, or `IPOnDemand` (since `0.6.0-dev.0`);
- rule `type`: not read, as in Xray-core v26.10.31, so it may be absent or
  hold anything;
- selectors: `inboundTag`, `domain`/`domains`, `ip`, `network`, `port`,
  `sourceIP`/`source`, `sourcePort`, `localIP`, `localPort`, `user`,
  `protocol`, and `localOS`;
- destination: `outboundTag`, or `balancerTag` when `outboundTag` is absent
  or empty, as in Xray-core;
- `routing.balancers` with `tag`, prefix-based `selector`, optional
  `fallbackTag`, and `random` (the default), `roundRobin`, `leastPing`, or the
  bounded `leastLoad` strategy.

Rule fields read as Xray-core v26.10.31 reads them:

- `inboundTag`, `domain`, `domains`, `ip` and `localOS` are Xray's
  `StringList`: an array of strings, or one string split at commas without
  trimming. Go reads a `null` entry as an empty string.
- `network` names `tcp` and `udp`, case-insensitively. Xray-core keeps any
  other name, such as `quic` or the ` udp` in `"tcp, udp"`, as a network no
  connection uses.
- `port` is a number or a comma-separated string of ports and `from-to`
  ranges over `0..=65535`. A single port reads as a JSON integer, with no sign
  or leading zero, and a range's ends as decimal digits.
- When both are given, `domains` replaces `domain`, though both must parse.
- A condition given with nothing it can match keeps the rule from applying,
  as in Xray-core: `"port": 0`, `""` or a reversed range such as `"2-1"`, a
  `network` of only unknown names, an empty inbound tag, or a geosite
  selection with no domains.
- A rule with no condition at all is refused, as Xray-core refuses it, rather
  than taking every connection.

Rules can also check where a connection comes from:

- `sourceIP` (or `source`, read only when `sourceIP` is absent or `null`) and
  `sourcePort` match the peer: a SOCKS or HTTP client, or for TUN the app.
  `localIP` and `localPort` match the address the connection arrived on. The
  IP fields are IP rule lists like `ip`, and the ports read like `port`. As in
  Xray-core, a connection whose address is unknown, such as a query of the
  built-in DNS, matches no IP rule and has port 0. A TUN flow has no local
  address.
- `user` matches the account a SOCKS client logged in with, also over HTTP
  `CONNECT` on a SOCKS port with Basic credentials, and the flows of its UDP
  association, or the account of an HTTP inbound's Basic credentials.
  Entries are exact, case-sensitive names, or `regexp:` patterns matched
  anywhere in the name. As in Xray-core, an empty name matches nothing and a
  pattern that does not compile is ignored, here with a warning.
- On a SOCKS UDP flow, as in Xray-core, the source is the client's UDP
  endpoint and the local address is the association's relay socket, on its
  own port.

`protocol` matches the protocol sniffing named, by prefix: `http1`, `tls`,
`quic`, `bittorrent` (a BitTorrent handshake over TCP, a uTP `ST_SYN` over
UDP), or `fakedns` for a fake IP whose domain the fake DNS knows when no other
sniffer named it, so `"http"` matches `http1`. As in Xray-core, a flow is named
only when its inbound has sniffing enabled, every sniffer runs whatever
`destOverride` lists, TLS and QUIC need a server name, and `metadataOnly`
names only fake IPs. HTTP needs a `Host` header, read as Xray-core reads it:
the last one counts, even past the headers, its name is not trimmed, and one
whose port Go's `strconv.Atoi` refuses, such as `example.com:0x50`, keeps the
request unnamed. A flow sniffing does not name matches no `protocol`
rule. A request the HTTP inbound forwards, rather than tunnels, is
`http/1.1`, as in Xray-core. When a rule has `protocol`, flows are sniffed for it even where
`destOverride` would not read them, though only `destOverride` decides whether
a sniffed domain replaces the destination. On TUN that opens a TCP flow
before routing it, as for an unmapped fake IP. A flow is read only until every
sniffer has ruled it out, as in Xray-core, so a protocol no sniffer knows is
routed as soon as its first bytes arrive.

`attrs` maps attribute names to regular expressions, and a rule applies when
every named attribute is there and its value matches anywhere in it,
case-sensitively. As in Xray-core, a request the HTTP inbound forwards has
the inbound's own attributes: `:method` uppercased, `:path` decoded, and
each header's first value under its lowercased name, without `host` or
hop-by-hop headers, and with an empty `user-agent` when none was sent. Other
attributes come from sniffing an HTTP request, so the inbound needs sniffing
enabled, and `metadataOnly` records none:

- `:method` and `:path` are the request line's method and target as
  written, query included, when the line has exactly three parts split at
  spaces.
- Every other line with a colon is a header, under its lowercased but
  untrimmed name, with a trimmed value. A later header replaces an earlier
  one. Lines past the headers count too, as Xray-core reads every line up
  to an empty one.
- A `Host` header that does not parse ends the reading, and then no
  `:method` or `:path` is recorded. A request with no host is not named
  `http1`, but its attributes still count.

Names in `attrs` are lowercased, so names that differ only in case keep one
pattern. `null` or `{}` sets no condition, a `null` pattern needs only the
attribute to be there, and a pattern that does not compile refuses the
config, where Xray-core panics. UDP flows and flows sniffing does not read as
HTTP have no attributes and match no `attrs`. When a rule has `attrs`, TCP
flows are sniffed for it as for `protocol`.

`localOS` limits a rule to operating systems named as Go's `runtime.GOOS`,
compared case-insensitively: `darwin` on macOS, `ios` on iOS, its simulators
and Mac Catalyst, `android`, `linux`, `windows`. Go has no tvOS, watchOS or
visionOS value, so those report `ios` too. Unknown names never match, and
`""` makes a rule that never applies. The result is fixed for the process.
Rules are evaluated in declaration order, and every populated selector field
inside one rule is ANDed; alternatives belong in arrays/ranges or separate
ordered rules.

Differences from Xray-core:

- A numeric `port` above 65535 is rejected. Xray-core keeps it and truncates
  it to 16 bits when matching, so `65617` would match port 81.
- Regular expressions in `regexp:` domains, `user` and `attrs` are compiled
  by Rust's `regex` crate, not Go's RE2. The two read a few constructs
  differently. `\Q…\E` and octal escapes such as `\0` are refused here,
  while `(?x)`, `(?u)`, `\u0041`, `a++` and repeat counts above 1000 are
  accepted here, where Xray-core refuses them. `\d`, `\w`, `\s` and `\b` match
  Unicode here and ASCII in Go. `\<`, `\b{start}` and `&&` in a class are
  assertions or set operations here and literals in Go.
- Where Xray-core's HTTP sniffer waits for more bytes, as for a request
  without a `Host`, it routes after about 200 ms; here the request is routed
  once its headers end.

`IPOnDemand` resolves a domain when evaluation reaches an IP condition, after
the rule's inbound, network, protocol, port and user predicates and before its
domain predicate, matching the pinned Xray order. An earlier matching domain-only rule avoids
DNS entirely. A combined domain/IP rule can trigger DNS even when its domain
predicate will not match. Every returned address is eligible, while rule order
takes priority over address order and the outbound receives the original
destination. At most 256 unique socket-address candidates are allowed; an
oversized result fails the selection rather than being truncated. The resolver
owns its result allocation; this is a bound on routing work.

Each selection attempts at most one lookup through the shared managed
resolver/cache. On lookup failure or an empty answer, later domain/metadata
rules still apply, otherwise the configured default is used. Internal DNS
bootstrap routing skips resolution for both strategies to prevent recursion.
The new strategy inherits configured DNS families, single-flight, bounded
stale service, and cancellation; it does not introduce its own resolver or
background tasks. Literal IP targets never require DNS.

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
awaits an `IPIfNonMatch` or `IPOnDemand` lookup retains its original revision. Direct targets
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
5-second timeout and, as in Xray-core, considers any HTTP response healthy,
whatever its status; the request carries Xray's Chrome navigation headers.
Sequential mode sleeps for the interval after each outbound, matching Xray's
pacing. Concurrent mode probes at most four outbounds at once, then sleeps for
the interval after the full round.

The observer starts only after the core and any configured startup probe have
started successfully. It dials each leaf directly by tag, so routing rules and
selector state cannot redirect its measurement. Stop cancels the observer with
the rest of the core runtime. Rust health snapshots expose unknown/healthy/
unhealthy state, delay, last-try and last-success timestamps, consecutive
failure count, and a typed redacted failure category; raw URLs and transport
error strings are not retained.

Hosts that schedule their own checks, such as a mobile tunnel heartbeat, can
request one probe at a time through C ABI 1.9 and the Swift/Kotlin adapters
without an `observatory` object. It accepts the same URLs as the startup probe,
dials one leaf by tag or the default outbound with routing bypassed, takes a
host timeout of 1 to 60000 ms, and returns the delay or the same typed failure
category. Its result is not written to health snapshots and does not
influence selector groups.

Domain matchers, read in routing rules as Xray-core's `ParseDomainRules`
reads them:

- bare string or `keyword:value`, a substring. Text with any other prefix,
  such as `foo:bar`, is a substring too;
- `domain:value`, `full:value`, `regexp:value`, `dotless:value`;
- `geosite:code` and `geosite:code@attribute`;
- `ext:file.dat:code`, and its spellings `ext-domain:` and `ext-site:`.

A prefix may have an empty value, as in Xray-core: an empty substring,
`keyword:` or `regexp:` matches every domain, `domain:` only names ending in a
dot, and `full:` none.

IP matchers:

- IPv4/IPv6 address or CIDR;
- `geoip:private`, built in so no `geoip.dat` is needed: Xray-core's own
  private/reserved set (`common/geodata/consts.go`), which includes `0.0.0.0/8`,
  `198.18.0.0/15`, the TEST-NETs, IPv4 multicast and reserved space through
  `255.255.255.255` (`224.0.0.0/3`), `::/127` and `ff00::/8`, as common
  `geoip.dat` builds do;
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

If no rule matches, the first outbound is used as the default.

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
AAAA answer.

`UseSystem` (or `UseSys`, `use_system`, `use-sys` and the other Xray
spellings) is `UseIP` narrowed on each lookup to the address families the
system has a route for, as Xray-core v26.10.31's `checkSystem` narrows them:

- A UDP `connect` toward a root DNS server of each family, which sends
  nothing, tells which families have a route. A family without one is neither
  asked for nor answered, and with neither, a lookup is answered empty.
- On Android, iOS, macOS, Windows and a Linux desktop session the result stands
  for 100 ms, elsewhere for the life of the core, as in Xray-core.
- The probe sockets go through the socket protector, so inside the mobile VPN
  they see the network the core dials over. Xray-core's unprotected probe sees
  the VPN's own routes on Android.
- A server's own `queryStrategy: "UseSystem"` narrows that server alone, as
  `UseIP` would with the global strategy; one left without a routed family is
  passed over.
- The destination cache keys each entry by the families routed when it was
  looked up, so a change of network takes effect on the next lookup. Answers
  hijacked from TUN and fake IP answers follow the same routes. Bootstrap
  resolution keeps ignoring the global strategy.

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
`queryStrategy`, `finalQuery`, `tag`, and `timeoutMs`. `domains` is Xray's
`StringList`: an array, `null`, or one string split at commas without
trimming, where a `null` entry reads as an empty string. Its entries are domain
rules as Xray-core v26.10.31's `geodata.ParseDomainRules` reads them:
`keyword:`, `domain:`, `full:`, `regexp:`, `dotless:`, `geosite:`, and `ext:`
with its `ext-domain:` and `ext-site:` spellings. Anything else, even text
with a colon such as `foo:bar`, is a substring, and a prefix may have an empty
value: an empty entry, `keyword:` or `regexp:` puts every name first, while
`domain:` and `full:` put none, because names lose their terminal dot before
matching. A geosite selection with no domains is accepted and puts no name
first.
Top-level `disableFallback`, `disableFallbackIfMatch`, `disableCache`,
`serveStale`, and `serveExpiredTTL` are also supported. `serveStale: true`
requires caching plus an explicit `serveExpiredTTL` from 1 through 86400
seconds. Xray treats zero as an unbounded stale lifetime; this mobile-oriented
core rejects that value rather than silently retaining records forever.
Per-server cache/stale overrides remain unsupported because the current cache
is owned once per Core rather than once per upstream. Special
`localhost`/`fakedns` clients and routed DoQ are rejected until their
runtime semantics exist; they are not silently approximated as classic UDP.

`enableParallelQuery: true` asks every server a lookup selects at once, as
Xray-core v26.10.31's parallel query does, instead of one after another. The
selection is the serial one. Servers next to each other in it that share a
policy race as a group: the first of them, in selection order, to answer with
addresses gives the answer. Groups settle in order, so a later group's answer
waits until every member of the earlier groups failed, and the remaining
lookups are dropped once an answer is found. Two servers share a policy when
their own `clientIp`, `skipFallback`, `queryStrategy`, `tag`, `domains`,
`expectedIPs`, `expectIPs` and `unexpectedIPs` are equal as Xray-core's config
builder compares them: as written, trimmed and lowercased, with lists sorted.
So `"queryStrategy": "UseIP"` and an absent one are two policies there and
here, and every string entry shares the policy of an object with none of those
fields. A `null` `enableParallelQuery` is `false`, as in Go.

`clientIp`, at the top level and in an object server, is sent as the EDNS
client subnet (RFC 7871) of every query, as Xray-core v26.10.31 sends it. A
server's own value replaces the top-level one, and a `null` one means none, so
the top-level value applies. The value is an IP address read as Xray-core reads
an address: brackets and surrounding spaces are dropped, an IPv4-mapped
address is IPv4, and a domain, `host:port` or a non-string fails the
configuration. The query then carries Xray-core's OPT record byte for byte: a
1350-byte UDP payload size, the DNSSEC OK bit, an extended RCODE byte of
`0xE0` (from Go packing `SetEDNS0(1350, 0xfe00, true)`), and the address cut to
/24 for IPv4 or /96 for IPv6. With the DNSSEC OK bit, servers may add
signature records; answers keep only the addresses. Every DoH query carries
EDNS padding (RFC 7830) of 100 to 299 zero bytes, drawn once per lookup for both
families, as Xray-core pads it, with or without a client subnet.

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
`qType` is Xray's `PortList`: a number, or a comma-separated string of types
and `from-to` ranges over `0..=65535`, where empty entries add nothing. A
single type reads as a JSON integer, with no sign or leading zero, and a
range's ends as decimal digits. As in Xray-core, a reversed range such as
`"24-23"` adds no type, and a rule left with no type answers every type, as
does `"qType": 0`. Ranges stay compact and are normalized instead of being
eagerly expanded. Deliberately, a number above 65535 is rejected: Xray-core
keeps it and truncates it to 16 bits, so 65617 would answer type 81. `rCode`
accepts `0..=65535`, defaults to zero, and is used by Return and by Hijack when
the selected query is not A/AAAA. `domain` is a `StringList` of the same
domain rules as a server's `domains`, plain text being a substring. An absent,
`null`, or empty list sets no condition; any entry sets one, even a geosite
selection with no domains, which then matches no name. Rules are ordered,
selectors inside a rule are ANDed, and a miss Hijacks A/AAAA and Returns an
empty NOERROR response for other types.

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
domain string, an Xray-core `"#N"` RCODE string, or a nonempty ordered array
containing only IP strings. Every IP in an array is retained as a resolution
candidate. Names are canonicalized to
lowercase without a terminal dot at the managed resolver boundary. Keys are
domain rules as Xray-core's `geodata.ParseDomainRule` reads them, with the
whole name as the plain form: an unprefixed key, even one with a colon such as
`foo:bar`, is an exact name rather than a routing-style keyword. Prefixes may
have empty values, so `keyword:` maps every name, while an empty key, `full:`
or `domain:` maps none. `ext-site:` spells `ext:`, and a geosite selection with
no domains maps nothing. Explicit `full:` mappings take precedence over
broader matching rules. Alias resolution is bounded to eight hops; static IP
candidates use the shared 10-second hosts TTL. If that bound is reached, the
terminal alias still uses the configured DNS-server plan; only a configuration
without DNS servers may send it to the operating-system fallback.

A `"#N"` value, as in Xray-core's `app/dns/hosts.go`, answers the name with
DNS RCODE `N` and no records instead of resolving it; `"#3"` (NXDOMAIN) is the
usual way to block a domain. It applies to the name itself and to names that
alias to it. The DNS outbound Hijack, the TUN DNS hijack and the fake IP Hijack
answer A and AAAA queries with that RCODE before any server or fake IP is
used, and routing (`IPOnDemand`, `IPIfNonMatch`), `domainStrategy` and freedom
lookups see a failed lookup with no addresses. `"#0"` is an empty NOERROR
answer, as Xray-core turns it into an empty response. `N` is read like Go's
`strconv.Atoi` (so `"#+5"` and `"#05"` are 5), but must be 0 through 15: the
DNS header holds a 4-bit RCODE, and Xray-core writes a larger value over the
neighbouring header flags. `"#"`, a non-integer, a negative value or one above
15 is rejected with a config error. An array keeps accepting only IP strings.

Deliberately, a `full:` or `domain:` pattern in `dns.hosts`, a server's
`domains` or a DNS outbound rule drops its terminal dot too, so
`full:x.test.` matches `x.test`. Xray-core drops the dot from the query but
not from the pattern, so there such a pattern never matches.

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
policy, and the broader
Xray DNS feature set are not implemented. This does not limit the DNS
outbound's documented TLS/REALITY `streamSettings`. The public resolver result
carries every candidate and TTL metadata. An explicitly enabled
`sockopt.happyEyeballs` policy consumes those candidates through the bounded
raw-TCP race described above; its Xray-compatible zero-delay default leaves the
race disabled and dials the candidates the way Go's `net.Dialer` does.

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
SOCKS and HTTP relays follow Xray-core's half-close timer: `connIdle` while
both directions are open, `downlinkOnly` once the client finished sending, and
`uplinkOnly` once the server finished sending. Each phase uses the shorter of
the inbound and outbound level values. TUN TCP applies `downlinkOnly` after
the app finished sending and closes the flow when the server finished sending.
Missing values default to Xray-core's `connIdle` 300 s and `uplinkOnly` and
`downlinkOnly` 1 s.
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
with `xray_core_set_geodata_search_dir` before loading the config. The Swift and
Kotlin adapters expose it as `geodataSearchDirectory`.

File names must be relative and cannot escape a configured search directory.
Parsing enforces file, entry, matcher, rule, attribute, domain, and CIDR budgets
to bound untrusted input.

A selected GeoIP entry may contain up to 500,000 CIDRs. The entry is checked
before protobuf decoding. Every expansion is charged against the shared
per-configuration IP and total matcher budgets, including repeated references
to a cached category in different rules or DNS selectors.

This allows large current country sets: for example, Loyalsoldier's
[202609082347 snapshot](https://github.com/Loyalsoldier/v2ray-rules-dat/releases/tag/202609082347)
contains 300,531 CIDRs in `geoip:us`, exceeding the earlier limits of 250,000
CIDRs per category and 300,000 IP matchers per configuration. Raising these
ceilings increases the maximum parsing work and routing state a configuration
can request. File-size, entry-size, path, and other resource checks still apply.

## Diagnostics

Parser errors include JSON paths. Warnings do not fail a load; callers should
display them. The C ABI exposes warnings through
`xray_core_config_warnings`, and the checked-in Swift/Kotlin adapters surface
them through their platform logging paths.

Current aggregate limits include 4,096 routing rules, 250,000 domain matchers,
750,000 IP matchers, and 1,000,000 matchers total per config. These limits are
implementation safeguards and may change across major ABI or documented
configuration revisions.
