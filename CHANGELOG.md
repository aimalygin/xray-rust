# Changelog

All notable changes will be documented in this file.

In this changelog, the stable channel means a non-prerelease tag eligible for
registry publication. Published packages are listed in
[GitHub Releases](https://github.com/aimalygin/xray-rust/releases). All versions
below 1.0 remain pre-1.0 in API and security maturity and do not imply a
long-term supported release series.

## Unreleased

- Android, iOS and tvOS: an SRV or TXT `addressPortStrategy` works. With no
  `/etc/resolv.conf` on the device, the lookup now asks the servers in
  `dns.servers`, routed and protected as the core's own DNS queries. Each
  dial used to ask loopback nameservers, as Go does, that no phone runs, and
  dial the configured server once they failed. Without a server to ask, the
  configured server is dialled at once and the log says so once. See
  [Socket options](docs/xray-core-differences.md#socket-options).
- A TCP flow through a MASQUE or WireGuard outbound recovers from a burst
  loss without waiting for its retransmission timer. The userspace TCP/IP
  stack resent one segment when the peer had repeated an ACK three times and
  left every other segment of the same burst to the timer, which waited at
  least a second. It now resends the next missing segment with each ACK that
  stops short of what was sent (NewReno, RFC 6582), reads the peer's
  selective ACKs for a loss that repeated ACKs do not show, a retransmission
  lost in its turn among them, and halves its window once for a burst
  instead of once for each segment found missing. Where the peer has nothing
  to say, a flight lost whole or at its end, the timer still decides. Over
  MASQUE it now fires 200 ms past the round trip, as Linux's does, instead
  of the second of RFC 6298; over WireGuard it keeps the second. TCP that
  enters through the TUN interface is terminated by other sockets, which
  take neither change. Xray-core's MASQUE server drops what a burst leaves
  beyond 32 queued packets, so an upload through it paid that second over
  and over. On a loopback one 64 MiB upload took 5 to 8 s and takes 0.25 s
  (Xray-core's own client: 0.4 s); eight parallel 256 KiB uploads took
  1.0 s and take 0.02 s, or about 0.2 s in the runs where a flow loses a
  whole flight (Xray-core: 0.03 s). WireGuard times on a loopback are
  unchanged: nothing is dropped on that path.
- A TCP flow through a MASQUE or WireGuard outbound no longer stops for good
  while it uploads. Two faults in the userspace TCP/IP stack could strand it.
  The stack went to sleep when its queue of outgoing packets was full, and
  only WireGuard's engine told it when the queue had drained: over MASQUE it
  slept on with the queue empty and packets waiting to be read. And a fast
  retransmit that met a full queue was forgotten instead of sent with the
  next free slot, which left a flow with unacknowledged data and no timer;
  this one could strand a WireGuard flow as well. Against Xray-core's MASQUE
  server on a loopback, eight parallel uploads used to hang in a large share
  of runs. They complete now.
- Linux: the download of a connection from a SOCKS, HTTP or transparent
  inbound is moved in the kernel with `splice(2)` once the outbound reads a
  bare TCP socket: a freedom outbound from its first byte, and VLESS Vision
  after its download switches to direct mode, as Xray-core moves them. On a
  saturated loopback this doubled download throughput and halved the
  client's CPU per byte; upload, encrypted streams, TUN flows and every
  other platform copy as before. A pipe the kernel will not grow to 64 KiB,
  or a `splice` it refuses, falls back to copying. Xray-core's
  `xray.buf.splice` environment flag (`XRAY_BUF_SPLICE`) turns it off, here
  for Vision as well as freedom. See
  [Linux splice](docs/xray-core-differences.md#linux-splice).
- A TCP connection relayed from a SOCKS, HTTP or transparent-proxy inbound,
  or for a reverse session, no longer keeps the memory a transfer needed for
  as long as it stays open. Each direction used to grow a buffer of its own up
  to `bufferSize` (128 KiB by default) and keep it until the connection
  closed. It now keeps 4 KiB and reads past that into a buffer the process
  lends, which it gives back whenever no data is waiting. Read sizes are
  unchanged. On macOS, 512 connections held open after each moved 4 MiB in
  both directions take 16 MiB instead of 150 MiB, and 13 MiB instead of 21 MiB
  after an 8 KiB exchange; throughput and latency measured the same. A
  `bufferSize` above 128 KiB still gives each direction its own buffer. TUN
  flows use other buffers and are unchanged. See
  [Policy](docs/config-compatibility.md#policy).
- The crawl a REALITY client runs when its server answers with a real
  certificate is now limited across the process: four at once, two on a
  phone. A connection answered that way while that many are running is closed
  instead of crawled and fails with the same error. Until now every such dial
  left a connection held for up to 120 s, so a network that redirected the
  server's address to the real site, or a profile its server no longer
  matched, could exhaust a VPN extension's memory and descriptors. See
  [REALITY real-certificate crawl](docs/xray-core-differences.md#reality-real-certificate-crawl).
- Compatibility reference moved to Xray-core v26.11.9
  (`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`, Go 1.27.3): CI, interop
  guards, oracle modules, fixtures and the benchmark harness pin it. See the
  [migration record](docs/xray-core-v26.11.9-migration.md).
- Freedom `finalRules` read `delay` and `logLevel` as Xray-core v26.11.9
  does. `blockDelay` still works with a deprecation warning and wins over
  `delay`; `logLevel` is `none`, `debug`, `info`, `warning` or `error`, is
  checked, and writes nothing here, since xray-rust logs no blocked
  connection. An allow rule with a delay or a level is refused, as upstream
  now refuses it. See [Freedom outbound](docs/config-compatibility.md#freedom-outbound).
- `chrome`, `hellochrome_auto` and an empty `fingerprint` send Chrome 155,
  Xray-core v26.11.9's default: Chrome 133's hello with GREASE and ML-DSA
  44/65/87 signature algorithms and a `trust_anchors` extension carrying 28
  Chrome Root Store trust anchor IDs. `hellochrome_155` is a new name and joins
  `random`'s draw; `hellochrome_133` keeps Chrome 133. See
  [TLS ClientHello shaping](docs/config-compatibility.md#tls-clienthello-shaping).
- Every uTLS-shaped hello, on TLS and REALITY, draws its GREASE values per
  connection as uTLS does, one per slot, and the Chrome profiles whose uTLS
  spec shuffles its extensions (`hellochrome_106_shuffle` through
  `hellochrome_155`, and so `chrome`) draw their extension order per
  connection too, GREASE, padding and pre_shared_key staying in place. Until
  now each profile sent `0x0a0a` in every GREASE slot and one fixed order.
  See [uTLS per-connection draws](docs/xray-core-differences.md#utls-per-connection-draws).
- The Chrome profiles with ECH GREASE (`chrome`, `hellochrome_120`,
  `hellochrome_120_pq`, `hellochrome_131`, `hellochrome_133` and
  `hellochrome_155`) draw its payload length per connection as uTLS does, 128,
  160, 192 or 224 bytes, instead of always 128. Padded profiles now pad as
  BoringSSL does: a hello past 511 bytes before padding goes out without the
  padding extension instead of with an empty one, and one of 508 to 511 bytes
  gets a single byte. Chrome 120's hello now goes unpadded with the three
  longer ECH lengths, as does any padded profile's behind a long server name.
  See [ECH GREASE](docs/config-compatibility.md#ech-grease).
- A uTLS-shaped hello answers a HelloRetryRequest as uTLS does. The second
  ClientHello carries the requested group's key share alone, where it kept
  the GREASE share beside it and was refused with `illegal_parameter` by
  OpenSSL and Go servers; a cookie goes anywhere but the last two places,
  where the second ClientHello could not be built at all; and the padding
  follows the second ClientHello's own length. It takes a server sharing no
  key share group with the profile, or one sending a cookie, to ask for a
  retry. See [TLS ClientHello shaping](docs/config-compatibility.md#tls-clienthello-shaping).
- XDRIVE on Google Drive follows Xray-core v26.11.9: rings as deep as
  `concurrency` (64 by default, at most 256) with spare rings made ahead,
  sessions announced after their first segment with that segment inline,
  read-ahead and hedged reads, and on the Drive side a shared token fetch
  with background refresh and backoff, a stop on refused OAuth credentials,
  a cooldown after throttling, a reserved lane for watermarks and the head,
  per-try timeouts that retire stalled connections and a 32 MiB answer cap.
  It still meets v26.10.31's server. See [XDRIVE](docs/config-compatibility.md#xdrive).
- Mux runs every TCP `concurrency` from zero up to 128 as 128 children per
  parent, keeps a larger one, and lets a parent hand out 1024 children over
  its life, as Xray-core v26.11.9 does; both concurrencies take any 16-bit
  value instead of at most 64.
- Hardening of the transports and parsers added since 0.9.0 against a
  hostile or broken peer:
  - mKCP: a datagram too short for the masks inside an `mkcp-legacy` AES
    mask is dropped; it used to panic the connection's driver, which left
    the stream hanging. A repeated data segment is acknowledged again in its
    place instead of growing the ack list, and every ack flush, without
    bound as Xray-core's does.
  - xmc: reading stops while more than 64 KiB of keep-alive answers wait for
    the carrier, so a server that sends keep-alives and reads nothing no
    longer grows the client's memory.
  - realm: one attempt punches at most 64 addresses. Xray-core punches every
    address the rendezvous lists, ten times a second for ten seconds.
  - MASQUE: the control capsules waiting for the request stream are bounded
    at 256 KiB as well as at Xray-core's 128 capsules, and the error for a
    `user` with a colon no longer quotes the value. Over HTTP/2, a DATAGRAM
    capsule longer than the 8,192-byte packets the tunnel reads is skipped
    as it arrives instead of being queued whole and dropped on read. A
    tunnel the proxy closes within five seconds of establishing it counts as
    a failed dial, so flows wait a second before the next handshake instead
    of each paying for one.
  - HTTP inbound: a header block of a request, or of a response it forwards,
    stops at 1 MiB (Go's `http.DefaultMaxHeaderBytes`) instead of being read
    for as long as the peer sends headers. A header whose name is not a
    token, such as `Transfer-Encoding : chunked`, is no longer forwarded;
    Go's `Header.writeSubset` leaves it out too.
  - xdns: a UDP resolver's socket reads answers from that resolver's address
    alone. Xray-core reads them from any source.
  - VLESS reverse: a tunnel whose portal lets more than 2,048 session Ends
    wait unread fails instead of queueing them without bound.
- Socket options: `sockopt.interface` is bound before every other option.
  In Xray-core's order an option that fails first stops the rest, the
  binding among them: `tcpFastOpen` on Apple platforms, where the kernel
  refuses it on a dialing socket, and a `mark` the process may not set, as
  on Android, left the socket unbound and the dial went on over whatever
  interface the system chose. The connection to a `realm` rendezvous and
  the `addressPortStrategy` lookups now take the outbound's `sockopt` as
  well as the platform's protection, and so does the raw socket of an
  `xicmp` mask without `dgram`.
- DNS: a server's `queryStrategy: "UseSystem"` while the system routes
  neither family, the gap between two networks, leaves the lookup unanswered
  instead of answering it empty. The empty answer stayed in the DNS cache for
  30 seconds after the routes were back.
- The FinalMask `filter` mask is accepted in `finalmask.tcp` and
  `finalmask.udp` of any outbound, any number of times and anywhere, as
  Xray-core v26.11.9's client accepts it. Its `blockedSourceIPs` and
  `allowedSourceIPs` are validated as `Filter.Build` validates them,
  `geoip:` and `ext:` rules against the geodata files, and the mask is then
  ignored: Xray-core filters only a server's incoming connections, and its
  client passes every connection through. Profiles carrying a filter, which
  failed to parse, now load, and a carrier with filters sends what it sends
  without them. A filter after udphop or xicmp is refused, where Xray-core
  fails every dial. See [filter mask](docs/config-compatibility.md#filter-mask).
- Freedom and WireGuard take FinalMask's UDP masks, as Xray-core v26.10.31's
  `FinalMask.DialUDP` wraps their sockets: noise, `header-custom`, Salamander
  with Gecko, sudoku, xdns and xicmp, with the code and order of the QUIC
  carriers' masks. Freedom puts every UDP flow under them, from SOCKS and
  TUN, the PROXY header, its `noises` and the DNS queries routed through it
  included; a masked flow takes replies only from its destination. WireGuard
  puts its one socket under them, which takes one peer and opens anew with
  the masks' state at every rebind. udphop and realm are refused on both for
  now. See [UDP masks on freedom and WireGuard](docs/config-compatibility.md#udp-masks-on-freedom-and-wireguard).
- A ChromeParrot connection that closes before its handshake is confirmed
  sends its CONNECTION_CLOSE once. One packet per datagram stopped the close
  at the first packet space with keys, the connection never counted it as
  sent, and it made a new close packet on every poll, as fast as the socket
  took them, until the close timer: after a certificate the client refused,
  or a dial given up after the Finished. Found in XHTTP over HTTP/3 and
  Hysteria, which parrot Chrome by default.
- Xray's BBR (`conservative` and `aggressive`): the bytes a bandwidth should
  have delivered over an interval no longer wrap past 2^63, which 100 Mbit/s
  reaches after 92 idle seconds. The wrapped, negative count kept the
  ack-aggregation epoch open on the first ACK after the idle and took the
  cap off the congestion window. Xray-core's product wraps.
- A TUN session over a file descriptor no longer dies without the host
  hearing of it:
  - A packet the device refuses stops holding the write queue. A raw-IP
    packet that is neither IPv4 nor IPv6, or any write that fails with
    `EINVAL` or `EMSGSIZE`, was retried with backoff for ever while every
    packet behind it waited; it is now dropped and counted in
    `outbound_dropped_packets`.
  - Android: `XrayVpnService` on the default file-descriptor backend calls
    `onXrayTunnelFatalError` when the core's read or write loop gives up on
    the descriptor. Only the packet-pump backend reported a dead tunnel
    until now, so the app kept showing a tunnel that moved no packets.
    `XrayTunStats` gains `tunFdReadLoopExits` and `tunFdWriteLoopExits`.
    A shutdown step that throws during that teardown no longer swallows the
    callback.
  - A TUN TCP flow whose client sends a few bytes and closes while the
    sniffer still waits for more keeps those bytes for the destination. The
    flow was closed and the bytes dropped without an error.
- XHTTP, MASQUE and XDRIVE's storages over HTTP/3 move to a fresh protected
  socket when the host reports that the OS network changed, and keep their
  streams and tunnels, as Hysteria and WireGuard already did. Until now such a
  connection sat out its idle timeout on a socket whose network was gone
  before the next flow dialed again. `xray_core_rebind_hysteria` carries the
  request, so hosts need no change: the mobile wrappers already call it on
  every network change. `Core::rebind_quic` is the Rust entry. Connections
  behind a `realm`, `xdns` or `xicmp` mask, and mKCP, do not move. Xray-core
  has no counterpart.
- Hysteria, XHTTP over HTTP/3 and XDRIVE's storages over HTTP/3 shape their
  QUIC handshake like Chrome's, as Xray-core v26.10.31's default ChromeParrot
  does, unless
  `finalmask.quicParams.disableChromeParrot` is true. Until now the flag had
  to be true: without it parsing warned, `false` failed, and profile imports
  set it. It is now read as Xray reads it, a Go `bool` with `null` for false,
  on every transport, and imports no longer add it. See
  [ChromeParrot](docs/config-compatibility.md#chromeparrot).
  - The ClientHello is uTLS's Chrome QUIC one: no GREASE, TLS 1.3,
    X25519MLKEM768 and X25519 key shares, brotli certificate compression,
    ALPS, a GREASE ECH extension, and its extensions in a new random order
    on every connection, drawn as uTLS draws it.
  - The vendored `quinn-proto` gains `TransportConfig::chrome_parrot`:
    transport parameters encoded as Chrome encodes them, Initial packet
    numbers from 1 with Chrome's lengths, 1,250-byte chaos-protected Initial
    datagrams (a large ClientHello's head and tail first), and one packet per
    datagram until the handshake is confirmed, the Handshake ACK apart from
    the Finished.
  - quic-go's pinned values apply with it: a 30-second idle timeout, 6 MiB
    stream and 15 MiB connection windows, 100 and 103 streams, zero-length
    source connection IDs and an 8-byte first destination ID; Hysteria
    advertises 65,536-byte DATAGRAM frames, as Xray's client then does.
  - The congestion controller that runs before Xray's switch starts at
    quic-go's 32-packet window instead of 12,000 bytes.
  - MASQUE never parrots Chrome, as in Xray-core.
  - `H3QuicConfig::chrome_parrot` turns it on for any HTTP/3 client, with the
    TLS configuration `TlsConnector::h3_client_config_for` builds for it.
- A VLESS outbound with `reverse` is the bridge of Xray-core v26.10.31's
  VLESS reverse proxy: it keeps tunnels open to its server, and the server,
  the portal, opens TCP and UDP connections back through them to what the
  bridge's routing lets it reach. See
  [VLESS reverse proxy](docs/config-compatibility.md#vless-reverse-proxy).
  - Each connection is routed as if an inbound tagged `reverse.tag` had
    accepted it, with the portal's client as its source, the outbound's
    `email` as its user and `reverse.sniffing` as its sniffing. A freedom
    outbound refuses these connections unless its `finalRules` allow them,
    as Xray-core's freedom does, so each service the portal may reach needs
    an `allow` rule. So does the freedom a `dialerProxy` chain ends on, for
    the hop before it, and for the tunnel when the outbound dials through
    one; under a shared Mux, `testpre` or gRPC connection the chain is left
    as it is. Under an XHTTP link, and through a dedicated freedom fragment
    outbound that `dialerProxy` names, sessions and the tunnel are refused
    before dialing unless that freedom's `finalRules` allow the server.
  - Tunnels are kept as Xray-core keeps them: every two seconds the bridge
    opens one when none is active or each holds more than 16 sessions, and
    another when the portal drains one after more than 256 sessions. A
    tunnel lost to a network change is replaced once the carrier fails or
    nothing crossed it for the `connIdle` of the outbound user's level, 300
    seconds by default.
  - A tunnel is a VLESS request with the reverse command over the outbound's
    whole carrier: every transport and security, VLESS encryption, Vision,
    the TCP masks, `sockopt` and `dialerProxy`. A core with only a bridge
    starts without an inbound.
  - The legacy `reverse` at the root, with bridges and portals, fails parsing
    with Xray-core's message: upstream removed it in v26.4.25. The portal's
    side, VLESS inbound users with `reverse`, is not supported.
  - Deliberate differences: a tunnel holds at most 512 sessions and a bridge
    16 tunnels; each destination of a UDP session is routed on its own, as a
    SOCKS association's are; a bridge whose outbound cannot be built, such as
    Vision without TLS or REALITY, fails the core's start; XHTTP links and
    folded freedom fragments refuse always, where Xray-core refuses only the
    dials that carry the session.
- quinn-udp 0.5.16. On macOS and iOS, a datagram longer than the 1,472-byte
  receive buffer no longer makes a QUIC carrier spin at full CPU:
  - The carriers are Hysteria, XHTTP over HTTP/3, MASQUE over HTTP/3 and DoQ.
    Salamander reads into its own buffer and was not affected.
  - quinn-udp 0.5.15 retried recvmsg after the cut datagram until a datagram
    that fits arrived.
  - On macOS the socket is connected, so only the server or a host on the path
    could cause it. On iOS anyone who could reach the client's port could.
  - Linux and Android were not affected. 0.9.0 was.
- The FinalMask `fragment` mask selects whole writes with `packets`, as
  Xray-core v26.10.31 does: empty or absent cuts every write, a number or a
  `from-to` range the writes so numbered, each into raw pieces, every piece
  its own write followed by its delay. Raw pieces need no TLS, so they run
  on any TCP carrier of a proxy and on a raw freedom outbound; the deprecated
  freedom `fragment` reads the same selectors. `tlshello` keeps its record
  split. A write stages at most 64 KiB, 4096 pieces or ten seconds of delays
  at once and continues in its next call. See
  [TLS ClientHello fragmentation](docs/config-compatibility.md#v08-tls-clienthello-fragmentation).
- The FinalMask noise mask builds `type: "exp"` packets as Xray-core does:
  `<b hex>`, random `<r>` bytes, `<rc>` letters and `<rd>` digits, `<t>` Unix
  seconds, the connection's `<c>` counter and an eight-byte `<n>`, built anew
  for every send. A corpus of expressions read by Xray-core's own
  configuration, and the packets its mask sends, are checked against
  `tools/noise-exp-oracle`. A nonempty `script` (Lua) is refused for now. A
  `hex` noise packet no longer accepts a sign, as Go's decoder refuses it.
- Salamander, Gecko with it, runs on XHTTP over HTTP/3 and MASQUE over
  HTTP/3 as on Hysteria, and Salamander on mKCP as a header mask grouped with
  `mkcp-legacy`'s, as Xray-core applies it to any UDP dial. Gecko on mKCP is
  refused for now. See [Hysteria carrier additions](docs/config-compatibility.md#v08-hysteria-carrier-additions).
- The `xdrive` transport carries VLESS through a storage both ends reach, as
  Xray-core v26.10.31's client does: each connection announces a session
  under `sessions/`, writes its direction as numbered segments under
  `streams/<session>/c2s` and reads the server's under `s2c`, with `.end`
  and `.err` marks, the writer's coalescing of a growing buffer for up to
  eight flush ticks and the reader's polling, hole timeout and deletes. The
  `local` service keeps the objects as files in `remoteFolder`, so a client
  and Xray-core's server meet in a shared folder; `s3` keeps them in a
  bucket and `template` in any HTTP storage a JSON template describes. See
  [XDRIVE](docs/config-compatibility.md#xdrive).
  - `xdriveSettings` is read as Xray-core reads it, all four services and
    every field; the outbound must be VLESS with `encryption`, without
    `flow` or `testpre`, with Mux on for TCP and UDP. The server address is
    never looked up.
  - The HTTP storages are reached as Xray-core's Go client reaches them:
    the stream's TLS, or a Chrome hello without it, HTTP/2 or HTTP/1.1 by
    ALPN with Go's settings, flow-control windows, pseudo-header order and
    headers, Chrome's `fetch` headers, transparent gzip, a 60-second stall
    timeout, one connection a host until it answers over HTTP/1.1, XMUX
    reuse with the HTTP/2 keepalive of `hKeepAlivePeriod`, and
    `streamSettings.address` and `port`, now read for XDRIVE, as the place
    every connection goes.
  - `s3`: path-style or virtual-hosted requests signed with SigV4 and a
    session token, listings with delimiter and continuation, deletes of an
    object and what lies under it, eight tries with backoff and
    `Retry-After`, redirects taken as answers.
  - `template`: put, get, delete and list requests from the template with
    `{folder}`, `{name}`, `{prefix}`, `{data}`, `{secretN}` and `{token}`,
    auth `none`, `static`, `oauth2` (a cached token, fetched again on 401)
    or `basic`, two-step operations through `hrefPath`, flat names,
    listings read with Go's `regexp`, retries by status or by a 403's
    reason, and redirects followed as Go's `http.Client` follows them.
  - `google-drive`: files in a Drive folder by id over Drive's v3 API, an
    access token from the refresh token, small objects in descriptions and
    larger ones as media, ids remembered by name for every session, and
    retries after Drive's rate limits; a session goes in rings of two to
    eight slots each way with a watermark, frames of `XDRVSL01` with the
    segment inline up to 14 KiB or in the body, segments growing from 14 KiB
    after eight full ones, a burst at once, and slots reused only once the
    reader took what they held.
  - Over `alpn` exactly `["h3"]` a storage is reached over HTTP/3, its QUIC
    connections set up as XHTTP's are, with the stream's `quicParams` and
    UDP masks, Salamander among them, and ChromeParrot unless
    `disableChromeParrot` is true, as in Xray-core.
  - Deliberate differences: a writer waits once twice `concurrency`
    segments are not yet stored, where Xray-core keeps cutting; no
    `xdriveSettings` and an empty `local` folder fail when the core starts,
    where Xray-core fails every dial; a stream dropped without shutdown
    stores its end mark in the background for up to two minutes; one
    outbound's storage is shared by its sessions only, not with other
    outbounds that name the same one; a template's or Drive's answer is
    read up to 64 MiB; `{name}` and the like are replaced in a fixed order,
    HTTP/2 headers written in one and Drive listings taken in name order,
    where Go's map order varies; HTTP/3 request headers come in the vendored
    `h3`'s order and a storage over HTTP/3 cannot go through another
    outbound.
  - The vendored `h2` gains `go_request_pseudo_order`, the request
    pseudo-header order of Go's `net/http`.
- The `masque` outbound and `masque` transport connect to a MASQUE proxy as
  Xray-core v26.10.31's client does: one CONNECT-IP tunnel (RFC 9484) over
  HTTP/3 or HTTP/2, with Basic authorization from `user` and `pass`, the addresses the
  proxy assigns, and every TCP and UDP flow from SOCKS, HTTP and TUN carried
  through a userspace TCP/IP stack over the tunnel. Destination names
  resolve through the tunnel with `remoteDNS`. See
  [MASQUE](docs/config-compatibility.md#masque).
  - Tunnels are reused as Xray-core's `xmux` reuses them: by default one,
    retired after 1800 to 3000 seconds. `finalmask.quicParams` and the UDP
    masks apply; congestion `brutal` runs BBR, as in Xray-core, and the BBR
    profiles take over after the handshake, as on XHTTP over HTTP/3.
  - Over HTTP/3 every UDP mask rides the tunnel's QUIC socket as on XHTTP
    over HTTP/3, `realm` and `xicmp` included, since Xray-core's dial opens it
    through the same `finalmask` path. A realm introduction counts toward the
    tunnel's ten seconds, as it runs under Xray-core's dial context.
  - Over HTTP/2 (`tlsSettings.alpn` naming `h2` and not `h3`) the client
    dials TCP and TLS as the stream settings ask, uTLS fingerprint, `sockopt`
    and TCP masks included, and runs Xray-core's own HTTP/2 client: its
    SETTINGS, windows and keepalive, and its request header block byte for
    byte. Packets travel in DATAGRAM capsules on the request stream.
  - `warp` reaches Cloudflare WARP as Xray-core's client does: the device's
    P-256 key authenticates with a certificate made at each dial, the
    endpoint is known by its key, `cf-connect-ip` over HTTP/3 with draft or
    RFC 9297 datagrams, or a plain CONNECT with bare capsules over HTTP/2,
    and the configured addresses. It is tested against a local stand-in
    built from Xray-core's own warp tests, not against Cloudflare.
  - Deliberate differences: a tunnel takes 16 TCP and 512 UDP flows, the
    bounds of the WireGuard outbound's stack, which it shares; `remoteDNS`
    takes at most 8 servers and no scoped address; an empty `address`,
    chaining and Mux fail the configuration, and so do the TCP fragment
    mask over HTTP/3, and UDP masks and a `TE` header other than `trailers`
    over HTTP/2; the other TCP masks fail over HTTP/3 when the core starts.
- The WireGuard outbound's userspace TCP/IP stack now takes IP packets from
  any source, as MASQUE needs; WireGuard itself is unchanged.
- The `xicmp` UDP mask carries mKCP, Hysteria, XHTTP over HTTP/3 and
  MASQUE over HTTP/3 in ICMP, as Xray-core's client does: every datagram
  rides in an echo request to the server after the client's 8-byte id, and
  the server's come back in its echo replies. See
  [xicmp mask](docs/config-compatibility.md#xicmp-mask).
  - `dgram` takes datagram ICMP sockets, which macOS, iOS, Android and Linux
    within `net.ipv4.ping_group_range` grant without privilege; raw sockets
    need root or `CAP_NET_RAW`.
  - Each server address gets its own socket, never bound and connected to
    it, which a Network Extension needs; the families the addresses do not
    use need no socket.
  - It must be the last UDP mask and runs neither with udphop, xdns, realm
    nor header-custom, nor with sudoku on QUIC. An outbound address that is
    a name, with no `ips`, is refused when the core starts, where Xray-core
    fails every dial.
- The `realm` UDP mask reaches a server behind NAT, as Xray-core's client
  does: mKCP, Hysteria, XHTTP over HTTP/3 and MASQUE over HTTP/3 learn their
  public addresses from STUN servers over the carrier's own socket, a
  Hysteria realm rendezvous introduces them to the server registered under
  the realm's name, both sides punch, and the carrier's datagrams go to the
  address that answered. See
  [realm mask](docs/config-compatibility.md#realm-mask).
  - `portMapping` is read but not acted on yet: no UPnP or NAT-PMP mapping
    is made, as when Xray-core finds no gateway.
  - It must be the last UDP mask and runs neither with udphop, xdns nor
    header-custom. A URL port of 0 or above 65535, a host with a colon that
    is no IPv6 address, a token with control characters and a STUN server
    whose port Xray-core cannot use fail the configuration, where Xray-core
    fails every dial or skips the server.
  - The rendezvous is spoken over HTTP/1.1 and its name and the STUN
    servers' are resolved like the outbound's server address. A Hysteria
    connection whose network changes closes, and the next dial is introduced
    again.
- `quicParams.bbrProfile` `conservative` and `aggressive` work on Hysteria and
  XHTTP over HTTP/3: they run a port of Xray-core's own BBR sender with the
  profile's gains, startup rounds and options, where they failed to parse
  before. See [BBR profiles](docs/config-compatibility.md#bbr-profiles).
  - As in Xray-core, the controller takes over from quic-go's default Reno,
    here Quinn's NewReno, once the connection is up: right after the
    handshake on XHTTP, after the authentication reply on Hysteria. Brutal,
    `force-brutal` and the profile's BBR when a Hysteria server announces no
    rate now switch at the same points. Before, Hysteria's Brutal and its BBR
    fallback ran Quinn's BBR until the reply, and `force-brutal` ran Brutal
    from the first packet.
  - `standard`, the default, still runs Quinn's BBR. The port runs it too,
    but switching the default is left for a separate decision.
  - A profile is read with Go's lowercasing, so `AGGRESSİVE` is accepted as
    Xray-core accepts it.
- The `xdns` UDP mask carries mKCP, Hysteria and XHTTP over HTTP/3 in DNS,
  as Xray-core's client does: every datagram rides in base32 in the names of
  queries to recursive resolvers, which reach the server's domain, and comes
  back in TXT, A, AAAA or CNAME answers; polls keep queries waiting at the
  server for what it sends. See
  [xdns mask](docs/config-compatibility.md#xdns-mask).
  - Resolvers are DNS over UDP or TCP at an IP address. Names and DNS over
    HTTPS are not supported yet and fail the configuration.
  - DNS over TCP sends each message after its two-byte length. Xray-core's
    client fails to write it, so its TCP resolvers reach no real resolver.
  - It must be the last UDP mask, and runs neither with udphop nor, on QUIC,
    with sudoku. A domain with an empty label or one longer than 63 bytes
    fails the configuration, where Xray-core's client panics at its first
    query, and so does an unknown record type, which Xray-core refuses at
    every dial.
- The `xmc` TCP mask makes every TCP carrier a Minecraft 26.1.2 login, as
  Xray-core's does: a handshake and Login Start as one of the profiles, the
  server's RSA key checked against the one the password derives, AES-128-CFB8,
  about a second of padding that copies a real login, then the proxied bytes
  in custom payload packets. See
  [xmc mask](docs/config-compatibility.md#xmc-mask).
  - It must be the last TCP mask, and REALITY cannot run over it:
    Xray-core's REALITY server panics on every connection through xmc.
  - A password over 113 bytes fails the configuration, where Xray-core fails
    every login.
- VLESS UDP through SOCKS or TUN no longer stops for good when a response
  arrives in pieces. The relay dropped a response read that had already taken
  a frame's head whenever an outgoing datagram or a flush came first, and
  then read the rest of the stream out of step. Transports that deliver one
  write in several reads (WebSocket, gRPC, XHTTP and now `xmc`) made it
  likely; the reader now keeps what it took.
- The `sudoku` mask hides every byte as sudoku clues, with Xray-core's
  tables: as a TCP mask on every TCP carrier, REALITY included, and as a UDP
  mask on mKCP, Hysteria and XHTTP over HTTP/3. Entropy, ASCII and custom
  layouts, rotating tables and padding are read as Xray-core reads them. See
  [sudoku mask](docs/config-compatibility.md#sudoku-mask).
  - The TCP mask must be the last TCP mask.
  - On Hysteria and XHTTP over HTTP/3 every QUIC packet goes out at least
    four times its size. The carrier lets the system fragment such datagrams
    and turns path MTU discovery off, as quic-go is on Xray-core's masked
    conn. Xray-core's server drops every reply when Salamander comes after
    sudoku, so list Salamander first.
  - An unknown `ascii` mode or a malformed custom table fails the
    configuration, where Xray-core fails every dial.
- `udphop` is now the last UDP mask, where Xray-core dials it: Xray-core
  reverses the list and dials only an outermost `udphop`, so a mask after it
  fails every dial with `incorrect index`. The first place used to be
  required here, which refused working Xray-core configurations and took ones
  it cannot dial. Hysteria links with port hopping and Salamander now import
  with the hop last.
- The `header-custom` TCP mask runs Xray-core's handshake on every TCP
  carrier before anything else: raw, WebSocket, HTTPUpgrade, gRPC and XHTTP,
  under none, TLS or REALITY. Every item kind and transform op is read, with
  the carrier's addresses as metadata. See
  [header-custom TCP mask](docs/config-compatibility.md#header-custom-tcp-mask).
  - A `fragment` mask may come before it, not after.
  - `rand` is at most 65536 bytes, and an item sent or read and a `pad` at
    most 1 MiB.
- The `header-custom` UDP mask works on mKCP, Hysteria and XHTTP over HTTP/3,
  at its place among the noise, Salamander and `mkcp-legacy` masks. `prefix`
  mode puts the client's items before every datagram and checks and takes
  the server's off every reply; `standalone` exchanges them as separate
  datagrams before the first datagram to a peer, and again once five seconds
  have passed since the last reply. See
  [header-custom UDP mask](docs/config-compatibility.md#header-custom-udp-mask).
  - A standalone request unanswered for a second goes out again, where
    Xray-core waits for good.
  - It is refused with `udphop` and on other UDP carriers, and a header is
    at most 4096 bytes.
  - A null item reads as an empty one, in the TCP mask too, as in Xray-core.
- mKCP: `network: "kcp"` and `"mkcp"` carry VLESS, VMess, Trojan,
  Shadowsocks, SOCKS and HTTP over Xray-core's reliable stream over UDP, plain
  or under TLS, Vision included. Profiles with it used to fail to parse. See
  [mKCP](docs/config-compatibility.md#mkcp).
  - `kcpSettings` takes Xray's fields and defaults. `header` and `seed` are
    ignored, as by Xray-core v26, with a warning.
  - `mkcp-legacy` masks, the original obfuscation, AES-128-GCM from a seed and
    the old headers, and a noise mask apply in array order.
  - `mtu` is at most 8192, where Xray-core panics on a full segment.
    Salamander, `udphop`, TCP masks and chaining are refused on mKCP.
- VLESS `testpre` keeps that many carrier connections opened ahead of the
  requests that take them, as Xray-core does, up to 64. Profiles with it used
  to fail to parse.
  - A dialer holds one connection until a request takes it, then waits 200 ms
    and opens the next; one held two minutes is closed instead of used.
  - A failed dial waits before the next, up to ten seconds, and a request
    waits sixteen seconds for a connection. Xray-core does neither.
- Profile import reads `vless://` share links as format `vless` (ABI 1.17,
  `VLESS_PROFILE_IMPORT`, bit 30): raw, WebSocket, HTTPUpgrade, gRPC and XHTTP
  with none, TLS or REALITY, VLESS encryption, Vision flows and Remnawave's
  `fm`, and IDs read as Xray-core reads them, as in VMess links. See
  [VLESS share-link import](docs/vless-profile-import.md). The Swift and
  Kotlin SDKs expose it as `XrayProfileFormat.vless` and
  `XrayProfileFormat.Vless`, with the `vlessProfileImport` /
  `VlessProfileImport` capability; their own VLESS importers stay as separate
  parsers.
- Trojan and URI-form VMess imports refuse an empty `alpn`, an empty ALPN
  entry or one with spaces, which TLS cannot send, and keep an HTTPUpgrade
  path with `?ed=` that the parser only warns about.
- Android `XrayVpnService` can rebind Hysteria2 and WireGuard carriers on
  network changes. A subclass opts in with `networkChangeRebindEnabled()` and
  `ACCESS_NETWORK_STATE`; each session then runs `XrayNetworkChangeCoordinator`
  on a private control worker and closes it before the core and TUN fd. The
  carrier policy is `selectUnderlyingNetwork()`, by default the system default
  network, and `onXrayNetworkRebind()` / `onXrayNetworkChangeError()` report
  the outcome.
- Android `startXrayTunnel` with different arguments while an earlier start is
  in flight replaces it instead of being ignored; a call with the same
  arguments is still ignored. The new `onXrayTunnelStartCancelled()` reports a
  start that a stop or a replacing start cancelled, so every accepted start
  ends in exactly one started, failed or cancelled callback.

- Every `streamSettings.sockopt` field of Xray-core v26.10.31 is read and set
  on each socket an outbound opens, in Xray-core's order on Linux and
  Android and on Apple platforms. Profiles with fields other than
  `happyEyeballs`, `dialerProxy` and `domainStrategy` used to fail to parse.
  - Every outbound TCP socket now keeps alive after 45 seconds idle and every
    45 seconds, as Xray-core's do, unless `tcpKeepAliveIdle` or
    `tcpKeepAliveInterval` says otherwise.
  - The first option that fails stops the rest and is logged, while an
    `interface` that cannot be bound fails the dial. On Apple platforms a
    configured `tcpFastOpen` always fails, as there.
  - `penetrate` gives an XHTTP `downloadSettings` leg the outbound's own
    socket options and chain. Without it the download leg dials with its own
    socket options and no longer goes through the outbound's `dialerProxy`.
  - Hysteria takes socket options for its QUIC socket, and a `dialerProxy`
    inside `downloadSettings` is refused.

- WireGuard outbounds read `streamSettings.sockopt`, as Xray-core's do.
  Profiles with it used to fail to parse.
  - Its options go on the device's UDP sockets, and its `domainStrategy`
    picks which address of a domain peer endpoint is dialed.
  - `settings.domainStrategy` is no longer read, of any value, since
    Xray-core v26.10.31 has none. Destination lookups ask for the families
    of the local addresses, with IPv6 answers first when there is an IPv6
    one, as there; the setting used to narrow or order them.
  - Other stream settings and a `dialerProxy` are still refused.
- `sockopt.addressPortStrategy` replaces a domain server's address, port or
  both with its first usable SRV or TXT record before each dial, as
  Xray-core does. Its six values used to fail to parse.
  - The records are looked up as Go's resolver does for Xray-core, from the
    nameservers of `/etc/resolv.conf`, and a failed lookup dials the
    configured server.
  - Every proxy outbound reads it, over every transport and UDP, and so does
    an XHTTP download leg with the `sockopt` it dials with. Freedom refuses
    it, as there, and so does an outbound chained through `dialerProxy`.
- The `udphop` UDP mask reads every Xray-core mode: `intervalLocal`,
  `intervalRemote` and `perConnRemote`, alone or together, and `remoteIPs`
  of IPs and prefixes. Only `intervalLocal,intervalRemote` with ports used to
  parse.
  - `intervalLocal` alone keeps the configured server address, and
    `perConnRemote` draws the first address without hopping.
  - A remote hop also takes a fresh local socket, and `remoteIPs` of the
    other family than the server's are not drawn.
- VLESS and VMess outbound settings are read as Xray-core v26.10.31 reads
  them. Profiles in either shape below used to fail to parse.
  - A non-null `address` is the simplified form, with the server and its user
    in `settings`, and `vnext` is not read. VLESS refused it, and VMess
    refused it next to `vnext`.
  - An `id` of 1 to 30 bytes of text names the UUID Xray-core's
    `uuid.ParseString` makes of it, so a server with the same text accepts
    it.
  - VLESS `testseed` sets Vision's padding parameters. `reverse` and a
    nonzero `testpre` are refused.
- `dns.enableParallelQuery` asks every selected DNS server at once and takes
  the first answer of the earliest group of servers sharing a policy, as
  Xray-core does. Profiles with it used to fail to parse.
- `dns.clientIp` and a DNS server's own `clientIp` are sent as the EDNS
  client subnet of every query, as Xray-core sends them. Profiles with them
  used to fail to parse. DoH queries now carry Xray-core's EDNS padding.
- `dns.queryStrategy: "UseSystem"`, globally or for one server, is `UseIP`
  narrowed on each lookup to the address families the system has a route
  for, as Xray-core's `checkSystem` narrows them. Profiles with it used to
  fail to parse.
  - The probe connects a UDP socket toward a root DNS server of each family
    without sending anything. On mobile and desktop platforms its result
    stands for 100 ms.
  - Its sockets go through the socket protector, so inside the mobile VPN it
    sees the network the core dials over, where Xray-core's sees the VPN's
    own routes on Android.
  - Cached entries, hijacked answers and fake IP answers follow the routes.
- The `socks` outbound runs over every transport, as Xray-core's does:
  WebSocket, HTTPUpgrade, gRPC and XHTTP, with TLS, and REALITY over raw,
  gRPC and XHTTP. Such profiles used to fail to parse.
  - `UDP ASSOCIATE` sends its control connection through the transport. The
    datagrams still travel over plain UDP, as there.
  - A relay of the other address family moves on to the server's next
    family instead of failing the flow.
  - Over a transport other than raw, and under REALITY, a relay address of
    `0.0.0.0` or `::` names the server's first address of the socket's
    family, as Xray-core names the configured server.
  - A plaintext XHTTP `downloadSettings` leg to a public server is accepted,
    as a plaintext public SOCKS server is.
- The `http` outbound runs over every transport too, with TLS, and REALITY
  over raw, gRPC and XHTTP. Only the raw transport's TLS can make a tunnel
  HTTP/2; every other transport, and REALITY, carries HTTP/1.1, as in
  Xray-core. A plaintext XHTTP `downloadSettings` leg to a public server is
  accepted, as a plaintext public HTTP proxy is.
- The SOCKS inbound reads its handshake as Xray-core v26.10.31 does.
  - A domain that is an IP literal, such as `127.0.0.1` or `[::1]`, is that
    IP, so `ip` rules match it. An IPv4-mapped address is IPv4.
  - A domain with characters other than letters, digits, `-`, `.` and `_`
    closes the connection without a reply, as any request that does not
    parse now does. Such requests used to get a general failure reply.
  - Tor's `RESOLVE` commands connect. `BIND` and unknown commands get
    `REP = 0x07` before the address is read.
  - The request's version and reserved bytes, and the login's version byte,
    are not checked. A failed login gets status `0xFF`.
  - The whole handshake shares one `handshake` timeout.
  - UDP datagrams without a payload are dropped, and their reserved bytes
    are not checked.
- The SOCKS inbound reads `users` as another name for `accounts`, keeps the
  last account of a name, and accepts empty or missing credentials and
  `null` settings, as Xray-core does.
- The HTTP outbound speaks HTTP/2 when the proxy's TLS picks `h2`, as
  Xray-core does: its TLS now offers the protocols Xray-core offers, `h2`
  included, instead of `http/1.1` alone, and later tunnels share the HTTP/2
  connection. A proxy that offers only HTTP/1.1 is unaffected, as are imported
  `https://` links. An Xray-core HTTP inbound behind TLS needs
  `alpn: ["http/1.1"]`, for Xray-core's client and this one alike.
- The HTTP outbound sends its `headers` as Xray-core does, Go templates
  naming the connection's source and target included. Profiles with them
  used to fail to parse.
- The `loopback` outbound routes a connection again, as if it came from the
  inbound tag it names, as Xray-core's does. Its own `sniffing` cannot be
  enabled yet. A chain of more than 8 loopbacks fails the connection, where
  Xray-core would crash.
- A Mux pool no longer refuses new connections once its parent connections
  have each opened 128 children while a few long-lived children keep them
  open. Such parents now finish their remaining children while new
  connections go to a new parent, with at most 16 parents per pool.

- SOCKS and HTTP proxy connections honor `uplinkOnly` and `downlinkOnly` from
  policy levels, as in Xray-core. After one side finished sending, the
  connection now closes once the other side has been quiet for that time,
  instead of waiting for `connIdle` (300 s by default). `downlinkOnly` now
  defaults to 1 s like Xray-core, also for TUN; it used to be 2 s.
- A REALITY server that answers with a real certificate no longer gets an
  aborted handshake. As in Xray-core, a certificate valid for the server name
  completes TLS, the client crawls `spiderX` over HTTP/2 like a browser
  (honouring its `p`, `c`, `t`, `i` and `r` parameters, within limits), and
  the connection then fails without sending any user data. An invalid
  certificate still aborts the handshake. A `spiderX` that is neither empty
  nor starts with `/` is now a configuration error, as in Xray-core, and
  share links with such an `spx` are refused at import.
- VLESS (with or without Vision) and Trojan outbounds no longer send the
  request header on its own. As in Xray-core, the header waits for the first
  payload and leaves in the same write, so over TLS or REALITY the first
  record is no longer a header-only record of a predictable size. When the
  app sends nothing first, the header goes out after the same wait as
  Xray-core: 500 ms for VLESS, 100 ms for Trojan. With Vision, the empty
  padding frame is now sent only in that case, behind the header, instead of
  on every connection.
- Outbound URL probes no longer announce themselves. The observatory, startup
  and on-demand probes used to send `User-Agent: xray-rust-…-probe`; they now
  send Xray-core's Chrome navigation headers in Go's order. As in Xray-core,
  the observatory counts any HTTP response as alive, so a probe URL answering
  `503` no longer marks working outbounds unhealthy. The startup and
  on-demand probes keep their 2xx/3xx rule.
- The XHTTP HTTP/2 client opens with the SETTINGS frame Xray-core's Go
  client sends: push disabled, a 1 MiB maximum frame and a 10 MiB header
  list limit next to the stream window, in Go's order. It used to announce
  the stream window alone.
- The XHTTP HTTP/3 client announces Xray-core's 10 MiB header limit instead
  of 2^62-1 and no longer lists datagram, extended CONNECT and WebTransport
  settings that are off.

- The release fuzz campaign also covers the decoders that read server data:
  gRPC and WebSocket framing, Shadowsocks TCP responses, VLESS responses with
  Vision, and the REALITY ServerHello capture. Reads are split at arbitrary
  boundaries.
- The Android and Apple VLESS link importers accept more common links. They
  used to reject them with an unsupported `type` or `security` error.
  - Raw TCP with TLS, with or without `flow=xtls-rprx-vision`.
  - WebSocket and HTTPUpgrade with TLS, keeping `host` and `path`.
  - gRPC with TLS or REALITY, keeping `serviceName`, `authority` and
    `mode=gun` or `mode=multi`.
  - As in Xray-core, Vision over WebSocket, HTTPUpgrade or gRPC needs VLESS
    encryption, and REALITY works only over raw TCP, XHTTP and gRPC. Links
    that turn off certificate checks with `allowInsecure` on these transports,
    or carry another transport's fields, are still rejected.
- The Android and Apple VLESS link importers read `fm`, the percent-encoded
  JSON of Xray's `streamSettings.finalmask` that Remnawave puts in links. It
  used to be dropped silently. The object is copied unchanged into the
  profile, and the core checks the masks when the profile loads. An empty
  `fm` is ignored; a value that is not a JSON object, or a repeated `fm`,
  fails the import.
- On Android, the TUN admission callback and socket protection no longer
  attach the calling native thread to the JVM and detach it again on every
  call. Each native thread is attached once, as a daemon thread, and detached
  when it exits. Threads the JVM already owns are left as they are.
- Remnawave XRAY_JSON profiles no longer fail on the fields the panel adds to
  them. Every profile in such a subscription used to fail to parse.
  - The root `remarks` label and `meta` object are type-checked and ignored.
  - `tlsSettings.enableSessionResumption` takes a boolean. As in Xray-core, a
    uTLS-shaped handshake never resumes, whatever its value.
  - Shadowsocks `uot` and `UoTVersion`, which 3x-ui also writes, are ignored
    as in Xray-core. UDP stays native, and `uot: true` raises a warning.
- `trojan://` and `vmess://` links from Remnawave and similar panels import.
  Every Remnawave Trojan gRPC link used to fail, because it always carries
  `mode=gun`.
  - gRPC `mode=multi` turns on `multiMode`; WebSocket `heartbeatPeriod`, XHTTP
    `extra` and the TLS certificate checks `pcs` (`pinnedPeerCertSha256`) and
    `vcn` (`verifyPeerCertByName`) are carried into the profile.
  - `headerType=none` imports. `headerType=http`, other gRPC modes and TLS
    `cs` (cipher suites) are still refused, and the error now names the
    parameter.
  - `fm`, the percent-encoded JSON of the host's `finalmask`, becomes
    `streamSettings.finalmask` and is checked as canonical JSON is. A mask the
    core does not implement fails with an error naming `fm` instead of failing
    the whole link as unsupported.
- `hy2://` links with a certificate pin (`pinSHA256`) import, so Hysteria
  servers with a self-signed certificate can be added from a link. The pin
  maps to `pinnedPeerCertSha256` and is checked as Xray-core checks it.
  `insecure=1` (or `true`) is accepted next to a pin and still refused without
  one; `insecure=false` now imports. Remnawave's `fm` (the host's
  `finalmask`) imports too; its Salamander entry must match `obfs` and
  `obfs-password`, which the panel derives from it, and appears once.
- `dns.hosts` supports Xray-core's `"#N"` values, such as
  `"ads.example.com": "#3"` to answer NXDOMAIN and block a domain. Such a value
  used to be read as an alias to the name `#3`, so the domain was still
  resolved.
  - DNS hijacked through TUN or a DNS outbound answers A and AAAA queries for
    the name with that RCODE and no records; routing, `domainStrategy` and
    freedom treat the name as having no addresses. `"#0"` gives an empty
    answer, as in Xray-core.
  - `N` must be from 0 to 15, the range the DNS header holds; other values,
    which Xray-core accepts and writes over the header flags, are rejected.
- Freedom's `noises` send their datagrams before each UDP flow's first, as
  Xray-core's do, with Xray-core's deprecation warning. Profiles with them
  used to fail to parse. The removed `noise` object fails, as in Xray-core.
- The HTTP inbound, and HTTP on a SOCKS port, forward plain HTTP requests
  such as `GET http://example.com/`, as Xray-core does; they used to answer
  them with a `400`.
  - Each request is routed on its own, as `http/1.1`, with the request's
    method, path and headers as its `attrs`.
  - It goes on as Go's `Request.Write` writes it, with `Connection: close`
    and without hop-by-hop headers. The response comes back as Go's
    `Response.Write` writes it.
  - A response of known length keeps the connection for another request
    when the client sent `Proxy-Connection: keep-alive`. A response that
    does not come gets a `503`.
- A blackhole's `http` reply is the one Xray-core v26.10.31 writes, with CRLF
  line endings and its headers in Go's order, instead of the older one with
  LF line endings.
- The HTTP inbound answers as Xray-core's HTTP server does. HTTP on a SOCKS
  port answers the same way.
  - It sniffs its tunnels, so `destOverride`, `protocol` and `attrs` apply.
    Its `sniffing` used to be ignored.
  - `accounts` (or `users`) require `Proxy-Authorization: Basic`, and name
    the user for routing's `user`. Profiles with them used to fail to parse.
  - `CONNECT` is answered with `200 Connection established` before routing,
    as Xray-core answers it, instead of `200 Connection Established` once the
    outbound opened, or a `502` when it did not.
  - A `CONNECT` target without a port goes to port 80, and a request that
    does not parse is closed without a reply. Only the first
    `Proxy-Authorization` counts, as in Xray-core; the last one used to.
- Routing rules can match an HTTP request's attributes with Xray-core's
  `attrs`, such as `{"attrs": {":method": "GET", "user-agent": "^curl/"}}`.
  Profiles with it used to fail to parse.
  - As in Xray-core, sniffing records the request line's `:method` and
    `:path` and each header under its lowercased name. Each pattern must
    match its attribute's value anywhere, case-sensitively.
  - With an `attrs` rule, TCP flows are sniffed for their attributes even
    where `destOverride` would not read them, as for `protocol`.
- Routing rules can match the sniffed protocol with Xray-core's `protocol`,
  such as the common `{"protocol": ["bittorrent"], "outboundTag": "block"}`.
  Profiles with it used to fail to parse.
  - The names are Xray-core's: `http1`, `tls`, `quic`, `bittorrent` and
    `fakedns`, matched by prefix. BitTorrent is recognized by its TCP
    handshake and by a uTP `ST_SYN` over UDP.
  - HTTP is read as Xray-core's sniffer reads it: a request is named only by
    a `Host` header it can parse, the last one counting, and that header's
    host, without a port in any form Go accepts, is the sniffed domain.
  - With a `protocol` rule, flows are sniffed for their protocol even where
    `destOverride` would not read them; `destOverride` still alone decides
    whether a sniffed domain replaces the destination. On TUN such a TCP flow
    is opened before routing.
  - Sniffing stops reading once every sniffer has ruled a flow out, as in
    Xray-core, instead of waiting up to 250 ms for more bytes.
  - `protocol` holds under `domainStrategy` `IPOnDemand` too, checked before
    the destination IP as in Xray-core.
- Routing rules can check where a connection comes from, with Xray-core's
  `sourceIP` (or `source`), `sourcePort`, `localIP`, `localPort` and `user`.
  Profiles with them used to fail to parse.
  - The source is the SOCKS or HTTP client, or for TUN the app; the local
    address is where the connection arrived. On a SOCKS UDP flow they are the
    client's UDP endpoint and the association's relay socket, as in
    Xray-core.
  - `user` matches the account a SOCKS client logged in with, by exact name or
    `regexp:` pattern, also for HTTP `CONNECT` on a SOCKS port and for the
    flows of its UDP association.
  - As in Xray-core, any `sourcePort` or `localPort` given sets a condition,
    an unknown port reads as 0, and an unknown address matches no IP rule.
- Inbound sniffing reads as Xray-core v26.10.31 reads it. Profiles it accepts
  no longer fail to parse.
  - `domainsExcluded` and `ipsExcluded` are supported. Profiles with a
    nonempty `domainsExcluded`, such as the common
    `["courier.push.apple.com"]`, used to fail to parse. A sniffed domain in
    `domainsExcluded`, or a destination IP in `ipsExcluded`, keeps the
    connection on its original destination.
  - `destOverride` names are case-insensitive, `https` and `ssl` spell `tls`,
    and `fakedns` and `fakedns+others` are accepted. A fake IP is still turned
    back into its domain whenever `dns.fakeIp` is enabled.
  - `destOverride` and both exclusion lists also take a comma-separated
    string.
  - As in Xray-core, every field is checked even when sniffing is off, so a
    disabled block with an unknown `destOverride` name is now rejected. A
    `null` sniffing object means no sniffing.
- DNS domain rules read as Xray-core v26.10.31 reads them: a server's
  `domains`, `dns.hosts` keys and the DNS outbound's rules. Profiles it accepts
  no longer fail to parse.
  - A server's `domains` and a DNS outbound rule's `domain` take `null`
    entries, which read as empty strings, and `domains` itself may be `null`.
  - Domain rules take Xray-core's syntax there too: text with an unknown
    prefix is a substring in `domains` and `domain`, and an exact name as a
    `dns.hosts` key; `ext-site:` spells `ext:`; and a prefix may have an empty
    value, so `"keyword:"` as a hosts key maps every name.
  - A geosite selection with no domains is accepted. It puts no name first,
    maps nothing as a hosts key, and keeps a DNS outbound rule from applying.
  - A DNS outbound rule's `qType` reads as Xray-core's `PortList`. A reversed
    range such as `"24-23"` adds no type, so a rule left with no type answers
    every type, where it used to fail parsing. A single type with a sign or a
    leading zero, such as `"053"`, is now rejected, as there.
- Routing rules read as Xray-core v26.10.31 reads them. Profiles it accepts
  no longer fail to parse, and a few rules now apply as they do there.
  - `type` is no longer required or checked, so rules without
    `"type": "field"` parse.
  - `inboundTag`, `domain`, `domains` and `ip` also take a comma-separated
    string. `network` keeps a name other than `tcp` and `udp` as one no
    connection uses, and `outboundTag` wins over `balancerTag`.
  - Domain rules take Xray-core's syntax: text with an unknown prefix is a
    substring, `ext-site:` spells `ext:`, and a prefix may have an empty value.
  - Behavior changes, all matching Xray-core: `"port": 0` or `""` now keeps
    the rule from applying, where it used to match every port, and so does a
    reversed range, which used to fail parsing. `domains` replaces `domain`
    rather than adding to it. A rule with no condition is refused instead of
    taking every connection, and a geosite selection with no domains matches
    nothing instead of failing to parse.
  - A final rule's reversed port range is accepted too, and covers no port.
- Freedom: `proxyProtocol` and `finalRules`, which used to fail parsing.
  - `proxyProtocol` 1 or 2 writes that PROXY protocol header first, naming the
    inbound's client (for TUN, the app) and the address freedom connected to,
    byte for byte as Xray-core's go-proxyproto writes it. A UDP flow sends it
    as its own first datagram, and a freedom `dialerProxy` hop sends it to the
    next server, so a client can reach a server behind a PROXY-protocol load
    balancer.
  - `finalRules` allow or block addresses by network, port and IP, the first
    matching rule deciding. A domain is checked by every address it resolves
    to. A blocked TCP connection is held and discarded until the client gives
    up or `blockDelay` passes; a blocked UDP flow drops its datagrams, and an
    open one drops replies from blocked sources.
  - The removed `ipsBlocked` is accepted with a warning and ignored, as in
    Xray-core, and `finalRules` on a freedom that itself dials through
    `dialerProxy` are dropped with a warning.
- Freedom: `redirect` and `userLevel`, which used to fail parsing.
  - `redirect` sends every connection and UDP flow to another address, port or
    both, read with Xray-core's rules: an empty host, `0.0.0.0` or `::` keeps
    the address, and port 0 keeps the port.
  - Replies of a redirected UDP flow come from the destination the client
    addressed, and a freedom `dialerProxy` hop redirects the next server.
  - `userLevel` gives freedom its own idle timer at that level, beside the
    inbound's, so the shorter `connIdle` wins.
  - As in Xray-core, freedom without `userLevel` now runs at level 0. An
    inbound level with a longer `connIdle` therefore no longer keeps freedom
    connections open longer.
- Freedom: `streamSettings.sockopt.domainStrategy`, with Xray-core's eleven
  strategies, together with the deprecated spellings that Xray-core migrates
  into it: freedom's `settings.domainStrategy` and `settings.targetStrategy`,
  and an outbound `targetStrategy`. Profiles with any of them used to fail to
  parse, including the common `"domainStrategy": "UseIPv4"` on a direct
  outbound. `IPv4` and `IPv6` strategies dial only that family, and `IPv4v6`
  and `IPv6v4` fall back to the other one. If nothing is found, `Use` retries
  both families and `Force` fails. A UDP flow named by sniffing or a fake IP
  prefers its original family, and a freedom `dialerProxy` hop resolves the
  next server with its own strategy. Other outbounds accept only `AsIs` for
  now.
- Hysteria: Gecko, the shape layer that a Salamander `packetSize` selects in
  Xray-core and that Hysteria 2.9.2 added. Such profiles no longer fail to
  import. Handshake datagrams travel as two to eight randomly padded
  fragments, and replies are reassembled; later traffic stays plain
  Salamander. Padding stops at 1,452 bytes so fragments fit the path MTU;
  Xray-core pads up to 2,048 and relies on IP fragmentation. `hy2://` links
  with `obfs=gecko` import with Hysteria's default sizes, 512 to 1,200 bytes.
- QUIC: Brutal congestion control and Hysteria's bandwidth exchange.
  Hysteria now reads all of `finalmask.quicParams`, as Xray-core's Hysteria
  dialer does, instead of only `udpHop` and `disableChromeParrot`, so profiles
  with `brutalUp`/`brutalDown` import. The client announces `brutalDown` to the
  server and sends with Brutal at the lower of `brutalUp` and the server's
  announced rate, or with BBR when either is zero. `force-brutal` now works on
  Hysteria and XHTTP H3. `disableGSO` and `brutalDisableLossCompensation` take
  effect, and `disableStatelessReset`, which only Xray servers read, is
  accepted. Conservative and aggressive BBR profiles, and plain `brutal` over
  XHTTP H3, which crashes Xray-core's dialer, are rejected when parsing. The
  vendored `quinn-proto` gains a lost-packet callback for Brutal's loss
  compensation.
- Freedom and proxy carriers no longer dial only the first resolved address
  when `sockopt.happyEyeballs` is off. As with Go's `net.Dialer`, which
  Xray-core uses, the first address family is tried address by address
  within a 16-second budget, and the other family joins after 300 ms or as
  soon as the first fails. A host whose first address is unreachable, such as
  `localhost` served only on IPv4 or a server behind broken IPv6, now
  connects through the next one, as it does with Xray-core.
- SOCKS inbound: like Xray-core's, it now also serves SOCKS 4/4a `CONNECT`
  and HTTP `CONNECT` on the same port, choosing by the first byte, and
  `mixed` is accepted as its alias. Under `password`, SOCKS 4 is refused as
  Xray refuses it, and HTTP needs the same accounts as
  `Proxy-Authorization: Basic` credentials, or gets Xray's
  `407 Proxy Authentication Required`. Plain HTTP forwarding (non-`CONNECT`
  methods) is still answered with `400`, as on the HTTP inbound.
- Xray-core configs with these options now parse instead of failing:
  - routing rules take `localOS`, an array or comma-separated string of Go
    `runtime.GOOS` names (`darwin`, `ios`, `android`, `linux`, `windows`),
    so a shared profile can route differently per platform. Apple platforms
    other than macOS report `ios`, as Go has no tvOS or visionOS value;
  - blackhole `response.type: "custom"` replies with the bytes of
    `customResponseData` (padded standard base64, at most 65,535 bytes), over
    TCP and as one datagram to a UDP flow;
  - Xray's protocol aliases `direct` (freedom), `block` (blackhole) and
    `tunnel` (`dokodemo-door`).
- Sniffing: QUIC reassembles a ClientHello spread over several Initial packets
  and datagrams, as Xray-core does. A Chrome-shaped ClientHello with a
  post-quantum key share fills two datagrams (the fixture is captured from
  Xray-core's ChromeParrot stack), so its server name was not sniffed before
  and such flows ignored domain routing rules. While the ClientHello is
  incomplete, a flow waits at most 200 ms and 32,767 bytes for the rest, then
  forwards every datagram it read, in order. Only the gap-free part of the
  CRYPTO stream is parsed, so a missing piece is never read as part of a name.
  QUIC draft-29 Initials and CONNECTION_CLOSE frames are recognized as well.
- Compatibility reference moved to Xray-core v26.10.31
  (`a4a3dff5b20c2faae567b742c172c7b95e75c083`, Go 1.27.3): CI, interop
  guards, oracle modules, fixtures and the benchmark harness pin it. See the
  [migration record](docs/xray-core-v26.10.31-migration.md).
- VLESS without TLS or VLESS encryption, and Trojan without TLS, now accept
  a server IP address only when it is private (10/8, 172.16/12, 192.168/16,
  fc00::/7), loopback or link-local, as Xray-core v26.10.31 does. Addresses in
  the shared (100.64.0.0/10), benchmarking (198.18.0.0/15), documentation,
  reserved, multicast and unspecified ranges, which v26.10.21 also exempted,
  are now a configuration error, and an imported link to one is refused.
  `geoip:private` routing is unchanged.
- XHTTP: `xhttpSettings.h2Params`, a server option added in v26.10.31, is
  accepted and ignored, like `serverMaxHeaderBytes`. A v26.10.31 server
  accepts `uplinkHTTPMethod: "OPTIONS"`, which the client already sent; a live
  interop test now covers it.
- Freedom `settings.fragment` parses with a deprecation warning pointing at
  `streamSettings.finalmask.tcp`, as Xray-core v26.10.31 prints. Profile
  imports never produce it.
- Xray-core v26.10.31 turns MPTCP off on its listeners because of a Linux
  kernel MPTCP vulnerability. xray-rust never enables MPTCP on its SOCKS,
  HTTP or TPROXY listeners and does not accept `tcpMptcp`.
- Shadowsocks: `xchacha20-poly1305` (AEAD-2017) and the UDP packets of
  `2022-blake3-chacha20-poly1305` now run XChaCha20-Poly1305 as an HChaCha20
  subkey over AWS-LC's ChaCha20-Poly1305 instead of the portable RustCrypto
  AEAD. The wire bytes are unchanged (the draft-irtf-cfrg-xchacha-03 vector,
  the pinned Go fixtures and a differential test against RustCrypto pass),
  and on Apple M6 one 8 KiB record seals and opens at 2,241 instead of
  1,167 MiB/s. Through a SOCKS inbound and a common Xray-core v26.10.21
  server (single-flow full duplex, five rotated runs), `xchacha20-poly1305`
  rose from 644 to 987 MiB/s, from 60% to 92% of the Xray-core client and
  level with `chacha20-poly1305` (1,042 MiB/s); the 0.9.0 measurements had
  recorded 59%.
- TUN: configurable MTU (ABI 1.16, `TUN_MTU`, bit 29). `xray_core_set_tun_mtu`
  takes 1280..=9000 before config load and rejects other values instead of
  clamping; the default stays 1500 on every profile. The Kotlin and Swift
  adapters pass one value to the interface and the core
  (`XrayCore.supportedTunMtu`, `create(..., tunMtu)`, `XrayCore(..., tunMtu:)`,
  `XrayVpnService.startXrayTunnel(..., tunMtu)`, the provider's `tunMtu()`) and
  keep 1500 on a library without the capability. A tun inbound's JSON
  `settings.mtu` now gets a warning: the host, not the config, owns the MTU.
  Previously a host interface above 1500 lost every longer packet silently.
  See [TUN MTU](docs/ffi.md#tun-mtu).
- Android: `XrayVpnService` now sets the interface MTU after `buildTunnel()`,
  so an override's own `setMtu` is replaced by the `tunMtu` of
  `startXrayTunnel` (1500 by default). A host that lowered the MTU in
  `buildTunnel()`, for example to 1400, passes that value as `tunMtu` instead.
- TUN: each TCP socket's receive buffer is `max(32 KiB, 4 × MSS)`, so kernel
  senders, which only send whole segments into the window, do not stall on a
  jumbo MTU. Unchanged up to MTU 8232; at 9000 it adds at most 768 KiB on
  `Mobile`. The TUN packet queues also hold at most `depth × 1500` bytes, so
  a jumbo MTU does not multiply their memory.
- UDP: a datagram larger than its outbound path carries (VLESS UDP, Mux/XUDP
  and Trojan 8192 bytes, native VMess 8094, WireGuard its tunnel MTU less
  28/48, so 1392 at the default 1420) no longer ends the whole flow or, over
  length-prefixed VLESS, reaches the target split in two. It is dropped alone and
  counted in the new `udp_oversize_datagrams` stat (appended to
  `XrayTunStats`, now 592 bytes on 64-bit targets, and to the Kotlin and Swift
  stats), and a TUN host gets an ICMP fragmentation-needed or packet-too-big
  with the path MTU, which senders that set DF (QUIC, PMTU discovery) follow. This already
  affected WireGuard outbounds at the default 1500-byte TUN.
- TUN UDP: when a flow's 256-datagram queue is full, only the new datagram is
  dropped (counted in `udp_channel_dropped_packets`, as before) and the flow
  keeps its outbound, as in Xray-core. A burst used to end the flow, so the
  next datagram opened a new outbound with a fresh handshake.
- Shadowsocks UDP (either family): a datagram too large for Xray's 8192-byte
  UDP buffer once framed (8153 bytes of payload for `aes-128-gcm` and 8142 for
  `2022-blake3-aes-128-gcm` to an IPv4 address), or for one Mux frame over
  Mux, is now dropped alone like on the other UDP paths, counted in
  `udp_oversize_datagrams`, and answered with an ICMP fragmentation-needed or
  packet-too-big on TUN. It used to end the whole UDP flow, so the next
  datagram opened a new association.
- Fake IP: each `Core` starts allocating at a random address of
  `dns.fakeIp.ipv4Pool` and continues sequentially from there, as Xray-core
  starts from the current time within the pool. It always started at the
  pool's first free address, so after a tunnel restart an app still holding an
  old fake IP was routed and dialed as whichever new domain got that address.
- Hysteria UDP: an empty datagram is skipped and the flow stays up. Every
  Hysteria parser, Xray-core's included, drops a message without data. It
  used to end the whole UDP flow, so the next datagram opened a new session.
- Hysteria UDP reassembly follows Xray-core: an unfragmented datagram that
  arrives between the fragments of a larger one is delivered without dropping
  the larger one, and a fragment with a new fragment count starts a new
  packet. Both used to discard the incomplete datagram, and the second one its
  own fragment too.
- WireGuard: opening a TCP connection or UDP flow waits for room in the
  32-command queue it shares with UDP sends, within the 10-second open
  deadline. With more than 32 busy UDP flows a new connection used to fail as
  if the flow limits (16 TCP, 512 UDP) were reached; only those limits fail an
  open now.
- DNS: a bare `"localhost"` or `"fakedns"` string in `dns.servers` (any case)
  is now a configuration error, as the object form already was. Xray's
  system-resolver and FakeDNS clients are not implemented, and these strings
  used to parse as an ordinary UDP resolver on port 53. Explicit URLs such as
  `tcp://localhost` and domains such as `localhost.example` still parse.

## 0.9.0 - 2026-11-01

Published on 2026-11-03 with exact-candidate release evidence and the
owner-accepted limitations in the
[0.9.0 release](https://github.com/aimalygin/xray-rust/releases/tag/v0.9.0).

- Require versioned exact-candidate Apple/Android evidence for 0.9 publication.
  SOCKS, HTTP and classic Shadowsocks AEAD each need every device transition on
  Apple and both Android adapter paths, plus throughput, latency and memory
  comparisons. HTTP relays no UDP, so it must show its UDP probes refused
  rather than carried. Their links join profile import, and Trojan, SS2022 and VMess
  join the legacy regression. Android Wi-Fi/cellular and lock/wake remain not
  tested. v0.8 evidence does not satisfy the gate. See
  [0.9.0 release preparation](docs/v090-release.md).

- Mux (Trojan, Shadowsocks 2022, VMess): a child that reads slower than the
  server sends no longer loses its session. When a child's receive queue was
  full, the shared runtime reset it, so bulk downloads through a slow local
  consumer such as the TUN stack ended after a few hundred KiB while the server
  logged `read/write on closed pipe`. The parent's reader now waits for that
  child to drain, end or be dropped, as Xray-core's Mux client blocks on the
  session pipe. Queues stay bounded; like Xray-core, a stalled child delays its
  siblings' downloads on the same parent until it drains or closes.

- TUN TCP acknowledges client data after handing it to the outbound, so the
  ACK advertises the drained receive window. The stack ran smoltcp's ingress
  and egress in one `Interface::poll` and read the sockets only afterwards:
  the ACK for a full-window burst offered what was left of the 32 KiB window,
  and the reopened window followed on a later loop turn, up to 1 ms later
  (tokio timer resolution). Kernel TCP senders (Android `VpnService`, Linux
  tun, Darwin utun) do not send a partial segment into a window below one MSS,
  so a window-limited upload stalled on every burst. In an emulation of such a
  sender, a single upload through a 1500-byte TUN rose from 94 to 636 MiB/s.

- Add classic Shadowsocks AEAD client support (`aes-128-gcm`, `aes-256-gcm`,
  `chacha20-poly1305`, `xchacha20-poly1305` and Xray's aliases such as
  `chacha20-ietf-poly1305`) to the `shadowsocks` outbound, its TCP and native
  UDP paths, Mux/XUDP and SIP002 `ss://` import. Real subscriptions still carry
  these servers, which were previously rejected. Key derivation, framing,
  chunk sizes and accepted method names follow Xray-core v26.10.21 and are
  checked against vectors generated from it and live against its server;
  `none` and stream ciphers stay rejected, as upstream. Method names are now
  case-insensitive for both Shadowsocks families, as in Xray-core, and an
  unsupported method is reported at `settings.method`. No ABI change: the
  `shadowsocks2022` import format and capability bit cover both families, and
  older libraries reject the new methods with a configuration error.

- XHTTP over HTTP/3 (exact `h3` ALPN) now hops its UDP carrier, accepting the
  `finalmask.udp` udphop mask and the legacy `quicParams.udpHop`, as Xray-core
  does for any UDP transport. Previously the mask failed to parse and the
  legacy form failed when the transport was built. The first Initial already
  uses a hop port; each interval moves the connection to a fresh protected
  socket while QUIC migrates the path, the timer starts with the connection and
  stops with it, and a failed hop keeps the current path. Scheduled hops, for
  Hysteria as well, now always change the port: Xray draws with replacement,
  so with two ports half of its hops stay put. `H3Error::UnsupportedUdpHop` is
  replaced by `InvalidUdpHop` for out-of-range policies. The legacy `udpHop`
  warning points only QUIC carriers at the mask and tells others it has no
  effect.

- Support `mux` on VLESS outbounds, matching Xray-core v26.10.21. VLESS joins
  the bounded shared Mux/XUDP pools of Trojan, Shadowsocks 2022 and VMess on
  raw, WebSocket, HTTPUpgrade, gRPC and XHTTP with TLS or REALITY, with VLESS
  encryption too. UDP follows Xray's outbound handler: `xudpProxyUDP443`, then
  the XUDP pool, then the TCP pool, then VLESS's own UDP command. Profiles that
  enabled Mux on VLESS previously failed to parse. With `xtls-rprx-vision`, as
  on XHTTP, `mux.concurrency` must be negative, because the Xray inbound drops
  a Vision account's Mux connection on its first TCP child; XUDP pooling stays
  available.

- Mobile: cancel in-flight on-demand outbound probes without stopping the core
  (ABI 1.15, `OUTBOUND_PROBE_CANCEL`, bit 28). The existing
  `xray_core_cancel_outbound_probes` is a teardown latch: after it every later
  probe on that core fails, so a host whose user dismissed a health check had
  no way to abort it and probe again later. The new
  `xray_core_cancel_inflight_outbound_probes`, Kotlin
  `XrayCore.cancelOutboundProbes()` and Swift `XrayCore.cancelOutboundProbes()`
  end only the probes already running; they return `RUNTIME_ERROR` with
  `outbound probe cancelled by the host`, and later probes run normally.
  Startup-probe preflights and the teardown latch keep their behaviour (#81).

- Android: expose the live `tcpRemoteWrittenBytes` and `tcpRemoteReadBytes` TUN
  counters that the C ABI and Swift adapter already report, and add
  `XrayTunStats.uplinkBytes` / `downlinkBytes` (TCP plus UDP remote payload).
  Hosts sampling `outboundAccountingSnapshot()` for a traffic meter only saw
  bytes of closed connections. The new constructor parameters default to zero
  and come last, so source callers keep compiling (#81).

- Android: publish the TUN interface contract as `XrayTunInterface` (IPv4
  `10.7.0.1/32`, IPv6 `fd00:7872::1/128`, DNS anchor `198.18.0.1`, MTU 1500)
  and add `VpnService.Builder.applyXrayTunInterface(dnsAnchor)`, so hosts with
  their own `VpnService` stop copying SDK internals. `XrayVpnService` uses the
  same helper; the established interface is unchanged (#81).

- Report live bytes in per-outbound accounting. The accounting snapshot added a
  connection's payload bytes to `uplinkBytes`/`downlinkBytes` only when it
  completed, so a host polling it as a traffic meter saw nothing during a long
  download and then a jump at close. Each outbound now also carries
  `activeUplinkBytes`/`activeDownlinkBytes`: the bytes relayed so far by its
  opening and active connections, read under the same registry lock that moves
  them into the completed totals, so the sum never decreases. The existing
  fields keep their completed-only meaning, `revision` still advances only on
  inventory changes, and schema version 1 gains the fields additively. Swift
  and Kotlin expose them as optional values that are absent with an older
  native library.

- WireGuard resolves destinations with the caller's resolver when no
  `remoteDNS` server is routable through the tunnel. A split `allowedIPs` that
  excluded the configured servers (as in an imported wg-quick profile with
  `DNS` outside `AllowedIPs`) made every domain destination fail with no route,
  reported only as "all configured DNS servers are unavailable". A failed
  tunnel query still never falls back to host DNS. The parser warns at
  `remoteDNS` when no server is routable, and profile import accepts that
  warning, since the profile is what the wg-quick file asked for.

- Shape `fingerprint: "randomizednoalpn"` on the weights Xray-core's preset
  uses: TLS 1.3 with an X25519 key share and no ALPN. It had shared the TLS 1.2
  snapshot of the bare uTLS `hellorandomizednoalpn`, so plain TLS failed against
  TLS-1.3-only servers, and REALITY configs and share links with
  `fp=randomizednoalpn` were rejected although Xray-core dials them. The new
  snapshot leads with the X25519MLKEM768 share, so REALITY v26.10.21 servers
  accept it. `hellorandomizednoalpn` keeps its TLS 1.2 shape.

- Android: `XrayNetworkChangeCoordinator` no longer mistakes a partial initial
  callback burst for a migration. Until the network passed to `start` reports
  or is lost, the control worker reads its current state and offers it as a
  candidate, so another network reporting first neither requests rebind nor
  moves a policy that keeps the previous carrier (#89).
- Android: `XrayNetworkChangeCoordinator` works on API 24-25. Before Android O
  `onAvailable` is not followed by capability or link-property callbacks, so
  networks never became candidates and migrations were silently missed; the
  coordinator now reads a network's current state once in `onAvailable` there.

- Match the routing `geoip:private` set to Xray-core's built-in private set
  (`common/geodata/consts.go`), which the plaintext-server exemption already
  used. The previous nine networks left out `0.0.0.0/8`, `198.18.0.0/15`, the
  TEST-NETs, multicast and broadcast (`224.0.0.0/3`), `::` and `ff00::/8`, so a
  `geoip:private` -> direct rule sent mDNS, SSDP and broadcast traffic through
  the proxy; Xray-core, reading `geoip:private` from any common `geoip.dat`,
  keeps it direct. DNS `expectedIPs`/`unexpectedIPs` still load
  `geoip:private` from `geoip.dat`.

- HTTP profile import refuses a legacy Base64 whole-authority link such as
  `http://<Base64 of user:pass@host:port>` with `Unsupported`. With the default
  port it was imported as a one-label host, so the profile reached no server
  and DNS bootstrap sent the encoded credentials to the carrier resolver.

- Profile import rejects display names containing bidi embeddings, overrides
  or isolates (U+202A..U+202E, U+2066..U+2069), from the link fragment or the
  `name` option. They reorder surrounding text, so a name could display as a
  different profile in system VPN UI (CVE-2021-42574). LRM, RLM and ALM stay
  allowed for right-to-left names.

- Treat an outbound `"proxySettings": null` as absent, as Xray-core does.
  Next to `sockopt.dialerProxy` it was rejected as a combination, and alone it
  was rejected as a non-object, so panel output with explicit null fields
  failed to load.

- `sockopt.dialerProxy` chains no longer depend on outbound order. An outbound
  that chains to a freedom fragment handler gains its mask; listed before an
  outbound that chains through it, it was then mistaken for a fragment handler
  itself and rejected. Xray-core resolves the tags at dial time, so both orders
  now parse to the same configuration.

- Grow gRPC stream receive windows with the link, as grpc-go's BDP estimator
  does under Xray's default `grpcSettings`. Every stream kept HTTP/2's
  65,535-byte window, which capped a flow's download at one window per round
  trip. Windows now start there and double while a sample fills two thirds of
  them, up to 16 MiB, or 1 MiB with the mobile and low-memory profiles; any
  configured `initialWindowsSize` still pins them, as in grpc-go, and the
  opening burst is unchanged. Samples start as DATA arrives, as grpc-go's
  do, so grpc-go's server never counts a BDP ping toward its
  `too_many_pings` limit. At an added 113 ms, gRPC downloads rose from 4.4 to
  124.9 Mbit/s under a 150 Mbit/s limit (Go 124.6) and from 4.4 to 187.6
  without one (Go 183.8). On loopback one download runs 2.2 times as fast and
  its larger window raises its peak footprint from 3.1 to 6.9 MiB.
- Return XHTTP H2 stream credit once a sixteenth of the window has been
  read, instead of after about a third of it, through a vendored h2 option.
  Without a rate limit at an added 113 ms, XHTTP H2 downloads rose from 181.5
  to 261.9 Mbit/s (Go 253.0). Go's client returns credit every 4 KiB; a
  WINDOW_UPDATE for every read cost a fast local download 16% of its speed.
  On loopback a single download now runs about 2% below the previous policy,
  and a duplex transfer peaks at 7.6 MiB instead of 6.0.
- Let a new XHTTP H2 connection carry 100 streams before the server's
  SETTINGS arrive, as Go's client assumes, instead of one. A packet-up flow's
  first upload found the connection full while its download held the only
  stream and dialed a second connection: a TLS round trip before the first
  byte, and twice the connections per flow. At an added 113 ms such a flow now
  reaches its first byte in 239 ms instead of 362 (Go 241) on two connections
  per warmup and download instead of four, as Go does.
- With the mobile and low-memory profiles, open XHTTP H2 streams at 1 MiB and
  grow them to Go's 4 MiB only for a reader that keeps up, so a stalled
  download pins a quarter of the memory. A configured window stays fixed.
  With the mobile profile, eight XHTTP H2 downloads whose readers stall
  through TUN fell from a 61.5 MiB to a 19.2 MiB peak footprint at the same
  speed, for about 3% more CPU.
- Auto-tune XHTTP H3 receive windows as Xray's quic-go does, from 2 MiB per
  stream and 3 MiB per connection up to 6 MiB and 15 MiB or the configured
  maxima, which were rejected before. The mobile profiles keep the initial
  windows fixed.
- Send XHTTP H3 datagrams on a connected UDP socket on macOS, as Hysteria
  already did: an unconnected socket looks up the route for every datagram.
  In one profiled run of eight SOCKS uploads, throughput rose from 281 to
  372 MiB/s and client CPU per MiB fell from 6.3 to 3.4 ms. Eight uploads
  through TUN, which the client now feeds faster than a local server drains,
  hold more in their QUIC buffers: a 31.9 MiB peak footprint instead of 9.6,
  for 37% more throughput.
- Share one QUIC send budget between XHTTP H3 uploads. Each XHTTP H3 request
  owns a QUIC connection, and every connection kept a send window of at
  least 2 MiB, so 32 uploads to a local Xray-core server that drained slower
  than they wrote held 71 MiB of a 95 MiB heap in quinn's send buffers.
  While several connections upload, each now keeps its share of 16 MiB,
  between 128 KiB and 2 MiB, and grows with its congestion window only to
  its share of 10 MB; up to eight uploads keep the 2 MiB they had. With the
  mobile and low-memory profiles they share 4 MiB and never grow past it.
  Against Xray-core v26.10.21, 32 uploads now peak at 87.7 instead of
  162.1 MiB RSS and 32 duplex transfers at 78.2 instead of 140.6, at the
  same throughput and CPU per byte; a single upload peaks 0.2 MiB higher.
  An 8 MiB budget took 32 uploads to 53 MiB but cost eight uploads 2–4% more
  CPU per byte; see the [2026-10-30 report](docs/benchmarks/results/2026-10-30-xhttp-h3-send-budget/README.md).
- Give each XHTTP H3 and DoQ endpoint a receive buffer for four datagrams,
  two with the mobile and low-memory profiles, through a vendored quinn
  option. On Linux and Android quinn reserved room for 32 datagrams of 64 GRO
  segments, 2.9 MiB, in every endpoint, and every XHTTP H3 request owns one:
  32 downloads from Xray-core v26.10.21 kept 43 MiB of these buffers
  resident, and glibc's `calloc` zeroes a reused one in full. In a Linux
  container 32 downloads, duplex transfers and uploads now peak at 114.6,
  131.9 and 42.3 MiB RSS instead of 154.3, 183.9 and 73.4, at the same
  throughput and CPU per byte. GRO stays on: without it downloads lost a
  quarter of their throughput. macOS and Hysteria are unchanged; see the
  [2026-10-30 receive-buffer report](docs/benchmarks/results/2026-10-30-xhttp-h3-receive-batch/README.md).
- Stop h3 from buffering XHTTP H3 downloads outside QUIC flow control,
  through a vendored h3 0.0.8. While a download's stream stayed full, h3 read
  one more QUIC chunk than it handed out for every DATA frame, and those
  chunks no longer counted against the receive window: in 32 downloads from
  Xray-core v26.10.21 in a Linux container they reached about 20 MiB in six
  seconds and 46 MiB in 28, and a server of 700-byte frames got 4.1 MiB ahead
  of a reader that had taken 1 MiB. h3 now decodes buffered frames before
  reading, as upstream's unreleased fix does, and reads during a DATA frame
  only while part of it is missing. 32 downloads now peak at 95.8 MiB RSS
  instead of 112.5, and four times as long a transfer at 103.9 instead of
  140.7, with 4–7% more throughput and less CPU per byte. Most of the rest is
  data waiting in the 32 full 2 MiB stream windows; see the
  [2026-10-31 report](docs/benchmarks/results/2026-10-31-xhttp-h3-download-memory/README.md).
  On macOS, where readers keep up, the XHTTP H3 cases are unchanged
  ([macOS re-check](docs/benchmarks/results/2026-10-31-xhttp-h3-macos-recheck/README.md)).
- Share one QUIC receive budget between concurrent XHTTP H3 downloads, and
  hold a download to it only while its reader falls behind. Every XHTTP H3
  request owns a QUIC connection, and a reader slower than its server keeps
  the whole 2 MiB stream window full: 32 downloads from Xray-core v26.10.21
  in a Linux container held 57 MiB that way. A download whose reader has not
  found its stream empty for four 64 KiB samples and two round trips now
  grants at most its share of 16 MiB, or 4 MiB with the mobile and
  low-memory profiles, split between the connections that downloaded in the
  last one to two seconds. It never grants less than 128 KiB or than its
  reader took in those round trips. A lone download keeps its full auto-tuned
  window, and the 2 MiB handshake windows are unchanged. 32 downloads now
  peak at 50.0 instead of 96.7 MiB RSS, 32 duplex transfers at 63.6 instead
  of 110.6, and with the mobile profile 32 downloads at 43.5 instead of 96.3,
  at equal or higher throughput. One- and eight-flow cases, the macOS
  collector's `xhttp-h3` cases and eight downloads over 54 and 114 ms round
  trips stay within run-to-run spread; holding every download to its share
  would have cut those eight downloads at 54 ms from 3.5 to 1.4 Gbit/s.
  Vendored quinn-proto's `set_stream_receive_window` now also lowers a
  window, without withdrawing credit already sent; see the
  [2026-10-31 receive-budget report](docs/benchmarks/results/2026-10-31-xhttp-h3-receive-budget/README.md).
- Benchmarks: the issue #28 runner compares gRPC and the time to first byte,
  and the migration collector can pin a Go-verified reference by SHA-256.
  `scripts/run-migration-campaign.py` runs a whole before/after campaign: it
  waits for a quiet machine before every attempt, retries blocks that only
  external load rejected, and resumes after the last attempt. The publisher
  takes `--pin` and `--label` for comparisons other than the migration; the
  [2026-10-30 report](docs/benchmarks/results/2026-10-30-perf-branch/README.md)
  compares this branch with `main`, and the
  [2026-10-30 three-engine group](docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/README.md)
  compares it with Xray-core v26.10.21 and sing-box v1.14.4. `xray-bench
  chart --omit-sing-box-1000-flows` leaves out a sing-box 1,000-flow series
  that did not complete, as `--omit-sing-box-reality` does for REALITY.

- Bound the bytes each TUN TCP flow can queue toward its outbound: 512 KiB on
  desktop, 256 KiB with the mobile profiles and 128 KiB with `low-memory`. The
  queue was bounded only by message count, which allowed up to 8 MiB per flow
  (4 MiB on mobile), and its copy buffer grew past its cap. With a slow
  outbound, eight XHTTP packet-up uploads through TUN reached a 92 MiB
  footprint on desktop and 63 MiB on mobile; they now stay near 35 and 33 MiB
  at the same speed, and duplex transfers fall from 111 to 42 MiB. Data beyond
  the limit waits in the TCP window, so applications see ordinary
  backpressure. Such paced uploads cost 7–9% more client CPU on desktop and
  about 4.5% with the mobile profile; faster outbounds measured no change.
- Mask WebSocket client frames without a system call per frame: mask keys come
  from the thread-local ChaCha CSPRNG instead of `getentropy` for every 4 KiB
  frame, and masking runs eight bytes at a time. Keys stay fresh and
  unpredictable per frame, and the wire shape is unchanged. Client CPU for
  WebSocket uploads fell by 53–59% and for duplex transfers by 24%.
- Copy XHTTP H2 response frames that wait for a slow reader out of h2's shared
  read buffer, which each queued frame otherwise pinned at roughly twice its
  size. Eight stalled XHTTP H2 downloads through TUN fell from a 65 MiB to a
  44 MiB footprint, at about 4% more CPU for the copies. Flow control is
  unchanged: credit still returns only as the reader consumes data. Readers
  also take several frames per read, which lowered CPU on fast SOCKS
  transfers.
- Start XHTTP H3 connections with a 2 MiB QUIC send window that grows with the
  congestion window up to 10 MB, as Hysteria already did, instead of quinn's
  fixed 10 MB. Each XHTTP H3 request has its own connection, so a slow uplink
  could otherwise buffer 10 MB per upload.
- Benchmarks: build comparison binaries with `scripts/build-isolated-release.py`
  (the collector now requires its provenance record), report the exact peak
  physical footprint, and drive TUN TCP echo by readiness instead of 1 ms
  sleeps. The v26.10.21 migration report gains an erratum: its "before" client
  was a mixed build, and the flagged regressions did not reproduce.

- Bound outbound UDP opens by the outbound level's `handshake` policy (10 s by
  default) on the SOCKS, TPROXY and TUN inbounds, as TCP opens already were.
  Through a `socks` outbound, or Trojan, VMess or VLESS over TLS or REALITY, a
  server that accepted the connection and then stayed silent kept the UDP flow
  opening indefinitely; on SOCKS and TPROXY each such flow also held one of the
  64 shared pending-open permits, so a stalled upstream could block new UDP
  flows. The open now fails at the deadline and the next datagram retries.
  Hysteria and WireGuard are bounded by the policy as well as by their fixed
  10 s client deadline; DNS upstream exchanges keep their attempt deadlines.
  Xray-core sets the same deadline on its SOCKS client handshake. A `handshake`
  of 0 leaves UDP opens unbounded, as Xray-core's WireGuard client treats it,
  instead of failing every open on its first poll.

- Update the development compatibility reference to Xray-core v26.10.21 / Go 1.27.3.
- Restrict the REALITY `random` and `randomized` pools to the four profiles
  with the X25519MLKEM768 key share that v26.10.21 servers require. REALITY
  fingerprints without that share, such as `ios`, `edge` and `qq`, still parse
  and dial, since older servers accept them, but now produce a warning. Verify
  ML-DSA65 and Vision against the new reference.
- Add `sockopt.dialerProxy` chaining and the bounded Finalmask UDP-hop form;
  retain legacy spellings with migration diagnostics and update profile import.
- Resolve WireGuard destination names through tunnel-owned `remoteDNS` with TTL
  caching and TCP fallback, keeping peer bootstrap separate.
- Add HTTPUpgrade WebSocket key/version headers and QUIC v2 Initial sniffing.
  QUIC transport remains v1, with an explicit native-TLS/ChromeParrot limitation.

- Update webpki-roots to 1.0.11, removing the emSign C1 and C3 trust anchors
  whose issuing chains include compromised intermediate certificates.

- Update the zstd dependency family to patched releases, fixing the
  abandoned-stream data leak and decompression memory-safety advisories
  reported by RustSec without changing TLS certificate-compression settings.

- Honour `"udp": false` on the SOCKS inbound. Previously the flag was only
  type-checked and `UDP ASSOCIATE` was relayed anyway. Like Xray-core, the
  request now gets `REP = 0x07` (command not supported) with a `0.0.0.0:0`
  bind address, after login under `password`; no relay socket is created,
  nothing is dialed and the control connection is closed. `CONNECT` is
  unaffected. An absent `udp` still enables `UDP ASSOCIATE`, unlike Xray-core,
  which treats it as `false`; this is an open compatibility question. In the
  Rust model, `InboundProtocol::Socks` now carries `SocksInboundSettings`
  (`auth` and `udp`), whose default keeps UDP enabled.

- Android: share snapshot/enum decoding and VLESS parameter validation without
  changing their accepted values or errors. VPN session shutdown retains later
  cleanup failures as suppressed exceptions on the original error; descriptor
  ownership, shutdown order, and public SDK/FFI contracts are unchanged (#81).

- Mobile: prepare SOCKS outbound server addresses before installing Android VPN
  or Apple Network Extension settings, in both flat and legacy `servers` forms.
  Pin all resolved A/AAAA candidates in `dns.hosts`, preserve credentials and TLS
  metadata, and reject tunnel-owned carrier addresses. Apple also excludes every
  SOCKS carrier candidate from tunnel routes; destination domains still resolve
  at the SOCKS proxy.

- Android: run the reference `XrayVpnService` startup probe after DNS
  bootstrap and before `Builder.establish()`, on a separate unstarted core
  without a TUN fd. A failed, timed-out or cancelled probe leaves routes and
  DNS untouched, and a successful one is not repeated by the data-path core.
  Kotlin adds `XrayCore.preflightStartupProbe()` and the
  `StartupProbePreflight` capability over the existing ABI 1.12 entry point;
  `stopXrayTunnel()` and `XrayCore.stop()`/`close()` cancel a pending
  preflight. This ports the Apple fix for #69 from #70.

- Android: the reference `XrayVpnService` marks its VPN as not metered on
  Android 10+, `XrayCore.ffiInfo()` reads the native version and capabilities
  once per process, and `XrayCore.stats()` checks the native value count.

- Expose the geodata search directory in the Android adapter:
  `XrayCore.create(geodataSearchDirectory = …, geodataSearchPolicy = …)` and an
  overridable `XrayVpnService.geodataSearchDirectory()`. The policy defaults to
  `Exclusive` because the core's process-default directories are meaningless in
  an Android app. Routing replacement reuses the same directory, and the
  reference service passes it to both the startup-probe preflight core and the
  data-path core. Document how
  to install geodata under `noBackupFilesDir` and correct the claim that
  `geoip:private` never needs `geoip.dat`: DNS IP rules read it from the file.

- Add RFC 1929 username/password authentication to the SOCKS inbound
  (`"auth": "password"` with `accounts`). Password-protected UDP associations
  accept datagrams only from the declared client endpoint and refuse requests
  that leave the port unset, such as `0.0.0.0:0`, and
  `accounts` under `noauth` are now rejected instead of ignored (#78).
- Parse the Xray `socks` outbound in its flat and legacy `servers` forms, with
  optional RFC 1929 `user`/`pass` credentials over raw/tcp with none or TLS
  security. Mixed forms, more than one server or user, a lone `user` or `pass`,
  empty credentials, a zero port, enabled Mux, other networks and REALITY fail
  closed. Without TLS the credentials travel in cleartext.
- Carry UDP through the `socks` outbound with `UDP ASSOCIATE`. Unlike Xray,
  which always declares `0.0.0.0:0`, the request declares the relay socket's
  real port, so servers that admit only the declared client endpoint, such as
  a password-protected xray-rust SOCKS inbound, accept it. The association
  ends when the server closes the control connection, malformed or fragmented
  relay datagrams are dropped instead of ending it, and an oversized datagram
  is an error rather than an empty datagram. The datagrams use a protected
  plain UDP socket; TLS covers only the control connection.
  Unspecified relay addresses use the actual TCP peer after Happy Eyeballs,
  and IPv4-mapped proxy literals select IPv4 for both sockets. Pinned Xray-core
  interop covers UDP, TLS control, IPv4/IPv6/domain targets, and TUN UDP/DNS;
  the password-inbound restriction on undeclared UDP ports remains in force.

- Add the Xray `http` outbound: HTTP/1.1 `CONNECT` with optional Basic
  credentials, in the flat and legacy `servers` forms, over raw/tcp with none
  or TLS security. TLS offers only `http/1.1`, also under a uTLS fingerprint,
  and only status 200 opens the tunnel, as in Xray. The request matches the
  Go client's, masquerade headers included. The response head is limited to
  16 KiB and tunnel bytes that arrive with it are kept, where Xray loses them.
  Custom `headers`, HTTP/2, UDP, Mux, a lone `pass`, an empty `user` or one
  containing `:`, other networks and REALITY fail closed; without TLS the
  credentials travel in cleartext. Android and Apple prepare the proxy host
  before VPN setup like a SOCKS server's (#79).

- Fix false checksum failures in Gradle provenance verification after a partial
  download is retried. Verify completed temporary files against both canonical
  sidecars and the existing SHA-256 locks.

- Update Tokio to 1.53.3, ctutils to 0.4.4, rustls-webpki to 0.103.16 and
  webpki-roots to 1.0.10 to resolve the RustSec advisories tracked in #83;
  replace the yanked der 0.8.0 with 0.8.1.
- Register TUN and benchmark descriptors with Tokio's new API using private
  close-on-exec duplicates. Async readiness owns its descriptor for its entire
  lifetime, while the caller's original BORROWED/OWNED close policy is preserved.

## 0.8.1 - 2026-10-18

Release candidate preparation; publication and exact-candidate release
qualification are pending.

- Run the Apple startup probe after DNS bootstrap and before installing tunnel
  routes and DNS. A failed, timed-out or cancelled probe leaves network settings
  untouched; a successful preflight is not repeated when the data-path core
  starts. This fixes application connectivity failures during VPN startup (#70).
- Add C ABI 1.12, `STARTUP_PROBE_PREFLIGHT` and
  `xray_core_preflight_startup_probe`, with the matching Swift adapter. Existing
  `xray_core_start` probe behavior and protocol/configuration formats are
  unchanged. The updated Apple provider requires the matching native library
  when startup probes are enabled.
- Update Tokio to 1.53.2, aws-lc-rs to 1.18.1, zeroize to 1.9.1, uuid to 1.28.0,
  zstd to 0.14.2, async-trait to 0.1.92, aho-corasick to 1.1.5 and thiserror to
  2.0.21, together with their resolved transitive dependencies.
- Update the core Android build to AGP 9.4.1, Gradle 9.8.1 and built-in Kotlin
  2.4.21, with verified dependency metadata and unchanged minimum API/compile SDK.
- Fix UDP loopback port collisions in the device-test fixtures (#60) and add
  direct-target WireGuard fixture coverage (#61). These are test-environment
  changes, not client runtime fixes. Restore scheduled interoperability checks
  and update CI artifact actions.
- Preserve the published 0.8.0 evidence and the subsequent Android, iPhone and
  Apple TV reports with their original source/binary identities. They do not
  establish a fresh full-device or calibrated performance pass for 0.8.1.

## 0.8.0 - 2026-10-11

Stable release preparation; publication status is tracked in [the promotion record](docs/v08-stable-promotion.md).

- Fix `xtls-rprx-vision` direct mode over plain TLS on the raw transport.
  Direct reads and writes now use the connection beneath the TLS session, as
  they already did beneath REALITY and as Xray-core does, instead of staying
  inside the session. Previously an inner TLS session carried through
  VLESS + TLS + Vision to Xray-core failed with EOF right after its handshake.
  Local Xray-core interop now carries a real inner TLS session through TLS
  Vision as well as REALITY Vision, including a bulk round in each direction.
- Add an Xray-compatible `blackhole` outbound so profiles that route ads, QUIC
  or other denied traffic to `block` load and keep blocking it. `none` closes
  TCP after the inbound acknowledgement and `http` first sends Xray's fixed
  403 reply. A UDP flow is dispatched once, gets the `http` reply once, and
  then discards its datagrams until it is idle. Nothing is dialed and no
  socket is opened. Unknown response types and blackhole proxy chains fail
  closed.
- Close TUN TCP flows whose remote closes before the client's handshake ACK
  without waiting for another client segment.
- Added a capability-gated on-demand outbound probe in C ABI 1.9 and the
  Swift/Kotlin adapters. A host heartbeat can send one bounded HTTP(S) probe
  through a leaf outbound of a running core, selected by tag or the default
  outbound, and receive its delay or a typed failure matching the health
  snapshot categories. Invalid URLs, timeouts outside 1 to 60000 ms, and
  unknown tags are rejected before any network activity; results do not change
  health snapshots or selector state, and diagnostics stay redacted. Lifecycle
  calls cancel probes before draining shared calls, so stop/close do not wait
  for a 60-second probe timeout. Swift rejects embedded NUL before the C bridge.
  The probe uses bit 22, reserving ABI 1.8 and bits 19–21 for v0.8 clients.

- Add Trojan, Shadowsocks 2022 and VMess AEAD client outbounds for SOCKS,
  HTTP, TUN and routed DNS, with shared protected carriers and bounded Mux/XUDP.
  SS2022 supports all three methods and AES identity chains; VMess supports
  AES/ChaCha/auto and authenticated-length/termination options. Legacy
  Shadowsocks AEAD-2017 and nonzero VMess alterId remain excluded.
- Add shared profile imports, capability bits and Swift/Kotlin integration
  through additive C ABI 1.11. Retain Xray-core v26.7.28 as the compatibility
  reference and document transport, nonce, session and recovery limits.
- Add independent-server and carrier matrices, wire oracles, fuzz coverage
  and a separate v0.8 release-evidence gate. Historical physical results keep their original build identities; current
  release decisions and limitations are recorded separately.
- Reduce VMess record I/O and crypto overhead with bounded batching and
  read-ahead, preserving authenticated delivery, plaintext erasure and UDP
  boundaries. Admit at most two sustained raw-TCP ChaCha duplex relays to an
  additional task per core; AES retains the combined relay. Record the CPU,
  throughput, memory and latency tradeoffs against pinned Xray and sing-box.
- Wait for inbound owners and admitted VMess relay children during Core.stop.
- Expose existing Hysteria/WireGuard rebind through Android adapters and add
  configurable Hysteria stream budgets through C ABI 1.10. Defaults remain 64 TCP/32 UDP streams
  per session; host-selected limits remain bounded and do not add QUIC sessions.
- Add opt-in TUN flow admission through C ABI 1.11 and Swift/Kotlin callbacks,
  including an Android 10+ UID allowlist helper. Admission runs before upstream
  TCP/UDP/DNS handling with bounded workers/queues and an explicit timeout
  policy. Unknown Android owners are denied by the strict helper.
- Support bounded Hysteria Salamander and automatic port hopping with protected
  socket replacement, retaining the authenticated session and stream leases.
- Support first-ClientHello fragmentation for TCP TLS/REALITY in FinalMask and
  dedicated freedom `dialerProxy` profiles. Preserve handshake authentication
  and Vision direct mode; delay/count/memory bounds and unsupported combinations
  fail explicitly. UDP noise supports bounded FinalMask preludes on Hysteria2 and XHTTP H3, including Salamander ordering and idle reset. Linux TPROXY adds transparent IPv4/IPv6 TCP/UDP via dokodemo-door with shared routing and bounded flows.

- Avoid an unnecessary Apple initial-path rebind while preserving real network
  changes and recovery. Absorb Hysteria UDP receive bursts with a bounded
  16-packet queue; the shared 1 MiB payload budget is unchanged.
- Preserve the owner's release-specific deferral of further iPhone Hysteria
  startup-failure investigation and the unconfirmed 5% performance gate.
  Failures remain recorded; no zero-regression or reliability guarantee is made.

## 0.7.0 - 2026-09-27

Stable source release. Canonical SDK packages and their publication status are
listed in [xray-rust-mobile releases](https://github.com/aimalygin/xray-rust-mobile/releases).

- Add Hysteria 2 and standard WireGuard client outbounds for SOCKS, HTTP,
  TUN and routed DNS, with bounded TCP/UDP resources and independent native
  server interoperability checks. WireGuard supports up to eight peers,
  IPv4/IPv6, PSKs and authenticated peer isolation.
- Add protected carrier rebinding and bounded mobile network-change recovery.
  Preserve active WireGuard sessions and keep TUN download/cancellation
  responsive while an upload is blocked.
- Forward client TCP FIN through TUN after draining buffered upload, preserving
  server replies after half-close and releasing naturally closed connections.
- Allow up to 512 WireGuard UDP sessions, allocated on demand, so short requests
  using fresh source ports do not exhaust the old 16-session budget before
  TUN idle cleanup. Retain bounded queues and verify budget reclamation.
- Reduce shared async setup allocations, bound packet-protocol TUN upload
  queues, reuse WireGuard TCP receive storage and improve QUIC ACK handling.
  The CLI defaults to two Tokio workers and preserves the explicit override.
  Improve XHTTP/H3 receive batching without waiting for future data.
- Expose capability discovery, shared profile import and network-change
  notifications through the additive C ABI 1.7 and matching Swift/Kotlin APIs.
- Retain the pinned Xray-core v26.7.28 compatibility target. Supported options
  and bounds are documented; this release does not claim full upstream parity.
- Defer the higher XHTTP/H2 TUN RSS to a future version by owner decision.
  Separate Hysteria2 latency/short WAN duplex gaps remain documented; complete
  performance parity has not been established. See [performance evidence](docs/v07-performance.md).
- Preserve device/performance measurements of clean candidate `3533166` and
  validate stable promotion as version/documentation/evidence tooling only.
  Runtime, dependencies, ABI and build inputs must remain unchanged.
- Record two explicit owner decisions: Android cellular handover was not tested;
  the investigated rare Android WireGuard timeout case is accepted for 0.7.
  Original failures remain visible; no root-cause fix or general reliability
  allowance is claimed. See [stable evidence](docs/v07-stable-promotion.md).
- Require versioned exact-candidate Apple/Android evidence for 0.7 publication.
  New checks include both protocols, both Android adapter paths, recovery and
  legacy regression coverage; old v0.6 evidence remains independently validated.

- Add shared Rust import for Hysteria2 links and WireGuard configuration files,
  exposed through C ABI 1.5 and equivalent Swift/Kotlin SDK APIs. Advertise
  protocol/import capabilities and validate bounded input with redacted errors.
  Preserve WireGuard peers, PSKs and split routes; require explicit real DNS.
- Prepare Hysteria 2 and all WireGuard peer endpoint DNS before mobile tunnel
  setup on Apple and Android, preserving profile addresses and credentials.
  Apple adds outer-carrier route exclusions; Android keeps socket protection.
- Reject FakeDNS-only mobile routes that require real destination DNS through
  WireGuard or Freedom, including balancer candidates and fallbacks. Preserve
  VLESS/Hysteria remote resolution and IP-only split routes.

## 0.6.1 - 2026-09-09

- Promotes the tested `0.6.1-rc.1` implementation to stable, including the
  4 MiB XHTTP/H2 stream receive window and bounded TUN download prefetch.
- Runtime code, Swift/Kotlin adapters, public C ABI, compiler settings and
  external dependency versions and source identities are unchanged from RC1.
  Only workspace version metadata, the generated contract's `coreVersion`
  and release documentation change.
- Retains the original RC1 device and performance evidence with its measured
  commit/tree identity. Stable builds and automated release gates run in
  GitHub Actions; no new local tests, benchmarks or device campaigns are
  claimed. See [stable promotion](docs/v061-stable-promotion.md).

## 0.6.1-rc.1 - 2026-09-09

- Add optional `xhttpSettings.h2StreamReceiveWindow` (integer bytes,
  65,535–16,777,216). Absent/null keeps the 4 MiB default; connection credit
  remains 16 MiB. Support aliases, `extra` and independently configured
  download carriers. Other transports and POST pacing retain their defaults.

- Raise XHTTP/H2 stream receive credit to 4 MiB to remove the 64 KiB
  single-download bottleneck on high-RTT paths (issue #28), retaining the
  16 MiB connection window. Add delayed-path, partial-read, stalled-stream
  and cancellation regressions; document the increased per-stream buffering
  allowance and related transport limits in the
  [window audit](docs/transport-window-audit.md).
- Prevent a stalled TUN TCP download from blocking neighboring TCP, UDP and
  control events. Bound remote prefetch to 256 KiB per flow, preserve DNS frame
  and FIN ordering, and keep upload and host cancellation responsive while
  waiting for download space. Batch immediately ready reads without waiting
  for more data. Add deterministic and runtime regressions;
  record the repeated [iPhone validation](docs/issue28-tun-validation.md).

## 0.6.0 - 2026-09-08

- Promotes the completed v0.6 RC scope: bounded VLESS 1-RTT/0-RTT encryption,
  lazy `IPOnDemand` routing, independent XHTTP downloads, mobile projection,
  and supported-configuration schema and CLI tooling.
- Preserves the RC runtime, dependencies, adapters and C ABI. Only version
  metadata, release verification tooling and documentation change; a blocking
  promotion check verifies that boundary against the published RC commit.
- The owner confirmed RC profile import, connect, disconnect and reconnect in
  a real application on 2026-09-08. This is an owner report, separate from CI
  and the archived bounded iPhone 13 / Samsung device campaigns.
- Accepts the published RC device and performance evidence with its original
  commit/tree identity. Long device soak campaigns are removed from the
  current release checklist at the owner's request and are not claimed.
  Final automated builds and release gates run on the stable source revision.
- See [stable promotion](docs/v06-stable-promotion.md) for provenance,
  publication steps and the exact verification boundary.

## 0.6.0-rc.1 - 2026-09-05

- Published the frozen source candidate and matching mobile SDK after the
  exact-commit CI, performance and bounded physical-device gates passed.
  [Release evidence](docs/v06-release-evidence.md#published-v060-rc1) records
  source provenance, published artifacts and coverage limits. The date above
  identifies the candidate freeze; publication completed on 2026-09-08 UTC.
  Long soak tests were omitted by owner decision and are not claimed.
- Added the generated supported-configuration contract, exact parser-backed
  `config check` with JSON reports/stdin/resource directories, and canonical
  `config example` exports. Parser and tooling share recognized field sets;
  CI guards fixture parity, contract freshness and CLI behavior.
- Extracted DNS and stream/security parsing along existing ownership boundaries
  without changing config acceptance or the C ABI.

- Added bounded XHTTP `downloadSettings` for packet-up/stream-up: independently
  addressed and protected HTTP/1.1, HTTP/2, HTTP/3 or REALITY download carriers,
  separate pools, shared session identity and cancellation. Recursive stacks,
  security downgrades, stream-one and chaining combinations fail closed.
- Extracted XHTTP config normalization and core carrier compilation, added a
  pinned configuration/application oracle and download lifecycle regressions.

- Started `0.6.0-dev.0` development against the retained, exact Xray-core
  `v26.7.28` contract. Published `v0.5.0` core/mobile artifacts remain pinned.
- Added canonical routing `IPOnDemand` with ordered lazy DNS, all-address
  matching, a fail-closed 256-candidate work limit, shared managed cache and
  cancellation, and one atomic policy revision per selection. A common
  23-case Go/Rust oracle checks compatibility with the pinned reference.
- Added `ipOnDemand` to schema-1 routing snapshots and both Swift/Kotlin
  decoders without changing C ABI symbols or layouts. Extracted routing
  parsing and evaluation from the larger config/outbound modules.
- Added bounded VLESS `mlkem768x25519plus` 1-RTT/0-RTT,
  `native`/`xorpub`/`random`, one-to-eight mixed X25519/ML-KEM-768 relay keys,
  configurable padding, raw/WS/HTTPUpgrade/gRPC/XHTTP carriers, and optional
  Vision. Vision Direct retains outer security/carriers and random header
  masking. TCP, UDP, and XUDP use the shared encryption boundary.
- Replaced the Rust `VlessUser.encryption` string with typed
  `VlessEncryption`, extracted VLESS parsing, and redacted crypto config/wire
  diagnostics. The public plaintext-server guard follows the first selected
  user. Added pinned Go primitive/live interop checks, cancellation/replay/
  corruption coverage, and a narrowly patched BLAKE3 byte-context API. Swift
  and Kotlin import errors redact key-bearing encryption values.
- Added equivalent Swift/Kotlin bounded share-link import with common Rust
  validation/projection fixtures. Reject malformed ML-KEM coefficients before
  dialing. Added dedicated handshake/record fuzz drivers and full pinned Xray
  none/TLS/REALITY interoperability with a local cover origin.
- Added a memory-only 0-RTT ticket cache that publishes after authenticated
  padding, invalidates on failed/cancelled resumption, and never automatically
  retries early data. The exact Go oracle distinguishes real resumed handshakes
  and covers mixed relay chains, configured padding, expiry, and cold recovery.
- Expanded encrypted full-Xray interop to 540 application flows across 204
  profiles, including inner TLS/Vision Direct, both gRPC encodings, XHTTP H1/H2/H3,
  mixed keys, session reuse, UDP and UDP/443. Swift/Kotlin encrypted raw/XHTTP
  share links preserve both Vision flows, with shared projection fixtures.

## 0.5.0 - 2026-09-03

- Promoted `v0.5.0-rc.1` to the stable channel after the complete automated
  release matrix passed, including pinned Xray-core interoperability,
  ASan/Miri/Loom hardening, bounded fuzzing, controlled-loss transport tests,
  exact-revision performance budgets, Apple builds, and the four-ABI Android
  AAR.
- Accepted the completed physical Apple H2/REALITY and memory rehearsals plus
  the Android H2/H3/REALITY, transition, recovery, memory, and cancellation
  rehearsals as the device evidence for this release. The previously planned
  clean six-hour Apple and Android campaigns were not run and are not claimed
  by this release.
- Ships the RC1 implementation unchanged apart from stable version and
  documentation metadata: managed encrypted DNS and caching, health-aware
  selectors, validated TCP chaining, connection management, structured TUN
  diagnostics, and atomic routing-policy replacement remain the supported
  `v0.5` scope.

## 0.5.0-rc.1 - 2026-09-02

- Added blocking v0.5 host-hardening release gates: eight one-minute ASan fuzz
  campaigns now include SOCKS/HTTP inbound parsing, QUIC Initial sniffing,
  XHTTP framing, and TUN queues; selected library/FFI tests run under ASan and
  Miri; and Loom exhaustively models atomic routing-policy publication.
- Added a pinned-Xray Linux `tc netem` RC gate covering full-duplex WebSocket,
  HTTPUpgrade, gRPC, and XHTTP H1/H2/H3 plus two-minute held-open H2/H3
  `stream-one` sessions under controlled delay, jitter, and packet loss.
- Completed the focused v0.5 credential-boundary review. Config and wire debug
  output now redact VLESS UUIDs and REALITY short IDs, FFI error allocations
  are cleared before release, and QUIC Initial derived secrets and keys have
  bounded zeroizing lifetimes. The documented residual lifetime of credentials
  required by active VLESS/JSON state is not presented as an independent
  security audit.
- Added capability-gated routing-policy hot replacement in C ABI 1.4 and the
  Swift/Kotlin adapters. Hosts can compile a scoped `routing` JSON document,
  including `geosite`/`geoip` matchers from the handle's configured geodata
  generation, and atomically publish it for new flows while existing flows,
  outbound topology, and shared transport pools remain untouched. Invalid
  outbound/balancer references or topology changes retain the previous
  revision; a redacted schema-versioned snapshot reports the active revision,
  rule count, and domain strategy.
- Added a clean five-run v0.5 pre-device performance gate. A new
  `phase2-probe` measures production selector/chaining, atomic switching,
  health/selection snapshots, DNS caching, live connection inventory,
  accounting/close, structured TUN diagnostics, and TUN statistics. The macOS
  runner also replays v0.4.0 routing, DNS-selector, process-RSS, TCP, and
  inherited-fd TUN anchors under explicit budgets and rejects dirty or
  mixed-revision evidence before the physical Apple/Android campaign. The
  first clean candidate gate passed and records the remaining 1,000-flow RSS
  headroom as an explicit device-profiling risk.
- Restored small-rule routing performance lost before v0.5 when the shared
  domain and IP indexes replaced linear matchers. Domain sets of at most eight
  entries now retain a linear fast path while geosite-sized sets keep their
  compiled hash/automaton indexes; single IP ranges and empty inverse sets also
  avoid the generic range search. On the same release probe, 4096-rule DNS
  selector last-hit latency fell from 91.5 to 26.4 microseconds without
  regressing the 4096-matcher indexed path, and the 64-rule IP route probe fell
  from 472 to 367 nanoseconds.
- Started the `v0.5` development line with additive C ABI minor-version and
  capability discovery. The canonical Swift and Kotlin adapters expose the
  loaded ABI version and capability mask and reject incompatible major or
  insufficient minor revisions before allocating a core handle.
- Split outbound topology, lazy handler construction, and routing policy into
  an immutable `OutboundGraph`, a shared `OutboundFactory`, and
  `OutboundRouter`. Each `Core` now owns one graph/factory before start, so
  future selector and health state can reuse transport pools without rebuilding
  the core.
- Added Xray-compatible selector groups: `routing.balancers` expands tag
  prefixes into sorted graph nodes, `balancerTag` rules support random,
  round-robin, and fallback selection, and a shared atomic override/snapshot
  API switches new flows without rebuilding handlers or their transport pools.
- Added the bounded Xray-compatible `observatory` subset and health-backed
  selection. Lifecycle-owned HTTP(S) URL probes publish typed, redacted health
  snapshots; random and round-robin skip known-dead candidates, while
  `leastPing` deterministically selects the lowest healthy delay and falls back
  when no healthy candidate remains. Explicit overrides remain authoritative.
  `leastLoad` uses a 16-result rolling health window, Xray-compatible
  deviation/average/failure ordering, bounded top-N distribution, RTT and
  failure-rate filters, duration baselines, and literal tag costs. Regex costs
  fail closed; non-TCP chaining shapes remain.
- Extended C ABI 1.2 with capability-gated atomic selector override/clear and
  two-pass, schema-versioned JSON snapshots for selection and redacted health
  state. The Swift and Kotlin adapters expose equivalent typed APIs; SwiftPM
  tests and the four-ABI Android JNI/AAR build cover the shared wire contract.
- Added validated transport-layer TCP outbound chaining through Xray
  `proxySettings`. The immutable graph resolves tag edges and rejects missing
  targets or cycles before core start; Freedom/VLESS carriers retain shared
  handler pools and apply TLS/WebSocket/HTTPUpgrade/gRPC/TCP-backed XHTTP over
  the nested protected stream. Protocol-layer/UDP/DNS, REALITY, and XHTTP
  HTTP/3 chain shapes fail closed while those lifecycle boundaries remain
  unsupported.
- Added core-owned connection management for routed SOCKS TCP/UDP, HTTP TCP,
  and TUN TCP/UDP flows. ABI 1.3 plus equivalent Swift/Kotlin models expose
  revisioned opening/active inventory, addressable close, and cumulative
  per-outbound accounting. Swift and Kotlin also expose the seven typed TUN
  diagnostic queues under the existing diagnostic capability bit.
- Added managed encrypted DNS transports for strict routed `tls://` DoT,
  routed/provider-local HTTP/2 DoH (`https://` / `https+local://`), and
  provider-local `quic+local://` DoQ. All use
  non-recursive bootstrap resolution, certificate/name verification, bounded
  operations, and mobile preflight pinning; the TUN anchor supports both UDP
  and length-prefixed TCP clients. DoH and DoQ currently open one connection
  per exchange; DoQ uses exact ALPN `doq` and one bidirectional stream.
- Added a typed 30-second NXDOMAIN/NODATA cache and optional bounded
  stale-while-revalidate for positive destination answers. Global Xray
  `disableCache`, `serveStale`, and `serveExpiredTTL` fields are supported;
  transport failures are never cached, refreshes remain single-flight, and an
  explicit 1-through-86400-second stale window is required.
- Added managed platform-resolver injection for Rust embeddings. The new
  constructors retain `dns.hosts`, configured servers, routed query transport,
  and cache ownership; `System` uses the dependency only for no-server
  destination fallback and non-recursive endpoint bootstrap, while
  `StaticOnly` ignores it and remains fail-closed. Runtime startup preserves
  the same dependency instead of silently restoring `getaddrinfo`.
- Expanded the blocking pinned-Xray oracle matrix for v0.5. The live suite now
  proves round-robin traffic reaches both Xray VLESS members and a two-hop
  transport-layer chain reaches its final echo target without local domain
  resolution. The RC gate also submits one shared Phase 2 balancer/chaining/
  observatory/encrypted-DNS/cache config to `xray run -test`, then explicitly
  runs DoT/DoH/DoQ framing and failover, configured-DNS policy/bootstrap, and
  cache/singleflight/stale-refresh oracle filters.
- Added Android VLESS share-link import parity for the portable Apple subset:
  raw/TCP REALITY and XHTTP/SplitHTTP with none, TLS, or REALITY security. The
  Kotlin API emits the same mobile TUN topology, rejects duplicate or
  unsupported security-critical fields, bounds XHTTP `extra` to 64 KiB and one
  compatibility decode, and keeps unsupported secret values out of errors.
- Extended the test-only Android physical-device harness with owner-controlled
  canonical JSON import through an overwrite-and-delete private pending file
  and per-protocol bounded stress counts. A physical Android 15 rehearsal
  passed a pinned-certificate VLESS XHTTP `stream-one` endpoint over exact H3,
  including a Mac preflight oracle, 660/660 device HTTP attempts, stable
  repeated-cycle recovery memory, and disconnect/reconnect recovery. The
  short dirty-revision run remains diagnostic and does not replace the clean
  six-hour Android release report.

## 0.4.1-rc.4 - 2026-08-31

- Fixed an XHTTP/2 `stream-up` deadlock where a concurrent downlink poll could
  cancel the uplink's pending flow-control reservation and strand a sustained
  upload. Added deterministic split read/write coverage and an 8 MiB live
  Xray-core interoperability regression.
- Added safe pre-commit HTTP/2 GOAWAY retry handling plus regression coverage
  for non-replay after commitment and request/buffer ownership across
  cancellation.
- Accepted an HTTP/3 `H3_NO_ERROR` request reset only after every declared
  fixed-length request byte was delivered, while preserving failure for
  unknown-length or premature resets; added transport and full-load interop
  regressions.
- Added weekly broad pinned Xray-core interoperability and resource gates plus
  a warning-only upstream-main compatibility smoke check.
- Scoped the RC4 REALITY/Vision comparator omission to the measured stable
  sing-box v1.13.20 evidence: Xray-core v26.7.28's default `minClientVer`
  26.3.27 rejects that build's REALITY `ClientVer` 1.8.1. RC4 records
  `--skip-sing-box` and publishes xray-rust/Xray-core results only for those
  two workloads, while the generic harness retains sing-box REALITY support
  for compatible or patched binaries. The fixture and timeout remain
  unchanged.
- Published fresh five-run RC4 evidence against exact Xray-core v26.7.28 and
  stable sing-box v1.13.20: 139 validated series and 695 embedded results with
  exact revisions, binary hashes, a deterministic raw-archive digest, and new
  dated charts/tables. The publication records the reviewed sing-box
  gRPC/full-duplex/32 nondeterministic timeout and Xray-core H3 pressure/32
  reset/timeout boundaries without substituting isolated diagnostics.
- Made the benchmark publication depth-limit policy test portable across
  Python JSON decoders, and constrained JFrog-token secret-scan exemptions to
  the two reviewed dated benchmark replay records containing binary SHA-256s.
- Corrected roadmap, implementation-status, verification, configuration,
  migration, benchmark, and release documentation for RC4.
- Routing `ip` matchers are compiled once at load time into a shared sorted
  range index (`xray-routing::IpRangeSet`/`IpMatcherSet`), also used by DNS
  `expectedIPs`/`unexpectedIPs` filters. Outbound selection cost no longer
  grows with the size of a `geoip:` list (route-probe, 16 rules x 5000 CIDRs:
  ~152 us -> ~0.5 us per selection).
- Routing IP matching now follows Xray-core `HeuristicIPMatcher` exactly, as
  the DNS filters already did: IPv4-mapped IPv6 targets (`::ffff:a.b.c.d`) are
  matched as IPv4; an inverse matcher only applies to targets of an address
  family it has networks for, so `!10.0.0.0/8` no longer matches an IPv6
  target; a doubly negated matcher is treated as positive (not expressible in
  configuration, so parsed configs are unaffected).
- CIDR prefixes longer than the address family width are rejected with an
  error at every construction site instead of being clamped.
- `xray-bench route-probe --cidrs-per-rule N` generates N distinct
  non-merging CIDRs per rule to expose per-matcher routing cost; `0` is
  rejected.

## 0.4.1-rc.3 - 2026-08-28

- Made the blocking RC interoperability gate self-contained on a clean runner:
  it now builds the `xray-rust` CLI in the release profile and passes that
  exact binary to the benchmark harness while keeping implicit builds disabled.
  A hermetic clean-target regression test prevents stale `target/debug`
  artifacts from masking this release-gate failure again.

## 0.4.1-rc.2 - 2026-08-28

- Declared the fuzz workspace package under the repository's MPL-2.0 license
  and allowed the OSI-approved NCSA component required by `libfuzzer-sys`, so
  the blocking `cargo deny` release gate covers the fuzz targets successfully.

## 0.4.1-rc.1 - 2026-08-28

- Retargeted the Xray-core oracle, ignored interoperability suite, and
  benchmark harness from v26.5.9 to exact v26.7.28 commit
  `5ca6f4b7d4dc20a881d4330e498892697627ec0c`. Oracle Go modules and committed
  REALITY/gRPC fixtures now use the target dependency graph, while benchmark
  auto-builds reject any other or source-modified checkout.
- Synchronized supported v26.7.28 behavior for `streamSettings.method`, XHTTP
  `sessionID*` names and `maxConnections=3` explicit-settings default, DNS TTLs
  above 300 seconds, DNS-outbound `qType`/`Return`/`rCode`, and fail-closed
  plaintext VLESS servers. The DNS default for non-A/AAAA queries is now an
  empty NOERROR response; legacy `qtype` and `Reject` remain warned aliases,
  with `Reject` preserving REFUSED unless an explicit `rCode` overrides it.
  VLESS without TLS/REALITY is now limited to Xray's exact
  private/reserved/test IP and private/test/dotless-domain exemption set.
  This is intentionally stricter than Xray v26.7.28 for legacy `vnext` input:
  upstream applies the guard only to its simplified top-level settings, while
  xray-rust applies it to the legacy shape it supports.
  TLS now rejects canonical `allowInsecure: true` and supports Xray's
  comma-separated full-DER `pinnedPeerCertSha256` model. Exact leaf pins
  short-circuit PKI/name checks; presented CA pins retain chain, time, and
  destination-derived DNS/IP name verification. Comma-separated
  `verifyPeerCertByName` now trims and ORs DNS/IP SAN names against ordinary
  roots or a pinned CA without changing SNI; leaf pins retain their upstream
  short-circuit. Unsupported `fromMitm`, ECH, custom trust stores, and removed
  pin forms remain fail-closed.
  XHTTP now generates target-compatible custom session IDs for all nine
  predefined tables and literal ASCII alphabets, preserving exact/half-open
  length semantics, per-flow freshness, placement keys, the UUID fallback, and
  Xray's conditional trailing-slash behavior for path metadata.
- Added release-candidate-only blocking interoperability and bounded libFuzzer
  gates, plus idempotent source-only GitHub prerelease publication. The RC path
  does not publish a crate or invoke any package registry.

## 0.4.0 - 2026-08-27

- Added Apple VLESS share-link import for `xhttp`/`splithttp` with plaintext,
  TLS, or REALITY transport security, including bounded single- or
  double-percent-decoded `extra` JSON. TLS/REALITY fields are preserved and
  unsupported non-empty certificate-pin/ECH parameters fail closed. XHTTP
  profiles never acquire a raw-only Vision flow from the Apple profile
  migration helpers. The core now applies Xray's one-level `extra` replacement
  rule for the modeled v26.5.9 XHTTP surface, preserving outer `host`, `path`,
  and `mode`. Removed `scMaxConcurrentPosts` values remain import-compatible
  but are explicitly ignored rather than being misread as
  `scMaxBufferedPosts`.
- Reduced plaintext H1 XHTTP packet-up memory pressure: body buffers now grow
  in Xray-sized 8 KiB steps only while data is available, so a 500000-byte
  `scMaxEachPostBytes` ceiling is not pinned by every active flow. Body-mode
  POSTs also reuse the actual allocation instead of cloning every payload;
  H2/H3 behavior is unchanged. Added an exact-profile RSS harness with
  held-flow, 16 KiB control, settle, and ACK-gated rollover phases.
- Updated `h2` to 0.4.16 for its upstream RustSec fix and refreshed the
  transitive `chacha20` lock entry to 0.10.2 after 0.10.1 was yanked.

## 0.3.2 - 2026-08-16

- Preserved an omitted VLESS `flow` when importing Apple share links instead
  of silently enabling `xtls-rprx-vision`. This matches the link semantics and
  prevents an early EOF when the server-side client is configured without a
  flow. Explicit Vision and Vision UDP/443 values remain supported.

## 0.3.1 - 2026-08-16

- Updated the REALITY client version advertised in the authenticated handshake
  from `1.8.0` to the implemented Xray-core compatibility baseline `26.7.28`.
  This prevents current Xray-core servers from rejecting xray-rust under the
  default `minClientVer` of `26.3.27`.
- Synchronized the uTLS fingerprint namespace and `ModernFingerprints` pool
  with Xray-core v26.7.28. The explicit `hellochrome_133`,
  `hellofirefox_148`, and `hellosafari_26_3` names are accepted again, while
  `random` now draws from the current eleven-profile pool. Older profiles that
  moved out of that pool remain available by explicit name. All supported
  REALITY-capable shapes match the Go uTLS oracle, and all eleven modern
  profiles complete VLESS + REALITY + Vision interoperability against
  Xray-core v26.7.28.
- Added optional Android `XrayCore.create(fileLoggingDirectory = ...)` support
  for bounded, app-controlled diagnostic exports. File logging remains off
  unless the host supplies an existing private directory.

## 0.3.0 - 2026-08-10

- Fixed the fd-backed TUN pump giving up permanently on a single transient I/O
  error. Both the read and the write loop used to break on anything that was
  not `EINTR`, and nothing supervises those tasks, so one `ENOBUFS` or
  `ENETDOWN` — ordinary conditions while a phone moves between Wi-Fi and
  cellular — stopped all packet flow for good while the tunnel went on
  reporting itself connected. Errors are now classified: an interrupted
  syscall is reissued for free, a packet that cannot be encoded is dropped
  without consuming the retry budget, a genuinely transient failure backs off
  and retries, and only a closed descriptor ends the loop.
- Added `tunFdReadLoopExits`, `tunFdWriteLoopExits` and
  `tunFdTransientIoErrors`, surfaced through the FFI, the periodic debug log
  and the Swift adapter. A pump that gives up is no longer silent: a non-zero
  exit counter means the tunnel has stopped moving packets while still
  reporting connected, and transient errors growing without an exit means the
  descriptor is unhealthy but recovering. The packet-I/O log line now also
  records which utun descriptor and interface the pump bound to.
- Apple utun discovery now identifies the interface by its kernel control id
  rather than by an interface-name prefix. Option 2 on `SYSPROTO_CONTROL` is
  defined per control, and an ordinary `AF_UNIX` socket answers it with four
  unrelated bytes instead of failing — so a successful lookup never implied
  "this is a utun". This is the same technique WireGuard adopted after
  73 minutes with the prefix version, and the one sing-box and Tun2SocksKit
  use today. It still returns the first match; proving the interface belongs
  to this provider needs `virtualInterface`, which is iOS 18 and later.
- `XrayCoreError` now carries its status code and message through the NSError
  bridge. It conformed only to `Error`, so Swift bridged it using the type
  name and case index alone and a real engine failure reached the user as
  "The operation couldn't be completed. (XrayMobileAdapter.XrayCoreError
  error 0.)", discarding the one thing that said what went wrong.
- Imported VLESS configs now enable `http`, `tls` and `quic` sniffing and pin
  `dns.queryStrategy` to `UseIPv4`, and a DNS mode switch no longer discards
  that pin. Sniffing is the only way a flow recovers its domain when the
  fake-IP mapping is gone — after a tunnel restart the table is empty while
  clients still hold cached fake IPs, and without it those connections are
  dialled literally as unroutable `198.19.x.y`. Existing profiles keep the
  config they were imported with; re-import the share link to pick this up.
- The Apple full tunnel continues to install both IPv4 and IPv6 default
  routes. An earlier implementation of this work removed `::/0` because the
  fake-IP pool is IPv4-only, but that made IPv6 literals and AAAA destinations
  bypass the VPN. The Rust TUN data path supports literal IPv6 TCP/UDP, so the
  privacy-preserving default is to capture it; only resolved outer proxy
  endpoints receive narrow `/128` bootstrap exclusions.
- Added the WebSocket and HTTPUpgrade stream transports for VLESS outbounds.
  `streamSettings.network` now accepts `ws`/`websocket` and `httpupgrade`
  alongside `tcp`/`raw`, with `wsSettings` and `httpupgradeSettings` carrying
  `path`, `host`, `headers` and — for WebSocket — `heartbeatPeriod`. Both
  transports send Xray's browser-masquerade header block and serialize the
  request the way Go writes an `http.Request`, and both are verified against a
  live xray-core rather than against a reading of it.
  `?ed=N` in the path means different things on the two despite the shared
  spelling: on WebSocket it is an early-data budget carried in
  `Sec-WebSocket-Protocol`; HTTPUpgrade retains the spelling for config
  compatibility but waits for the `101` because sending payload before it can
  strand bytes in Xray's inbound buffered reader. `docs/config-compatibility.md`
  has the full surface, including the
  header-casing split between the two and the one place the masqueraded
  browser version diverges from Xray's.
- Rejected two transport pairings that would otherwise build here and then
  fail on the wire: REALITY with `ws` or `httpupgrade`, which xray-core
  answers with "REALITY only supports RAW, XHTTP and gRPC for now", and
  `xtls-rprx-vision` with anything but raw under `tls` or `reality`, because
  Vision splices itself into the security connection's internals and breaks
  when a transport wraps it. The second is narrower than xray-core's own rule
  rather than a copy of it — xray-core asks whether the transport dialer
  handed the security conn straight back, which mKCP does and raw with a
  `tcpSettings.header.type` authenticator does not, and it skips the question
  entirely when VLESS `encryption` is on. Neither case arises here: no
  transport we implement hands the conn back except raw, and
  `encryption: "none"` is the only value we accept.
  `docs/config-compatibility.md` has the full account. A `freedom` outbound
  also refuses ws and httpupgrade; they are implemented for VLESS only, and
  refusing beats silently dialling plain TCP.
- TLS connections are now shaped to look like a browser.
  `tlsSettings.fingerprint` selects a uTLS ClientHello shape from the same 58
  names xray-core accepts, and an absent or empty value means `chrome` rather
  than no shaping, which is the default xray-core itself applies.
  `fingerprint: "unsafe"` is the opt-out and sends the TLS stack's own hello.
  Fourteen of the 58 names are TLS-1.2-era: eleven of those are shaped but not
  byte-exact, because rustls emits a `supported_versions` extension uTLS does
  not and nothing in the shaping API can suppress it, and the other three — the
  `hello360_7_5` aliases refused below — build no ClientHello at all.
  `docs/config-compatibility.md` carries the detail and the full name list.
- Shaped connections handshake on the aws-lc-rs crypto backend rather than
  ring, and offer the post-quantum key share their profile plans:
  X25519MLKEM768 for `chrome`, none at all for a TLS-1.2-era profile. Matching
  a current browser requires both, and both are real changes — in what goes on
  the wire, and in which backend performs the handshake.
  `fingerprint: "unsafe"` keeps the previous ring path.
- Session resumption is disabled on shaped connections. A resumed handshake
  emits a second ClientHello carrying `pre_shared_key`, an extension the
  fingerprint never described, so shaping and resumption cannot both hold.
  Every reconnect is now a full handshake where it previously resumed, which
  costs a round trip and a signature verification on links that reconnect
  often. `fingerprint: "unsafe"` keeps resumption.
- `fingerprint: "random"` and `fingerprint: "randomized"` now draw a real
  fingerprint per process instead of both resolving to one frozen shape. Every
  install used to send the same ClientHello for these names — the opposite of
  what someone selecting them is asking for. Each name now draws independently
  from xray-core's `ModernFingerprints` on first use and keeps that draw for
  the life of the process, so two installs differ while one install never
  changes between connections. `randomized` diverges from xray-core in kind:
  xray-core hands it to uTLS's randomized-spec generator, which has no port
  here, so a real browser shape is drawn rather than a novel one synthesized.
  `randomizednoalpn` stays pinned to a fixed shape, because every modern
  fingerprint carries the ALPN extension that name exists to suppress.
- Removed three `fingerprint` names that xray-core does not accept:
  `hellochrome_133`, `hellofirefox_148` and `hellosafari_26_3`. They are real
  uTLS `ClientHelloID`s but appear in none of the three maps Xray's
  `GetFingerprint` consults, so a profile naming one parsed here and then
  failed on xray-core with `unknown "fingerprint"`. The accepted set is now
  exactly Xray's, and `tlsSettings.fingerprint` / `realitySettings.fingerprint`
  reject the three at parse time. Replace them with `chrome`, `firefox` and
  `safari` respectively — those are the shapes the dropped names already
  resolved to, byte for byte, so the ClientHello on the wire does not change.
  The Apple `XrayRealityFingerprintMode` constants and picker entries are gone
  with them; a stored profile still naming one reads back as no selection.
- Added the gRPC stream transport for VLESS outbounds.
  `streamSettings.network` now accepts `grpc`, with `grpcSettings` carrying
  Xray's own eight keys — `serviceName`, `multiMode`, `authority`,
  `user_agent`, `idle_timeout`, `health_check_timeout`,
  `permit_without_stream` and `initial_windows_size`. Unlike the other stream
  transports it does not wrap one socket: every flow to one server becomes
  another stream on one shared HTTP/2 connection, opened by the first flow and
  held between them, with grpc-go's keepalive gate and its dormancy on a
  connection carrying no call. The reusable connection is also retired after
  grpc-go's independent 30-minute no-RPC timeout, which Xray leaves at its
  default; active streams are not interrupted, and the next flow performs a
  fresh bounded dial. A camelCase `idleTimeout` is rejected rather than
  accepted, because Go matches on the struct tag and drops that key in silence,
  leaving a profile that looks configured and dials with no keepalive.
  The `:path`, the `Hunk` and `MultiHunk` framing and the first HEADERS block
  are pinned against a live grpc-go v1.81.0 oracle, and five ignored scenarios
  carry real traffic through an xray-core gRPC inbound over plaintext, TLS and
  REALITY. One thing is deliberately not grpc-go's: the connection-level
  receive window is opened to 16 MiB, because `h2` pins it at 65535 whatever
  SETTINGS say and releases it only from the application's read path, so on a
  connection every flow of an outbound shares, one flow whose consumer stops
  reading would hold the window all the others need. It costs one extra
  `WINDOW_UPDATE` in the opening burst. `docs/config-compatibility.md` has the
  full surface, `docs/status.md` the four differences that remain.
- REALITY is now accepted with `network: "grpc"`, where it was refused. The
  guard allowed only the raw transport while its own error message read
  "REALITY only supports RAW, XHTTP and gRPC for now" — the message quoted
  Xray's rule correctly and the condition did not. REALITY over gRPC is the
  deployment gRPC mostly exists for, so this is the pairing that unblocks it.
  `xtls-rprx-vision` is still refused alongside it, and xray-core refuses it
  over gRPC too: the gRPC dialer returns a `Hunk` wrapper rather than the
  security conn, so the connection under Vision is neither a `*tls.Conn`, a
  `*tls.UConn` nor a `*reality.UConn`. That is a fact about the dialer, not
  about the network name — mKCP hands its TLS conn straight back and carries
  Vision fine — and it holds only because VLESS `encryption` is off, which is
  the sole setting we accept. `docs/config-compatibility.md` has the full
  account.
- Added two direct dependencies for the gRPC transport: `h2` 0.4.15 for the
  HTTP/2 client it speaks over, and `http` 1 for the request and header types
  that client takes — `grpcSettings.authority` is parsed and stored as an
  `http::uri::Authority`, so the type is part of the transport's public
  surface. Six more crates land in the lockfile behind them — `atomic-waker`,
  `fnv`, `futures-sink`, `tokio-util`, `tracing` and `tracing-core` — and
  `cargo deny check advisories bans licenses sources` is clean against the
  existing allow-list.
- Added the XHTTP stream transport for VLESS outbounds. `network` accepts
  `xhttp` and the legacy `splithttp` alias, with Xray-compatible priority
  between their settings blocks and all three modes: `packet-up`, `stream-up`,
  and `stream-one`. The runtime normalizes the complete modeled padding,
  metadata-placement, packet-pacing, and xmux surface instead of accepting
  those settings and ignoring them. HTTP/1.1 has safe packet-connection reuse;
  HTTP/2 uses capacity-aware pooled connections; the xmux manager persists
  across every cached selection of one outbound. H1/H2 mode, wire, lifecycle,
  and live Xray-core interoperability matrices cover the production paths.
- Replaced the public one-shot `select_*` helpers with methods on a long-lived
  `OutboundRouter`. Callers embedding `xray-core-rs` must construct one
  `Arc<OutboundRouter>` from their immutable `Arc<CoreConfig>`, retain it for
  that configuration's lifetime, and call its selector methods. Reconstructing
  a router for each selection discards the gRPC and XHTTP connection pools, so
  compatibility wrappers would preserve source syntax while silently losing
  the lifecycle behavior this release adds.
- Added phase-one XHTTP over HTTP/3. Exact TLS `alpn: ["h3"]` selects a
  protected UDP/QUIC v1 path with no TCP downgrade, stock TLS 1.3, Happy
  Eyeballs candidate racing, reusable H3 connections, and all three XHTTP
  modes. Its declared limits fail closed: receive windows are static in Quinn
  rather than quic-go-adaptive, standard BBR is a Quinn approximation, and
  the pool conservatively permits one active HTTP request per QUIC connection.
  QUIC v2, unequal adaptive maxima, non-standard BBR profiles, Brutal,
  UDP-hop, and debug side effects are not accepted. Hermetic H3 wire and
  lifecycle tests plus live Xray-core `packet-up`, `stream-up`, and
  `stream-one` cases pass. The generic stream benchmark now exposes
  `xhttp-h3` with an exact `h3`/UDP fixture and default QUIC parameters. Actual
  release and controlled-RTT/loss runs remain required before any H3
  performance-parity claim.
- Patched the vendored `h3-quinn` 0.0.10 receive adapter so cancelling a
  pending response read can send `STOP_SENDING(H3_REQUEST_CANCELLED)` instead
  of panicking on an empty internal stream slot. Focused regressions cover the
  pending-poll edge, the exact cancellation code, and reuse of the same QUIC
  connection for a later request.
- Matched Go's XHTTP automatic gzip behavior across H1, H2, and H3, including
  Range/HEAD and explicit-header suppression, H1/H2 versus H3 casing rules,
  raw H1 packet bypass, concatenated gzip members, and stream-local malformed
  response errors that do not retire a healthy multiplexed connection.
- Fixed nine uTLS profiles — eleven of the accepted `fingerprint` names — being
  unable to complete a plain-TLS handshake at all. Their parrot sends a
  TLS-1.2-era ClientHello with no `supported_versions` extension while the
  rustls config still offered TLS 1.3, so a 1.3-capable server answered with
  TLS 1.2, its ServerHello carried the RFC 8446 §4.1.3 downgrade sentinel, and
  rustls read that as an attack. The config is now capped at the version the
  hello actually claims, as uTLS caps its own, and the 32-byte legacy session
  id rustls drops along with TLS 1.3 is redrawn per connection so the hello
  does not change shape in exchange. Nothing had exercised these before
  `security: "tls"` started shaping: REALITY has always refused them for
  lacking an X25519 key share, which is the same fact from the other side.
- `fingerprint: "hello360_7_5"`, and its aliases `360` and `hello360_auto`, are
  now refused with a reason instead of dialling. All twenty of that profile's
  cipher suites are CBC, RC4 or 3DES and this client implements none of them,
  so whichever the server picked was one it could not speak and the connection
  died at ServerHello under an error naming neither the fingerprint nor the
  cause. The refusal happens where the rustls config is built, so the TCP
  socket is still opened but no ClientHello is sent. xray-core completes that
  handshake, because Go still ships the legacy suites; this is our limit rather
  than the parrot's, and saying so beats discovering it a round trip later.

## 0.2.0 - 2026-08-05

- Fixed file logging initialization inside the iOS Network Extension sandbox.
  `xray_core_new` failed with "Operation not permitted" because runtime log
  files were opened by walking every ancestor directory with read access,
  which the sandbox denies outside the app-group container. Apple platforms
  now resolve the log path with a single `O_NOFOLLOW_ANY` open, which keeps
  rejecting symlinks in any path component; other unix targets keep the
  hardened directory walk.

## 0.1.1 - 2026-08-03

- Added Packet Tunnel support for loading verified geodata generations from a
  shared App Group directory. Explicit App Group generations are searched
  exclusively so missing assets fail closed instead of mixing with bundle or
  process-default geodata; configurations without App Group settings preserve
  the existing bundle-resource fallback.
- Stabilized the Packet Tunnel provider's cross-process `NSError` domain and
  codes, and expanded tests for App Group path validation, start configuration,
  DNS pinning, and runtime geodata loading. Swift clients with an exhaustive
  switch over `XrayPacketTunnelProviderError` must handle the new
  `invalidGeodataConfiguration` case.
- Documented an atomic, immutable-generation workflow for host-managed geodata.

## 0.1.0 - 2026-08-02

- Added a sample-only `Default DNS` preset (`FakeDNS` with routed
  `tcp://1.1.1.1`) and shared mobile DNS preflight so invalid full-tunnel DNS
  topologies are rejected by the host before Network Extension startup. The
  Apple client now waits for a real connected or failed status and surfaces the
  provider's last disconnect error instead of treating submission of the start
  request as success.
- Added non-destructive DNS test controls to the Apple reference client. A
  saved profile can switch at reconnect between its original JSON, the fixed
  sample preset, FakeDNS, and the local DNS proxy over classic, routed TCP, or
  provider-local TCP;
  an optional FakeDNS upstream also enables restored-domain resolution when
  routing selects Freedom. Manual modes keep the trusted upstream
  user-supplied; generated effective DNS settings retain `dns.hosts` bootstrap
  pins and the routed-DNS tag, and never overwrite the source profile JSON.
- Kept the DNS outbound TCP handler out of ordinary SOCKS connection futures,
  allocating its type-erased future only after a DNS route is selected. This
  removes 1.2 KiB from both enclosing async states and brought the same-machine
  1000-flow RSS median from 20.52 MiB back to 18.27 MiB without detached tasks
  or changed cancellation behavior.
- Extended the process benchmark harness with a strict, repeatable DNS matrix
  covering FakeDNS and proxied UDP/TCP clients, plus latency, query-rate,
  CPU-per-1000-query, and RSS charts. Raw artifacts now carry run IDs, DNS
  transport, Git/worktree provenance, canonical CLI arguments, and SHA-256
  hashes for the measured binaries; incompatible series fail chart generation.
- Added global Xray-compatible `dns.queryStrategy` for `UseIP`, `UseIPv4`, and
  `UseIPv6`, including common Xray aliases. The policy controls configured DNS
  wire queries, destination static host arrays, and destination fallback
  results; wrong-family static mappings remain terminal NODATA. Bootstrap
  resolution keeps all pinned/system candidates for IPv6-only and DNS64/NAT64
  carrier reachability. IPv4-mapped AAAA answers are discarded before server
  failover, while mapped socket candidates otherwise follow their IPv4
  semantics. IPv4 fake-IP returns NODATA without allocating a mapping under
  `UseIPv6`; the byte-transparent raw TUN DNS proxy preserves client qtypes.
  `UseSystem` fails config validation until route capability can be supplied by
  the embedding platform instead of being approximated.
- Added Xray-compatible `streamSettings.sockopt.happyEyeballs` for Freedom and
  VLESS TCP carriers. The modeled defaults are IPv4 preference,
  `interleave: 1`, `tryDelayMs: 0`, and `maxConcurrentTry: 4`; zero delay or
  zero concurrency is the feature-off sentinel, while `interleave: 0`
  exhausts the preferred address family before trying the alternate family.
  When enabled with multiple candidates, the scheduler races raw TCP only,
  accelerates the next candidate after a fast failure, bounds concurrency, and
  performs exactly one TLS or REALITY handshake on the winning socket. Losing
  and caller-cancelled attempts are dropped in place without detached tasks;
  socket protection is applied independently to every launched candidate.
- Added ordered multi-address DNS results with TTL metadata. Configured A and
  AAAA lookups run concurrently, preserve every usable candidate, apply the
  Xray-core 300-second answer/cache cap and 10-second static-host TTL, and
  expose remaining TTL on cache hits. `IPIfNonMatch` now evaluates rules in
  configuration order against all resolved IPs instead of only the first.
  Xray-compatible `dns.hosts` values may now be a single IP/domain string or a
  nonempty ordered array of IP strings; every array candidate is retained. Bare
  host keys now use Xray's exact/full default instead of routing keyword
  semantics, including during Android and Apple bootstrap.
  Authoritative NXDOMAIN/NODATA advances to later configured upstreams before
  becoming terminal, while the bounded cancellation-safe cache remains
  mobile-friendly.
- Added a reusable DNS query-transport boundary: query construction and strict
  A/AAAA/CNAME parsing stay in `xray-transport`, while TUN, SOCKS, HTTP, and
  startup probes can send configured DNS through routed Freedom or VLESS.
  Valid truncated UDP answers retry over TCP, results are bounded/cached with
  cancellation-safe typed single-flight plus one-at-a-time LRU eviction, and
  fake-IP-restored Freedom targets resolve through `dns.servers` even in mobile
  `StaticOnly` mode. Exact `full:` hosts mappings win over broader rules, and
  managed/cache identities are canonicalized across case and a terminal dot.
- Made configured-DNS failure semantics explicit: NXDOMAIN and A+AAAA NODATA
  are terminal, SERVFAIL/invalid/transport failures advance to the next
  upstream, one server shares an A/AAAA timeout budget, and the total lookup
  deadline now includes any operating-system fallback.
- Extended routed DNS to preserve domain upstreams. VLESS sends them for remote
  resolution; Freedom uses the separate bootstrap resolver and fails over when
  `StaticOnly` has no terminal `dns.hosts` IP or IP array. After domain rules
  miss, DNS-upstream `IPIfNonMatch` routing uses only that bootstrap role for
  its IP pass and cannot recurse through destination DNS. Like Xray-core, a failed
  `IPIfNonMatch` lookup continues to the default outbound instead of aborting
  routing, so a default VLESS can still resolve the domain remotely.
- Added fake-IP DNS-over-TCP and Xray-style bounded LRU mappings through
  `dns.fakeIp.poolSize`; reserved `198.18.0.1` for the local DNS anchor and
  `198.18.0.2` for the TUN client address. A pool covering its complete address
  range now reuses the evicted LRU address without scanning the exhausted range.
- Fixed Apple full-tunnel DNS without selecting a public resolver: fake-IP and
  any valid IP/domain `dns.servers` profile advertise the tunnel-local
  `198.18.0.1` interception anchor, while explicit host IPv4/IPv6 DNS overrides
  remain supported. Before applying the anchor, the provider resolves domain
  VLESS servers and domain DNS upstreams, installs every ordered IPv4/IPv6
  bootstrap result as canonical exact `dns.hosts` arrays, preserves VLESS
  addresses exactly, bounds alias traversal, accepts DNS64 results, and fails
  startup on cycles or unresolved bootstrap. The asynchronous preflight has
  one shared five-second deadline, exactly-once lifecycle completion, and a
  process-wide gated resolver worker so a non-interruptible `getaddrinfo`
  cannot block the provider callback or create an unbounded queue. Before the
  core starts, Apple installs an excluded `/32` or `/128` route for every VLESS
  carrier candidate alongside both default tunnel routes. Pinned DNS-upstream
  addresses remain routed through the tunnel instead of gaining a global
  privacy-bypassing exclusion, and tunnel-owned addresses fail closed instead
  of becoming route-poisoning carrier exclusions. IPv4-mapped IPv6 carriers
  are normalized consistently before both Rust dialing and Apple route setup.
  Missing or conflicting host DNS modes still fail closed.
  Fake-IP DNS returns NODATA for supported non-A queries sent to the anchor.
- Made fake-only mobile profiles topology-aware without choosing a public DNS:
  default VLESS plus IP-only Freedom rules remains valid because VLESS resolves
  restored domains remotely, while default or domain-routed Freedom requires
  explicit `dns.servers` and is rejected before the VPN interface is installed.
  The Apple direct reference profile no longer auto-enables fake-IP and instead
  requires a host-selected DNS override.
- Made Android reference VPN startup asynchronous and cancellation-safe. DNS
  bootstrap lookups share one five-second deadline; start and blocking resolver
  workers use bounded zero-queue pools, stop never waits for a pending lookup,
  token-scoped state transitions prevent late publication or rapid-restart
  races, and every ordered A/AAAA bootstrap result is pinned in a `dns.hosts`
  array. Each Happy Eyeballs TCP candidate is protected separately through
  `VpnService.protect(fd)` before connect.
- Added a bounded tunnel-local UDP/TCP DNS proxy for IP/domain `dns.servers`.
  Upstream attempts follow configured order and use the existing outbound
  router (including VLESS and protected Freedom sockets); failures return
  SERVFAIL or reset TCP without silently selecting a public resolver. UDP
  ignores unrelated replies from the selected peer until the attempt deadline;
  raw and fake DNS/TCP share a dedicated flow limit, and raw TCP inactivity is
  bounded by `connIdle` with a five-second ceiling.
- Fixed a Vision direct-mode read switching the whole connection to cleartext:
  the TLS session now survives a direct read so the uplink stays encrypted
  until Vision switches that direction too, matching Xray-core's per-direction
  reader/writer swap.
- Added the first interop coverage that carries a real TLS session through
  REALITY Vision, exercising the direct-mode path that echo workloads skip.
- Hardened FFI, DNS, logging, geodata, and mobile lifecycle boundaries.
- Added bounded routing and TUN data paths.
- Added reproducible mobile artifact and supply-chain checks.
- Added open-source licensing, security, contribution, and release
  documentation.
- Recorded the pre-release live-profile disclosure in `SECURITY.md` and made
  the history secret scan attribute hits to individual commits.
