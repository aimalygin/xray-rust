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
| `routing` | `field` rules only |
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

`freedom` and `vless` are supported. VLESS accepts one `vnext` server with one
or more UUID users, but the runtime currently selects the first user.
`encryption: "none"`, optional `level`, and these flow values are accepted:

- empty/no flow;
- `xtls-rprx-vision`;
- `xtls-rprx-vision-udp443`.

`streamSettings.network` is currently `tcp` only. Security values are:

- `none`;
- `tls`, with `serverName` and `allowInsecure` (certificate verification is
  enabled by default);
- `reality`, with `serverName`, a supported `fingerprint`, base64url
  `publicKey`, hexadecimal `shortId`, optional `spiderX`, and optional
  `mldsa65Verify`.

TLS fingerprint shaping and non-empty custom ALPN lists are not supported.
`tcpSettings.header.type` may be absent, empty, or `none`. WebSocket, HTTP/2,
gRPC, QUIC, KCP, and other stream transports are not supported. Outbound mux,
`proxySettings`, `sendThrough`, multiple VLESS servers, and outbound chaining
are rejected.

VLESS UDP is carried over the supported TCP transport using VLESS datagram or
XUDP framing; it does not make `streamSettings.network: "udp"` valid.

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
- selectors: `inboundTag`, `domain`/`domains`, and `ip`;
- destination: `outboundTag`.

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

Balancers and non-`field` rules are unsupported. Rules are evaluated in order;
if none matches, the first outbound tag is used as the default.

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

`dns.servers` accepts at most eight string or object entries. The existing
string shorthand accepts IP addresses, socket addresses, or domain names with
an optional nonzero port. The Xray object subset requires `address`, supports
`port` (`0` or omission means `53`), `domains`, `skipFallback`, per-server
`queryStrategy`, and `finalQuery`. `domains` may be an array or one
comma-separated string and supports bare keyword, `keyword:`, `domain:`,
`full:`, `regexp:`, `dotless:`, `geosite:`, `ext:`, and `ext-domain:` rules.
Top-level `disableFallback` and `disableFallbackIfMatch` are also supported.
Special `localhost`/`fakedns` clients, URL transports, `clientIp`,
`expectedIPs`/`expectIPs`/`unexpectedIPs`, tags, per-server timeouts,
cache/stale controls, and parallel queries are rejected until their runtime
semantics exist; they are not silently approximated as classic UDP.

Managed selection follows Xray: every matching object entry is tried in
configuration order, followed by unmatched entries in configuration order.
`skipFallback` removes an entry only from the latter phase;
`disableFallback` always removes that phase and `disableFallbackIfMatch`
removes it after any match. `finalQuery` truncates the plan where encountered.
If these rules otherwise produce an empty plan, the first configured entry is
still tried. Duplicate endpoints in separate policy objects remain separate
managed clients. A per-server family policy intersects the global policy and
cannot widen it.

The core consumes these policy matchers once during construction. Exact rules
are indexed by hash and suffix rules by reversed domain labels, following
Xray-core's Compact mobile matcher trade-off; keyword and regex rules remain
linear. The resulting immutable set is shared across SOCKS, HTTP, TUN, and
startup-probe routing contexts. Policy domains are released from the retained
runtime config after compilation, while endpoints and flags remain available
to the raw DNS proxy planner.

The TUN-local `198.18.0.1:53` anchor and
`198.18.0.2:53` client address cannot be configured as upstreams, including as
IPv4-mapped IPv6 literals. With `UseIP`, the resolver sends A and AAAA
concurrently and retains all usable answers in DNS order (A before AAAA);
single-family strategies send only their selected query. All modes validate
A/AAAA records plus CNAME chains in `xray-transport`; a CNAME-only follow stays
on the server that supplied the alias. If that continuation fails, the next
selected server is retried with the original name; after the plan is exhausted,
the alias is not sent to any other resolver. The delivery transport
is replaceable, so TUN resolution sends them through the outbound router
rather than duplicating the DNS parser. A valid UDP response with `TC=1`
retries over TCP to the same server. UDP transports ignore responses with an unrelated
transaction ID, opcode, name, type, or class until the attempt deadline.
Managed destination results use a bounded 256-entry LRU cache. Authoritative
answer TTLs are clamped to 1–300 seconds and the minimum TTL across the answer
chain controls expiry; static `dns.hosts` IPs use 10 seconds, while resolvers
without TTL metadata use the 300-second policy cap. Cache hits expose the
remaining TTL rather than extending it. ASCII case is canonicalized, and
overflow evicts one least-recently-used entry rather than flushing the whole
cache. Concurrent misses for the same `(domain, port)` share one
cancellation-safe lookup and the same typed outcome instead of opening
duplicate routed DNS/VLESS sessions.

For managed runtimes, including TUN, SOCKS, HTTP, and startup probes, `System`
resolution is `dns.hosts` → routed `dns.servers`. When no `dns.servers` are
configured, unresolved names use the cached operating-system resolver. Authoritative
NXDOMAIN and A+AAAA NODATA advance to the next configured server, matching
Xray-core's ordered failover. If no later server succeeds, an authoritative
negative result is terminal and does not leak into the operating-system
fallback. SERVFAIL, malformed replies, and transport failures also move to the
next server. Exhausting a nonempty configured server plan is terminal and never
sends the original qname to the operating-system resolver. The five-second
resolution deadline includes configured-server endpoint bootstrap and the
no-server fallback.
A and AAAA run concurrently under the same wall-clock server budget when
`UseIP` is selected.
`StaticOnly` uses the same routed path and then fails closed; its separate
bootstrap resolver never uses `dns.servers` or the operating-system resolver.
Explicitly injected resolvers remain trusted integration dependencies and are
used as-is.
The two `disableFallback*` fields control Xray's fallback phase within the
configured name-server list. They are independent from endpoint bootstrap: in
`System` mode a domain-valued DNS upstream may still use the operating-system
resolver to find the upstream itself, but never to retry the original qname.

When fake-IP is disabled and at least one usable server is present, TUN clients
can use `198.18.0.1:53` as a local UDP/TCP DNS proxy. The proxy keeps
server order, removes duplicates, and sends each upstream attempt through the
normal outbound router, so Freedom sockets retain platform socket protection
and VLESS routes do not gain a hidden direct-DNS bypass. DNS sessions route on
their original IP/domain metadata. With `IPIfNonMatch`, domain rules run first;
only an unmatched domain upstream uses the separate bootstrap resolver for the
IP-rule pass, so destination DNS cannot recurse into itself. UDP requests have
bounded per-attempt and total timeouts; unrelated replies from the selected
peer are ignored, while invalid/unavailable upstreams return
SERVFAIL, and an oversized reply is converted to a truncated response so the
client can retry over TCP. TCP is a byte-transparent stream and supports
multiple length-prefixed DNS messages on one connection; failed opens are
reset. Raw and fake DNS/TCP share a dedicated limit of up to 32 flows. Raw
DNS/TCP idle time, including blocked bridge writes, is capped by the smaller of
the inbound `connIdle` policy and five seconds.
A raw-anchor query keeps the client's original question type and does not apply
global/per-server `queryStrategy`, `domains`, or fallback policy. Object entries
contribute only their endpoint to the raw declaration-order/deduplicated proxy
plan. This is the byte-transparent equivalent of Xray DNS outbound
`Direct`. Xray DNS outbound `Hijack` semantics (including its A/AAAA family
gate, DNS hosts/cache, and per-server policy) remain a separate unsupported
feature rather than a partial hybrid in the raw proxy.
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
10-second hosts TTL.
`dns.fakeIp` supports `enabled`, an IPv4 `ipv4Pool`, optional positive
`poolSize`, and `ttl` for the current TUN routing path. `poolSize` defaults to
the smaller of 32768 and the usable pool capacity. The bounded mapping table
uses Xray-style LRU rollover: active mappings stay stable, and the least
recently used mapping is evicted when a new domain crosses `poolSize`.
`198.18.0.1` and `198.18.0.2` are always reserved for the DNS anchor and TUN
client address. Fake DNS synthesizes A records over UDP and length-prefixed TCP
for both the anchor and hard-coded port-53 destinations. With `UseIPv6`, its
IPv4-only pool returns NODATA for A without allocating a mapping. AAAA returns
NODATA on both paths; other valid single-question types return NODATA at the
anchor and over TCP, while non-anchor UDP continues through the normal UDP
path. Fake-IP takes precedence over raw proxying. When a later TCP/UDP flow targets a fake
address, the original domain is restored before routing. VLESS carries that
domain for remote resolution; Freedom resolves it through the managed routed
resolver, including in mobile `StaticOnly` mode. DNS-over-HTTPS/TLS, client-IP,
per-server rule objects, negative/stale caching, and the broader Xray DNS
feature set are not implemented. The public resolver result carries every
candidate and TTL metadata. An explicitly enabled `sockopt.happyEyeballs`
policy consumes those candidates through the bounded raw-TCP race described
above; its Xray-compatible zero-delay default leaves the race disabled.

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
