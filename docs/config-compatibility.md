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

`freedom`, `vless`, and `dns` are supported. DNS outbound settings are described
below. VLESS accepts one `vnext` server with one or more UUID users, but the
runtime currently selects the first user.
`encryption: "none"`, optional `level`, and these flow values are accepted:

- empty/no flow;
- `xtls-rprx-vision`;
- `xtls-rprx-vision-udp443`.

`streamSettings.network` is currently the TCP transport only, spelled either
`tcp` or `raw` (Xray renamed it to `raw`; both names are accepted and mean the
same thing). Security values are:

- `none`;
- `tls`, with `serverName`, `allowInsecure` (certificate verification is
  enabled by default), `fingerprint`, and `alpn`, described below;
- `reality`, with `serverName`, a supported `fingerprint`, base64url
  `publicKey`, hexadecimal `shortId`, optional `spiderX`, and optional
  `mldsa65Verify`.

`tcpSettings.header.type` — equally `rawSettings.header.type` — may be absent,
empty, or `none`. WebSocket, HTTP/2,
gRPC, QUIC, KCP, and other stream transports are not supported. Outbound mux,
`proxySettings`, `sendThrough`, multiple VLESS servers, and outbound chaining
are rejected.

VLESS UDP is carried over the supported TCP transport using VLESS datagram or
XUDP framing; it does not make `streamSettings.network: "udp"` valid.

### TLS ClientHello shaping

`security: "tls"` sends a uTLS-shaped ClientHello, as Xray-core does on every
TLS connection. `tlsSettings.fingerprint` selects the shape from the same 58
names Xray accepts. An absent or empty value means `chrome`, matching Xray's
`GetFingerprint("")`, so shaping is the default rather than an opt-in; an
unknown name is rejected at parse time with a JSON path and the offending
value. Unlike `realitySettings.fingerprint`, no X25519 key share is required,
so the fourteen names REALITY rejects are usable here.

Those 58 are the union of the three maps Xray's `GetFingerprint` consults --
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

Fourteen of the 58 names are shaped but not byte-exact: the TLS-1.2-era
profiles, which are exactly the ones REALITY rejects. Their uTLS hello declares
no `supported_versions` extension, while the TLS stack emits that extension on
every ClientHello it builds — a TLS-1.2-only configuration included, where it
carries just `0x0303` — and nothing in the shaping API can suppress it. The
extension order is pinned so uTLS's own order survives as an exact prefix and
the one extra extension sits last. The remaining names declare the extension
themselves, so nothing is appended to their hellos.

An IP-literal `serverName` is supported. As in uTLS, the SNI extension is
elided and the rest of the shape shifts to match, rather than the handshake
failing.

#### What `random` and `randomized` resolve to

`fingerprint: "random"` matches Xray: one of the nineteen names in Xray's
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
shape before", nineteen buckets shared with the Xray population is the crowd we
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

`dns.servers` accepts at most eight string or object entries. String shorthand
accepts IP addresses, socket addresses, domain names with an optional nonzero
port, and `tcp://host[:port]` / `tcp+local://host[:port]`. TCP schemes are
case-insensitive, default to port `53`, support bracketed IPv6 literals, and
use TCP from the first query rather than as a truncation retry. `tcp://` enters
normal outbound routing; `tcp+local://` bypasses routing and opens a protected
direct socket. The accepted URI subset is deliberately authority-only:
userinfo, paths, queries, fragments, whitespace, scoped IPv6, and zero ports
fail closed. In an object entry, the port embedded in the TCP URI is
authoritative and the separate `port` field is ignored after validation,
matching Xray-core's effective behavior. The Xray object subset requires `address`, supports
`port` (`0` or omission means `53`), `domains`, `skipFallback`, per-server
`queryStrategy`, `finalQuery`, `tag`, and `timeoutMs`. `domains` may be an array or one
comma-separated string and supports bare keyword, `keyword:`, `domain:`,
`full:`, `regexp:`, `dotless:`, `geosite:`, `ext:`, and `ext-domain:` rules.
Top-level `disableFallback` and `disableFallbackIfMatch` are also supported.
Special `localhost`/`fakedns` clients, DoH/DoQ URL transports, `clientIp`,
cache/stale controls, and parallel queries are rejected until their
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
answer TTLs are clamped to 1–300 seconds and the minimum TTL across the answer
chain controls expiry; static `dns.hosts` IPs use 10 seconds, while resolvers
without TTL metadata use the 300-second policy cap. Cache hits expose the
remaining TTL rather than extending it. ASCII case is canonicalized, and
overflow evicts one least-recently-used entry rather than flushing the whole
cache. Concurrent misses for the same normalized
`(domain, port, queryStrategy)` share one cancellation-safe lookup and the same
typed outcome instead of opening duplicate routed DNS/VLESS sessions. One
managed destination cache and single-flight table is shared by every
SOCKS/HTTP listener, TUN consumer, and startup probe in a `Core` runtime; a
separate `Core` owns a separate cache.

For managed runtimes, including TUN, SOCKS, HTTP, and startup probes, `System`
resolution is `dns.hosts` → configured `dns.servers`: classic and `tcp://`
clients are routed, while `tcp+local://` clients intentionally dial directly.
When no `dns.servers` are
configured, unresolved names use the cached operating-system resolver. Authoritative
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
Explicitly injected fallback resolvers remain trusted integration dependencies;
their results are used as-is, while the no-server call is still bounded by the
same five-second fallback deadline.
The two `disableFallback*` fields control Xray's fallback phase within the
configured name-server list. They are independent from endpoint bootstrap: in
`System` mode a domain-valued DNS upstream may still use the operating-system
resolver to find the upstream itself, but never to retry the original qname.

When fake-IP is disabled and at least one usable server is present, TUN clients
can use `198.18.0.1:53` as a local UDP/TCP DNS proxy. The proxy keeps
server order and removes duplicates by endpoint, effective tag, and transport.
Classic and `tcp://` attempts enter the normal outbound router, so Freedom
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
        "action": "direct",
        "qtype": "1,28,64-65",
        "domain": ["domain:example.com", "geosite:private"]
      }
    ]
  }
}
```

The compatibility aliases `network`/`address`/`port` override their
`rewrite*` counterparts exactly as in Xray; a zero port preserves the original
port. `action` is case-insensitive and must be Direct, Drop, Reject, or Hijack.
QTYPE accepts a number or comma/range string over `0..=65535`; ranges stay
compact and are normalized instead of being eagerly expanded. Domain accepts a
string or array and supports the same `keyword`, `domain`, `full`, `regexp`,
`dotless`, `geosite`, and `ext` grammar as other DNS matchers. Bare values are
keywords. Rules are ordered, selectors inside a rule are ANDed, and empty
QTYPE/domain selectors are wildcards. A miss Hijacks A/AAAA and Rejects other
types. Explicit Hijack of a non-address type also Rejects.

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

Drop sends no response. Reject synthesizes REFUSED while preserving the query
ID and question. Hijack uses the shared destination resolver or the per-Core
FakeIP mapper when configured and remains family-specific. A mapping allocated
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
`StaticOnly` mode. Managed `dns.servers`
DoH/DoT/DoQ transports, `clientIp`, negative/stale caching, and the broader
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
