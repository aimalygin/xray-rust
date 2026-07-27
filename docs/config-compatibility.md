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
| `dns` | Hosts, string servers, and `fakeIp` subset |
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

`dns.servers` accepts IP addresses, socket addresses, or domain names with an
optional port. The resolver sends UDP A/AAAA queries, understands CNAME
responses, falls back to the system resolver, and caches results.

`dns.hosts` maps supported domain matchers to an IP or alias domain.
`dns.fakeIp` supports `enabled`, an IPv4 `ipv4Pool`, and `ttl` for the current
TUN routing path. DNS-over-HTTPS/TLS, client-IP, per-server rule objects, and
the broader Xray DNS feature set are not implemented.

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
