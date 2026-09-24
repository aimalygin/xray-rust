# Xray-core v26.9.8 source delta and migration audit

Status: source delta reviewed on 2026-09-08 (UTC); migration and runtime
verification have not been performed. This record supports the baseline
decision for the selected Hysteria 2 / WireGuard `v0.7` work.

## Exact comparison and evidence boundary

| Reference | Full commit |
| --- | --- |
| Current oracle, Xray-core `v26.7.28` | `5ca6f4b7d4dc20a881d4330e498892697627ec0c` |
| Candidate, Xray-core `v26.9.8` | `37ceb8b4b65ee919fb772a8034e572f76a6e87a2` |
| Rust source inspected | `8a86a7f762aba919ff75cad5980a28612ba2dfe8` |

The exact [upstream comparison](https://github.com/XTLS/Xray-core/compare/5ca6f4b7d4dc20a881d4330e498892697627ec0c...37ceb8b4b65ee919fb772a8034e572f76a6e87a2)
contains **43 commits and 97 changed files**, with 3,576 insertions and 1,272
deletions including generated protobuf files and dependency checksums.
GitHub's comparison API and local Git agree on the commit and file counts.
The [candidate release](https://github.com/XTLS/Xray-core/releases/tag/v26.9.8)
was published on 2026-09-08 and is marked prerelease, as is the existing
`v26.7.28` release in GitHub's metadata.

This audit inspected the commit inventory, configuration and relevant runtime
diffs, dependency version changes, and all three commits in the updated
REALITY dependency. It also checked the current Rust parser and fingerprint
tables. Platform-only work is summarized separately. It is not a full audit
of every transitive dependency, an executed interop matrix, or security signoff.
The existing Xray checkout remains clean at `v26.7.28`; fetching the candidate
did not switch it. No runtime, SDK, dependency lock or oracle pin is changed.

## Highest-impact changes for the existing Rust client

### REALITY now requires a hybrid key share

The REALITY dependency moves from `9234c772ba8f` to
`8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8`. The
[new server check](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)
requires an `X25519MLKEM768` key share (group `0x11ec`, 1,216 bytes) before
the optional ordinary X25519 share. An X25519-only or draft-Kyber-only hello
does not satisfy it. Changing only the advertised Xray version cannot repair
that incompatibility.

In the Xray configuration builder, the old automatic `minClientVer =
[26, 3, 27]` assignment and warnings are disabled. Explicit version limits
remain available. This removes the default version floor but does not relax
the new key-share check.

Static inspection of our generated profiles and eleven-member `random` pool
found the following necessary-condition results:

| Key-share condition | Current modern profiles |
| --- | --- |
| Satisfied (4) | `hellofirefox_148`, `hellochrome_131`, `hellochrome_133`, `hellosafari_26_3` |
| Not satisfied (7) | `hellofirefox_120`, `hellochrome_120`, `helloios_13`, `helloios_14`, `helloedge_106`, `hello360_11_0`, `helloqq_11_1` |

The default `chrome` alias uses `hellochrome_133`'s profile. These are static
key-share findings, not four successful handshakes or a measured failure
rate. The process-wide `random` selection can currently choose one of the
seven incompatible shapes. Other explicit aliases and randomized profiles
also need a complete new-server matrix before support can be claimed.

Local evidence: [fingerprint registry](../crates/xray-utls/src/lib.rs),
[generated profiles](../crates/xray-transport/src/utls_profiles.rs), and
[profile application](../crates/xray-transport/src/utls_shaping.rs).

The same dependency update increases the target TLS-record buffer from 8 KiB
to 17 KiB and fixes background probe connection leaks, truncated-record
handling and a race. See the
[three-commit dependency comparison](https://github.com/XTLS/REALITY/compare/9234c772ba8f...8cdf7bf9c7f0).
These are reference-server implementation changes; they are not evidence of
the corresponding defects in our Rust client.

### Outbound chaining configuration is removed upstream

[Config changes](https://github.com/XTLS/Xray-core/commit/65458e919fcb3548d44481ea7929031a14bf117e)
make a non-null `outbounds[].proxySettings` a configuration error and direct
users to `streamSettings.sockopt.dialerProxy`. The old protocol-layer chaining
runtime and protobuf field are also removed.

For the transport-layer subset we support, the upstream spelling changes from:

```json
{"proxySettings": {"tag": "hop", "transportLayer": true}}
```

to:

```json
{"streamSettings": {"sockopt": {"dialerProxy": "hop"}}}
```

These are outbound fragments, not complete runnable profiles. Our current
parser accepts the first form and rejects `sockopt.dialerProxy`; its only
supported socket-options field is `happyEyeballs`. This is a concrete
configuration migration task, not just an oracle-version update. Define the
canonical new spelling and explicit treatment of old SDK/config inputs while
retaining cycle checks, transport restrictions and fail-closed behavior.
See [the parser's field registry](../crates/xray-config/src/surface.rs).

The same upstream commit runs VLESS/Trojan transport-security validation after
normalization and checks `vnext[0]` / `servers[0]`, closing the previous legacy
plaintext-config bypass. Our VLESS parser already rejects that plaintext
case; its documented divergence and fixtures need to be revisited.

### QUIC client defaults change for both Hysteria and XHTTP/H3

The [Hysteria 2.12.2 update](https://github.com/XTLS/Xray-core/commit/ada99a4eb00f169b0e2d650990d77fb7930967bb)
updates `apernet/quic-go` and enables `ChromeParrot` by default in both client
paths. It also selects zero-length client connection IDs and clears the
client-certificate callback for that mode.

The exact dependency's [configuration documentation](https://github.com/apernet/quic-go/blob/184d081eef3e/interface.go)
states that ChromeParrot overrides flow-control windows, stream limits, idle
timeout and packet size with Chrome's values, changes transport-parameter
encoding and Initial packet construction, and ignores conflicting settings.
Consequently the new reference's effective defaults cannot be inferred solely
from the numeric window assignments in Xray's dialer. This is also separate
from the existing TCP uTLS `fingerprint` field.

New `streamSettings.finalmask.quicParams` fields are:

| Field | Effect in the inspected source |
| --- | --- |
| `disableChromeParrot` | Opts the client out of the new default mode |
| `disableGSO` | Disables QUIC UDP segmentation offload |
| `brutalDisableLossCompensation` | Keeps Brutal's ACK-rate compensation factor at one |
| `disableStatelessReset` | Disables the new server stateless-reset key setup |

BBR controller initialization now seeds its packet size no higher than QUIC's
actual initial packet size. The Rust parser currently rejects all four new
fields; its H3 uses Quinn with the documented fixed-window and BBR differences.
The v0.7 design must explicitly choose a supported contract and document any
ChromeParrot difference. Do not report the old H3 measurements as results for
these changed defaults.

### XHTTP lifecycle and HTTP/2 recovery fixes

- [77f98eba](https://github.com/XTLS/Xray-core/commit/77f98eba0978cbcb425e2f8ec3cec86bd5aa8444)
  and [eef6e63b](https://github.com/XTLS/Xray-core/commit/eef6e63bc16d6e97fd98178556d49aad7978809a)
  fix client closure/read publication races and upload byte counting after
  buffer ownership transfer.
- [dffc7ada](https://github.com/XTLS/Xray-core/commit/dffc7ada5eef8a8b3df7da8928536ce57135a119)
  makes packet-up bodies reconstructible through `Request.GetBody`, enabling
  Go's HTTP/2 transport to retry after GOAWAY.
- HTTP/3 client/server code now explicitly owns and closes `quic.Transport`
  along with the UDP socket.

These fixes suggest targeted GOAWAY, close-before-response, concurrent close,
byte-accounting and cancellation cases for our implementation. They do not
establish that our Rust implementation has the same Go races, and HTTP request
retry must not become unconditional replay of application data.

## Changes for the selected v0.7 protocols

### WireGuard

[c7e569b0](https://github.com/XTLS/Xray-core/commit/c7e569b0377724600af1ea2a05eb8f4c7c3e0609)
adds `settings.remoteDNS` and TTL-aware address caching. Empty settings retain
the existing Cloudflare DNS addresses inside the WireGuard stack. The special
single-element value `["local"]` resolves target domains through Xray's
configured DNS client; explicit IP strings choose the tunnel-side resolvers.
The userspace remote resolver computes the minimum A/AAAA TTL with a
300-second ceiling in the inspected code.

Endpoint bootstrap still uses local resolution. Both local and remote
resolution now feed one hostname-keyed handler cache, whose source has a
cleanup-loop TODO. For our mobile design, specify bounded eviction, resolver
role separation and validation of `remoteDNS` literals rather than copying
this map and `MustParseAddr` construction unchanged.

[7d214f8b](https://github.com/XTLS/Xray-core/commit/7d214f8b094f75322fa3990f8aadad1c912f24f5)
fixes `sendThrough` by setting the outbound gateway before initializing the
WireGuard device. The WireGuard engine and gVisor dependency versions are
unchanged; these are outbound integration changes, not a new WireGuard wire
protocol or crypto revision.

### Hysteria 2 and optional Realm features

Beyond the shared QUIC changes, the update adds Realm `ipMode` selection
(`dual`, `v4`, `v6`) and optional `portMapping` using UPnP/NAT-PMP, including
mapping renewal and teardown. This brings a new `libp2p/go-nat` dependency and
related discovery libraries. These options need a separate scope decision;
standard Hysteria 2 client support does not require enabling every Realm mode.

Server masquerade gains `xForwarded`, Unix-socket proxy targets and response
buffer pooling. A subsequent
[Unix-path fix](https://github.com/XTLS/Xray-core/commit/de2caf3cef7a350453ba9079543f09660b0d837c)
is included. These affect our reference servers rather than add Rust server
scope. The `proxy/hysteria` control/framing files are unchanged in this range.
UDP hopping and Salamander already existed in `v26.7.28`.

## Routing, DNS, direct traffic and other fixes

| Area | Delta | Rust/mobile implication |
| --- | --- | --- |
| Routing | `localOS` matches the OS running Xray, case-insensitively; result is fixed when building the rule | New optional host-policy input, currently rejected by our grammar; mobile OS mapping needs an explicit contract |
| Router/observatory | Atomic publication for routing/balancer data fixes API races; an empty `subjectSelector` match now sleeps instead of spinning; `HealthCheckSettings` becomes an exported Go type | Retain our atomic policy and empty-selection behavior tests; no new embedded API service is needed |
| macOS process routing | IPv4-mapped AF_INET6 sockets can match IPv4 process lookups | Relevant only if process-based routing is selected later |
| Freedom | Legacy `settings.domainStrategy` and outbound `targetStrategy` migrate to `sockopt.domainStrategy`; non-AsIs `targetStrategy` takes precedence. `sockopt.addressPortStrategy` is rejected. Resolution/final-rule checks and the actual remote-endpoint check are reworked | Audit direct DNS/Happy Eyeballs and chaining fixtures; our current Freedom settings are empty, so advanced final-rule options remain outside the supported subset |
| UDP dialing | Wildcard binding follows the destination's IPv4/IPv6 family | Relevant regression case for mobile protected UDP sockets and both new protocols |
| QUIC sniffing | Recognizes QUIC v2 Initial packets, including v2 salt and label differences | Our sniffer currently handles v1; sniffing support and outbound QUIC-version support are distinct decisions |
| BitTorrent sniffing | Reworks uTP SYN/extension validation | Outside our currently claimed HTTP/TLS/QUIC sniffing subset |
| Blackhole | Adds base64 `response.customResponseData` with `type: "custom"` | Our parser does not support a blackhole outbound; no automatic scope addition |
| WebSocket/HTTP/buffers | Fixes address access before deferred WS dialing, a short HTTP 1xx-response panic, and partial buffered writes; HTTP outbound tolerates missing inbound metadata | Review analogous lifecycle/bounds cases, without assuming Go-specific bugs apply to Rust |
| SS2022 | Closes the server connection on early returns | Reference maintenance; SS2022 remains deferred |
| Listeners | Empty listen handling and TCP port-zero validation are adjusted; custom Linux inbound sockopts are no longer accidentally nested under TCP-only handling | Check intentional differences in local test-listener configuration; no gateway feature expansion |

The `app/dns` and `proxy/dns` source trees do not change. DNS-related changes
are in the WireGuard resolver, Freedom resolution path and `miekg/dns`
dependency. VLESS encryption, Vision and Xray's TLS/uTLS transport source are
also unchanged; the VLESS outbound removes an unused connection reference.
This does not imply unchanged REALITY behavior, because its dependency changed.

## Platform and dependency changes

- Darwin TUN replaces busy-spin waiting with kqueue readiness waits and a
  bounded sleep fallback. Windows TUN changes adapter identity, routes, MTU
  and outbound-interface handling. These are changes to Xray's Go adapters,
  not patches automatically inherited by our native adapters.
- FreeBSD gains automatic system routing and outbound-interface selection.
  OpenBSD gains TPROXY support, followed by IPv6 and SO_REUSEPORT corrections.
  These gateway/platform additions are outside the selected mobile scope.
- Docker login action updates are CI maintenance.

Selected direct dependency changes from `go.mod`:

| Dependency | v26.7.28 | v26.9.8 |
| --- | --- | --- |
| Go language/toolchain minimum | 1.26 | 1.27 |
| apernet/quic-go | `v0.59.1-0.20260425001925-6c6cc9bcb716` | `v0.61.1-0.20260806010916-184d081eef3e` |
| REALITY | `9234c772ba8f` | `8cdf7bf9c7f0` |
| gRPC | 1.82.1 | 1.83.2 |
| protobuf | 1.36.11 | 1.36.12 |
| cloudflare/circl | 1.6.4 | 1.6.5 |
| miekg/dns | 1.1.72 | 1.1.73 |
| x/net; x/crypto | 0.57.0; 0.54.0 | 0.58.0; 0.55.0 |
| pion/stun; testify | 3.1.6; 1.11.1 | 3.1.7; 1.12.1 |
| libp2p/go-nat | absent | `v1.0.1-0.20250821073202-01afc089f138` |

uTLS, wireguard-go and gVisor retain their existing pins. Transitive updates
include DTLS, pion transport, x/text and Google RPC metadata; NAT discovery
adds UPnP/NAT-PMP/SSDP and route-discovery dependencies.

Our CI currently pins Go 1.26.5 with `GOTOOLCHAIN=local`, so a new-oracle build
requires an explicit toolchain update. The isolated gRPC/masquerade oracle
modules, exact-source guards and provenance checks must move together; old
release/benchmark evidence must retain its original identity.

## Baseline decision: retain v26.7.28

After this source audit, the owner decided on 2026-09-08 to keep the current
Xray-core version and start Hysteria 2 / WireGuard implementation. The items
below apply to a future v26.9.8 migration; they do not block implementation
against the selected v26.7.28 reference.

`v26.9.8` is a useful candidate for the planned Hysteria 2 / WireGuard scope,
but adopting it requires work on already supported functionality. Required
decisions and verification for a future migration are:

1. Define REALITY fingerprint acceptance, aliases and random selection for the
   new server check; regenerate/review fixtures and run exact-server interop.
2. Define chaining migration to `sockopt.dialerProxy`, including old-input
   handling, grammar/tooling and equivalent Swift/Kotlin behavior.
3. Define the Hysteria/XHTTP QUIC defaults and supported new options, including
   ChromeParrot's interaction with resource limits; then measure and test them.
4. Revalidate Freedom/DNS, IPv6 UDP, XHTTP GOAWAY and cancellation behavior.
5. Update the isolated reference toolchain and run the selected supported-surface
   matrix before changing the compatibility pin.

The source audit is complete within the stated boundary. The actual oracle
remains `v26.7.28`; no new-source runtime or device pass is claimed.

## Reproducing the source inventory

Run from an Xray-core checkout containing both commits. These commands do not
switch the checkout:

```sh
git rev-list --count 5ca6f4b7d4dc20a881d4330e498892697627ec0c..37ceb8b4b65ee919fb772a8034e572f76a6e87a2
git log --reverse --format='%H %s' 5ca6f4b7d4dc20a881d4330e498892697627ec0c..37ceb8b4b65ee919fb772a8034e572f76a6e87a2
git diff --stat 5ca6f4b7d4dc20a881d4330e498892697627ec0c 37ceb8b4b65ee919fb772a8034e572f76a6e87a2
git diff --ignore-all-space 5ca6f4b7d4dc20a881d4330e498892697627ec0c 37ceb8b4b65ee919fb772a8034e572f76a6e87a2 -- infra/conf proxy/wireguard transport/internet/hysteria transport/internet/splithttp
```
