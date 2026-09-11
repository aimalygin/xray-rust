# v0.7 mobile DNS bootstrap

The Swift packet-tunnel provider and Kotlin reference VPN service prepare the
implemented JSON/core subset of Hysteria 2 and WireGuard before installing the
VPN's DNS interception. This increment retains Xray-core v26.7.28 and the existing
native protocol implementations and workspace version 0.6.1. Bootstrap itself
did not change C ABI 1.4; the subsequent [profile import](v07-profile-import.md)
increment extends it to ABI 1.5.

## Carrier preparation

- Hysteria uses `settings.address`; VLESS retains `settings.vnext[].address`.
- WireGuard uses every `settings.peers[].endpoint`, preserving peer order.
  Only the outer host is extracted from `host:port` or `[IPv6]:port`; private
  keys, PSKs, inner addresses, allowed IPs and destination domains are not
  bootstrap targets. Endpoint syntax errors omit the supplied value.
- Domain identities are canonicalized for `dns.hosts` only. Existing exact
  mappings and aliases are retained. A terminal system lookup produces all
  usable A/AAAA candidates in order, including DNS64 results. Original endpoint
  strings, TLS names, auth, peer policies and DNS-server objects remain intact.
- Apple excludes every outer carrier candidate with an IPv4 `/32` or IPv6
  `/128` route. DNS-upstream pins and WireGuard inner addresses never create
  carrier exclusions. Android continues to protect each native outer UDP socket
  through `VpnService.protect(fd)` and does not add global exclusions.
- Literal, resolved and aliased carrier addresses cannot point to the adapter's
  DNS anchor or tunnel interface. Apple and Android retain their own interface
  address sets. This also closes the Android VLESS carrier alias gap.

The existing five-second total startup deadline, cancellation/generation guards,
zero-queue resolver admission and eight-step alias limit remain unchanged. A
failed or cancelled peer lookup fails the entire preparation. WireGuard peer
count remains 1..8. Preparation does not probe endpoints or change the runtime's
first-candidate selection. Pins remain fixed for one tunnel lifetime; migration
and re-bootstrap on network transitions remain acceptance work.

## FakeDNS and destination resolution

WireGuard encrypts IP packets and therefore needs a real destination IP even
when every outer endpoint is pinned. As with Freedom, a FakeDNS-only config
without `dns.servers` cannot select WireGuard as the default outbound or through
a TUN-applicable rule capable of matching domain traffic. The preflight also
checks prefix-expanded balancer candidates and `fallbackTag`, regardless of the
currently selected peer. An IP-only rule, or a rule restricted to another inbound,
remains allowed. VLESS and Hysteria can keep domain destinations for remote
resolution. No public resolver is inserted automatically.

Swift reports `unsafeFakeIPWireguardRouting` from the shared preflight, mapped
to the existing provider `invalidDNSRoutingTopology` error. Kotlin rejects the
same topology before `Builder.establish()`. Existing Freedom cases remain covered.
These checks are conservative topology validation, not a simulation of rule
ordering, static destination mappings or current balancer health.

## Verification and remaining scope

Focused tests cover mixed Hysteria/WireGuard profiles, repeated and aliased
hosts, both outer IP families, complete settings preservation, tunnel-local
address rejection, malformed endpoint redaction, last-peer failure and startup
deadlines/cancellation. Topology tests cover defaults, domain/catch-all/combined
rules, IP-only and non-TUN exceptions, and balancer prefix/fallback paths. Apple
also feeds the four canonical Hysteria/WireGuard JSON fixtures through pinning
and the current Rust core validator, including the provider's FakeDNS error map.

Reproduce with a current local Apple XCFramework and the configured Android SDK:

```sh
swift test --disable-sandbox --package-path platform/apple \
  --filter 'XrayMobileDNSPreflightTests|XrayPacketTunnelProviderTests'
platform/android/gradlew -p platform/android :xraymobile:testDebugUnitTest
cargo test --locked -p xray-ffi --test mobile_artifacts_tests
```

Observed on macOS arm64, 2026-09-11 UTC: 147 selected Swift tests, all 89 Kotlin
adapter unit tests and all 30 mobile FFI contract tests passed. The Swift run
compiled the package against a locally built debug macOS-arm64 native library
in a temporary XCFramework; it did not use a published mobile binary. The
mobile toolchain script guard, all 13 public-fixture checks, Rust formatting and
strict Clippy for `xray-ffi --all-targets --all-features` also passed.

This is host-side preparation evidence. Hysteria share-link and WireGuard file
import plus capability discovery are covered by the subsequent
[SDK increment](v07-profile-import.md). Application integration, independent
native-server tests, cross-compilation and physical-device lifecycle/memory tests
remain v0.7 work. No mobile release artifacts are published by this increment.
