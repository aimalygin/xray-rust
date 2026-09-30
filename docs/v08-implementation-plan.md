# v0.8 implementation plan and evidence

Started 2026-09-30 (America/Chicago).

The owner selected complete **Trojan, Shadowsocks 2022 and VMess AEAD** clients
for the core and both mobile SDKs. Shadowsocks AEAD-2017 and legacy VMess
authentication are excluded. All three clients are release requirements.

This document distinguishes the delivery target from implemented behavior.
All three clients now have JSON outbounds, TCP/UDP runtime paths, shared
profile imports, ABI capability bits and Swift/Kotlin adapters. Their pinned
Xray live matrices and host SDK tests pass. Shared bounded Mux works for all
three protocols, including pooled UDP and VMess standalone XUDP. Independent
sing-box, REALITY, split-XHTTP and cross-protocol chain matrices now pass.
The existing graph boundaries remain explicit; candidate-bound release
acceptance is still outstanding. These are local development changes, not a
published 0.8 release.

## Fixed compatibility and distribution boundaries

Retain Xray-core **v26.7.28**, full commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, by owner decision on 2026-09-30.
The local `Xray-core` reference checkout was verified clean at that commit.
The existing `scripts/verify-oracle-fixtures.py` guard checks that identity
before the new oracle runs. The reference repository is read-only: use
`-mod=readonly` and write generated output in `xray-rust` or a temporary path.

The v26.9.8 source audit and v26.9.30 inventory are migration backlog. Their
defaults, grammar and dependency implementations must not be substituted for
the selected source. In particular, this pin still uses `sing-shadowsocks`
v0.2.7; the later upstream SS2022 rewrite is not our oracle.

Preserve the published `0.7.0` baseline and device exceptions with their
original provenance. The distribution repository stays on its reviewed
`v0.7.0` core pin until a new candidate supplies the complete source/header/
adapter/artifact identity. Develop native adapter changes in the core's
`platform/apple` and `platform/android` trees; synchronize the distribution
repository through its existing release process. Do not publish capability
bits for implementations absent from the linked binary.

## Initial source review

| Finding at the pinned source | Implementation consequence |
| --- | --- |
| All three clients and reference-server registrations exist in `infra/conf/xray.go`. Their builders accept flattened settings and legacy `servers` / `vnext` forms, with one server; VMess requires one user. | Build positive/negative configuration fixtures for both input forms. Define conflicts and stricter fail-closed rules explicitly. |
| Trojan derives `hex(SHA224(password))`; TCP/UDP requests use commands 1/3 and SOCKS-style address tags. Its UDP reader rejects payloads above 8192 bytes. | Treat the token and complete request header as credentials. Bound UDP before allocation or transmission; do not advertise the u16 length field as a 65535-byte peer limit. |
| Trojan's pinned security check runs before legacy settings normalization and inspects the flattened address. It does not impose a Mux requirement. | Apply security validation after our own normalization to both shapes. Maintain explicit public plaintext rejection. Newer public guidance is not evidence of a mandatory check in this pin. |
| SS2022 delegates to `sing-shadowsocks` v0.2.7. It offers AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. AES supports identity-key chains; ChaCha rejects multiple keys. Oversized PSKs can be normalized by its key derivation. | Test the locked dependency as well as the Xray wrapper. Specify key normalization and size bounds; do not silently truncate keys or apply AES identity framing to ChaCha. |
| VMess has AEAD header/body codecs, AES-128-GCM/ChaCha20-Poly1305 and `auto`. Unknown security strings become `auto` in the Go builder; legacy `alterId` is absent from its account struct. | Reject unsupported explicit security values and nonzero legacy `alterId` ourselves. Do not mistake ignored JSON for implemented legacy authentication. |
| Pinned VMess recognizes `AuthenticatedLength` and `NoTerminationSignal`; termination defaults come from this exact account/client code. | Derive option/default fixtures from this revision; current website defaults are not the contract. |
| `build_transport_layer` and related endpoint/security compilation currently extract VLESS settings directly. `outbound.rs` exceeds 8000 lines. | Extract protocol-independent endpoint/carrier compilation before adding more stream outbounds. Preserve Host/authority, SNI, XHTTP download, chaining and protected-dialing semantics. |
| VLESS has XUDP framing; the core does not yet provide general Mux session pooling. | General Mux is separate shared work with its own lifecycle and resource tests. Reuse wire pieces only where the pinned protocol agrees. |

Inspected reference files: `infra/conf/{xray,trojan,shadowsocks,vmess}.go`,
`proxy/trojan/{config,protocol,client}.go`,
`proxy/shadowsocks_2022/outbound.go`,
`proxy/vmess/{account.go,encoding/client.go,outbound/outbound.go}`, and the
locked `sing-shadowsocks` `shadowaead_2022` constructor. This is a focused
source review and wire-oracle foundation, not a completed security audit or
live-server compatibility matrix.

## Delivery sequence

Each increment must leave unsupported configurations fail closed. A codec,
parser branch or successfully imported profile alone does not establish
runtime support. The table is the implementation order, not separate releases.

| Increment | Concrete output | Completion evidence |
| --- | --- | --- |
| M0: contracts and fixtures | Exact oracle pin, source findings, wire/config fixtures, per-protocol accepted/rejected matrix and resource ownership | Reproducible oracle output; explicit remaining design decisions |
| M1: shared stream carrier | Extract endpoint/security/carrier compilation and protected connection setup from VLESS-specific code | Existing VLESS, Vision, TLS/REALITY, XHTTP and chaining regressions pass without changed wire/defaults |
| M2: Trojan | Bounded framing, typed redacted config, TCP/UDP runtime, imports and native adapters | Pinned Xray and independent Trojan TCP/UDP; SOCKS/HTTP/TUN/DNS and SDK tests |
| M3: SS2022 | Dedicated crypto/record/session component, all three methods, AES identity chains, native UDP, imports and adapters | Locked Xray plus independent SS2022 server; replay, authentication, restart, rebind and resource evidence |
| M4: VMess AEAD | Dedicated crypto/record component, both body ciphers and auto, TCP/UDP, agreed options, imports and adapters | Xray plus independent VMess server; response binding, masking/padding, time/nonce/EOF and resource evidence |
| M5: shared Mux/XUDP and full matrix | Bounded Mux client/session ownership and applicable XUDP paths for the selected clients; complete transport and graph coverage | Pool saturation, blocked-reader isolation, session close/reconnect/cancel, UDP identity and cross-protocol regressions |
| M6: release acceptance | Frozen scope, candidate-bound physical/performance evidence and matching native artifacts | Both Android paths, Apple hardware, core/SDK CI and external package-consumer checks |

M5 design belongs in M0/M1; its final integration follows the ordinary protocol
paths so defects can be isolated. Existing graph restrictions remain explicit:
general protocol-layer chains, REALITY over a preconnected stream and QUIC
chaining are not obtained merely by extracting a TCP carrier. Any restriction
that conflicts with the selected complete client target must be resolved and
documented before feature freeze, not hidden behind a success-shaped parser.

## Target protocol and transport matrix

Every row below is a release target to implement and verify, not a passing
matrix. Enumerate exact profiles and exclusions in executable fixtures before
enabling each combination.

| Surface | Trojan | Shadowsocks 2022 | VMess AEAD |
| --- | --- | --- | --- |
| Ordinary carriage | TCP over verified TLS; framed UDP over that stream | Encrypted TCP and native encrypted UDP | AEAD TCP and framed UDP |
| Addresses and ingress | IPv4, IPv6, domains; SOCKS TCP/UDP, HTTP TCP, TUN TCP/UDP, routed DNS | Same | Same |
| Existing stream carriers | Raw, WS, HTTPUpgrade, gRPC, XHTTP where supported by the pin | Audit TCP transport extensions separately from native UDP | Raw, WS, HTTPUpgrade, gRPC, XHTTP where supported by the pin |
| Security combinations | TLS and pinned-compatible REALITY combinations; no Vision flow | Protocol encryption; optional outer security only in a proven carrier combination | Protocol AEAD; TLS/REALITY combinations where the pin supports them; no Vision flow |
| Mux/XUDP | Shared bounded implementation and explicit configuration matrix | Check wrapper applicability independently of native UDP | Shared bounded implementation plus pinned VMess Mux command/XUDP handling |
| Core services | Routing, selectors, probes, DNS, accounting, close and diagnostics | Same | Same |
| Mobile delivery | Shared Rust import, ABI discovery, Swift/Kotlin bootstrap and lifecycle | Same | Same |

Keep negative cases for AEAD-2017 `ss://` methods, nonzero VMess `alterId`,
unknown methods/options, non-empty Trojan `flow`, invalid certificate settings,
unusable keys, oversized input and unsupported transport/security combinations.
Errors must identify the input path or typed error without echoing credentials.

## Configuration, import and SDK work

- Add dedicated `parser/trojan.rs`, `parser/shadowsocks.rs` and
  `parser/vmess.rs` modules and typed secret-bearing models. Keep field registry,
  generated configuration tooling and canonical/rejected fixtures in sync.
  Validate endpoint/security after normalizing the chosen input form.
- Add `trojan://`, SIP002 `ss://` for SS2022 only, and `vmess://` import through
  the shared Rust parser. VMess's common base64 JSON form and any URI form
  require separate fixture sets; never infer one dialect's fields from another.
  Bound decoded data as well as encoded input, reject conflicting duplicates,
  and preserve literal plus signs, percent encoding, IPv6 brackets and names.
- Retain the current import envelope budgets: 256 KiB request, 64 KiB source
  text, 256 KiB result and 128 UTF-8 bytes for names. Add method-specific key,
  password, nesting and decoded-size limits before admitting those formats.
- Extend `ProfileFormat`, the existing offline import API and capability
  discovery additively. Allocate new capability bits only when the corresponding
  runtime exists. Determine ABI minor bumps with the implementation, keeping
  ABI major 1 and existing symbol/layout contracts intact.
- Project each protocol into both native adapters in the same increment.
  Verify endpoint bootstrap, Android socket protection and physical-network
  binding, Apple tunnel routes, secure host-owned profile persistence, and
  sanitized import/startup errors. Credential-bearing imported JSON remains
  a secret even though its Debug representation is redacted.

## Resource and security contracts

Reuse existing core admission/operation limits instead of adding detached
per-flow runtimes. Each protocol must own cancellation, task joins, buffers,
secret material, connection accounting and cleanup explicitly. Freeze numeric
caps before enabling that runtime; exercise the boundary and one-over cases.

For the first Trojan framing increment:

- passwords: 1–4096 UTF-8 bytes; the password is borrowed and not retained;
- derived authentication: 56 bytes, redacted Debug and zeroizing storage;
- complete request headers: redacted Debug and zeroizing storage;
- domains: 1–255 UTF-8 bytes without whitespace/control characters; DNS/IDNA
  normalization remains the configuration/resolver layer's responsibility;
- ports: nonzero u16;
- UDP payload: at most 8192 bytes, matching the pinned receiver;
- UDP frame: at most 8455 bytes with the maximum domain; payload decoding
  borrows input and validates the advertised length before waiting for payload;
- partial frames return `Incomplete` without mutable decoder state. The future
  stream owner must cap its buffer and discard the session on malformed frames.

The strict CRLF/domain/port checks are intentional local validation. The Go
reader is more permissive in some malformed cases; accepted well-formed wire
compatibility does not require copying that permissiveness. Empty UDP framing
is represented by the codec; the runtime must test and document whether the
reference actually forwards an empty datagram before claiming that behavior.

For SS2022, freeze limits for decoded key chains, TCP records, UDP payloads,
concurrent sessions, replay windows, retained old server sessions and expiry.
Replay state may only advance after authentication. Eviction must not shorten
required anti-replay lifetimes; reject admission at capacity instead. Test clock
changes and server restart independently of carrier reconnection.

For VMess, bound request/response headers and body buffers, reject invalid
authenticated lengths before allocation, prevent nonce-counter reuse, and
preserve half-close/termination behavior. Bound failed-authentication draining
and all early exits. Do not retry or replay application data automatically.

For Mux, set per-outbound connection/session/queue budgets and per-session
backpressure before implementation. A blocked child must not starve sibling
traffic or control frames; closing the parent must reclaim every child.

## Verification and acceptance

The first increment is checked with:

```sh
cargo test --locked -p xray-proxy
cargo clippy --locked -p xray-proxy --all-targets -- -D warnings -W clippy::perf -W clippy::suspicious
cargo fmt --all -- --check
bash scripts/check-v08-protocol-oracle.sh
bash scripts/tests/check-public-fixtures.test.sh
```

The Trojan oracle imports the pinned Go implementation and generates 12 request
headers (two synthetic passwords, three address families, TCP/UDP) plus three
UDP frames. Rust compares its bytes to those fixtures and checks decoding,
every truncation, concatenated frames, invalid metadata, bounds and redaction.
This provides codec evidence only. It does not test TLS, a running server,
async cancellation, mobile devices or full protocol authentication behavior.

Local validation on 2026-09-30 passed: all 96 `xray-proxy` tests (including six
Trojan tests), Clippy, formatting, pinned oracle regeneration/comparison and
all 13 public-fixture guard tests. Shell syntax and `git diff --check` also
passed. The pinned Xray-core checkout remained clean. These results cover the
local first increment; no remote CI run or release acceptance is claimed.

The oracle is wired into the existing blocking `go-oracles` CI job. Extend its
fixtures and tests for SS2022/VMess as those implementations arrive. Independent-server
versions and binary/source checksums must be selected and recorded before each
runtime acceptance; they are not yet established by this kickoff.

Before release, keep the existing workspace, parser/FFI, fuzz, sanitizer/Miri/
Loom, dependency, controlled-network and native-build gates. Add protocol-specific
negative/fuzz targets, bounded core integration tests, and source-authenticated
performance comparisons. Preserve existing 0.7 comparison limits and all
failed/uncertain measurements.

Physical acceptance covers import, TCP/UDP/DNS, cancellation, reconnect,
lock/wake, network transitions and bounded resource recovery for all three
protocols, including Android FileDescriptor and PacketPump. Reports identify
the exact candidate, device/OS, durations, transitions and measured limits.
The 0.7 Android cellular and timeout exceptions are not inherited, and there is
no fixed-duration long-soak requirement.

## Next implementation increment

Complete final regressions and SDK artifacts within the existing documented
outbound graph, then run the release hardening and performance/device campaign
against a frozen candidate. Do not inherit earlier
release exceptions or treat local host artifacts as mobile release artifacts.

## Implementation evidence — 2026-09-30

M1 extracted a shared protected stream carrier. Core unit/regression tests
passed after extraction; the final combined 0.8 regression campaign remains a
release requirement.

Trojan now supports flat/legacy settings, redacted and wiped credentials,
`trojan://` imports, level policies, TCP and framed UDP. Live pinned-Xray tests
pass for raw TLS, WS, HTTPUpgrade, gRPC and XHTTP stream-one, SOCKS/HTTP,
TUN TCP/UDP, routed DNS and managed destination lookups. Tests also cover
wrong credentials, an untrusted certificate, accounting and host-initiated
connection closure. Stream UDP cancellation tests preserve buffered reads and
poison partially written frames.

Shadowsocks 2022 now supports all three methods, flat/legacy settings, AES
identity chains, native UDP and SIP002 plain/encoded-userinfo imports. Golden
vectors use the real locked `sing-shadowsocks` APIs, including three-key AES
chains and oversized-key normalization. Live pinned-Xray tests pass for all
three methods, both AES multi-user methods, raw/WS/HTTPUpgrade/gRPC/XHTTP,
SOCKS/HTTP, TUN TCP/UDP, DNS, accounting and host closure. Codecs reject forged,
replayed, misbound and stale responses before committing replay state. Reads
and buffered writes survive cancellation; TCP response salts require exact
equality (stricter than the locked Go client's erroneous ordering comparison).

Both native SDKs pass shared Rust import/capability/bootstrap tests using the
current linked library (host JNI and a test-only macOS XCFramework). Apple
host test artifacts are not universal release artifacts. Android tests require
`ANDROID_HOME` and `JAVA_HOME`. The configuration suite passed serially after
an existing parallel GeoIP fixture-name collision; the failure was not a
protocol or parser regression. Clippy passes with warnings denied.

Reproduction:

- `CARGO_INCREMENTAL=0 bash scripts/check-v08-protocol-oracle.sh`
- `CARGO_INCREMENTAL=0 bash scripts/check-trojan-interop.sh`
- `CARGO_INCREMENTAL=0 bash scripts/check-shadowsocks2022-interop.sh`
- `CARGO_INCREMENTAL=0 cargo test --locked -p xray-config -- --test-threads=1`
- `scripts/test-profile-import-jni.sh --tests '*XrayV07DnsBootstrap*'`

### Measured bounds and remaining acceptance

Trojan's pinned reader permits 8192 payload bytes. Its writer includes the
address/header in an 8192-byte buffer: maximum reply payload is 8181 bytes
for IPv4, 8169 for IPv6, and `8184 - domain-byte-length` for a domain. The Go
oracle checks exact success/one-over boundaries separately for reads/writes.

The SS2022 codec accepts standard UDP wire packets up to 65507 bytes. The core
limits outgoing wire packets to **8192 bytes**, including authentication and
identity headers, because the pinned Xray UDP hub truncates larger datagrams.
Its receive storage is 65508 bytes to detect oversized input. Each association
owns one protected connected UDP socket, two replay windows of 8128 IDs and
at most two server sessions; a third cannot evict a recently active previous
session within 60 seconds. No detached per-association driver is created.
TCP record plaintext is bounded by 65535 bytes; outgoing chunks by 8192 bytes.
PSKs have at most 8192 encoded bytes and eight keys; ChaCha accepts one key.
Native UDP uses the server's UDP port independently of its TCP carrier, as the
pinned Xray wrapper does. SIP003 plugins and AEAD-2017 imports are rejected.

These results do not yet cover independent servers, physical devices,
REALITY/split-XHTTP combinations, complete chaining and Mux/XUDP, network
handover/restart campaigns, fuzz acceptance or final performance budgets.
They do not close M2/M3 release acceptance by themselves.

### VMess and shared Mux increment

VMess AEAD now supports AES-128-GCM, ChaCha20-Poly1305 and hardware-selected
`auto`, `AuthenticatedLength` and `NoTerminationSignal`, both JSON shapes,
base64-JSON and UUID-authority `vmess://` dialects. Nonzero `alterId`, insecure
TLS, unknown options and duplicate import aliases are rejected. The ABI adds
`VMESS_OUTBOUND` at bit 21; development ABI minor is 1.8 (bits 19/20 identify
Trojan/SS2022). The workspace package version is still the 0.7 development base.

The pinned Go oracle covers command-key/KDF/AuthID, both body ciphers, masking,
padding and authenticated lengths. Stream tests cover every truncated boundary,
cancelled read/write/flush/shutdown, response binding, forged headers/data/EOF,
UDP packet boundaries and nonce exhaustion. Counters fail before nonce reuse:
a VMess direction is limited to 65,536 AEAD records (roughly 507 MiB of maximum
outgoing chunks, less for small records). Exhaustion terminates the flow; no
transparent reconnect or replay is performed. Response headers are limited to
259 authenticated bytes; unsupported response commands/options are rejected.

Live Xray tests pass for raw, WS, HTTPUpgrade, gRPC and XHTTP stream-one;
AES/ChaCha/auto and both options; SOCKS/HTTP, TUN TCP/UDP, routed DNS and managed
destination lookup. Wrong UUID and untrusted TLS fail. Ordinary VMess UDP uses
standalone XUDP except ports 53/443, following the pinned cone-mode dispatch.
The XUDP reader has a bounded persistent buffer and survives cancellation.

Shared Mux is enabled through `mux` for Trojan, SS2022 and VMess. Positive
`concurrency` / `xudpConcurrency` is capped at 64; TCP zero defaults to 8,
negative disables TCP; XUDP zero shares the TCP pool and negative selects the
protocol's native UDP path. UDP/443 accepts `reject` (default), `allow`, `skip`.
Disabled Mux remains inert but validates field types. General VLESS Mux is still
unsupported; its pre-existing single-association XUDP remains available.

Each pool admits at most four parent connections, each with 128 lifetime child
IDs and the configured simultaneous-child cap. A child queues at most eight
8192-byte frames in each direction; this is at most 64 KiB per direction per
child (4 MiB per pool at the default concurrency, up to 32 MiB at the maximum,
plus framing/task state). A dedicated UDP pool has its own bound. Saturation
fails admission; blocked readers are reset without blocking siblings. Idle
parents expire after 30 seconds; retired IDs are never reused in a parent.
Core stop cancels and joins drivers. Parent failure does not replay child data.
Keyed BLAKE3 association IDs are stable within a handler and separate across
handlers; managed DNS uses zero rather than claiming a user-flow identity.

A separate pinned-Xray test passes TCP and UDP for all three protocols with
shared and separate UDP pools: six TCP flows use two protected parents at
concurrency four, UDP payloads through 8192 bytes round-trip, host closure leaves
siblings alive, and core stop removes children. Unit tests cover pool capacity,
blocked-child isolation/control delivery, cold-connect cancellation, idle expiry,
parent failure/reconnect and join. The Go oracle now includes 24 Mux frames.

Additional reproduction:

- `CARGO_INCREMENTAL=0 bash scripts/check-vmess-interop.sh`
- `CARGO_INCREMENTAL=0 bash scripts/check-mux-interop.sh`
- `CARGO_INCREMENTAL=0 cargo test --locked -p xray-core-rs --lib`:
  489 passed, two existing ignored tests after Mux integration.
- `cargo test --locked -p xray-ffi --test profile_import_tests`:
  all five formats pass exact ABI sizing and native config load.
- New `v08_protocols` sanitizer-fuzz target and seeds are wired into the existing
  blocking extended campaign. A local 61-second ASan smoke completed 839,361
  executions without a crash (593 MiB peak RSS); this is not the extended
  release campaign or a complete cryptographic audit.

The host Swift run before Mux integration passed 8 import tests and 136 tunnel
provider tests; JNI import/bootstrap also passed. Their link artifact will be
rebuilt after the remaining runtime work. This is not physical-device evidence.

### Independent server and expanded carrier evidence

`scripts/check-v08-independent-interop.sh` verifies sing-box **v1.13.20**,
revision `56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778` (the existing benchmark pin),
module sum `h1:2PfQuwVsV3rbvvOqoJOc1K2CY5xe5b9BL/TmIlGoCPE=` and its go.mod
sum before a read-only build. It records binary SHA-256 and Go build metadata
in `target/v08-independent/reference.json`. The Xray oracle remains unchanged.
Trojan raw/TLS, WS, HTTPUpgrade and gRPC; all three SS2022 methods and AES
multi-user identities; and VMess AES/ChaCha/auto/options and the same four
carriers pass SOCKS TCP/UDP, HTTP, accounting, close, TUN and routed DNS.
Wrong Trojan/VMess credentials and untrusted TLS fail. Sing-box SS2022 uses
sing-shadowsocks too (v0.2.8); this is a second server integration, not a fully
independent SS2022 cryptographic implementation or security audit.

This matrix found an actual VMess response-compatibility defect: sing-vmess
echoes negotiated request options where Xray emits zero. The authenticated
response parser now accepts zero or the exact negotiated byte, retaining
marker binding and rejecting unknown options/response commands. A regression
test covers both accepted values and failed negotiation.

The expanded pinned Mux matrix passes **27 configurations**, plus **18 TUN/DNS
scenarios**, across raw, WS, HTTPUpgrade, gRPC and XHTTP. Xray's XHTTP listener
sets its allowed Mux network to UDP: TCP Mux on XHTTP now fails configuration
and programmatic construction, while negative TCP concurrency plus a dedicated
UDP pool passes. gRPC/XHTTP transport reuse is accounted for separately from
Mux parent counts. UDP/443 and native fallback policy tests cover all modes.

`scripts/check-v08-carrier-interop.sh` passes **171 profiles**: 18 REALITY
raw/gRPC/XHTTP combinations with/without applicable Mux; 81 TLS XHTTP profiles
covering all three upload modes and H1/H2/H3 independent download combinations;
and 72 cross-protocol transport-layer chains with/without Mux over raw, WS,
gRPC and XHTTP. Each transfers a server-first greeting and 131,077-byte duplex
TCP payload; applicable UDP paths round-trip 1/1200/4096 bytes. The TLS bridge
uses pinned ephemeral certificates and preserves one real Xray session
namespace; REALITY uses a local TLS 1.3 cover origin, with no public endpoint.
These tests also verify socket protection and final connection cleanup.

All-feature workspace Clippy passes with warnings denied. Full workspace,
native SDK rebuilds and release hardening results are recorded separately as
they complete; none of the results above establishes physical-device or
candidate-bound performance acceptance.

### Host hardening, native builds and recovery checks

The combined workspace run passed **2356 tests**, with 88 explicitly ignored
integration tests across 93 suites. Those ignored protocol cases are exercised
by the separate live matrices above. AddressSanitizer passed **852 tests**
(two existing ignored cases); the existing Miri gates passed 38 tests and the
routing publication Loom model passed. Rebuilt host SDK tests passed **324
Swift tests** and the JNI import/DNS-bootstrap tests. The four Android native
ABIs and the AAR build pass, including its ELF dependency and 16 KiB alignment
checks. The signed iOS device app builds; physical execution still needs an
unlocked device. Universal Apple packaging is in progress. These are local
development-tree checks; their logs do not identify a frozen release candidate.

Additional SS2022 live recovery tests cover all three ciphers and both AES
identity configurations on Xray and sing-box. They verify response binding,
authentication before replay-state updates, duplicate/old-response rejection,
client-session recreation on a changed UDP source port and server restart
with unchanged keys. An initial test expecting seamless same-session NAT
rebinding timed out on both servers. Source review and a follow-up wire test
confirm that both pinned servers retain the session's first return address.
The passing test explicitly checks that behavior before opening a fresh
client session on the new path; it does not relabel the original failure as
successful seamless migration. Host reconnect must recreate the association.
IPv6 TCP and IPv6/domain UDP also pass for all three protocols, native and Mux
on Xray and native on sing-box.

The existing performance collector now accepts `--suite v08` for 60 distinct
Trojan/SS2022/VMess SOCKS/TUN workload cases, with five fresh-process repeats
in a full run. The temporary Apple fixture accepts the same three clients.
Their preparation is not measured performance or physical-device acceptance.

The version selector and `v08-release-evidence.yml` now use the separate
schema-4 validator in `scripts/check-v08-release-evidence.py`. It requires all
three Apple protocol scenarios, FileDescriptor and PacketPump scenarios for
each Android protocol, every listed address/DNS/lifecycle/network transition,
legacy regressions, and explicitly budgeted throughput/latency/memory samples
for each new protocol. Archives remain bound to a clean candidate commit/tree
and hashed raw artifacts. The 66 tests covering the old and new evidence gates
pass; schema 1–3 and the 0.7 owner-acceptance metadata cannot satisfy schema 4.
No actual 0.8 release evidence archive has been accepted yet.
