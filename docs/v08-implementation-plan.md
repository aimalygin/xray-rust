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
original provenance. The published distribution retains its reviewed `v0.7.0`
identity. The 0.8 development SDK uses an exact commit/tree/header pin with
unprepared artifact locks; publication remains blocked until a tagged candidate
supplies the complete source/header/adapter/artifact identity. Develop native adapter changes in the core's
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
checks. The signed iOS device app builds, but installation on the available
iPad fails because its device ID is absent from the signing profile. The owner
deferred physical Apple testing rather than registering the device; no device
registration or successful physical test is claimed. Android hardware is not
currently connected. Local universal Apple packaging and all eight Swift
platform builds now pass, together with 282 distribution-SDK tests and archive
structure verification. The local Xcode 27 check uses SwiftPM's native build
system for the unchanged macOS 11 minimum; canonical CI keeps Xcode 16.4.
These are local
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

The extended local ASan fuzz campaign completed all 13 targets, with 60 seconds
per target and **9,927,655 executions** without a crash. Its raw logs and corpus
are retained under `target/v08-fuzz-campaign`; the campaign began on the dirty
development tree and is not exact-candidate release evidence. The staged
Android SDK AAR and a separate minified Maven consumer both build, including
calls to the new import/capability APIs and all four native ABIs. The 60-case
performance smoke run passes; measured five-repeat acceptance remains open.

The physical Apple deferral leaves that release gate open. It is not a waiver
of device acceptance, does not authorize Apple Developer account changes,
and does not carry the old 0.7 device exceptions into this release.

### Initial clean-candidate automated and host measurements

Core commit `0250497b7f8aaca66b0086b95892558e7042cc98`, tree
`89b36701a9f1c6f26212cc8f00484a47b2d4db1b`, passes the complete
[workflow-dispatch CI run](https://github.com/aimalygin/xray-rust/actions/runs/36791055607):
Rust tests/lints/docs, pinned and independent Go oracles, release interoperability,
controlled-network checks, dependency/secret checks, Miri/Loom/ASan, Android
and Apple builds, Swift tests, adapter links and unsigned sample apps.
The exact-candidate ASan fuzz campaign completes all 13 targets at 60 seconds
each, with **28,661,647 executions** and no crash. Its corpus and the
controlled-network evidence were also retained locally under
`target/v08-ci-evidence` before the CI artifacts expire.

The same clean source and frozen release binaries pass the historical five-run
macOS pre-device budgets: 1000 idle flows use a median 23,360 KiB against a
25,000 KiB limit; direct TCP median latency is 42 microseconds against 55.
The v0.6 feature budgets also pass: VLESS encryption 297.34 MiB/s against a
253.36 MiB/s lower bound, IPOnDemand latency 0.218 ms against 1.217 ms, and
XHTTP peak-memory median 19.08 MiB against 64 MiB. Raw measurements and binary
identities are under `target/v08-performance/{pre-device,v06-features,builds.json}`.

The full new-protocol matrix completes **300/300 byte- and cleanup-verified
runs**: 60 Trojan/SS2022/VMess SOCKS/TUN cases with five fresh-process repeats.
`target/v08-performance/full` preserves every result and the verified summary;
`protocol-table.md` records each median and full range. Eight-flow TUN TCP
latency uses sequential flows, one concurrent flow, and includes the synthetic
packet driver. These host measurements do not establish competitor parity or
physical-device acceptance. Paired historical transport and Hysteria2/WireGuard
comparisons are collected separately against the published v0.7.0 binaries.

The distribution changes are reviewed in
[mobile SDK PR 33](https://github.com/aimalygin/xray-rust-mobile/pull/33).
Its initial core pin identified the measured source above; the current optimized
pin is recorded below. Artifact locks remain unprepared and no 0.8 package is
published by these checks.

### Full-client comparison with Xray-core and sing-box

The [dated comparison](benchmarks/results/2026-09-30-v08-protocols/README.md)
now contains **1050/1050 successful primary trials**, plus a final 210/210 smoke
matrix, using the unchanged frozen runtime above. Seven protocol/cipher
profiles cover one/eight SOCKS flows and upload/download/full-duplex/TCP echo/UDP
echo, with five repeats per client. Both references are full CLI clients:
Xray-core v26.7.28 and sing-box v1.13.20, built with Go 1.26.0. Bulk payloads are
256 MiB per flow/direction; matched client-first readiness is documented.

All 140 case/reference pairs have lower candidate RSS medians. Trojan meets
11/12 bulk throughput and 12/12 bulk CPU point targets under the existing 3%
Mac policy. All 72 SS2022/VMess bulk comparisons miss both speed and CPU targets.
Overall parity is **not met**; lower memory and passing traffic do not close
that performance gap. Every sample, deficit, paired interval and failed earlier
smoke attempt is retained in the report's verified numeric archive.

Driver-only fixes close a fixed-size warmup without relying on a reference's
half-close propagation and add the same client preface for every bulk client.
A separate Xray VMess AES-128 server-first upload failure remains documented.
The workload driver is frozen at `2d8afb6e6d9f601f0446aa74382f6e24dac9a7dd`;
benchmark/CI commit `04075f42bb500661246ae8dc590ef17d6285609b` passes
[complete CI](https://github.com/aimalygin/xray-rust/actions/runs/36803952030).
Product crates and the SDK core pin were unchanged by that comparison. It adds no
physical-device, TUN-competitor or publication acceptance.

### CPU optimization with bounded memory

Runtime `ce6deef3fe1b3f8536c471235dd2a6c003e7e9e5`, tree
`07005cb7084a48e6ef793f53b1cd442d69c1b35d`, addresses the measured ARM software
AEAD and repeated record-buffer allocation/erasure costs. SS2022/VMess reuse
the existing AWS-LC provider and bounded pending buffers, preserving plaintext
erasure, nonce/replay limits and cancellation behavior. No worker-count increase,
eager maximum buffers or global pool is introduced.

The [new CPU report](benchmarks/results/2026-09-30-v08-cpu/README.md) contains
630/630 passing full-client trials against the same pinned Xray-core/sing-box,
plus paired backend/buffer/worker controls and RSS scaling to 512 connections.
Paired eight-flow downloads use 68–89% less CPU than the initial runtime, with
0.06–0.20 MiB higher sampled RSS. At 512 held connections measured RSS is lower
than baseline. All 70 full-matrix cases still have lower RSS than both references.
SS2022/VMess meet 45/72 bulk CPU and 18/72 throughput point targets (3% policy);
one-flow and throughput deficits remain, so overall parity is still not met.

The [complete core CI](https://github.com/aimalygin/xray-rust/actions/runs/36811418960)
passes on this runtime, including pinned/independent oracles, host hardening,
fuzz smoke, controlled-network, release interoperability and Android/Apple builds.
All 120 local proxy tests and all-target clippy pass. Rebuilding gives the exact
measured executable hash. A separate PR run's VLESS fixture port collision
passed on rerun; the failure is documented in the report.

Mobile commit `f13776dca033514adb12864b2ddd301a77e4d551` pins this runtime and
passes [SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36811502022)
and source-sync verification. Prior pre-device, physical-device or artifact
evidence for `0250497` does not become evidence for this new source. Physical
Apple testing remains explicitly deferred, Android hardware is unavailable,
and artifact locks and release acceptance remain open.

### Record I/O and plaintext-erasure optimization

Runtime `5e32972976074551aea4ce42e98f5e0dde7159c9`, tree
`3c1993a1b1ce6ba68ea102caa6547346c8ac1c83`, removes read/write coupling under
backpressure, coalesces record reads within one bounded allocation and erases
delivered plaintext with aligned word-sized Zeroize stores. Volatile stores,
compiler fences, nonce/replay limits and authentication remain enforced. The
small aligned-slice conversion is covered by strict-provenance Miri; worker
counts and wire record limits are unchanged.

The [I/O and erasure report](benchmarks/results/2026-10-01-v08-io/README.md)
retains isolated backpressure/read/erasure controls, 144 paired final trials,
a five-repeat duplex confirmation and 24 memory clients measured through
512 held connections. Relative to the preceding `ce6deef` runtime, downloads
use 11–32% less CPU; one-flow AES downloads improve 52–61% in throughput.
Held-connection RSS rises by 0.016–0.094 MiB at 512 connections. Active peaks,
upload controls and the mixed initial ChaCha duplex result are also reported.

The full three-client matrix completes 629/630 trials, with all 210 Rust trials
passing. One sing-box Trojan UDP run times out; its two following primary runs
and a separate 15-run confirmation pass. The original failure remains in the
primary summary, making that reference group incomplete. All 139 complete RSS
comparisons remain below the references. SS2022/VMess meet 56/72 bulk CPU and
26/72 throughput Mac point targets (strict: 55 and 22); overall parity remains
not met. One-flow VMess and multi-flow ChaCha differences are quantified.

All 128 local proxy tests, clippy, formatting and the fuzzing feature check
pass. [Complete core CI](https://github.com/aimalygin/xray-rust/actions/runs/36899854548)
passes at this exact runtime, including pinned/independent interop,
Miri/Loom/ASan, fuzz smoke, controlled-network and Android/Apple builds.
Mobile commit `a735aae5e7916f18c0125afa28e509a9ddd48c2c` pins it and passes
[SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36899932350)
and core/source-sync checks. The committed release rebuild matches the measured
binary. All 1036 archived members rehash correctly and both parity summaries
recompute exactly from the archive. Physical Apple testing remains deferred,
Android hardware is unavailable, and publication artifacts remain unprepared;
previous source/device evidence is not inherited by this runtime.

### Relay allocation and VMess padding follow-up

Runtime `fdc0dad1aa1ffe39d3621008ab66512b30ccf452`, tree
`fec66ef23ea8512f97c123d090ca889a1501b77e`, keeps relay scheduling, activity notifications,
timeouts and buffer limits unchanged while pinning three futures in their
parent task. Only public VMess ChaCha record padding uses a 256-byte zeroizing
OS-entropy cache per thread; keys, IVs, authentication and nonces retain their
existing paths. No per-connection cache or dependency is introduced.

The [relay and padding follow-up](benchmarks/results/2026-10-01-v08-relay/README.md)
removes three relay future allocations and batches only VMess ChaCha record
padding entropy. Paired eight-flow VMess ChaCha upload uses 7.9% less CPU and
is 9.1% faster; settled RSS is 0.34–0.41 MiB lower at 512 held connections.
The larger relay rewrite and AES padding batching were rejected after throughput
regressions. All 630 three-client trials pass, including all 210 Rust trials.
RSS is lower in 140/140 complete reference comparisons; SS2022/VMess meet
57/72 bulk CPU and 26/72 speed point targets under the 3% Mac policy.
Overall parity remains **not met**. SDK commit `874cc8e` pinned
runtime `fdc0dad`; core/SDK CI and archived evidence reconstruction verified that
runtime. Candidate-bound device and artifact acceptance remained open.

144 fresh paired controls, a separate 20-trial SS2022 AES duplex confirmation,
24 held-memory clients and the 630-trial comparison
retain exact results, rejected alternatives and complete-block environment
retry provenance. Both parity summaries and control medians recompute from the
archive. The committed release rebuild has the measured executable's digest.
The first Linux FFI CI attempt hit a pre-existing descriptor-reuse test race;
the original failure is retained, the exact runtime is rechecked, and a separate
test-only fix removes the non-atomic close-before-dup2 setup. Local FFI validation
and the follow-up PR Rust/secrets jobs cover that fixture correction. See the report for all
identities and validation links.

Physical Apple acceptance remains explicitly deferred, Android hardware remains
unavailable and artifact locks remain unprepared. This host benchmark does not
establish physical-device energy, WAN or TUN competitor parity.

### Bounded VMess receive batching

Runtime `1804e17890baf4c3a587fbd86d6a17a0787ce9dd`, tree
`8501825d7a40170ca192269b9ec7657fbb721663`, batches at most two available
VMess TCP records into the caller's buffer. It returns immediately when a
following record would block, preserves UDP boundaries and plaintext erasure,
and defers a later record's error until the already authenticated prefix has
been delivered. The fairness bound and partial/error semantics have dedicated
tests. No crypto, nonce, dependency, ABI or worker-policy change is involved.

The [bounded VMess read follow-up](benchmarks/results/2026-10-01-v08-batch/README.md)
keeps at most two available TCP records per read. Independent controls show
10–12% faster one-flow AES download and 14–26% faster eight-flow download,
with lower CPU. After 1 MiB exchanges, settled RSS grows by 3.7–3.8 MiB at
512 connections (about 4%); short exchanges show no higher median RSS. The
16-record variant was rejected for 33–41 MiB extra RSS. Upload results vary
between campaigns, so no reliable upload improvement is claimed.
All 270 fresh three-client VMess trials pass, including 90 Rust trials; RSS is
lower in 60/60 reference comparisons. VMess meets 27/36 bulk CPU and 15/36
throughput point targets under the 3% Mac policy; parity remains **not met**.
SDK commit `a67a60c` pins runtime `1804e17`. The report retains every sample,
rejected variant, diagnostic trace and exact-runtime validation reference.
Physical-device and artifact acceptance remain open.

Local validation passes 133 proxy tests, 493 core library tests, all-target
proxy clippy, and ten pinned-Xray/independent-sing-box carrier, TUN/DNS/lifecycle
and Xray Mux integration tests. The committed release rebuild matches the
measured binary. The evidence contains 280 paired trials, 42 held-memory clients
with three warmup sizes, and the 270-trial VMess comparison. Native profiles
with symbols are diagnostic only; failed and rejected experiments remain
visible. The initial supply-chain CI job failed on a partial crates.io download;
its original log and exact-commit retry status are retained in the report.

### VMess AES syscall and relay census

The [84-trial diagnostic follow-up](benchmarks/results/2026-10-01-v08-census/README.md)
keeps runtime `1804e17` and SDK pin `a67a60c` unchanged. On one-flow AES upload,
the uninstrumented client spends about 76% of CPU inside the OS. Separate libc
observations show approximately 34.8k scalar writes and 34.3k `getentropy` calls
per 256 MiB, while Xray batches records into about 4.1k writes and uses
`arc4random_buf`. Both writers retain an approximately 8 KiB record limit.
Internal counts show about 2,059 relay transfers and 156 received activity
notifications, so idle-timer changes are a lower-priority hypothesis.

Next candidates are an isolated Darwin padding-source experiment and bounded
write batching under an explicit memory budget. Neither is implemented or
claimed faster by the census. Earlier rejected AES entropy-cache results are
retained; fewer calls alone do not prove an improvement, especially at eight
flows where Rust already uses less CPU in this diagnostic set. Any retained
runtime change still needs paired normal-release controls, 512-connection
retained-RSS checks and candidate-bound validation. The census verifies all
payload totals, preserves diagnostic patches, and confirms the restored normal
release remains byte-identical to the measured binary.
