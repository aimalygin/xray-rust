# v0.8 release readiness

Reviewed on 2026-10-04. Development implementation is ready for candidate
acceptance; **release acceptance is not complete**. Required scope is Trojan,
Shadowsocks 2022 (all three methods) and VMess AEAD in the core and both SDKs.
Shadowsocks AEAD-2017 and legacy VMess authentication remain excluded.

## Reviewed source and evidence

The code review covers core `1185511dc5ed3425ba4839b4ebe38d31a89c1263` and SDK
`04ccf8accd5ea793ac43fe8415a03a8e44dc8ef4` in draft
[PR42](https://github.com/aimalygin/xray-rust/pull/42) and
[PR33](https://github.com/aimalygin/xray-rust-mobile/pull/33). Review focused on
the new protocol codecs/importers, record bounds and authenticated delivery,
UDP replay/cancellation, Mux admission and cleanup, VMess direction migration,
Core.stop, ABI capabilities, endpoint bootstrap and canonical SDK source sync.
No additional runtime defect was confirmed in those paths. This is a targeted
source review, not an independent security audit or a physical-device result.

The review found a candidate metadata gap: SDK version `0.8.0-rc.1` was paired
with workspace version `0.7.0`, preventing the v0.8 evidence workflow's version
check from passing. Candidate preparation aligns the workspace/lockfile version
dated changelog and generated configuration contract. Runtime sources, dependencies and ABI remain those reviewed
above; the SDK must pin the resulting exact commit/tree and lockfile hash.
The version change produces a new binary identity. Earlier measured binary
hashes remain historical evidence and must not be relabeled as the new candidate.

Local review validation: 504 core unit tests pass (two manual tests remain
ignored), including the eight adaptive relay tests and Mux/lifecycle tests;
53 evidence-policy tests and 28 SDK policy tests pass. Release-version fixture
checks and all four configuration-contract tests pass, and the aligned
workspace selects evidence profile `v08`. The first new-candidate CI attempt
identified a stale generated `coreVersion`; regenerating the contract changed
only that version field and restored the snapshot test.
The initial sandboxed core attempt could not bind local sockets; rerunning
with local networking passed all 504 tests. No product failure was suppressed.
All 13 lockfile changes are local workspace versions; dependency entries are
unchanged. New candidate CI results must be retained separately from the
earlier successful runs linked below.

Completed evidence at the reviewed revisions:

| Area | Evidence and limit |
| --- | --- |
| Core automated checks | [PR CI](https://github.com/aimalygin/xray-rust/actions/runs/37087744606) and [full CI](https://github.com/aimalygin/xray-rust/actions/runs/37088048492) passed, including Apple/Android, pinned oracles and interoperability, supply-chain, hardening, fuzz and controlled-network jobs. These run identities belong to `1185511`, not a later commit. |
| SDK checks | [SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/37087816527) passed Apple, Android, metadata and secrets at `04ccf8a`; local exact-core and canonical-source checks also pass. These are source/CI consumer checks, not published-package or device acceptance. |
| Runtime controls | Shared codec tests cover malformed records, nonce exhaustion and partial writes; relay tests cover quota, quiet migration, half-close and cancellation. Core and pinned live interop checks are recorded in the [adaptive relay report](benchmarks/results/2026-10-02-v08-adaptive-relay/README.md). |
| Performance | [Performance history](v08-performance.md) retains each tested runtime, failures and controls. Final ChaCha single-flow duplex improves speed 58–60% and CPU 10–11%, costing 0.92–1.11 MiB across 512 held connections and 13–27 microseconds of eight-flow p95 latency. AES single-flow duplex remains 22.6% slower than Xray; the owner accepted retaining this implementation for 0.8. No universal or device parity is claimed. |

The frozen runtime candidate is core `de33998158e84c03f280f979ba2d4212072e5bc4`
and SDK `0148543fef8736e01625bc678ca321cc483e1e12`. Its
[ordinary core CI](https://github.com/aimalygin/xray-rust/actions/runs/37136652768),
[full core CI](https://github.com/aimalygin/xray-rust/actions/runs/37136753222) and
[SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/37136753055)
passed. The [2026-10-03 physical iPhone report](device-results/2026-10-03-iphone17-v08/README.md)
records fresh binaries built from that exact candidate: LAN cipher/lifecycle
checks and WAN Trojan/VMess transitions passed. Original SS2022 WAN IPv6 UDP
failed; Go controls reproduced the network size/DF dependence. SS2022 transition
success requires the report's explicit diagnostic fragmentation relay. All
failures and limits remain visible; this is not full device/release acceptance.

The [2026-10-04 iPhone follow-up](device-results/2026-10-04-iphone17-lifecycle-resources/README.md)
uses the same Rust library and SDK sources on iOS 27.0.1, with DEBUG reference-app
instrumentation. Startup cancellation and rapid restarts passed for every new
cipher configuration. Bounded extension CPU/footprint measurements and legacy
controls are retained with their actual workloads and thermal states. An initial
Trojan TCP timeout and two intermittent WireGuard failures remain failed despite
passing controls; the latter prevents claiming clean legacy acceptance. The
collector's separate console-interleaving interruption is also retained. These
changes do not repin the native runtime or establish complete performance gates.

## Remaining acceptance, in order

- [x] Freeze the runtime candidate commit/tree and SDK pin after metadata/source
  review, and pass its ordinary/full CI. The identities and runs are above.
  Later documentation does not relabel these binaries; any runtime/build-input
  change requires reassessing applicability and collecting fresh evidence.
- [ ] Complete Apple device acceptance for Trojan, SS2022 and VMess. The owner
  supplied an iPhone already covered by signing; the bounded checks above are
  complete. Resolve the SS2022 production-path/MTU condition and intermittent
  WireGuard failures, investigate the isolated Trojan timeout, and finish the
  remaining calibrated performance/evidence requirements. Bounded cancellation,
  restart and resource observations are linked above; their limits remain open. The
  separate unregistered iPad remains deferred; no account change was made.
- [ ] Collect Android scenarios for each protocol through both FileDescriptor
  and PacketPump. Android hardware was unavailable at the last acceptance
  attempt; host tests and emulator results do not close this device gate.
- [ ] For each protocol/device path, record IPv4/IPv6 TCP and UDP, domain
  destinations, routed DNS, start/stop, cancellation, reconnect, Wi-Fi/cellular
  transitions, lock/wake and bounded resource recovery. Include profile imports,
  redacted failures and the shared legacy scenarios. There is no fixed-duration
  long-soak requirement; record actual durations and limits.
- [ ] Assemble the exact-candidate schema-4 archive required by
  [check-v08-release-evidence.py](../scripts/check-v08-release-evidence.py):
  hashed resource profiles, sanitized logs, transition timelines, raw benchmark
  and build data, protocol comparisons and known limitations. Include at least
  five clean samples per required performance metric and explicit budgets.
  Preserve older benchmark identities; collect missing candidate-bound samples
  instead of presenting old measurements as a new run.
- [ ] Validate that archive locally and with
  [v08-release-evidence.yml](../.github/workflows/v08-release-evidence.yml) on
  the same candidate. Prior schemas and 0.7 release exceptions do not satisfy
  this gate. No accepted 0.8 archive is recorded yet.
- [ ] After the release decision and verified core tag, prepare canonical
  XCFramework/SwiftPM and four-ABI AAR artifacts from the exact SDK/core
  pins. Verify source provenance, headers, symbols, platform slices and checksums,
  then run clean package-consumer checks, including the locally staged Maven
  consumer. An RC remains GitHub-only; remote Maven publication is a stable
  release step. Current SDK artifact locks are
  intentionally unprepared; a local or CI build is not the publication lock.
- [ ] Obtain the owner's merge/publication decision. Both PRs remain drafts;
  no tag, merge, registry publication or GitHub release is authorized here.

The current v0.8 device/performance evidence gate is defined by code in
`scripts/check-v08-release-evidence.py` and its shared validator. The SDK
[release procedure](https://github.com/aimalygin/xray-rust-mobile/blob/codex/v08-sdk/docs/releasing.md)
defines artifact ordering. Unsupported combinations and resource/nonce limits
remain in [configuration compatibility](config-compatibility.md).
