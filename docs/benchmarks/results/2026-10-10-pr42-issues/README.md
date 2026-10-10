# PR42 issue follow-ups: transport options and TUN admission

This evidence measures `2d45346` (Android rebind and configurable Hysteria
budgets) and `1799432` (optional TUN admission) against `5ebcad0`. The baseline
binary is the previously validated `3f07fa7` runtime; `5ebcad0` changes only
documentation. Stage 3 measures `8e003d3` (Salamander and port hopping).
Stage 4 is `c26eb54` (bounded ClientHello fragmentation). The final runtime
follow-up is `c81927f`, which releases expired pending UDP admission buffers.
The reference remains Xray-core v26.7.28 at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

## Functional checks

- Stage 1 workspace: 2,438 passed, 93 ignored; strict Clippy, Swift (330 tests),
  JNI, and live Xray/native Hysteria checks passed. The raised-budget test opens
  96 TUN TCP flows on one session and verifies recovery/release at the limit.
- Stage 2 workspace: 2,451 passed, 93 ignored. After the final disabled-policy
  TCP task-allocation refinement, all core/FFI unit and runtime data-path tests
  passed again (727 passed, 16 ignored), as did strict Clippy and live pinned
  Hysteria checks. Swift (331 tests), actual JNI admission callbacks and the
  repository-script checks passed. Ignored tests are external/manual gates,
  not results counted as passing.
- Admission is checked before TCP upstream dial and before UDP routing, DNS or
  FakeDNS handling. Tests cover explicit denial, timeout policy, a blocked host
  callback during close, IPv6, cached UDP verdicts and bounded resource pressure.
- Stage 3 workspace: 2,456 passed, 98 ignored across 94 test executables;
  strict Clippy, repository scripts, and both pinned Xray/native Hysteria
  carrier matrices passed. The tests include protected rebind, automatic
  hopping, Salamander TCP/inner-TLS/UDP, wrong-password rejection and a complete
  1472-byte carrier receive. Final core/config rerun: 1,172 passed, 70 ignored.
- Stage 4 workspace: 2,467 passed, 102 ignored; strict Clippy and all
  repository-script checks pass. The fragment unit tests check
  unchanged handshake payloads, exact record lengths, zero-delay coalescing,
  partial writes, bounded delays and cancellation. Protected-socket tests check
  TCP/TLS/REALITY failure before connect. Four live pinned-Xray cases pass:
  FinalMask TLS, TLS Vision, REALITY Vision, and legacy freedom `dialerProxy`
  REALITY Vision. A relay observes actual ClientHello record lengths; inner
  TLS and a 256 KiB verified transfer survive Vision direct mode.

The first `c26eb54` Linux CI Rust job failed in the existing DNS benchmark
fixture: its UDP-selected ephemeral port was already occupied in the separate
TCP namespace (`AddrInUse`). The follow-up retries a bounded 32 fresh socket
pairs and adds a deterministic held-TCP-listener collision test. It changes
fixture allocation in `xray-bench`, not the core or the workloads measured
below. Stage 4 retains its frozen `c26eb54` source/binaries; the final
accounting follow-up and its new measurements are identified separately.

A final review found a pending-admission accounting edge case: if an executor
is paused long enough for UDP idle expiry, a new packet can remove the old
pending entry before its timeout/completion is consumed. `c81927f` releases
that entry's buffered-byte budget on removal. A deterministic regression test
first failed (18 accounted bytes instead of 6), then passed after the fix; it
also verifies that the old decision cannot admit the replacement flow. All
523 core unit tests and 190 runtime tests pass (16 external tests ignored),
as does strict core Clippy. This path is only entered when admission is enabled.
The four live fragmentation cases also pass again on this final runtime and
are now selected by `check-v08-carrier-interop.sh` in ordinary PR CI.

## Physical Android check

`android-admission.json` retains a sanitized six-case before/after matrix from
a Samsung SM-A145F, Android API 35, using the exact `1799432` native/adapters
revision (not the later `c26eb54` binary). The VPN captured only the dedicated test
application. An excluded test application successfully bypassed that allowlist
with `SO_BINDTODEVICE` when admission was disabled. With admission enabled,
excluded TCP reset and excluded UDP timed out, with **no connection/datagram at
the controlled destination**. Ordinary included TCP/UDP and included bound UDP
continued to echo all 31 scheduled bytes.

Android returned `INVALID_UID` for included **bound TCP** too, so the strict
unknown-owner policy correctly denied that case. This device limitation is
explicit; the test does not establish universal UID visibility on every OEM.
The VPN was disconnected after testing, and the three newly created test
applications were uninstalled. Probe-launch retries and private
device identifiers/endpoints are described but not published in raw logs.

## Performance

Each full Hysteria matrix has five alternating fresh-process pairs for eight
Hysteria cases: TUN upload/download/duplex and SOCKS UDP, each with one/eight
flows. Bulk validates 1 GiB per direction; UDP validates 1,000 messages of
1,200 bytes per flow. Both versions use one frozen harness and a fresh common
server per pair. Source/binary hashes, compiler-load observation, process cleanup,
CPU, RSS, throughput and distributions are retained. These are shared-Mac
loopback observations, not device energy or all-network release acceptance.

Stage 1's full campaign passed 79/80 runs. Eight-flow candidate UDP repeat 3
timed out at 120 seconds. It remains a failure in the original summary; its
cause was not established. A subsequent same-binary A/A control passed 20/20
runs, and a separate expanded A/B group passed 40/40. The latter's candidate
median throughput was +0.52%, CPU/byte unchanged and median latency +0.41%.
These follow-ups do not erase or explain the original timeout.

Stage 2's complete campaign passed 80/80. TCP median throughput changes ranged
from −1.16% to +0.50%, with CPU/byte from −0.14% to +1.56%. Eight-flow UDP was
−3.00% throughput and +3.85% CPU/byte (a 10 ms CPU-counter step); its full
distribution remains visible. No zero-regression guarantee is inferred from
this short host campaign.

A subsequent stage 2 UDP group used 10,000 messages per flow to improve the
CPU-counter resolution. All 10 runs passed: throughput −1.80%, CPU/byte +0.86%,
median latency +0.86%. It is a separate workload, not extra primary repetitions.

Stage 3 passed all 80 Hysteria runs. TCP throughput changes were −0.59%..+3.63%,
CPU/byte −2.24%..+0.48%; UDP CPU/byte was unchanged, throughput +1.50%/+4.67%.
The separate 40-run ordinary TLS/REALITY Vision TUN duplex matrix passed too:
throughput −0.49%..−3.96%, CPU/byte −0.78%..+1.56%. These feature-disabled
loopback results retain the distributions and do not measure hopping under
mobile network loss or the cost of enabled Salamander encryption.

Stage 4's ordinary TLS/REALITY Vision TUN matrix passed 40/40 runs: median
throughput approximately unchanged to +3.18%, CPU/byte −1.16%..0%, RSS −4.21%..+4.47%.
The earlier stage 3 Vision eight-flow throughput dip did not reproduce in
this final-source matrix. Complete final Hysteria TCP cases measured throughput
−2.87%..+0.86% and CPU/byte −1.26%..+0.72%. The final Hysteria group passed 79/80: candidate
UDP eight-flow repeat 3 again reached the 120-second deadline. This is retained
as a second failure, not reclassified as benchmark noise or a passing result.
Separate diagnostic controls with a 15-second local deadline and system UDP
counters investigate baseline/candidate behavior; they do not replace either
primary campaign. Both completed without failures: same-binary A/A 40/40,
then baseline/candidate A/B 40/40. No checksum or full-socket-buffer UDP drops
were observed during those controls. Global no-socket drop counts belong to
the shared host and cannot attribute a loss to the test processes.

A separate sequence-instrumented A/A diagnostic completed 100 runs, with one
failure on the original baseline binary (repeat 20, baseline label). For its
failed flow, request sequence 1 reached the echo destination and the echo
socket successfully sent the reply; the SOCKS client received no reply within
five seconds. The other seven flows completed all 1,000 round trips. Thus this
symptom also occurs before the issue changes. The observation localizes that
failure after the echo send, but does not identify the downstream component,
prove the same cause for the two primary timeouts, or establish a changed loss
rate. No engine fix or automatic UDP retransmission is inferred from it. The following
fixed-size A/B sequence campaign passed 100/100 (50 baseline, 50 candidate).
Sequence/counter instrumentation and the five-second reply deadline are
retained as a patch with provenance; diagnostic timings are excluded from the
performance comparisons.

Enabling fragmentation (`length=100-200`, `delay=1 ms`, `maxSplit=32`) on the
same final binary passed 40/40 TLS/REALITY Vision duplex runs. Compared with
that binary's disabled option, median throughput changes were −2.25%..+1.37%,
CPU/byte −0.90%..+0.60%, RSS −0.31%..+2.57%. This checks sustained 1 GiB transfers;
configured per-fragment delays intentionally add first-handshake latency.
It does not establish behavior on a particular DPI network.

The final `c81927f` ordinary TLS/REALITY Vision rerun passes 40/40: throughput
−2.34%..−0.73%, CPU/byte −1.56%..−0.30%, RSS −2.50%..0%. It is a separate
campaign on the exact buffer-accounting follow-up, not pooled with stage 4.
The same final binary passes all 80 Hysteria runs: TCP throughput
−2.00%..+2.80%, CPU/byte −9.60%..+0.41%, RSS −1.49%..+4.32%. UDP one/eight-flow
throughput is +0.80%/+1.18%, CPU/byte 0%/−3.85%, latency 0%/+0.83%.
These passing repeats do not resolve the earlier UDP failures. The larger
CPU improvement in eight-flow upload is an observation, not an optimization
claim for the unrelated admission accounting fix.

The separate `xray-bench tun-admission` run alternated five pairs of 1,000 new
TCP flows, with 50 warmups per batch. A no-op callback added 8.33 µs to the
median batch p50 connect-to-first-verified-byte latency (71.67 → 80.00 µs).
Every enabled batch made exactly 1,050 callbacks and every disabled batch zero.
This measures the dispatch overhead once per new flow; Android UID lookup and
established-flow throughput are different measurements.

`measurements.tar.gz` contains the original manifests, raw performance results,
summaries, collector and selected validation logs. Configuration requests,
credentials, certificate keys and raw private device logs are excluded.
`evidence-index.json` hashes each member. `summaries.json` retains complete and
incomplete campaigns separately; controls must not be counted as repetitions
of the primary campaign. CI results belong to each exact pushed revision.

## Replaying the host controls

Extract `measurements.tar.gz` and use the collectors in `collectors/` with
`--root`, `--output`, `--case` and `--repeats` as recorded in each manifest.
The root layout contains clean `baseline/` and `candidate/` source checkouts,
`bin/baseline/{xray-rust,xray-bench}`, `bin/candidate/xray-rust`, and the pinned
`bin/xray-core`. Build each engine in release mode before starting collection;
leave Go/Tokio worker and GC overrides unset. The collector creates fresh
local-only fixture credentials and rejects overlapping compiler processes or
surviving test processes. Keep failed campaigns and follow-ups in separate
output directories. Source and binary identities must be recorded again on
another machine; timings are not portable expected values.

The sequence diagnostic uses the separate harness patch and provenance in
`diagnostic/` and requires `--harness`. Its payload stamps, echo counters and
per-response timeout change the workload; its timings are excluded from
performance comparisons. The production engine binaries are unchanged.
