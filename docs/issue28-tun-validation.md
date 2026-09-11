# Issue #28: TUN isolation repair and device validation

This follows the [initial iPhone experiment](issue28-iphone-validation.md),
which exposed shared TUN backpressure and unsafe buffering assumptions in the
XHTTP/H2-only candidate. Base source is v0.6.0,
`8a86a7f762aba919ff75cad5980a28612ba2dfe8`. The candidate includes the 4 MiB
H2 stream-window fix and the TUN changes described here. Measurements were
recorded on 2026-09-09 UTC.

## Behavior and memory bounds

The shared stack-event receiver stays active when a TCP flow cannot accept
data. Deferred events are retried once per pass; a blocked reader goes to the
back instead of stopping all TCP and UDP/control events. Each pass also
limits new events to the existing channel depth, so continuously active
producers cannot monopolize the main loop.

All TCP download producers, including fake DNS, DNS-outbound transfers and
parallel DNS hijack lookups, use the same per-flow delivery mechanism:

- A flow has at most one unacknowledged chunk, no larger than 64 KiB. The
  stack permits another chunk only when at least 64 KiB is available within
  a 256 KiB prefetch allowance. Copying data into smoltcp replenishes that
  allowance. This small pipeline hides scheduling latency without letting a
  stalled reader fill the previous multi-megabyte TUN queue. Admitted and
  deferred payload bytes together respect the per-flow prefetch limit.
- The bridge combines immediately ready reads up to 64 KiB before delivery,
  avoiding one stack/task round trip per H2 or TLS frame. It never waits for
  a batch to fill. EOF or an error observed after data is retained until those
  bytes are delivered.
- Complete DNS frames share a flow-local serial gate. Large frames are
  divided into bounded chunks without interleaving other DNS responses. The
  queued delivery retains the gate even if its sender is cancelled, so a
  cancelled writer cannot create additional deferred chunks for that flow.
- Download acknowledgement waits remain inside the bridge's select loop;
  upload, shutdown, host cancellation and idle timeout remain serviceable.
- FIN cannot overtake deferred bytes. Abort and stale-generation events
  release their deliveries; a reused socket handle does not inherit old data.
- Existing per-flow/global TCP byte policies, upload accounting, pressure
  hysteresis, active-flow limits, protocol settings and the public ABI remain
  unchanged. Deferred chunks are outside the existing admitted-byte counter
  but are bounded by admitted producers (one chunk per TCP flow generation,
  plus bounded transient stale events awaiting the next drain).

This is not a process-memory bound. smoltcp still owns two 32 KiB buffers per
TCP socket, remote readers and upload queues retain their own bounded
storage, and TLS/H2/QUIC allocate independently. H2's connection receive
window remains 16 MiB: four completely unread 4 MiB responses can still
exhaust it. The separate H2 flow-control test covers this limit; a successful
four-reader device scenario does not remove that protocol-level limit.

An intermediate implementation acknowledged immediately on queue admission.
It restored neighboring progress, but the iPhone's three-reader stage
reached 36.141 MiB and triggered the deliberately lowered 35 MiB probe stop.
That intermediate implementation was superseded by bounded prefetch. Its
evidence is retained as `tun-35`, not reported as a passing campaign. A
single-chunk, 16 KiB prefetch variant then passed the isolation campaign, but
five-transfer median times were about 11–13% longer than the old TUN in that
exploratory comparison. This motivated a 64 KiB pipeline and fresh speed
comparisons. H2 retained its throughput,
but ten raw TCP transfers per variant, with the second pair in reverse order,
confirmed a median increase from 0.571 to 0.663 seconds (16%). The final
candidate therefore allows reads/chunks up to 64 KiB and a 256 KiB prefetch
pipeline; it keeps the same per-flow delivery and cancellation discipline.
Upload/UDP read sizes remain unchanged. With those larger reads alone, raw
TCP matched its fresh control (0.489 vs 0.491 seconds), but H2 still took
0.745 vs 0.596 seconds. The final implementation additionally coalesces
immediately ready frames; it was rebuilt and revalidated after that change.

## Regression tests

`tun_backpressure_tests.rs` covers independent TCP/UDP and close events,
bounded delivery during cancellation, complete-frame ordering, combined
upload/download budget pressure and recovery, stale generations, and FIN
ordering with an established smoltcp socket, checks that ready-frame batching preserves EOF/errors without waiting,
and that prefetch stops
at 256 KiB and resumes only after stack progress. The first isolation test was
run before the repair and failed because the neighboring open event was never
applied.

The new `runtime_data_path_tests/tun_download_backpressure.rs` test uses a
real runtime, local TCP/UDP servers and a smoltcp client. It stops reading an
8 MiB response, verifies bounded prefetch, sends upload data on that same
connection, performs a UDP round trip and UDP cancellation, opens another
TCP connection, verifies every byte of its 64 KiB response before EOF, and
cancels the stalled flow through the public connection API.

Validation on the final production source:

- Workspace: **2,189 passed, 0 failed, 45 ignored**, including the TCP/UDP
  integration test and all nine new unit regressions.
- Local pinned Xray-core interoperability: **20 passed**, including the
  15-case XHTTP H1/H2/H3 mode/security matrix, gRPC, WebSocket, HTTPUpgrade,
  TLS, REALITY/Vision and routing/chaining.
- Workspace Clippy with all targets/features and warnings denied, API docs
  with warnings denied, formatting and whitespace checks passed.

Final-source logs: `target/issue28-tun-{workspace,interop,clippy,doc}.log`.
Earlier focused/integration and test-only Clippy logs are also retained.

## Physical device: final candidate

Physical iPhone 13 / iOS 18.6.2, release Rust static libraries with a Debug
Swift host/extension, actual fd-backed mobile TUN. The stand and armed-reader
sequence match the earlier experiment: two cycles with 1/3/4 readers that
stop consuming, a neighboring 1 MiB download at each stage, cancellation of
one reader and another download, then connection cleanup and recovery.
XHTTP/H2 has 113 ms added round-trip delay; raw VLESS/TCP is a separate local
control without that delay. Both use a 35 MiB probe stop in this campaign.

| Observed result | XHTTP/H2 (`final-batched-h2`) | Raw VLESS/TCP (`raw-final-batched`) |
| --- | ---: | ---: |
| Neighbor downloads with 1/3/4 stalled readers | 6/6 passed | 6/6 passed |
| Downloads after cancelling one reader | 2/2 passed | 2/2 passed |
| Observed peak extension footprint | 24.594 MiB | 3.688 MiB |
| Final recovery footprint, median | 4.172 MiB | 3.203 MiB |
| Observed peak extension RSS | 55.750 MiB | 19.641 MiB |
| Safety stop, payload errors or runtime replacement | None | None |

The previous H2-only candidate had eight timeouts in these eight checks and
42.422 MiB observed peak footprint. Its raw control also had eight timeouts.
The final candidate completed both full sequences with zero traffic errors;
final active TCP/UDP counts were zero. As before, footprint is
`TASK_VM_INFO.phys_footprint`, not RSS; these are sampled maxima. Polling
gaps, background device traffic and retained allocator pages limit direct
memory comparisons. Two short cycles are not a proof of OOM safety or an
unbounded-concurrency guarantee. Bridge logs show two H2 connections in each
armed-reader run; this is not a guarantee that four fully stalled responses
on one H2 connection leave room for a fifth. The dedicated transport test
explicitly verifies exhaustion and cancellation recovery at that limit.

## Final throughput comparison

The same performance harness was installed with the original TUN plus the
4 MiB H2 window (control), and with the final TUN repair. Each run performed
one 8 MiB warmup, then five separately verified 8 MiB downloads without
stalled readers. All host builds/tests had finished before this comparison.
H2 ran candidate then control; raw ran control then candidate. The H2 delay
line and raw local path are the same as above; do not compare the carriers
as if they had the same RTT.

| Carrier | Control median (range), seconds | Final median (range), seconds |
| --- | ---: | ---: |
| XHTTP/H2 | 0.685 (0.601–0.709) | 0.632 (0.589–0.675) |
| Raw VLESS/TCP | 0.571 (0.506–0.581) | 0.557 (0.467–0.592) |

All payloads passed verification. This bounded comparison did not reproduce
the intermediate candidates' slowdown. The ranges overlap, so it is not
evidence of a general speedup; five trials on local Wi-Fi do not establish
WAN/CDN, high-concurrency or every-protocol performance. Exact trial times
are in `performance.json` and the `*perf-batched*-device.log` files.

Both columns above use Rust clients. A later, separate
[Rust versus Go client experiment](issue28-client-comparison.md) uses the
same Mac for both engines and does not run through the iPhone TUN.

## Reproducibility

`target/mobile/issue28-tun/` retains the two harness sources, stand, runners,
source snapshots, release static library, installed builds, console/build
logs and generated summaries. `manifest.json` records SHA-256 identities.
`artifacts-first/` holds the superseded admission-acknowledgement candidate;
`artifacts-16k/` holds the single-chunk prefetch experiment, and `artifacts/`
holds the final 256 KiB prefetch candidate with ready-frame batching.
`artifacts-unbatched/` retains the 256 KiB pipeline before that last change. `artifacts-64k/` retains the
intermediate 64 KiB pipeline and its smaller read size. Private fixture
profiles are not publication artifacts. No production Apple adapter or user
profile source was changed for the probe.

Cleanup removed the separate `Xray Issue28 Probe` VPN manager, its secure
configuration reference and the probe's device log files. The existing
manager remained (one manager after cleanup). The normal UI build with the
baseline v0.6.0 Rust library was installed and launched again; this restores
an ordinary baseline build, not a byte-identical copy of the app previously
installed on the phone. The local stand and its child servers were stopped.

Whole-TUN output suspension is outside this slow-reader campaign. The
existing `PacketDevice.outbound` deque has no intrinsic byte cap, so sustained
UDP delivery while the host stops draining all TUN output remains a separate
egress-memory concern; this patch does not add that queue or establish its
memory safety.

No release, remote push or issue comment is part of this work.
