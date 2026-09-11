# Issue #28: initial physical iPhone validation

Measured on 2026-09-09 UTC (2026-09-08 device local time).

This report retains the original transport-only candidate's failed campaign.
The subsequent TUN repair and repeated measurements are recorded in the
[follow-up validation](issue28-tun-validation.md).

**The 4 MiB XHTTP/H2-only candidate was not cleared for release.** The physical
device confirms the single-download improvement, but also substantially
higher observed memory use and a cancellation-recovery failure in a TUN
stalled-reader scenario. The latter was absent from the transport-only tests.

## Setup and scope

- Physical iPhone 13, iOS 18.6.2, connected to Xcode by USB. Traffic traversed
  Wi-Fi to a local Mac; USB was used for installation and console capture.
- Baseline core: `8a86a7f762aba919ff75cad5980a28612ba2dfe8` (v0.6.0).
  Candidate: the same source plus only the receive-window change in
  `crates/xray-transport/src/stream/xhttp/h2.rs`. Both Rust static libraries
  were built with `cargo build -p xray-ffi --release --target aarch64-apple-ios
  --locked --offline`, Rust 1.96.0, deployment target 15.0. Swift host and
  NetworkExtension used identical Debug build settings and probe source.
- Actual fd-backed Packet Tunnel, mobile TUN runtime profile, debug logging
  disabled. Memory came from the extension process, not the foreground app.
- Local pinned Xray-core `5ca6f4b7d4dc20a881d4330e498892697627ec0c`, with the
  repository's Go TLS/H2 bridge and a loopback payload server. VLESS,
  XHTTP `packet-up`, pinned TLS certificate, ALPN `h2`, `xmux.maxConnections=1`,
  long reuse lifetime. The trace contains two H2 connections per run
  (separate request uses); the setting is not a claim that all memory belongs
  to one connection. Connection receive credit remained 16 MiB each.
- A bounded, pipelined delay line added 56.5 ms in each direction. Thus
  **113 ms is added delay**, plus actual local-network and processing time.
  This is a controlled local experiment, not a WAN/CDN or cellular benchmark.
- Only the synthetic target was routed to the local payload server. Other
  device traffic was routed to an unavailable local endpoint. Background
  attempts still entered TUN; observed active-flow counts are not exclusively
  the four intentional readers and were not identical across runs.

The bridge captured baseline `SETTINGS len=0` (the protocol's default 65,535
bytes) and candidate `INITIAL_WINDOW_SIZE=4194304`. Both advertised the same
connection `WINDOW_UPDATE` increment, 16,711,681. This verifies that the
intended library variants actually ran on the phone.

## Workload and measurements

After five seconds idle, the app downloaded 8 MiB and checked every byte.
It then opened four TCP connections and consumed each server's ready marker
before starting any flood. In each of two cycles it activated one, three,
then four readers that stopped consuming data; each server attempted 64 MiB.
Each stage waited eight seconds and attempted a separate 1 MiB download.
Next it cancelled the first stalled reader, waited three seconds, and retried
the neighboring download. Finally it closed all test sockets, requested
active-connection cancellation, and observed recovery for 15 seconds. A
further 15-second recovery interval ended the run.

Socket reads had a four-second inactivity timeout, not a four-second total
transfer limit. A successful download validated both length and payload.
The harness continued after a neighbor timeout to collect later memory and
recovery data: its `completed` marker means **the sequence finished**, not
that every traffic assertion passed.

The probe requested runtime stats approximately every 0.5 seconds. RSS is
`MACH_TASK_BASIC_INFO.resident_size`; footprint is `TASK_VM_INFO.phys_footprint`.
The latter is not interchangeable with RSS. IPC sampling is not continuous:
the baseline had a 19.18-second sampling gap around the single download, and
stalled-download checks also delayed samples. All peaks below are **observed
sample maxima**, not guaranteed lifetime maxima. A 45 MiB footprint threshold
was a probe safety stop, not an asserted iOS memory limit.

| Metric, armed-reader run | Baseline, 64 KiB | Candidate, 4 MiB |
| --- | ---: | ---: |
| Single 8 MiB download, including opening | 18.551 s | 1.118 s |
| Idle footprint, median | 3.172 MiB | 3.000 MiB |
| Observed peak footprint | 14.063 MiB | 42.422 MiB |
| Observed peak RSS | 36.188 MiB | 72.453 MiB |
| Final recovery footprint, median | 3.407 MiB | 4.797 MiB |
| Final recovery RSS, median | 36.188 MiB | 52.438 MiB |
| Neighbor checks with 1 / 3 / 4 stalled readers | 6 timeouts / 6 checks | 6 timeouts / 6 checks |
| Neighbor check after cancelling first reader | 2 successes / 2 checks | 2 timeouts / 2 checks |
| Safety stop or observed runtime replacement | None | None |

The candidate's single-download time was about **16.6 times shorter** in this
run. An earlier exploratory run measured 19.696 s versus 1.120 s, but that
version of the harness could not open later readers once the first reader
blocked TUN. It is retained as exploratory evidence, not counted as another
completed stalled-reader campaign.

Candidate footprint reached 39.907 MiB in cycle one and 42.422 MiB in cycle
two, with both maxima during cancellation. After closing all flows the
reported footprint fell, and final active TCP/UDP counts were zero. RSS
remained elevated; this does not establish that all allocations or resident
pages were returned. No extension termination, runtime-identifier change,
payload mismatch or 45 MiB safety stop was observed. Two short cycles do not
establish OOM safety, absence of leaks, or performance with many H2
connections. Different background attempts and sampling gaps also prevent
treating the peak difference as an exact per-window allocation cost.

## Additional TUN bottleneck

The behavior has a corresponding mechanism in unchanged
`crates/xray-core-rs/src/tun.rs`:

1. `try_apply_stack_event` rejects `RemoteData` when a per-flow or global
   queue budget is full.
2. `apply_or_delay_stack_event` puts that event at the front of
   `delayed_stack_events`; `drain_stack_events` immediately returns if the
   front event still cannot be admitted.
3. The main loop disables `stack_rx.recv()` while a delayed event exists.
   Other flows' data, open/close notifications and UDP events share that
   channel, so one stalled reader can prevent unrelated progress.

The six neighbor failures occurred on the original core as well as the
candidate. However, cancellation recovered the baseline neighbor twice and
did not recover the candidate neighbor within either inactivity timeout.
Larger receive credit therefore **amplifies an existing isolation defect**;
the observed recovery regression must not be dismissed because the root
mechanism predates this patch. Transport-only H2 cancellation and isolation
tests bypass TUN and cannot establish end-to-end isolation here.

A control used the same candidate executable and armed-reader harness over
ordinary VLESS/TCP, without XHTTP, TLS/H2, or the added delay line. It also
produced six neighbor timeouts and two post-cancellation timeouts across the
two cycles. The initial 8 MiB transfer succeeded in 0.502 s, observed peak
footprint was 7.563 MiB, and final recovery footprint was 3.328 MiB with no
active TCP/UDP flows. This isolates the failure from H2 receive-window policy;
its throughput is not an A/B comparison because that path has no injected
113 ms delay. See `raw-control-device.log` and the `raw-control` summary.

The required repair had to preserve ordering within each flow while allowing other
flows and control events to progress, with bounded per-flow and aggregate
memory. Merely draining the shared channel into an unbounded deferred queue
or raising every memory budget is not an acceptable repair. A deterministic
TUN regression should cover a slow reader, neighboring TCP progress, UDP and
close events, cancellation, and queue-budget pressure; physical A/B should
then be repeated on the resulting candidate.

## Local evidence

The ignored local directory `target/mobile/issue28/` retains the exact probe
source (`artifacts/Issue28Probe.swift`), `stand.py`, `run-device.py`,
`summarize.py`, both static libraries, installed app builds, build/install
logs, console logs, `summary.json`, and `manifest.json`. The manifest records
SHA-256 identities of the libraries, extension executables and harness.
The private local profiles contain ephemeral fixture credentials and are not
publication artifacts. The summary can be regenerated with:

```sh
python3 target/mobile/issue28/summarize.py
```

| Artifact | SHA-256 |
| --- | --- |
| Baseline Rust archive | `ee5ed7dd8ca45df512c7f36b905deee72accc31478b1f4ca2086f6403b0b876b` |
| Candidate Rust archive | `52a0f856e4d932d2b802291ca9d5ef3bd049acb9ce7c9ae20ebf1d4b916965b4` |
| Armed-reader Swift probe | `a1d0b8a966fad92b15fe6551f4c1b3446692cfdb103810599237a03f555ee6e8` |

The Swift Debug builds emitted a `default.profraw` write-permission warning
on exit. Coverage output was not used for these measurements; the console
and synchronized JSON measurements were captured successfully. This warning
is not an extension memory-pressure termination.

## Device cleanup

The probe stopped its VPN after every run. A targeted cleanup removed the
single `Xray Issue28 Probe` manager and its ephemeral secure configuration;
the existing user manager remained (`removed=1 remainingManagers=1`). The
probe's JSON files were removed from the device after console capture. The
ordinary XrayClient interface was rebuilt and installed with the **baseline
v0.6.0 Rust library**, then launched without probe arguments. User profiles
were not edited or deleted. This was a local Debug rebuild, not restoration
of an archived byte-identical App Store/TestFlight binary. All local stand
processes were stopped and their test ports were checked closed.

No release, remote push or issue comment is part of this validation.
