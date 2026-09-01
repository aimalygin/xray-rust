# v0.5 Pre-Device Performance Gate — 2026-09-01

This is pre-release host evidence, not a replacement for the physical Apple
and Android transition/soak campaign.

## Provenance

- Source: `8fbca90499cbc645d347334a35faf5121d9ce1ff`
  (`bench(v0.5): add pre-device regression gate`).
- Workspace and measured xray-rust source were clean and named the same commit
  in all embedded results.
- Harness profile: `release`; Rust/Cargo `1.96.0`.
- Host: arm64, macOS 26.5.2 (25F84), the same local publication host used for
  the v0.4.0 anchors below.
- Harness SHA-256:
  `b2765dee6d906fb8208c880c89b5c56b5619d7ecf40d51ce12115652dba27452`.
- xray-rust SHA-256:
  `97bf5492b7d01a47c701b9d3b8658f2da447f55bea0795e8159b83997898a8ed`.
- Command:

  ```sh
  scripts/run-v05-pre-device-benchmarks.sh target/benchmarks/v05-pre-device-8fbca90
  ```

The ignored local evidence directory contains 40 `result.json` files and five
five-run `summary.json` files. The checker passed every budget and provenance
condition at the revision above.

## Shared-Path Comparison

Values are medians of five independent release probes or the median field of a
five-run process summary. Lower is better.

| Slice | v0.4.0 | v0.5 candidate | Change | Budget | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| 64-rule route selection | 384 ns | 365 ns | -4.9% | <=500 ns | pass |
| 4,096-rule DNS selector, last hit | 21,896 ns | 26,374 ns | +20.5% | <=30,000 ns | pass |
| 4,096-rule DNS selector, semantic miss | 21,980 ns | 25,897 ns | +17.8% | <=30,000 ns | pass |
| Idle RSS | 3,932 KiB | 4,400 KiB | +11.9% | <=5,120 KiB | pass |
| 100 held-flow RSS | 5,632 KiB | 6,768 KiB | +20.2% | <=7,500 KiB | pass |
| 1,000 held-flow RSS | 18,708 KiB | 23,632 KiB | +26.3% | <=25,000 KiB | pass |
| Plain TCP median latency | 39 us | 41 us | +5.1% | <=55 us | pass |
| fd-backed TUN RSS | n/a | 5,760 KiB | n/a | <=8,192 KiB | pass |

The 1,000-flow RSS result is the narrowest process budget: 1,368 KiB, or 5.5%,
remains before the ceiling. Against the later v0.4.1-rc.4 publication (20.9
MiB), the current 23.08 MiB is about 10.4% higher. The increase scales with
active flows and is consistent with the intentionally added per-flow
connection inventory, cancellation/observation channels, accounting, and
larger managed task state rather than an idle-process leak. This remains a
required Instruments/Perfetto focus on physical devices.

## New Phase 2 Paths

v0.4.0 has no equivalent management surface, so these rows use absolute
ceilings fixed before the clean run.

| Slice | Five-run median | Budget | Result |
| --- | ---: | ---: | --- |
| Probe peak RSS | 7,904 KiB | <=10,240 KiB | pass |
| Round-robin selection | 107 ns | <=200 ns | pass |
| Eight-hop chain selection | 334 ns | <=600 ns | pass |
| Atomic override switch | 111 ns | <=250 ns | pass |
| 64-member selection snapshot | 1,543 ns | <=3,000 ns | pass |
| 64-member health snapshot | 1,662 ns | <=3,500 ns | pass |
| Warm DNS cache hit | 158 ns | <=300 ns | pass |
| 64-connection inventory snapshot | 2,687 ns | <=5,000 ns | pass |
| Outbound accounting snapshot | 45 ns | <=100 ns | pass |
| Addressable connection close | 2,071 ns | <=4,000 ns | pass |
| Diagnostic queue record/poll | 67 ns | <=150 ns | pass |
| TUN statistics snapshot | 16 ns | <=50 ns | pass |

Every DNS-cache probe observed exactly one upstream call: one untimed fill and
no timed-loop misses.

## Pre-v0.5 Regression Investigation

The large selector regression was introduced before the v0.5 feature line by
`bb78e7e` (shared compiled domain indexes), with a smaller contribution from
`4ba781b` (shared IP range indexes). Those changes correctly made large
geosite/geoip sets effectively size-independent, but also routed thousands of
tiny per-rule matcher sets through hash/index lookup and unconditional ASCII
normalization. The 4,096-rule last-hit path rose from roughly 21.9 us in v0.4.0
to about 91.5 us, even though most rules contained only one exact matcher.

`c581fa3` keeps a linear representation for domain sets of at most eight,
directly checks a single IP range, and skips empty inverse sets while retaining
the compiled representation for large matcher collections. This clean run
holds route selection below the v0.4.0 median and brings the broad selector to
26.4/25.9 us. The remaining 17.8–20.5% selector difference is attributed to
the v0.5 graph/target abstraction and remains visible under the fixed 30 us
budget rather than being treated as recovered parity.

## Decision

The host performance prerequisite passes. Physical Apple/Android testing may
begin, with 1,000-flow resident memory and long-lived transition/soak memory
growth treated as explicit release-gate risks.
