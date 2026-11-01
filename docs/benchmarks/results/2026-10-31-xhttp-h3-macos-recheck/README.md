# XHTTP H3 on macOS after the Linux receive-side fixes

Measured **2026-10-31 10:18–11:45 America/Chicago** on the Apple M6 of the
[three-engine group](../2026-10-30-v26.10.21-three-engine/README.md)
(Mac18,5, 12 cores, 32 GiB, macOS 27.0 26A425, AC power), against the same
Xray-core v26.10.21 server.

Two XHTTP H3 changes came after the
[send-budget report](../2026-10-30-xhttp-h3-send-budget/README.md), and both
were measured on Linux:
- `9340a335` gives each endpoint a receive buffer for four datagrams
  ([receive-buffer report](../2026-10-30-xhttp-h3-receive-batch/README.md)).
- `54c77a31` vendors h3 0.0.8 so downloads stay inside QUIC flow control
  ([download-memory report](../2026-10-31-xhttp-h3-download-memory/README.md)).

This re-check asks whether either change moves the macOS numbers the branch
publishes. **Neither does.**
- The six stream cases and the collector's twelve `xhttp-h3` cases stay
  within the run-to-run spread.
- Three small changes clear it:
  - `xhttp-h3-tun-download-8` peaks 2–3% lower.
  - `xhttp-h3-socks-full-duplex-8` uses 2.4% less CPU per byte.
  - `xhttp-h3-socks-full-duplex-1` loses 1.5% of its throughput. Its interval
    ends at −0.01%, and the matching stream and TUN cases don't confirm it.
- The macOS XHTTP H3 values in the send-budget report, the three-engine group
  and the performance-branch report need no new numbers.
- The receive budget merged later (`95280e73`) was checked on this host only
  on the collector's twelve cases, in the
  [receive-budget report](../2026-10-31-xhttp-h3-receive-budget/README.md).

| Build | Commit | Executable SHA-256 |
| --- | --- | --- |
| before | `bae0ed5b4e16ad4de6dcd5d104600cc11c30ea51` | `a9026942dcd0ff25bc10a466fbaebaa114df564e84c38ab5ca7dd604a6430397` |
| after | `57b5a6553c5dd52d70b4f2dc13e3c1e1f3b37a9b` | `0b151cc25e2bff3c6a0a7600281997f05b10807ed3a7cb8930008442ca375f5d` |

`before` is the isolated `bae0ed5b` client of the send-budget campaigns.
`after` was built the same way, by `scripts/build-isolated-release.py` from
its exported commit, with Rust 1.96.0. In code the two differ only by
`9340a335` and `54c77a31`; the commits between them change documentation and
CI scripts. The xray-bench driver (`e5a9561f…`, built from `b01fcd06`), the
server (`b8c58f14…`) and the collector's cover origin are the frozen inputs of
the 2026-10-30 campaigns.

Little was expected to move on macOS:
- macOS quinn reads one datagram at a time, so `9340a335` leaves this
  platform alone by construction.
- h3's read-ahead grew only while a reader lagged behind a full stream
  window. Here a download runs at about 2.3 Gbit/s and its windows stay
  nearly empty.

## Stream cases

`xray-bench` XHTTP H3 stream scenarios ran in five rounds of interleaved
pairs. The order alternated across rounds and scenarios. A pair was repeated
when either run failed or the collector's ambient-load rule rejected it.

30 pairs were accepted out of 49 attempted. 27 runs between 10:19 and 11:15
were rejected for external load; another session was compiling release
builds on the same Mac for most of that time. No run failed.

Each cell gives the before → after median and the median paired change:

| Case | Peak RSS, MiB | Peak footprint, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: | ---: |
| `stream-xhttp-h3-upload-32` | 88.9 → 89.7 (+1.3%) | 82.5 → 83.0 (+1.5%) | +0.7% | −1.1% |
| `stream-xhttp-h3-full-duplex-32` | 78.4 → 77.6 (−0.4%) | 72.4 → 71.6 (−0.3%) | +0.1% | −0.2% |
| `stream-xhttp-h3-download-32` | 16.9 → 16.8 (−0.6%) | 10.9 → 10.9 (−0.1%) | +0.4% | −0.5% |
| `stream-xhttp-h3-upload-1` | 11.8 → 11.9 (+0.7%) | 5.8 → 6.0 (+2.4%) | +8.6% | +1.8% |
| `stream-xhttp-h3-full-duplex-1` | 12.1 → 12.1 (+0.0%) | 6.1 → 6.1 (+1.0%) | +1.1% | −1.9% |
| `stream-xhttp-h3-download-1` | 9.3 → 9.3 (−0.2%) | 3.3 → 3.3 (+1.9%) | −0.1% | +0.0% |

- **32-flow memory.** Upload and duplex pairs spread from −9% to +12%, as in
  the earlier campaigns. Their medians are within about 2% of the published
  87.7 and 78.2 MiB.
- **Single upload.** Throughput rose in all five pairs, by +1.9% to +12.9%.
  The collector's single uploads show no such change (below). The send-budget
  campaign measured single uploads spreading from −11.4% to +21.9%, so I
  don't count this as a change.

## Migration collector, `xhttp-h3-*`

`scripts/run-migration-benchmarks.py --case-id` ran the twelve XHTTP H3
cases, each as one block of five adjacent AB/BA pairs. Blocks went through
`scripts/run-migration-campaign.py`'s quiet-machine wait and retry policy.
`xhttp-h3-socks-full-duplex-1` was rejected for its environment once and
passed on its second attempt; every other block passed on its first.

Changes are median paired changes with the publisher's exact bootstrap
interval. Trials pass the publisher's own `validate_trial` checks.

| Case | Throughput | CPU per GiB | Peak footprint, MiB |
| --- | ---: | ---: | ---: |
| `xhttp-h3-socks-upload-1` | −2.1% (−9.8 to +6.3) | −1.8% (−3.5 to +1.8) | 5.9 → 5.9 (+0.0%) |
| `xhttp-h3-socks-download-1` | −0.1% (−0.7 to +1.7) | −1.0% (−1.0 to +0.0) | 3.3 → 3.4 (+1.9%) |
| `xhttp-h3-socks-full-duplex-1` | −1.5% (−4.0 to −0.0) | +0.7% (+0.0 to +3.6) | 6.5 → 6.7 (+1.0%) |
| `xhttp-h3-socks-upload-8` | +2.1% (−6.3 to +5.8) | −2.8% (−7.0 to +9.3) | 26.1 → 26.9 (+11.7%) |
| `xhttp-h3-socks-download-8` | −0.3% (−0.4 to +0.3) | +0.1% (−0.4 to +0.7) | 4.8 → 4.8 (+1.0%) |
| `xhttp-h3-socks-full-duplex-8` | +3.0% (−0.3 to +3.5) | −2.4% (−3.3 to −0.1) | 26.4 → 27.6 (+4.4%) |
| `xhttp-h3-tun-upload-1` | −0.1% (−0.6 to +2.3) | +0.0% (−10.0 to +0.0) | 4.4 → 4.6 (+5.3%) |
| `xhttp-h3-tun-download-1` | −0.5% (−16.1 to +3.1) | +0.0% (+0.0 to +16.7) | 4.1 → 4.2 (−0.4%) |
| `xhttp-h3-tun-full-duplex-1` | −4.0% (−6.1 to +0.9) | +6.7% (−6.3 to +6.7) | 6.1 → 6.0 (−1.3%) |
| `xhttp-h3-tun-upload-8` | +0.5% (−2.9 to +1.3) | −1.7% (−3.4 to +1.8) | 32.0 → 32.2 (−2.0%) |
| `xhttp-h3-tun-download-8` | +0.1% (−1.7 to +0.8) | +0.0% (−1.3 to +1.3) | 6.5 → 6.3 (−2.6%) |
| `xhttp-h3-tun-full-duplex-8` | −0.5% (−3.1 to +0.6) | +0.8% (−0.8 to +2.5) | 30.0 → 30.4 (+1.7%) |

- **Lower download memory.** `xhttp-h3-tun-download-8` peaks 2.6% lower in
  footprint (−6.9% to −0.5%) and 2.3% lower in sampled RSS (−4.5% to −1.2%).
  That is about 0.2 MiB, the direction h3's read-ahead fix points.
- **8-flow uploads.** The `xhttp-h3-socks-upload-8` footprint change has an
  interval of −10.9% to +15.8%, and the duplex case one of −5.2% to +17.9%.
  `bae0ed5b` alone measured 26.6 and 27.0 MiB for the upload case in the
  send-budget and arena campaigns, so 26.9 MiB after is within its own range.
- **Single duplex flows.** `xhttp-h3-socks-full-duplex-1` throughput is −1.5%,
  with an interval ending at −0.01%. The matching stream case is +1.1%, and
  the interval of `xhttp-h3-tun-full-duplex-1`'s −4.0% spans zero.

## Evidence and replay

- [`data/stream-ab.jsonl`](data/stream-ab.jsonl) holds every stream run,
  rejected attempts included. Names of unrelated processes were removed.
- [`data/collector.json`](data/collector.json) holds every accepted
  collector trial's metrics and the build inputs.
- [`scripts/run-ab.sh`](scripts/run-ab.sh) ran both campaigns with the
  send-budget report's
  [`stream_ab.py`](../2026-10-30-xhttp-h3-send-budget/scripts/stream_ab.py)
  and [`collector_h3.py`](../2026-10-30-xhttp-h3-send-budget/scripts/collector_h3.py).
  That report's two summarizers rendered the tables. The paths are this
  host's, and the collector needs Python 3.11 or later.
- Raw results, collector blocks, build records and logs stay outside Git
  under `target/benchmarks/2026-10-31-h3-merged*.noindex/`.

## Not covered

- Linux and Android are covered by the two Linux reports. Phones were not
  measured.
- A memory change smaller than the 32-flow cases' spread of about ±10% would
  not show in the stream pairs.
