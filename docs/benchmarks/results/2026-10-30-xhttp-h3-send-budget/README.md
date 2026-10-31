# XHTTP H3 uploads: one send budget instead of 2 MiB per connection

Measured **2026-10-30 18:21–21:01 America/Chicago** on the Apple M6 of the
[three-engine group](../2026-10-30-v26.10.21-three-engine/README.md)
(Mac18,5, 12 cores, 32 GiB, macOS 27.0 26A425, AC power), against the same
Xray-core v26.10.21 server.

Thirty-two XHTTP H3 uploads now peak at **87.7 instead of 162.1 MiB RSS**
and 32 duplex transfers at **78.2 instead of 140.6 MiB**, at the same
throughput and CPU per byte. Single flows, downloads and the migration
collector's 8-flow cases stay within the run-to-run spread. A single upload
peaks 0.2 MiB higher.

| Build | Commit | Executable SHA-256 |
| --- | --- | --- |
| before | `a87a02922a500207a687c1d921237b2b253eb871` | `ef91bdc7dac747b7f0161d6d8f0d8dee0397cb776ba6e3638c8b6e1d6939edbf` |
| after, 8 MiB budget | `55ffe03408e5d520c1dbe9510ced1481e2a970ea` | `7ae751025a3c5658142d42d9ef59f222cea5d240597a868df1c236755f951744` |
| after, 16 MiB budget | `bae0ed5b4e16ad4de6dcd5d104600cc11c30ea51` | `a9026942dcd0ff25bc10a466fbaebaa114df564e84c38ab5ca7dd604a6430397` |

Each client was built by `scripts/build-isolated-release.py` from its
exported commit, with Rust 1.96.0 and the same `Cargo.lock`. The xray-bench
driver (`e5a9561f…`, built from `b01fcd06`), the server (`b8c58f14…`) and the
collector's cover origin are the frozen inputs of the 2026-10-30 campaigns.

## Where the memory went

`stream-xhttp-h3-upload-32` on a symbolized build of `a87a0292`, with macOS
malloc stack logging. Eight seconds into the transfer the live heap was
94.5 MiB:

| Allocating site | Live MiB |
| --- | ---: |
| quinn `SendStream::write`: QUIC send buffers | 71.3 |
| quinn-proto BBR delivery-rate snapshots | 6.5 |
| SOCKS relay buffers | 4.2 |
| Thread stacks | 4.1 |
| Sent-packet tracking, connection, TLS and endpoint state | about 4 |
| Everything else | about 5 |

Every XHTTP H3 request owns a QUIC connection, and `stream-up` opens two per
flow. The 32 upload connections each held 2.2 MiB of unacknowledged data:
their send windows never fell below 2 MiB, while the median congestion
window was 243 KB. The local server drained slower than the clients wrote
(smoothed RTT 12 ms, about 300,000 packets lost), so the windows filled with
data that only waited in the client. Freed buffers stayed resident, so the
footprint ran about 1.5 times the live heap and peaked during the opening
burst. The 32 download connections held almost nothing, and quinn's
per-endpoint receive buffer on macOS is a single 1,472-byte datagram.

## Policy

While `n` connections have uploaded within the last one to two seconds,
each keeps `budget / n` of send window, between 128 KiB and 2 MiB, and grows
toward twice its congestion window up to `10 MB / n`. A lone upload keeps
the former 2 MiB to 10 MB range. A new connection starts at 128 KiB until
its first 64 KiB, so a burst of uploads cannot fill 2 MiB each before it is
counted. The budget is 16 MiB, or 4 MiB with the mobile and low-memory
profiles, which also stop growing there. Hysteria keeps its own window.

The first version, `55ffe034`, shared 8 MiB. It took 32 uploads further down
(53.2 MiB RSS, +9.5% throughput, −9.3% CPU per GiB), but eight uploads,
which lose no packets on this host, then kept 1 MiB to 1.25 MB windows and
paid for the shallower queue: the collector's `xhttp-h3-socks-upload-8` rose
from 3,005 to 3,150 ms/GiB, interval +0.3% to +6.1%, and TUN by 1.8%.
Sixteen MiB keeps eight uploads at their 2 MiB (`bae0ed5b`).

Two other policies were rejected before these campaigns. A window that
follows a lone upload's congestion window (40–65 KB on loopback) with a
128 KiB floor cost that upload 12–32% more CPU per byte. A
budget counted from each connection's first sample until it closes would
let idle uploads shrink an active one's share, and the first connections to
count still filled multi-megabyte windows during BBR startup: 34 MiB live,
86 MiB footprint.

## Stream transport, interleaved

`xray-bench run --engine xray-rust --workload stream-transport
--stream-transport xhttp-h3 --xhttp-mode stream-up --iterations 4096
--payload-size 65536`, one run per invocation. Five rounds; each round runs
every case once per build, alternating which build goes first across rounds
and cases. A pair was repeated, both builds, when either run broke the
migration collector's load rule (an external process at one core, two cores
in total, or a compiler). RSS is xray-bench's 100 ms sample; footprint is
the client's `ri_lifetime_max_phys_footprint`, polled every 50 ms. Values
are medians of the five pairs and the median paired change.

**`bae0ed5b`, 16 MiB** (20:06–20:34, 30 pairs, none repeated):

| Case | Peak RSS, MiB | Peak footprint, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: | ---: |
| `stream-xhttp-h3-upload-32` | 162.1 → 87.7 (−46.0%) | 156.2 → 77.3 (−50.7%) | −0.4% | −0.4% |
| `stream-xhttp-h3-full-duplex-32` | 140.6 → 78.2 (−47.3%) | 134.5 → 69.5 (−49.8%) | −2.1% | +0.6% |
| `stream-xhttp-h3-upload-1` | 11.8 → 12.0 (+1.2%) | 5.8 → 6.0 (+2.9%) | +10.1% | +0.0% |
| `stream-xhttp-h3-full-duplex-1` | 12.1 → 12.0 (−1.0%) | 6.1 → 6.0 (−1.3%) | −1.0% | +0.6% |
| `stream-xhttp-h3-download-32` | 16.8 → 16.8 (+0.2%) | 10.8 → 10.8 (+0.6%) | +0.1% | +0.0% |
| `stream-xhttp-h3-download-1` | 9.4 → 9.3 (−0.7%) | 3.3 → 3.3 (−1.4%) | −0.4% | +0.0% |

Every 32-flow pair lost 40–54% of its RSS. Duplex throughput moved −2.9% to
+3.7% and upload −1.5% to +5.1%; single uploads spread from −11.4% to
+21.9%, and their CPU counter moves in 10 ms ticks.

**`55ffe034`, 8 MiB** (18:21–19:24, 30 pairs; 20 of 50 attempts repeated
under load from other desktop work):

| Case | Peak RSS, MiB | Peak footprint, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: | ---: |
| `stream-xhttp-h3-upload-32` | 151.8 → 53.2 (−65.9%) | 141.3 → 46.0 (−67.7%) | +9.5% | −9.3% |
| `stream-xhttp-h3-full-duplex-32` | 148.0 → 50.4 (−64.8%) | 141.8 → 44.4 (−67.6%) | +1.7% | −3.9% |
| `stream-xhttp-h3-upload-1` | 11.8 → 12.0 (+1.3%) | 5.8 → 6.0 (+3.2%) | +2.8% | +0.0% |
| `stream-xhttp-h3-full-duplex-1` | 12.2 → 12.0 (−0.6%) | 6.2 → 6.0 (−0.5%) | +1.5% | −3.6% |
| `stream-xhttp-h3-download-32` | 16.9 → 16.9 (+0.5%) | 10.8 → 10.9 (+1.0%) | +0.2% | +0.2% |
| `stream-xhttp-h3-download-1` | 9.4 → 9.3 (−0.3%) | 3.3 → 3.3 (+0.0%) | −0.7% | +0.0% |

## Migration collector, `xhttp-h3-*`

`scripts/run-migration-benchmarks.py --case-id` for the twelve XHTTP H3
cases, each one block of five adjacent AB/BA pairs, run through
`scripts/run-migration-campaign.py`'s quiet-machine wait and retry policy.
Every block passed on its first attempt. Changes are median paired changes
with the publisher's exact bootstrap interval; trials pass the publisher's
own `validate_trial` checks.

**`bae0ed5b`, 16 MiB** (20:44–21:01):

| Case | Throughput | CPU per GiB | Peak footprint, MiB |
| --- | ---: | ---: | ---: |
| `xhttp-h3-socks-upload-1` | +1.4% (−6.2 to +12.8) | +1.8% (−10.9 to +14.0) | 5.7 → 5.9 (+3.0%) |
| `xhttp-h3-socks-download-1` | −0.1% (−0.7 to +1.1) | −1.0% (−1.9 to +1.0) | 3.3 → 3.3 (−0.9%) |
| `xhttp-h3-socks-full-duplex-1` | −1.0% (−2.1 to −0.3) | +0.0% (−2.1 to +1.4) | 6.3 → 6.6 (+4.7%) |
| `xhttp-h3-socks-upload-8` | −1.3% (−3.6 to +1.0) | +2.1% (−2.0 to +8.4) | 30.7 → 26.6 (−9.2%) |
| `xhttp-h3-socks-download-8` | +0.2% (−0.3 to +0.3) | +0.1% (+0.0 to +0.3) | 4.7 → 4.8 (+2.6%) |
| `xhttp-h3-socks-full-duplex-8` | +1.0% (+0.2 to +4.1) | −0.3% (−3.5 to +0.4) | 28.5 → 26.8 (−10.5%) |
| `xhttp-h3-tun-upload-1` | +0.1% (−16.5 to +18.7) | +0.0% (+0.0 to +0.0) | 4.5 → 4.4 (−1.4%) |
| `xhttp-h3-tun-download-1` | −0.1% (−1.3 to +10.5) | +0.0% (−14.3 to +7.7) | 4.2 → 4.2 (−0.4%) |
| `xhttp-h3-tun-full-duplex-1` | −0.2% (−10.9 to +1.2) | +0.0% (−6.2 to +14.3) | 6.3 → 6.3 (+1.3%) |
| `xhttp-h3-tun-upload-8` | +0.7% (−1.6 to +2.3) | +0.0% (−3.4 to +1.8) | 31.9 → 30.9 (+1.4%) |
| `xhttp-h3-tun-download-8` | +0.9% (−1.4 to +3.9) | −1.2% (−5.0 to +1.3) | 6.4 → 6.5 (+2.4%) |
| `xhttp-h3-tun-full-duplex-8` | +1.0% (−3.1 to +1.9) | −0.8% (−0.8 to +1.7) | 30.2 → 30.8 (+1.9%) |

`xhttp-h3-socks-full-duplex-1` runs the same window policy under both
budgets, and the 8 MiB campaign measured it at +1.0% (+0.1 to +2.6): a
one-percent paired change is within what separates two campaigns here.
`xhttp-h3-socks-upload-8`'s CPU per GiB moved +2.0% to +8.4% in four pairs
and −2.0% in the fifth. Under the 16 MiB budget eight uploads keep a lone
upload's 2 MiB floor but stop growing there, which lowered the SOCKS 8-flow
footprints by 9–10%.

**`55ffe034`, 8 MiB** (19:26–19:43), the rows that decided against it:

| Case | Throughput | CPU per GiB | Peak footprint, MiB |
| --- | ---: | ---: | ---: |
| `xhttp-h3-socks-upload-8` | −0.9% (−2.3 to −0.4) | +4.0% (+0.3 to +6.1) | 32.6 → 28.4 (−9.0%) |
| `xhttp-h3-tun-upload-8` | +0.0% (−2.0 to +1.1) | +1.8% (+1.8 to +3.5) | 32.3 → 28.1 (−13.0%) |
| `xhttp-h3-tun-full-duplex-8` | −0.6% (−2.0 to +1.8) | +0.0% (−2.5 to +0.8) | 30.4 → 26.0 (−14.4%) |

All twelve rows of both campaigns are in [data](data/).

## Not covered

- On Linux and Android quinn sizes each endpoint's receive buffer for up to
  64 GRO segments times a 32-datagram batch, about 3 MiB of address space
  per endpoint, and every XHTTP H3 request has its own endpoint. This Mac
  uses 1,472 bytes per endpoint, so nothing here measures it.
- Much of what remains is allocator fragmentation: in a 32-flow upload with
  an 8 MiB prototype, about half of the small-allocation zone. h3-quinn
  copies every write into quinn in pieces of whatever size the window
  allows.
- The vendored BBR keeps up to 4,096 delivery snapshots per connection,
  about 200 KiB for each fast upload.
- Phones were not measured; their 4 MiB budget follows the memory class.

## Evidence and replay

- [`data/stream-ab-16mib.jsonl`](data/stream-ab-16mib.jsonl) and
  [`data/stream-ab-8mib.jsonl`](data/stream-ab-8mib.jsonl) hold every
  stream run, rejected attempts included; names of unrelated processes were
  removed. [`data/collector-16mib.json`](data/collector-16mib.json) and
  [`data/collector-8mib.json`](data/collector-8mib.json) hold every trial's
  metrics and the build inputs.
- [`scripts/stream_ab.py`](scripts/stream_ab.py) ran the stream rounds,
  [`scripts/collector_h3.py`](scripts/collector_h3.py) the collector
  campaign, and the two summarizers rendered the tables. The binary paths
  in them are this host's. The collector needs Python 3.11 or later; a
  first invocation under the system Python 3.9 stopped before measuring.
- Raw results, collector blocks, build records and logs stay outside Git
  under `target/benchmarks/2026-10-30-h3-send-budget*.noindex/`.
