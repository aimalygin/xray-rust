# XHTTP H3 on Linux: where 32 downloads' memory goes

Measured **2026-10-30 22:59 – 2026-10-31 00:29 America/Chicago** in Docker
Desktop 29.6.1's Linux VM (kernel 6.12.76-linuxkit, aarch64, 12 vCPUs, 7.9 GiB,
Debian bookworm with glibc 2.36) on the Apple M6, with the setup of the
[receive-buffer report](../2026-10-30-xhttp-h3-receive-batch/README.md): its
image plus allocator and profiler packages, its harness and its Xray-core
v26.10.21 (`1b1647c`) built for linux/arm64.

After the receive-buffer change, 32 `stream-up` downloads still peaked at
about 115 MiB on Linux against 16.8 MiB on macOS. On Linux the client is the
slower side: its two Tokio workers move 11 Gbit/s on about 1.9 cores while
Xray-core sends faster, so every download's QUIC stream window stays nearly
full. On macOS the same transfer runs at 2.3 Gbit/s, and the send-budget
report found its download connections holding almost nothing. On Linux two
things hold the data:

- **quinn's stream receive buffers, 56–59 MiB**: each of the 32 download
  connections keeps about 1.8 of its 2 MiB stream window filled. This is flow
  control doing its job, and why the mobile profile, whose windows do not
  grow, peaks the same: here the default windows rarely grow either.
- **h3's frame buffers, 11–25 MiB at the peak and growing**: h3 0.0.8 read a
  QUIC chunk ahead for every DATA frame while the stream stayed full. Those
  bytes had already left the QUIC window, so nothing bounded them; in
  transfers four times as long they reached 36–46 MiB.

The second is a bug, now fixed by a vendored h3 (`54c77a31`, see
[`vendor/h3/XRAY-PATCH.md`](../../../../vendor/h3/XRAY-PATCH.md)). In release
builds, 32 downloads now peak at **95.8 instead of 112.5 MiB**, and a
transfer four times as long at **103.9 instead of 140.7 MiB**, with 4.1% and
6.7% more throughput and as much less CPU per byte. What remains is mostly the
full receive windows, which only a policy change can shrink.

| Build | Commit | Executable SHA-256 (linux/arm64) |
| --- | --- | --- |
| before | `94347de0` | `b236a955dc04f90a0387986f8328eafcb3a36e743fd965e344b12140eedbee70` |
| after | `54c77a31` | `1a820a30e890aaaffe44a3f4635713aa1b6dc57b1b22899d361b449ad273bdfe` |
| harness | `33d5d35c` | `6c89386b927d6df45c8ede23cd9ca943016f0864b1a912b5240e57ffef5aef94` |
| Xray-core | v26.10.21 `1b1647c` | `2aff4d5a0426f5226936114b1dbd950d1510e1db3da8a994f4ae757aa3eede40` |

`94347de0` builds the same client code as `9340a335`, the receive-buffer
report's "after". Both clients were built with Rust 1.96.0 and the release
profile, each from its own `git archive` export into its own new target
directory.

## Where it sits

An instrumented build (below) sampled the client every 50 ms. Peak-RSS sample
of three interleaved 32-flow downloads per variant, `xray-bench run --workload
stream-transport --stream-transport xhttp-h3 --xhttp-mode stream-up --traffic
download --connections 32 --iterations 4096 --payload-size 65536`; medians
with the range in parentheses, MiB:

| Where | h3 0.0.8 | Fixed h3 | Bounded by |
| --- | ---: | ---: | --- |
| quinn stream receive buffers, 32 downloads | 55.9 (46.0–58.7) | 58.8 (56.4–59.8) | each stream's 2 MiB window |
| h3 frame buffers | 21.3 (11.0–24.6) | 0.0 | nothing; now two QUIC chunks per stream |
| Packet headers and tags, partly read GRO datagrams | 2.2 (2.0–2.4) | 1.8 (1.7–2.1) | the two above |
| Other live heap: connections, TLS, runtime, H3 batches, relay buffers | 14.0 (13.5–14.4) | 12.9 (12.6–13.0) | connection count |
| glibc free heap still resident | 13.4 (13.4–21.4) | 11.3 (11.2–17.9) | earlier live peaks |
| Endpoint receive buffers and thread stacks (mapped, resident part) | 2.8 (2.8–3.0) | 2.7 (2.7–2.9) | 368 KiB per endpoint, 23 MiB reserved |
| Executable and libraries (`RssFile`) | 11.4 | 11.4 | |
| **Peak RSS** | **119.0 (113.1–125.0)** | **100.3 (99.0–102.7)** | |

Per run the rows add up to the RSS exactly; their medians need not. "Other
live heap" includes about 1 MiB of the instrumentation's own allocation
headers and, with h3 0.0.8, the queues that held the read-ahead chunks; H3
response batches and relay buffers account for 1.0 and 1.1 MiB of it. The
instrumented build runs about 10% slower than a release build, whose peaks in
the same case are 112.5 and 95.8 MiB (below).

The median download connection had 1.8 MiB buffered throughout; in four of
the 16 instrumented 32-flow runs one connection's window grew to 4 MiB. The
queues between each endpoint and its connection held 1.4 MiB at most, all 32
together, and no assembler ever defragmented. The upload connections of the
32 flows held almost nothing.

## How it was attributed

**Allocators.** Wrapper scripts ran the unchanged release client of
`9340a335` under other allocators and glibc settings, three interleaved runs
each (`data/allocators.jsonl`). Peak `VmHWM`, median and range:

| Allocator | Peak RSS, MiB | Gbit/s | CPU ms per GiB |
| --- | ---: | ---: | ---: |
| glibc 2.36 | 117.8 (114.6–118.9) | 11.1 | 1,500 |
| `MALLOC_ARENA_MAX=1` | 103.5 (101.8–112.9) | 10.1 | 1,624 |
| `MALLOC_ARENA_MAX=2` | 110.5 (107.0–119.3) | 11.3 | 1,465 |
| `MALLOC_ARENA_MAX=4` | 113.3 (111.2–114.6) | 11.8 | 1,404 |
| glibc, mmap and trim thresholds fixed at 128 KiB | 119.8 (117.0–121.6) | 11.8 | 1,406 |
| jemalloc 5.3 (`LD_PRELOAD`) | 171.5 (87.9–185.2) | 13.0 | 1,279 |
| mimalloc 2.0 (`LD_PRELOAD`) | 165.7 (161.0–166.5) | 11.4 | 1,465 |

No allocator came near macOS's 16.8 MiB, and one arena saved 14 MiB at the
cost of throughput: most of the memory was live.

**Instrumented build.** `scripts/instrumentation.diff` (against `c0df74c9`)
adds a global allocator that tags allocations by site and counts live bytes
per tag (received datagrams, H3 batches, endpoint buffers, relay buffers,
assembler defragmentation), counters for every quinn assembler's buffered
bytes, for the bytes queued between each endpoint and its connection and for
each connection's buffered bytes, and a sampler thread that writes those with
`/proc/self/status` and glibc's `mallinfo2` every 50 ms.
`scripts/instrumentation-h3.diff` adds byte and chunk counters to crates.io h3
0.0.8's `BufList` and switches between its read-ahead and the fix. Every run
is in `data/attribution-runs.jsonl`, with its sample at peak RSS and a 500 ms
series.

The first build showed received-datagram allocations live beyond what the
assemblers held, by 2 MiB a few hundred milliseconds in and by 23 MiB six
seconds later, released only as connections closed. A transfer four times as
long peaked at 160.3 MiB instead of 118.9, with the gap at 59 MiB. A census of
every live datagram allocation (`data/census.jsonl`) found none older than a
second and all but 0.4 MiB younger than 300 ms, so nothing leaked: something
queued young packets. With GRO off each allocation held a single packet and
the gap stayed, 73,000 live packets (84 MiB) against 52,000 assembler chunks
(58 MiB), so coalesced datagrams were not pinning them. The h3 counters then
matched the gap to within 2–3 MiB of packet headers.

## h3's read-ahead

`FrameStream::poll_next` read a chunk from the QUIC stream before decoding,
and `poll_data` read one before handing out each piece of a DATA frame, even
when the bytes they needed were already buffered. Each piece takes at most one
chunk, so a frame boundary inside a chunk left one more chunk buffered, and
`poll_next` added another per frame. When the reader catches up, a read finds
nothing and a piece drains the buffer by one chunk; when the client is slower
than the network, every read finds a chunk. The chunks are already outside the
QUIC window, which credit-returns them to the server, so the server sends
more.

The final instrumented build, 32 downloads of 1 GiB each (16,384 × 64 KiB,
about 25 s), two rounds in rotating order (`data/long-instrumented.jsonl`):

| h3 | Peak RSS, MiB | Most in h3 buffers | Most chunks in one stream | Gbit/s |
| --- | ---: | ---: | ---: | ---: |
| 0.0.8 | 149.5, 142.8 | 41.0 MiB (36,762 chunks) | 2,493 | 11.2, 11.6 |
| hyperium/h3#344 (`poll_next` only) | 101.9, 100.9 | 4 chunks | 2 | 12.6, 12.8 |
| `poll_next` and `poll_data` (vendored) | 99.8, 103.6 | 2 chunks | 2 | 12.7, 12.7 |

Upstream fixed `poll_next` in hyperium/h3#344 (issue #308), merged in August
2026 after 0.0.8, the latest release. Its `poll_data` still reads on every
call. That was enough in these downloads, but with small frames it grows the
buffer by a chunk per frame: the vendored crate's
`poll_data_reads_only_what_the_current_frame_needs` fails with upstream's
change alone, and passes once `poll_data` reads only while part of the current
frame is still missing. Reading first in that case keeps a truncated frame an
`UnexpectedEnd`. With crates.io h3 0.0.8, the new end-to-end test
`small_data_frames_wait_in_the_stream_window` saw the server write 4.1 MiB past
a reader that had taken 1 MiB through a 256 KiB window. With the vendored h3
the server stayed 247–254 KiB ahead in ten runs, within the window, and the
test passed 20 times in a row on macOS and on Linux.
`scripts/check-vendored-sources.sh` passes on macOS with its new h3 step: the
archive checksum, a zero-fuzz reconstruction and h3's 172 unit tests. The
`xray-transport` tests and clippy pass on Linux and on macOS.

## Before and after

Release builds, interleaved with alternating order, as in the receive-buffer
report. Peak RSS is the client's `VmHWM`, read from `/proc` every 100 ms; CPU
is its user and system ticks per GiB moved. Medians, and the median paired
change with the range of paired changes.

**Default profile**, five pairs per case:

| Case | Peak RSS, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: |
| download-32 | 112.5 → 95.8 (−15.6%) | +4.1% (−8.5 to +6.4) | −4.2% (−6.3 to +9.0) |
| full-duplex-32 | 129.2 → 110.3 (−14.6%) | +1.9% (+1.8 to +4.6) | −1.9% (−4.9 to −1.7) |
| upload-32 | 44.5 → 44.4 (−1.6%) | +1.4% (−2.9 to +5.1) | −1.4% (−2.0 to +2.5) |
| download-1 | 11.9 → 12.0 (+1.6%) | +1.6% (+0.0 to +6.1) | +0.0% (−2.8 to +2.9) |
| full-duplex-1 | 14.2 → 14.4 (+1.0%) | +0.4% (−17.0 to +4.1) | +1.8% (+0.0 to +18.2) |
| upload-1 | 14.0 → 14.0 (−1.3%) | −1.5% (−4.8 to +5.2) | +0.0% (−5.0 to +10.5) |

**Four times as long**, 16,384 × 64 KiB per flow, three pairs:

| Case | Peak RSS, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: |
| download-32 | 140.7 → 103.9 (−26.9%) | +6.7% (+6.3 to +11.4) | −6.8% (−10.4 to −6.0) |

**Mobile profile** (`XRAY_TUN_PROFILE=mobile`), three pairs per case:

| Case | Peak RSS, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: |
| download-32 | 112.9 → 96.2 (−10.4%) | +2.2% (−28.3 to +6.4) | −2.8% (−6.4 to +26.1) |
| full-duplex-32 | 129.5 → 110.1 (−16.2%) | +0.7% (−6.5 to +2.3) | +0.1% (−2.1 to +5.5) |
| upload-32 | 32.2 → 31.9 (−1.7%) | +0.6% (+0.3 to +12.8) | −0.6% (−12.0 to −0.2) |

The longer the transfer, the more the fix saves: the earlier build's peak
kept rising with the h3 buffers, from 112.5 to 140.7 MiB, while the fixed one
stayed near 100. One mobile download pair's "after" run moved 9.5 Gbit/s
against 13.6–14.2 for the others, which makes its throughput and CPU ranges;
it still peaked 7.5 MiB lower. Uploads and single flows, which never fill a
download window here, are unchanged within noise. The single-flow CPU figures
rest on a few dozen 10 ms ticks.

## What remains, and what could shrink it

- **The receive windows, about 57 MiB.** Xray-core's default 2 MiB stream and
  3 MiB connection windows, which the XHTTP H3 client mirrors, times 32
  downloads that the client drains slower than the server fills. A budget
  shared by concurrent downloads, like the send budget, could cap the sum:
  `Connection::set_stream_receive_window` lowers the credit later
  `MAX_STREAM_DATA` frames grant without touching the transport parameters, so
  each connection would still open at 2 MiB, as Xray's client does. At 32
  downloads on loopback a 512 KiB share would still exceed each flow's
  bandwidth-delay product many times over, but a lone download on a long path
  must keep the full window, and that trade needs its own A/B. Not done here.
- **glibc's free heap, 11–18 MiB.** Freed buffers stay resident; one arena
  trims a few MiB at a cost in throughput. Left alone.
- **The rest, about 30 MiB**: the executable, connection and TLS state for 64
  QUIC connections, the endpoint buffers capped by the receive-buffer change,
  stacks.

## Not covered

- No Android device. Android defaults to the constrained memory class, whose
  windows stay at 2 MiB and 3 MiB, so 32 downloads that a phone drains slower
  than the network fills would hold about the same 57 MiB; Scudo replaces
  glibc there.
- macOS, iOS and Windows run the same h3 code: any reader slower than the
  network let 0.0.8's buffers grow. In the macOS benchmark the download
  connections held almost nothing, so nothing queued there; no macOS
  benchmark was repeated here.
- Loopback with GSO and GRO intact; the server is Xray-core's quic-go.

## Evidence and replay

- [`data/allocators.jsonl`](data/allocators.jsonl): the allocator matrix.
- [`data/attribution-runs.jsonl`](data/attribution-runs.jsonl): every
  instrumented run with its build, harness result, peak sample and series.
- [`data/census.jsonl`](data/census.jsonl): the live-datagram census of a
  28-second run with GRO and one without, by age and connection.
- [`data/ab2-default.jsonl`](data/ab2-default.jsonl),
  [`data/ab2-long.jsonl`](data/ab2-long.jsonl) and
  [`data/ab2-mobile.jsonl`](data/ab2-mobile.jsonl): every release run.
- [`data/attribution-summary.jsonl`](data/attribution-summary.jsonl) and
  [`data/long-instrumented.jsonl`](data/long-instrumented.jsonl): the harness
  results of the final instrumented runs.
- [`scripts/`](scripts/): `Dockerfile.mem` (the receive-buffer report's image
  plus jemalloc, mimalloc, heaptrack, gdb and strace), the allocator
  `wrappers/`, `run-mem.sh` (one run with a 100 ms `/proc` series and a
  `CLIENT` that may be a wrapper), `matrix-alloc.sh`, `attr.sh` (instrumented
  interleaved runs), `long-attr.sh` (the long instrumented runs), `ab2.sh` and
  `ab2-campaign.sh` (the release A/B, with the receive-buffer report's
  `run-one-v2.sh`), `chain.sh` (waits until no other benchmark runs on the host
  and its load stays low, then starts both), both instrumentation diffs,
  `collect_attribution.py`, `summarize_attribution.py`, `summarize_ab2.py` and
  `memlog.py`. Paths are this host's scratch directory and Docker volumes.
