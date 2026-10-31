# XHTTP H3 on Linux: a receive buffer for four datagrams per endpoint

Measured **2026-10-30 21:24–22:04 America/Chicago** in Docker Desktop
29.6.1's Linux VM (kernel 6.12.76-linuxkit, aarch64, 12 vCPUs, 7.9 GiB,
Debian bookworm with glibc 2.36) on the Apple M6 of the
[send-budget report](../2026-10-30-xhttp-h3-send-budget/README.md), against
Xray-core v26.10.21 (`1b1647c`) built for linux/arm64 with Go 1.27.3.

On Linux and Android quinn gave every endpoint a receive buffer for 32
datagrams of 64 GRO segments of 1,472 bytes: 2.9 MiB. Every XHTTP H3 request
owns a QUIC connection and its own endpoint, and `stream-up` opens two per
flow, so 32 flows had 64 of these buffers. Whether the memory is real
depends on the traffic and the allocator:

- Each `recvmmsg` fills slots from the first, up to 64 KiB each with GRO,
  so a slot's pages become resident once enough datagrams queue for a call
  to reach it. In 32-flow downloads 17–20 of the 32 download endpoints
  reached the 2.1 MiB maximum, every slot having held a 64 KiB datagram:
  43–48 MiB resident in all, 62–65 MiB for duplex transfers and 32–36 MiB
  for uploads. A single download reached 2.1 MiB in two of three runs.
- Once glibc frees one of these buffers it serves later ones from its
  heaps, and `calloc` zeroes a reused chunk in full: an endpoint whose
  buffer reuses a freed chunk holds all 2.9 MiB, idle or not.

XHTTP H3 and DoQ endpoints now read four datagrams per receive call, two on
a constrained host, through a vendored quinn option. GRO stays on. In
release builds, 32 downloads now peak at **114.6 instead of 154.3 MiB**,
duplex transfers at **131.9 instead of 183.9 MiB** and uploads at **42.3
instead of 73.4 MiB**, with throughput and CPU per byte unchanged or
slightly better. With the mobile profile the same cases fall by 26–50%.
macOS reads one datagram at a time and is unchanged; so is Hysteria.

| Build | Commit | Executable SHA-256 (linux/arm64) |
| --- | --- | --- |
| before | `33d5d35c` | `123aa7201b6d719a6ae247581883a4cb778fa3ac670185e4d3053631149a9208` |
| after | `9340a335` | `c48d4f8e7cff4a0bb13369a75963e32fd17162cec7ebd5f934b9b38fb7474dc2` |
| harness | `33d5d35c` | `6c89386b927d6df45c8ede23cd9ca943016f0864b1a912b5240e57ffef5aef94` |
| Xray-core | v26.10.21 `1b1647c` | `2aff4d5a0426f5226936114b1dbd950d1510e1db3da8a994f4ae757aa3eede40` |

Both clients were built with Rust 1.96.0 and the release profile, each from
its own `git archive` export into its own new target directory.

## The buffer

`vendor/quinn/src/endpoint.rs` sized it as
`max_udp_payload_size (1,472) × max_receive_segments × BATCH_SIZE`.
quinn-udp 0.5.15 reports 64 receive segments when the kernel accepts
`UDP_GRO`, as Linux and Android kernels since 5.0 do, and reads 32
datagrams per `recvmmsg`; on Apple targets both are 1. quinn copies every
datagram out before it processes the next batch, so the buffer only stages
what one call returns. A GRO datagram never exceeds 64 KiB, so at most 17
of the 23–24 pages a slot spans are ever written.

## Where it became resident

An instrumented build (`scripts/instrumentation.diff`) sampled every live
endpoint buffer with `mincore(2)` every 200 ms; it also lets an environment
variable disable GRO or cap the batch. Same harness and server; three
interleaved runs per case. `xray-bench run --workload stream-transport
--stream-transport xhttp-h3 --xhttp-mode stream-up --iterations 4096
--payload-size 65536`. Peak resident pages per endpoint, unchanged code:

| Case | Resident, all 64 buffers | Endpoints at 500+ pages (of 64) | Others |
| --- | ---: | ---: | --- |
| download-32 | 42.6–48.2 MiB | 17–20 | 15–18 at 50–499, 29–30 below 50 |
| full-duplex-32 | 62.1–65.1 MiB | 26–28 | 15–20 at 50–499 |
| upload-32 | 31.6–35.7 MiB | 15–17 | the rest 2–49 |
| download-1 | 0.3–2.1 MiB | 0–1 of 2 | |

The four-datagram runs of the same matrix kept 2.0–2.1, 3.0–5.1, 0.9 and
0.1 MiB. In the duplex runs the largest of those buffers had all 93 pages
resident: past glibc's raised mmap threshold `calloc` had zeroed them in
full, which is the 368 KiB bound per endpoint.

`scripts/glibc-calloc-churn.c` repeats the allocation pattern with glibc
2.36 alone: two threads each keep four 2.9 MiB `calloc` buffers and replace
them in turn, writing only one. While they were fresh mappings or fresh
heap, the three idle buffers had 3–41 of their 2,211 pages resident; once
glibc reused freed chunks for them, from the second or third round on, all
2,211.

## Batch and GRO

Medians of three interleaved runs of the instrumented build (faster
profile: no LTO, 16 codegen units). The harness's CPU figure has one-second
resolution; throughput is the comparable measure here.

| Receive path | download-32, MiB / Gbit/s | full-duplex-32 | upload-32 | download-1, Gbit/s |
| --- | ---: | ---: | ---: | ---: |
| GRO, 32 datagrams (before) | 156.7 / 10.0 | 189.7 / 10.1 | 76.5 / 12.9 | 5.6 |
| GRO, 8 | 116.6 / 10.6 | 134.5 / 10.0 | 43.5 / 12.8 | 5.7 |
| GRO, 4 | 119.1 / 10.3 | 130.0 / 10.3 | 42.9 / 12.8 | 5.6 |
| GRO, 2 | 115.7 / 10.4 | 130.4 / 10.3 | 45.6 / 12.8 | 5.6 |
| GRO, 1 | 122.8 / 10.1 | 133.7 / 10.0 | 44.3 / 12.6 | 5.6 |
| no GRO, 32 | 129.6 / 7.5 | 133.9 / 8.5 | 44.1 / 13.0 | 5.2 |

Without GRO, downloads lost a quarter of their throughput, so the fix keeps
it. A small batch could cost most when GRO coalesces nothing, so a second
matrix disabled GRO and varied the batch (`data/batch-no-gro.jsonl`):
download-32 medians were 6.3, 7.5, 6.4, 7.1 and 6.9 Gbit/s for batches of 32,
8, 4, 2 and 1, full-duplex-32 8.3, 7.9, 8.2, 8.1 and 8.0, and download-1
5.1, 5.0, 5.2, 5.0 and 4.8. Single runs of one configuration ranged from 4.1
to 7.6 Gbit/s, so no batch size separated from the others; one datagram was
lowest only in the single download, 7% below 32.

Four datagrams bound a busy endpoint at 256 KiB written by the kernel and
any endpoint at 368 KiB. A constrained host reads two, for 184 KiB.

## Before and after

Release builds, interleaved with alternating order. Peak RSS is the
client's `VmHWM`, read from `/proc` every 100 ms; CPU is its user and system
ticks per GiB moved. Medians and the median paired change; the first
download-32 pair lacks a `VmHWM` reading, so that row has four pairs.

**Default profile**, five pairs per case:

| Case | Peak RSS, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: |
| download-32 | 154.3 → 114.6 (−26.1%) | +2.2% (+1.3 to +4.6) | −2.0% (−4.1 to −1.1) |
| full-duplex-32 | 183.9 → 131.9 (−28.7%) | +1.1% (−1.6 to +3.4) | −1.0% (−3.3 to +1.5) |
| upload-32 | 73.4 → 42.3 (−43.1%) | +0.0% (−1.1 to +1.6) | −0.2% (−2.2 to +0.2) |
| download-1 | 12.2 → 12.0 (−1.0%) | +2.1% (−0.5 to +7.8) | +0.0% (−17.1 to +2.9) |
| full-duplex-1 | 16.5 → 14.6 (−11.3%) | +2.8% (−5.0 to +8.2) | +0.0% (−6.7 to +1.8) |
| upload-1 | 13.8 → 13.6 (−0.8%) | −0.7% (−4.9 to +2.2) | +0.0% (+0.0 to +3.3) |

**Mobile profile** (`XRAY_TUN_PROFILE=mobile`, the constrained memory class
and two datagrams), three pairs per case:

| Case | Peak RSS, MiB | Throughput | CPU per GiB |
| --- | ---: | ---: | ---: |
| download-32 | 153.2 → 112.3 (−26.9%) | +3.5% (+3.3 to +3.9) | −3.6% (−4.1 to −3.5) |
| full-duplex-32 | 180.4 → 133.3 (−26.1%) | +1.7% (−0.9 to +4.0) | −1.8% (−4.3 to +0.4) |
| upload-32 | 62.5 → 31.2 (−49.6%) | −0.1% (−1.4 to +1.3) | −0.1% (−2.0 to +1.7) |

Single-flow transfers last under a second, so their CPU figures rest on a
few dozen 10 ms ticks.

## Not covered

- No Android device was measured. Bionic's Scudo allocator replaces glibc
  there and caches and reuses large blocks differently, so the resident
  share of a 184 KiB buffer can differ from these runs. NIC GRO and 16 KiB
  pages were not tested either.
- Loopback hands the client the server's GSO batches intact; a real link
  coalesces less, which the no-GRO matrix brackets.
- A 32-flow download still peaks at about 115 MiB here, against 16.8 MiB on
  macOS in the send-budget report, and the mobile profile, whose receive
  windows do not grow, peaks the same. That remainder was not attributed.
- Hysteria keeps quinn's batch: it has one endpoint per client.
- `scripts/check-vendored-sources.sh` builds quinn's tests against
  crates.io quinn-proto, which has no `set_stream_receive_window`, so that
  step has failed to compile since `e98fe285` added quinn's forwarder to it.
  With the vendored quinn-proto, quinn's library tests pass with this patch
  on Linux: 17 passed, 3 ignored.

## Evidence and replay

- [`data/ab-default.jsonl`](data/ab-default.jsonl) and
  [`data/ab-mobile.jsonl`](data/ab-mobile.jsonl) hold every release-build
  run; [`data/batch-gro.jsonl`](data/batch-gro.jsonl) and
  [`data/batch-no-gro.jsonl`](data/batch-no-gro.jsonl) the instrumented
  matrices; [`data/residency-per-endpoint.jsonl`](data/residency-per-endpoint.jsonl)
  each instrumented run's peak resident pages and touched slots per buffer.
- [`scripts/`](scripts/) has the image (`Dockerfile`, which adds procps for
  the harness's `ps`), the in-container drivers (`run-one.sh` and
  `matrix-*.sh` for the matrices, `run-one-v2.sh` and `ab.sh` for the A/B),
  the summarizers, the instrumentation patch and the glibc program. Paths
  are this host's Docker volumes.
- Xray-core was cross-compiled offline from the Go module cache's
  `github.com/xtls/xray-core@v1.260327.1-0.20261021115930-1b1647cd9ddf`
  with `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags
  "-s -w -buildid= -X github.com/xtls/xray-core/core.build=1b1647c"`; only
  its Linux-only `vishvananda/netlink` came from the Go module proxy, checked
  against Xray-core's `go.sum`.
