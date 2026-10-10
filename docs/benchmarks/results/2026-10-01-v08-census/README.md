# VMess AES syscall and relay census — Apple M3 Pro

The remaining **one-flow AES upload gap is dominated by CPU time inside the OS**,
not evidence of an AES throughput ceiling. On 256 MiB, the unmodified Rust client
uses a median 234.0 ms CPU, of which 177.5 ms (75.9%) is system CPU; Xray-core uses
157.8 ms, including 68.9 ms system CPU. Median Unix syscall counts are 87,676 vs
18,312. Rust user CPU is lower in this set. Counts identify optimization targets;
they do not assign a causal CPU percentage to each syscall family.

A separate libc census finds about **34,827 scalar write calls in Rust vs 4,112
write/writev calls in Xray**, averaging 7.58 vs 64.18 KiB per call. Rust also makes
34,285 `getentropy` calls during the same-sized upload; the pinned Go clients call
`arc4random_buf` instead. Library entry calls and kernel syscalls are distinct.
No speed improvement, memory improvement or production runtime change is claimed
by this investigation.

## Identity and method

Measured stock Rust runtime `1804e17890baf4c3a587fbd86d6a17a0787ce9dd`; executable
SHA-256 `784ce279f375de47332cfb3efa7dd90905767fdd226f8cf5364f27263eb3d937`.
Instrumentation started from report-only source `e557e98`; application/build inputs
match that runtime. Xray-core v26.7.28 at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c` and sing-box 1.13.20 at
`56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778` retain the binaries from the
[preceding comparison](../2026-10-01-v08-batch/README.md). SDK pin remains unchanged.
[Host snapshot](data/host.json): M3 Pro, macOS 26.6.2; desktop SOCKS loopback, stock worker defaults. Each flow
verifies 256 MiB, using 65,536-byte driver blocks. One/eight flows, upload/download,
three rotating repeats. Fresh common Xray fixture and client processes.

All **84 full diagnostic trials pass**:

- 36 **kernel** trials: original, uninstrumented clients. Driver-side
  `proc_pidinfo(PROC_PIDTASKINFO)` snapshots before flow setup and after workload/
  500 ms settle record Unix/Mach syscall counts, context switches, user/system CPU.
  Warmup and process startup are excluded; flow setup and cleanup remain included.
- 36 **libc** trials: those same stock executables with a diagnostic interposition
  library counting call sizes and returns. Only the launched test client receives
  the library. These timings/RSS are excluded from performance conclusions.
- 12 **internal** trials: a temporary Rust build counts completed relay reads,
  activity messages, VMess records, copies, inner I/O polls and pending states.
  Drop summaries include the separate 1 KiB warmup. These timings/RSS are likewise
  excluded. Verified bytes include documented preface/READY/completion markers.

No builds or profiling overlap the accepted campaigns. Every repeated result and
range is retained in [summary data](data/summary.json). CPU counter conversion is
checked against the coarser independent `ps` samples in every trial. Darwin task
times use Mach ticks ([Apple source](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/bsd_kern.c));
the harness stores raw ticks, the host timebase (125/3), and nanoseconds. Initial
4 MiB calibration output mislabeled ticks as ns; those smoke trials remain
archived but are excluded from all final CPU tables. The corrected harness was
frozen before the full campaigns. Scalar/vector I/O and both randomness entry
points passed deterministic count/byte calibration.

## Uninstrumented client kernel counters

Medians of three repeats. Eight-flow rows transfer 2 GiB total; one-flow rows
transfer 256 MiB. User and system medians need not sum to the median total.
`candidate` denotes the existing production Rust binary.

| Workload / flows | Client | User ms | System ms | Total ms | System share | Unix calls |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| upload-1 | candidate | 56.5 | 177.5 | 234.0 | 75.9% | 87,676 |
| upload-1 | xray | 88.0 | 68.9 | 157.8 | 44.2% | 18,312 |
| upload-1 | singbox | 78.7 | 102.5 | 181.2 | 56.7% | 38,104 |
| download-1 | candidate | 70.5 | 109.2 | 179.7 | 60.7% | 71,481 |
| download-1 | xray | 69.0 | 55.6 | 125.5 | 44.0% | 13,199 |
| download-1 | singbox | 88.7 | 194.5 | 284.5 | 68.9% | 173,592 |
| upload-8 | candidate | 351.4 | 1057.3 | 1408.7 | 75.1% | 570,273 |
| upload-8 | xray | 868.0 | 1013.8 | 1881.9 | 53.5% | 194,658 |
| upload-8 | singbox | 691.5 | 1148.6 | 1839.6 | 62.8% | 275,649 |
| download-8 | candidate | 464.7 | 798.2 | 1262.8 | 63.2% | 456,345 |
| download-8 | xray | 787.4 | 1327.9 | 2115.3 | 62.8% | 254,285 |
| download-8 | singbox | 682.6 | 2156.3 | 2836.3 | 76.0% | 1,275,286 |

The eight-flow Rust points already use less CPU than both references in this set,
even with more syscalls than Xray. Thus fewer calls are not a universal speed or
CPU predictor: scheduling, syscall type and batching matter. The strongest
remaining target demonstrated here is the **single-flow upload** path. This
small diagnostic matrix does not replace the earlier 270-trial comparison or
establish full parity. It is not an isolated CPU-core or device-energy result.

## Separate libc call census

Write-family counts include failed/would-block attempts and small setup/control
writes. Rust `send` forwards to `sendto`; only the lower `sendto` layer is counted
in the table, avoiding double-counting. `write`, `writev` and `sendmsg` are added
where present. Bytes successfully returned by these families cover all verified
traffic (plus bounded protocol overhead). Mean sizes divide returned bytes by
all attempts, and do not describe TCP packet sizes.

| Workload / flows | Client | Write calls | Mean KiB/call | getentropy calls | arc4random_buf calls |
| --- | --- | ---: | ---: | ---: | ---: |
| upload-1 | candidate | 34,827 | 7.58 | 34,285 | 0 |
| upload-1 | xray | 4,112 | 64.18 | 0 | 36,286 |
| upload-1 | singbox | 20,531 | 12.82 | 0 | 20,207 |
| download-1 | candidate | 18,580 | 14.11 | 6 | 0 |
| download-1 | xray | 6,025 | 43.51 | 0 | 6 |
| download-1 | singbox | 36,887 | 7.11 | 0 | 6 |
| upload-8 | candidate | 278,634 | 7.57 | 274,274 | 0 |
| upload-8 | xray | 46,617 | 45.30 | 0 | 295,787 |
| upload-8 | singbox | 173,348 | 12.14 | 0 | 165,194 |
| download-8 | candidate | 151,072 | 13.88 | 49 | 0 |
| download-8 | xray | 73,552 | 28.51 | 0 | 47 |
| download-8 | singbox | 301,813 | 6.95 | 0 | 48 |

On one-flow upload, Xray issues a median 4,104 `writev` calls and presents 36,873
vector segments, roughly nine segments per call. Its pinned
[AuthenticationWriter](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/crypto/auth.go)
collects encrypted record buffers and the
[buffer writer](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/buf/writer.go)
passes them through `net.Buffers.WriteTo`. Its regular buffer limit is 8,192 bytes,
as in the Rust record writer. Vector segments/attempts are not asserted to equal
unique wire records, but both code and call census establish batching beyond one
record per send.

This is a **partial libc census**, not a complete syscall trace. In particular,
Xray's pinned [POSIX reader](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/buf/readv_posix.go)
invokes `SYS_READV` directly, bypassing libc interposition. Its missing libc readv
count is not zero kernel reads. Kernel totals come from the separate campaign.
No attempt is made to subtract counters between differently instrumented trials
or derive per-call CPU costs from those differences.

## Internal Rust work

Counts include the one warmup flow and protocol markers; byte conservation is
verified separately against each run's payload. A record is distinct from a
relay block, library call, socket poll or kernel syscall.

| Workload / flows | Records sealed | Records opened | Relay write_all calls | Activity notifications received |
| --- | ---: | ---: | ---: | ---: |
| upload-1 | 34,825 | 5 | 2,059 | 156 |
| download-1 | 4 | 36,875 | 18,589 | 120 |
| upload-8 | 278,581 | 26 | 16,467 | 1,247 |
| download-8 | 18 | 299,489 | 151,306 | 5,664 |

One-flow upload reads about 127 KiB per positive relay read on average, but emits
about 7.53 KiB plaintext per encrypted record. The relay already handles large
blocks; the VMess writer splits them and drains its single pending record before
accepting the next. The activity channel already coalesces most notifications:
roughly 156 are received for about 2,059 relay transfers. These counts give less
reason to prioritize idle-timer redesign than socket writes and padding entropy;
they do not prove the timer has zero cost. Pending counts and scheduling-sensitive
values are diagnostic observations, not stock-client performance estimates.

## Decision and memory constraint

There is no demonstrated protocol/Rust/AES ceiling. The evidence points to two
specific next experiments:

1. **Padding randomness on Darwin:** compare a suitable buffered OS CSPRNG path
   with the current per-record `getentropy` path, keeping session keys, IVs and
   nonces unchanged. `arc4random_buf`, observed in both pinned Go clients, is a
   concrete candidate. This could avoid an extra buffer per connection, but its
   speed and memory effects still need normal-release paired controls. Earlier
   AES entropy-cache and AWS-LC RNG experiments were rejected; see the
   [previous report](../2026-10-01-v08-relay/README.md). Fewer entropy calls alone
   are not a proven optimization.
2. **Bounded write batching:** send several already-encrypted records together,
   with an explicit memory budget and immediate short-request progress. Xray's
   design demonstrates the mechanism, not free memory savings. Validate both
   active traffic and retained RSS at 512 connections. Do not simply adopt the
   previously rejected 16-record buffering level.

No production code, SDK pin, crypto behavior or buffer policy was changed in this
census. All temporary source edits were restored, and the ordinary release
rebuild is byte-identical to the measured stock binary. No new physical-device,
release-artifact or energy acceptance is claimed.

## Evidence and verification

[Archive index](evidence-index.json) hashes all raw result files, diagnostic logs,
calibration probes, manifests, source patches and original source hashes.
Generated credentials/configs and executables are excluded. [Build identities](data/builds.json)
retain diagnostic binary/library/source hashes. The frozen library's scalar I/O,
vector segment counting and both randomness entrypoints are independently checked
in [calibration](data/calibration.json).

The verifier rehashes every archive member, verifies all complete trial matrices,
reconstructs every summary, checks per-flow byte conservation and CPU conversion,
and checks that the normal release digest and production source identity remain
unchanged. Diagnostic CPU/RSS results are not promoted to optimization evidence.

```sh
python3 docs/benchmarks/results/2026-10-01-v08-census/data/verify.py \
  --repo "$PWD" --report docs/benchmarks/results/2026-10-01-v08-census
```
