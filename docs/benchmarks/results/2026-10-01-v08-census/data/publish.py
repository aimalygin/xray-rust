#!/usr/bin/env python3
import hashlib,importlib.util,json,subprocess,tarfile,tempfile
from pathlib import Path
ROOT=Path('/Users/antonmalygin/xray-rust');BASE=ROOT/'target/v08-census-investigation';REPORT=ROOT/'docs/benchmarks/results/2026-10-01-v08-census'
assert subprocess.check_output(['git','remote','get-url','origin'],cwd=ROOT,text=True).strip()=='git@github.com:aimalygin/xray-rust.git'
REPORT.mkdir(parents=True,exist_ok=True);(REPORT/'data').mkdir(exist_ok=True)
files=[]
for camp in ['kernel','libc','internal','smoke-kernel','smoke-libc','smoke-internal','smoke-libc-v2']:
 p=BASE/camp
 files.append(p/'manifest.json')
 files.extend(sorted(p.glob('*/result.json')))
 if camp in ['internal','smoke-internal']:files.extend(sorted(p.glob('*/stderr.log')))
for name in ['instrument.py','instrumentation.patch','census.rs','task_info.rs','interpose.c','run.py','summarize.py','builds.json','builds-initial-calibration.json','calibration.json','reference-inspection.json','host.json','probe.c','probe-v2.c','probe.map','probe-v2.map','build.log','build-v2.log','restored-release-build.log','summary.log']:
 files.append(BASE/name)
files=sorted(set(files));index={str(p.relative_to(BASE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
with tarfile.open(REPORT/'measurements.tar.gz','w:gz') as archive:
 for p in files:archive.add(p,arcname=str(p.relative_to(BASE)),recursive=False)
(REPORT/'evidence-index.json').write_text(json.dumps(index,indent=2)+'\n')
for name in ['summary.json','host.json','builds.json','calibration.json','reference-inspection.json','summarize.py','publish.py','run.py','instrument.py','interpose.c','census.rs','task_info.rs']:(REPORT/'data'/name).write_bytes((BASE/name).read_bytes())
s=json.loads((BASE/'summary.json').read_text())
def med(c,case,v,key):return s[c][case][v][key]['median']
def integer(v):return f'{v:,.0f}'
rows=[]
for case,vs in s['kernel'].items():
 for v in ['candidate','xray','singbox']:
  m=vs[v];label=case.replace('vmess-aes128-socks-','')
  rows.append(f"| {label} | {v} | {med('kernel',case,v,'user_ms'):.1f} | {med('kernel',case,v,'system_ms'):.1f} | {med('kernel',case,v,'cpu_ms'):.1f} | {med('kernel',case,v,'system_cpu_pct'):.1f}% | {integer(med('kernel',case,v,'unix_calls'))} |")
ios=[]
for case in s['libc']:
 for v in ['candidate','xray','singbox']:
  ios.append(f"| {case.replace('vmess-aes128-socks-','')} | {v} | {integer(med('libc',case,v,'deduplicated_write_calls'))} | {med('libc',case,v,'mean_write_bytes')/1024:.2f} | {integer(med('libc',case,v,'getentropy_calls'))} | {integer(med('libc',case,v,'arc4random_buf_calls'))} |")
inside=[]
for case in s['internal']:
 inside.append(f"| {case.replace('vmess-aes128-socks-','')} | {integer(med('internal',case,'candidate','vmess_records.seals'))} | {integer(med('internal',case,'candidate','vmess_records.opens'))} | {integer(med('internal',case,'candidate','relay_direction.write_all_calls'))} | {integer(med('internal',case,'candidate','relay_idle.activity_received'))} |")
readme='''# VMess AES syscall and relay census — Apple M3 Pro

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
'''+ '\n'.join(rows)+'''

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
'''+ '\n'.join(ios)+'''

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
'''+ '\n'.join(inside)+'''

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
python3 docs/benchmarks/results/2026-10-01-v08-census/data/verify.py \\
  --repo "$PWD" --report docs/benchmarks/results/2026-10-01-v08-census
```
'''
(REPORT/'README.md').write_text(readme)
print('Report:',REPORT,'archive members:',len(index),'archive bytes:',(REPORT/'measurements.tar.gz').stat().st_size)
