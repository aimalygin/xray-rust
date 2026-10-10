#!/usr/bin/env python3
"""Render the report and LF CSV from the archived numeric summaries."""
import csv
import json
from pathlib import Path
import sys

repo=Path(sys.argv[1]).resolve();report=repo/'docs/benchmarks/results/2026-10-01-v08-batch';data=report/'data'
def read(name):return json.loads((data/name).read_text())
inputs=read('inputs.json');controls=read('control-summary.json');summary=read('summary-mac-3pct.json');ci=read('ci-run.json');sdk=read('mobile-ci-run.json')
cases={c['id']:c for c in json.loads((repo/'target/v08-batch-investigation/comparison/manifest.json').read_text())['cases']}
def change(a,b):return (b/a-1)*100
lines=[f'''# Bounded VMess receive batching — Apple M3 Pro

Runtime `{inputs['candidate']['commit']}`, tree `{inputs['candidate']['tree']}`;
release executable SHA-256 `{inputs['candidate']['sha256']}`.
SDK commit `{sdk['headSha']}` pins this exact runtime. The preceding runtime
is `fdc0dad1aa1ffe39d3621008ab66512b30ccf452`, already optimized for accelerated
AEAD, record I/O, erasure and relay allocation; see the
[previous report](../2026-10-01-v08-relay/README.md).
The baseline source `00f660b` adds only the previously documented test/report fixes.
The normal committed release rebuild is byte-identical to the measured candidate.

Rust 1.96.0, locked offline release build, incremental compilation disabled.
M3 Pro, 12 cores, 18 GiB, macOS 26.6.2, AC power. The common harness, Xray-core
v26.7.28 and sing-box 1.13.20 remain frozen at the previous pins; exact source,
module and binary identities are in [inputs](data/inputs.json).
These are desktop SOCKS loopback results, not physical-device, energy or WAN results.

## Decision and mechanism

Keep **at most two available VMess TCP records per read**. Previously each
successful read returned at most one record fragment. The new reader can deliver
a second authenticated record into the caller's existing buffer, reducing relay
iterations and writes when data is ready. It immediately returns bytes already
obtained when the next record would block; there is no batching delay. The poll
budget is bounded, UDP still delivers one whole datagram, and every record is
authenticated before delivery. Plaintext is erased as it is copied, including
partial reads. If a later record fails after progress, the valid prefix is returned
first and the original error is delivered on the next read; the failed stream
cannot resume writes. Keys, nonces, crypto providers, record limits, worker counts
and relay buffer caps are unchanged.

The 16-record experiment improved AES one-flow download from 1591 to 2104 MiB/s
and reduced CPU from 210 to 150 ms, but increased settled RSS by **33–41 MiB at
512 connections after 128 KiB exchanges**. It also had a one-flow AES upload
slowdown. It was rejected. No new payload buffer is allocated by either reader;
the cost comes with the shared relay growing its buffer more aggressively. Two
records retain a smaller, measured memory tradeoff.

Nine symbol-enabled native `sample` traces of the baseline show hardware AES
(`aesv8_gcm_8x_enc_128` / `aesv8_gcm_8x_dec_128`) and socket, entropy, copying and
erasure paths. Their top-of-stack counts are retained in
[the diagnostic summary](data/profile-summary.json). These are wall samples
including waiting threads, with small entries omitted by `sample`; they are not
CPU percentages. Instrumented timings are excluded. The initial oversized 1 GiB
profiling probe failed with a broken pipe and remains archived as a failed
probe; its exact cause was not established. Nine bounded 375 MiB probes passed.
The controlled normal-release measurements below determine the decision.

## Paired controls

Five campaigns contain **280 fresh-client trials**: 72 for the rejected 16-record
variant, 72 for two records, 48 latency/UDP trials, 60 independent five-repeat
confirmations and 28 seven-repeat upload checks. Client order rotates; both
variants use the identical fixture and verified payload. Each bulk flow transfers
256 MiB per direction, with one or eight flows. CPU means client CPU consumed for
completed work, not utilization. Startup CPU is separate; CPU counter granularity
is 10 ms. RSS samples are process RSS, excluding driver, server and kernel memory.
This interactive desktop is not a CPU-isolated host. All samples and ranges,
including conflicting upload results, are in [control data](data/control-summary.json).
Compilation, tests, profiling and archive generation do not overlap accepted
performance measurements.

Initial two-record controls (three repeats):

| Profile / flows / workload | CPU ms, baseline → candidate | CPU change | MiB/s, baseline → candidate | Speed change |
| --- | ---: | ---: | ---: | ---: |''']
def table(group):
 rows={(r['case'],r['version']):r['metrics'] for r in controls[group]}
 for case in sorted({c for c,v in rows}):
  a=rows[case,'baseline'];b=rows[case,'batch2'];cpu=a['cpu_ms']['median'];cpu2=b['cpu_ms']['median'];rate=a['throughput_mib_s']['median'];rate2=b['throughput_mib_s']['median']
  lines.append(f"| {case.replace('-socks-', ' / ')} | {cpu:.0f} → {cpu2:.0f} | {change(cpu,cpu2):+.1f}% | {rate:.0f} → {rate2:.0f} | {change(rate,rate2):+.1f}% |")
table('batch2-controls')
lines.extend(['','Independent five-repeat confirmation:','','| Profile / flows / workload | CPU ms, baseline → candidate | CPU change | MiB/s, baseline → candidate | Speed change |','| --- | ---: | ---: | ---: | ---: |'])
table('confirmation-controls')
lines.extend(['','AES download improves in both independent campaigns: one-flow speed +9.9% and +11.7%, eight-flow speed +13.9% and +25.6%; CPU also falls in both. Upload is less stable. The five-repeat AES eight-flow point regressed 4.1% in speed after improving in the first controls. A further seven-repeat check was run to investigate that concern, retaining every original point:','','| Profile / flows / workload | CPU ms, baseline → candidate | CPU change | MiB/s, baseline → candidate | Speed change |','| --- | ---: | ---: | ---: | ---: |'])
table('upload-confirmation')
lines.extend(['','The AES upload slowdown did not reproduce. Its seven-repeat throughput ranges are broad and overlap (baseline 1970–2719, candidate 1973–2728 MiB/s); the positive median is not treated as a reliable upload improvement. ChaCha eight-flow upload changes sign between campaigns as well; the final point is −2.3% in speed and +1.3% CPU. The repeatable result supporting this change is AES download, with a bounded memory cost, rather than uniform gains across traffic.','', '## Memory after short and long transfers','','42 fresh clients hold 0, 32, 128 and 512 verified TCP connections. Each connection first echoes 8 KiB, 128 KiB or 1 MiB in each direction. Three rotating repeats, five RSS samples per point. This includes memory retained after bulk activity, which the previous 8 KiB-only check did not characterize. These are settled RSS points, not saturation peaks or exact heap allocations.','', '| Warmup per connection / profile | Baseline at 512, MiB | Two records, MiB | Delta | 16 records, MiB |','| --- | ---: | ---: | ---: | ---: |'])
for group,label in [('small-held-memory','8 KiB'),('active-held-memory','128 KiB'),('bulk-held-memory','1 MiB')]:
 rows={(r['profile'],r['version']):r['rss_mib'] for r in controls[group] if r['connections']==512}
 for profile in ['vmess-aes128','vmess-chacha20']:
  a=rows[profile,'baseline']['median'];b=rows[profile,'batch2']['median'];large=rows.get((profile,'batch16'),{}).get('median')
  lines.append(f"| {label} / {profile} | {a:.3f} | {b:.3f} | {b-a:+.3f} MiB ({change(a,b):+.1f}%) | {f'{large:.3f}' if large is not None else '—'} |")
lines.extend(['','Small exchanges show no higher median RSS. After 1 MiB exchanges, the retained variant adds 3.7–3.8 MiB at 512 connections (about 4.2–4.3%). This is a real tradeoff, not a claim of free batching. Adaptive buffer growth and OS RSS make individual runs variable: one AES candidate point was 70.33 MiB versus the other two near 92 MiB; its cause was not established and it is retained. All four connection counts and every sample remain in the data.','', '## Short-request latency','','Three repeats per case; median of per-trial latency statistics, microseconds. TCP median changes are 0–3 µs. Tail points are mixed and are not claimed to improve uniformly. UDP packet semantics are unchanged.','','| Profile / workload / flows | Median, baseline → candidate | p95 | p99 |','| --- | ---: | ---: | ---: |'])
rows={(r['case'],r['version']):r['metrics'] for r in controls['latency-controls']}
for case in sorted({c for c,v in rows}):
 a=rows[case,'baseline'];b=rows[case,'batch2'];pairs=[f"{a[k]['median']:.0f} → {b[k]['median']:.0f}" for k in ['latency_median_us','latency_p95_us','latency_p99_us']]
 lines.append('| '+case.replace('-socks-',' / ')+' | '+' | '.join(pairs)+' |')
lines.extend(['','## Frozen three-client VMess comparison','','270/270 trials pass: AES, ChaCha and auto × five workloads × one/eight flows × three clients × three repeats. All 90 Rust trials pass. Whole-case selection preserves original client rotation and all attempts; a complete case may be retried only for observed compiler interference. No result is selected by performance. This new comparison covers VMess; the preceding report retains the full earlier Trojan/SS2022/VMess matrix at its own runtime identity.','', '| AES, one flow | Rust CPU ms / MiB/s / RSS MiB | Xray-core | sing-box |','| --- | ---: | ---: | ---: |'])
for traffic in ['upload','download','full-duplex']:
 row=next(r for r in summary['rows'] if r['case']==f'vmess-aes128-socks-{traffic}-1');values=[]
 for version in ['candidate','xray','singbox']:
  m=row['versions'][version]['metrics'];values.append(f"{m['cpu_ms']['median']:.0f} / {m['throughput_mib_s']['median']:.0f} / {m['rss_mib']['median']:.2f}")
 lines.append('| '+traffic+' | '+' | '.join(values)+' |')
comparisons=[c for r in summary['rows'] for c in r['comparisons'].values()]
rss=sum(c['metrics']['rss_mib']['meets_point_target'] for c in comparisons)
bulk=[c for r in summary['rows'] if cases[r['case']]['traffic'] in ['upload','download','full-duplex'] for c in r['comparisons'].values()]
cpu=sum(c['metrics']['cpu_ms']['meets_point_target'] for c in bulk);rate=sum(c['metrics']['throughput_mib_s']['meets_point_target'] for c in bulk)
lines.extend(['',f'RSS is strictly lower in **{rss}/{len(comparisons)}** VMess case/reference comparisons. Under the explicit 3% desktop allowance, {cpu}/{len(bulk)} bulk CPU and {rate}/{len(bulk)} throughput point targets are met. Overall measured parity status: **{summary["parity"]["status"]}**. These point counts do not remove three-repeat uncertainty or establish full-product parity. See [all medians](comparison.csv), [strict results](data/summary-strict.json) and [3% results](data/summary-mac-3pct.json).','',f'''## Validation and reproduction

133 proxy tests and 493 core library tests pass (two existing manual core tests
ignored), along with all-target proxy clippy and formatting. The two new unit
tests cover bounded batching, prompt return after progress, partial records,
deferred EOF errors and plaintext erasure. Existing forged-frame, authenticated
length, fragmented I/O, backpressure and UDP boundary tests also pass. Ten
additional local integration tests cover pinned Xray and independent sing-box
VMess carriers, TCP/UDP/TUN/DNS/lifecycle, and Xray Mux.

[Full core CI]({ci['url']}) targets this exact runtime; recorded status:
**{ci['conclusion'] or ci['status']}**. The first supply-chain
job stopped on a partial crates.io download of `futures-lite` (curl error 18),
after the vendored archive checksums passed. The failed log and original status
are retained; only failed CI work was retried at the same commit. This is not a
source or dependency update. [SDK CI]({sdk['url']}) recorded status:
**{sdk['conclusion'] or sdk['status']}**. Canonical adapter/source identity checks
pass. ABI 1.8 and 0.8.0-rc.1 metadata are unchanged.

The [archive index](evidence-index.json) authenticates each archived numeric
result, manifest, attempted block, rejected patch, diagnostic trace and test log.
Generated fixture credentials and executables remain local. Verification
reconstructs both parity summaries and every control/memory summary, proves
complete-case selection, checks exact runtime/SDK CI identities and the normal
release rebuild digest. Debug benchmark smoke output in test logs is correctness
evidence only.

```sh
python3 docs/benchmarks/results/2026-10-01-v08-batch/data/verify.py \\
  --repo "$PWD" --report docs/benchmarks/results/2026-10-01-v08-batch \\
  --rebuild target/v08-comparison-driver/release/xray-rust
```

Physical Apple testing remains deferred by the owner; Android hardware and
candidate-bound publication artifacts remain outstanding. These host results
do not inherit earlier device evidence or establish mobile battery performance.
'''])
(report/'README.md').write_text('\n'.join(lines))
with (report/'comparison.csv').open('w',newline='') as f:
 writer=csv.writer(f,lineterminator='\n');metrics=['cpu_ms','throughput_mib_s','rss_mib'];versions=['candidate','xray','singbox']
 writer.writerow(['case']+[v+'_'+k for v in versions for k in metrics])
 for r in summary['rows']:writer.writerow([r['case']]+[r['versions'][v]['metrics'][k]['median'] for v in versions for k in metrics])
print('Wrote README and LF CSV:',report)
