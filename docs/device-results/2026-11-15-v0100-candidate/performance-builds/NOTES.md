# Host performance, fourth 0.10.0 candidate 7eb199bb — 2026-11-15

Do not delete: release evidence. Full CI on the candidate: run 43748376213 (running when this was
made; the coordinator watches it). Commands: `run-campaign.sh` (those of
`docs/v010-release-evidence.md` "Performance"), run from the stand's clean clone
`../device-7eb199bb.noindex/candidate`; log `campaign.log`. Machine quiet at the start
(`campaign-start-load.txt`: load 2.75 and falling, no compiler, no container load, no other
campaign); started 19:04:58Z, finished 19:54:27Z. No device run overlapped it.

Builds (`builds.log`, `build/*.json`): baseline v0.9.0 `30928ad5` sha256 275cc1ec… and reference
Xray-core v26.11.9 (CGO 0) 799824a3… reproduce every earlier campaign's hashes; candidate
d9ba9b0e70e009059804094f799e16ac0bad83a8f3975083a131c0f963eb5eef, harness
c3ed969cc8a57b179c4bd4ad07c01719ebaaa5862d0106fe972b0f94fe2ce854.

## v010 suite (`v010/`, 19:04:58–19:39:41Z): manifest status pass, 300 run directories

Every run returned 0 and no run saw compiler load. One flow, five repeats, paired with Xray-core's
client; median of the pairwise ratios (third candidate's `../perf-706a766c.noindex/v010` in
brackets):

| | throughput, % of Xray-core | p95 latency, % of Xray-core | peak RSS, MiB (Xray-core) |
| --- | --- | --- | --- |
| mKCP (`mkcp-vless`) | 132.1 (103.0) | 101.3 (100.9) | 11.1 (59.8) [11.3] |
| MASQUE (`masque-h3`) | 155.1 (168.4) | 87.7 (88.2) | 12.8 (41.9) [12.7] |

Every row is within the gate (throughput ≥ 90%, latency ≤ 110%, memory ≤ 110% of Xray-core).
Pairwise mKCP throughput ratios: 136.4, 132.1, 133.3, 129.7, 60.8. mKCP moves a lot between
repeats on every candidate (third: 90.1–174.2); the one pair at 60.8% is that noise, the median
holds the gate.

## Comparison against 0.9.0 (`release-comparison/`, 19:39:41–19:54:27Z)

`release-comparison/release-comparison.json` (candidate tree b637ff77, baseline 0.9.0 tree
e55a6c3f), written by the collector. Medians, candidate as % of 0.9.0: throughput 90.6–111.7%,
p95 latency 90.9–107.0%, peak memory 107.6–117.7%.

Rows the collector calls `regression`, all memory, ten rows: http (115.1%), hysteria2 (113.2%),
shadowsocks-aead (115.6%), shadowsocks2022 (115.4%), socks (115.3%), trojan (112.8%),
vless-reality (113.9%), vmess (116.5%), xhttp-h2 (111.2%), xhttp-h3 (117.7%). The same family as
on the second candidate (the same ten); on the third, xhttp-h1 stood in for xhttp-h2 (here
xhttp-h1-memory is 107.6%, xhttp-h2 111.2%).

- trojan-throughput, 83.3% on the third candidate, is 99.3% here (0.9.0 2010–2086 MiB/s,
  candidate 2010–2046): both binaries at the lower of the two levels seen on the third.
- Close to the throughput budget, within it: vmess-throughput 90.6% (0.9.0 2334–2607, candidate
  2188–2440 MiB/s) and vless-reality-throughput 91.1% (0.9.0 2212–2637, candidate 2093–2487).
  Neither protocol's code changed between the third and fourth candidates (#299 touches QUIC
  carriers and the resolver); on the third they were 111.4% and 99.7%. Both 0.9.0 and the candidate
  spread by 10–15% between repeats in both rows, so this reads as run-to-run spread, not a code change;
  whether to re-measure is the owner's call.

## The four common measurements (`features/`, 2026-11-15 21:33:32–21:37:54Z)

Asked for by the coordinator for the archive (the checker's `MEASUREMENT_COMPARISONS`; the v0.10
guide's "Performance" section does not mention them). `scripts/run-v06-feature-benchmarks.py
features`, run from the stand's clean clone `../device-7eb199bb.noindex/candidate` with the pinned
Xray-core v26.11.9 cloned into its git-ignored `Xray-core/` (676eaf66), Go 1.27.3, Rust 1.96.0; log
`features.log`, load at start and end in `features-start-load.txt` / `features-end-load.txt`
(load 2.1 at the start, 2.3 at the end, no compiler or other campaign during the measurement; the
script's own `cargo build` ran first, 21:32–21:33Z). Five clean samples each, every threshold met
(`features/performance.json`, result pass):

| Metric | Median | Threshold |
| --- | ---: | --- |
| process-throughput | 546.6 MiB/s | at least 10 |
| vless-encryption-throughput | 359.2 MiB/s | at least 272.7 (half of plain VLESS's median) |
| ip-on-demand-latency | 0.166 ms | at most 1.162 (direct median + 1 ms) |
| xhttp-memory | 18.5 MiB | at most 64 |

The script builds its own CLI in `candidate/target` (sha256 65a8ac23…, not the isolated build
d9ba9b0e…: another target directory, so other embedded paths; same commit and tree, recorded in
`features/build-manifest.json`); its Xray-core is 2999bd8e… (built by the script without
`-trimpath`). The clone stayed clean.

Correction to the v010 table above: "the gate" there quoted 90% / 110% / 110%. The archive's gate
rows are computed as 0.9.0's `summarize_protocols_v09.py` did (docs/v010-release-evidence.md), with
its thresholds: throughput at least 50% of paired Xray-core, p95 latency at most 200%, sampled peak
RSS at most 64 MiB. Every row clears both readings.
