# Host performance, 0.10.1 candidate 3cef7c42 — 2026-11-18

Do not delete: release evidence. Full CI on the candidate: run 44003926752, all thirteen jobs
passed. Commands: `run-campaign.sh` (those of `docs/v010-release-evidence.md` "Performance", as the
0.10.0 campaign ran them), from the clean clone of the candidate commit
`../device-3cef7c42.noindex/candidate`; log `campaign.log`. Started 14:20:47Z, finished 15:14:08Z,
under `caffeinate -dimsu`. No device run, build or other campaign overlapped it. Load at the start
3.67 (`campaign-start-load.txt`: WindowServer, a browser and an IDE well under 100% each); no run
of the v010 suite saw compiler load and no collector rejected a block for ambient load.

Builds (`builds.log`, `build/*.json`, made 2026-11-17 02:42–03:06Z at background priority from the
same clone): baseline v0.9.0 `30928ad5` sha256 275cc1ec… and reference Xray-core v26.11.9 (CGO 0)
799824a3… reproduce every earlier campaign's hashes; candidate
b237e2b82bf2ed12943fe2fb53fdb95852343bc6c0679166abcc4c463e59d53d (byte-identical to the build from
#321's head that ran the host loopback checks), harness
51c8a741ee53b26451c83a4d02cfe8a44558e1740e933328f0a74991f6c52803.

## v010 suite (`v010/`, 14:20:47–14:55:08Z): manifest status pass, 200 runs

Every run returned 0. One flow, five repeats, paired with Xray-core's client over a common
Xray-core server; median of the pairwise ratios (0.10.0's `../../release-0100/perf-7eb199bb.noindex`
in brackets):

| | throughput, % of Xray-core | p95 latency, % of Xray-core | peak RSS, MiB (Xray-core) |
| --- | --- | --- | --- |
| mKCP (`mkcp-vless`) | 139.7 (132.1) | 101.2 (101.3) | 11.1 (60.4) [11.1] |
| MASQUE (`masque-h3`) | 150.3 (155.1) | 89.4 (87.7) | 12.6 (45.0) [12.8] |

The gate's thresholds (0.9.0's: throughput at least 50% of paired Xray-core, p95 latency at most
200%, sampled peak RSS at most 64 MiB) hold for every row. Pairwise mKCP throughput ratios: 84.5,
139.7, 155.2, 117.0, 164.4 (mKCP moves a lot between repeats on every candidate).

Outside the gate, MASQUE's one-flow download is a median 21.0% of Xray-core's client (pairs 66.9,
27.0, 21.0, 17.6, 19.9; candidate 18.8–109.2 MiB/s, Xray-core 91.4–169.7), against 11.8% on 0.10.0.
Upload on one flow 174.4%, full duplex 150.3%, download on eight flows 147.1%.

## Comparison against 0.9.0 (`release-comparison/`, 14:55:08–15:09:50Z)

`release-comparison/release-comparison.json` (candidate tree d430ce5f, baseline 0.9.0 tree
e55a6c3f), written by the collector. Medians, candidate as % of 0.9.0: throughput 94.0–106.2%,
p95 latency 91.6–109.8%, peak memory 96.3–127.5%.

Rows the collector calls `regression`, all memory, nine rows: http (113.3%), shadowsocks-aead
(114.9%), shadowsocks2022 (114.9%), socks (113.4%), trojan (112.0%), vless-reality (113.1%), vmess
(115.8%), xhttp-h2 (127.5%), xhttp-h3 (116.8%). The same family as 0.10.0's ten, less
hysteria2-memory (0.10.0: 113.2%; here 16.25 MiB median against 0.9.0's 16.88, 96.3%).

- xhttp-h2-memory: 0.9.0 11.58–13.38 MiB (median 11.89), candidate 13.91–15.80 (median 15.16). On
  0.10.0 the candidate measured 13.20–15.09 (median 13.77) against 0.9.0 11.67–15.02: the two
  candidates' samples overlap, and this run's 0.9.0 median is lower than 0.10.0's. vless-reality,
  which goes through the same rustls, is unchanged from 0.10.0 (median 9.95 against 10.02 MiB).
  No change of this release is known to touch XHTTP H2 apart from rustls. Read as the same
  regression as 0.10.0's, measured higher in this run; whether to re-measure is the owner's call.
- Close to the budgets, within them: socks-latency 109.2%, vmess-latency 109.8%,
  vmess-throughput 94.0%, xhttp-h1-memory 106.9%, wireguard-memory 106.0%.

## The four common measurements (`features/`, 15:09:50–15:14:08Z)

`scripts/run-v06-feature-benchmarks.py`, from the same clone with the pinned Xray-core v26.11.9
cloned into its git-ignored `Xray-core/` (676eaf66), Go 1.27.3, Rust 1.96.0; log `features.log`,
load at start and end in `features-start-load.txt` / `features-end-load.txt` (4.53 at the start,
just after the comparison's last run, 2.55 at the end). Five samples each, every threshold met
(`features/performance.json`, result pass):

| Metric | Median | Threshold |
| --- | ---: | --- |
| process-throughput | 542.2 MiB/s | at least 10 |
| vless-encryption-throughput | 365.0 MiB/s | at least 267.0 (half of plain VLESS's median) |
| ip-on-demand-latency | 0.165 ms | at most 1.165 (direct median + 1 ms) |
| xhttp-memory | 18.4 MiB | at most 64 |

The script builds its own CLI in `candidate/target` (sha256 87fdd48b…, not the isolated build
b237e2b8…: another target directory, so other embedded paths; same commit and tree, recorded in
`features/build-manifest.json`); its Xray-core is 3713f08e… (built by the script without
`-trimpath`). The clone stayed clean.
