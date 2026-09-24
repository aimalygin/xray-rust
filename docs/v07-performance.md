# v0.7 performance verification

Protocol competitor comparison: [2026-09-20 parity investigation](benchmarks/results/2026-09-20-v07-parity/README.md).
H2/TUN memory follow-up: [2026-09-21 profiles and repeated controls](benchmarks/results/2026-09-21-h2-tun-memory/README.md).
H2/TUN allocation follow-up: [allocation lifetimes and rejected arena-reuse experiments](benchmarks/results/2026-09-21-h2-allocation-lifetime/README.md).
Previous regression evidence: [fixes and campaign](benchmarks/results/2026-09-19-v07-fixes/README.md).
The [initial comparison](benchmarks/results/2026-09-19-v07/README.md) is retained with its failures.

Owner decision on 2026-09-21: keep the current implementation and defer further
H2/TUN RSS investigation and optimization to a future release, with no version
assigned. The measured memory target remains unmet; both arena-reuse prototypes
remain excluded. Hysteria2 performance gaps and uncertain comparison intervals
remain recorded separately. The dated evidence and acceptance results are unchanged.

The previous fix candidate passed both historical gates and 990/990 primary runs.
Those changes restore idle-memory budgets and H1 TUN throughput, reduce Hysteria2 TUN memory,
and resolve the observed WireGuard load failures. Follow-up results, residual
tradeoffs and rejected alternatives are recorded in the final report; this
host evidence does not replace mobile-device/network acceptance.

Those historical counts apply to the previous candidate. They do not establish
Hysteria2/WireGuard parity with other implementations. The new comparison uses
the user-approved Mac target: strictly lower sampled process RSS, throughput
at least 97% of each reference, and CPU/latency/startup at most 103%. This explicit
3% performance allowance accounts for the imperfect host; reliability has no
allowance. Original differences, failed runs, environmental quality flags and
uncertain intervals remain visible. The 15% investigation thresholds below are
separate historical review flags. See the dated report for accepted changes,
fresh checks, rejected experiments and remaining deficits.

## Comparing native implementations and full clients

Build checksum-pinned releases of Xray, sing-box (with QUIC, gVisor and
WireGuard), native Hysteria, and the official wireguard-go userspace adapter in
`tools/wireguard-reference/cmd/bench-client`. The latter is explicitly a small
library adapter; sing-box and Xray provide the complete-client controls. Record
source commits, compiler versions, build commands and executable SHA256s.

```sh
python3 scripts/prepare-v07-protocol-parity.py --root /absolute/parity \
  --rust /absolute/frozen/xray-rust --harness /absolute/frozen/xray-bench \
  --xray /absolute/pinned/xray --singbox /absolute/pinned/sing-box \
  --hysteria /absolute/pinned/hysteria --wireguard /absolute/pinned/native-wireguard-client
python3 scripts/run-v07-protocol-parity.py --root /absolute/parity \
  --repeats 5 --output /absolute/parity/evidence/local
python3 scripts/run-v07-protocol-parity.py --root /absolute/parity \
  --repeats 5 --one-way-ms 25 --rate-mbps 100 --bulk-mib 2 \
  --echo-iterations 30 --output /absolute/parity/evidence/rtt50
python3 scripts/summarize-v07-protocol-parity.py /absolute/parity/evidence/local \
  --max-regression-pct 3 --output /absolute/parity/evidence/local/summary-mac-3pct.json --check
```

The four clients use a fresh common Xray server and the same validated SOCKS
workload. TCP covers upload/download/duplex and RTT; UDP is concurrent echo,
not saturation or maximum packet rate. The native adapter has one outstanding
UDP request per association. Each measured client is spawned directly after
configuration translation; Python/OpenSSL startup is outside its CPU total.
A verified TCP echo and graceful close precede steady measurements. Startup
wall time includes that echo, and startup CPU/lifetime CPU are retained.
Warmup is not used for the separate cold-connection stress checks.

The delayed path is a bounded userspace UDP relay, not physical WAN evidence.
Its intentional drops, errors and leaked child processes invalidate collection.
Kernel UDP loss is separate and must not be mistaken for a zero-loss path.
RSS sampling is every 100 ms and excludes kernel socket memory and the common
server. Both queue bounds and kernel buffer requests should be reported.
Three-to-five repetitions and coarse CPU counters cannot prove exact equality;
the checker reports `not_met` or `unproven` when the requested target lacks
supporting evidence. Its default allowance remains zero for reproducibility;
`--max-regression-pct 3` explicitly enables the Mac policy. `--output` preserves
the original strict summary alongside the new assessment. The allowance never
waives strictly lower external RSS, failed trials or environmental interference.
`binary_builds` records adjacent frozen-build metadata; the collector workspace
patch alone must never be presented as the measured binary's exact source.
Worker overrides from the parent shell are cleared. Use `--candidate-workers`
or `--reference-go-workers` for explicit controls; the latter sets GOMAXPROCS
only for prepared Go clients. Keep stock-default and equal-worker comparisons
separate, since CPU scheduling defaults can change the result substantially.

The campaign compares immutable release binaries of v0.6.1 and the v0.7
development candidate on the same host, with the same Rust compiler and release
profile. The Hysteria2/WireGuard workloads are new measurements of the candidate;
v0.6.1 does not implement those protocols. Functional interoperability results
and phone recovery timings are separate from these process measurements.

## Preparing the frozen binaries

Create clean baseline/candidate checkouts at the exact commits named in the dated
report, plus a separate checkout containing this driver. Build each engine and
its original `xray-bench` from its own checkout, using `cargo build --locked --release -p xray-cli --bin xray-rust`
and `cargo build --locked --release -p xray-bench --bin xray-bench`.
Copy them immediately to
`CAMPAIGN/bin/{baseline,candidate}/`; later builds must not replace these copies.
Build the modified driver separately as `CAMPAIGN/bin/protocol-bench`.

Use a distinct Cargo target directory for each source checkout, including
temporary canonical vendor reconstructions. Sharing a target between roots can
reuse stale same-package fingerprints when source mtimes precede a previous
build. The investigation detected this and rebuilt affected candidates in fresh
targets before accepting their measurements. Keep immutable executable copies,
source/tree identities, full source patches and hashes alongside each result;
a successful build log alone does not prove which source was measured.

Build `CAMPAIGN/bin/xray-core` from the exact clean reference checkout with
`GOTOOLCHAIN=go1.26.5 GOENV=off GOWORK=off go build -o /absolute/campaign/bin/xray-core ./main`.
The collector verifies its embedded Git build identity. Preserve compiler/build
logs and each binary's SHA-256 alongside the manifests. Never build or run
another workload concurrently with measurements.

## Existing regression gates

Run the original scripts from each clean source checkout, with the same toolchain:

```sh
GOTOOLCHAIN=go1.26.5 bash scripts/run-v05-pre-device-benchmarks.sh /absolute/output/regression
GOTOOLCHAIN=go1.26.5 python3 scripts/run-v06-feature-benchmarks.py /absolute/output/features
```

The existing thresholds remain unchanged. Keep the five raw repetitions and all
failures. A failing validator does not invalidate completed raw measurements, and
its first reported failure does not mean subsequent budgets passed.

## Additional transport and protocol measurements

`scripts/run-v07-performance.py` consumes a campaign directory containing clean
`baseline` and `candidate` source checkouts and their matching release binaries
under `bin/{baseline,candidate}/{xray-rust,xray-bench}`. `bin/xray-core` must be built
from exact clean Xray-core v26.7.28. The new `xray-bench protocol-run REQUEST.json`
driver is built separately, leaving both measured engines unchanged.

```sh
python3 scripts/run-v07-performance.py --root /absolute/campaign \
  --harness /absolute/campaign/bin/protocol-bench --suite legacy \
  --output /absolute/campaign/evidence/legacy
python3 scripts/run-v07-performance.py --root /absolute/campaign \
  --harness /absolute/campaign/bin/protocol-bench --suite tun \
  --output /absolute/campaign/evidence/tun
python3 scripts/run-v07-performance.py --root /absolute/campaign \
  --harness /absolute/campaign/bin/protocol-bench --suite new \
  --output /absolute/campaign/evidence/new
python3 scripts/summarize-v07-performance.py /absolute/campaign/evidence/new
```

`--smoke` uses smaller workloads and one repetition for harness verification.
`--case` selects an explicit diagnostic case; `--iterations` changes its work size.
All overrides are recorded, and those
results cannot substitute for the original full campaign.

- **Legacy:** the existing per-version harness runs VLESS/REALITY bulk download
  plus WebSocket, HTTPUpgrade, gRPC and XHTTP H1/H2/H3 upload/download/full-duplex
  with one/eight flows. Clean H1 runs transfer 32 MiB per direction/flow; the other
  legacy streams transfer 64 MiB. The H1 volume was fixed before the clean rerun
  to keep its paced uploads near 16 seconds while retaining five repetitions.
  XHTTP modes are packet-up/stream-up/stream-one respectively.
- **TUN:** one common new driver runs Freedom, VLESS/TLS and XHTTP H1/H2/H3
  through each immutable engine's fd-backed TUN. One/eight TCP flows upload,
  download and transfer simultaneously in both directions. No host TUN interface
  or OS route is created: datagrams carry Darwin-utun framing over a socketpair.
- **Additional REALITY/Vision:** `--suite reality` covers SOCKS and TUN with
  one/eight flows and upload/download/full-duplex. It uses one fresh shared
  reference server after eight seconds of warmup, and fresh client processes.
  Its raw byte-pattern workload is separate from the original REALITY bulk test.
- **New protocols:** Hysteria2 and standard WireGuard against the same pinned
  Xray server, through SOCKS and TUN, one/eight flows, all three bulk directions,
  1024-byte TCP echo latency and 1200-byte UDP request/reply traffic. UDP has one
  outstanding request per concurrent flow; its throughput is validated echo
  throughput, not a maximum unidirectional packet-rate claim. TUN TCP latency
  retains the old sequential driver and reports `concurrent_flows: 1`; bulk TCP
  and UDP use concurrent flows.

There are five fresh-process repetitions per case and version. Apart from the
additional REALITY suite described above, generic runs also start a fresh reference server with fresh synthetic keys, avoiding shared peer
state across WireGuard client restarts; paired version
order alternates. The generic bulk driver sends 32 MiB per SOCKS flow and 4 MiB
per TUN flow in 64 KiB chunks. Every payload byte is validated. TUN UDP also
checks per-flow sequence numbers and rejects duplicate or mismatched replies.
The synthetic socketpair requests 1 MiB send/receive queues at both ends and
records the kernel-accepted sizes. Darwin defaults (2/4 KiB) caused the initial
smoke download to measure socket backpressure, about 0.6 MiB/s even for Freedom;
those preliminary values are excluded from capacity comparisons. The historical
regression driver remains unchanged.
The inner TUN TCP driver has 64 KiB per-direction socket buffers and a bounded
2048-packet output queue. These driver limits can constrain observed throughput.

Only the client engine's process RSS and cumulative CPU time are sampled, at
100 ms intervals in the generic driver. It retains a 500 ms pre-work interval
and a post-work interval; samples are not guaranteed continuous RSS peaks. CPU
time includes setup/settle work within the sampled interval. Generic throughput
counts upload plus download application bytes over the recorded transfer window;
thus full-duplex counts both directions. Only echo workloads contribute round-trip latency to the comparison summary;
the TUN bulk driver records time-to-ready samples separately from echo latency.
Echo latency includes the first request
and may include lazy protocol setup. Fixture and driver CPU are excluded from the
reported engine CPU but share the same host, so this is not device/WAN capacity.
The old REALITY fixture may contact its cover destination during warmup;
application benchmark payload remains on the measurement host.

The manifest records versions, source trees, lockfile/binary/harness hashes,
scheduled axes and every command/exit status. The summarizer requires all
scheduled repetitions exactly once and checks payload counts and axes. A failed
group gets no passing median. More than 15% throughput loss or more than 15%
latency/CPU/RSS growth marks a case for investigation; it is not proof of a
regression without considering raw spread, duration and repeatability. Preserve
the original group when collecting a separate diagnostic repeat.

## WireGuard reference-client control

When the Rust client's eight-flow SOCKS upload/full-duplex cases fail, run the
same workloads through the pinned Go client to help isolate the failure:

```sh
python3 scripts/run-v07-wireguard-control.py --root /absolute/campaign \
  --harness /absolute/campaign/bin/protocol-bench \
  --output /absolute/campaign/evidence/wireguard-control
python3 scripts/summarize-v07-performance.py /absolute/campaign/evidence/wireguard-control
```

This diagnostic uses five fresh server/client repetitions per case, the same
payload volumes and driver, and `noKernelTun: true` to keep the Go client in
userspace. It is an isolation control, not a v0.6.1 protocol comparison. Complete
the primary campaign before running it; do not overlap competing workloads.

## Process lifetime and evidence validity

The first generic-driver collections were invalidated after discovering that a
fixture handle did not automatically kill/wait for its child. Leftover engines
could contaminate subsequent measurements. The original release gates ran before
this error and remain separate. Every affected collection has `quality.json`
with `usable_for_performance: false`; the summarizer rejects it.

The corrected driver owns a kill/wait guard on success, failure and timeout. The
collector also refuses to start over existing campaign processes, checks the
isolated process group after each run and records an empty engine inventory.
Leaked descendants make the run fail and stop the campaign. Tests exercise
normal completion, a deliberately leaked child, interruption and Rust error-path
cleanup. Only the subsequent clean collections support the dated conclusions.

## Follow-up comparisons and controlled delay

Freeze engine binaries before starting a comparison. The follow-up collector
accepts explicit builds, uses one driver for every version, alternates paired
order, and retains failures and process cleanup evidence:

```sh
python3 scripts/run-v07-performance-followup.py \
  --engine baseline=/absolute/old/xray-rust \
  --engine candidate=/absolute/fixed/xray-rust \
  --harness /absolute/protocol-bench --reference /absolute/xray-core \
  --suite tun --repeats 5 --output /absolute/results/tun
python3 scripts/summarize-v07-performance.py /absolute/results/tun
```

Supported suites are `new`, `tun`, `reality`, and `legacy`. Use a single candidate
for new protocols absent from v0.6.1. Generic suites also accept repeated
`--case` selections, `--iterations`, and explicit `--connections` counts from
1 through 16. For example, `--suite new --connections 16 --case
wireguard-socks-full-duplex-16` stresses every WireGuard TCP slot. Keep the full
matrix separately from diagnostic subsets. Builds, tests and measurements run
serially; other CPU-intensive work can affect these host-local results.

The delayed collector places a bounded userspace UDP relay between the client
and the same pinned reference. It changes no host routes or interfaces. Defaults
add 25 ms in each direction and serialize packets at 100 Mbit/s independently
per direction:

```sh
python3 scripts/run-v07-delayed-protocol.py \
  --engine baseline=/absolute/old/xray-rust \
  --engine candidate=/absolute/fixed/xray-rust \
  --harness /absolute/protocol-bench --reference /absolute/xray-core \
  --protocol wireguard --path socks --repeats 3 \
  --one-way-ms 25 --rate-mbps 100 --iterations 32 \
  --output /absolute/results/wireguard-delay
python3 scripts/summarize-v07-performance.py /absolute/results/wireguard-delay
```

`--protocol hysteria2 --path tun` exercises the reduced TUN upload queues across
a delayed path. Bulk bytes are validated by the same driver. Relay queue drops
and errors invalidate a delay-only comparison; kernel UDP loss is not counted by
those relay counters. Scheduler jitter, startup and the userspace implementation
remain part of this controlled host experiment. It does not replace physical
mobile-device or real-network acceptance. Do not combine the earlier unpaced
relay diagnostics with the paced results.
