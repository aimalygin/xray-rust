# v0.8 protocol comparison

Latest results: [CPU investigation and optimized runtime](benchmarks/results/2026-09-30-v08-cpu/README.md).
Runtime `ce6deef3fe1b3f8536c471235dd2a6c003e7e9e5` replaces the ARM software
AEAD backend and removes repeated record allocations/erasure. All 630 trials
pass; RSS remains lower than both references in all 70 cases. SS2022/VMess meet
45/72 bulk CPU point targets and 18/72 throughput targets under the 3% Mac
policy, versus 0/72 for both in the initial comparison. Overall parity remains
unmet. Paired controls measure CPU reductions of 68–89% and RSS scaling through
512 held connections; the two-worker CLI default is unchanged.

The [initial five-repeat comparison](benchmarks/results/2026-09-30-v08-protocols/README.md)
retains all 1050 primary trials and failed preparation attempts. The methodology
below describes that baseline; the optimized follow-up uses the same frozen
references and workload driver, with three repeats per point and separate
causal/memory controls. Exact identities and every deficit remain in each report.

Compare the full xray-rust, Xray-core and sing-box clients on the same host,
through the same SOCKS workload and a common Xray-core server. This is separate
from the candidate-only SOCKS/TUN matrix and the v0.7 regression campaign.

## Frozen implementations

- Initial xray-rust baseline: clean source
  `0250497b7f8aaca66b0086b95892558e7042cc98`, tree
  `89b36701a9f1c6f26212cc8f00484a47b2d4db1b`, Rust 1.96.0, locked release
  builds with incremental compilation disabled.
- Optimized xray-rust: `ce6deef3fe1b3f8536c471235dd2a6c003e7e9e5`, tree
  `07005cb7084a48e6ef793f53b1cd442d69c1b35d`; same compiler and release policy.
- The workload driver is built separately when a benchmark-only fix is needed.
  Its own commit/tree, compiler, command and binary digest are recorded in
  `--harness-build` metadata; it does not change the measured engine or SDK pin.
- Xray-core: v26.7.28, clean commit
  `5ca6f4b7d4dc20a881d4330e498892697627ec0c`, Go 1.26.0, CGO disabled.
- sing-box: v1.13.20, commit
  `56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778`, Go 1.26.0, CGO disabled,
  `with_utls,with_gvisor,with_quic,with_wireguard`. The preparation script checks
  the pinned module checksums and compares extracted source with the module
  archive. The module-cache build has no embedded Git revision; its verified
  module origin and executable hash are recorded instead.

Build the references before collecting measurements. The sing-box build is:

```sh
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 \
  go -C /absolute/module-cache/github.com/sagernet/sing-box@v1.13.20 \
  build -mod=readonly -trimpath -tags with_utls,with_gvisor,with_quic,with_wireguard \
  -ldflags '-X github.com/sagernet/sing-box/constant.Version=1.13.20' \
  -o /absolute/build/sing-box ./cmd/sing-box
```

`prepare-v08-protocol-comparison.py` consumes the Rust campaign's `builds.json`
and `go mod download -json github.com/sagernet/sing-box@v1.13.20` metadata. It
copies immutable executables into a new directory and writes `inputs.json`.
Pass `--harness-build /absolute/build/harness-build.json` for a separate driver
build (`commit`, `tree`, `rustc`, `build_arguments`, `incremental`, `sha256`).
Paths and SHA-256 hashes identify the actual binaries measured; the collector
commit is recorded separately and must not be substituted for runtime identity.

```sh
python3 scripts/prepare-v08-protocol-comparison.py \
  --root /absolute/comparison \
  --candidate /absolute/frozen/xray-rust --harness /absolute/frozen/xray-bench \
  --candidate-builds /absolute/frozen/builds.json \
  --xray /absolute/frozen/xray-core --singbox /absolute/build/sing-box \
  --singbox-source /absolute/build/sing-box-source.json
python3 scripts/run-v08-protocol-comparison.py \
  --inputs /absolute/comparison/inputs.json --output /absolute/comparison/smoke --smoke
python3 scripts/run-v08-protocol-comparison.py \
  --inputs /absolute/comparison/inputs.json --output /absolute/comparison/full --repeats 5
python3 scripts/summarize-v07-protocol-parity.py /absolute/comparison/full \
  --output /absolute/comparison/summary-strict.json
python3 scripts/summarize-v07-protocol-parity.py /absolute/comparison/full \
  --max-regression-pct 3 --output /absolute/comparison/summary-mac-3pct.json
```

## Matched profiles and workloads

| Profile | Wire settings |
| --- | --- |
| Trojan | TCP + verified TLS, Chrome fingerprint, HTTP/1.1 ALPN |
| SS2022 AES-128 | `2022-blake3-aes-128-gcm`, 16-byte key |
| SS2022 AES-256 | `2022-blake3-aes-256-gcm`, 32-byte key |
| SS2022 ChaCha20 | `2022-blake3-chacha20-poly1305`, 32-byte key |
| VMess AES-128 | AEAD, `aes-128-gcm`, alterId 0 |
| VMess ChaCha20 | AEAD, `chacha20-poly1305`, alterId 0 |
| VMess auto | AEAD, `auto`, alterId 0 |

VMess uses global padding, the default unauthenticated length mode, and XUDP
for the driver's non-DNS/non-QUIC UDP destinations. sing-box's explicit options
match the pinned Rust/Xray defaults. SS2022 and VMess have no extra TLS layer.
Trojan pins the generated leaf certificate in Rust/Xray; sing-box pins its
public key only after the preparation step verifies the same leaf digest.
General connection multiplexing, extra transports and SS2022 identity chains
are outside this baseline. No Shadowsocks AEAD-2017 or legacy VMess is included.

Each profile has one and eight concurrent flows, with TCP upload, download,
full-duplex, TCP echo and UDP echo: **70 cases**. Five repeats for each of three
clients give **1050 measured trials**, preceded by 210 short smoke trials in
the initial campaign. The optimized follow-up uses three repeats, **630 trials**.
Bulk transfers validate 256 MiB per flow/direction in 64 KiB chunks. Echo uses
1000 sequential requests per flow, 1024-byte TCP or 1200-byte UDP payloads;
UDP is request/response latency, not maximum packet-rate saturation. Smoke uses
four bulk chunks or ten echo requests and cannot establish performance.
For bulk setup, all clients send the same one-byte preface before receiving
the server's readiness marker. Both markers are validated outside the timed
payload window and excluded from byte totals. This exercises client-initiated
traffic and avoids a separately retained pinned-Xray VMess server-first failure.
The old server-first smoke failure is not relabeled as a successful trial.

Every case/repeat gets a fresh common server and credentials. Client processes
are fresh and their order rotates. A verified TCP echo and graceful close
precede measurement. Config translation runs before spawning the actual client;
Python and OpenSSL CPU are excluded. Startup wall time includes the verified
warmup, and startup/lifetime CPU are retained separately from workload CPU.
Go/Tokio worker and GC overrides are cleared, leaving each client's defaults.
Do not run compilation, another benchmark or other heavy local work in parallel.
The collector checks compiler activity before each block and observes it once
per second during each client run. It also flags `ANECompilerService` at 5% CPU
or above. These samples cannot prove an otherwise idle host; any detected
interference remains visible and prevents a passing parity assessment.

## Interpretation and boundaries

All traffic stays on the measurement host. SOCKS and proxy listeners use
loopback; target servers bind the driver's selected local host address.
The common Xray server and driver consume host CPU but are not included in
the measured client's resource counters. Sampled RSS is taken every 100 ms;
it excludes kernel buffers and can miss short allocation peaks. macOS process
CPU counters are coarse, especially for small workloads. Bulk rate uses the
validated transfer window; connection setup and echo RTT remain separate.

Publish all five samples, medians/ranges, p95/p99 echo latency, failed trials,
byte counts, cleanup checks, engine hashes and paired bootstrap ratio intervals.
Five repetitions on one shared Mac cannot establish universal performance.
The existing Mac comparison policy is reported explicitly: RSS strictly lower,
throughput at least 97% of each reference, CPU/latency/startup at most 103%.
Also retain the strict zero-allowance assessment. A completed comparison can
legitimately report `not_met` or `unproven`; successful traffic is not a parity
claim, and uncertainty must not be hidden by a performance allowance.

This campaign does not compare TUN implementations. The existing Rust-only
fd-backed TUN driver is not exposed equivalently by the stock sing-box CLI;
forcing an alternate ingress would change the measured path. WAN, packet loss,
mobile SDK/device behavior, battery and physical-network transitions require
separate evidence. The previously deferred Apple device gate remains open.
