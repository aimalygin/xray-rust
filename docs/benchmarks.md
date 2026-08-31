# Benchmarks

The benchmark harness compares `xray-rust`, the cloned Xray-core, and sing-box under the same compatible local workloads. It is a process-level harness: each engine runs as a child process with an equivalent generated config, the workload sends validated traffic through SOCKS5, and the harness samples OS RSS/CPU counters while the process is alive.

The active Xray-core oracle is `v26.7.28` at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. Auto-builds require that exact
checkout and reject source changes; caller-supplied binaries must report Xray
`26.7.28` and are identified by their executable SHA-256. Published
`v26.5.9` sections below are retained as historical result groups, not as the
current harness target.

## Current RC4 publication

The current immutable evidence is the
[2026-08-31 Xray-core v26.7.28 result group](benchmarks/results/2026-08-31-v26.7.28/README.md).
It contains exactly 139 release series and 695 embedded results, five clean
runs per series. Its manifest is checked by
`scripts/check-benchmark-publication.py`; a publication with a missing case,
wrong revision/hash, dirty provenance, debug binary, failed run, or modified
omission is rejected.

The official GitHub latest-release response fetched on 2026-08-31 resolved
stable sing-box `v1.13.20`. RC4 pins that tag, revision
`56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778`, the exact
`with_gvisor,with_utls,badlinkname,tfogo_checklinkname0` build tags, and the
measured binary SHA-256. Xray-core remains exact `v26.7.28` at the full commit
above. A new comparator or date must create a new result group; dated evidence
never overwrites historical charts.

Three reviewed boundaries are disclosed rather than repaired by selecting a
better retry:

- stable sing-box is omitted from the two REALITY workloads with
  `--skip-sing-box` because its REALITY `ClientVer` 1.8.1 is below Xray-core's
  default `minClientVer` 26.3.27; generic harness support remains available
  for compatible or patched binaries;
- sing-box is omitted only from `stream-grpc-full-duplex-32` after two frozen
  campaigns timed out following three and four completed runs; later isolated
  successes are diagnostics, not substitutes for either campaign;
- Xray-core is omitted only from `xhttp-pressure-xhttp-h3-32` after a frozen
  reset, a 300-second exact-retry timeout, and reduced-load failures above four
  flows. The xray-rust full 32-flow workload still passed five clean campaign
  runs.

Only reviewed `summary.json` files are committed. The host-specific raw run
directories remain outside Git in a deterministic checksum-addressed archive;
its location and digest are in the manifest. The exact absolute inputs and
argument matrix are in the dated `commands.sh`. Localhost evidence does not
establish controlled RTT/loss behavior, mobile device energy, or wide-area VPN
performance.

A bounded migration smoke on 2026-08-28 passed all 19 workloads available to
the Xray-core engine, all six stream transports, five stream traffic drivers,
three XHTTP modes, `reality-matrix` 7/7, and all six cases in
`bench-xhttp-memory.sh` for both engines. The ignored artifacts are under
`target/benchmarks/v26728-smoke/`; they validate compatibility and harness
coverage, not publication-quality performance numbers.

## First Slice

Supported workloads:

- `idle`
- `tcp-freedom`
- `tcp-bulk-throughput`
- `routed-tcp-freedom`
- `many-idle-flows`
- `reconnect-burst`
- `mixed-long-lived`
- `udp-freedom`
- `tun-udp-freedom`
- `tun-fake-dns`
- `tun-fake-dns-tcp`
- `tun-dns-proxy`
- `tun-tcp-freedom`
- `tun-tcp-stale-flows`
- `tun-reality-blackhole`
- `udp-vless`
- `udp-xudp`
- `vision-xudp`
- `reality-vision-xudp`
- `reality-vision-bulk-throughput`
- `grpc-bulk-throughput`
- `stream-transport`

The harness writes results under:

```text
target/benchmarks/<run-id>/<engine>/<workload>/
```

For one run, the workload directory contains:

- `config.json`: generated engine config.
- `result.json`: summary RSS, CPU, throughput bytes, status, and workload metadata.
- `samples.csv`: raw timestamped process samples.
- `stdout.log` and `stderr.log`: child process logs.
- `summary.json`: min/median/p95 aggregate summary. With one run, all three values match the single run.

When `--runs N` is greater than `1`, the workload directory contains `summary.json` plus one subdirectory per raw run:

```text
target/benchmarks/<run-id>/<engine>/<workload>/run-001/
target/benchmarks/<run-id>/<engine>/<workload>/run-002/
target/benchmarks/<run-id>/<engine>/<workload>/run-003/
```

Current `result.json` and `summary.json` files carry the generated `run_id`
and a `provenance` object. Its JSON fields are `harness_profile` (`debug` or
`release`), optional `workspace_git` with `revision` and optional `dirty`,
optional `engine_source_git` with the measured engine checkout's `revision`
and optional `dirty`, optional `harness_binary_path`, `harness_binary_sha256`,
`engine_binary_path`, `engine_binary_sha256`, and `working_directory`, plus
`invocation_args`. `workspace_git` is the runtime checkout state observed at
the end of the run; it is not an embedded build revision and can differ from
the source used by an older binary. The SHA-256 fields identify the exact
harness and measured engine executable files at run end. `invocation_args` is
the canonical effective `xray-bench run` CLI argument vector rather than a
shell-quoted string, so those arguments can be replayed without guessing how
paths were escaped; it does not capture environment variables or reconstruct
the binaries' build source. A repeated-run summary is written only when every
raw result has the same run ID and provenance; fields default cleanly when
older stored results are read.

For `stream-transport`, both result files also record `stream_transport`,
`stream_traffic`, and (for XHTTP) `xhttp_mode`, `xhttp_profile`, and the
effective `xhttp_max_post_bytes`; `settle_ms` records the post-flow sampling
window. Packet-up pressure runs add
`uplink_write_ops` and `uplink_write_ops_per_second`. The effective axes are
also present in `provenance.invocation_args`, so summaries from different
transport, traffic, or XHTTP-mode cases are rejected instead of being merged.

## Run xray-rust Only

```sh
cargo run -p xray-bench -- run --engine xray-rust --workload idle --duration-ms 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --connections 1 --iterations 10 --payload-size 1024
cargo run --release -p xray-bench -- run --engine xray-rust --workload tcp-bulk-throughput --connections 1 --iterations 2048 --payload-size 4194304 --run-timeout-ms 300000
scripts/fetch-geodata.sh --output-dir /private/tmp/bench-geodata
cargo run --release -p xray-bench -- run --engine xray-rust --workload routed-tcp-freedom --geodata-dir /private/tmp/bench-geodata --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
cargo run -p xray-bench -- run --engine xray-rust --workload many-idle-flows --connections 100 --duration-ms 1000
cargo run -p xray-bench -- run --engine xray-rust --workload reconnect-burst --connections 16 --iterations 25
cargo run -p xray-bench -- run --engine xray-rust --workload mixed-long-lived --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload udp-freedom --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-udp-freedom --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-fake-dns --connections 1 --iterations 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tun-fake-dns-tcp --connections 16 --iterations 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tun-dns-proxy --transport both --connections 32 --iterations 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tun-dns-proxy --transport udp --dns-upstream-transport tcp-routed --connections 32 --iterations 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tun-dns-proxy --transport both --dns-upstream-transport tcp-local --connections 32 --iterations 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tun-tcp-freedom --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-tcp-stale-flows --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-reality-blackhole --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload udp-vless --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload udp-xudp --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload vision-xudp --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload reality-vision-xudp --xray-core-bin /path/to/xray-core --connections 1 --iterations 10 --payload-size 512
cargo run --release -p xray-bench -- run --engine xray-rust --workload reality-vision-bulk-throughput --xray-core-dir Xray-core --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust --workload grpc-bulk-throughput --xray-core-dir Xray-core --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust --workload stream-transport --stream-transport xhttp-h2 --traffic full-duplex --xhttp-mode stream-up --xray-core-dir Xray-core --connections 1 --iterations 4096 --payload-size 65536 --run-timeout-ms 300000
cargo run --release -p xray-bench -- run --engine xray-rust --workload stream-transport --stream-transport xhttp-h3 --traffic full-duplex --xhttp-mode stream-one --xray-core-dir Xray-core --connections 1 --iterations 4096 --payload-size 65536 --run-timeout-ms 300000
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --runs 5 --connections 8 --iterations 1000 --payload-size 4096
cargo run --release -p xray-bench -- route-probe --iterations 100000 --rules 64 --outbounds 8
cargo run --release -p xray-bench -- route-probe --iterations 100000 --rules 64 --outbounds 8 --dns-candidates 8
cargo run --release -p xray-bench -- dns-policy-probe --iterations 10000 --servers 4 --matchers 4096
```

By default, the harness uses `target/debug/xray-rust` or builds it with:

```sh
cargo build -p xray-cli --bin xray-rust
```

Use `--xray-rust-bin <path>` to point at an already built binary.

## Stream Transport Release Matrix

`stream-transport` runs the same validated SOCKS/TCP workload through VLESS
over WebSocket, HTTPUpgrade, gRPC, or XHTTP. The currently executable axes are:

- `--stream-transport ws|httpupgrade|grpc|xhttp-h1|xhttp-h2|xhttp-h3`.
- `--traffic upload|download|full-duplex|packet-up|held-open`. `held-open`
  establishes every requested logical flow, keeps it open for
  `--duration-ms`, and closes it without application payload. `packet-up`
  waits for a target acknowledgement after every payload write so iterations
  cannot collapse into a few large buffered POSTs.
- `--xhttp-mode packet-up|stream-up|stream-one`, valid only for XHTTP and
  defaulting to `packet-up`.
- `--xhttp-profile legacy-extra-h1-packet-up` selects the legacy share-link
  memory profile described below and implies `xhttp-h1` plus `packet-up`.
- `--xhttp-max-post-bytes N` changes XHTTP `scMaxEachPostBytes` independently
  from `--payload-size`; the named legacy profile defaults it to `500000`.
- `--settle-ms N` keeps sampling after logical flows close.
- The existing `--connections`, `--iterations`, `--payload-size`, `--runs`,
  and process-sampling options. One iteration is one validated payload chunk
  per logical flow.

The SOCKS-stage setup fields stop at the local SOCKS reply. For this workload,
`setup_total_us` continues until the target's validated ready marker comes
back through VLESS, so an engine that acknowledges SOCKS before completing a
lazy transport handshake cannot hide that delay between setup and the
payload-only transfer window.

Except for the explicit plaintext legacy profile below, the fixture is a local
Xray-core VLESS server with a generated self-signed TLS certificate. Each run
stores the certificate, private key, fixture config,
and fixture logs below `fixture/<transport>-server/`. Only the client engine
process is sampled; the fixture is excluded from RSS/CPU counters but still
shares loopback CPU with it. The generated matrix is:

| Transport | TLS ALPN | Compared clients |
| --- | --- | --- |
| WebSocket | `http/1.1` | xray-rust, Xray-core, sing-box |
| HTTPUpgrade | `http/1.1` | xray-rust, Xray-core, sing-box |
| gRPC | `h2` | xray-rust, Xray-core, sing-box |
| XHTTP H1 | `http/1.1` | xray-rust, Xray-core |
| XHTTP H2 | `h2` | xray-rust, Xray-core |
| XHTTP H3 | `h3` over UDP/QUIC v1 | xray-rust, Xray-core |

The `xhttp-h3` selector requires TLS with the exact configured ALPN list
`["h3"]` and uses a UDP fixture port plus process-log readiness rather than a
TCP probe. The Rust client config explicitly selects default
`finalmask.quicParams`. The live Xray-core functional matrix has passed
`packet-up`, `stream-up`, and `stream-one`; those tests establish protocol
interoperability, not throughput or resource parity.

Xray-core clients pin the generated certificate SHA-256; xray-rust and
sing-box use their explicit local-fixture insecure mode. This keeps every
case encrypted and ALPN-equivalent without depending on a public CA. The
legacy `grpc-bulk-throughput` workload remains unchanged for historical
comparisons: it still uses cleartext gRPC and its old one-way traffic driver.

### Legacy XHTTP H1 packet-up memory profile

`--xhttp-profile legacy-extra-h1-packet-up` reproduces the effective transport
shape of the reported share link without retaining its customer address or
UUID. It is intentionally plaintext HTTP/1.1 (`security: none`) and emits the
legacy one-level `extra` object exactly as follows; the outer synthetic host is
`vless.test` and the path is `/`:

```json
{
  "host": "vless.test",
  "path": "/",
  "mode": "packet-up",
  "extra": {
    "noGRPCHeader": false,
    "scMaxConcurrentPosts": 100,
    "scMaxEachPostBytes": "500000",
    "scMinPostsIntervalMs": "60",
    "xmux": {
      "cMaxReuseTimes": 0,
      "hKeepAlivePeriod": 0,
      "hMaxRequestTimes": "600-900",
      "hMaxReusableSecs": "1800-3000",
      "maxConnections": 16
    },
    "xPaddingBytes": "100-1000"
  }
}
```

`scMaxConcurrentPosts` remains in the emitted profile because it is part of
the legacy input, but current Xray ignores that removed field. The separate
`--xhttp-max-post-bytes` flag replaces only the string value above, allowing a
controlled 16 KiB comparison while leaving every other profile field intact.

Run the local memory matrix with:

```sh
XRAY_CORE_DIR=/path/to/Xray-core scripts/bench-xhttp-memory.sh
```

The script runs five repeats by default: held-open cases at 1, 16, and 32
flows; a 16-flow, 16 KiB max-POST control; and 1000 acknowledged packet-up
iterations at 1 and 16 flows. One thousand iterations crosses the profile's
`hMaxRequestTimes` upper bound of 900. Its environment variables can change
durations, repeats, sample rate, payload size, traffic iterations, and output
directory. Each raw `samples.csv` appends a
`phase` column (`startup`, `workload`, `opening`, `traffic`, `held-open`,
`settle`, or `complete`). `result.json` also contains `memory_phases`, with
sample count and first/median/peak/last RSS for every observed phase. Only the
client engine process is sampled: the Xray-core fixture and the Apple Network
Extension container overhead are excluded.

Use these regression guardrails on five-run medians. They are designed to
catch transport-buffer regressions, not to claim a universal Network
Extension memory ceiling:

- every run finishes with `status: ok`, contains a `held-open` or `traffic`
  phase as appropriate, and contains `settle` when `--settle-ms` is non-zero;
- at 16 held flows, the 500000-byte profile's held-open median RSS is no more
  than 4096 KiB above the otherwise identical 16384-byte control; a roughly
  8 MiB difference is the expected signature of an eager 500000-byte buffer
  per flow;
- during sustained traffic, the final 20% median RSS is no more than
  `max(4096 KiB, 5%)` above the first 20% median after opening;
- final settle RSS does not exceed the preceding held/traffic peak by more
  than 4096 KiB. Allocator retention is allowed; RSS need not return to its
  startup level.

Provenance records the executable SHA-256 and
`engine_source_git.revision`/`dirty`. For a source-backed Xray-core comparison,
pass the checkout with `--xray-core-dir` and do not also select an explicit
binary (the script does this), especially when separating the active v26.7.28
reference from older groups such as v26.5.9 across `4c384271`. Whenever
`--xray-core-bin` is present, source provenance is deliberately omitted even if
`--xray-core-dir` is also present; the binary SHA-256 is the exact identifier.

Abrupt OOM/SIGKILL is a known artifact gap. The sampler currently writes
`samples.csv` and `result.json` only after the workload future returns, so a
killed engine can leave logs and a run directory without partial samples.
Preserving samples during arbitrary process death needs a broader streaming
artifact-writer refactor and is deliberately outside this benchmark change.

#### Branch-local XHTTP memory validation (2026-08-27)

A release-mode macOS loopback run validated the profile while it was added.
The xray-rust workspace was dirty at `e8825ed`; Xray-core was v26.5.9 at
`1bdb488`. These numbers measure only the engine process and are development
regression anchors, not an Apple Network Extension memory budget.

Five-run medians for 16 held flows (`duration=3 s`, `settle=1 s`) were:

| Engine | max POST | held-open RSS | peak RSS |
| --- | ---: | ---: | ---: |
| xray-rust | 500000 | 7,312 KiB | 7,376 KiB |
| xray-rust | 16384 control | 7,216 KiB | 7,280 KiB |
| Xray-core v26.5.9 | 500000 | 34,960 KiB | 35,008 KiB |
| Xray-core v26.5.9 | 16384 control | 34,784 KiB | 34,800 KiB |

The xray-rust 500000-to-control held-flow delta was therefore 96 KiB, well
below the 4 MiB guardrail. An earlier development build that materialized one
500000-byte vector per active flow showed about a 7.5 MiB delta in the same
single-run comparison; that result directly motivated the data-proportional
8 KiB H1 packet buffer.

One 16-flow rollover stress run used 1000 acknowledged 16 KiB writes per flow
(16,000 operations and 250 MiB total), crossing every configured
`hMaxRequestTimes=600-900` limit:

| Engine | Result | Duration | Ops/s | Peak RSS | first-to-last 20% traffic RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| xray-rust | ok | 64.7 s | 256 | 9,760 KiB | +48 KiB |
| Xray-core v26.5.9 | ok | 78.0 s | 213 | 41,696 KiB | +1,776 KiB |

Both engines completed the rollover workload in this topology; the run did
not reproduce an Xray-core process failure. The xray-rust release binary was
identified by SHA-256 `5e170018395254b7468ca238d92c8a8e94318157c51d80a57b0b6176aa4e7624`;
the local Xray-core binary was
`abc61e1ecaef469d0a0f1c841abf746366058a835ca998b7e287aaea37da03aa`.

### Recorded branch-local release smoke (2026-08-10)

The following results are a loopback smoke snapshot collected with a release
harness and release engine binaries. The workspace was dirty at revision
`dbf5df3`; the Xray-core checkout was at `1bdb488`. They are regression
evidence for that exact local state, not a publication or performance-parity
claim.

The one-flow smoke passed 12/12 cases for `xray-rust` and the same 12/12 cases
for Xray-core: full-duplex WebSocket, HTTPUpgrade, and gRPC, plus `packet-up`,
`stream-up`, and `stream-one` for each of XHTTP H1, H2, and H3. A short
32-flow, one-run full-duplex smoke also passed for gRPC and XHTTP H2/H3
`stream-up`:

| Transport | xray-rust | Xray-core |
| --- | ---: | ---: |
| gRPC | 5163 Mbps | 4794 Mbps |
| XHTTP H2 `stream-up` | 4195 Mbps | 3533 Mbps |
| XHTTP H3 `stream-up` | 1492 Mbps | 1767 Mbps |

Those 32-flow values are single-run health checks; their ordering and ratios
must not be treated as stable performance results. The representative repeated
H3 result used one logical flow, full-duplex `stream-up`, and five runs of
1024 x 64 KiB payloads, or 64 MiB in each direction per run:

| Engine | Throughput min / median / p95 | Median CPU | Median peak RSS | Run ID |
| --- | ---: | ---: | ---: | --- |
| xray-rust | 2054 / 2131 / 2157 Mbps | 1300 ms | 15984 KiB | `1786396487197` |
| Xray-core | 1836 / 2161 / 2187 Mbps | 1660 ms | 37296 KiB | `1786396498142` |

The VLESS REALITY Vision matrix also passed 21/21 cases (three fingerprints by
seven traffic kinds), run ID `1786396283275`.

All of these runs used local loopback fixtures. No controlled RTT/loss run was
performed, and the full 42-case matrix (36 base cases plus six XHTTP packet
pressure cases), five runs per case, was not run. Consequently this snapshot
does not establish throughput, resource-use, congestion-controller, or overall
performance parity with Xray-core.

The smallest release gate is 36 base cases: six transports, three traffic
directions, and 1 or 32 simultaneous logical flows. Use XHTTP `stream-up` for
that base matrix so its split downlink/uplink lifecycle is exercised without
mixing packet POST pacing into the streaming throughput number. Run the
commands with a release harness and explicit release engine binaries, five
times per case. Size `iterations × payload-size × connections` so the measured
transfer window lasts at least one second on the test machine; the values
below are a starting point, not a publication constant.

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo build --release -p xray-cli --bin xray-rust

for transport in ws httpupgrade grpc xhttp-h1 xhttp-h2 xhttp-h3; do
  for traffic in upload download full-duplex; do
    for flows in 1 32; do
      xhttp_args=()
      case "$transport" in xhttp-*) xhttp_args=(--xhttp-mode stream-up) ;; esac
      cargo run --release -p xray-bench -- compare \
        --workload stream-transport --stream-transport "$transport" \
        --traffic "$traffic" "${xhttp_args[@]}" \
        --connections "$flows" --iterations 4096 --payload-size 65536 \
        --runs 5 --run-timeout-ms 300000 \
        --xray-rust-bin target/release/xray-rust \
        --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN"
    done
  done
done
```

Add six XHTTP packet-pressure cases (`xhttp-h1`/`xhttp-h2`/`xhttp-h3` × 1/32
flows):

```sh
for transport in xhttp-h1 xhttp-h2 xhttp-h3; do
  for flows in 1 32; do
    cargo run --release -p xray-bench -- compare \
      --workload stream-transport --stream-transport "$transport" \
      --traffic packet-up --xhttp-mode packet-up \
      --connections "$flows" --iterations 4096 --payload-size 16384 \
      --runs 5 --run-timeout-ms 300000 \
      --xray-rust-bin target/release/xray-rust --xray-core-dir Xray-core
  done
done
```

A canonical targeted H3 `stream-one` release comparison is:

```sh
cargo run --release -p xray-bench -- compare \
  --workload stream-transport --stream-transport xhttp-h3 \
  --traffic full-duplex --xhttp-mode stream-one \
  --connections 32 --iterations 4096 --payload-size 65536 \
  --runs 5 --run-timeout-ms 300000 \
  --xray-rust-bin target/release/xray-rust --xray-core-dir Xray-core
```

`uplink_write_ops_per_second` counts payload-bearing `write_all` operations
issued by the benchmark client. It is deliberately **not** labelled HTTP POST
rate: TCP buffering and the XHTTP packet uploader may coalesce or split those
writes. Measuring actual POST rate needs an instrumented reverse proxy or
transport-level counter and is a separate benchmark wave. `stream-one` is
available for targeted XHTTP sweeps but is not an extra dimension in the
smallest release gate.

The recorded HTTP/3 release smoke is not enough for a performance-parity
claim. The phase-one engine deliberately holds QUIC receive windows static at
2 MiB per stream and 3 MiB per connection where Xray's quic-go path can adapt
toward 6 MiB and 15 MiB; its standard BBR setting is a Quinn-BBR approximation;
and its pool conservatively allows one active HTTP request per QUIC connection.
Loopback runs cannot quantify these differences. Run the complete base and
packet-pressure matrices above, plus targeted `stream-one` and `stream-up`
sweeps, and compare H3 with both Xray-core H3 and this client's XHTTP H2.
Controlled RTT/loss runs are still required to expose fixed-window,
connection-pool, and congestion-controller behavior.

The portable harness reports process CPU, peak RSS, setup time, validated
throughput, and the packet-up write-operation metric. It does not claim heap
allocation counts: `ps` cannot provide comparable Go/Rust allocation data.
Use a separately recorded Instruments/heap-profiler run when allocation
evidence is needed, and do not merge those numbers into this matrix.

## REALITY Fingerprint Matrix

`reality-matrix` is an in-process `xray-rust` functional/benchmark matrix for
VLESS `xtls-rprx-vision` over REALITY against a real local Xray-core server
fixture. It starts `Core` directly with `StartupProbeOptions`, so the connection
startup path includes the same startup probe hook used by the Apple packet tunnel
extension. The startup probe is always run first for each fingerprint as an
active REALITY/Vision readiness probe for the Xray-core fixture; if
`startup-probe` is not selected in `--traffic`, the warmup result is omitted
unless it fails. The local topology is:

```text
traffic client -> SOCKS 127.0.0.1:<ephemeral> -> xray-rust Core
  -> VLESS REALITY Vision -> local xray-core server fixture -> local target
```

By default, the command runs every `XRAY_REALITY_CAPABLE_FINGERPRINTS`
fingerprint and every traffic kind:

- `startup-probe`: HTTP `204` probe through the REALITY outbound.
- `tcp-connect`: SOCKS CONNECT to a local TCP target, then close.
- `tcp-echo-small`: validated small TCP echo payload.
- `tcp-echo-body`: validated larger TCP echo payload.
- `http-first-byte`: HTTP GET through the tunnel, wait for first response body byte.
- `http-body`: HTTP GET through the tunnel, read and validate the full response body.
- `udp-xudp-echo`: SOCKS UDP ASSOCIATE through Vision/XUDP to a local UDP echo target.

Examples:

```sh
cargo run -p xray-bench -- reality-matrix --xray-core-dir Xray-core
cargo run -p xray-bench -- reality-matrix --xray-core-dir Xray-core --fingerprints chrome,hellochrome_120_pq --traffic startup-probe,tcp-connect,http-body,udp-xudp-echo --iterations 3 --body-bytes 1048576
```

Useful options:

- `--fingerprints <csv>`: comma-separated supported fingerprints, or `all`.
- `--traffic <csv>`: comma-separated traffic kinds, or `all`.
- `--iterations <n>`: repeat each traffic case.
- `--small-payload-size <bytes>`: payload for `tcp-echo-small` and `udp-xudp-echo`.
- `--body-bytes <bytes>`: payload/body size for `tcp-echo-body` and `http-body`.
- `--probe-timeout-ms <ms>`: startup probe timeout. The matrix default is
  15000ms because the local Xray-core REALITY fixture can spend up to about 5s
  preparing its first post-handshake record detector path; pass `5000` for
  strict Apple extension default-timeout coverage.
- `--run-timeout-ms <ms>`: watchdog per startup or traffic case.
- `--xray-core-bin <path>` / `--xray-core-dir <path>` / `--no-auto-build`: Xray-core fixture selection.

Results are written to:

```text
target/benchmarks/<run-id>/reality-matrix/
```

The directory contains `result.json` with every fingerprint/traffic case status,
per-case latency/setup summaries, byte counts, and error messages. Generated
per-fingerprint client configs are stored under `configs/`.

## Run sing-box Only

Point `SING_BOX_BIN` at a local sing-box executable. Use any location on the
host; `/path/to/sing-box` below is only a placeholder:

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo run -p xray-bench -- run --engine sing-box --sing-box-bin "$SING_BOX_BIN" --workload idle --duration-ms 1000 --no-auto-build
cargo run -p xray-bench -- run --engine sing-box --sing-box-bin "$SING_BOX_BIN" --workload many-idle-flows --connections 100 --duration-ms 1000 --no-auto-build
```

The sing-box slice supports the SOCKS/process-level workloads: `idle`, `tcp-freedom`, `tcp-bulk-throughput`, `many-idle-flows`, `reconnect-burst`, `mixed-long-lived`, `udp-freedom`, `reality-vision-xudp`, `reality-vision-bulk-throughput`, `grpc-bulk-throughput`, and the WS/HTTPUpgrade/gRPC cases of `stream-transport`. Stream-transport and REALITY workloads start an Xray-core server fixture and sample only the client engine process. XHTTP is compared only between xray-rust and Xray-core because sing-box does not implement that transport. The sing-box binary must include `with_utls`; the harness uses `with_gvisor,with_utls,badlinkname,tfogo_checklinkname0` when auto-building sing-box. TUN and fake VLESS/XUDP sing-box workloads are intentionally not part of this slice because they need a different topology than the rootless fd-backed harness.

The stable sing-box v1.13.20 build selected for RC4 is incompatible with
`reality-vision-xudp` and `reality-vision-bulk-throughput` against the pinned
Xray-core v26.7.28 fixture. The server's default `minClientVer` 26.3.27 rejects
that build's REALITY `ClientVer` 1.8.1. This is an evidence-specific boundary,
not a generic harness limitation: direct sing-box runs and ordinary compares
remain available for compatible or patched binaries. RC4 uses the explicit
compare-only `--skip-sing-box` flag, without sing-box binary/source arguments,
to record why those two publication series are xray-rust/Xray-core only. Do
not weaken the fixture or increase the timeout.

RC4 also omits sing-box only from `stream-grpc-full-duplex-32`. Two frozen
campaigns completed all five xray-rust and Xray-core runs, but sing-box timed
out after three and four successful runs, respectively, at the required
300000 ms timeout. Later isolated diagnostics completed successfully, so the
publication records a nondeterministic timeout rather than claiming protocol
incompatibility or substituting a better retry. The canonical two-engine
invocation uses `--skip-sing-box` without sing-box binary/source arguments;
the manifest fail-closes on the exact scenario, reason, campaign counts, and
timeout evidence.

RC4 additionally omits Xray-core only from
`xhttp-pressure-xhttp-h3-32`. The pinned comparator reset its completion-marker
connection after xray-rust completed 5/5, the exact retry timed out at 300000
ms, and reduced-load diagnostics reset or timed out above four flows. The
candidate-only full-load run remains mandatory; no reduced diagnostic is
substituted.

The RC4 publication therefore contains exactly 139 benchmark series and 695
embedded five-run results. Its base matrix contributes 27 summaries and 135
results; historical v26.5.9 charts and summaries remain unchanged and must be
read as historical evidence for their recorded comparator versions.

Each run has a watchdog timeout. The default is 30 seconds; override it with
`--run-timeout-ms <milliseconds>` when exercising intentionally slow workloads.
On timeout, the harness drops the running engine handle so the child process is
terminated instead of leaving a stuck benchmark behind.

## Compare Engines

From the main repository checkout, these compatible process-level workloads
compare all three engines:

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 1000 --payload-size 1024
cargo run --release -p xray-bench -- compare --workload tcp-bulk-throughput --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 2048 --payload-size 4194304 --run-timeout-ms 300000
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run --release -p xray-bench -- compare --workload grpc-bulk-throughput --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
```

For the pinned RC4 comparator, run the two REALITY workloads without sing-box
binary/source arguments and explicitly record the omission:

```sh
cargo run -p xray-bench -- compare --skip-sing-box --workload reality-vision-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run --release -p xray-bench -- compare --skip-sing-box --workload reality-vision-bulk-throughput --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
```

The reviewed RC4 gRPC omission is likewise a two-engine command:

```sh
cargo run --release -p xray-bench -- compare --skip-sing-box \
  --workload stream-transport --stream-transport grpc \
  --traffic full-duplex --connections 32 --iterations 4096 \
  --payload-size 65536 --runs 5 --run-timeout-ms 300000 \
  --xray-core-dir Xray-core
```

The TUN and fake VLESS/XUDP workloads remain comparable between `xray-rust` and Xray-core in this slice, except for `tun-fake-dns`, `tun-fake-dns-tcp`, and `tun-dns-proxy`. These workloads deliberately exercise the xray-rust local DNS extensions (`dns.fakeIp` and anchor proxying through `dns.servers`, respectively); run them with `run --engine xray-rust`, since `compare` rejects them until equivalent cross-engine configurations are defined. The compare command skips sing-box for the other TUN workloads because sing-box's CLI TUN path uses a real platform TUN topology, while the older VLESS/XUDP fake-server workloads use Xray JSON configs instead of sing-box outbound schema. `routed-tcp-freedom` is also xray-rust vs Xray-core only: sing-box ≥1.8 does not read Xray-format `.dat` geodata, and semantically equivalent `.srs` rule-sets cannot be guaranteed.

```sh
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-stale-flows --xray-core-dir Xray-core --runs 5 --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-reality-blackhole --xray-core-dir Xray-core --runs 5 --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run --release -p xray-bench -- compare --workload routed-tcp-freedom --xray-core-dir Xray-core --geodata-dir /private/tmp/bench-geodata --runs 5 --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
```

The TUN workloads can also be run with xray-rust runtime profiles. The harness
passes `--tun-profile` through as `XRAY_TUN_PROFILE` for the engine process, so
the same TUN fd workload can be sampled under `default`, `low-memory`, or
`throughput` queue/budget presets:

```bash
cargo run -p xray-bench -- run --engine xray-rust --workload tun-udp-freedom --tun-profile low-memory --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-tcp-freedom --tun-profile throughput --connections 1 --iterations 100 --payload-size 1024
```

From an isolated worktree under `.worktrees/`, pass the main checkout's Xray-core path:

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir ../../Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 1000 --payload-size 1024
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir ../../Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir ../../Xray-core --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir ../../Xray-core --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --skip-sing-box --workload reality-vision-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-stale-flows --xray-core-dir ../../Xray-core --runs 5 --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-reality-blackhole --xray-core-dir ../../Xray-core --runs 5 --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
```

The compare command auto-builds `target/debug/xray-rust`, an Xray-core binary, and a sing-box binary under the run directory unless `--no-auto-build` is provided. Every guarded Xray-core auto-build recompiles the exact pinned checkout and replaces its revision-scoped output artifact; xray-rust and sing-box outputs may be reused within a benchmark group. Use `--xray-core-bin <path>` and `--sing-box-bin <path>` to benchmark existing binaries without rebuilding.

## Publishing Numbers and Charts

Numbers quoted in the README and in
[docs/benchmarks/results.md](benchmarks/results.md) must come from release
builds on both sides. The
harness's default debug auto-build of `xray-rust` is for development only; Go
engines are always optimized builds, so a debug Rust binary makes whichever
number you quote untrustworthy. Build and pass the release binary explicitly,
and run the harness itself in release so client-side stream validation is not
the bottleneck:

The complete RC4 replay record, including the resolved comparator paths,
hashes, geodata identities, all stream/pressure/memory cases, and chart
command, is the dated
[`commands.sh`](benchmarks/results/2026-08-31-v26.7.28/commands.sh). The shorter
commands below are developer examples, not the provenance record for the
published group.

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo build --release -p xray-cli --bin xray-rust
cargo run --release -p xray-bench -- compare --workload tcp-bulk-throughput \
  --xray-rust-bin target/release/xray-rust --xray-core-dir Xray-core \
  --sing-box-bin "$SING_BOX_BIN" \
  --runs 5 --connections 1 --iterations 2048 --payload-size 4194304 --run-timeout-ms 300000
```

Run a release-binary compare for each charted workload — `idle`,
`many-idle-flows` ×100 and ×1000 (the ×1000 run needs a raised `ulimit -n`;
see the workload note), `tcp-freedom`, `udp-freedom`, `reality-vision-xudp`,
`tcp-bulk-throughput`, `reality-vision-bulk-throughput`, and
`routed-tcp-freedom` (nine chart-input workload groups; the last needs `--geodata-dir`
after fetching geodata with
`scripts/fetch-geodata.sh --output-dir /private/tmp/bench-geodata`, see
above). Use the two-engine REALITY commands shown above rather than carrying
the sing-box binary/source flags from the ordinary example into those
workloads. Each
compare invocation writes one `target/benchmarks/<run-id>`
group; the `--group` flags passed to `chart` must jointly cover all nine
series.

`chart` renders the published SVG charts (README highlights plus the rest in
[docs/benchmarks/results.md](benchmarks/results.md)) from one or more compare
run groups. The current RC4 invocation records its exact comparator boundary:

```sh
cargo run --release -p xray-bench -- chart \
  --group target/benchmarks/<run-id-1> --group target/benchmarks/<run-id-2> \
  --date 2026-08-29 \
  --hardware "<recorded RC4 hardware and OS>" \
  --xray-rust-version <RC4-git-short-rev> \
  --xray-core-version v26.7.28 \
  --sing-box-version v1.13.20 \
  --omit-sing-box-reality \
  --geodata-version "geosite-<tag> geoip-<tag>"
```

It reads `<group>/<engine>/<workload>/summary.json` for `idle`,
`many-idle-flows` (once per charted connection count), `tcp-freedom`,
`udp-freedom`, `reality-vision-xudp`, `tcp-bulk-throughput`,
`reality-vision-bulk-throughput`, and `routed-tcp-freedom`. By default the two
REALITY slots retain historical three-engine loading and rendering. RC4 passes
`--omit-sing-box-reality`, so those slots require only xray-rust and Xray-core;
routed geodata is always two-engine and the other slots use all three engines.
With the flag, the mixed latency chart retains the three-engine legend for its
direct TCP/UDP groups and dynamically notes, using the supplied comparator
versions, why the REALITY group has no sing-box bar. The REALITY throughput
chart uses only two engine labels and the same note. The renderer writes
light/dark SVG pairs (`memory-rss`, `latency`, `throughput`,
`reality-throughput`, `cpu-per-gib`, `geo-setup-latency`, `geo-memory`) to
`docs/benchmarks/media/` (override with
`--out-dir`). Charts select `many-idle-flows` summaries by their recorded
connection count, so both scales come from separate compare runs; geo charts
read the `routed-tcp-freedom` summaries (xray-rust and Xray-core only — no
sing-box series, and the setup-latency chart carries the reply-time caveat,
see the routed-tcp-freedom workload note in the Metrics section below).
Metadata is passed by flags rather than sniffed so regeneration is
deterministic; `--geodata-version` is
optional and only prints a warning if omitted, since it labels the geo charts
rather than gating them. The command fails if any required summary is
missing or its status is not `ok`. Bars show the median across runs;
whiskers span min to p95 (for latency: min run median up to the median run
p95).

### DNS chart inputs

DNS publication charts use eight separate xray-rust-only release groups. Build
the engine once, then keep `--runs`, `--connections`, and `--iterations`
identical across every invocation. The publication recipe is five runs, 16
logical clients, and 1000 iterations:

```sh
cargo build --release -p xray-cli --bin xray-rust

cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-fake-dns \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-fake-dns-tcp \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000

cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-dns-proxy \
  --transport udp --dns-upstream-transport classic \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-dns-proxy \
  --transport tcp --dns-upstream-transport classic \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-dns-proxy \
  --transport udp --dns-upstream-transport tcp-routed \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-dns-proxy \
  --transport tcp --dns-upstream-transport tcp-routed \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-dns-proxy \
  --transport udp --dns-upstream-transport tcp-local \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000
cargo run --release -p xray-bench -- run --engine xray-rust \
  --xray-rust-bin target/release/xray-rust --workload tun-dns-proxy \
  --transport tcp --dns-upstream-transport tcp-local \
  --runs 5 --connections 16 --iterations 1000 --run-timeout-ms 120000
```

`tun-fake-dns` is inherently the UDP-client case and
`tun-fake-dns-tcp` is inherently the TCP-client case, so neither takes a
chart-defining `--transport`. The six proxy groups form the UDP/TCP client ×
`classic`/`tcp-routed`/`tcp-local` upstream matrix. Do not use
`--transport both` for a chart input: the chart loader rejects combined client
transports rather than attributing their merged samples to either series.
The shared value of 16 also matches the TCP driver's active-connection cap;
using 32 would let UDP run 32 queries concurrently while TCP runs two waves,
confounding both query-rate and peak-RSS comparisons.

Pass each resulting `target/benchmarks/<run-id>` directory with a repeatable
`--dns-group` flag. DNS inputs may be rendered on their own:

```sh
cargo run --release -p xray-bench -- chart \
  --dns-group target/benchmarks/<fake-dns-udp-run-id> \
  --dns-group target/benchmarks/<fake-dns-tcp-run-id> \
  --dns-group target/benchmarks/<proxy-udp-classic-run-id> \
  --dns-group target/benchmarks/<proxy-tcp-classic-run-id> \
  --dns-group target/benchmarks/<proxy-udp-tcp-routed-run-id> \
  --dns-group target/benchmarks/<proxy-tcp-tcp-routed-run-id> \
  --dns-group target/benchmarks/<proxy-udp-tcp-local-run-id> \
  --dns-group target/benchmarks/<proxy-tcp-tcp-local-run-id> \
  --date 2026-08-01 \
  --hardware "Apple M3 Pro, 18 GB RAM, macOS 26.5.2" \
  --xray-rust-version <git-short-rev>
```

The eight `--dns-group` flags can instead be appended to the normal
`chart --group ...` command to write the regular and DNS charts together.
Omitting `--dns-group` preserves the old chart behavior and output set.
Supplying any DNS group requires the complete eight-input matrix with
`status=ok`; duplicates, mixed workload parameters, missing transport
metadata, and partial matrices fail closed. Every input must come from a
release harness, and the Git state, harness/engine binary paths, and working
directory recorded in `provenance` must agree across the matrix. Both binary
SHA-256 fields are mandatory, must be 64-character lowercase hexadecimal
values, and must agree too; run IDs and
the three scenario selectors in `invocation_args` are expected to differ,
while every other effective CLI argument must match. Publication inputs with
fewer than 100 iterations are rejected.
DNS-only rendering needs only the date, hardware, and xray-rust version; the
normal cross-engine charts retain their Xray-core and sing-box version
requirements.

The DNS extension writes four additional light/dark SVG pairs:
`dns-latency`, `dns-query-rate`, `dns-cpu-per-1k-queries`, and
`dns-memory-rss`. They compare UDP and TCP clients for FakeDNS, classic DNS,
routed DNS-over-TCP, and local DNS-over-TCP. Every raw run has exactly
`2 * connections * iterations` validated queries: one A and one HTTPS query
per logical client per iteration. Query rate is
`queries * 1000 / duration_ms`; CPU cost is
`cpu_millis * 1000 / queries` milliseconds per 1000 queries; RSS is
`peak_rss_kib / 1024` MiB. Rate, CPU, and RSS are derived separately from each
raw `result.json` before their min/median/p95 aggregation, avoiding ratios of
already-aggregated numerators and denominators. Latency uses the median of
per-run medians for the bar, the minimum run median for the lower whisker, and
the median run p95 for the upper whisker.

These are hybrid, cache-warmed local fixtures, as the note embedded in every
DNS SVG states. All logical clients reuse one domain: the first managed A
lookup warms the shared TTL cache and subsequent A requests mostly measure
cache hits; FakeDNS likewise reuses its mapping instead of exercising lease
churn. In the proxy fixture HTTPS is raw-forwarded to a deterministic NODATA
response; FakeDNS also returns HTTPS NODATA without allocating another
mapping. Every chart pools the A and HTTPS samples rather than reporting
per-qtype metrics. The graphs therefore do not claim cold recursive lookup
cost, diverse-domain cache behavior, successful HTTPS-record payload
handling, or FakeDNS pool growth. The RSS chart is peak process memory for
this steady workload, not a lease-index stress result.

## Metrics

The first scoreboard is intentionally portable and comparable across Go and Rust:

- peak resident set size from `ps` RSS.
- CPU time delta from `ps` cumulative process time.
- CPU milliseconds per GiB transferred when a workload moves payload bytes.
- throughput megabits per second when a workload moves payload bytes, computed from validated bytes over the transfer window only — first byte to last validated byte, excluding connection setup. This rate is exact only at `--connections 1`; with concurrent connections it is the aggregate over the union of the per-connection transfer windows, not a per-connection average. The whole-run window stays available as `duration_ms` and the transfer window as `transfer_duration_ms`, so their difference exposes the setup cost instead of hiding it. In the historical v26.5.9 `reality-vision-bulk-throughput` evidence, Xray-core spent roughly 640 ms before the first byte, against roughly 90-120 ms for the then-tested sing-box and xray-rust — folded into the denominator, that gap would have amortized setup into the rate. Those sing-box measurements are historical only and are not a v26.7.28 performance claim; RC4 omits the incompatible stable sing-box REALITY leg described above. Most of that historical 640 ms was not the handshake. It was the same VLESS header hold described under `grpc-bulk-throughput` below: these bulk workloads are server-first, so Xray-core's outbound waits out its full 500 ms `ReadMultiBufferTimeout` looking for a first client payload to pack with the header (`Xray-core/proxy/vless/outbound/outbound.go:334-336`; `xtls-rprx-vision` only changes the else branch at :343-349, not the timeout). In that historical probe, first byte landed 595-649 ms after the SOCKS reply when the client only read, and 72-73 ms when it wrote one byte first — roughly 500 ms was the header hold and only the remainder was Xray-core answering SOCKS eagerly and dialing REALITY lazily. Workloads that do not measure a transfer window fall back to the whole-run window. `cpu_millis_per_gib` is still measured over the whole-run window rather than the transfer window; at gigabyte scale this is immaterial (setup burns a few milliseconds of CPU) but is worth noting since the two metrics sit adjacent and now cover different windows. The byte count aggregates both directions, matching the CPU-per-GiB convention, so echo-style workloads read roughly twice their one-way goodput; quote streaming throughput from `tcp-bulk-throughput`, where traffic is one-directional.
- thread count when the local `ps` implementation exposes it.
- validated bytes sent and received by the workload.
- latency microsecond percentiles for traffic workloads. For `many-idle-flows`, latency is SOCKS TCP flow setup time.
- setup microsecond breakdown for SOCKS TCP setup workloads: local TCP connect to the inbound, SOCKS method negotiation, SOCKS CONNECT request/response, full SOCKS setup, and total setup time.
- min, median, and p95 aggregates across repeated runs.
- for `stream-transport --traffic packet-up`, logical uplink write operations
  and operations per second over the same merged transfer window. Every write
  is target-acknowledged before the next begins, preventing cross-iteration
  batching; these are still client operations rather than HTTP-server request
  instrumentation.

`tcp-freedom`, `udp-freedom`, `tun-udp-freedom`, `tun-fake-dns`, `tun-fake-dns-tcp`, `tun-dns-proxy`, `udp-vless`, `udp-xudp`, `vision-xudp`, and `reality-vision-xudp` record round-trip latency samples for validated traffic. Both fake-DNS workloads record two samples per connection per iteration, one for A and one for HTTPS. `tun-dns-proxy` records the same two samples for each selected client transport, so `--transport both` records four samples per connection per iteration. `summary.json` aggregates each run's latency min/median/p95/p99 across repeated runs. Both JSON files record `dns_transport` (`udp` for `tun-fake-dns`, `tcp` for `tun-fake-dns-tcp`, and the selected client transport for `tun-dns-proxy`). For `tun-dns-proxy`, both files also record `dns_upstream_transport`, so classic, routed TCP, and local TCP runs cannot be accidentally aggregated together.

**Use at least a few hundred iterations for any latency number you publish.**
A freshly spawned engine serves its first flow about twenty milliseconds into
process life, and ten round trips complete in one to two milliseconds — so a
ten-iteration run measures the warm-up transient and nothing else. Such runs
swing by more than 2× between sessions while thousand-iteration runs on the
same machine repeat to within a microsecond. The charted latency series
(`tcp-freedom`, `udp-freedom`, `reality-vision-xudp`) all use 1000
iterations for this reason; the ten-iteration commands above are smoke tests.
`tcp-bulk-throughput` streams a deterministic byte pattern from a local TCP source through SOCKS5 CONNECT as one continuous transfer per connection (`--iterations` chunks of `--payload-size` bytes). The client validates the pattern chunk-by-chunk while reading, so throughput covers only verified bytes. Unlike `tcp-freedom` it has no per-iteration round trip, making it the workload to quote for streaming throughput. Size the transfer so the window outlasts the ramp: a gigabyte crosses loopback in about 150 ms, short enough that TCP window growth and CPU frequency scaling weigh on the rate, so the charted series moves 8 GiB per run for a window near a second.
`reality-vision-bulk-throughput` is `tcp-bulk-throughput` carried through
VLESS REALITY with `xtls-rprx-vision` (uTLS fingerprint `chrome`) to the same
Xray-core server fixture that `reality-vision-xudp` uses; the fixture's
`freedom` outbound dials back to the local source server. The fixture process
is not sampled, but it shares loopback CPU with the client engine, so
absolute numbers understate a dedicated-server setup. The bulk pattern is not
inner TLS, so Vision does not switch to direct copy: the stream stays
REALITY-encrypted end to end, and the chart measures the encrypted relay
path.
`grpc-bulk-throughput` is `tcp-bulk-throughput` carried through VLESS over the
gRPC stream transport to an Xray-core server fixture whose `freedom` outbound
dials back to the local source server. It is the historical workload that
first measured a stream transport's framing rather than raw TCP; the generic
`stream-transport` matrix now supplies equivalent WS, HTTPUpgrade, gRPC, and
XHTTP cases under TLS. Both the legacy client outbound and the
fixture inbound use `serviceName: "bench"` and `security: none`, so the number
covers the `Hunk` framing and one HTTP/2 stream and not three different TLS
stacks. `xtls-rprx-vision` is deliberately absent, and the rule that excludes
it is neither "only RAW" nor "only TLS". Xray's VLESS outbound reaches into the
connection under it for the `input`/`rawInput` fields Vision needs, and it
accepts exactly two shapes
(`Xray-core/proxy/vless/outbound/outbound.go:268-285`): a
`*encryption.CommonConn` — VLESS `encryption` is on — which is tested first and
does not care what the network is; or, failing that, an `iConn` that is a
`*tls.Conn`, `*tls.UConn` or `*reality.UConn`. Everything else gets "XTLS only
supports TLS and REALITY directly for now." Resist restating that as a list of
networks; every such shortcut written here so far has been wrong. The criterion
is whether the transport dialer hands the security conn straight back as
`iConn`, and it is a property of the dialer, not of `network` or of `security`:
RAW does (`Xray-core/transport/internet/tcp/dialer.go:76-102`) — unless a
`header` authenticator wraps it again on the way out (`dialer.go:105-115`) —
and so does mKCP, whose dialer ends `iConn = tls.Client(iConn, ...); return
iConn` (`Xray-core/transport/internet/kcp/dialer.go:99-103`). The stream
transports never expose it. Setting `security: tls` under gRPC therefore does
**not** buy the second shape: the gRPC dialer feeds that conn to grpc's
`ContextDialer` (`Xray-core/transport/internet/grpc/dial.go:138-151`) and
returns a `HunkConn` or `MultiHunkConn` wrapper instead (`dial.go:65,74`); ws,
httpupgrade and xhttp wrap their TLS conn the same way. Four configurations
were run against the vendored 26.5.9 binary, each with `xtls-rprx-vision` set
on both ends. `network: grpc, security: none` plus a `decryption`/`encryption`
pair carries Vision fine — the client logs `proxy: Xtls Unpadding new block`
and the tunnel serves traffic. So does `network: kcp, security: tls` with
`encryption: none`, which is the case the "only RAW" shortcut got wrong:
HTTP 200 through the tunnel, `XtlsPadding 78 70 0` on the client and `Xtls
Unpadding new block, content 78 padding 70 command 0` on the server.
`network: grpc, security: tls` is refused with exactly that error — and so is
RAW with `security: tls` plus `tcpSettings.header.type: "http"`, which is the
case the "RAW with `tls`" shortcut got wrong. This fixture has
neither VLESS encryption nor a TLS-shaped `iConn`, so Vision is out, and the
REALITY/Vision configs still cannot be reused with the network swapped. Unlike
the REALITY fixture, the gRPC fixture has no warm-up wait — there is no cover
origin whose record shape has to be learned before a client may connect.

Three properties of this number are easy to misread, and each changes what it
means:

- **The sing-box leg is not grpc-go.** `SING_BOX_BUILD_TAGS` omits
  `with_grpc`, so sing-box builds `transport/v2raygrpclite` — an
  `http2.Transport` speaking the same `/serviceName/Tun` shape by hand — rather
  than the real gRPC stack Xray-core and this client are ported against. Adding
  `with_grpc` would invalidate every sing-box number previously published from
  this harness, so the tag stays off and the caveat is stated instead. Read the
  sing-box bar as "sing-box as it ships in this harness", not as a grpc-go
  datapoint.
- **Throughput is measured over the transfer window, not the whole run**, as it
  is for every workload here (see the throughput bullet above). Everything
  before the first validated byte is outside the rate: the SOCKS handshake, the
  engine's dial, the TCP connect, the HTTP/2 preface and SETTINGS exchange, and
  the TLS handshake when one is configured. For a pooled transport that is
  worth naming rather than assuming — the preface is paid on the first dial and
  never again, so a run that opens one connection charges it once and hides it,
  and a run that opens many amortises it further. The two engines also put it
  on opposite sides of the SOCKS reply: xray-rust dials before answering SOCKS
  CONNECT, so its setup is charged to the harness's connect phase, while
  Xray-core answers SOCKS first and dials lazily. Neither placement costs more
  than about a millisecond on loopback h2c — in the harness's own debug log
  Xray-core goes from `proxy/socks: TCP Connect request` to
  `proxy/vless/outbound: tunneling request` in 1.1 ms, TCP connect and preface
  included — so the gap in the table below is not this. Quote
  `transfer_duration_ms` and `duration_ms` alongside the rate anyway, or the
  gRPC bar reads as if setup were free.
- **Xray-core's half-second before first byte is a VLESS header hold, not
  transport setup.** Its VLESS outbound buffers the request header and waits up
  to 500 ms for a first *client* payload to pack alongside it
  (`ReadMultiBufferTimeout(time.Millisecond * 500)`,
  `Xray-core/proxy/vless/outbound/outbound.go:334-336`; the header is flushed
  by `SetBuffered(false)` at :354). This workload is server-first — the client
  issues SOCKS CONNECT and only reads — so no uplink payload ever arrives, the
  timeout expires in full, and only then does the server see the header and
  dial the source. Probed against these same two configs: first byte lands
  507 ms after the SOCKS reply on the first connection *and* on the second one,
  which reuses the pooled `ClientConn`, and 2.7 ms when the client writes a
  single byte before reading; the fixture's VLESS inbound logs `firstLen` at
  T+504 ms in the first case and T+0.5 ms in the second. The hold is
  per-stream and protocol-level, neither gRPC-specific nor pooling-specific:
  the same probe against the same pair of configs with `network: tcp` measures
  506 ms too. But it is why Xray-core's transfer window below is half its run
  duration.

A local three-engine anchor from this machine (Apple M3 Pro, 18 GB RAM, macOS 26.5.2;
release harness and release `xray-rust`, five runs, one connection, 256 × 4 MiB
= 1 GiB per run) shows how far apart the two windows put the same run:

| engine | throughput (transfer window) | duration_ms | transfer_ms | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- |
| xray-rust | 8268 Mbps | 1052 | 1039 | 4.9 MiB | 890 |
| Xray-core | 16615 Mbps | 1034 | 517 | 132.5 MiB | 1160 |
| sing-box (lite) | 5586 Mbps | 1550 | 1538 | 37.2 MiB | 3100 |

Medians across five runs. Xray-core streams the gigabyte at twice our rate
once it starts, but spends 518 ms getting there — the 500 ms VLESS header hold
above, not tunnel setup — so the same gigabyte takes both engines the same
wall-clock second; we and sing-box reach first byte in 12 ms. Neither
column alone is the whole story, which is why both are here. On memory and CPU
per gigabyte the ordering does not depend on the window: 4.9 MiB against
132.5 MiB and 37.2 MiB, and 890 CPU-ms/GiB against 1160 and 3100.

These are regression anchors for this machine, not published cross-engine
claims: `grpc-bulk-throughput` is not one of the charted series and `chart`
does not read it.

`routed-tcp-freedom` is `tcp-freedom` with SOCKS5 domain CONNECT through a
config carrying real geosite/geoip routing rules
(`geosite:category-ads-all`, `geoip:private`, `geoip:cn`, `geosite:cn`) and
several tagged `freedom` outbounds. Connections alternate between a domain
that matches the last geosite rule and one that falls through every rule to
the default outbound; both resolve to `127.0.0.1` via `dns.hosts`, so no
packet leaves the machine. `--geodata-dir` must contain `geosite.dat` and
`geoip.dat` (fetch pinned, checksum-verified files with
`scripts/fetch-geodata.sh --output-dir <dir>`). Headline numbers:
`setup_socks_connect_us` (time from SOCKS CONNECT request to the engine's
reply) and `peak_rss_kib` (matcher memory for the loaded geodata).

**Measurement asymmetry:** the two engines send the SOCKS reply at different
pipeline stages — xray-rust replies after rule evaluation, hosts resolution,
and the local dial complete (`crates/xray-core-rs/src/socks.rs`, non-sniffing
path), while Xray-core replies during the SOCKS handshake before routing and
dialing (`proxy/socks/protocol.go` → `writeSocks5Response`, dispatch
afterwards). The chart therefore compares different spans of work and must
not be read as a pure routing-cost comparison; it is published as "time to
SOCKS reply" with this note.

**Run-to-run instability:** the rendered `geo-setup-latency` chart
(`docs/benchmarks/media/geo-setup-latency-{light,dark}.svg`, committed but
not currently embedded in the README) swung from 426 µs / 126 µs to 181 µs /
201 µs (xray-rust / Xray-core) across two publication runs with no runtime
change in between — a rank flip, not just noise in the margin. At
`--connections 8`, each run contributes only 8 `setup_socks_connect_us`
samples, which is too small a sample for this metric to be published as a
cross-engine comparison at the current recipe; treat it as directional only
until the sample size is raised.

`many-idle-flows` opens `--connections` SOCKS TCP flows to a local target, keeps them idle for `--duration-ms`, and reports RSS/CPU while those flows are held. This is the first local memory-slope workload; compare its peak RSS against `idle` and divide the delta by the connection count for an approximate per-flow resident-memory cost. For a scale point, the publication charts also run `many-idle-flows` with
`--connections 1000`. xray-rust's inbounds have no application-level
connection cap (matching Xray-core and sing-box); the ceiling is the
process's file-descriptor limit, which the CLI raises to the hard limit at
startup the way the Go runtime does. The harness side needs a
file-descriptor limit of several thousand (`ulimit -n`).
`reconnect-burst` repeatedly opens and closes SOCKS TCP flows with `--connections` parallel workers and `--iterations` reconnects per worker. It is intended to separate base setup cost from the memory slope of held idle flows.
`mixed-long-lived` keeps TCP and UDP SOCKS flows open together, paces `--iterations` across `--duration-ms`, and validates both echo paths. It is a local mobile-like foreground/background traffic mix.
`udp-freedom` uses SOCKS5 UDP ASSOCIATE with the inbound configured as `{ "udp": true, "ip": "127.0.0.1" }`, then validates echoed UDP payloads through a local UDP target.
`tun-udp-freedom` uses a Unix `socketpair` as an inherited fd-backed TUN device, sends Darwin utun-framed IPv4/UDP packets into a `tun` inbound, and validates echoed payloads from a local UDP server. It does not create a real system utun interface, install routes, or require root. To stay compatible with Xray-core's gVisor martian-packet filter, the UDP target is the host's local non-loopback IPv4 address rather than `127.0.0.1`.
`tun-fake-dns` reuses that rootless inherited TUN socketpair with `dns.fakeIp` enabled for `198.19.0.0/16` and an explicit `poolSize` of 32768. Every iteration sends an A query and an HTTPS (type 65) query for `bench.example` to the local fake-DNS anchor `198.18.0.1:53` for every requested connection. The workload keeps up to `min(2 * --connections, 32)` queries outstanding, schedules one query per logical connection before its second query, uses fd readiness instead of interval polling, and matches out-of-order responses by client port, transaction ID, and query type. Larger connection counts run in bounded waves to avoid overflowing the inherited datagram TUN path. It validates that A returns `198.19.0.1` and that HTTPS returns NOERROR/NODATA without allocating another mapping, then records DNS-message payload bytes and one round-trip latency sample per query. RTT starts at the successful socketpair write and ends when the matching response has been read and validated. `--payload-size` is ignored. The workload is xray-rust-only for now.
`tun-fake-dns-tcp` uses the same fake-IP config and A/HTTPS validation over length-prefixed DNS/TCP. It keeps at most 16 simultaneous smoltcp connections, applies the same bounded frame queue and retransmission-deadline handling as the raw DNS-proxy TCP workload, and records one latency sample per query. This is a separate workload so the historical UDP-only `tun-fake-dns` baseline remains comparable.
`tun-dns-proxy` starts local UDP and TCP DNS responders on one IP-literal loopback endpoint and sends A plus HTTPS queries for `proxy-bench.example` to `198.18.0.1:53` through the inherited TUN packet API. `--transport udp|tcp|both` selects the client-to-anchor path and defaults to `both`. The independent `--dns-upstream-transport classic|tcp-routed|tcp-local` option selects the generated `dns.servers` entry and defaults to `classic`: classic uses the bare endpoint, routed TCP uses `tcp://`, and local protected TCP uses `tcp+local://`. The A query exercises the family-aware managed Hijack path, while HTTPS deliberately exercises raw forwarding through the same anchor and, for TCP, the same client session. Because every logical client reuses one domain, the first managed A lookup populates the shared TTL cache and later A requests measure cache hits; this fixture is not a cache-miss benchmark. An UDP client run with either TCP upstream mode also measures the UDP-to-DNS/TCP framing adapter; a TCP client run alternates managed and raw requests one at a time through the query-aware client-session adapter. Concurrent mixed-query pipelining is covered by runtime tests rather than claimed by this throughput fixture. AXFR/IXFR transparent handoff and failure injection are likewise covered by runtime tests. UDP shares the readiness-driven, 32-query bounded window used by `tun-fake-dns`; TCP uses at most 16 simultaneous smoltcp connections and a bounded 512-frame backpressure queue, with readiness wakeups plus smoltcp retransmission deadlines. Larger `--connections` values run in waves. The harness verifies the anchor source address and port at the packet layer, then verifies transaction ID, QR, question, and the fixture's deterministic A or HTTPS NODATA response. Bytes count DNS messages without IP/UDP/TCP framing, and `--payload-size` is ignored. This workload is xray-rust-only.
The current fake-DNS workloads intentionally reuse one domain and therefore do not measure lease-index churn/RSS. The raw proxy fixture is IP-literal; routed TCP uses the generated Freedom outbound while local TCP bypasses outbound routing. Separate future slices should cover more-than-`poolSize` fail-closed pressure and post-TTL reuse, domain upstreams over VLESS/Freedom bootstrap, and fake-IP → resolved TCP/UDP target setup; those claims should not be inferred from the present baselines.
`tun-tcp-freedom` uses the same inherited fd-backed TUN path with a smoltcp TCP client on the benchmark side. It completes a TCP handshake through the TUN inbound, sends echo payloads, validates the returned TCP stream data, and sends a final RST so each measured flow is released before the next one starts.
`tun-tcp-stale-flows` uses the same path but deliberately drops each synthetic client without FIN or RST, then holds the engine for `--duration-ms`. It measures the RSS/CPU cost of TUN flows whose client disappeared before TCP teardown reached the tunnel.
`tun-reality-blackhole` routes those synthetic TUN TCP flows through VLESS Reality Vision to a local TCP server that accepts connections but never sends a TLS ServerHello. Its generated policy sets `handshake` to one second, while the workload holds the process for `--duration-ms`. Compare it with `tun-tcp-stale-flows` to separate userspace TCP flow memory from pending Reality/TLS-open memory and to check whether each engine enforces the configured handshake deadline. For xray-rust, a hold interval longer than the configured handshake must report zero active blackhole connections. The CLI and `result.json` report blackhole connections as accepted/active after the hold interval, so socket cleanup is observable even when an allocator keeps process RSS high. macOS runs use the desktop TUN profile; Apple mobile builds additionally cap active TCP flows and concurrent pending opens according to their mobile runtime profile.
`udp-vless` uses the same SOCKS5 UDP client path, but routes through a local fake VLESS UDP server over TCP before validating echoed UDP payloads. It targets UDP/53 to keep the VLESS UDP framing length-prefixed.
`udp-xudp` targets a non-DNS UDP port and validates XUDP/Mux frames through the local fake VLESS server.
`vision-xudp` uses VLESS over local TLS with `xtls-rprx-vision` and XUDP/Mux
frames against a local fake Vision server. Both client configs pin the full DER
SHA-256 of that generated self-signed certificate with
`pinnedPeerCertSha256`; neither benchmark path disables certificate
verification.
`reality-vision-xudp` uses VLESS Reality with `xtls-rprx-vision` and XUDP/Mux frames against an Xray-core server fixture, then validates echoed UDP payloads through the same SOCKS5 UDP client path. The fixture process is not sampled in RSS/CPU; only the selected client engine is sampled. The harness waits out a fixed REALITY warm-up after the fixture logs `started` (override with `XRAY_BENCH_REALITY_WARMUP_MS`): the REALITY library must first learn the post-handshake record shape of the real `dest`, which takes a TLS handshake to that host plus a five-second read deadline, and a client that connects inside that window stalls — or is dropped when the dest closes the borrowed connection.

`route-probe` is an in-process xray-rust microprobe for setup-path routing cost. It builds a synthetic config with IP/CIDR routing rules and tagged freedom outbounds, then repeatedly calls the same TCP outbound selection path used by SOCKS CONNECT. This isolates routing/outbound selection from TCP accept, SOCKS parsing, and outbound socket connect noise.

`--dns-candidates N` adds the cached `IPIfNonMatch` second pass without adding network timing. `N=0` is the original synchronous direct-IP probe. For `N>0`, the probe uses a domain target and performs one untimed routing selection to warm a `CachingDnsResolver`; the generated lookup contains `N-1` non-matching IPv4 addresses followed by the address matched by the final CIDR rule. The timed loop verifies that the upstream resolver is not queried again. Compare `N=1` with `N=2` or `N=8` to isolate additional candidate-scan cost; the delta from `N=0` also includes cached name normalization, cache locking and async resolver dispatch. It does not measure DNS wire latency, TTL expiration, or TCP dialing. Candidate count is capped at 4096, and timing runs should use `--release`.

`--cidrs-per-rule N` (default `1`) gives every non-final rule `N` distinct non-matching `/28` blocks inside `10.0.0.0/8` instead of one `/16`, so the probe scales the per-rule matcher count the way `geoip:` rules do (a `geoip:cn` rule carries tens of thousands of CIDRs). `N=1` keeps the historical config shape. The blocks are separated by a one-block gap so the compiled range index cannot merge them; `rules x N` is capped at 524288.

`--domains-per-rule N` (default `0`) switches the probe target to the domain `route-probe.invalid` and gives every non-final rule `N` distinct non-matching `domain:` suffixes (`miss-<rule>-<i>.invalid`) while the final rule carries one exact `full:` match, so the probe scales the per-rule domain-matcher count the way `geosite:` rules do. `N=0` keeps the IP-target probe; with `N>0` the rules carry no IP matchers and `--cidrs-per-rule` is ignored. It cannot be combined with `--dns-candidates`; `rules x N` is capped at the parser's 250000-domain budget. The result also reports `peak_rss_kib`, the process peak RSS sampled after the config and router are built and before the timed loop, so retained matcher memory can be compared across builds.

`dns-policy-probe` is an in-process microprobe for managed DNS object-server policies and the general DNS outbound classifier. Every run measures two object-server plans through the production selector: the common path where all `--servers` entries have no `domains`, and a worst-case path where the final server carries `--matchers` exact-domain rules and only its last rule matches. It also builds the same number of deterministically permuted, non-adjacent IPv4 host rules through the production IP-filter compiler and reports separate rotating hit and miss timings over the resulting fragmented range index. The DNS-outbound half treats `--servers` as the ordered rule count: common hits the first Direct rule, while worst scans to the final rule and its final keyword matcher before returning Return. Those iterations include parsing one valid A wire query and running the production first-match classifier, but no network I/O or response synthesis.

The probe also emits `dns-policy-probe-selector` slices for 0, 64, and 4096 DNS routing rules; 4096 is the parser's routing-rule limit. Every rule is an exact `bench-in`/UDP/53 DNS route. The first-hit target measures the compiled prefilter plus selection of the first DNS rule; the last-hit target forces an ordered scan to the final rule. The structural miss uses UDP/443 and measures the ordinary-packet fast path where no DNS outbound can apply, while the semantic miss uses a nonmatching UDP/53 domain and measures a full DNS-selector miss. With zero rules both hit flags are false; otherwise `hit_selected_dns` and `last_hit_selected_dns` must be true. Every miss must preserve the regular path through `miss_preserved_regular_path` or `semantic_miss_preserved_regular_path`. Rules are compiled before timing, and their router construction cost is reported separately as `compile_us`.

Compilation is excluded from query timing but reported separately as `compile_us`; `pattern_bytes` is the deterministic retained object-server domain-pattern payload and deliberately excludes allocator/hash-table/regex-engine overhead, so it is not an RSS estimate. `ip_filter_ranges` reports retained merged ranges. Object-server selector iterations include result allocation; IP-filter iterations measure membership only. The command validates selector order, DNS-outbound actions, DNS route hit/miss behavior, and both IP hit/miss outcomes before measuring and writes all metrics to `target/benchmarks/<run-id>/dns-policy-probe/result.json`. New outbound fields deserialize with defaults so stored pre-outbound results remain readable. Matcher count is capped at the parser's 250,000-domain budget, and timing runs should use `--release`.

On the same machine used while adding the compact index, the final local release run with 4 servers and 4096 exact matchers improved from 27,948 ns to 81 ns per worst-case selection (common path: 128 ns to 67 ns). Compilation took 575 µs and retained 121,769 bytes of pattern payload. The full parser budget of 250,000 exact matchers across 8 servers compiled in 23,644 µs, retained 7,888,887 payload bytes, and selected in 68 ns per iteration. These are regression anchors for this machine, not cross-device performance claims; mobile-native RSS and energy still require Instruments/Perfetto runs.

The added fragmented IP-filter slice compiled 4,096 host rules into 4,096 ranges in a representative 66 µs and measured 11 ns per rotating hit and 13 ns per rotating miss. At 250,000 rules/ranges, representative compilation took 4,107 µs, with 17 ns hits and 19 ns misses. These are medians from repeated local release runs after the rotating probes were spread across the matcher set; they are regression anchors rather than device-independent claims.

Later benchmark slices should add long-running DNS/FakeDNS stress and mobile-native traces from Instruments or Perfetto. This harness keeps those paths open without putting benchmark logic into the production runtime.
