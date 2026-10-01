# v0.8 CPU investigation — Apple M3 Pro

The main costs were the ARM software cryptographic backends and repeated
record-buffer allocation/erasure. The optimized client uses the existing
AWS-LC provider for SS2022/VMess record AEAD and reuses bounded write buffers.
The default CLI worker count remains two. This report is a host measurement,
not physical-device, TUN, WAN, battery, or release-acceptance evidence.

## Source and measurement identity

- Candidate: `ce6deef3fe1b3f8536c471235dd2a6c003e7e9e5`, tree
  `07005cb7084a48e6ef793f53b1cd442d69c1b35d`.
- Candidate binary SHA-256:
  `2180631c4187dd3cd85fda27d06c3b98a22f92c0954b841d3a1c13d9bd1beb04`.
- Baseline is the same frozen pre-optimization client as the
  [initial comparison](../2026-09-30-v08-protocols/README.md): runtime
  `0250497b7f8aaca66b0086b95892558e7042cc98`.
- Identical frozen driver, Xray-core v26.7.28 (`5ca6f4b...`), and sing-box
  v1.13.20 (`56f91d...`). Exact complete identities, compiler versions, tags,
  and checksums are in [inputs.json](data/inputs.json).
- M3 Pro, 12 cores, 18 GiB, macOS 26.6.2, AC power. Host details are in
  [host.json](data/host.json). Release Rust 1.96.0, no incremental compilation,
  no global target-CPU/crypto-feature overrides. Both Go references use 1.26.0.
- The main matrix uses 7 protocol/cipher profiles × 1/8 flows ×
  upload/download/duplex/TCP echo/UDP echo × 3 clients × 3 repetitions.
  Each bulk flow transfers 256 MiB per direction. The same preface, checked
  payloads, fresh common server, warmup, rotating client order, CPU accounting,
  100 ms RSS sampling and compiler observer as the initial comparison apply.
- Three repetitions per point support descriptive comparisons; bootstrap
  intervals can be broad. CPU is quantized to 10 ms, especially relevant to
  short echo workloads. The shared loopback server/harness use host CPU but
  are excluded from the measured client CPU/RSS.

## Confirmed causes

1. **ARM backend selection.** The locked `aes` 0.8.4 and `polyval` 0.6.2
   require `aes_armv8` / `polyval_armv8` cfg flags for ARM acceleration;
   the recorded build has neither. `chacha20` 0.9.1 similarly selects its
   portable backend without `chacha20_force_neon`, and `poly1305` 0.8.0 has
   no ARM SIMD backend. This is specific to these locked versions and this
   build, not a claim about all RustCrypto implementations or x86 performance.
   VMess `auto` detected hardware AES yet selected a software implementation.
2. **Record buffers.** `Vec::zeroize()` individually cleared initialized
   elements, then the full retained capacity. The codecs invoked it on each
   read phase and drain, including empty pending buffers. Writes allocated
   temporary length/body buffers, appended tags with possible growth, copied
   into another frame, and erased/freed temporaries for every record.
3. **Worker tradeoff.** The CLI has two workers; the FFI runtime already
   selects 2–6 based on available parallelism. More workers can improve
   multi-flow ChaCha throughput but cost CPU and RSS. They do not repair
   wasteful per-byte work. The unchanged two-worker default is used in the
   three-client scoreboard; explicit worker experiments are separate.

[Backend audit](data/backend-audit.json) records the inspected locked-source
checksums and compiled dependency flags. Full cryptographic contexts and the
8 KiB payload buffer are reused in the microbenchmark, with unique per-record
nonces and plaintext round-trip checks. It isolates encryption/decryption from
networking, framing, allocation and scheduling. Median MiB/s, combined seal/open:

| Cipher | Original RustCrypto backend | Existing AWS-LC provider | Ratio |
| --- | ---: | ---: | ---: |
| AES-128-GCM | 228.7 | 9779.0 | 42.8× |
| AES-256-GCM | 182.6 | 8324.4 | 45.6× |
| ChaCha20-Poly1305 | 571.3 | 1890.7 | 3.3× |

These microbenchmark ratios are not end-to-end speedups. The paired ablations
in the archive separate baseline → crypto-only and crypto-only → initial
buffer reuse. The final candidate additionally avoids re-erasing already
consumed plaintext and successfully encrypted pending frames. Each stage's
binary hash, source patch, raw results and cleanup/quality checks are retained.

## Implementation and memory constraints

- `xray-proxy/src/aead.rs` reuses workspace-pinned AWS-LC 1.17.0. No dependency
  version upgrade, hand-written cipher, or machine-specific compiler flags.
  Native SS2022 UDP XChaCha20-Poly1305 and single-block AES header operations
  remain on their existing implementations; TCP gains do not establish UDP
  saturation performance.
- Encode the record prefix and body into one owned pending buffer. SS2022
  retains its 8192-byte write chunks; VMess retains its 8192-byte wire limit
  and existing padding/length options. Storage grows lazily for actual writes.
  No new pool, eager maximum-sized buffer or larger queue.
- Decrypted payload bytes are erased as they are delivered, including partial
  reads. Decrypted headers/lengths are erased when advancing phases; full
  allocations are still wiped on drop. Failed authentication clears the
  provider's possibly modified input; failed writes clear pending plaintext.
  AWS-LC's default allocator cleanses its key-context allocation on free;
  temporary derived key material remains `Zeroizing`.
- Record counters, nonce exhaustion, replay protection, response binding,
  cancellation semantics and partial-write ownership are preserved. VMess's
  65536-record-per-direction bound is unchanged.
- Final CLI file size: 14,927,920 bytes versus 14,944,496 baseline. This is not
  a resident-memory measurement. Refer to measured RSS below, including the
  separate 15-idle-connection control.

## Results

### Paired baseline → final runtime

Eight downloads, 256 MiB each (2 GiB total), three rotating fresh-process repeats. CPU is client CPU time for the same completed bytes, not CPU percentage or power.

| Profile | CPU ms, before → after | CPU reduction | MiB/s, before → after | RSS MiB, before → after |
| --- | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 12670 → 1510 | 88.1% | 322 → 2689 | 6.27 → 6.47 |
| SS2022 ChaCha20 | 7500 → 2410 | 67.9% | 545 → 1687 | 6.19 → 6.25 |
| VMess AES-128 | 16550 → 1890 | 88.6% | 247 → 2170 | 5.59 → 5.72 |
| VMess ChaCha20 | 10350 → 2830 | 72.7% | 396 → 1444 | 5.61 → 5.69 |

The small-flow RSS cost is measurable: +0.06–0.20 MiB in these eight-flow controls. Reuse therefore does not mean zero extra retained memory. The separate one-active-plus-15-idle controls also retain a small fixed cost:

| Profile | CPU ms, before → after | Sampled peak RSS MiB, before → after |
| --- | ---: | ---: |
| SS2022 AES-128 | 1590 → 240 | 5.58 → 5.73 |
| SS2022 ChaCha20 | 960 → 390 | 5.50 → 5.64 |
| VMess AES-128 | 2140 → 300 | 5.62 → 5.70 |
| VMess ChaCha20 | 1420 → 490 | 5.59 → 5.72 |

### RSS scaling with held connections

Each fresh client is measured at 0, 32, 128 and 512 held TCP connections. Every connection first echoes 8192 checked bytes each way. Each point uses five RSS samples after settling; the table is the median across three clients. These are retained-RSS observations, not saturated-transfer peak measurements. No throughput is inferred from this Python driver.

| Profile | 0 connections | 32 connections | 128 connections | 512 connections |
| --- | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 4.16 → 4.17 | 6.78 → 6.88 | 11.14 → 11.08 | 28.09 → 27.67 |
| SS2022 ChaCha20 | 4.16 → 4.19 | 6.77 → 6.83 | 11.09 → 11.00 | 28.12 → 27.56 |
| VMess AES-128 | 4.16 → 4.17 | 7.25 → 7.06 | 11.88 → 11.30 | 30.33 → 28.28 |
| VMess ChaCha20 | 4.14 → 4.19 | 7.23 → 7.05 | 11.83 → 11.30 | 30.34 → 28.31 |

All cells are MiB, baseline → final. At 512 connections the final client uses 0.42–0.56 MiB less for the two tested SS2022 profiles and about 2.0 MiB less for VMess. This bounds the measured tradeoff without assuming that per-connection buffers are free or that idle connections equal busy connections.

### Full clients on the final runtime

**630/630 trials pass** payload, engine-identity and process-cleanup checks, with no detected compiler interference. RSS medians are strictly lower than both references in all 70 cases (140 comparisons). Of the 72 SS2022/VMess bulk case/reference comparisons, CPU meets 45 point targets and throughput 18 under the existing 3% Mac policy; strict counts are 44 and 17. The baseline met 0/72 for either metric. Trojan meets 12/12 CPU and 11/12 throughput targets. **Overall parity remains `not_met`**, including one-flow, throughput, startup and tail-latency differences. These counts are point comparisons, not claims that all confidence intervals support parity.

The table below is the eight-flow download slice. Each cell is **MiB/s / CPU ms / sampled peak RSS MiB**. All workloads, repeats, ranges and intervals remain in [all metrics](all-metrics.md), [point deficits](point-deficits.md), and the [full summary](data/summary-mac-3pct.json).

| Profile | xray-rust | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| Trojan TLS | 2195 / 1830 / 8.39 | 1607 / 2410 / 36.61 | 1581 / 2390 / 31.62 |
| SS2022 AES-128 | 2650 / 1530 / 6.39 | 2263 / 2060 / 39.27 | 2169 / 1980 / 30.62 |
| SS2022 AES-256 | 2599 / 1570 / 6.41 | 2294 / 2110 / 38.97 | 2237 / 1970 / 30.75 |
| SS2022 ChaCha20 | 1622 / 2500 / 6.31 | 2663 / 3810 / 40.34 | 2780 / 3560 / 30.36 |
| VMess AES-128 | 2167 / 1890 / 5.70 | 2426 / 2150 / 36.88 | 1995 / 3170 / 29.89 |
| VMess ChaCha20 | 1439 / 2830 / 5.70 | 2682 / 3690 / 40.08 | 1988 / 5600 / 30.69 |
| VMess auto | 2171 / 1880 / 5.72 | 2483 / 2080 / 36.67 | 1956 / 2950 / 30.20 |

### Worker-count control

Same final binary and eight-flow download, explicitly changing only workers. Cells are **MiB/s / CPU ms / RSS MiB**; these are separate diagnostic runs, not substitutes for the stock-client scoreboard.

| Profile | 2 workers (default) | 4 workers | 6 workers |
| --- | ---: | ---: | ---: |
| SS2022 AES-128 | 2498 / 1600 / 6.44 | 2520 / 2230 / 6.72 | 2419 / 2440 / 6.83 |
| SS2022 ChaCha20 | 1594 / 2540 / 6.38 | 2521 / 3020 / 6.55 | 2738 / 3420 / 6.64 |
| VMess AES-128 | 2130 / 1910 / 5.70 | 2231 / 2700 / 5.91 | 2014 / 3130 / 6.08 |
| VMess ChaCha20 | 1436 / 2840 / 5.70 | 2124 / 3570 / 5.89 | 2245 / 4360 / 6.05 |

AES obtains little additional throughput while CPU and RSS increase. ChaCha gains throughput, but its total client CPU also increases. This supports keeping the two-worker CLI default when CPU efficiency and memory matter. The unchanged FFI 2–6-worker policy needs separate SDK/device measurements. [Control summary](data/control-summary.json) retains all samples/ranges and identifies the excluded contaminated worker subset.

## Validation and evidence

- `cargo test --locked --offline -p xray-proxy --all-targets`: **120 tests pass**,
  including cross-provider wire-byte equality, all cipher/AAD/tag rejection,
  pinned Go fixtures, partial reads/writes, cancellation, nonce exhaustion and
  buffer reuse bounds. The custom microbenchmark's debug invocation is only a
  smoke check; release measurements explicitly use 32768 iterations.
- `cargo fmt --all --check` and proxy all-target clippy with `-D warnings` pass.
- Complete [core CI at ce6deef](https://github.com/aimalygin/xray-rust/actions/runs/36811418960)
  passes Rust, pinned/independent Go interoperability, host hardening
  (Miri/Loom/ASan), fuzz smoke, controlled-network, release interop, supply-chain,
  secrets, Android and Apple jobs. This is automated validation, not physical
  device or release-evidence acceptance. The independent PR run initially hit
  a VLESS fixture port collision before Xray started (`address already in use`);
  its [failed-job rerun](https://github.com/aimalygin/xray-rust/actions/runs/36811033086)
  passes. No protocol change was used to hide that infrastructure failure.
- [SDK CI at f13776d](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36811502022)
  passes for the new `ce6deef` core pin. Canonical adapters/source checks pass;
  ABI 1.8 and version 0.8.0-rc.1 are unchanged, artifact locks remain unprepared.
- Rebuilding the committed runtime with the same locked release command gives
  exactly the measured executable SHA-256. Later edits are report/scanner/bench
  smoke handling only; the mobile pin remains the runtime commit.
- Every one of the 856 archived files is rehashed; strict and 3% main summaries
  are independently recomputed from extracted raw data and match exactly.
  [Control reconstruction](data/summarize-controls.py) verifies the archive,
  selected controls, identities and three-sample groups before producing its
  summary. Local check logs and CI records are retained under `data/`.

The archive contains numeric results and exact manifests, source snapshots,
compiler-interference flags, build/test logs and paired controls. Generated
fixture credentials and full binaries remain local. The initial worker sweep
stopped at run 35 because ANECompilerService reached 12% during the third
VMess/ChaCha two-worker trial; that rejected evidence is retained. The affected
profile is rerun as a fresh complete series; it must not be treated as a clean
36-run sweep or silently mixed into the result.

The first held-memory driver attempt timed out in Python listener cleanup,
after its first 512-connection sample: it awaited listener closure before closing
accepted streams. The corrected driver closes accepted streams first and retains
per-point progress. All 24 fresh clients in the new run pass. The failed original
driver, log and manifest are retained under `held-memory-preparation/`; its
partial measurement is not used in the memory tables.

Reproduction from the repository root (use fresh output paths and the frozen
inputs from this report; do not compile or run other loads during measurement):

```sh
CARGO_INCREMENTAL=0 cargo build --locked --release -p xray-cli
CARGO_INCREMENTAL=0 cargo bench --locked -p xray-proxy --bench aead_backends --no-run
# Run the resulting release aead_backends executable for each provider:
/absolute/aead_backends rustcrypto 32768
/absolute/aead_backends aws-lc 32768
python3 scripts/run-v08-protocol-comparison.py \
  --inputs /absolute/frozen/inputs.json --output /absolute/new/full --repeats 3
python3 scripts/run-v08-cpu-controls.py \
  --binary baseline=/absolute/baseline --binary candidate=/absolute/candidate \
  --reference /absolute/xray --harness /absolute/harness \
  --output /absolute/new/final-controls --traffic download --flows 8 --repeats 3
# The held-memory.py source is included in measurements.tar.gz:
python3 /absolute/extracted/investigation/held-memory.py \
  --repo /absolute/xray-rust --baseline /absolute/baseline \
  --candidate /absolute/candidate --reference /absolute/xray \
  --output /absolute/new/held-memory
python3 docs/benchmarks/results/2026-09-30-v08-cpu/data/summarize-controls.py \
  docs/benchmarks/results/2026-09-30-v08-cpu --output /absolute/control-summary.json
```

Repeat the microbenchmark three times per provider. `--flows 1 --idle 15`
reproduces the active/idle control. Worker controls use repeated `--binary`
arguments pointing at the identical final binary, plus `--worker workers2=2`,
`--worker workers4=4`, and `--worker workers6=6`. Original intermediate source
patches and their binary identities are archived; they are diagnostic stages,
not separately supported product builds. Reference preparation, profiles and
the shared harness are documented in [v08-performance.md](../../../v08-performance.md).

## Remaining limits

There is no evidence here of an unavoidable Rust or Tokio CPU limitation.
Two avoidable costs account for most of the original deficit. The remaining
tradeoffs are more specific:

- **Scheduling versus speed:** two workers limit multi-flow ChaCha throughput;
  the controlled worker sweep measures the speed/CPU/RSS tradeoff directly.
  Increasing concurrency does not solve the single-flow CPU deficit.
- **Record and I/O boundaries:** the codecs still parse lengths and bodies in
  separate read phases, own plaintext buffers, copy data to the caller and wipe
  consumed plaintext. Those operations and task wakeups are plausible remaining
  costs, but this investigation did not isolate their individual contributions.
  One-flow AES/auto download CPU is still 1.07–2.38× a reference in the observed
  failing cases; syscall/stack profiling is the next targeted investigation.
  Read-ahead/coalescing would need a measured per-connection memory budget and
  cancellation/record-limit checks, rather than larger buffers by default.
- **Wire constraints:** VMess's record size and 65536 nonce-counter bound remain
  enforced. Changing framing/chunking or reconnect semantics would be a separate
  protocol change, not a free performance optimization.
- **Coverage:** native SS2022 XChaCha UDP has not been backend-switched, UDP
  tests here measure echo latency rather than saturation, and this host cannot
  establish x86/Android/device throughput, TUN competitor parity or battery use.
  CPU time per completed workload is not energy consumption.

Physical Apple testing remains deferred by the owner's instruction; Android
hardware is unavailable. The SDK source pin is updated to the optimized runtime,
but prior physical/device or binary-artifact evidence must not be reused for
this new commit. No v0.8 tag or release is created by this investigation.
