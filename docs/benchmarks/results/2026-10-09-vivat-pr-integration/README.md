# PR #48–50 integration validation — 2026-10-09

The integration retains all original PR commits and leaves draft #42 separate.
The probe uses C ABI 1.9 / bit 22, preserving ABI 1.8 / bits 19–21 for #42.
Swift rejects embedded NUL; lifecycle calls cancel probes before draining shared
calls. The shared C cancellation API does not relax handle lifetime rules.

The tested main baseline is `f5aefca40b9f492e8095ba3c1620ae627ce331ee`.
The frozen candidate is `17f0d8c77fc177d50d0aa08a34a40f767a9d3d07`; production
binaries were built at `bc9db66da5484606838af8308d40493e79e176a0`. Later changes
are tests, CI policy, and evidence only. Build manifests record hashes and tools.
The Xray-core reference is v26.7.28, commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

## Performance

Five fresh-process paired repetitions per case, alternating engine order. The
same frozen baseline `xray-bench` drives both engines. Final cases validate 1 GiB
per direction (16,384 × 64 KiB for one connection, 2,048 × 64 KiB per connection
for eight). Duplex validates 2 GiB total. Release builds use locked dependencies,
Rust 1.96.0 and the same build flags. No builds or tests ran alongside final
measurements; this was a shared development host, not an isolated lab.

Candidate/main changes in medians; CPU is normalized by validated bytes. The
collector's 15% investigation threshold is retained in raw manifests, but is
not treated as proof that smaller differences are acceptable.

| TUN case | Throughput | CPU/MiB | Peak RSS |
| --- | ---: | ---: | ---: |
| reality-vision-tun-download-1 | -2.78% | -0.58% | +1.11% |
| reality-vision-tun-download-8 | -1.34% | -0.67% | +2.04% |
| reality-vision-tun-full-duplex-1 | -0.39% | -0.60% | -3.38% |
| reality-vision-tun-full-duplex-8 | +1.41% | -3.47% | -0.86% |
| reality-vision-tun-upload-1 | -1.82% | -1.09% | +0.53% |
| reality-vision-tun-upload-8 | -0.39% | -3.31% | +1.63% |
| vless-tls-tun-download-1 | +0.80% | +0.61% | +1.69% |
| vless-tls-tun-download-8 | +0.50% | -0.65% | -3.70% |
| vless-tls-tun-full-duplex-1 | -0.35% | +0.30% | -1.81% |
| vless-tls-tun-full-duplex-8 | +1.49% | -0.40% | -3.25% |
| vless-tls-tun-upload-1 | +0.08% | -0.56% | +0.18% |
| vless-tls-tun-upload-8 | +0.85% | -0.71% | +1.87% |

All 120 final-matrix runs passed. Across this matrix throughput changes range
from −2.78% to +1.49%, CPU/MiB from −3.47% to +0.61%, and peak RSS from −3.70%
to +2.04%. No sustained regression was reproduced in the investigated cases.

The initial PR #48-only, shorter TLS upload/1 case reported −21.14% throughput
and +16% CPU. All 60 initial runs remain in `pr48/`; they are not replaced by
later measurements. A 1 GiB confirmation reported −0.48% throughput / +1.09%
CPU; its identical-binary A/A control reported −0.72% / +0.54%. The original
outlier's exact cause was not established.

The final REALITY download/1 median was −2.78% throughput with overlapping raw
sample ranges. Its A/A control reported +0.96% throughput / unchanged CPU;
an independent candidate confirmation reported +0.39% throughput / +1.18% CPU.
Both attempts and controls are retained. There are 220 measured runs in total.

These are loopback host throughput/CPU/RSS measurements, not physical-device
energy, long-running leak, all-transport, or all-network acceptance. Real inner
TLS after Vision's direct switch is validated functionally with concurrent bulk
transfer; the throughput matrix uses the existing non-TLS payload driver.

## Compatibility and validation

- Full Rust all-targets suite: 2,339 passed, 72 externally gated tests ignored.
  Strict all-features/all-targets Clippy passed.
- Pinned live Xray suite: 23 passed, spanning TLS, REALITY, Vision, WS,
  HTTPUpgrade, gRPC, selected XHTTP H1/H2/H3 modes, bursts and proxy chaining.
- Swift package: 323 passed with the CI-pinned geodata. Host JNI: 9 passed,
  including actual Rust/JNI probe and stop/close cancellation tests.
- Blackhole `none`/`http`: actual Rust and Xray processes agree byte-for-byte
  over SOCKS TCP and UDP, including a single UDP HTTP response followed by
  absorption. An initial diagnostic harness incorrectly declared source port 9
  in UDP ASSOCIATE; Xray correctly filtered that traffic. That invalid attempt,
  corrected script, and corrected results are retained and distinguished.
- A separate temporary merge of #42 at `1388c61` with integration at `bc9db66`
  passed blackhole (11), probe (5), live Trojan/SS2022/VMess (6), inner TLS (2),
  and FFI version/capability (6) tests. `validation.json` records its commit.
  This is targeted compatibility evidence, not approval to merge or release #42.

The full suite exposed three test races: accepted sockets inheriting nonblocking
mode on macOS, timestamp-only GeoIP fixture directory collisions, and an H3 test
assuming one scheduler yield delivered STOP_SENDING. Fixes affect tests only;
the two H3 finish-race tests also passed 100 repeated executions. Earlier failed
logs remain in the archive. Swift's first run lacked geodata; the complete
repeat used the same pinned data as CI.

Secret scanning retains exact path/value/rule restrictions, with positive leak
controls. Historical v0.7 promotion hashes are checked against its immutable
published commit, and the Rust CI checkout supplies that history. None of these
changes re-label the historical release evidence.

## Evidence and reproduction

`measurements.tar.gz` contains every performance manifest, raw result, summary,
client/server log, build manifest, and the validation logs. Ephemeral certificate
keys, certificate files, and generated request/config files for the TLS fixtures
are omitted; the unchanged repository collector reconstructs those fixtures.
The blackhole harness/configs are included because they contain only loopback
addresses and no credentials. `evidence-index.json` hashes every archived member;
`summaries.json` retains all measurements and distributions in readable form.

Extract into a temporary directory, verify member hashes, then rerun
`scripts/summarize-v07-performance.py` on each extracted case directory. Its
relative output paths, validated byte counts, failures, and raw distributions
are preserved. `validation/run-final-matrix.py` records the exact final workload
schedule. The recorded absolute paths identify the original experiment, and may
be relocated when rebuilding the two source revisions.
