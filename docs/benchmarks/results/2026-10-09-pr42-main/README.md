# PR #42 after merging main — 2026-10-09–10

The measured pre-merge PR revision is `1388c613971c8785f22107e2fac6be85f956e388`.
The candidate is merge commit `3f07fa7ecab2a00530ebfb649e15edc6a5dfc734`, with
main `d0b5496f1d38e7b1b10c33513829ed56ce7c490f` as its second parent. The merge
keeps the v0.8 protocol implementations and the Vision, blackhole and outbound
probe changes already on main. ABI 1.9 retains Trojan/SS2022/VMess bits 19–21
and the separate probe bit 22. Binary identities remain bound to this measured
runtime commit, independently of subsequent documentation commits.

The merge also repairs the test-only `RuntimeState` initializer for main's
`probe_dns` field and the canonical workflow guard's missing
`test_v08_android_fixture` entry. No interop/performance gate was removed or
weakened, and no new protocol runtime optimization was introduced in this work.

## Compatibility and CI

The [complete CI run on the merge commit](https://github.com/aimalygin/xray-rust/actions/runs/38024178277)
passes all six ordinary jobs: Rust, oracles/interoperability, secrets,
supply-chain, Apple and Android. Conditional release/scheduled jobs are not
part of that ordinary PR run. Later PR revisions have their own check results.

- Local workspace/all-targets: 2,437 passed; 91 external/manual tests remain
  ignored in that invocation. Linux CI: 2,432 passed with the same 91 ignored.
- Strict all-features/all-targets Clippy and the complete repository-script
  check block pass. The 21 secret-exception scope/positive-control tests pass.
- Six local pinned live Trojan/SS2022/VMess tests and two real inner-TLS tests
  after Vision's TLS/REALITY direct switch pass.
- The CI oracle/interop job records 279 passing Rust test executions plus its
  Go checks: pinned codecs, Trojan/SS2022/VMess TCP/UDP/TUN, Mux, independent
  sing-box, REALITY/split-XHTTP/chains, Hysteria and WireGuard controls.
- Apple XCFramework, 329 Swift tests, adapter links and unsigned sample apps
  pass. Android AAR verification and adapter tests pass.

The common Xray server is v26.7.28 at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. Both measured clients are Rust.
This comparison measures the effect of merging main into the existing PR;
earlier Rust-versus-Xray-client performance gaps remain in their dated reports.

## Performance method

The primary matrix has 31 cases with five fresh-process pairs each, alternating
which engine runs first. All 310 included runs validate the exact scheduled
bytes and process cleanup. It includes all seven new protocol/cipher profiles
on TUN duplex with one/eight flows, SOCKS UDP with eight flows, additional
Trojan upload/download cases, and legacy VLESS TLS/REALITY TUN cases.

Bulk work is 1 GiB per direction; duplex validates 2 GiB total. Single-flow
VMess uses 256 MiB per direction to remain below its existing fail-closed AEAD
record limit. UDP uses 1,000 × 1,200-byte messages per flow; the longer controls
use 10,000. These limits are unchanged protocol behavior, not relaxed by the
benchmark. Each pair shares a fresh common server/key set and uses fresh clients.

Both engines were built with Rust 1.96.0, locked dependencies and the same
release flags in separate empty target directories. One frozen pre-merge
`xray-bench` drives both; its source is unchanged between the two revisions.
Manifests record binary/source/tool hashes, workloads, CPU, RSS and raw samples.
The existing TUN setup/measurement boundary is preserved; SOCKS UDP has verified
TCP warmup outside measurement. This is a shared development Mac with per-second
compiler-load observation, not an isolated lab or physical-device energy test.

## Primary results

Changes in candidate/baseline medians; CPU is normalized by validated bytes.
The collector's historical 15% review threshold is not an acceptance allowance.
The separate investigation policy also checks smaller changes and pair signs.

| Case | Throughput | CPU/MiB | Peak RSS |
| --- | ---: | ---: | ---: |
| trojan-tls-tun-full-duplex-1 | +1.09% | +0.60% | +0.83% |
| trojan-tls-tun-full-duplex-8 | +1.86% | -0.73% | -0.89% |
| trojan-tls-socks-udp-8 | -1.24% | +0.00% | -1.43% |
| ss2022-aes128-tun-full-duplex-1 | -0.22% | +0.87% | +1.68% |
| ss2022-aes128-tun-full-duplex-8 | +0.35% | -1.11% | +1.55% |
| ss2022-aes128-socks-udp-8 | +1.06% | +0.00% | -1.74% |
| ss2022-aes256-tun-full-duplex-1 | -0.63% | -0.57% | +2.53% |
| ss2022-aes256-tun-full-duplex-8 | +1.35% | -0.74% | +2.17% |
| ss2022-aes256-socks-udp-8 | -2.62% | +0.00% | -1.00% |
| ss2022-chacha20-tun-full-duplex-1 | +1.28% | +0.00% | -2.64% |
| ss2022-chacha20-tun-full-duplex-8 | +0.69% | +0.26% | -0.47% |
| ss2022-chacha20-socks-udp-8 | -0.20% | +4.17% | -0.50% |
| vmess-aes128-tun-full-duplex-1 | +0.53% | +0.00% | +2.59% |
| vmess-aes128-tun-full-duplex-8 | +0.13% | +1.50% | -0.80% |
| vmess-aes128-socks-udp-8 | -2.06% | +5.56% | +0.73% |
| vmess-chacha20-tun-full-duplex-1 | -0.41% | +0.00% | +0.83% |
| vmess-chacha20-tun-full-duplex-8 | -0.88% | +0.26% | +1.08% |
| vmess-chacha20-socks-udp-8 | -0.41% | +5.00% | -0.48% |
| vmess-auto-tun-full-duplex-1 | -0.89% | +0.00% | +0.21% |
| vmess-auto-tun-full-duplex-8 | -0.87% | +3.72% | +8.06% |
| vmess-auto-socks-udp-8 | +0.63% | +0.00% | -0.72% |
| trojan-tls-tun-upload-1 | +0.34% | -1.06% | +0.36% |
| trojan-tls-tun-download-1 | +0.38% | +0.00% | +0.93% |
| trojan-tls-tun-upload-8 | +3.17% | +0.66% | -0.39% |
| trojan-tls-tun-download-8 | -2.48% | +0.64% | -2.47% |
| vless-tls-tun-download-1 | +0.41% | +0.59% | +1.09% |
| vless-tls-tun-full-duplex-1 | -0.03% | +0.59% | +1.77% |
| vless-tls-tun-full-duplex-8 | +3.06% | +0.00% | +0.70% |
| reality-vision-tun-download-1 | +0.31% | +0.58% | +0.00% |
| reality-vision-tun-full-duplex-1 | +0.66% | +1.20% | +1.55% |
| reality-vision-tun-full-duplex-8 | -1.24% | -1.15% | +3.03% |

Across this primary matrix throughput changes range from −2.62% to +3.17%;
UDP median latency changes range from −0.79% to +0.86%. Initial CPU and RSS
signals are retained rather than replaced by the follow-ups below.

## Investigation and controls

The short VMess AES UDP case initially reports +5.56% CPU (180 to 190 ms).
VMess ChaCha and SS2022 ChaCha similarly differ by one 10 ms CPU quantum in
short runs. The host driver's `ps time` accounting has that resolution.
Ten-times-longer workloads and identical-binary A/A controls investigate all
three profiles, retaining the original shorter observations.

VMess auto/eight-flow duplex initially reports +8.06% peak RSS. A fresh paired
repeat reports +3.55% (+0.47 MiB), +3.05% throughput and −2.28% CPU. Across the
ten candidate/baseline pairs, RSS increases in five and decreases in five.
The A/A run spans 12.67–14.55 MiB for the same executable; its median ratio is
−1.05%. The data does not establish a consistent memory regression, and is not
proof that every smaller memory difference is zero.

| Follow-up / control | Throughput | CPU/MiB | Peak RSS |
| --- | ---: | ---: | ---: |
| memory-confirmation | +3.05% | -2.28% | +3.55% |
| memory-aa-clean | +0.92% | +1.52% | -1.05% |
| udp-long-confirmation-ss2022-chacha20 | -0.17% | +0.45% | -0.50% |
| udp-long-confirmation-vmess-aes128 | -0.05% | -0.59% | +0.00% |
| udp-long-confirmation-vmess-chacha20 | -0.19% | -1.12% | -0.71% |
| udp-long-aa-ss2022-chacha20 | +0.11% | -0.45% | +0.00% |
| udp-long-aa-vmess-aes128 | +0.09% | -0.59% | -0.48% |
| udp-long-aa-vmess-chacha20 | +0.03% | +0.56% | +0.24% |

The 80 included follow-up/control runs all pass. Longer UDP candidate/baseline CPU changes range from −1.12% to +0.45%, with throughput from −0.19% to −0.05%. No sustained throughput or CPU regression was reproduced in this bounded host matrix. This does not establish all-network, physical-device energy or release acceptance.

## Retained interruptions and evidence

The original primary collection stopped after 299 successful transfers when
Apple `ANECompilerService` reached 61.7–96.9% CPU during a REALITY duplex run.
All original observations remain in `perf-primary`. Only its 29 fully complete
cases without observed compiler activity are used; both incomplete REALITY
duplex cases were repeated as complete fresh groups in `perf-reality-completion`.
`perf-primary-complete` is a derived 31-case view, with source-manifest hashes
and byte-identical copies of the selected raw results; it is not another run.

The system service also interrupted the first CPU confirmation and the last
memory A/A pair. Those attempts remain with explicit quality failures. Further
controls keep the first five complete clean pairs, rejecting a whole pair only
for observed compiler activity, never for its performance value. Pair order
alternates, rejected attempts and the selection ledger are retained, and no
unrelated system process is stopped. Aggregate control directories are derived
views; individual attempts are archived separately.

An initial smoke request incorrectly supplied SOCKS-only options to the TUN
driver and was rejected before client startup. Its original collector/log and
the corrected eight-run smoke are retained. An initial release build reused
stale Cargo artifacts across worktrees; both measured engines were subsequently
rebuilt in distinct empty targets. The initial compile failure for the missing
test field, original PR CI failure and successful validation logs are retained.

`measurements.tar.gz` contains manifests, raw results, summaries, client/server
logs, collectors and validation/build logs. Generated configuration requests,
credentials, certificate keys and certificate files are omitted. The existing
fixtures reconstruct them. `evidence-index.json` hashes every archived member;
`summaries.json` contains the full distributions and explicitly identifies
incomplete/invalid campaigns. Derived views must not be counted as new trials.

Extract into a temporary directory, verify every member against the index, and
run `scripts/summarize-v07-performance.py` on each complete non-invalid campaign.
The collection helpers and pair-selection scripts retain the exact
schedule, source identities and acceptance rules. Absolute paths identify the
original experiment and can be relocated when rebuilding the recorded revisions.

The [v0.8 release/device gates](../../../v08-release-readiness.md) remain open.
Historical iPhone/Android failures and owner-skipped transitions retain their
original verdicts. SDK PR33 is separate and is not repinned by this work. The
PR remains a draft, and no tag or package is published by this work.
