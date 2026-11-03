# 0.9.0 candidate measurements — 2026-11-02

**Publication authorized with explicit 0.9.0 limitations; distribution gates pending.**
Every scenario and transition required by the v0.9 schema-4 gate passed on a
physical iPhone and a physical Samsung phone, and all 13 performance metrics
passed their thresholds. The owner performed the physical iPhone Wi-Fi/cellular
and lock/wake actions. Superseded attempts are kept under [failed/](failed/)
with their causes; none was a defect in the native library. Asked whether to
release 0.9.0 with these limitations and publish the evidence, the owner
answered “Да, публикуй”. The
[0.9.0 decision record](../../releases/v0.9.0-owner-decisions.json) lists the
scoped decisions and the accepted known limitations.

## Candidate and artifact boundary

- Core commit `30928ad51b4a434546cf143f8e385a8746523172`, tree
  `e55a6c3f021643bd507a611c247f2781aaabbb83`.
- SDK candidate `9e030609c5734616cf79ee900abeaddfea0cfe0a`
  (xray-rust-mobile) pins that core commit in `release/core.env`.
- Native libraries and host binaries use the workspace release profile
  (Rust 1.96.0; Android NDK 26.3.11579264). iPhone and Samsung host and probe
  apps are Debug harnesses, not store or release packages.
- Android native arm64 SHA256:
  `11ae10381ce170f3053024bd4a783ea313ffbc13f4e9542d0fe2770b1815c10b`.
- Apple static library (aarch64-apple-ios) SHA256:
  `247a216985dc51aa749d036f5c4701725bea64a44cea521d8ce4c02c1e666361`.
- Host CLI `xray-rust` SHA256 `6e378c68d0326d631b44cab20a884128cec7e0918611018f3c6980de2cf4a77b`;
  reference Xray-core v26.10.21 (macOS) SHA256
  `186ab2062fe347d513bfa41d4afebc1cd4c7f70e0675e523648eb34049f68ebb`.
- Devices: iPhone 17 Pro Max (iPhone18,2) / iOS 27.0.1 (24A446), Samsung
  SM-A145F / Android 15 API 35, arm64. Device identifiers, private addresses,
  server addresses and fixture credentials are redacted; the probes address
  the fixture through documentation addresses (198.51.100.7, 2001:db8::7).

## iPhone

| Run | Result | Coverage |
| --- | --- | --- |
| [v09 smoke](ios-v09-smoke-result.json) | 4/4 | SOCKS, HTTP, HTTPS, SS AEAD: IPv4/IPv6 TCP, IPv4/IPv6 UDP (HTTP: refused), domain, routed DNS, import, three start/stop cycles, close-connections with verified closure and recovery, invalid-import redaction |
| [v09 lifecycle](ios-v09-lifecycle-result.json) | 4/4 | startup cancellation (12) and rapid restart (20) |
| [v09 resources](ios-v09-resources-result.json) | 4/4 | one/eight-flow cycles and 20 recovery samples per protocol |
| [SS AEAD ciphers](ios-ciphers-v09-result.json) | 4/4 | aes-128-gcm, aes-256-gcm, chacha20-poly1305, xchacha20-poly1305 |
| [legacy](ios-legacy-v09-result.json) | 9/9 | VLESS REALITY, XHTTP H1/H2/H3, WireGuard, Hysteria2, Trojan, SS2022, VMess |
| [shared](ios-shared-result.json) | 3/3 | VLESS encryption, IP-on-demand, XHTTP download session |
| FakeDNS controls | as expected | [AsIs negative](ios-fakedns-negative-result.json) failed as designed (literal TCP passed, synthetic domain did not); [recovery](ios-fakedns-recovery-result.json) passed |
| Projection [FD](ios-projection-file-descriptor-result.json) / [packet pump](ios-projection-packet-pump-result.json) | 36 + 36 observations | actual TCP and UDP callback counters on both backends |

Resource recovery stayed inside the preregistered 8 MiB RSS/footprint and
8-thread bounds: maximum RSS growth 3,325,952 bytes (3.2 MiB), footprint growth
196,608 bytes, thread growth 1.

**WAN** ([ios-wan/](ios-wan/), reference server Xray-core v26.10.21 on the
owner's VPS, test port only; 3x-ui and other services were recorded before and
restored after each run). Each protocol ran a Wi-Fi baseline, Wi-Fi to cellular,
back to Wi-Fi, and a screen lock with the probe in the background, with zero
retries and the runtime unchanged:

| Protocol | Recovery after cellular / Wi-Fi / unlock (s) | Lock (s) | TCP | UDP |
| --- | --- | ---: | ---: | ---: |
| SOCKS | 6.0 / 5.4 / 5.4 | 30.5 | 12 | 8 echoed |
| HTTP | 10.9 / 9.8 / 10.0 | 27.1 | 12 | 8 refused |
| HTTPS | 11.4 / 11.0 / 10.8 | 37.6 | 12 | 8 refused |
| SS AEAD (aes-256-gcm) | 3.3 / 3.3 / 3.3 | 36.6 | 12 | 8 echoed |

SOCKS UDP needs the reference server's ephemeral relay ports: the SOCKS run
passed while the provider firewall temporarily allowed UDP 32768-60999. The
attempts with only the test port open are retained.

## Samsung

| Run | Result | Coverage |
| --- | --- | --- |
| [v09 matrix](android-v09/events.jsonl) | 14/14 | SOCKS, HTTP, HTTPS, four SS AEAD ciphers on FD and packet-pump: IPv4/IPv6 TCP and UDP (HTTP: refused), domain, routed DNS, close and cancel/start recovery; link import; 3 invalid-import controls |
| [legacy](android-legacy-v09/events.jsonl) | 18/18 | nine pre-0.9 outbounds on both backends |
| [TCP cancellation](android-cancel-tcp/events.jsonl) | 16/16 | local active close and disconnect; remote EOF 1.10-1.46 s, inside the bound every time |
| [UDP cancellation](android-cancel-udp/events.jsonl) | 8/8 | delayed UDP cancel and recovery, SOCKS and SS AEAD |
| Resources [A](android-resources-a/events.jsonl) / [B](android-resources-b/events.jsonl) | 14/14 | 6,720/6,720 HTTP and 9,600/9,600 UDP under burst; recovery inside max(8 MiB, 25% of first recovery RSS) and 4 threads (largest growth 13,074,432 bytes, thread growth 0) |
| [shared](android-shared/events.jsonl) | 6/6 | VLESS encryption, IP-on-demand, XHTTP download session; AsIs negative and recovery controls; host-adapter projection 6/6 |

Wi-Fi/cellular and lock/wake were not run on Android (owner decision
2026-11-01); they are not tested, not successful.

Host loopback preflights ([host-loopback/](host-loopback/)) passed v09 4/4,
ciphers 4/4 and legacy 9/9.

## Performance

Release build of the candidate on Apple M6 (macOS), with no other heavy load
running. By owner decision only the 13 gate metrics were measured; there is no
non-regression claim against 0.8.1.

| Metric | Median | Threshold |
| --- | ---: | --- |
| process-throughput | 587.5 MiB/s | at least 10 |
| vless-encryption-throughput | 351.1 MiB/s | at least 276.5 (half of plain VLESS) |
| ip-on-demand-latency | 0.165 ms | at most 1.159 (direct + 1 ms) |
| xhttp-memory | 20.7 MiB | at most 64 |
| socks-throughput / latency / memory | 101.6% / 98.2% / 5.8 MiB | ≥50% / ≤200% / ≤64 MiB |
| http-throughput / latency / memory | 104.2% / 101.8% / 8.4 MiB | ≥50% / ≤200% / ≤64 MiB |
| shadowsocks-aead-throughput / latency / memory | 59.3% / 102.2% / 6.0 MiB | ≥50% / ≤200% / ≤64 MiB |

Protocol metrics are single-flow loopback SOCKS ingress, five rotating-order
pairs against pinned Xray-core v26.10.21 over a common Xray-core server; each
sample is the worst profile of its group in that repeat
([comparisons](performance-protocols/protocol-comparisons.json)). The
Shadowsocks AEAD throughput sample is set by xchacha20-poly1305 at a median 59%
of Xray (about 680 versus 1140 MiB/s); the other three ciphers reached 95-100%.

## Harness changes and superseded attempts

None of these touched the native library or the production provider; patches
and tools are in [tools/](tools/).

- Android REALITY warm-up: the driver started the matrix right after fixture
  readiness, and the first REALITY decoy handshake made the first HTTP probe
  time out. A 10 s wait fixes it (3/3 fail without, 3/3 pass with;
  [diagnosis](diagnostics/android-reality-warmup/README.txt)).
- iOS close check: the probe's closure verification needs a live flow, which
  HTTP lacks; an idle 1-byte held TCP flow must now end less than 5 s after the
  close request ([patch](tools/ios-probe-http-held-flow-and-fakedns.patch)).
- XHTTP download bridge LAN bind for the Android shared run
  ([patch](tools/download-bridge-lan-bind.patch)).
- Debug sample-provider observation hooks for the iOS projection runs
  ([patch](tools/ios-projection-build.patch)).

Superseded attempts, each with its cause: Android v09 (permission dialog),
Android legacy (REALITY warm-up), Android shared (bridge bound to loopback),
Android UDP cancel (collector syntax error, nothing ran), iPhone smoke ×3
(runner arguments; close check without a live flow; held flow ended at the echo
limit), iPhone resources (one HTTPS first exchange closed after 10 s, not
reproduced), iPhone WAN HTTP (app not returned to foreground after unlock),
iPhone WAN SOCKS ×3 (relay ports blocked; narrowed container port range
exhausted), and the protocol performance collector (missing suite field).

## Reproduction

The tools in [tools/](tools/) ran from a detached worktree of the candidate;
`<repo>`, `<candidate-worktree>`, `<scratch>` and `<home>` replace local paths.
[inventory.json](inventory.json) lists every published file with the SHA256 of
its source and of its redacted copy.

## Remaining release work

Validate the archive with
[v09-release-evidence.yml](../../../.github/workflows/v09-release-evidence.yml)
on the exact candidate, then follow the tag, package and clean-consumer steps in
[the release plan](../../v090-release.md). Do not move an existing tag or
replace these measurements with another candidate's results.
