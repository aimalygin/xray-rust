# v0.7 performance fixes — 2026-09-19

The selected fixes pass both historical release gates and all 990 primary
transport/protocol runs. The observed idle-memory failures, H1 TUN stall and
WireGuard load-completion failures are resolved on this host. This report
retains failed alternatives and all initial performance review flags; it does
not establish physical-device or unrestricted network acceptance.

The starting point is v0.7 development commit
`7f87ffe7eaf4ed088a45172d2468df956f26550b`. Legacy comparisons use v0.6.1
`ed5258a3a589c2a1f9330142f37c8f3d28a640fa`. New protocols are compared against
the original v0.7 build or an explicitly identified intermediate build. Both
versions run on the same macOS host with pinned Go Xray-core v26.7.28
`5ca6f4b7d4dc20a881d4330e498892697627ec0c` and one frozen external driver.

## Causes and fixes

- **Idle TCP memory:** Hysteria2/WireGuard connection setup enlarged a shared
  async future from about 4 KiB to 9.8 KiB, including Freedom/VLESS tasks.
  Boxing those cold setup paths restores the shared future to 3920 bytes
  (routed wrapper: 4128 bytes). Three preliminary 1000-flow repetitions fell
  to 24,096–24,112 KiB from the original 31,680 KiB median; final release-gate
  values supersede these preliminary measurements.
- **TUN upload stalls:** freeing the bounded bridge queue did not wake the
  actor that still held unread TCP bytes. It could wait for a TCP probe for
  roughly one second. Capacity release now wakes a backpressured actor, with
  registration followed by a capacity recheck to cover the race. A regression
  test fails before the fix and passes after it without sending another packet.
  The upload batch remains alive beside download and cancellation; existing
  stalled-upload download/host-close tests remain required.
- **WireGuard deadlock:** delivery into a full inner IP queue retained the
  peer/device locks needed by reverse traffic. The engine releases them after
  authentication and allowed-IP validation, before awaiting delivery. A bounded
  receive-path regression test fails before the patch and passes after it.
- **WireGuard packet loss under load:** engine queues could exhaust the
  56 data reservations. Diagnostics recorded hundreds of admission drops and
  TCP retransmission pauses. Four-packet engine queues leave headroom for both
  UDP families, the adapter and handshake backlog. The 64 total reservations
  and eight reserved control slots remain enforced.
- **WireGuard delayed-path throughput:** the 16 KiB inner TCP window limited
  progress across nonzero RTT. TCP now uses 256 KiB per direction, Reno and
  disabled Nagle, with direct writes into the existing socket buffer. Sixteen
  slots bound TCP window storage at 8 MiB per client. The carrier requests a 7 MiB receive
  buffer per enabled family, matching the pinned wireguard-go request; this
  avoids large concurrent receive bursts overwhelming the host's default queue.
- **WireGuard receive-window mismatch:** `DeviceCapabilities.max_burst_size`
  clamped the TCP window on the wire after the socket recorded its advertisement.
  An actual SYN advertised only 10,944 bytes instead of 65,535. The adapter now
  leaves the TCP window intact; its eight-packet channel still enforces packet
  admission. The wire-level regression test fails before and passes after this fix.
- **TCP loss recovery:** the previous smoltcp 0.13.1 rate-limited acknowledgements
  of repeated, already-consumed data; a deterministic lost-ACK test reproduces it.
  smoltcp 0.14.0 passes the same test and includes corrections to fast-retransmit
  RTO backoff and Reno's congestion-window accounting. Stalled-flow diagnostics
  on 0.13.1 recorded 60-second RTOs, completed upload, incomplete download and no
  engine admission drops or UDP I/O errors. This motivated the dependency update;
  the stress campaign below determines its observed effect on load completion.
  See the [upstream release](https://github.com/smoltcp-rs/smoltcp/releases/tag/v0.14.0),
  [fast retransmit fix](https://github.com/smoltcp-rs/smoltcp/pull/1155),
  [Reno fix](https://github.com/smoltcp-rs/smoltcp/pull/1156) and
  [data ACK fix](https://github.com/smoltcp-rs/smoltcp/pull/1162).
- **Hysteria2/WireGuard TUN memory:** an eight-message upload queue and 64 KiB
  batch target avoid duplicating large amounts of data already held by QUIC or
  the inner TCP windows. A batch can exceed its target by one final message of
  at most 32 KiB. Other outbounds retain their existing bridge limits.

## Final paired measurements

All values are medians. H1 compares v0.6.1 with the selected fix; new protocols
compare original v0.7 `7f87ffe` with the selected fix. Each row has three pairs
unless stated otherwise. Throughput counts both directions for duplex.

| Scenario | Before | Fixed | Evidence group |
| --- | ---: | ---: | --- |
| H1 TUN duplex, 32 MiB/direction, one flow | 56.05 MiB/s in v0.6.1 | 57.11 MiB/s | final2-h1-long |
| Hysteria2 TUN upload, eight flows × 32 MiB | 72.24 MiB/s; 103.86 MiB RSS; 2140 ms CPU | 210.80 MiB/s; 47.27 MiB RSS; 2100 ms CPU | final2-hysteria-long |
| Hysteria2 TUN duplex, eight flows × 32 MiB/direction | 295.54 MiB/s; 106.89 MiB RSS; 4570 ms CPU | 300.44 MiB/s; 43.70 MiB RSS; 4350 ms CPU | final2-hysteria-long |
| WireGuard upload, one flow, 2 MiB, added 50 ms RTT / 100 Mbit/s | 0.290 MiB/s; 200 ms CPU | 2.195 MiB/s; 90 ms CPU | final2-wireguard-original-delay |
| WireGuard download, one flow, same delayed path | 0.192 MiB/s; 440 ms CPU | 3.309 MiB/s; 170 ms CPU | final2-wireguard-original-delay |
| WireGuard upload, eight flows, same delayed path | 2.305 MiB/s; 730 ms CPU; 9.22 MiB RSS | 9.172 MiB/s; 450 ms CPU; 10.80 MiB RSS | final2-wireguard-original-delay |
| WireGuard download, eight flows, same delayed path | 1.523 MiB/s; 2180 ms CPU; 7.67 MiB RSS | 10.403 MiB/s; 960 ms CPU; 9.11 MiB RSS | final2-wireguard-original-delay |
| Hysteria2 TUN download, eight flows, 4 MiB/flow, delayed path, five pairs | 10.873 MiB/s; 640 ms CPU | 10.874 MiB/s; 620 ms CPU | final2-hysteria-delay-download |

Five additional short Hysteria2 pairs (4 MiB per flow, eight TUN flows)
measure upload at 131.71 → 120.11 MiB/s (−8.8%), RSS 72.13 → 39.77 MiB and
CPU 370 → 350 ms. Duplex measures 237.76 → 246.31 MiB/s, RSS 65.66 → 41.08 MiB
and CPU 680 → 650 ms. The short-upload decrease stays below the pre-existing
15% review screen; it is retained as a tradeoff, not described as a speedup.
The much larger upload gain in the 32 MiB-per-flow case is volume-dependent.

The original v0.7 H1 TUN long diagnostic measured 8.73 MiB/s. The final
v0.6.1 comparison above verifies restoration of the old throughput level.
WireGuard's eight-flow delayed-path RSS crosses the 15% review screen
(+17.1% upload, +18.7% download): the additional 1.58/1.44 MiB accompanies
larger, explicitly bounded TCP windows. CPU falls 38%/56% while throughput
increases 4.0×/6.8×. This memory tradeoff is retained, not hidden as noise.

The initial paced Hysteria2 download comparison reported 860/1100 ms CPU.
Five final original-v0.7/fix pairs instead measure 640/620 ms, with unchanged
throughput. The original CPU increase did not reproduce. Rejected J added
conditional notifier polling and extra synchronization without demonstrated
CPU benefit; those changes are absent from the selected source.

## Matrix and flagged controls

The primary matrix completed all **990/990 byte-validated runs**:

| Suite | Cases | Runs | Failed |
| --- | ---: | ---: | ---: |
| Legacy transports | 37 | 370 | 0 |
| Freedom/VLESS/XHTTP through TUN | 30 | 300 | 0 |
| Additional REALITY/Vision SOCKS/TUN | 12 | 120 | 0 |
| Hysteria2/WireGuard TCP/UDP | 40 | 200 | 0 |

The historical legacy matrix has no crossings of the 15% review screen.
The full new-protocol measurements, including median/range, echo latency,
RSS and CPU per MiB, are in [protocol-table.md](protocol-table.md).
[review-table.md](review-table.md) retains the four initially flagged cases.
[data/campaign-summary.json](data/campaign-summary.json) retains their exact
ratios rather than rewriting the primary outcome after follow-ups.

Three TUN CPU flags were one 10 ms sampling/accounting quantum on the short
4 MiB workloads. Five pairs at 32 MiB per flow have no screen crossings:

| Flagged TUN case | Short CPU, v0.6.1/fix | Longer CPU, v0.6.1/fix | Longer throughput, v0.6.1/fix |
| --- | ---: | ---: | ---: |
| Freedom duplex, one flow | 30/40 ms | 130/130 ms | 567.25/572.76 MiB/s |
| VLESS/TLS download, one flow | 50/60 ms | 110/100 ms | 565.82/560.06 MiB/s |
| XHTTP H3 upload, one flow | 60/70 ms | 320/310 ms | 27.66/139.09 MiB/s |

These controls do not reproduce a sustained CPU penalty. H3's long baseline
has large timing spread; the table preserves the observation without claiming
that all H3 workloads gained fivefold throughput.

The short eight-flow REALITY/Vision duplex screen crossed twice: initial
v0.6.1/fix medians 1395.67/1109.61 MiB/s and a separate five-pair repeat
1361.10/1085.21 MiB/s (about −20%). This was investigated further, not removed
from the primary summary. Five pairs at four times the byte count
(128 MiB per flow/direction) measure 1573.43/1593.56 MiB/s (+1.3%), CPU
1710/1840 ms (+7.6%) and RSS 11.56/11.72 MiB, with no screen crossings.

A fixed 20-repeat three-version control at the original 32 MiB volume then
measures medians 1053.87 / 1152.94 / 1027.63 MiB/s for v0.6.1 / original v0.7 /
the fix. The fix is −2.5% versus v0.6.1 and −10.9% versus original v0.7, below
the existing review threshold; CPU is 510/515/520 ms. Throughput ranges are
881–1565 / 691–1558 / 876–1488 MiB/s. Thus the specific 20% deficit is not
stable across independent collections, and the longer control does not show a
sustained throughput loss. The cause of the short-run timing variation is not
proven. No speculative REALITY runtime change is included; this case should
remain in subsequent platform acceptance, with all original flags visible.

The final paired controls and longer follow-ups total 222 successful runs
outside the primary 990. The unsupported close-probe invocation is excluded
from that count. The selected-source 40-run WireGuard stress series is separate.



## Window-size selection and rejected alternatives

The original v0.7 matrix passed only 83/100 WireGuard runs. Intermediate I
passed its first bounded stress tests but later failed one of 100 WireGuard
matrix runs. K removed the receive-window clamp while retaining smoltcp 0.13.1
and still failed two of 20 eight-flow duplex runs. L/L2 reproduced the stall
with diagnostic logging/polling and are excluded from performance comparison.
These failures are retained; increasing only carrier buffers or the advertised
window was insufficient.

Selected M uses smoltcp 0.14.0 and 256 KiB windows. It completed 20/20
32 MiB-per-flow duplex runs on eight connections and another 20/20 on all
sixteen connections (512 MiB sent and 512 MiB received per sixteen-flow run).
With 50 ms added RTT / 100 Mbit/s and 2 MiB per flow, single-flow download
improved from I's 1.474 to 3.374 MiB/s. Corrected Reno congestion accounting
reduced short upload throughput from I's 4.522 to 1.817 MiB/s, so I is not a
valid "faster and stable" alternative. The final comparison also measures the
original v0.7 build directly, separately from these intermediate prototypes.

N enlarged each window to 1 MiB. On 16 MiB single-flow transfers it increased
upload/download from M's 4.005/4.483 to 7.241/9.504 MiB/s. The gain did not survive
load acceptance: after 20/20 eight-flow passes, both first sixteen-flow runs
hit the 120-second deadline. The third run was interrupted and that incomplete
series receives no aggregate performance result. O also enabled 32 reassembly
ranges (default: four); its isolated out-of-order packet test improved from
9/32 to 32/32 delivered bytes without retransmission, but its first sixteen-flow
load run still timed out. Both changes were reverted. Their raw failures and
source patches remain archived, and no larger-window result is presented as
accepted production performance.

The selected memory/throughput balance does not saturate every delayed
single-flow upload. Against the pinned Go client on the short 2 MiB delayed
upload, M measured 1.80 vs 4.14 MiB/s, 30 vs 70 ms CPU and 7.0 vs 38.0 MiB RSS.
Reno starts conservatively; disabling congestion control to improve that number
would remove required network feedback. Device/network acceptance remains
necessary, especially when the OS clamps the requested carrier receive buffer.

## Validation and provenance

Both original clean-snapshot gates passed at temporary source commit
`61373052dc8b6784162c81650faa6bd92f0604aa`, using unchanged thresholds and
five repetitions. The main development branch is not committed by this task.
The full legacy/TUN/REALITY/new-protocol matrix completed successfully.
The [original report](../2026-09-19-v07/README.md) is preserved unchanged.

| Historical gate | Fixed median | Existing limit |
| --- | ---: | ---: |
| Idle RSS | 4624 KiB | 5120 KiB |
| 100-flow RSS | 7280 KiB | 7500 KiB |
| 1000-flow RSS | 24112 KiB | 25000 KiB |
| Connection close | 2272 ns | 4000 ns |
| TCP latency | 40 µs | 55 µs |
| fd-backed TUN RSS | 6288 KiB | 8192 KiB |
| Process throughput | 523.973 MiB/s | ≥10 MiB/s |
| VLESS encryption throughput | 282.580 MiB/s | ≥241.431 MiB/s |
| IP-on-demand latency | 0.225 ms | ≤1.222 ms |
| XHTTP memory | 19.375 MiB | ≤64 MiB |

The earlier 100/1000-flow RSS failures (8304/31680 KiB) are fixed. Connection
close has substantial per-run noise: final gate samples are 686–3105 ns,
median 2272 ns. Five alternating per-version controls at the gate's 64
connections measure v0.6.1/fix medians of 582/555 ns; at the maximum supported
256 connections, 4280/4808 ns (+12.3%, ranges 980–4579 / 2790–6166 ns). The
4000 ns gate applies to 64 connections, not this larger diagnostic. An attempted
1000-connection control was rejected by the unmodified historical driver before
measurement; it is retained as an invalid invocation and replaced by 256. No
close-path optimization is claimed. Five same-driver TUN echo pairs measure
380/370 ms CPU and 5888/6288 KiB RSS. The historical isolated 130/320 ms pair
does not establish a reproducible 2.5× CPU regression.

The GotaTun patch regenerates the vendor tree from its checksum-pinned upstream
archive with all four patches applied at zero fuzz. Ninety engine tests pass. Selected library groups pass 481 core tests (two
reference-dependent tests covered separately), 169 transport tests and four
WireGuard unit tests. The TUN data-path group passes 173 tests, with its four
reference-dependent Hysteria2/WireGuard cases exercised separately. Native
WireGuard checks include replay/forgery, multi-peer isolation, lifecycle,
network-change, roaming, crash, keepalive and real timed rekey.

One initial parallel Go-Xray PSK runtime test exceeded its 40-second deadline.
It passed five isolated repetitions and five complete parallel WireGuard groups
without reproducing. The timeout and all repetitions remain archived; its cause
is unresolved. Existing test diagnostics now identify the phase on timeout,
without changing deadlines or assertions. All 18 selected-source validation groups pass; the final native and Go-Xray
PSK runtime checks pass as well. Exact commands and durations are retained in
[data/tests.json](data/tests.json). Clippy, formatting and benchmark-collector tests pass.
Native references are Hysteria app/v2.12.2 at
`619a6f856b69fb7ee6a7a379e810e68b84004605` and official wireguard-go 0.0.20250522
at `f333402bd9cbe0f3eeb02507bd14e23d7d639280`, via the pinned test-only adapter.

Raw results retain configurations, byte validation, repetitions, process CPU/RSS
samples, exit status, source patches, binary/script hashes and process cleanup.
Instrumented C/G and the incomplete F experiment are explicitly excluded from
performance summaries. The early unpaced relay is diagnostic only; paced results
use independent 100 Mbit/s serialization in each direction and 25 ms one-way
latency. Relay counters do not count kernel UDP drops.

RSS sampling does not include kernel socket storage and can miss short peaks.
The 7 MiB carrier receive-buffer request applies per enabled address family and
may be clamped/rejected by the OS. Network changes can temporarily retain an old
socket set for the existing three-second drain. Physical-device memory, thermal
behavior and real-network acceptance remain separate from this macOS campaign.

## Reproduction and stored evidence

The exact selected engine/build identity is in [data/build.json](data/build.json).
The clean temporary commit is `61373052dc8b6784162c81650faa6bd92f0604aa`, tree
`de25a855c181144f67c8b4559b6c0caa2ad9d1e2`. The engine SHA-256 is
`a4d94361a40257a38e9dfc88aa5a25f624b6a583b2bfd7676b84fd886baf5aee`.
The final benchmark binary is
`cc028e57522d039194eac50e9eda7f78234315aaae79f0ee329f981e1895a6e1`.

Use the [reproduction guide](../../../v07-performance.md) for frozen builds,
unchanged historical gates, primary matrix and delayed-path commands. Extract
[raw-evidence.tar.gz](raw-evidence.tar.gz) to inspect exact commands, samples,
configs, failures and diagnostics. [artifact-index.json](artifact-index.json)
records every archived file's size and SHA-256. Selected final manifests and
summaries also remain directly readable under [data/](data/).

The archive includes `source/final.patch` against original `7f87ffe`,
`source/intermediate-i.patch` and intermediate build patches; reproduction does
not require the temporary local Git objects. `source/documentation.patch`
contains later report/status updates. Driver and binary hashes distinguish
versions: the historical harness's runtime `source_revision` / Git fields can
identify its working directory, so they must not override the frozen binary
mapping in each manifest. Release-gate runs use clean matching source/binaries.

The source fixes are copied into the development checkout without creating a
commit, replacing the historical report or modifying release thresholds.
