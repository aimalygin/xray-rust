# 0.7.0 evidence scope and known limitations

The four fresh calibrated release budgets were measured on clean core
353316687b22c2fabbaf37ab5668dda05a972f46 (tree f5aacb1fb5a5bbda9eac83a7330059219ce6b0ce),
with five samples per metric. They passed their previously frozen thresholds.
They are not a new paired 0.6.1 comparison or proof of external protocol parity.
The raw data and toolchain/build hashes, including Go 1.24.0, are retained.
The historical v0.5 budget attempt affected by concurrent build load is retained
alongside its unchanged successful repeat in the nested comparisons archive.

Historical Hysteria2/WireGuard comparisons keep their measured source and binary
identities (including b9577f8 and Go 1.26.5); no result is relabeled as a stable
0.7.0 measurement. Full parity remains unestablished. The target is lower sampled
client RSS and no more than 3% worse other performance metrics on this shared Mac.
H2/TUN upload RSS investigation was deferred by the owner. Other recorded
Hysteria2 deficits and uncertainty remain visible, not converted into passes.
The current split-session memory gate does not resolve the H2/TUN RSS issue.
The larger bounded WireGuard session occupancy has not been compared for memory
against external clients.

Physical iPhone 17 Pro Max and Samsung SM-A145F retained, legacy, import,
protocol, cancellation and bounded recovery checks passed on measured core
3533166. iPhone cellular/Wi-Fi handover and 30-second lock/wake passed.
Both Android FileDescriptor and PacketPump protocol paths passed Wi-Fi,
30-second screen-off/wake, restart and fresh-flow recovery. Android cellular
handover was NOT TESTED: the Samsung has no mobile Internet, and the owner
explicitly waived this transition for 0.7. Historical failed attempts remain
in the logs. Screen-off Dozing is not deep sleep; fresh-flow recovery does not
claim seamless migration of an established flow. Local diagnostic Xcode builds
are distinct from the canonical locked CI distribution builds.

The investigated rare Android WireGuard timeout case is closed as a 0.7 release
blocker by explicit owner decision. This is not a root-cause finding or a claim
of a product fix. Direct UDP had 1 timeout / 5000 requests; the paired official
WireGuard comparison had 0 / 3000, and xray-rust had 1 / 3000. Different loss
positions and finite sample sizes do not establish statistical equivalence or
exclude a client defect. A separately diagnosed redirect fixture association bug
was corrected; that does not prove the causes of the original two timeouts.
Diagnostic builds keep their own identities, separate from the measured release
candidate. This acceptance is scoped to the recorded case, not general packet
loss or reliability regressions. See the hashed release decisions and original
analyses in protocol-comparisons.tar.gz.

The archive result is accepted-with-exceptions. Stable source validation must
separately prove that runtime, dependencies, ABI and build inputs are unchanged
from the measured candidate. No new stable-version physical campaign, long
soak, battery, kernel WireGuard or arbitrary WAN performance result is claimed.
