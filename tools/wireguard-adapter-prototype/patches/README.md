# GotaTun prototype patch provenance

- Upstream: [mullvad/gotatun v0.9.1](https://github.com/mullvad/gotatun/tree/dab390cdf9dcfb7a6fa85dd8798db92b681ad296),
  exact commit `dab390cdf9dcfb7a6fa85dd8798db92b681ad296`.
- Source archive SHA-256:
  `2a2745851b2989b6d388330b3b9ccfa180ecd12260014b708e01489abae02722`.
- First local patch: [gotatun-mobile-memory.patch](gotatun-mobile-memory.patch),
  authored for xray-rust's isolated mobile adapter probe on 2026-09-08.
- License: MPL-2.0; original source headers and incorporated upstream notices are
  preserved. Added source files carry MPL-2.0 identifiers. The production vendor tree
  retains the complete upstream licenses and notices.
- The first patch makes no Cargo manifest, Cargo.lock, crypto algorithm or reference pin changes.
  The production vendor tree applies this same patch and separately normalizes
  the crate manifest; see [vendor provenance](../../../vendor/gotatun/XRAY-PATCH.md).

The patch adds configurable packet admission, bounded pending queues/source
counters, receiver-index cleanup, immutable bounded device configuration,
suspend/stop reclamation, and 12 tests. It transfers packet reservations across
existing encryption/decryption calls; it does not replace those implementations.

The guarded script verifies the exact archive before applying this patch with
zero fuzz. It runs library tests and real IPv4 UDP interoperability/pressure
recovery against the unchanged Xray-core v26.7.28 reference. Run from the core
repository with Go 1.26.5 on PATH and Rust 1.96.0:

```sh
bash scripts/check-wireguard-adapter-prototype.sh
```

The [adapter contract](../../../docs/v07-wireguard-adapter.md) explains the actual
limits, exclusions and remaining adoption work. Allocation counters describe
packet storage reservations, not a process RSS measurement or a completed audit.

## PSK ownership patch

Apply [gotatun-psk-hygiene.patch](gotatun-psk-hygiene.patch) after the memory patch.
It replaces plain owned PSK arrays with a non-Copy, redacted, zeroizing boxed key
in `Peer`, `PeerMut`, Noise state and inspection snapshots. Constructors and
explicit clones allocate zero-filled owned storage before copying the secret;
ownership moves keep that allocation's address. The two handshake KDF calls now
borrow the key instead of producing a copied optional-array temporary. Replacement
and removal drop the old zeroizing owner. Set/update/get APIs now use the explicit
`PresharedKey` type; device/UAPI conversion and existing tests are adapted.

The patch adds `zeroize = 1.8.2` as a direct dependency of GotaTun using the version
already present in the upstream lockfile. Only that dependency edge is added to
the lockfile. It adds three tests for stable ownership/independent wiping,
redacted peer snapshots and Noise key replacement. Existing matching/mismatching
PSK, one-sided PSK, rekey and peer-update tests remain enabled.

Bounded mobile mode continues to reject UAPI. Its authorized plaintext export
format and broader UAPI key serialization are outside this runtime's secret
lifetime guarantee. Caller JSON/string buffers also remain caller-owned; the
runtime guarantees redaction and cleanup for its decoded key owners, not removal
of every compiler/crypto temporary or memory locking against swap/core dumps.

The shared guard verifies both patches with zero fuzz, compares the vendor tree,
runs all 89 engine tests, and tests PSK TCP/UDP and failed authentication against
Xray-core v26.7.28. Algorithm code and both upstream reference revisions remain
unchanged.
