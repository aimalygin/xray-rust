# 0.7.0 stable preparation and source boundary

The owner selected stable 0.7.0 in both repositories without a public RC.
Publication follows the complete evidence gate, final CI, canonical SDK builds
and package verification. This document does not claim those later gates have
already completed.

## Measured candidate and retained evidence

The clean measured core is commit `353316687b22c2fabbaf37ab5668dda05a972f46`,
tree `f5aacb1fb5a5bbda9eac83a7330059219ce6b0ce`, package version `0.7.0-rc.1`.
No public RC tag is required or invented for this measured source.

The [immutable evidence snapshot](https://github.com/aimalygin/xray-rust/tree/2f64938035366b5bff53caa41288d4aa753fb79f)
contains `v07-release-evidence.zip`, SHA-256
`b10aa3e1c6c0451f0d52b0ed13b0272d805fb88cbdbebd94f7c7069cb531330b`.
Schema 3 records **accepted-with-exceptions**, not unconditional passage.

- iPhone 17 Pro Max: nine scenario groups; Hysteria2/WireGuard, actual
  cellular/Wi-Fi, lock/wake, cancellation, retained features, legacy transports
  and import. RSS growth 3,407,872 bytes; native thread growth 0.
- Samsung SM-A145F: eleven groups; both FileDescriptor and PacketPump paths,
  Wi-Fi screen-off/wake/reconnect, cancellation, retained/legacy/import checks
  and bounded resource recovery. Maximum observed RSS growth 14,159,872 bytes;
  native thread growth 2. Both fit the original 32 MiB / 8-thread limits.
- Passing bounded campaigns recorded zero fatal and unrecovered errors. All
  historical failed attempts remain included with their original results.
- Four calibrated performance gates passed five samples each. Dated comparison
  reports retain their original commits, binaries, workloads and host-quality
  caveats. Full Hysteria2/WireGuard performance parity is not established.

## Explicit owner decisions

The [canonical decisions](releases/v0.7.0-owner-decisions.json) are included
verbatim and hashed in the evidence archive.

Android cellular handover was not tested because the Samsung has no mobile
Internet. The owner waived exactly that transition on four Android protocol
paths for 0.7. Apple cellular and all other required transitions remain required.

The owner accepted the investigated rare Android WireGuard timeout case as a
0.7 release decision. Direct UDP recorded 1 timeout / 5000 requests; the paired
official WireGuard comparison recorded 0 / 3000 and xray-rust 1 / 3000.
These observations do not prove a cause or statistical equivalence. Original
failures and separately identified test-fixture corrections are retained.
No generic packet-loss allowance or product fix is claimed.

The accepted shared-Mac tolerance remains at most 3% worse non-memory metrics,
with lower RSS as the target. Deferred H2/TUN RSS work, other Hysteria2 deficits
and uncertainty remain in [performance documentation](v07-performance.md) and
the archive's known limitations. This is not a claim of complete parity.

## Enforced stable delta

`scripts/check-v07-stable-promotion.py` pins the measured archive's complete
SHA-256 and commit/tree, requires a clean final HEAD descended from that source,
and compares every tree entry, file mode and blob. It permits only:

- Workspace/package version changes to 0.7.0 in Cargo.toml/Cargo.lock, with
  unchanged external dependency identities and manifest/build settings.
- Only `coreVersion` in the generated configuration contract.
- Explicitly listed release documentation, owner decisions, evidence validators
  and their tests. The CI workflow permits only the exact extra test invocation.
- The scanner correction for nine exact file SHA-256 values in the immutable
  automated evidence index, plus negative controls. Before/after hashes pin
  both the scanner configuration and its tests; broader exclusions are rejected.

After PR #37 merged, whole-history scanning also encountered the separate
evidence branch added after the preceding CI runs. Nine values in
`automated-validation.json` at `e2bb086b270edc1a5437ac61199127c2dd4cb84b`
matched the generic API-key heuristic because their file names contain `key`.
All nine were recomputed from the corresponding CI archive members and are
file digests. The correction permits only those values in that exact index
path for that one rule; other values, paths, and scanner rules remain active.

Runtime, new build files, adapters, ABI, compiler settings, dependencies,
unapproved paths, deletions, symlinks and file-mode changes are rejected.
The output separates the final stable revision from `measuredCandidate`, keeps
`accepted-with-exceptions`, and explicitly sets `newPhysicalDeviceRun: false`.
Schema 2 and older v0.6 validation remain strict; these exceptions do not carry
forward to another stable version.

## Remaining distribution gates

Run complete CI on the final stable source and dispatch `v07-release-evidence.yml`
on that revision using the immutable archive URL and checksum. Revalidate at the
core annotated-tag boundary. The existing core workflow publishes RC source
bundles automatically; the stable source release is finalized separately only
after the stable tag's applicable gates pass.

Pin the mobile SDK to the verified stable core tag/object/commit/tree and source
hashes. Prepare the canonical XCFramework using the locked toolchain, review its
checksum PR, and verify the release AAR/Maven bundle and consumers. Publish the
stable mobile channel and its GitHub Packages mirror; Maven Central follows the
existing protected publication workflow. No placeholder checksum can pass the
mobile release boundary. Long soak, deep sleep, battery and arbitrary WAN
performance are not claimed by these bounded campaigns.
