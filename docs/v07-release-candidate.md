# v0.7.0-rc.1 preparation

Preparation started on 2026-09-22 in `codex/v0.7.0-rc.1`, from core `7f87ffe`
plus the accepted performance/runtime work. The measured development runtime
is `b9577f874b3f102880ae078038855803d85f5d04`; its dated evidence is retained.
This document records preparation, not a published RC or completed final acceptance.

## Frozen scope

- Hysteria2 and standard WireGuard client outbounds, TCP/UDP, routed DNS,
  protected sockets and bounded mobile lifecycle handling.
- Matching Swift/Kotlin profile import, bootstrap, capabilities and additive C
  ABI 1.7. Compatibility remains pinned to Xray-core v26.7.28, with independent
  native Hysteria/WireGuard interoperability gates.
- Accepted TUN/WireGuard/QUIC/XHTTP performance corrections only. Both private
  arena-reuse experiments are excluded. H2/TUN RSS work is deferred by the owner;
  remaining Hysteria2 gaps and uncertainty stay documented in
  [performance evidence](v07-performance.md).

## Preparation and acceptance sequence

1. Commit matching `0.7.0-rc.1` metadata, generated contract, the versioned evidence
   gate and supported configuration boundaries. Record the exact clean commit/tree
   outside the checkout before collecting new evidence.
2. Run full CI on that revision: Rust tests/Clippy/format, native and Xray
   interoperability, existing VLESS/XHTTP paths, ABI/mobile builds, vendor/source
   verification, fuzz/hardening and dependency/secret checks. Run the historical
   benchmark gates with their existing rules; retain preceding comparisons.
3. Collect bounded physical Apple and Android scenarios on the final candidate,
   including both Android adapters. Use the [v0.7 evidence contract](v07-release-evidence.md).
   Prior iPhone development reports precede the newest runtime changes; no fresh
   Android v0.7 or final-candidate acceptance is claimed by this preparation.
4. Assemble/review the evidence ZIP, publish its immutable input and pass the
   exact-candidate evidence workflow before creating the core public RC tag.
5. Mobile initially pins the exact candidate commit for source builds/tests.
   After the core tag passes, replace the commit pin with its verified tag object,
   commit/tree and file hashes. Prepare the canonical Apple archive, merge its
   checksum lock, then publish matching mobile XCFramework/AAR assets on GitHub.
6. Verify clean public SDK consumers and real-application import, connect,
   disconnect, reconnect and network recovery. Stable `0.7.0` follows RC acceptance;
   it is not part of an automatic tag/version-only promotion in this preparation.

Long soak tests remain outside the checklist. No device report, public tag,
canonical Apple checksum or successful CI run is fabricated as a placeholder.
Release readiness is recorded with the actual CI/evidence identifiers as they
become available; remaining physical or application checks block that stage.

For repeated device campaigns, keep the test VPS connection instructions in a
durable private local record: endpoint or SSH alias, user, existing key reference,
reserved test port and service restoration procedure. Keep that record separate
from temporary protocol credentials and SSH helper scripts. Campaign cleanup
removes temporary credentials and services, while retaining the connection
instructions for the next run; neither credentials nor private connection details
belong in published evidence.
