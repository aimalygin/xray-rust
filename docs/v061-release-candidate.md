# v0.6.1-rc.1 release candidate

Preparation began on 2026-09-09 from `codex/xhttp-h2-window-fix`, commit
`9f7b8348603d1a2d51a200cbcf4a136ad496efda`. The release preparation branch is
`codex/v0.6.1-rc.1`. The intended core and mobile SDK version is `0.6.1-rc.1`.
This record describes preparation, not completed publication.

## Scope

- XHTTP/H2 uses a 4 MiB stream receive window by default, with the optional
  bounded `h2StreamReceiveWindow` setting. Connection credit remains 16 MiB.
- Stalled TUN TCP downloads no longer block neighboring data or control
  events. Per-flow prefetch is bounded to 256 KiB, with cancellation and
  DNS/FIN ordering preserved.
- The Swift/Kotlin adapters and public C ABI are unchanged. Dependencies
  retain their existing versions and source identities.

The [window audit](transport-window-audit.md),
[TUN/iPhone measurements](issue28-tun-validation.md), and
[Rust/Go comparison](issue28-client-comparison.md) document the implementation
and its limits. Larger H2 stream credit permits more per-stream buffering;
the TUN prefetch bound is not a process-memory ceiling. The controlled
comparison does not establish WAN/CDN performance or parity with Go on
uncapped paths.

## Publication gates

Freeze the release metadata and generated configuration contract before
collecting evidence. Record the resulting clean commit and tree in the
evidence archive, outside the frozen candidate checkout.

1. Run the complete manually dispatched CI release gates on the frozen
   candidate, plus the local regression and v0.6 feature benchmarks.
2. Collect fresh physical Apple and Android reports and assemble the
   exact-candidate archive described in [v0.6 release evidence](v06-release-evidence.md).
   Earlier v0.6.0 campaigns and issue #28 experiments retain their original
   provenance; they are not evidence for this new commit and tree.
3. Validate and publish the evidence ZIP, then dispatch `v0.6 release
   evidence` on the frozen candidate with its immutable URL and SHA-256.
4. After those gates pass, create and push the annotated core tag
   `v0.6.1-rc.1`. The tag workflow publishes the source prerelease.
5. Pin the mobile SDK to that exact core tag object, commit, tree and file
   hashes. Prepare the canonical Apple archive, merge its generated checksum
   lock, then tag the mobile SDK according to its two-phase release process.
6. Verify the public source bundle, XCFramework and standalone AAR and run
   clean public-consumer checks. RC publication is GitHub-only and does not
   publish a Maven Central or GitHub Packages coordinate.

Long device soak campaigns remain outside the current checklist. The bounded
device reports must still satisfy the existing exact-source validator; the
version-only v0.6.0 stable-promotion exception does not apply to this runtime
change.
