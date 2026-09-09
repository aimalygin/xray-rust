# v0.6.1 stable promotion

The owner authorized stable `0.6.1` releases for both the core and mobile SDK
on 2026-09-09, retaining the tested RC1 implementation. All new builds and
tests run in GitHub Actions. No new local or physical-device campaign is
part of this promotion.

## Source boundary

The measured core is `v0.6.1-rc.1`, annotated tag object
`005804d1f15939eaad6e5f3d91e2875807dcab8e`, commit
`1231add417a4e2e6aa4c9e51c13487d493498a1d`, tree
`2470643a54fd235425a7ce616ac41f22f32d673c`.

The stable source is descended directly from that candidate. Its delta is
limited to the workspace version in `Cargo.toml`, matching workspace-package
versions in `Cargo.lock`, `coreVersion` in `docs/config-contract.json`,
`CHANGELOG.md`, `README.md` and this record. Runtime sources, adapters, ABI,
build scripts, workflows, compiler options and external dependencies retain
their RC1 contents.

The historical `v0.6.0` promotion validator is not a validator for this new
stable revision. The RC1 evidence below keeps its original candidate identity;
it is not relabeled as measurements of the stable metadata commit.

## Retained RC1 verification

- [Full candidate CI](https://github.com/aimalygin/xray-rust/actions/runs/34358510554).
- [Exact-candidate evidence validation](https://github.com/aimalygin/xray-rust/actions/runs/34364249062).
- [RC1 tag CI and source publication](https://github.com/aimalygin/xray-rust/actions/runs/34364388912).
- [Immutable evidence source](https://github.com/aimalygin/xray-rust/tree/d746d492152240382da84a4715e67c0b704b9eee),
  SHA-256 `575aed426aff5e40eaad2f75f0d07bd1127f0edd9e6f9f820dc8807e56b59a4b`.

The bounded device and performance coverage and its exclusions remain as
recorded in [RC1 preparation](https://github.com/aimalygin/xray-rust/pull/29).
No new long-soak, WAN, network-switching or process-death result is claimed.

## Distribution

The core `v0.6.1` source release follows the full automated GitHub Actions
release matrix on its exact stable revision. The existing workflow publishes
RC source bundles automatically; the stable GitHub release is published
after the stable tag's applicable gates pass.

The [mobile SDK 0.6.1](https://github.com/aimalygin/xray-rust-mobile/releases/tag/v0.6.1)
is already immutable, at commit `a8826c4d7e9a45482068bc886cbb20aafcfb8093`.
It retains the measured RC1 core pin. This is the same runtime implementation
as the stable core, with different package-version metadata. Its tag, archive
checksums and core provenance must not be rewritten to claim a different
build. [Mobile release CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/34396082790)
completed successfully; GitHub Packages also contains the stable SDK.
