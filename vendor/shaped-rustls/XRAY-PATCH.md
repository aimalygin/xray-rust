# shaped-rustls at 474a31b7: rustls 0.23.46 with the ClientHello shaping API

Source: the `rustls` directory of the ClientHello-shaping fork
[aimalygin/shaped-rustls](https://github.com/aimalygin/shaped-rustls), commit
`474a31b7cb158a681970d048734abc7d7b4d1adc` (branch `xray/rustls-0.23.40`, which
despite its name is based on rustls 0.23.46 since that commit).
Archive: `https://codeload.github.com/aimalygin/shaped-rustls/tar.gz/474a31b7cb158a681970d048734abc7d7b4d1adc`,
SHA-256 `00509c60f2eca32098208f219ee2d9ebd37fc1502062f12c5c09495f7fde3697`.

The vendored crate is that archive's `rustls/Cargo.toml`, `rustls/build.rs`
and `rustls/src`, with the fork's `LICENSE`, `LICENSE-APACHE`, `LICENSE-ISC`
and `LICENSE-MIT` (the crate directory only links to them). `XRAY-PATCH.diff`
reconstructs it from those files with zero fuzz.
`scripts/check-vendored-sources.sh` verifies the archive and the exact
reconstruction, then runs the fork's library tests, in the fork's own
workspace and lockfile, against these sources.

## Changes

`XRAY-PATCH.diff` touches `Cargo.toml` alone; every source file is the fork's.

- The package is named `rustls`, version `0.23.46`, where the fork's manifest
  says `shaped-rustls` `0.23.4600`. `[patch.crates-io]` replaces a package by
  its own name only, and `scripts/check-vendored-advisories.sh` reads the
  upstream name and release from this manifest to audit them.
- The fork's `workspace = true` dependencies take the versions and features
  of the fork's workspace manifest.
- Dev-dependencies, tests, benches, the internal example and the `readme`
  field are removed: they refer to fork workspace files that are not vendored.

## Why it is still vendored

The fork publishes its crate as `shaped-rustls`, so a git or registry
dependency on it cannot stand in for `rustls` under `[patch.crates-io]`, and
tokio-rustls, which this workspace still builds its TLS streams with, depends
on the `rustls` package. Once the workspace no longer needs a third-party
crate between itself and rustls, it can depend on `shaped-rustls` under that
name (`rustls = { package = "shaped-rustls", ... }`, here and in the vendored
quinn crates); this directory, the `[patch.crates-io]` entry and the fork's
part of `scripts/check-vendored-sources.sh` go then.

Until then a move to a newer fork revision is: replace the files named above
from the new archive, regenerate `XRAY-PATCH.diff`, and update the revision
and checksum here, in `scripts/check-vendored-sources.sh` and in the root
`Cargo.toml`.

## What the move from ca91d48c brought

The previous copy was the fork at `ca91d48c` (rustls 0.23.40) with four
security fixes of rustls 0.23.45 and 0.23.46 backported by hand:
RUSTSEC-2026-0285, -0346, -0348 and -0349. The fork has since merged rustls
0.23.46, so those fixes are upstream's own commits now and the
acknowledgements in `scripts/check-vendored-advisories.sh` are gone.
RUSTSEC-2026-0347 (application data after an ECH rejection), which affects
rustls 0.23.44 and 0.23.45 only, is fixed in 0.23.46 as well.

Besides the merge, the fork changed no behaviour of the shaping code: it
cleared Clippy findings, and its tests no longer fail with the `brotli` and
`zlib` features. No ClientHello byte changes: the shaping oracle tests
(`utls_tls_shaping_tests`, `reality_rustls_tests`, `chrome_parrot_tests`,
`reality_clienthello_tests`, `utls_hello_retry_tests`, `shaped_rustls_tests`)
pass unchanged.

Two properties of the fork to keep in mind when reviewing it:

- an unknown extension in a TLS 1.3 certificate entry is ignored, where
  upstream rustls rejects the message, with or without a ClientHello
  customizer. A shaped hello can offer extensions rustls does not implement,
  and a peer may answer one there; Go's `crypto/tls` ignores them too. This
  has been the fork's behaviour since its commit `94f088e2`;
- the fork needs Rust 1.85, because the `aws_lc_rs` feature depends on the
  `shake` crate. This workspace's toolchain is newer.
