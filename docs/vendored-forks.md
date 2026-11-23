# Forks kept in `vendor/`

The workspace calls APIs that exist only in its own copies of a few
dependencies. Each copy is an upstream release plus a patch, kept in
`vendor/<crate>` with the note `XRAY-PATCH.md` that describes the patch.

A crates.io package cannot depend on a path or on a `[patch.crates-io]`
entry, so before the workspace can be published
([cargo-publishing.md](cargo-publishing.md)) every copy it builds on has to be
a crates.io package itself. Four of them are prepared for that; the QUIC stack
is next.

| Directory | Package | Version | Upstream release | How the workspace takes it |
| --- | --- | --- | --- | --- |
| `vendor/h2` | `xray-h2` | 0.4.2000 | h2 0.4.20 | path and version |
| `vendor/h3` | `xray-h3` | 0.0.800 | h3 0.0.8 | path and version |
| `vendor/smoltcp` | `xray-smoltcp` | 0.14.0 | smoltcp 0.14.0 | path and version |
| `vendor/gotatun` | `xray-gotatun` | 0.9.100 | GotaTun 0.9.1, commit `dab390cd` | path and version |
| `vendor/quinn-proto` | `quinn-proto` | 0.11.19 | the same | `[patch.crates-io]` |
| `vendor/quinn` | `quinn` | 0.11.12 | the same | `[patch.crates-io]` |
| `vendor/h3-quinn` | `h3-quinn` | 0.0.10 | the same | `[patch.crates-io]` |
| `vendor/tokio-rustls` | `tokio-rustls` | 0.26.4 | the same | path, tests and benches only |

None of the four `xray-*` packages is on crates.io yet. Until one is, its
version here can still change without a new release number.

The rustls fork is not in `vendor/`: it is the crates.io package
`shaped-rustls` ([shaped-rustls.md](shaped-rustls.md)).

## How the workspace takes a published fork

```toml
h2 = { package = "xray-h2", path = "vendor/h2", version = "0.4.2000" }
```

The path is what this workspace builds. The version is what a published crate
will depend on: cargo drops the path when it packages a crate and keeps the
package name and the version. Each fork's library keeps upstream's name, so
the code writes `h2::`, `h3::`, `smoltcp::` and `gotatun::` as it would with
upstream.

`vendor/h3-quinn` names `xray-h3` the same way, by the path `../h3`, so that
it and the workspace build one h3.

## Names and versions

A fork is named `xray-<upstream>`. The patch number of its version is
upstream's patch release times 100 plus the fork's own release:

- `xray-h2` 0.4.2000 is h2 0.4.20, fork release 0; a second release on the
  same h2 would be 0.4.2001, and the first one on h2 0.4.21 is 0.4.2100;
- `xray-smoltcp` 0.14.0 is smoltcp 0.14.0, fork release 0; the next release
  on it would be 0.14.1.

`shaped-rustls` follows the same rule. A crates.io version cannot be replaced,
so once a fork is published, any change to its files is a new fork release.

Each manifest keeps upstream's `rust-version`. The forks are built and tested
only with this workspace's toolchain.

## What the package says about itself

A fork is someone else's crate under another name, and its page must not read
as upstream's:

- the description starts with "A fork of" and the upstream release;
- the README opens with a notice: what the crate is a fork of, that it is not
  affiliated with upstream, where to report its bugs, and how to depend on it.
  Upstream's README follows unchanged;
- `repository` is this repository;
- `XRAY-PATCH.md` and, for the crates.io-based copies, `XRAY-PATCH.diff` are
  in the package. Upstream's license files are kept as they are.

For h2, h3 and smoltcp these are hunks of `XRAY-PATCH.diff`, with the root
entry of the copy's `Cargo.lock`. For GotaTun, which is rebuilt from
upstream's commit and four patches,
`tools/wireguard-adapter-prototype/prepare_vendor.py` writes them.

The manifests exclude `Cargo.toml.orig` and `.cargo_vcs_info.json`. Both came
with upstream's archive, cargo writes its own into every package, and it
refuses a source directory that would add files of those names.

## Checks

The supply-chain CI job runs three scripts over `vendor/`:

- `scripts/check-vendored-sources.sh` downloads each upstream archive by
  checksum, applies the patch with zero fuzz and requires the result to equal
  the copy file for file. For a published fork it also requires the version
  to name the archive it verified, so `xray-h2` 0.4.2000 cannot sit on
  anything but h2 0.4.20.
- `scripts/check-vendored-advisories.sh` audits the upstream release under
  each copy against RustSec. Advisories are filed against `h2`, not `xray-h2`,
  so the script reads the upstream name and release out of the fork's:
  `xray-h2` 0.4.2000 is audited as h2 0.4.20.
- `scripts/check-vendored-packages.sh` packages every `xray-*` copy as
  `cargo publish` would and lets cargo build each package from its archive.
  It uploads nothing.

## Publishing a fork

Publishing is the owner's decision for each crate and each version, and it
cannot be undone: a version can be yanked, not replaced or deleted.

From a clean checkout of the commit to publish, with a crates.io token that
`cargo login` stored:

```sh
CARGO_TARGET_DIR="$PWD/target/vendored-package" \
  cargo publish --locked --manifest-path vendor/h2/Cargo.toml
```

`vendor/gotatun` has no `Cargo.lock`, so it is published without `--locked`;
cargo resolves its dependencies and writes the lockfile into the package
only. The target directory is set because each copy is outside the workspace
and would otherwise build into `vendor/<crate>/target`, which the provenance
check reports as untracked files.

The four packages do not depend on one another, so their order is free.
`xray-h3` has to be on crates.io before the fork of h3-quinn that will depend
on it.

After a publication, record the version, the commit and the SHA-256 of the
crate archive here.

## Moving a fork to another upstream release

1. In `scripts/check-vendored-sources.sh`, name the new release and the
   checksum of its archive. For GotaTun the commit and checksum are in
   `scripts/check-wireguard-adapter-prototype.sh`.
2. Unpack the archive, apply `XRAY-PATCH.diff`, and resolve what no longer
   applies. Set the version: the new patch release times 100.
3. Rename the root entry of the copy's lockfile:
   `cargo update --workspace --manifest-path vendor/<crate>/Cargo.toml`.
4. Write the difference from the archive back into `XRAY-PATCH.diff`, and
   update `XRAY-PATCH.md` and the README notice, which name the release.
5. Update the version in the root `Cargo.toml` (in
   `crates/xray-wireguard/Cargo.toml` for GotaTun) and in the table above.
6. Run the three scripts and the workspace's tests.

A change to a fork on the same upstream release is the same procedure from
step 4, with the fork's release raised by one if the current version is
already on crates.io.
