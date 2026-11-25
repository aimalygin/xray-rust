# Forks kept in `vendor/`

The workspace calls APIs that exist only in its own copies of a few
dependencies. Each copy is an upstream release plus a patch, kept in
`vendor/<crate>` with the note `XRAY-PATCH.md` that describes the patch.

A crates.io package cannot depend on a path or on a `[patch.crates-io]`
entry, so before the workspace can be published
([cargo-publishing.md](cargo-publishing.md)) every copy it builds on has to be
a crates.io package itself. All seven are, and the root manifest has no
`[patch.crates-io]` section.

| Directory | Package | Version | Upstream release | On crates.io |
| --- | --- | --- | --- | --- |
| `vendor/h2` | `xray-h2` | 0.4.2000 | h2 0.4.20 | 2026-11-23, from `06ad5e23` |
| `vendor/h3` | `xray-h3` | 0.0.800 | h3 0.0.8 | 2026-11-23, from `06ad5e23` |
| `vendor/h3-quinn` | `xray-h3-quinn` | 0.0.1000 | h3-quinn 0.0.10 | 2026-11-23, from `06ad5e23` |
| `vendor/quinn-proto` | `xray-quinn-proto` | 0.11.1900 | quinn-proto 0.11.19 | 2026-11-23, from `06ad5e23` |
| `vendor/quinn` | `xray-quinn` | 0.11.1200 | quinn 0.11.12 | 2026-11-23, from `06ad5e23` |
| `vendor/smoltcp` | `xray-smoltcp` | 0.14.1 | smoltcp 0.14.0 | 0.14.0 on 2026-11-23, from `06ad5e23`; 0.14.1 waits for its upload |
| `vendor/gotatun` | `xray-gotatun` | 0.9.100 | GotaTun 0.9.1, commit `dab390cd` | 2026-11-23, from `06ad5e23` |

The last column is the day of the upload and the commit of this repository it
was made from, `06ad5e23e60da92c7c5e1b12a40baa71de5a05fa` for all seven; each
archive records its commit in `.cargo_vcs_info.json`. The SHA-256 of each
archive is in `scripts/check-vendored-published.sh`, which holds the copy in
`vendor/` to it.

Two more forks are not in this table. The rustls fork is not in `vendor/`:
it is the crates.io package `shaped-rustls`
([shaped-rustls.md](shaped-rustls.md)). `vendor/tokio-rustls` is
tokio-rustls 0.26.4 built on `shaped-rustls`; only tests and benches use it,
by path, and it is not published.

## How the workspace takes a fork

```toml
h2 = { package = "xray-h2", path = "vendor/h2", version = "0.4.2000" }
```

The path is what this workspace builds. The version is what a published crate
will depend on: cargo drops the path when it packages a crate and keeps the
package name and the version. Each fork's library keeps upstream's name, so
the code writes `h2::`, `h3::`, `h3_quinn::`, `quinn::`, `quinn_proto::`,
`smoltcp::` and `gotatun::` as it would with upstream.

The forks name one another the same way, so that the build holds one h3, one
quinn and one quinn-proto:

- `vendor/quinn` names `xray-quinn-proto` by the path `../quinn-proto`;
- `vendor/h3-quinn` names `xray-h3` by `../h3` and `xray-quinn` by `../quinn`.

`xray-quinn-proto` and `xray-quinn` are built on `shaped-rustls`, as the
workspace is.

## Names and versions

A fork is named `xray-<upstream>`. The patch number of its version is
upstream's patch release times 100 plus the fork's own release:

- `xray-h2` 0.4.2000 is h2 0.4.20, fork release 0; a second release on the
  same h2 would be 0.4.2001, and the first one on h2 0.4.21 is 0.4.2100;
- `xray-smoltcp` 0.14.0 is smoltcp 0.14.0, fork release 0; the next release
  on it would be 0.14.1.

`shaped-rustls` follows the same rule.

A crates.io version cannot be replaced, so a change to the files of a
published fork is a new fork release, and its version is raised in the same
change. `Cargo.lock` is the exception: nothing that depends on a library reads
its lockfile, and a copy's lockfile may be brought up to date under the same
version.

Each manifest keeps upstream's `rust-version`. The forks are built and tested
only with this workspace's toolchain.

## Features a fork does not have

A feature that cannot be built on the forks' dependencies is removed with its
code, so that a published package has no feature that fails to compile:

- `xray-quinn-proto` and `xray-quinn` have no `platform-verifier`, which is
  in upstream quinn's default features. It needs rustls-platform-verifier,
  whose verifier is built for upstream's rustls and not for `shaped-rustls`.
- `xray-h3-quinn` has no `datagram`. It needs h3-datagram, which is built on
  upstream's h3 and not on `xray-h3`.

The workspace enabled neither.

## What the package says about itself

A fork is someone else's crate under another name, and its page must not read
as upstream's:

- the description starts with "A fork of" and the upstream release;
- the README opens with a notice: what the crate is a fork of, that it is not
  affiliated with upstream, where to report its bugs, and how to depend on it.
  Upstream's README follows unchanged; quinn-proto ships none, so there the
  notice is the README;
- `repository` is this repository;
- `XRAY-PATCH.md` and, for the crates.io-based copies, `XRAY-PATCH.diff` are
  in the package. Upstream's license files are kept as they are.

For the copies taken from crates.io these are hunks of `XRAY-PATCH.diff`,
with the copy's `Cargo.lock` where it has one. For GotaTun, which is rebuilt
from upstream's commit and four patches,
`tools/wireguard-adapter-prototype/prepare_vendor.py` writes them.

The manifests exclude `Cargo.toml.orig` and `.cargo_vcs_info.json` where the
copy has them. Both came with upstream's archive, cargo writes its own into
every package, and it refuses a source directory that would add files of
those names.

## Checks

The supply-chain CI job runs four scripts over `vendor/`:

- `scripts/check-vendored-sources.sh` downloads each upstream archive by
  checksum, applies the patch with zero fuzz and requires the result to equal
  the copy file for file. It also requires each fork's version to name the
  archive it verified, so `xray-h2` 0.4.2000 cannot sit on anything but h2
  0.4.20, and runs the unit tests of h2, h3, quinn, quinn-proto and smoltcp
  with the copies' lockfiles.
- `scripts/check-vendored-advisories.sh` audits the upstream release under
  each copy against RustSec. Advisories are filed against `h2`, not `xray-h2`,
  so the script reads the upstream name and release out of the fork's:
  `xray-h2` 0.4.2000 is audited as h2 0.4.20.
- `scripts/check-vendored-packages.sh` packages the seven as `cargo publish`
  would and lets cargo build each package from its archive. It packages them
  together, in dependency order, each finished archive served to the next
  from a local registry, because `xray-quinn` cannot be built from its
  archive while the version of `xray-quinn-proto` it names is missing from
  crates.io. It uploads nothing.
- `scripts/check-vendored-published.sh` holds each copy to the crates.io
  package of its name. It does two things:
  - It compares. The workspace builds the forks from `vendor/`, and a crate
    published from it takes them from crates.io; the two are the same code
    only while a copy is what was uploaded under the version in its manifest.
    That version must not be yanked, and its archive, downloaded and checked
    against the SHA-256 recorded in the script, has to equal the copy file for
    file. Four files at the package root are cargo's: the published
    `Cargo.toml.orig` has to equal the copy's `Cargo.toml`, and
    `.cargo_vcs_info.json`, the rewritten `Cargo.toml` and `Cargo.lock` are
    left out.
  - It keeps the list of releases. The table in the script names every fork
    release made from this repository, and the crates.io index has to list
    exactly those, with the recorded checksums. A release on crates.io that
    the table does not name fails the check: `xray-h2 = "0.4.2000"` accepts a
    later 0.4.x, so an upload nobody recorded would reach whoever depends on
    the fork.

  A version in a manifest that is not on crates.io is a fork release that
  waits for its upload. The script reports it, with a warning on the CI run,
  and does not fail, so the change that raises a version can be merged before
  the upload.

## Publishing a fork

Publishing is the owner's decision for each crate and each version, and it
cannot be undone: a version can be yanked, not replaced or deleted.

From a clean checkout of the commit to publish, with a crates.io token that
`cargo login` stored:

```sh
CARGO_TARGET_DIR="$PWD/target/vendored-package" \
  cargo publish --locked --manifest-path vendor/h2/Cargo.toml
```

`vendor/gotatun` and `vendor/h3-quinn` have no `Cargo.lock`, so they are
published without `--locked`; cargo resolves their dependencies and writes
the lockfile into the package only. The target directory is set because each
copy is outside the workspace and would otherwise build into
`vendor/<crate>/target`, which the provenance check reports as untracked
files.

Cargo builds a package before it uploads it, with the package's dependencies
taken from crates.io, so the order matters where one fork depends on another:

1. `xray-quinn-proto`, then `xray-quinn`;
2. `xray-h3`;
3. `xray-h3-quinn`, after `xray-quinn` and `xray-h3`.

`xray-h2`, `xray-smoltcp` and `xray-gotatun` depend on none of the others. A
dry run of `xray-quinn` or `xray-h3-quinn` fails while the version of a fork
it depends on is not uploaded; the packaging check is what covers them before
that.

An upload has to be recorded at once: from the upload until its record is
merged, `check-vendored-published.sh` fails on the release it does not know,
for every pull request. After a publication:

1. Run `scripts/check-vendored-published.sh`. It fails on the new release and
   prints the SHA-256 the crates.io index lists for it.
2. Compare that with the archive cargo uploaded, which it leaves under
   `target/vendored-package/package/`:

   ```sh
   find target/vendored-package/package -name 'xray-h2-0.4.2000.crate' \
     -exec sha256sum {} +
   ```

3. Add the release to the table in the script, with that SHA-256, and to the
   table at the top of this document. The script then compares the published
   archive with the copy. A line in the script's table stays when the copy
   moves on to a later release.

## Moving a fork to another upstream release

1. In `scripts/check-vendored-sources.sh`, name the new release and the
   checksum of its archive. For GotaTun the commit and checksum are in
   `scripts/check-wireguard-adapter-prototype.sh`.
2. Unpack the archive, apply `XRAY-PATCH.diff`, and resolve what no longer
   applies. Set the version: the new patch release times 100.
3. Bring the copy's lockfile in line with its manifest:
   `cargo update --workspace --manifest-path vendor/<crate>/Cargo.toml`.
4. Write the difference from the archive back into `XRAY-PATCH.diff`, and
   update `XRAY-PATCH.md` and the README notice, which name the release.
5. Update the version where the fork is named: the root `Cargo.toml`
   (`crates/xray-wireguard/Cargo.toml` for GotaTun), the manifests of the
   forks that depend on it, and the table above. A fork whose manifest
   changes this way gets a release of its own.
6. Run the four scripts and the workspace's tests.
7. Once the change is merged, publish the new releases and record them, as
   above. Until then `check-vendored-published.sh` reports them as waiting.

A change to a fork on the same upstream release is the same procedure from
step 3, with the fork's release raised by one.
