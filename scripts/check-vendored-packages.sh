#!/usr/bin/env bash
# Packages each fork in vendor/ that is published under a name of its own
# (`xray-<upstream>`), as `cargo publish` would, and lets cargo build the
# package from its archive.
#
# The workspace takes these crates by path, so nothing else notices a
# manifest crates.io would refuse or an archive without a file the build
# needs. Each crate is packaged from a copy that is a git repository of its
# own: cargo then picks the files as it does in this repository, upstream's
# dot-files included, writes nothing into vendor/, and is not stopped by a
# file a developer has not committed yet. The copy has no commit, so its
# archive lacks one file of a published one: `.cargo_vcs_info.json`, cargo's
# record of the commit.
#
# Nothing is uploaded. Publishing is described in docs/vendored-forks.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-packages.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

packaged=0
for manifest in "$ROOT"/vendor/*/Cargo.toml; do
  read -r name version < <(
    awk '
      /^\[package\]/ { in_package = 1; next }
      /^\[/ { in_package = 0 }
      in_package && $1 == "name" { gsub(/"/, "", $3); name = $3 }
      in_package && $1 == "version" { gsub(/"/, "", $3); version = $3 }
      END { print name, version }
    ' "$manifest"
  )
  if [[ -z "$name" || -z "$version" ]]; then
    echo "cannot read the package name and version of $manifest" >&2
    exit 1
  fi
  # The other copies keep upstream's package name and are not published.
  [[ "$name" == xray-* ]] || continue

  directory="${manifest%/Cargo.toml}"
  copy="$temporary/${directory##*/}"
  cp -R "$directory" "$copy"
  # Every file, as in this repository's index: an upstream .gitignore names
  # files that are tracked here.
  git -C "$copy" init --quiet
  git -C "$copy" add --all --force
  # A copy with a lockfile is packaged with the one it ships; cargo writes
  # the lockfile of the others into the archive only.
  locked=()
  if [[ -f "$copy/Cargo.lock" ]]; then
    locked=(--locked)
  fi
  cargo package --allow-dirty ${locked[@]+"${locked[@]}"} \
    --manifest-path "$copy/Cargo.toml" --target-dir "$temporary/target"

  archive="$temporary/target/package/$name-$version.crate"
  # The disclosure of what the fork changes has to travel with the package.
  if ! tar -tzf "$archive" | grep -qx "$name-$version/XRAY-PATCH.md"; then
    echo "$name $version was packaged without XRAY-PATCH.md" >&2
    exit 1
  fi
  echo "packaged ${directory#"$ROOT"/} as $name $version"
  packaged=$((packaged + 1))
done

if [[ "$packaged" == 0 ]]; then
  echo 'vendor/ holds no package named xray-*' >&2
  exit 1
fi
echo "packaged and built $packaged vendored forks"
