#!/usr/bin/env bash
# Packages the forks in vendor/ that are published under names of their own
# (`xray-<upstream>`), as `cargo publish` would, and lets cargo build each
# package from its archive.
#
# The workspace takes these crates by path, so nothing else notices a
# manifest crates.io would refuse or an archive without a file the build
# needs.
#
# Some forks depend on others: xray-quinn on xray-quinn-proto, xray-h3-quinn
# on xray-h3 and xray-quinn. A package cannot be built from its archive while
# what it depends on is missing from crates.io, which is the case before a
# first upload and after every change of a version. So the copies are
# packaged together, as the members of a throwaway workspace: cargo takes
# them in dependency order and serves each finished archive to the next from
# a local registry, as `cargo publish --workspace` does before it uploads.
#
# That workspace is a git repository of its own, so cargo picks the files as
# it does in this repository, upstream's dot-files included, writes nothing
# into vendor/, and is not stopped by a file a developer has not committed
# yet. It has no commit, so each archive lacks one file of a published one:
# `.cargo_vcs_info.json`, cargo's record of the commit. Dependencies are
# resolved afresh there; the copies' own lockfiles are what
# check-vendored-sources.sh tests with.
#
# Nothing is uploaded. Publishing is described in docs/vendored-forks.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-packages.XXXXXX")"

workspace="$temporary/workspace"
mkdir "$workspace"
members=()
packages=()

# Cargo unpacks what it takes from the local registry into its own cache,
# under a directory named after that registry's path, which is new on every
# run. Remove the ones this run adds: those that hold nothing but the
# packages built here.
registry_sources="${CARGO_HOME:-$HOME/.cargo}/registry/src"
unpacked_before="$(ls -d "$registry_sources"/-* 2>/dev/null || true)"
clean_up() {
  rm -rf "$temporary"
  local directory entry
  for directory in "$registry_sources"/-*; do
    [[ -d "$directory" ]] || continue
    grep -qxF "$directory" <<<"$unpacked_before" && continue
    for entry in "$directory"/* "$directory"/.[!.]*; do
      [[ -e "$entry" ]] || continue
      [[ " ${packages[*]-} " == *" ${entry##*/} "* ]] || continue 2
    done
    rm -rf "$directory"
  done
}
trap clean_up EXIT

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

  # Under its own directory name: the copies name one another by `../<name>`.
  directory="${manifest%/Cargo.toml}"
  cp -R "$directory" "$workspace/${directory##*/}"
  members+=("${directory##*/}")
  packages+=("$name-$version")
done

if [[ "${#members[@]}" == 0 ]]; then
  echo 'vendor/ holds no package named xray-*' >&2
  exit 1
fi

{
  printf '[workspace]\nresolver = "2"\nmembers = [\n'
  printf '    "%s",\n' "${members[@]}"
  printf ']\n'
} >"$workspace/Cargo.toml"
# Every file, as in this repository's index: an upstream .gitignore names
# files that are tracked here.
git -C "$workspace" init --quiet
git -C "$workspace" add --all --force

cargo package --workspace --allow-dirty \
  --manifest-path "$workspace/Cargo.toml" --target-dir "$temporary/target"

for package in "${packages[@]}"; do
  archive="$temporary/target/package/$package.crate"
  if [[ ! -f "$archive" ]]; then
    echo "cargo wrote no archive for $package" >&2
    exit 1
  fi
  # The disclosure of what the fork changes has to travel with the package.
  # The listing is read whole first: `grep -q` leaves at its first match, GNU
  # tar then fails on the closed pipe, and pipefail would report that as no
  # match.
  listing="$(tar -tzf "$archive")"
  if ! grep -qxF "$package/XRAY-PATCH.md" <<<"$listing"; then
    echo "$package was packaged without XRAY-PATCH.md" >&2
    exit 1
  fi
  echo "packaged $package"
done
echo "packaged and built ${#packages[@]} vendored forks"
