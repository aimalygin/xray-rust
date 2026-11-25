#!/usr/bin/env bash
# Holds each fork in vendor/ that is published under a name of its own
# (`xray-<upstream>`) to the crates.io package of that name.
#
# The workspace builds these forks from vendor/, by path. A crate published
# from the workspace takes them from crates.io, by version. The two builds are
# the same code only while a copy is what was uploaded under the version its
# manifest names. A crates.io version cannot be replaced, so a change to a
# published copy has to come with a new fork release; this script fails when
# it does not.
#
# It also fails on a release it does not know. The table below is the list of
# the releases made from this repository, and for each fork the crates.io
# index has to list exactly those, with the recorded checksums: a requirement
# such as `xray-h2 = "0.4.2000"` accepts a later 0.4.x, so an upload nobody
# recorded would reach whoever depends on the fork.
#
# For the version in a copy's manifest:
#
# - recorded: it must not be yanked. The archive is downloaded, checked
#   against the recorded checksum and compared with the copy, file for file;
# - not recorded, which after the rule above means not on crates.io: the fork
#   release is new and waits for its upload. That is reported and is not a
#   failure, so that the change which raises a version can be merged before
#   the upload it precedes.
#
# Four files at the root of a package are cargo's and are left out of the
# comparison of the trees:
#
# - `.cargo_vcs_info.json` and `Cargo.toml.orig`: cargo writes its own. The
#   copies taken from crates.io still hold upstream's, which their manifests
#   exclude from the package. The published `Cargo.toml.orig` is the manifest
#   the package was made from, so it has to equal the copy's `Cargo.toml`;
# - `Cargo.toml`: cargo's rewrite of that manifest, without the `path` of a
#   dependency on another fork. It follows from `Cargo.toml.orig`;
# - `Cargo.lock`: cargo adds registry sources and checksums, and writes the
#   whole file for a copy that keeps none. Nothing that depends on a library
#   reads its lockfile.
#
# Every other file has to be in both and equal. Uploading a fork and recording
# it here are described in docs/vendored-forks.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-published.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

# Package, version and SHA-256 of the crate archive: one line for every fork
# release on crates.io, the ones the copies have moved on from included.
published='
xray-gotatun      0.9.100    fb11358b0aac5c3c7ecfe3473b8726ff9df0f22dc94015aeba95089d85c4f5da
xray-h2           0.4.2000   4e75d77c0b94312d27ad422687771ee3724f24785bbc0761a65b82c95799088d
xray-h3           0.0.800    3b887266ea1a0267622118c7ed3ca0a19f4514e90939026f49da2bbab5393fc0
xray-h3-quinn     0.0.1000   6fe202ccf3a931a7c9ac8cc41df30a64c61533bc3cdf619fe27917ee45f4c556
xray-quinn        0.11.1200  fdaab5b088caebdf4ca3bd26496238fa5f15221041dcc431f38132f685d72676
xray-quinn-proto  0.11.1900  9990bffafe7600ffdac6f264ae71b1afbd704a4e778c2a84440abce7d0ec8683
xray-smoltcp      0.14.0     dae857ff47fec9de345794a15cb1b646c998b9cc1833dc4d8b1b0e2def14d70f
xray-smoltcp      0.14.1     f17fda9dc881c59fbd37dd37ebe41ec54f593ddc069639307bf61ff9718b6d9b
'

cargo_files=(.cargo_vcs_info.json Cargo.toml.orig Cargo.toml Cargo.lock)

recorded_checksum() {
  awk -v name="$1" -v version="$2" \
    '$1 == name && $2 == version { print $3 }' <<<"$published"
}

# Prints the HTTP status; the body goes to the file named first.
fetch() {
  local output="$1"
  local url="$2"

  curl --location --silent --show-error \
    --proto '=https' --tlsv1.2 --retry 3 \
    --user-agent 'xray-rust-vendor-provenance/1.0' \
    --output "$output" --write-out '%{http_code}' \
    "$url"
}

checked=0
waiting=0

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
  copy="${manifest%/Cargo.toml}"

  # The sparse index keeps a crate at <first two letters>/<next two>/<name>,
  # one JSON object on a line for each version. Every name here has more than
  # three letters.
  index="$temporary/$name.index"
  status="$(fetch "$index" "https://index.crates.io/${name:0:2}/${name:2:2}/$name")"
  case "$status" in
    200) ;;
    # No crate of that name: nothing is published.
    404) : >"$index" ;;
    *)
      echo "the crates.io index answered $status for $name" >&2
      exit 1
      ;;
  esac

  # Every release crates.io lists has to be one recorded here.
  yanked=no
  while IFS= read -r record || [[ -n "$record" ]]; do
    [[ -n "$record" ]] || continue
    listed_version="$(sed -n 's/.*"vers":"\([^"]*\)".*/\1/p' <<<"$record")"
    listed_checksum="$(sed -n 's/.*"cksum":"\([0-9a-f]\{64\}\)".*/\1/p' <<<"$record")"
    if [[ -z "$listed_version" || -z "$listed_checksum" ]]; then
      echo "cannot read a record of $name in the crates.io index" >&2
      exit 1
    fi
    recorded="$(recorded_checksum "$name" "$listed_version")"
    if [[ -z "$recorded" ]]; then
      echo "crates.io holds $name $listed_version (SHA-256 $listed_checksum), which is not recorded in ${BASH_SOURCE[0]##*/}" >&2
      echo "Record the upload if it was made from this repository (docs/vendored-forks.md). If it was not, the fork has a release this repository does not know." >&2
      exit 1
    fi
    if [[ "$recorded" != "$listed_checksum" ]]; then
      echo "$name $listed_version: the crates.io index names SHA-256 $listed_checksum, the record here $recorded" >&2
      exit 1
    fi
    if [[ "$listed_version" == "$version" ]] && grep -qF '"yanked":true' <<<"$record"; then
      yanked=yes
    fi
  done <"$index"

  # And every release recorded here has to be on crates.io.
  while read -r recorded_name recorded_version _; do
    [[ "$recorded_name" == "$name" ]] || continue
    if ! grep -qF "\"vers\":\"$recorded_version\"" "$index"; then
      echo "$name $recorded_version is recorded as published, and the crates.io index does not list it" >&2
      exit 1
    fi
  done <<<"$published"

  recorded="$(recorded_checksum "$name" "$version")"
  if [[ -z "$recorded" ]]; then
    echo "$name $version is not on crates.io: vendor/${copy##*/} waits for its upload"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
      echo "::warning title=Fork release waits for its upload::$name $version is in vendor/${copy##*/} and not on crates.io"
    fi
    waiting=$((waiting + 1))
    continue
  fi
  if [[ "$yanked" == yes ]]; then
    echo "$name $version is yanked on crates.io" >&2
    exit 1
  fi

  archive="$temporary/$name-$version.crate"
  status="$(fetch "$archive" "https://static.crates.io/crates/$name/$name-$version.crate")"
  if [[ "$status" != 200 ]]; then
    echo "crates.io answered $status for the archive of $name $version" >&2
    exit 1
  fi
  echo "$recorded  $archive" | sha256sum --check -

  mkdir "$temporary/published" "$temporary/vendored"
  tar -xzf "$archive" -C "$temporary/published"
  package="$temporary/published/$name-$version"
  if [[ ! -d "$package" ]]; then
    echo "the archive of $name $version does not unpack into $name-$version" >&2
    exit 1
  fi

  if ! diff -u "$copy/Cargo.toml" "$package/Cargo.toml.orig"; then
    echo "vendor/${copy##*/}/Cargo.toml is not the manifest $name $version was published from" >&2
    echo "A published version cannot be replaced: raise the fork's release (docs/vendored-forks.md)." >&2
    exit 1
  fi

  cp -R "$copy" "$temporary/vendored/$name-$version"
  for file in "${cargo_files[@]}"; do
    rm -f "$package/$file" "$temporary/vendored/$name-$version/$file"
  done
  if ! (cd "$temporary" && diff -ru "published/$name-$version" "vendored/$name-$version"); then
    echo "vendor/${copy##*/} is not what $name $version holds on crates.io" >&2
    echo "A published version cannot be replaced: raise the fork's release (docs/vendored-forks.md)." >&2
    exit 1
  fi
  rm -rf "$temporary/published" "$temporary/vendored"

  echo "vendor/${copy##*/} equals $name $version on crates.io"
  checked=$((checked + 1))
done

if [[ "$checked" == 0 && "$waiting" == 0 ]]; then
  echo 'vendor/ holds no package named xray-*' >&2
  exit 1
fi
echo "held $checked vendored forks to their crates.io releases; $waiting wait for an upload"
