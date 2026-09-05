#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-provenance.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

download_and_verify() {
  local name="$1"
  local version="$2"
  local expected="$3"
  local archive="$temporary/$name-$version.crate"

  curl --fail --location --silent --show-error \
    --proto '=https' --tlsv1.2 --retry 3 \
    --user-agent 'xray-rust-vendor-provenance/1.0' \
    --output "$archive" \
    "https://static.crates.io/crates/$name/$name-$version.crate"
  echo "$expected  $archive" | sha256sum --check -
  tar -xzf "$archive" -C "$temporary"
}

download_and_verify \
  blake3 1.8.5 \
  0aa83c34e62843d924f905e0f5c866eb1dd6545fc4d719e803d9ba6030371fce
download_and_verify \
  h3-quinn 0.0.10 \
  8b2e732c8d91a74731663ac8479ab505042fbf547b9a207213ab7fbcbfc4f8b4

patch --batch --fuzz=0 -p1 \
  -d "$temporary/blake3-1.8.5" \
  <"$ROOT/vendor/blake3/XRAY-PATCH.diff"
diff -ruN \
  --exclude XRAY-PATCH.diff \
  --exclude XRAY-PATCH.md \
  "$temporary/blake3-1.8.5" \
  "$ROOT/vendor/blake3"

patch --batch --fuzz=0 -p1 \
  -d "$temporary/h3-quinn-0.0.10" \
  <"$ROOT/vendor/h3-quinn/XRAY-PATCH.diff"
for path in Cargo.toml LICENSE README.md src; do
  diff -ruN \
    "$temporary/h3-quinn-0.0.10/$path" \
    "$ROOT/vendor/h3-quinn/$path"
done

echo "verified vendored sources against checksum-pinned crates.io archives"
