#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-provenance.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

# Include ignored files here: an upstream .gitignore can hide crate files on
# the developer's filesystem even though a clean checkout will omit them.
untracked="$(git -C "$ROOT" ls-files --others -- vendor/blake3 vendor/h2 vendor/h3-quinn vendor/quinn vendor/quinn-proto vendor/gotatun vendor/smoltcp)"
if [[ -n "$untracked" ]]; then
  echo 'vendored source files are absent from the Git index:' >&2
  printf '%s\n' "$untracked" >&2
  exit 1
fi

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
download_and_verify \
  quinn-proto 0.11.16 \
  2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560
download_and_verify \
  quinn 0.11.9 \
  b9e20a958963c291dc322d98411f541009df2ced7b5a4f2bd52337638cfccf20
patch --batch --fuzz=0 -p1 \
  -d "$temporary/quinn-0.11.9" \
  <"$ROOT/vendor/quinn/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/quinn-0.11.9" "$ROOT/vendor/quinn"

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

patch --batch --fuzz=0 -p1 \
  -d "$temporary/quinn-proto-0.11.16" \
  <"$ROOT/vendor/quinn-proto/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/quinn-proto-0.11.16" "$ROOT/vendor/quinn-proto"
cargo test --locked --manifest-path "$temporary/quinn-proto-0.11.16/Cargo.toml" \
  --no-default-features --features rustls-ring --lib

# The quinn patch calls quinn-proto's patched `set_stream_receive_window`, so
# quinn is tested against the reconstruction above. Its published lockfile
# pins crates.io quinn-proto 0.11.13: move that entry, and only what 0.11.16
# needs, before the locked test.
quinn_proto_patch="patch.crates-io.quinn-proto.path=\"$temporary/quinn-proto-0.11.16\""
cargo update --config "$quinn_proto_patch" \
  --manifest-path "$temporary/quinn-0.11.9/Cargo.toml" \
  -p quinn-proto --precise 0.11.16
cargo test --locked --config "$quinn_proto_patch" \
  --manifest-path "$temporary/quinn-0.11.9/Cargo.toml" \
  --no-default-features --features runtime-tokio,rustls-ring --lib

download_and_verify \
  smoltcp 0.14.0 \
  b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f
patch --batch --fuzz=0 -p1 \
  -d "$temporary/smoltcp-0.14.0" \
  <"$ROOT/vendor/smoltcp/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/smoltcp-0.14.0" "$ROOT/vendor/smoltcp"
cargo test --locked --manifest-path "$temporary/smoltcp-0.14.0/Cargo.toml" \
  --no-default-features --features std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-tcp-reno,socket-udp \
  --lib

download_and_verify \
  h2 0.4.20 \
  7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118
patch --batch --fuzz=0 -p1 \
  -d "$temporary/h2-0.4.20" \
  <"$ROOT/vendor/h2/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/h2-0.4.20" "$ROOT/vendor/h2"
# The published crate omits the HPACK fixture files its fixture tests read.
cargo test --locked --manifest-path "$temporary/h2-0.4.20/Cargo.toml" \
  --lib -- --skip hpack::test::fixture

bash "$ROOT/scripts/check-wireguard-adapter-prototype.sh" --verify-vendor-only
echo "verified vendored sources against checksum-pinned archives"
