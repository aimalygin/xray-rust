#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-provenance.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

# Include ignored files here: an upstream .gitignore can hide crate files on
# the developer's filesystem even though a clean checkout will omit them.
untracked="$(git -C "$ROOT" ls-files --others -- vendor/h2 vendor/h3 vendor/h3-quinn vendor/quinn vendor/quinn-proto vendor/gotatun vendor/smoltcp vendor/tokio-rustls)"
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
  h3-quinn 0.0.10 \
  8b2e732c8d91a74731663ac8479ab505042fbf547b9a207213ab7fbcbfc4f8b4
download_and_verify \
  quinn-proto 0.11.19 \
  0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe
download_and_verify \
  quinn 0.11.12 \
  4051e23e9185c255a7e33ef59cdbca87a22d359052eecd22fc6b901fb37d9d11
patch --batch --fuzz=0 -p1 \
  -d "$temporary/quinn-0.11.12" \
  <"$ROOT/vendor/quinn/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/quinn-0.11.12" "$ROOT/vendor/quinn"

patch --batch --fuzz=0 -p1 \
  -d "$temporary/h3-quinn-0.0.10" \
  <"$ROOT/vendor/h3-quinn/XRAY-PATCH.diff"
for path in Cargo.toml LICENSE README.md src; do
  diff -ruN \
    "$temporary/h3-quinn-0.0.10/$path" \
    "$ROOT/vendor/h3-quinn/$path"
done

download_and_verify \
  h3 0.0.8 \
  10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be
patch --batch --fuzz=0 -p1 \
  -d "$temporary/h3-0.0.8" \
  <"$ROOT/vendor/h3/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/h3-0.0.8" "$ROOT/vendor/h3"
# The published tests module includes h3-quinn from upstream's repository
# layout, which no release ships; run the crate's other unit tests.
: >"$temporary/h3-0.0.8/src/tests/mod.rs"
cargo test --locked --manifest-path "$temporary/h3-0.0.8/Cargo.toml" --lib

# The rustls fork is the crates.io package `shaped-rustls`, which Cargo.lock
# pins by checksum like any other registry package. The vendored quinn-proto,
# quinn and tokio-rustls name it in place of the `rustls` package their
# published lockfiles pin, so each lockfile below gains the release this
# workspace builds before the crate is tested or checked on it.
shaped_rustls_version="$(awk '
  /^\[\[package\]\]/ { n = "" }
  $1 == "name" { gsub(/"/, "", $3); n = $3 }
  $1 == "version" && n == "shaped-rustls" { gsub(/"/, "", $3); print $3 }
' "$ROOT/Cargo.lock")"
if [[ ! "$shaped_rustls_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Cargo.lock does not name exactly one shaped-rustls release: '$shaped_rustls_version'" >&2
  exit 1
fi

patch --batch --fuzz=0 -p1 \
  -d "$temporary/quinn-proto-0.11.19" \
  <"$ROOT/vendor/quinn-proto/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/quinn-proto-0.11.19" "$ROOT/vendor/quinn-proto"
# Its published lockfile pins the rustls package, and the vendored manifest
# names the fork instead: add that entry, and only what it needs, before the
# locked test.
cargo update --manifest-path "$temporary/quinn-proto-0.11.19/Cargo.toml" --workspace
cargo update --manifest-path "$temporary/quinn-proto-0.11.19/Cargo.toml" \
  -p shaped-rustls --precise "$shaped_rustls_version"
cargo test --locked --manifest-path "$temporary/quinn-proto-0.11.19/Cargo.toml" \
  --no-default-features --features rustls-ring --lib

# The quinn patch calls quinn-proto's patched `set_stream_receive_window`, so
# quinn is tested against the reconstruction above. Its published lockfile
# pins crates.io quinn-proto 0.11.18 and rustls: move the first entry, and
# only what 0.11.19 and the fork need, before the locked test.
quinn_proto_patch="patch.crates-io.quinn-proto.path=\"$temporary/quinn-proto-0.11.19\""
cargo update --config "$quinn_proto_patch" \
  --manifest-path "$temporary/quinn-0.11.12/Cargo.toml" \
  -p quinn-proto --precise 0.11.19
cargo update --config "$quinn_proto_patch" \
  --manifest-path "$temporary/quinn-0.11.12/Cargo.toml" \
  -p shaped-rustls --precise "$shaped_rustls_version"
cargo test --locked --config "$quinn_proto_patch" \
  --manifest-path "$temporary/quinn-0.11.12/Cargo.toml" \
  --no-default-features --features runtime-tokio,rustls-ring --lib

# tokio-rustls serves the TLS of tests and benches only. Its tests directory
# holds a private key and is not vendored; XRAY-PATCH.diff removes the test
# targets with it and points the crate at the fork. Its own unit tests read
# that directory, so they do not run here: the workspace's test suites are
# what exercises this copy.
download_and_verify \
  tokio-rustls 0.26.4 \
  1729aa945f29d91ba541258c8df89027d5792d85a8841fb65e8bf0f4ede4ef61
rm -rf "$temporary/tokio-rustls-0.26.4/tests"
patch --batch --fuzz=0 -p1 \
  -d "$temporary/tokio-rustls-0.26.4" \
  <"$ROOT/vendor/tokio-rustls/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/tokio-rustls-0.26.4" "$ROOT/vendor/tokio-rustls"
cargo update --manifest-path "$temporary/tokio-rustls-0.26.4/Cargo.toml" --workspace
cargo update --manifest-path "$temporary/tokio-rustls-0.26.4/Cargo.toml" \
  -p shaped-rustls --precise "$shaped_rustls_version"
cargo check --locked --manifest-path "$temporary/tokio-rustls-0.26.4/Cargo.toml" \
  --target-dir "$temporary/tokio-rustls-target" --lib

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

# Vendored crates are path dependencies, so Cargo enforces their own lint
# levels instead of capping them as it does for registry crates. cargo-fuzz
# builds them with `--cfg fuzzing`, which otherwise only the release-gate
# fuzz job compiles.
RUSTFLAGS="--cfg fuzzing" cargo check --locked \
  --manifest-path "$ROOT/Cargo.toml" --target-dir "$temporary/fuzzing-target" \
  -p gotatun -p h2 -p h3 -p h3-quinn -p quinn -p quinn-proto -p smoltcp
echo "verified vendored sources against checksum-pinned archives"
