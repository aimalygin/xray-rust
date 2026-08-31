#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_XRAY_CORE_REVISION="5ca6f4b7d4dc20a881d4330e498892697627ec0c"

if [[ -z "${XRAY_CORE_CHECKOUT:-}" ]]; then
  echo "XRAY_CORE_CHECKOUT must point at the pinned Xray-core checkout" >&2
  exit 1
fi

XRAY_CORE_CHECKOUT="$(cd "$XRAY_CORE_CHECKOUT" && pwd -P)"
export XRAY_CORE_CHECKOUT

actual_revision="$(git -C "$XRAY_CORE_CHECKOUT" rev-parse --verify HEAD)"
if [[ "$actual_revision" != "$EXPECTED_XRAY_CORE_REVISION" ]]; then
  echo "Xray-core checkout is $actual_revision; expected $EXPECTED_XRAY_CORE_REVISION" >&2
  exit 1
fi

echo "RC interop Xray-core revision: $actual_revision"
go version
rustc --version

rc_interop_tmp="$(mktemp -d "${TMPDIR:-/tmp}/xray-rust-rc-interop.XXXXXX")"
trap 'rm -rf -- "$rc_interop_tmp"' EXIT
xray_core_binary="$rc_interop_tmp/xray"

env \
  -u GOFLAGS \
  -u GOEXPERIMENT \
  -u GOTOOLCHAIN \
  GOENV=off \
  GOWORK=off \
  CGO_ENABLED=0 \
  go -C "$XRAY_CORE_CHECKOUT" build -o "$xray_core_binary" ./main

# Keep the tag gate representative but bounded: classic and PQ REALITY,
# reduced burst concurrency, and an XHTTP slice spanning all modes plus
# H1/H2/H3. The ignored suite still exercises every supported stream family.
export XRAY_REALITY_INTEROP_FINGERPRINTS="chrome,hellochrome_120_pq"
export XRAY_REALITY_INTEROP_BURST_FINGERPRINTS="chrome"
export XRAY_REALITY_INTEROP_BURST_FLOWS="8"
export XRAY_XHTTP_INTEROP_CASES="h1-none-packet-up,h1-tls-stream-up,h2-tls-stream-one,h2-reality-packet-up,h3-tls-stream-up"

env -u XRAY_CORE_EXPECTED_REVISION \
  cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests \
  -- \
  --ignored \
  --nocapture \
  --test-threads=1

cargo build --locked --release -p xray-cli --bin xray-rust
xray_rust_binary="${CARGO_TARGET_DIR:-target}/release/xray-rust"

# The process-level harness runs the same bounded UDP workload through the
# Rust core and the exact Xray-core binary. Together these cover VLESS UDP and
# mux.cool XUDP without pretending that throughput samples are benchmarks.
for workload in udp-vless udp-xudp; do
  cargo run --locked --release -p xray-bench -- \
    compare \
    --workload "$workload" \
    --xray-rust-bin "$xray_rust_binary" \
    --xray-core-bin "$xray_core_binary" \
    --no-auto-build \
    --runs 1 \
    --connections 1 \
    --iterations 16 \
    --payload-size 256 \
    --out-dir "$rc_interop_tmp/$workload"
done

# DNS outbound has no compatible external process boundary in the current
# harness. Make its end-to-end TUN/SOCKS/HTTP policy slice an explicit RC gate
# while the Go semantic oracle remains covered by migration fixtures/tests.
cargo test --locked -p xray-core-rs \
  --test runtime_data_path_tests \
  dns_outbound \
  -- \
  --nocapture \
  --test-threads=1
