#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_XRAY_CORE_REVISION="5ca6f4b7d4dc20a881d4330e498892697627ec0c"

if [[ -z "${XRAY_CORE_CHECKOUT:-}" ]]; then
  echo "XRAY_CORE_CHECKOUT must point at the pinned Xray-core checkout" >&2
  exit 1
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"

XRAY_CORE_CHECKOUT="$(cd "$XRAY_CORE_CHECKOUT" && pwd -P)"
export XRAY_CORE_CHECKOUT

actual_revision="$(git -C "$XRAY_CORE_CHECKOUT" rev-parse --verify HEAD)"
if [[ "$actual_revision" != "$EXPECTED_XRAY_CORE_REVISION" ]]; then
  echo "Xray-core checkout is $actual_revision; expected $EXPECTED_XRAY_CORE_REVISION" >&2
  exit 1
fi

scheduled_tmp="$(mktemp -d "${TMPDIR:-/tmp}/xray-rust-scheduled-pinned-interop.XXXXXX")"
trap 'rm -rf -- "$scheduled_tmp"' EXIT
xray_core_binary="$scheduled_tmp/xray"

env \
  -u GOFLAGS \
  -u GOEXPERIMENT \
  -u GOTOOLCHAIN \
  GOENV=off \
  GOWORK=off \
  GOTOOLCHAIN=local \
  CGO_ENABLED=0 \
  go -C "$XRAY_CORE_CHECKOUT" build -o "$xray_core_binary" ./main

export XRAY_REALITY_INTEROP_FINGERPRINTS="chrome,hellochrome_133,hellofirefox_148,hellosafari_26_3,helloios_13,hello360_11_0,hellochrome_120_pq,hellofirefox_99"
export XRAY_REALITY_INTEROP_BURST_FINGERPRINTS="hellofirefox_99"
export XRAY_REALITY_INTEROP_BURST_FLOWS="32"
export XRAY_XHTTP_INTEROP_CASES="all"

env \
  -u GOFLAGS \
  -u GOEXPERIMENT \
  -u GOTOOLCHAIN \
  GOENV=off \
  GOWORK=off \
  GOTOOLCHAIN=local \
  CGO_ENABLED=0 \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests \
    -- --ignored --nocapture --test-threads=1

cargo build --locked --release -p xray-cli --bin xray-rust
xray_rust_binary="${CARGO_TARGET_DIR:-target}/release/xray-rust"
if [[ "$xray_rust_binary" != /* ]]; then
  xray_rust_binary="$repository_root/$xray_rust_binary"
fi

engine_args=(
  --xray-rust-bin "$xray_rust_binary"
  --xray-core-bin "$xray_core_binary"
)

for engine in xray-rust xray-core; do
  cargo run --locked --release -p xray-bench -- run \
    --engine "$engine" --workload many-idle-flows \
    "${engine_args[@]}" --no-auto-build --runs 1 --connections 100 --duration-ms 1000 \
    --out-dir "$scheduled_tmp/many-idle-flows-$engine"

  cargo run --locked --release -p xray-bench -- run \
    --engine "$engine" --workload stream-transport --stream-transport xhttp-h2 \
    --traffic held-open --xhttp-mode stream-one "${engine_args[@]}" \
    --no-auto-build --runs 1 --connections 32 --iterations 1 \
    --duration-ms 2000 --settle-ms 500 --sample-interval-ms 100 \
    --payload-size 16384 --run-timeout-ms 120000 \
    --out-dir "$scheduled_tmp/xhttp-held-open-$engine"
done
