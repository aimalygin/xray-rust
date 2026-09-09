#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly CHECKOUT="${XRAY_CORE_CHECKOUT:-"$WORKSPACE_ROOT/Xray-core"}"
readonly TEST_ROOT="$(mktemp -d)"
readonly GOTATUN_REV=dab390cdf9dcfb7a6fa85dd8798db92b681ad296
readonly GOTATUN_SHA=2a2745851b2989b6d388330b3b9ccfa180ecd12260014b708e01489abae02722
trap 'rm -rf "$TEST_ROOT"' EXIT


if [[ -n "${GOTATUN_ARCHIVE:-}" ]]; then
  cp "$GOTATUN_ARCHIVE" "$TEST_ROOT/gotatun.tar.gz"
else
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --retry 3 \
    "https://codeload.github.com/mullvad/gotatun/tar.gz/$GOTATUN_REV" \
    --output "$TEST_ROOT/gotatun.tar.gz"
fi
printf '%s  %s\n' "$GOTATUN_SHA" "$TEST_ROOT/gotatun.tar.gz" | shasum -a 256 --check -
tar -xzf "$TEST_ROOT/gotatun.tar.gz" -C "$TEST_ROOT"
readonly SOURCE="$TEST_ROOT/gotatun-$GOTATUN_REV"
patch --directory "$SOURCE" -p1 --fuzz=0 --batch --forward \
  < "$WORKSPACE_ROOT/tools/wireguard-adapter-prototype/patches/gotatun-mobile-memory.patch"
patch --directory "$SOURCE" -p1 --fuzz=0 --batch --forward \
  < "$WORKSPACE_ROOT/tools/wireguard-adapter-prototype/patches/gotatun-psk-hygiene.patch"
python3 "$WORKSPACE_ROOT/tools/wireguard-adapter-prototype/prepare_vendor.py" \
  "$SOURCE" "$TEST_ROOT/vendor"
diff -ruN --exclude XRAY-PATCH.md "$TEST_ROOT/vendor" "$WORKSPACE_ROOT/vendor/gotatun"
if [[ "${1:-}" == --verify-vendor-only ]]; then
  echo "verified vendored GotaTun against checksum-pinned source, patch and manifest normalization"
  exit 0
fi
if [[ $# != 0 ]]; then
  echo "usage: $0 [--verify-vendor-only]" >&2
  exit 2
fi
python3 - "$WORKSPACE_ROOT" "$CHECKOUT" <<'PY'
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("oracle_verification", Path(sys.argv[1]) / "scripts/verify-oracle-fixtures.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.verify_xray_core_checkout(Path(sys.argv[2]))
PY

mkdir -p "$SOURCE/gotatun/examples"
cp "$WORKSPACE_ROOT/tools/wireguard-adapter-prototype/main.rs" \
   "$SOURCE/gotatun/examples/xray_adapter_probe.rs"

env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main

cd "$SOURCE"
readonly BUILD_TARGET="${WIREGUARD_PROBE_TARGET_DIR:-"$WORKSPACE_ROOT/target/wireguard-adapter-prototype"}"
readonly HOST_TRIPLE="$(rustc +1.96.0 -vV | sed -n 's/^host: //p')"
readonly RUNNER_ENV="CARGO_TARGET_$(printf '%s' "$HOST_TRIPLE" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
# Upstream's cargo runner uses sudo for real TUN examples. This injected IP
# adapter needs no privileges. Override the runner for library tests, and
# build and execute the probe directly. Test/build on the current host.
env -u CARGO_BUILD_TARGET "$RUNNER_ENV=env" CARGO_TARGET_DIR="$BUILD_TARGET" \
  cargo +1.96.0 test --locked -p gotatun --no-default-features \
  --features ring,device --lib
env -u CARGO_BUILD_TARGET CARGO_TARGET_DIR="$BUILD_TARGET" \
  cargo +1.96.0 build --locked -p gotatun --no-default-features \
  --features ring,device --example xray_adapter_probe
XRAY_WIREGUARD_BINARY="$TEST_ROOT/xray" "$BUILD_TARGET/debug/examples/xray_adapter_probe"

cd "$WORKSPACE_ROOT"
XRAY_WIREGUARD_BINARY="$TEST_ROOT/xray" \
  cargo +1.96.0 test --locked -p xray-wireguard -- --include-ignored --nocapture
XRAY_WIREGUARD_BINARY="$TEST_ROOT/xray" \
  cargo +1.96.0 test --locked -p xray-core-rs --test wireguard_runtime_tests \
  --test runtime_data_path_tests wireguard_runtime_ -- --ignored --nocapture
