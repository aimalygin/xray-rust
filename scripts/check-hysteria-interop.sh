#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly CHECKOUT="${XRAY_CORE_CHECKOUT:-"$WORKSPACE_ROOT/Xray-core"}"
readonly TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

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

env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main

# How Xray-core's own configuration reads FinalMask noise `exp` packets, and
# what its noise mask sends for them, counters included.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/noise-exp-oracle/main.go" \
  "$TEST_ROOT/exp-vectors.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/noise/exp-vectors.json" "$TEST_ROOT/exp-vectors.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-config --test noise_tests exp_
cargo test --locked -p xray-transport --lib udp_noise::exp_tests
env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-transport --test hysteria_interop_tests -- --ignored --nocapture

env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-core-rs --test hysteria_runtime_tests \
  --test runtime_data_path_tests hysteria_runtime_ -- --ignored --nocapture

env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-core-rs --lib outbound::hysteria::tests -- --include-ignored --nocapture

# FinalMask prelude must reach both QUIC carriers, including both Salamander orders.
env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  XRAY_CORE_CHECKOUT="$CHECKOUT" XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-core-rs --test hysteria_runtime_tests \
  --test local_xray_interop_tests udp_noise_ -- --ignored --nocapture

# Salamander and Gecko outside Hysteria: XHTTP over HTTP/3 against Xray's
# own server under the same mask.
XRAY_CORE_CHECKOUT="$CHECKOUT" XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests salamander:: \
    -- --ignored --nocapture --test-threads=1
