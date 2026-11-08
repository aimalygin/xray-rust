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

spec = importlib.util.spec_from_file_location(
    "oracle_verification", Path(sys.argv[1]) / "scripts/verify-oracle-fixtures.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.verify_xray_core_checkout(Path(sys.argv[2]))
PY

# What Xray-core's own sudoku mask writes, freshly: its encoding draws clue
# sets, orders and padding at random, so only identical tables decode it.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/sudoku-oracle/main.go" \
  "$TEST_ROOT/vectors.json"

cd "$WORKSPACE_ROOT"
XRAY_SUDOKU_VECTORS="$TEST_ROOT/vectors.json" \
  cargo test --locked -p xray-transport --lib sudoku::
cargo test --locked -p xray-transport --lib kcp::mask
cargo test --locked -p xray-config --test sudoku_tests
cargo test --locked -p xray-core-rs --lib outbound::carrier::tests

# The client against Xray-core's own servers: every TCP carrier and mKCP.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests sudoku \
    -- --ignored --nocapture --test-threads=1
