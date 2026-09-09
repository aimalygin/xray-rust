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
cd "$WORKSPACE_ROOT"
XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-transport --test hysteria_interop_tests -- --ignored --nocapture

XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-core-rs --test hysteria_runtime_tests \
  --test runtime_data_path_tests hysteria_runtime_ -- --ignored --nocapture
