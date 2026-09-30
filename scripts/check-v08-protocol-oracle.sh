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

env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/v08-protocol-oracle/main.go" "$WORKSPACE_ROOT/tools/v08-protocol-oracle/ss2022.go" "$WORKSPACE_ROOT/tools/v08-protocol-oracle/vmess.go" "$WORKSPACE_ROOT/tools/v08-protocol-oracle/mux.go" \
  > "$TEST_ROOT/protocol-primitives.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/v08/protocol-primitives.json" "$TEST_ROOT/protocol-primitives.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-proxy --test trojan_wire_tests
cargo test --locked -p xray-proxy --lib shadowsocks2022
cargo test --locked -p xray-proxy --lib vmess
cargo test --locked -p xray-proxy --lib mux
