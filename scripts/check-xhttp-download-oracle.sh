#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly CHECKOUT="${XRAY_CORE_CHECKOUT:-"$WORKSPACE_ROOT/Xray-core"}"

# Reuse the full-commit and clean-source guard used by the wire oracles.
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

# Import the checked-out module itself, with its locked dependencies. Never
# resolve an oracle against moving main or an unrelated global Go workspace.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/xhttp-download-oracle/main.go" "$WORKSPACE_ROOT/tools/xhttp-download-oracle/bridge.go" \
  "$WORKSPACE_ROOT/tests/fixtures/xhttp-download/config.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-config --test xhttp_download_tests

readonly TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/download-oracle" \
  "$WORKSPACE_ROOT/tools/xhttp-download-oracle/main.go" "$WORKSPACE_ROOT/tools/xhttp-download-oracle/bridge.go"
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/encryption-oracle" \
  "$WORKSPACE_ROOT/tools/vless-encryption-oracle/main.go"
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
XRAY_DOWNLOAD_ORACLE="$TEST_ROOT/download-oracle" XRAY_VLESS_ENCRYPTION_ORACLE="$TEST_ROOT/encryption-oracle" \
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests \
    xhttp_download::full_xray_download_carrier_matrix -- --ignored --nocapture
