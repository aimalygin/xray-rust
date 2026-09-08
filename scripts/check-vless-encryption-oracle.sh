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
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/oracle" \
  "$WORKSPACE_ROOT/tools/vless-encryption-oracle/main.go"
"$TEST_ROOT/oracle" vectors > "$TEST_ROOT/primitives.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/vless-encryption/primitives.json" "$TEST_ROOT/primitives.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-vless-encryption --features fuzzing --lib
XRAY_VLESS_ENCRYPTION_ORACLE="$TEST_ROOT/oracle" \
  cargo test --locked -p xray-vless-encryption --test go_interop -- --ignored
XRAY_VLESS_ENCRYPTION_ORACLE="$TEST_ROOT/oracle" \
  cargo test --locked -p xray-core-rs --test vless_encryption_interop_tests -- --ignored

# Run the actual pinned Xray process, including its inbound authentication,
# outbound dispatch and a fully local REALITY cover origin.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
XRAY_VLESS_ENCRYPTION_ORACLE="$TEST_ROOT/oracle" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests \
    vless_encryption::full_xray_encrypted_ -- --ignored --nocapture
