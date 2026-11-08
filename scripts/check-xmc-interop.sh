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

# The RSA public key Xray-core's xmc mask derives from each password. The
# derivation is deterministic, so a fresh run matches the fixture exactly.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/xmc-oracle/main.go" \
  "$TEST_ROOT/vectors.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/xmc/vectors.json" "$TEST_ROOT/vectors.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-transport --lib xmc::
cargo test --locked -p xray-proxy --lib vless::udp
cargo test --locked -p xray-config --test xmc_tests
cargo test --locked -p xray-core-rs --lib outbound::carrier::tests

# The client against Xray-core's own server on every TCP carrier, with TCP
# and UDP through each, and strangers refused.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests xmc \
    -- --ignored --nocapture --test-threads=1
