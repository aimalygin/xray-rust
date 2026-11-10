#!/usr/bin/env bash
set -euo pipefail

# Builds the pinned Xray-core and holds the ClientHellos it sends for an empty
# fingerprint, `chrome`, `hellochrome_155` and `hellochrome_133` to the uTLS
# fixtures xray-rust's profiles are compared with byte for byte, then runs the
# Rust tests that make that comparison.

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly CHECKOUT="$(cd "${XRAY_CORE_CHECKOUT:-"$WORKSPACE_ROOT/Xray-core"}" && pwd -P)"
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
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main

cd "$WORKSPACE_ROOT"
python3 scripts/check-xray-default-fingerprint.py "$TEST_ROOT/xray" tests/fixtures/reality
cargo test --locked -p xray-transport --test reality_rustls_tests matches_utls_oracle_for_risky
cargo test --locked -p xray-utls
