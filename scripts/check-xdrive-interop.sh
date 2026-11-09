#!/usr/bin/env bash
set -euo pipefail

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

# What Xray-core's own XDRIVE code derives, names and stores: its tuning,
# object names, the local storage's name resolution, and its segment writer
# and reader driven step by step. The oracle is a test file the overlay adds
# to the package without touching the checkout; its runs are deterministic,
# so a fresh one matches the fixture byte for byte.
cat >"$TEST_ROOT/overlay.json" <<JSON
{"Replace": {"$CHECKOUT/transport/internet/xdrive/xray_rust_oracle_test.go": "$WORKSPACE_ROOT/tools/xdrive-oracle/wal_oracle_test.go"}}
JSON
XDRIVE_ORACLE_OUT="$TEST_ROOT/wal-vectors.json" \
  env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" test -mod=readonly -overlay "$TEST_ROOT/overlay.json" \
  ./transport/internet/xdrive -run '^TestXrayRustOracle$' -count=1 >/dev/null
cmp "$WORKSPACE_ROOT/tests/fixtures/xdrive/wal-vectors.json" "$TEST_ROOT/wal-vectors.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-transport --lib xdrive::
cargo test --locked -p xray-config --lib parser::xdrive
cargo test --locked -p xray-config --test xdrive_tests
cargo test --locked -p xray-core-rs --lib outbound::xdrive
cargo test --locked -p xray-core-rs --test core_lifecycle_tests xdrive

# Every recorded verdict of the config corpus, rechecked with `xray run -test`.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
python3 scripts/check-config-verdicts.py \
  "$TEST_ROOT/xray" tests/fixtures/xdrive/config-verdicts.json

# VLESS with encryption and Mux over XDRIVE against Xray-core's own XDRIVE
# server, the two meeting in a local folder: TCP and UDP of both families,
# parallel flows, X25519 and ML-KEM-768 authentication, small segments.
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests xdrive:: \
    -- --ignored --nocapture --test-threads=1
