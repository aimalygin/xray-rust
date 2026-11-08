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

# Xray-core's own BBR sender over simulated paths: every call it received and
# a digest of its whole state after each congestion event. The run is
# deterministic, so the fresh trace must equal the fixture, and the port must
# replay it to the same state at every step.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/bbr-oracle/main.go" \
  "$TEST_ROOT/trace.json"

cd "$WORKSPACE_ROOT"
XRAY_BBR_TRACE="$TEST_ROOT/trace.json" \
  cargo test --locked -p xray-transport --lib quic_congestion::
cargo test --locked -p xray-config --test quic_params_tests --test hysteria_tests
cargo test --locked -p xray-core-rs --lib outbound::hysteria::tests
cargo test --locked -p xray-transport --test stream_xhttp_h3_tests \
  each_congestion_choice_runs_its_controller_after_the_handshake

# Each profile against Xray-core's own servers: Hysteria, where the dialer
# installs it after authentication, and XHTTP H3 through the core.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-transport --test hysteria_interop_tests bbr_profiles \
    -- --ignored --nocapture
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests xhttp_h3_bbr_profiles \
    -- --ignored --nocapture --test-threads=1
