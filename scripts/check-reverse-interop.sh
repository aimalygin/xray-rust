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

# What Xray-core's own mux, reverse and VLESS code write on a reverse proxy:
# the portal's frames with its client's addresses, the bridge's answers, the
# portal's control messages and the request that opens a tunnel. Nothing is
# random, so a fresh run matches the fixture exactly.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/reverse-oracle/main.go" \
  "$TEST_ROOT/vectors.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/reverse/vectors.json" "$TEST_ROOT/vectors.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-proxy --lib reverse::
cargo test --locked -p xray-proxy --lib mux::
cargo test --locked -p xray-config --test vless_reverse_tests
cargo test --locked -p xray-core-rs --lib reverse::
cargo test --locked -p xray-core-rs --test reverse_bridge_tests

# Every recorded verdict of the config corpus, rechecked with `xray run -test`.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
python3 scripts/check-reverse-config-verdicts.py \
  "$TEST_ROOT/xray" tests/fixtures/reverse/config-verdicts.json

# The bridge against Xray-core's own portal: TCP and UDP services behind it
# over raw, VLESS encryption, TLS with Vision, WebSocket, gRPC and XHTTP;
# freedom refusing what its final rules do not allow; a wrong UUID opening
# nothing; a second tunnel once the portal drains the first; and dialerProxy
# chains whose last freedom refuses sessions, and a tunnel, until it allows
# the next hop, while Mux and gRPC links are left alone as Xray-core leaves
# them.
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests reverse:: \
    -- --ignored --nocapture --test-threads=1
