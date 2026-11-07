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

# What Xray-core's own header-custom TCP client and server send each other
# for each case, recorded over a pipe.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/header-custom-oracle/main.go" \
  "$TEST_ROOT/tcp-vectors.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/header-custom/tcp-vectors.json" "$TEST_ROOT/tcp-vectors.json"

# The UDP prefix and standalone exchanges, recorded as individual datagrams.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/header-custom-udp-oracle/main.go" \
  "$TEST_ROOT/udp-vectors.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/header-custom/udp-vectors.json" "$TEST_ROOT/udp-vectors.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-config --test header_custom_tests
cargo test --locked -p xray-transport --lib header_custom
cargo test --locked -p xray-transport --lib kcp::
cargo test --locked -p xray-transport --lib hysteria::carrier
cargo test --locked -p xray-transport --test header_custom_tests
cargo test --locked -p xray-core-rs --lib outbound::carrier::tests

# The client against Xray-core's own header-custom server, on each TCP carrier.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests header_custom:: \
    -- --ignored --nocapture --test-threads=1

XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests kcp_header_custom_udp \
    -- --ignored --nocapture --test-threads=1

# The QUIC carriers against Xray-core's Hysteria and XHTTP H3 servers.
env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-transport --test hysteria_interop_tests header_custom:: \
    -- --ignored --nocapture --test-threads=1
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests header_custom_udp_xhttp_h3 \
    -- --ignored --nocapture --test-threads=1
