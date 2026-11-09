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

# What Xray-core's own connectip package writes and reads: capsules, the
# datagrams composeDatagram builds, its ICMP Packet Too Big and which
# incoming packets it admits. The oracle is a test file the overlay adds to
# the package without touching the checkout. The run is seeded, so it
# matches the fixture exactly; the full run is ten times larger.
cat >"$TEST_ROOT/overlay.json" <<JSON
{"Replace": {"$CHECKOUT/transport/internet/masque/connectip/xray_rust_oracle_test.go": "$WORKSPACE_ROOT/tools/masque-oracle/connectip_oracle_test.go"}}
JSON
oracle() {
  MASQUE_ORACLE_OUT="$1" MASQUE_ORACLE_FULL="$2" \
    env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
    go -C "$CHECKOUT" test -mod=readonly -overlay "$TEST_ROOT/overlay.json" \
    ./transport/internet/masque/connectip -run '^TestXrayRustOracle$' -count=1 >/dev/null
}
oracle "$TEST_ROOT/vectors.json" 0
cmp "$WORKSPACE_ROOT/tests/fixtures/masque/connectip-vectors.json" "$TEST_ROOT/vectors.json"
oracle "$TEST_ROOT/vectors-full.json" 1

# What Xray-core's own HTTP/2 client writes for a tunnel up to its request:
# its SETTINGS, the connection window and the header block, byte for byte.
cat >"$TEST_ROOT/overlay-http2.json" <<JSON
{"Replace": {"$CHECKOUT/transport/internet/masque/xray_rust_http2_oracle_test.go": "$WORKSPACE_ROOT/tools/masque-oracle/http2_oracle_test.go"}}
JSON
MASQUE_HTTP2_ORACLE_OUT="$TEST_ROOT/http2-vectors.json" \
  env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" test -mod=readonly -overlay "$TEST_ROOT/overlay-http2.json" \
  ./transport/internet/masque -run '^TestXrayRustHTTP2Oracle$' -count=1 >/dev/null
cmp "$WORKSPACE_ROOT/tests/fixtures/masque/http2-request-vectors.json" "$TEST_ROOT/http2-vectors.json"

cd "$WORKSPACE_ROOT"
XRAY_MASQUE_VECTORS="$TEST_ROOT/vectors-full.json" \
  cargo test --locked -p xray-transport --lib masque::
cargo test --locked -p xray-wireguard --lib netstack
cargo test --locked -p xray-config --lib parser::masque
cargo test --locked -p xray-config --test masque_tests
cargo test --locked -p xray-core-rs --lib outbound::masque

# Every recorded verdict of the config corpus, rechecked with `xray run -test`.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
python3 scripts/check-masque-config-verdicts.py \
  "$TEST_ROOT/xray" tests/fixtures/masque/config-verdicts.json

# The client against Xray-core's own MASQUE server, over HTTP/3 and HTTP/2:
# TCP and UDP of both families from the SOCKS inbound, TCP from the HTTP
# inbound, names resolved through the tunnel, a uTLS fingerprint, a refused
# password, and TCP and UDP from the TUN.
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests masque:: \
    -- --ignored --nocapture --test-threads=1
XRAY_CLIENT_PROTOCOL_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-core-rs --test runtime_data_path_tests masque_tun \
    -- --ignored --nocapture
