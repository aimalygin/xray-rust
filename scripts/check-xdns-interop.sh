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

# What Xray-core's own xdns code does: NewDomain's verdicts, names, queries,
# its server's answers and its client's reading of mutated answers. The run
# is seeded, so it matches the fixture exactly; the full run is larger.
oracle() {
  env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
    go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/xdns-oracle/main.go" "$@"
}
oracle "$TEST_ROOT/vectors.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/xdns/vectors.json" "$TEST_ROOT/vectors.json"
oracle "$TEST_ROOT/vectors-full.json" full

cd "$WORKSPACE_ROOT"
XRAY_XDNS_VECTORS="$TEST_ROOT/vectors-full.json" \
  cargo test --locked -p xray-transport --lib xdns::
cargo test --locked -p xray-transport --lib hysteria::carrier
cargo test --locked -p xray-config --lib parser::xdns
cargo test --locked -p xray-config --test xdns_tests
cargo test --locked -p xray-core-rs --lib outbound::carrier::tests
cargo test --locked -p xray-core-rs --lib outbound::hysteria

# The client against Xray-core's own server, which answers as the domain's
# DNS server: mKCP through UDP and TCP resolvers, masks inside xdns, and
# XHTTP over HTTP/3.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests xdns:: \
    -- --ignored --nocapture --test-threads=1

# Hysteria, alone and around Salamander.
env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-transport --test hysteria_interop_tests xdns:: \
    -- --ignored --nocapture --test-threads=1
