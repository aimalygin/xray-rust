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

# What Xray-core's own xicmp code does: Xicmp.Build's verdicts, the echoes
# its marshal writes, x/net/icmp's checksum and ParseMessage. The run is
# seeded, so it matches the fixture exactly.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" run -mod=readonly "$WORKSPACE_ROOT/tools/xicmp-oracle/main.go" \
  "$TEST_ROOT/vectors.json"
cmp "$WORKSPACE_ROOT/tests/fixtures/xicmp/vectors.json" "$TEST_ROOT/vectors.json"

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-transport --lib xicmp::
cargo test --locked -p xray-transport --lib hysteria::carrier
cargo test --locked -p xray-config --lib parser::xicmp
cargo test --locked -p xray-config --test xicmp_tests
cargo test --locked -p xray-core-rs --lib outbound::carrier::tests

# Xray-core's server reads echo requests on raw ICMP sockets, which only
# Linux grants an unprivileged process through a capability.
if [[ "$(uname -s)" != Linux ]]; then
  echo "xicmp: the live checks need Linux, where Xray-core's server gets raw ICMP sockets" >&2
  exit 0
fi
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main

test_binary() {
  cargo test --locked -p "$1" --test "$2" --no-run --message-format=json |
    python3 -c 'import json,sys; print(next(v["executable"] for v in map(json.loads,sys.stdin) if v.get("reason")=="compiler-artifact" and v.get("executable") and "test" in v["target"]["kind"]))'
}
readonly CORE_TESTS="$(test_binary xray-core-rs local_xray_interop_tests)"
readonly HYSTERIA_TESTS="$(test_binary xray-transport hysteria_interop_tests)"

# The client against Xray-core's own server: mKCP with datagram sockets to
# the outbound's address and to two listed ones, with raw sockets, with
# masks inside xicmp, and XHTTP over HTTP/3; Hysteria, alone and around
# Salamander, before and after a rebind.
readonly LIVE='
  [ "${XRAY_XICMP_LIVE-}" = 1 ] || { echo "xicmp: XRAY_XICMP_LIVE did not reach the tests, which would skip" >&2; exit 1; }
  "$CORE_TESTS" xicmp:: --ignored --nocapture --test-threads=1
  env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$XRAY_VLESS_FULL_BINARY" \
    "$HYSTERIA_TESTS" xicmp:: --ignored --nocapture --test-threads=1
'
export CORE_TESTS HYSTERIA_TESTS
export XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT"
# The tests skip without it, so the binaries' other --ignored runs, which go
# without root, pass them by.
export XRAY_XICMP_LIVE=1
if [[ "$(id -u)" -eq 0 ]]; then
  sh -euc "$LIVE"
else
  # As root, for the server's raw sockets, in a network namespace of its
  # own whose ping_group_range also admits the client's datagram sockets.
  # The checkout belongs to another user, whom git then has to trust.
  sudo -n --preserve-env=CORE_TESTS,HYSTERIA_TESTS,XRAY_VLESS_FULL_BINARY,XRAY_CORE_CHECKOUT,XRAY_XICMP_LIVE \
    env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*' \
    unshare --net sh -euc '
      ip link set lo up
      sysctl -q -w net.ipv4.ping_group_range="0 2147483647"
    '"$LIVE"
fi
