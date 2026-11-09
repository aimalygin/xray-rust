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

# What Xray-core's own Hysteria dialer sends with its default ChromeParrot
# QUIC stack: the first flight and its retransmission, and every crypto/rand
# read behind them. The oracle is a test file the overlay adds to the
# checkout's hysteria package without touching it; testing/cryptotest makes
# the run deterministic, so it matches the fixture exactly.
cat >"$TEST_ROOT/overlay.json" <<JSON
{"Replace": {"$CHECKOUT/transport/internet/hysteria/xray_rust_chrome_parrot_oracle_test.go": "$WORKSPACE_ROOT/tools/chrome-parrot-oracle/initial_oracle_test.go"}}
JSON
CHROME_PARROT_ORACLE_OUT="$TEST_ROOT/initials.json" \
  env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" test -mod=readonly -overlay "$TEST_ROOT/overlay.json" \
  ./transport/internet/hysteria -run '^TestXrayRustChromeParrotOracle$' -count=1 >/dev/null
cmp "$WORKSPACE_ROOT/tests/fixtures/chrome-parrot/initials.json" "$TEST_ROOT/initials.json"

# The same draws through the vendored quinn-proto give the same transport
# parameters and encrypted datagrams, and through the ClientHello customizer
# the same ClientHello but for the key shares' key material.
cd "$WORKSPACE_ROOT"
XRAY_CHROME_PARROT_INITIALS="$TEST_ROOT/initials.json" \
  cargo test --locked -p xray-transport --test chrome_parrot_tests
XRAY_CHROME_PARROT_INITIALS="$TEST_ROOT/initials.json" \
  cargo test --locked -p xray-transport --lib chrome_parrot::
cargo test --locked -p xray-config --test chrome_parrot_tests
cargo test --locked -p xray-core-rs --lib -- chrome_parrot quic_never_parrots_chrome
cargo test --locked -p xray-core-rs --test core_lifecycle_tests chrome_parrot

# Every recorded verdict of the disableChromeParrot corpus, rechecked with
# `xray run -test`.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" build -mod=readonly -o "$TEST_ROOT/xray" ./main
python3 scripts/check-config-verdicts.py \
  "$TEST_ROOT/xray" tests/fixtures/chrome-parrot/config-verdicts.json

# Against Xray-core's own servers, with ChromeParrot and without: Hysteria
# TCP and fragmented UDP, Hysteria under Salamander, and XHTTP H3 through the
# core. A relay records the client's datagrams and the first flight on the
# wire is checked for ChromeParrot's shape.
env -u NATIVE_HYSTERIA_BINARY XRAY_HYSTERIA_BINARY="$TEST_ROOT/xray" \
  cargo test --locked -p xray-transport --test hysteria_interop_tests chrome_parrot \
    -- --ignored --nocapture
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests xhttp_h3_chrome_parrot \
    -- --ignored --nocapture --test-threads=1
