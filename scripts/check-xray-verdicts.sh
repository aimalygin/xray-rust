#!/usr/bin/env bash
set -euo pipefail

# Rechecks the config-verdict corpora that have no interop script of their
# own -- freedom's finalRules, the Mux settings and the FinalMask filter --
# with `xray run -test` of the pinned Xray-core, then runs the tests that hold
# xray-rust's parser to the same verdicts.

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
for corpus in freedom mux filter; do
  python3 scripts/check-config-verdicts.py \
    "$TEST_ROOT/xray" "tests/fixtures/$corpus/config-verdicts.json"
done

cargo test --locked -p xray-config --test freedom_settings_tests --test mux_tests \
  --test finalmask_filter_tests config_verdicts_match_xray_core
