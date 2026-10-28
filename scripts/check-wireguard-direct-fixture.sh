#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly CHECKOUT="${XRAY_CORE_CHECKOUT:-"$WORKSPACE_ROOT/Xray-core"}"
readonly TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
umask 077

unset GOFLAGS GOEXPERIMENT
export GOENV=off GOWORK=off GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0
python3 "$WORKSPACE_ROOT/scripts/verify-wireguard-reference.py"
python3 - "$WORKSPACE_ROOT" "$CHECKOUT" "$TEST_ROOT" <<'PY'
import importlib.util
from pathlib import Path
import sys

root, checkout, work = map(Path, sys.argv[1:])
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, root / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

load("verification", "verify-oracle-fixtures.py").verify_xray_core_checkout(checkout)
fixture = load("fixture", "run-v07-apple-protocol-fixture.py")
(work / "fixture").mkdir()
fixture.write_fixtures(work / "fixture", "127.0.0.1", 42001, 42002, 42003,
                       protocol="wireguard")
PY
go -C "$CHECKOUT" build -mod=readonly -trimpath -o "$TEST_ROOT/xray" ./main
go -C "$WORKSPACE_ROOT/tools/wireguard-reference" build -mod=readonly -trimpath \
  -o "$TEST_ROOT/wireguard-reference" .
sudo unshare --net python3 "$WORKSPACE_ROOT/scripts/check-wireguard-redirect-reuse.py" \
  --fixture-dir "$TEST_ROOT/fixture" --xray-binary "$TEST_ROOT/xray" \
  --go-binary "$TEST_ROOT/wireguard-reference" --output "$TEST_ROOT/result.json"
