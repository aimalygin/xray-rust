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
# and reader driven step by step; then what it and the Go library under it
# make of the HTTP storages: S3 URLs and SigV4 headers at a fixed time, S3
# answers, templates, subst and JSON paths, Retry-After dates, regexp,
# net/url resolution and http.Client's redirects. The oracles are test files
# the overlay adds to the package without touching the checkout; their runs
# are deterministic, so fresh ones match the fixtures byte for byte.
cat >"$TEST_ROOT/overlay.json" <<JSON
{"Replace": {"$CHECKOUT/transport/internet/xdrive/xray_rust_oracle_test.go": "$WORKSPACE_ROOT/tools/xdrive-oracle/wal_oracle_test.go", "$CHECKOUT/transport/internet/xdrive/xray_rust_http_oracle_test.go": "$WORKSPACE_ROOT/tools/xdrive-oracle/http_oracle_test.go", "$CHECKOUT/transport/internet/xdrive/xray_rust_drive_server_test.go": "$WORKSPACE_ROOT/tools/xdrive-oracle/drive_server_test.go"}}
JSON
XDRIVE_ORACLE_OUT="$TEST_ROOT/wal-vectors.json" \
  XDRIVE_HTTP_ORACLE_OUT="$TEST_ROOT/http-vectors.json" \
  env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" test -mod=readonly -overlay "$TEST_ROOT/overlay.json" \
  ./transport/internet/xdrive -run '^TestXrayRust(HTTP)?Oracle$' -count=1 >/dev/null
# A fixture that drifts shows how, not only the first byte where.
same_as_fixture() {
  if ! cmp -s "$WORKSPACE_ROOT/tests/fixtures/xdrive/$1" "$TEST_ROOT/$1"; then
    echo "tests/fixtures/xdrive/$1 differs from what the pinned Xray-core derives:" >&2
    diff -u "$WORKSPACE_ROOT/tests/fixtures/xdrive/$1" "$TEST_ROOT/$1" | head -n 80 >&2 || true
    return 1
  fi
}
same_as_fixture wal-vectors.json
same_as_fixture http-vectors.json

cd "$WORKSPACE_ROOT"
cargo test --locked -p xray-proxy --lib go_url
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

# The storage stand-ins: an S3 bucket that checks every SigV4 signature and a
# REST store for a template, each over HTTP and HTTPS, standard library only;
# and Xray-core's own fakeDrive on Google Drive's real paths, over TLS and
# HTTP/3, built from the overlay in the checkout.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C tools/xdrive-oracle/standin build -mod=readonly -o "$TEST_ROOT/xdrive-standin" .
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$CHECKOUT" test -c -mod=readonly -overlay "$TEST_ROOT/overlay.json" \
  -o "$TEST_ROOT/xdrive-drive-server" ./transport/internet/xdrive

# VLESS with encryption and Mux over XDRIVE against Xray-core's own XDRIVE
# server: in a local folder, TCP and UDP of both families, parallel flows,
# X25519 and ML-KEM-768 authentication, small segments; then in the
# stand-in's bucket and REST store, Xray-core over HTTP/1.1 and this client
# over HTTPS and HTTP/2 through the stream's address and port; then in the
# Drive stand-in, both in rings of slots, this client over HTTP/2 and over
# HTTP/3 through a noise mask.
XRAY_VLESS_FULL_BINARY="$TEST_ROOT/xray" XRAY_CORE_CHECKOUT="$CHECKOUT" \
  XDRIVE_STANDIN_BINARY="$TEST_ROOT/xdrive-standin" \
  XDRIVE_DRIVE_SERVER="$TEST_ROOT/xdrive-drive-server" \
  cargo test --locked -p xray-core-rs --test local_xray_interop_tests xdrive:: \
    -- --ignored --nocapture --test-threads=1
