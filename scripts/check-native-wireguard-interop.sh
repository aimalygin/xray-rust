#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly MODULE="$WORKSPACE_ROOT/tools/wireguard-reference"
readonly TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

unset GOFLAGS GOEXPERIMENT
export GOENV=off GOWORK=off GOTOOLCHAIN=go1.26.5 CGO_ENABLED=0
python3 "$WORKSPACE_ROOT/scripts/verify-wireguard-reference.py"
go -C "$MODULE" build -mod=readonly -trimpath -o "$TEST_ROOT/wireguard-reference" .
go -C "$MODULE" mod verify
python3 "$WORKSPACE_ROOT/scripts/verify-wireguard-reference.py"
go -C "$MODULE" test -mod=readonly ./...

cd "$WORKSPACE_ROOT"
env -u XRAY_WIREGUARD_BINARY NATIVE_WIREGUARD_BINARY="$TEST_ROOT/wireguard-reference" \
  cargo test --locked -p xray-wireguard --test interop --test multi_peer_tests \
  --test native_lifecycle --test network_change \
  -- --include-ignored --nocapture
env -u XRAY_WIREGUARD_BINARY NATIVE_WIREGUARD_BINARY="$TEST_ROOT/wireguard-reference" \
  cargo test --locked -p xray-core-rs --test wireguard_runtime_tests \
  --test runtime_data_path_tests wireguard_runtime_ -- --ignored --nocapture
