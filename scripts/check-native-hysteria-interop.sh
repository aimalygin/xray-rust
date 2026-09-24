#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly CHECKOUT="${HYSTERIA_CHECKOUT:-"$WORKSPACE_ROOT/target/references/hysteria-2.12.2"}"
readonly TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

python3 "$WORKSPACE_ROOT/scripts/verify-hysteria-reference.py" "$CHECKOUT"
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off GOTOOLCHAIN=go1.26.5 CGO_ENABLED=0 \
  go -C "$CHECKOUT/app" build -mod=readonly -trimpath -buildvcs=false -o "$TEST_ROOT/hysteria" .
# Building the reference must not silently update its dependency graph.
python3 "$WORKSPACE_ROOT/scripts/verify-hysteria-reference.py" "$CHECKOUT"

cd "$WORKSPACE_ROOT"
env -u XRAY_HYSTERIA_BINARY NATIVE_HYSTERIA_BINARY="$TEST_ROOT/hysteria" \
  cargo test --locked -p xray-transport --test hysteria_interop_tests \
  --test hysteria_native_interop_tests -- --ignored --nocapture
env -u XRAY_HYSTERIA_BINARY NATIVE_HYSTERIA_BINARY="$TEST_ROOT/hysteria" \
  cargo test --locked -p xray-core-rs --test hysteria_runtime_tests \
  --test runtime_data_path_tests hysteria_runtime_ -- --ignored --nocapture

env -u XRAY_HYSTERIA_BINARY NATIVE_HYSTERIA_BINARY="$TEST_ROOT/hysteria" \
  cargo test --locked -p xray-core-rs --lib outbound::hysteria::tests -- --include-ignored --nocapture
