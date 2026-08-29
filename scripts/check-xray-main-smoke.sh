#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${XRAY_CORE_CHECKOUT:-}" ]]; then
  echo 'XRAY_CORE_CHECKOUT must point at the Xray-core checkout' >&2
  exit 1
fi

if [[ -z "${XRAY_CORE_EXPECTED_REVISION:-}" ]]; then
  echo 'XRAY_CORE_EXPECTED_REVISION must name the full tested Xray-core commit' >&2
  exit 1
fi

if [[ ! "$XRAY_CORE_EXPECTED_REVISION" =~ ^[0123456789abcdef]{40}$ ]]; then
  printf 'XRAY_CORE_EXPECTED_REVISION must be an exact 40-character lowercase hexadecimal commit, got `%s`\n' \
    "$XRAY_CORE_EXPECTED_REVISION" >&2
  exit 1
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"

XRAY_CORE_CHECKOUT="$(cd -- "$XRAY_CORE_CHECKOUT" && pwd -P)"
actual_revision="$(git -C "$XRAY_CORE_CHECKOUT" rev-parse --verify HEAD)"
if [[ "$actual_revision" != "$XRAY_CORE_EXPECTED_REVISION" ]]; then
  printf 'Xray-core checkout is %s; expected %s\n' \
    "$actual_revision" "$XRAY_CORE_EXPECTED_REVISION" >&2
  exit 1
fi

printf 'Xray-core main smoke revision: %s\n' "$actual_revision"

unset GOFLAGS GOEXPERIMENT
export GOENV=off GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0
export XRAY_CORE_CHECKOUT XRAY_CORE_EXPECTED_REVISION

XRAY_XHTTP_INTEROP_CASES=h2-tls-stream-one \
  cargo test --locked -p xray-core-rs \
    --test local_xray_interop_tests \
    rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases \
    -- --ignored --nocapture --test-threads=1
