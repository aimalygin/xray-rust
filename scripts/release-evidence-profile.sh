#!/usr/bin/env bash
set -euo pipefail

# Output is a fixed allowlisted artifact/workflow prefix, safe to use in CI.
[[ "${1:-}" =~ ^v?0\.(6|7)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$ ]] || {
  echo "unsupported release evidence version: ${1:-missing}" >&2; exit 1;
}
case "${1:-}" in
  0.6.*|v0.6.*) echo v06 ;;
  0.7.*|v0.7.*) echo v07 ;;
  *) echo "unsupported release evidence version: ${1:-missing}" >&2; exit 1 ;;
esac
