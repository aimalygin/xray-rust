#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "missing required command: $PYTHON_BIN" >&2
  exit 1
fi

exec "$PYTHON_BIN" "$WORKSPACE_ROOT/scripts/tests/check-json-fixture-safety.py"
