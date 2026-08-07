#!/usr/bin/env bash
set -euo pipefail

# Regenerate every Go-oracle fixture and compare it with the committed copy.
# See scripts/verify-oracle-fixtures.py for what is checked and how each
# fixture's oracle flags are derived from the fixture itself.

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

for required in "$PYTHON_BIN" go; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "missing required command: $required" >&2
    exit 1
  fi
done

exec "$PYTHON_BIN" "$WORKSPACE_ROOT/scripts/verify-oracle-fixtures.py" "$@"
