#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$#" -eq 3 ]] || { echo "usage: $0 <evidence.zip> <commit> <tree>" >&2; exit 2; }

if grep -Fxq 'version = "0.6.0"' "$ROOT/Cargo.toml"; then
  python3 "$ROOT/scripts/check-v06-stable-promotion.py" "$@"
else
  python3 "$ROOT/scripts/check-v06-release-evidence.py" "$@"
fi
