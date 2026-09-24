#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$#" -eq 3 ]] || { echo "usage: $0 <evidence.zip> <commit> <tree>" >&2; exit 2; }
version="$(python3 -c 'import pathlib,sys,tomllib; print(tomllib.loads(pathlib.Path(sys.argv[1]).read_text())["workspace"]["package"]["version"])' "$ROOT/Cargo.toml")"
profile="$(bash "$ROOT/scripts/release-evidence-profile.sh" "$version")"
case "$profile" in
  v06) bash "$ROOT/scripts/check-v06-release-evidence.sh" "$@" ;;
  v07) python3 "$ROOT/scripts/check-v07-release-evidence.py" "$@" ;;
esac
