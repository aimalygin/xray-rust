#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLE_PACKAGE_DIR="$WORKSPACE_ROOT/platform/apple"
XCFRAMEWORK_PATH="${XCFRAMEWORK_PATH:-"$WORKSPACE_ROOT/target/mobile/apple/XrayRust.xcframework"}"
SWIFT_BIN="${SWIFT_BIN:-swift}"
SWIFTPM_HOME="${SWIFTPM_HOME:-"$WORKSPACE_ROOT/target/mobile/apple-swiftpm-home"}"
CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-"$WORKSPACE_ROOT/target/mobile/apple-clang-module-cache"}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

main() {
  require_command "$SWIFT_BIN"

  if [[ ! -d "$XCFRAMEWORK_PATH" ]]; then
    "$WORKSPACE_ROOT/scripts/build-apple-xcframework.sh"
  fi

  mkdir -p "$SWIFTPM_HOME" "$CLANG_MODULE_CACHE_PATH"

  HOME="$SWIFTPM_HOME" \
  CLANG_MODULE_CACHE_PATH="$CLANG_MODULE_CACHE_PATH" \
    "$SWIFT_BIN" build --disable-sandbox --package-path "$APPLE_PACKAGE_DIR"
}

main "$@"
