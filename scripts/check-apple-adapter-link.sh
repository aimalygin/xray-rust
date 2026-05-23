#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLE_PACKAGE_DIR="$WORKSPACE_ROOT/platform/apple"
XCFRAMEWORK_PATH="${XCFRAMEWORK_PATH:-"$WORKSPACE_ROOT/target/mobile/apple/XrayRust.xcframework"}"
OUT_DIR="${OUT_DIR:-"$WORKSPACE_ROOT/target/mobile"}"
SWIFT_BIN="${SWIFT_BIN:-swift}"
SWIFT_CONFIGURATION="${SWIFT_CONFIGURATION:-release}"
IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}"
TVOS_DEPLOYMENT_TARGET="${TVOS_DEPLOYMENT_TARGET:-17.0}"

LINK_TARGETS=(
  "ios-device:iphoneos:arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}"
  "ios-simulator-arm64:iphonesimulator:arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator"
  "ios-simulator-x86_64:iphonesimulator:x86_64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator"
  "tvos-device:appletvos:arm64-apple-tvos${TVOS_DEPLOYMENT_TARGET}"
  "tvos-simulator-arm64:appletvsimulator:arm64-apple-tvos${TVOS_DEPLOYMENT_TARGET}-simulator"
  "tvos-simulator-x86_64:appletvsimulator:x86_64-apple-tvos${TVOS_DEPLOYMENT_TARGET}-simulator"
)

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

build_link_target() {
  local name="$1"
  local sdk="$2"
  local triple="$3"
  local sdk_path
  sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"

  local scratch_path="$OUT_DIR/apple-swiftpm-link-$name"
  local swiftpm_home="$OUT_DIR/apple-swiftpm-home-$name"
  local module_cache="$OUT_DIR/apple-clang-module-cache-$name"
  mkdir -p "$scratch_path" "$swiftpm_home" "$module_cache"

  echo "checking Apple adapter link: $name ($triple)"
  HOME="$swiftpm_home" \
  CLANG_MODULE_CACHE_PATH="$module_cache" \
    "$SWIFT_BIN" build \
      --disable-sandbox \
      --package-path "$APPLE_PACKAGE_DIR" \
      --scratch-path "$scratch_path" \
      --configuration "$SWIFT_CONFIGURATION" \
      --sdk "$sdk_path" \
      --triple "$triple"
}

main() {
  require_command xcrun
  require_command "$SWIFT_BIN"

  if [[ ! -d "$XCFRAMEWORK_PATH" ]]; then
    "$WORKSPACE_ROOT/scripts/build-apple-xcframework.sh"
  fi

  local entry name sdk triple
  for entry in "${LINK_TARGETS[@]}"; do
    IFS=":" read -r name sdk triple <<<"$entry"
    build_link_target "$name" "$sdk" "$triple"
  done
}

main "$@"
