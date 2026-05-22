#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_PROJECT_DIR="$WORKSPACE_ROOT/platform/android"
XRAY_FFI_ANDROID_DIR="${XRAY_FFI_ANDROID_DIR:-"$WORKSPACE_ROOT/target/mobile/android"}"
GRADLE_BIN="${GRADLE_BIN:-gradle}"
GRADLE_USER_HOME="${GRADLE_USER_HOME:-"$WORKSPACE_ROOT/target/mobile/android-gradle-home"}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

first_existing_android_sdk_path() {
  local candidate
  for candidate in "${ANDROID_HOME:-}" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    if [[ -n "$candidate" && -d "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
}

first_existing_android_ndk_path() {
  local candidate
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    if [[ -n "$candidate" && -d "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  local sdk_path="$1"
  if [[ -d "$sdk_path/ndk" ]]; then
    find "$sdk_path/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n 1
    return 0
  fi
}

main() {
  require_command "$GRADLE_BIN"

  local sdk_path
  sdk_path="$(first_existing_android_sdk_path || true)"
  if [[ -z "$sdk_path" ]]; then
    echo "missing Android SDK: set ANDROID_HOME or install under ~/Library/Android/sdk" >&2
    exit 1
  fi

  local ndk_path
  ndk_path="$(first_existing_android_ndk_path "$sdk_path" || true)"
  if [[ -z "$ndk_path" ]]; then
    echo "missing Android NDK: set ANDROID_NDK_HOME, ANDROID_NDK_ROOT, or install under ANDROID_HOME/ndk" >&2
    exit 1
  fi

  if [[ ! -d "$XRAY_FFI_ANDROID_DIR/jniLibs" ]]; then
    ANDROID_HOME="$sdk_path" ANDROID_NDK_HOME="$ndk_path" \
      "$WORKSPACE_ROOT/scripts/build-android-libs.sh"
  fi

  mkdir -p "$GRADLE_USER_HOME"

  ANDROID_HOME="$sdk_path" \
  ANDROID_NDK_HOME="$ndk_path" \
  XRAY_FFI_ANDROID_DIR="$XRAY_FFI_ANDROID_DIR" \
  GRADLE_USER_HOME="$GRADLE_USER_HOME" \
    "$GRADLE_BIN" -p "$ANDROID_PROJECT_DIR" :xraymobile:assembleDebug --no-daemon
}

main "$@"
