#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-release}"
OUT_DIR="${OUT_DIR:-"$WORKSPACE_ROOT/target/mobile/apple"}"
HEADER_DIR="$WORKSPACE_ROOT/crates/xray-ffi/include"
XCFRAMEWORK_NAME="${XCFRAMEWORK_NAME:-XrayRust.xcframework}"
CRATE_PACKAGE="xray-ffi"
LIB_NAME="libxray_ffi.a"
CARGO_BIN="${CARGO_BIN:-cargo}"
TVOS_BUILD_STD="${TVOS_BUILD_STD:-auto}"
TVOS_RUST_TOOLCHAIN="${TVOS_RUST_TOOLCHAIN:-nightly}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}"
export TVOS_DEPLOYMENT_TARGET="${TVOS_DEPLOYMENT_TARGET:-14.0}"

IOS_DEVICE_TARGETS=("aarch64-apple-ios")
IOS_SIMULATOR_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")
TVOS_DEVICE_TARGETS=("aarch64-apple-tvos")
TVOS_SIMULATOR_TARGETS=("aarch64-apple-tvos-sim" "x86_64-apple-tvos")
MACOS_TARGETS=("aarch64-apple-darwin")

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

cargo_profile_args() {
  if [[ "$PROFILE" == "release" ]]; then
    echo "--release"
  else
    echo "--profile" "$PROFILE"
  fi
}

target_lib_path() {
  local target="$1"
  local profile_dir="$PROFILE"
  if [[ "$PROFILE" == "dev" ]]; then
    profile_dir="debug"
  fi
  if [[ "$PROFILE" == "release" ]]; then
    profile_dir="release"
  fi
  echo "$WORKSPACE_ROOT/target/$target/$profile_dir/$LIB_NAME"
}

is_tvos_target() {
  local target="$1"
  [[ "$target" == *"apple-tvos"* ]]
}

rust_target_is_installed() {
  local target="$1"
  rustup target list --installed 2>/dev/null | grep -Fxq "$target"
}

use_build_std_for_target() {
  local target="$1"
  if ! is_tvos_target "$target"; then
    return 1
  fi

  case "$TVOS_BUILD_STD" in
    1|true|yes)
      return 0
      ;;
    0|false|no)
      return 1
      ;;
    auto)
      if rust_target_is_installed "$target"; then
        return 1
      fi
      return 0
      ;;
    *)
      echo "invalid TVOS_BUILD_STD value: $TVOS_BUILD_STD" >&2
      exit 1
      ;;
  esac
}

build_target() {
  local target="$1"
  if use_build_std_for_target "$target"; then
    "$CARGO_BIN" "+$TVOS_RUST_TOOLCHAIN" build \
      -Z build-std=std,panic_abort \
      --package xray-ffi \
      --target "$target" \
      $(cargo_profile_args)
  else
    cargo build --package xray-ffi --target "$target" $(cargo_profile_args)
  fi
}

build_targets() {
  local target
  for target in "$@"; do
    build_target "$target"
  done
}

combine_staticlibs() {
  local output="$1"
  shift
  mkdir -p "$(dirname "$output")"
  if [[ "$#" -eq 1 ]]; then
    cp "$1" "$output"
  else
    lipo -create "$@" -output "$output"
  fi
}

group_libs() {
  local output="$1"
  shift
  local libs=()
  local target
  for target in "$@"; do
    libs+=("$(target_lib_path "$target")")
  done
  combine_staticlibs "$output" "${libs[@]}"
}

main() {
  require_command cargo
  require_command rustup
  require_command lipo
  require_command xcodebuild

  mkdir -p "$OUT_DIR"

  build_targets "${IOS_DEVICE_TARGETS[@]}"
  build_targets "${IOS_SIMULATOR_TARGETS[@]}"
  build_targets "${TVOS_DEVICE_TARGETS[@]}"
  build_targets "${TVOS_SIMULATOR_TARGETS[@]}"
  build_targets "${MACOS_TARGETS[@]}"

  local ios_device_lib="$OUT_DIR/ios-device/$LIB_NAME"
  local ios_simulator_lib="$OUT_DIR/ios-simulator/$LIB_NAME"
  local tvos_device_lib="$OUT_DIR/tvos-device/$LIB_NAME"
  local tvos_simulator_lib="$OUT_DIR/tvos-simulator/$LIB_NAME"
  local macos_lib="$OUT_DIR/macos/$LIB_NAME"

  group_libs "$ios_device_lib" "${IOS_DEVICE_TARGETS[@]}"
  group_libs "$ios_simulator_lib" "${IOS_SIMULATOR_TARGETS[@]}"
  group_libs "$tvos_device_lib" "${TVOS_DEVICE_TARGETS[@]}"
  group_libs "$tvos_simulator_lib" "${TVOS_SIMULATOR_TARGETS[@]}"
  group_libs "$macos_lib" "${MACOS_TARGETS[@]}"

  rm -rf "$OUT_DIR/$XCFRAMEWORK_NAME"
  xcodebuild -create-xcframework \
    -library "$ios_device_lib" -headers "$HEADER_DIR" \
    -library "$ios_simulator_lib" -headers "$HEADER_DIR" \
    -library "$tvos_device_lib" -headers "$HEADER_DIR" \
    -library "$tvos_simulator_lib" -headers "$HEADER_DIR" \
    -library "$macos_lib" -headers "$HEADER_DIR" \
    -output "$OUT_DIR/$XCFRAMEWORK_NAME"

  echo "$OUT_DIR/$XCFRAMEWORK_NAME"
}

main "$@"
