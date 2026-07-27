#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-release}"
OUT_DIR="${OUT_DIR:-"$WORKSPACE_ROOT/target/mobile/apple"}"
HEADER_DIR="$WORKSPACE_ROOT/crates/xray-ffi/include"
XCFRAMEWORK_NAME="${XCFRAMEWORK_NAME:-XrayRust.xcframework}"
FRAMEWORK_NAME="${FRAMEWORK_NAME:-XrayRust}"
FRAMEWORK_BUNDLE_NAME="$FRAMEWORK_NAME.framework"
CRATE_PACKAGE="xray-ffi"
LIB_NAME="libxray_ffi.a"
CARGO_BIN="${CARGO_BIN:-cargo}"
TVOS_BUILD_STD="${TVOS_BUILD_STD:-auto}"
TVOS_RUST_TOOLCHAIN="${TVOS_RUST_TOOLCHAIN:-nightly-2026-05-22}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
export TVOS_DEPLOYMENT_TARGET="${TVOS_DEPLOYMENT_TARGET:-14.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
APPLE_CARGO_TARGET_DIR="${APPLE_CARGO_TARGET_DIR:-"$OUT_DIR/cargo/$PROFILE/ios-$IPHONEOS_DEPLOYMENT_TARGET-tvos-$TVOS_DEPLOYMENT_TARGET-macos-$MACOSX_DEPLOYMENT_TARGET"}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-"$APPLE_CARGO_TARGET_DIR"}"

IOS_DEVICE_TARGETS=("aarch64-apple-ios")
IOS_SIMULATOR_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")
TVOS_DEVICE_TARGETS=("aarch64-apple-tvos")
TVOS_SIMULATOR_TARGETS=("aarch64-apple-tvos-sim" "x86_64-apple-tvos")
MACOS_TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin")

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

validate_output_paths() {
  case "$FRAMEWORK_NAME" in
    ""|"."|".."|*[!A-Za-z0-9._-]*)
      echo "unsafe FRAMEWORK_NAME: $FRAMEWORK_NAME" >&2
      exit 1
      ;;
  esac
  case "$XCFRAMEWORK_NAME" in
    ""|"."|".."|*[!A-Za-z0-9._-]*|*.xcframework/)
      echo "unsafe XCFRAMEWORK_NAME: $XCFRAMEWORK_NAME" >&2
      exit 1
      ;;
  esac
  if [[ "$XCFRAMEWORK_NAME" != *.xcframework ]]; then
    echo "XCFRAMEWORK_NAME must end in .xcframework" >&2
    exit 1
  fi

  mkdir -p "$OUT_DIR"
  local resolved_out_dir
  resolved_out_dir="$(cd "$OUT_DIR" && pwd -P)"
  if [[ -z "$resolved_out_dir" || "$resolved_out_dir" == "/" ]]; then
    echo "unsafe OUT_DIR: $OUT_DIR" >&2
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
  echo "$CARGO_TARGET_DIR/$target/$profile_dir/$LIB_NAME"
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
      --locked \
      -Z build-std=std,panic_unwind \
      --package xray-ffi \
      --target "$target" \
      $(cargo_profile_args)
  else
    "$CARGO_BIN" build --locked --package xray-ffi --target "$target" $(cargo_profile_args)
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

make_module_map() {
  local framework_path="$1"
  cat >"$framework_path/Modules/module.modulemap" <<EOF
framework module $FRAMEWORK_NAME {
  umbrella header "xray_ffi.h"
  export *
  module * { export * }
}
EOF
}

make_info_plist() {
  local framework_path="$1"
  local minimum_key="$2"
  local minimum_version="$3"

  cat >"$framework_path/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>$FRAMEWORK_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>org.xrayrust.$FRAMEWORK_NAME</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$FRAMEWORK_NAME</string>
  <key>CFBundlePackageType</key>
  <string>FMWK</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>$minimum_key</key>
  <string>$minimum_version</string>
</dict>
</plist>
EOF
}

make_static_framework() {
  local framework_path="$1"
  local static_lib="$2"
  local minimum_key="$3"
  local minimum_version="$4"

  rm -rf "$framework_path"
  mkdir -p "$framework_path/Headers" "$framework_path/Modules"
  cp "$static_lib" "$framework_path/$FRAMEWORK_NAME"
  cp "$HEADER_DIR"/*.h "$framework_path/Headers/"
  make_module_map "$framework_path"
  make_info_plist "$framework_path" "$minimum_key" "$minimum_version"
}

main() {
  require_command cargo
  require_command rustup
  require_command lipo
  require_command xcodebuild

  validate_output_paths

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

  local ios_device_framework="$OUT_DIR/ios-device/$FRAMEWORK_BUNDLE_NAME"
  local ios_simulator_framework="$OUT_DIR/ios-simulator/$FRAMEWORK_BUNDLE_NAME"
  local tvos_device_framework="$OUT_DIR/tvos-device/$FRAMEWORK_BUNDLE_NAME"
  local tvos_simulator_framework="$OUT_DIR/tvos-simulator/$FRAMEWORK_BUNDLE_NAME"
  local macos_framework="$OUT_DIR/macos/$FRAMEWORK_BUNDLE_NAME"

  make_static_framework "$ios_device_framework" "$ios_device_lib" "MinimumOSVersion" "$IPHONEOS_DEPLOYMENT_TARGET"
  make_static_framework "$ios_simulator_framework" "$ios_simulator_lib" "MinimumOSVersion" "$IPHONEOS_DEPLOYMENT_TARGET"
  make_static_framework "$tvos_device_framework" "$tvos_device_lib" "MinimumOSVersion" "$TVOS_DEPLOYMENT_TARGET"
  make_static_framework "$tvos_simulator_framework" "$tvos_simulator_lib" "MinimumOSVersion" "$TVOS_DEPLOYMENT_TARGET"
  make_static_framework "$macos_framework" "$macos_lib" "LSMinimumSystemVersion" "$MACOSX_DEPLOYMENT_TARGET"

  rm -rf "$OUT_DIR/$XCFRAMEWORK_NAME"
  xcodebuild -create-xcframework \
    -framework "$ios_device_framework" \
    -framework "$ios_simulator_framework" \
    -framework "$tvos_device_framework" \
    -framework "$tvos_simulator_framework" \
    -framework "$macos_framework" \
    -output "$OUT_DIR/$XCFRAMEWORK_NAME"

  echo "$OUT_DIR/$XCFRAMEWORK_NAME"
}

main "$@"
