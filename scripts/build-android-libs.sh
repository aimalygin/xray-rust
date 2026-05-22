#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-release}"
OUT_DIR="${OUT_DIR:-"$WORKSPACE_ROOT/target/mobile/android"}"
HEADER_DIR="$WORKSPACE_ROOT/crates/xray-ffi/include"
CRATE_PACKAGE="xray-ffi"
LIB_NAME="libxray_ffi.so"

TARGETS=(
  "aarch64-linux-android:arm64-v8a"
  "armv7-linux-androideabi:armeabi-v7a"
  "i686-linux-android:x86"
  "x86_64-linux-android:x86_64"
)

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

profile_dir() {
  if [[ "$PROFILE" == "release" ]]; then
    echo "release"
  else
    echo "$PROFILE"
  fi
}

build_target() {
  local target="$1"
  cargo build --package xray-ffi --target "$target" $(cargo_profile_args)
}

copy_target_lib() {
  local target="$1"
  local abi="$2"
  local source="$WORKSPACE_ROOT/target/$target/$(profile_dir)/$LIB_NAME"
  local dest_dir="$OUT_DIR/jniLibs/$abi"
  mkdir -p "$dest_dir"
  cp "$source" "$dest_dir/$LIB_NAME"
}

main() {
  require_command cargo

  mkdir -p "$OUT_DIR/include"
  cp "$HEADER_DIR/xray_ffi.h" "$OUT_DIR/include/xray_ffi.h"

  local entry target abi
  for entry in "${TARGETS[@]}"; do
    target="${entry%%:*}"
    abi="${entry##*:}"
    build_target "$target"
    copy_target_lib "$target" "$abi"
  done

  echo "$OUT_DIR"
}

main "$@"
