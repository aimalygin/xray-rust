#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-release}"
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-24}"
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

first_existing_android_ndk_path() {
  local candidate
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    if [[ -n "$candidate" && -d "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  for candidate in "${ANDROID_HOME:-}/ndk" "$HOME/Library/Android/sdk/ndk" "$HOME/Android/Sdk/ndk"; do
    if [[ -n "$candidate" && -d "$candidate" ]]; then
      find "$candidate" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n 1
      return 0
    fi
  done
}

host_toolchain_dir() {
  local ndk_path="$1"
  local host_tag
  case "$(uname -s)" in
    Darwin)
      for host_tag in "darwin-$(uname -m)" "darwin-x86_64"; do
        if [[ -d "$ndk_path/toolchains/llvm/prebuilt/$host_tag/bin" ]]; then
          echo "$ndk_path/toolchains/llvm/prebuilt/$host_tag"
          return 0
        fi
      done
      ;;
    Linux)
      for host_tag in "linux-$(uname -m)" "linux-x86_64"; do
        if [[ -d "$ndk_path/toolchains/llvm/prebuilt/$host_tag/bin" ]]; then
          echo "$ndk_path/toolchains/llvm/prebuilt/$host_tag"
          return 0
        fi
      done
      ;;
  esac
}

require_android_ndk_toolchain() {
  local ndk_path
  ndk_path="$(first_existing_android_ndk_path || true)"
  if [[ -z "$ndk_path" ]]; then
    echo "missing Android NDK: set ANDROID_NDK_HOME, ANDROID_NDK_ROOT, or ANDROID_HOME" >&2
    exit 1
  fi

  local toolchain_dir
  toolchain_dir="$(host_toolchain_dir "$ndk_path" || true)"
  if [[ -z "$toolchain_dir" ]]; then
    echo "missing Android NDK LLVM prebuilt toolchain under $ndk_path/toolchains/llvm/prebuilt" >&2
    exit 1
  fi

  echo "$toolchain_dir"
}

export_android_toolchain_env() {
  local toolchain_dir="$1"
  local bin_dir="$toolchain_dir/bin"
  local llvm_ar="$bin_dir/llvm-ar"

  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$bin_dir/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
  export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$bin_dir/armv7a-linux-androideabi${ANDROID_API_LEVEL}-clang"
  export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$bin_dir/i686-linux-android${ANDROID_API_LEVEL}-clang"
  export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$bin_dir/x86_64-linux-android${ANDROID_API_LEVEL}-clang"

  export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
  export CC_armv7_linux_androideabi="$CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER"
  export CC_i686_linux_android="$CARGO_TARGET_I686_LINUX_ANDROID_LINKER"
  export CC_x86_64_linux_android="$CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"

  export AR_aarch64_linux_android="$llvm_ar"
  export AR_armv7_linux_androideabi="$llvm_ar"
  export AR_i686_linux_android="$llvm_ar"
  export AR_x86_64_linux_android="$llvm_ar"
}

require_android_linkers() {
  local linker
  for linker in \
    "$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER" \
    "$CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER" \
    "$CARGO_TARGET_I686_LINUX_ANDROID_LINKER" \
    "$CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"; do
    if [[ ! -x "$linker" ]]; then
      echo "missing Android linker: $linker" >&2
      exit 1
    fi
  done
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

  local toolchain_dir
  toolchain_dir="$(require_android_ndk_toolchain)"
  export_android_toolchain_env "$toolchain_dir"
  require_android_linkers

  mkdir -p "$OUT_DIR/include"
  cp "$HEADER_DIR/xray_ffi.h" "$OUT_DIR/include/xray_ffi.h"

  local entry target abi
  for entry in "${TARGETS[@]}"; do
    IFS=":" read -r target abi <<<"$entry"
    build_target "$target"
    copy_target_lib "$target" "$abi"
  done

  echo "$OUT_DIR"
}

main "$@"
