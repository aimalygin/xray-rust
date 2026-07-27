#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-release}"
PINNED_ANDROID_API_LEVEL=24
ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-$PINNED_ANDROID_API_LEVEL}"
OUT_DIR="${OUT_DIR:-"$WORKSPACE_ROOT/target/mobile/android"}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-"$WORKSPACE_ROOT/target"}"
HEADER_DIR="$WORKSPACE_ROOT/crates/xray-ffi/include"
CRATE_PACKAGE="xray-ffi"
LIB_NAME="libxray_ffi.so"
PINNED_ANDROID_NDK_VERSION="26.3.11579264"
ANDROID_PAGE_SIZE=16384

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
  elif [[ "$PROFILE" == "dev" || "$PROFILE" == "debug" ]]; then
    return
  else
    echo "--profile" "$PROFILE"
  fi
}

profile_dir() {
  if [[ "$PROFILE" == "release" ]]; then
    echo "release"
  elif [[ "$PROFILE" == "dev" || "$PROFILE" == "debug" ]]; then
    echo "debug"
  else
    echo "$PROFILE"
  fi
}

first_existing_android_ndk_path() {
  local candidate
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    if [[ -n "$candidate" && -d "$candidate" ]]; then
      if [[ "$(basename "$candidate")" != "$PINNED_ANDROID_NDK_VERSION" ]]; then
        echo "Android NDK must be $PINNED_ANDROID_NDK_VERSION, got $candidate" >&2
        return 1
      fi
      echo "$candidate"
      return 0
    fi
  done

  for candidate in "${ANDROID_HOME:-}/ndk" "$HOME/Library/Android/sdk/ndk" "$HOME/Android/Sdk/ndk"; do
    if [[ -n "$candidate" && -d "$candidate/$PINNED_ANDROID_NDK_VERSION" ]]; then
      echo "$candidate/$PINNED_ANDROID_NDK_VERSION"
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

  export ANDROID_LLVM_READELF="$bin_dir/llvm-readelf"

  local page_size_flags
  page_size_flags="-C link-arg=-Wl,-z,max-page-size=$ANDROID_PAGE_SIZE -C link-arg=-Wl,-z,common-page-size=$ANDROID_PAGE_SIZE"
  append_rustflags CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS "$page_size_flags"
  append_rustflags CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS "$page_size_flags"
  append_rustflags CARGO_TARGET_I686_LINUX_ANDROID_RUSTFLAGS "$page_size_flags"
  append_rustflags CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS "$page_size_flags"
}

append_rustflags() {
  local variable_name="$1"
  local required_flags="$2"
  local current_flags="${!variable_name:-}"
  if [[ -n "$current_flags" ]]; then
    printf -v "$variable_name" "%s %s" "$current_flags" "$required_flags"
  else
    printf -v "$variable_name" "%s" "$required_flags"
  fi
  export "$variable_name"
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
  if [[ ! -x "$ANDROID_LLVM_READELF" ]]; then
    echo "missing Android ELF inspector: $ANDROID_LLVM_READELF" >&2
    exit 1
  fi
}

build_target() {
  local target="$1"
  cargo build \
    --locked \
    --manifest-path "$WORKSPACE_ROOT/Cargo.toml" \
    --package xray-ffi \
    --target "$target" \
    $(cargo_profile_args)
}

copy_target_lib() {
  local target="$1"
  local abi="$2"
  local source="$CARGO_TARGET_DIR/$target/$(profile_dir)/$LIB_NAME"
  local dest_dir="$OUT_DIR/jniLibs/$abi"
  mkdir -p "$dest_dir"
  cp "$source" "$dest_dir/$LIB_NAME"
}

verify_elf_alignment() {
  local library="$1"
  local minimum_alignment="0x4000"
  local alignment
  local saw_load_segment=0

  while IFS= read -r alignment; do
    saw_load_segment=1
    if (( alignment < minimum_alignment )); then
      echo "Android library has a LOAD segment aligned below 16 KB: $library ($alignment)" >&2
      exit 1
    fi
  done < <("$ANDROID_LLVM_READELF" -lW "$library" | awk '$1 == "LOAD" { print $NF }')

  if (( saw_load_segment == 0 )); then
    echo "Android library has no ELF LOAD segments: $library" >&2
    exit 1
  fi
}

main() {
  require_command cargo
  require_command awk

  if [[ "$ANDROID_API_LEVEL" != "$PINNED_ANDROID_API_LEVEL" ]]; then
    echo "Android API level must be $PINNED_ANDROID_API_LEVEL to match the library minSdk, got $ANDROID_API_LEVEL" >&2
    exit 1
  fi

  mkdir -p "$CARGO_TARGET_DIR"
  CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd -P)"
  export CARGO_TARGET_DIR

  local toolchain_dir
  toolchain_dir="$(require_android_ndk_toolchain)"
  export_android_toolchain_env "$toolchain_dir"
  require_android_linkers

  mkdir -p "$OUT_DIR"
  local canonical_out_dir
  canonical_out_dir="$(cd "$OUT_DIR" && pwd -P)"
  if [[ -z "$canonical_out_dir" || "$canonical_out_dir" == "/" ]]; then
    echo "refusing unsafe Android output directory: $canonical_out_dir" >&2
    exit 1
  fi
  OUT_DIR="$canonical_out_dir"

  mkdir -p "$OUT_DIR/include"
  cp "$HEADER_DIR/xray_ffi.h" "$OUT_DIR/include/xray_ffi.h"
  rm -rf "$OUT_DIR/jniLibs"

  local entry target abi
  for entry in "${TARGETS[@]}"; do
    IFS=":" read -r target abi <<<"$entry"
    build_target "$target"
    copy_target_lib "$target" "$abi"
    verify_elf_alignment "$OUT_DIR/jniLibs/$abi/$LIB_NAME"
  done

  echo "$OUT_DIR"
}

main "$@"
