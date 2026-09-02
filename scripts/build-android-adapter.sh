#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_PROJECT_DIR="$WORKSPACE_ROOT/platform/android"
XRAY_FFI_ANDROID_DIR="${XRAY_FFI_ANDROID_DIR:-"$WORKSPACE_ROOT/target/mobile/android"}"
XRAY_USE_PREBUILT_ARTIFACTS="${XRAY_USE_PREBUILT_ARTIFACTS:-0}"
GRADLE_BIN="${GRADLE_BIN:-"$ANDROID_PROJECT_DIR/gradlew"}"
GRADLE_USER_HOME="${GRADLE_USER_HOME:-"$WORKSPACE_ROOT/target/mobile/android-gradle-home"}"
PINNED_ANDROID_NDK_VERSION="26.3.11579264"
ANDROID_PAGE_ALIGNMENT_HEX="0x4000"

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
      if [[ "$(basename "$candidate")" != "$PINNED_ANDROID_NDK_VERSION" ]]; then
        echo "Android NDK must be $PINNED_ANDROID_NDK_VERSION, got $candidate" >&2
        return 1
      fi
      echo "$candidate"
      return 0
    fi
  done

  local sdk_path="$1"
  if [[ -d "$sdk_path/ndk/$PINNED_ANDROID_NDK_VERSION" ]]; then
    echo "$sdk_path/ndk/$PINNED_ANDROID_NDK_VERSION"
    return 0
  fi
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

verify_elf_alignment() {
  local readelf="$1"
  local library="$2"
  local alignment
  local saw_load_segment=0

  while IFS= read -r alignment; do
    saw_load_segment=1
    if (( alignment < ANDROID_PAGE_ALIGNMENT_HEX )); then
      echo "Android library has a LOAD segment aligned below 16 KB: $library ($alignment)" >&2
      return 1
    fi
  done < <("$readelf" -lW "$library" | awk '$1 == "LOAD" { print $NF }')

  if (( saw_load_segment == 0 )); then
    echo "Android library has no ELF LOAD segments: $library" >&2
    return 1
  fi
}

verify_elf_dependencies() {
  local readelf="$1"
  local library="$2"
  local needed
  local has_xray_ffi=0

  while IFS= read -r needed; do
    if [[ "$needed" == */* ]]; then
      echo "Android library contains an absolute DT_NEEDED dependency: $library ($needed)" >&2
      return 1
    fi
    if [[ "$needed" == "libxray_ffi.so" ]]; then
      has_xray_ffi=1
    fi
  done < <(
    "$readelf" -d "$library" |
      sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p'
  )

  if [[ "$(basename "$library")" == *"libxray_mobile_jni.so" ]] &&
    (( has_xray_ffi == 0 )); then
    echo "Android JNI library does not depend on portable libxray_ffi.so: $library" >&2
    return 1
  fi
}

verify_aar_native_libraries() (
  local aar="$1"
  local ndk_path="$2"
  local ffi_dir="$3"
  local toolchain_dir
  toolchain_dir="$(host_toolchain_dir "$ndk_path" || true)"
  if [[ -z "$toolchain_dir" || ! -x "$toolchain_dir/bin/llvm-readelf" ]]; then
    echo "missing Android NDK llvm-readelf under $ndk_path" >&2
    return 1
  fi

  local unpack_dir
  unpack_dir="$(mktemp -d)"
  trap 'rm -rf "$unpack_dir"' EXIT
  local abi library
  for abi in arm64-v8a armeabi-v7a x86 x86_64; do
    for library in libxray_ffi.so libxray_mobile_jni.so; do
      unzip -p "$aar" "jni/$abi/$library" >"$unpack_dir/$abi-$library"
      verify_elf_alignment \
        "$toolchain_dir/bin/llvm-readelf" \
        "$unpack_dir/$abi-$library"
      verify_elf_dependencies \
        "$toolchain_dir/bin/llvm-readelf" \
        "$unpack_dir/$abi-$library"
      if [[ "$library" == "libxray_ffi.so" ]] &&
        ! cmp -s "$ffi_dir/jniLibs/$abi/$library" "$unpack_dir/$abi-$library"; then
        echo "packaged Android FFI library does not match the selected artifact: $abi/$library" >&2
        return 1
      fi
    done
  done
)

main() {
  require_command "$GRADLE_BIN"
  require_command awk
  require_command cmp
  require_command mktemp
  require_command sed
  require_command unzip

  local sdk_path
  sdk_path="$(first_existing_android_sdk_path || true)"
  if [[ -z "$sdk_path" ]]; then
    echo "missing Android SDK: set ANDROID_HOME or install under ~/Library/Android/sdk" >&2
    exit 1
  fi

  local ndk_path
  ndk_path="$(first_existing_android_ndk_path "$sdk_path" || true)"
  if [[ -z "$ndk_path" ]]; then
    echo "missing Android NDK $PINNED_ANDROID_NDK_VERSION: set ANDROID_NDK_HOME, ANDROID_NDK_ROOT, or install it under ANDROID_HOME/ndk" >&2
    exit 1
  fi

  mkdir -p "$XRAY_FFI_ANDROID_DIR"
  XRAY_FFI_ANDROID_DIR="$(cd "$XRAY_FFI_ANDROID_DIR" && pwd -P)"

  if [[ "$XRAY_USE_PREBUILT_ARTIFACTS" == "1" ]]; then
    if [[ ! -d "$XRAY_FFI_ANDROID_DIR/jniLibs" ]]; then
      echo "prebuilt Android JNI libraries not found: $XRAY_FFI_ANDROID_DIR/jniLibs" >&2
      exit 1
    fi
  else
    ANDROID_HOME="$sdk_path" ANDROID_NDK_HOME="$ndk_path" \
    OUT_DIR="$XRAY_FFI_ANDROID_DIR" \
      "$WORKSPACE_ROOT/scripts/build-android-libs.sh"
  fi

  mkdir -p "$GRADLE_USER_HOME"

  ANDROID_HOME="$sdk_path" \
  ANDROID_NDK_HOME="$ndk_path" \
  XRAY_FFI_ANDROID_DIR="$XRAY_FFI_ANDROID_DIR" \
  GRADLE_USER_HOME="$GRADLE_USER_HOME" \
    "$GRADLE_BIN" -p "$ANDROID_PROJECT_DIR" :xraymobile:assembleDebug --no-daemon

  local aar="$ANDROID_PROJECT_DIR/xraymobile/build/outputs/aar/xraymobile-debug.aar"
  if [[ ! -f "$aar" ]]; then
    echo "Android AAR was not produced: $aar" >&2
    exit 1
  fi
  verify_aar_native_libraries "$aar" "$ndk_path" "$XRAY_FFI_ANDROID_DIR"
}

main "$@"
