#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
: "${JAVA_HOME:?set JAVA_HOME to a JDK with JNI headers}"
cd "$WORKSPACE_ROOT"

case "$(uname -s)" in
  Darwin) platform=darwin; extension=dylib; link_mode=-dynamiclib ;;
  Linux) platform=linux; extension=so; link_mode=-shared ;;
  *) echo 'host JNI import tests support macOS and Linux' >&2; exit 1 ;;
esac

test_root="$(mktemp -d "${TMPDIR:-/tmp}/xray-profile-import-jni.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT
cargo build --locked -p xray-ffi
native_dir="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}/debug"
native_dir="$(cd "$native_dir" && pwd -P)"
"${CXX:-c++}" -std=c++17 -fPIC "$link_mode" -Wall -Wextra -Werror \
  -I "$JAVA_HOME/include" -I "$JAVA_HOME/include/$platform" \
  -I crates/xray-ffi/include \
  platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp \
  -L "$native_dir" -lxray_ffi -Wl,-rpath,"$native_dir" \
  -o "$test_root/libxray_mobile_jni.$extension"
platform/android/gradlew -p platform/android :xraymobile:testDebugUnitTest \
  "-PxrayNativeImportLibraryPath=$test_root:$native_dir" \
  --tests '*XrayProfileImporter*' --console=plain "$@"
