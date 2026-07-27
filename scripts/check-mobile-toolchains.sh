#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_PROJECT_DIR="$WORKSPACE_ROOT/platform/android"

APPLE_TARGETS=(
  "aarch64-apple-darwin"
  "x86_64-apple-darwin"
  "aarch64-apple-ios"
  "aarch64-apple-ios-sim"
  "x86_64-apple-ios"
  "aarch64-apple-tvos"
  "aarch64-apple-tvos-sim"
  "x86_64-apple-tvos"
)

ANDROID_TARGETS=(
  "aarch64-linux-android"
  "armv7-linux-androideabi"
  "i686-linux-android"
  "x86_64-linux-android"
)

APPLE_SDKS=(
  "macosx"
  "iphoneos"
  "iphonesimulator"
  "appletvos"
  "appletvsimulator"
)

REQUIRED_COMMANDS=(
  "cargo"
  "rustc"
  "rustup"
  "xcodebuild"
  "xcrun"
  "lipo"
)

TVOS_BUILD_STD="${TVOS_BUILD_STD:-auto}"
TVOS_RUST_TOOLCHAIN="${TVOS_RUST_TOOLCHAIN:-nightly-2026-05-22}"
PINNED_ANDROID_NDK_VERSION="26.3.11579264"
PINNED_ANDROID_COMPILE_SDK="35"
PINNED_ANDROID_CMAKE_VERSION="3.22.1"
MINIMUM_ANDROID_JAVA_VERSION="17"
GRADLE_WRAPPER="$ANDROID_PROJECT_DIR/gradlew"

missing_count=0
tvos_build_std_required=0

ok() {
  echo "OK      $1"
}

missing() {
  echo "MISSING $1"
  missing_count=$((missing_count + 1))
}

info() {
  echo "INFO    $1"
}

check_command() {
  local command_name="$1"
  if command -v "$command_name" >/dev/null 2>&1; then
    ok "command $command_name: $(command -v "$command_name")"
  else
    missing "command $command_name"
  fi
}

check_gradle_wrapper() {
  if [[ -x "$GRADLE_WRAPPER" ]]; then
    ok "Gradle wrapper: $GRADLE_WRAPPER"
  else
    missing "executable Gradle wrapper at $GRADLE_WRAPPER"
  fi
}

java_home_command() {
  local command_name="$1"
  if [[ -n "${JAVA_HOME:-}" ]]; then
    local java_home_path="$JAVA_HOME/bin/$command_name"
    if [[ -x "$java_home_path" ]]; then
      echo "$java_home_path"
      return 0
    fi
    return 1
  fi

  command -v "$command_name" 2>/dev/null
}

check_android_jdk() {
  local java_bin
  java_bin="$(java_home_command java || true)"
  local javac_bin
  javac_bin="$(java_home_command javac || true)"

  if [[ -z "$java_bin" ]]; then
    missing "Android JDK java executable (set JAVA_HOME to JDK $MINIMUM_ANDROID_JAVA_VERSION or newer)"
    return
  fi
  if [[ -z "$javac_bin" ]]; then
    missing "Android JDK javac executable (set JAVA_HOME to a full JDK, not a JRE)"
  fi

  local java_spec_version
  java_spec_version="$(
    { "$java_bin" -XshowSettings:properties -version 2>&1 || true; } \
      | sed -n 's/^[[:space:]]*java\.specification\.version = //p' \
      | head -n 1
  )"
  local java_major="${java_spec_version#1.}"
  java_major="${java_major%%.*}"
  if [[ ! "$java_major" =~ ^[0-9]+$ ]]; then
    missing "unable to determine Android JDK version from $java_bin"
  elif (( java_major < MINIMUM_ANDROID_JAVA_VERSION )); then
    missing "Android JDK $MINIMUM_ANDROID_JAVA_VERSION or newer (found $java_spec_version at $java_bin)"
  else
    ok "Android JDK $java_spec_version: $java_bin"
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

check_android_sdk_platform() {
  local sdk_path="$1"
  local android_jar="$sdk_path/platforms/android-$PINNED_ANDROID_COMPILE_SDK/android.jar"
  if [[ -f "$android_jar" && -r "$android_jar" ]]; then
    ok "Android SDK platform android-$PINNED_ANDROID_COMPILE_SDK: $android_jar"
  else
    missing "Android SDK platform android-$PINNED_ANDROID_COMPILE_SDK ($android_jar)"
  fi
}

check_android_cmake() {
  local sdk_path="$1"
  local cmake_bin="$sdk_path/cmake/$PINNED_ANDROID_CMAKE_VERSION/bin/cmake"
  if [[ ! -x "$cmake_bin" ]]; then
    missing "Android SDK CMake $PINNED_ANDROID_CMAKE_VERSION executable at $cmake_bin"
    return
  fi

  local cmake_version
  cmake_version="$(
    { "$cmake_bin" --version 2>/dev/null || true; } \
      | sed -n '1s/^cmake version //p'
  )"
  if [[ "$cmake_version" == "$PINNED_ANDROID_CMAKE_VERSION" \
    || "$cmake_version" == "$PINNED_ANDROID_CMAKE_VERSION"-* ]]; then
    ok "Android SDK CMake $cmake_version: $cmake_bin"
  else
    missing "Android SDK CMake $PINNED_ANDROID_CMAKE_VERSION (found ${cmake_version:-unknown} at $cmake_bin)"
  fi
}

check_android_sdk() {
  local sdk_path
  sdk_path="$(first_existing_android_sdk_path || true)"
  if [[ -z "$sdk_path" ]]; then
    missing "Android SDK (set ANDROID_HOME or install under ~/Library/Android/sdk or ~/Android/Sdk)"
    return
  fi

  ok "Android SDK: $sdk_path"
  check_android_sdk_platform "$sdk_path"
  check_android_cmake "$sdk_path"
}

check_rust_targets() {
  if ! command -v rustup >/dev/null 2>&1; then
    missing "rustup is required before Rust target checks"
    return
  fi

  local installed_targets
  installed_targets="$(rustup target list --installed 2>/dev/null || true)"
  local rustup_targets
  rustup_targets="$(rustup target list 2>/dev/null | sed 's/ (installed)//' || true)"
  local rustc_targets
  rustc_targets="$(rustc --print=target-list 2>/dev/null || true)"
  local missing_rustup_targets=()

  local target
  for target in "${APPLE_TARGETS[@]}" "${ANDROID_TARGETS[@]}"; do
    if grep -Fxq "$target" <<<"$installed_targets"; then
      ok "Rust target $target"
    elif [[ "$target" == *"apple-tvos"* ]] && grep -Fxq "$target" <<<"$rustc_targets"; then
      info "Rust target $target is not installed; checking the configured tvOS build-std fallback"
      tvos_build_std_required=1
    elif grep -Fxq "$target" <<<"$rustup_targets"; then
      missing "Rust target $target"
      missing_rustup_targets+=("$target")
    else
      missing "Rust target $target"
    fi
  done

  if [[ "${#missing_rustup_targets[@]}" -gt 0 ]]; then
    info "install missing rustup-backed targets with: rustup target add ${missing_rustup_targets[*]}"
  fi
  check_tvos_build_std_fallback
}

check_tvos_build_std_fallback() {
  if [[ "$tvos_build_std_required" -eq 0 ]]; then
    return
  fi

  case "$TVOS_BUILD_STD" in
    auto|1|true|yes)
      ;;
    *)
      missing "tvOS build-std fallback disabled by TVOS_BUILD_STD=$TVOS_BUILD_STD"
      return
      ;;
  esac

  if rustup toolchain list | grep -Eq "^${TVOS_RUST_TOOLCHAIN}(-|[[:space:]])"; then
    ok "tvOS build-std toolchain $TVOS_RUST_TOOLCHAIN"
  else
    missing "tvOS build-std toolchain $TVOS_RUST_TOOLCHAIN"
    info "install it with: rustup toolchain install $TVOS_RUST_TOOLCHAIN --component rust-src"
    return
  fi

  if rustup "+$TVOS_RUST_TOOLCHAIN" component list --installed | grep -Eq '^rust-src'; then
    ok "tvOS build-std rust-src component"
  else
    missing "tvOS build-std rust-src component for $TVOS_RUST_TOOLCHAIN"
    info "install it with: rustup +$TVOS_RUST_TOOLCHAIN component add rust-src"
  fi
}

check_apple_sdks() {
  if ! command -v xcrun >/dev/null 2>&1; then
    missing "xcrun is required before Apple SDK checks"
    return
  fi

  local sdk
  local sdk_path
  for sdk in "${APPLE_SDKS[@]}"; do
    if sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path 2>/dev/null)"; then
      ok "Apple SDK $sdk: $sdk_path"
    else
      missing "Apple SDK $sdk"
    fi
  done
}

first_existing_android_ndk_path() {
  local candidate
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    if [[ -n "$candidate" && -d "$candidate" ]]; then
      if [[ "$(basename "$candidate")" != "$PINNED_ANDROID_NDK_VERSION" ]]; then
        continue
      fi
      echo "$candidate"
      return 0
    fi
  done

  local ndk_root
  for ndk_root in "${ANDROID_HOME:-}/ndk" "$HOME/Library/Android/sdk/ndk" "$HOME/Android/Sdk/ndk"; do
    if [[ -d "$ndk_root/$PINNED_ANDROID_NDK_VERSION" ]]; then
      echo "$ndk_root/$PINNED_ANDROID_NDK_VERSION"
      return 0
    fi
  done
}

check_android_ndk() {
  local ndk_path
  ndk_path="$(first_existing_android_ndk_path || true)"

  if [[ -z "$ndk_path" ]]; then
    missing "Android NDK $PINNED_ANDROID_NDK_VERSION (set ANDROID_NDK_HOME, ANDROID_NDK_ROOT, or install under ANDROID_HOME/ndk)"
    return
  fi

  ok "Android NDK: $ndk_path"

  if [[ -d "$ndk_path/toolchains/llvm/prebuilt" ]]; then
    ok "Android NDK LLVM toolchain directory"
  else
    missing "Android NDK LLVM toolchain directory at $ndk_path/toolchains/llvm/prebuilt"
  fi
}

main() {
  local command_name
  for command_name in "${REQUIRED_COMMANDS[@]}"; do
    check_command "$command_name"
  done

  check_rust_targets
  check_apple_sdks
  check_gradle_wrapper
  check_android_jdk
  check_android_sdk
  check_android_ndk

  if [[ "$missing_count" -eq 0 ]]; then
    ok "mobile toolchains are ready for Apple and Android artifact builds"
    exit 0
  fi

  info "mobile toolchains are not fully ready; missing checks: $missing_count"
  exit 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
