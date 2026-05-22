#!/usr/bin/env bash
set -euo pipefail

APPLE_TARGETS=(
  "aarch64-apple-darwin"
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
TVOS_RUST_TOOLCHAIN="${TVOS_RUST_TOOLCHAIN:-nightly}"

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
    elif grep -Fxq "$target" <<<"$rustup_targets"; then
      missing "Rust target $target"
      missing_rustup_targets+=("$target")
    elif [[ "$target" == *"apple-tvos"* ]] && grep -Fxq "$target" <<<"$rustc_targets"; then
      info "Rust target $target has no rustup prebuilt std here; TVOS_BUILD_STD=auto will use +$TVOS_RUST_TOOLCHAIN -Z build-std"
      tvos_build_std_required=1
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
      echo "$candidate"
      return 0
    fi
  done

  local ndk_root
  for ndk_root in "${ANDROID_HOME:-}/ndk" "$HOME/Library/Android/sdk/ndk" "$HOME/Android/Sdk/ndk"; do
    if [[ -d "$ndk_root" ]]; then
      find "$ndk_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n 1
      return 0
    fi
  done
}

check_android_ndk() {
  local ndk_path
  ndk_path="$(first_existing_android_ndk_path || true)"

  if [[ -z "$ndk_path" ]]; then
    missing "Android NDK (set ANDROID_NDK_HOME, ANDROID_NDK_ROOT, or ANDROID_HOME/ndk)"
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
  check_android_ndk

  if [[ "$missing_count" -eq 0 ]]; then
    ok "mobile toolchains are ready for Apple and Android artifact builds"
    exit 0
  fi

  info "mobile toolchains are not fully ready; missing checks: $missing_count"
  exit 1
}

main "$@"
