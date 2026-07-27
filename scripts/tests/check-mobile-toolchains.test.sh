#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../check-mobile-toolchains.sh
source "$WORKSPACE_ROOT/scripts/check-mobile-toolchains.sh"
REPOSITORY_ROOT="$WORKSPACE_ROOT"

TEST_TMP_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEST_TMP_ROOT"' EXIT

test_missing_android_sdk_platform_is_reported() {
  local test_root="$TEST_TMP_ROOT/missing-platform"
  mkdir -p "$test_root"

  local sdk_path="$test_root/sdk"
  mkdir -p "$sdk_path/platforms/android-$PINNED_ANDROID_COMPILE_SDK"

  local output_path="$test_root/output.txt"
  missing_count=0
  check_android_sdk_platform "$sdk_path" >"$output_path"

  if [[ "$missing_count" -ne 1 ]]; then
    echo "expected one missing component, got $missing_count" >&2
    return 1
  fi
  if ! grep -Fq \
    "MISSING Android SDK platform android-$PINNED_ANDROID_COMPILE_SDK" \
    "$output_path"; then
    echo "missing Android SDK platform was not reported" >&2
    return 1
  fi
}

test_android_build_rejects_mismatched_api_level() {
  local test_root="$TEST_TMP_ROOT/api-level"
  mkdir -p "$test_root"

  local output_path="$test_root/output.txt"
  if ANDROID_API_LEVEL=25 \
    bash "$REPOSITORY_ROOT/scripts/build-android-libs.sh" >"$output_path" 2>&1; then
    echo "mismatched Android API level was accepted" >&2
    return 1
  fi
  if ! grep -Fq \
    "Android API level must be 24 to match the library minSdk, got 25" \
    "$output_path"; then
    echo "mismatched Android API level did not produce the expected diagnostic" >&2
    return 1
  fi
}

test_android_build_uses_custom_cargo_target_and_debug_profile_dir() {
  local test_root="$TEST_TMP_ROOT/cargo-target"
  mkdir -p "$test_root"

  local sourceable_script="$test_root/build-android-libs-functions.sh"
  sed '$d' "$REPOSITORY_ROOT/scripts/build-android-libs.sh" >"$sourceable_script"

  PROFILE=dev
  CARGO_TARGET_DIR="$test_root/custom-cargo-target"
  OUT_DIR="$test_root/artifacts"
  # shellcheck source=/dev/null
  source "$sourceable_script"
  WORKSPACE_ROOT="$REPOSITORY_ROOT"

  local resolved_profile_dir
  resolved_profile_dir="$(profile_dir)"
  if [[ "$resolved_profile_dir" != "debug" ]]; then
    echo "PROFILE=dev resolved to $resolved_profile_dir instead of debug" >&2
    return 1
  fi

  local target="aarch64-linux-android"
  local abi="arm64-v8a"
  local source_library="$CARGO_TARGET_DIR/$target/debug/$LIB_NAME"
  mkdir -p "$(dirname "$source_library")"
  printf 'custom cargo target fixture\n' >"$source_library"

  copy_target_lib "$target" "$abi"
  if ! cmp -s "$source_library" "$OUT_DIR/jniLibs/$abi/$LIB_NAME"; then
    echo "Android artifact was not copied from the custom Cargo target directory" >&2
    return 1
  fi

  if ! grep -Fq -- '--manifest-path "$WORKSPACE_ROOT/Cargo.toml"' "$sourceable_script"; then
    echo "Android Cargo build is not anchored to the workspace manifest" >&2
    return 1
  fi
}

test_android_adapter_verifies_packaged_native_alignment() {
  local adapter_script="$REPOSITORY_ROOT/scripts/build-android-adapter.sh"
  for required_text in \
    "verify_aar_native_libraries" \
    "libxray_ffi.so" \
    "libxray_mobile_jni.so" \
    "0x4000" \
    "cmp -s"; do
    if ! grep -Fq "$required_text" "$adapter_script"; then
      echo "Android adapter verification missing: $required_text" >&2
      return 1
    fi
  done

  local module_build="$REPOSITORY_ROOT/platform/android/xraymobile/build.gradle.kts"
  if ! grep -Fq \
    'providers.environmentVariable("XRAY_FFI_ANDROID_DIR")' \
    "$module_build"; then
    echo "Android Gradle build does not consume the selected FFI artifact directory" >&2
    return 1
  fi
  if ! grep -Fq 'keepDebugSymbols += "**/libxray_ffi.so"' "$module_build"; then
    echo "Android packaging can rewrite the selected FFI library before provenance verification" >&2
    return 1
  fi

  local root_build="$REPOSITORY_ROOT/platform/android/build.gradle.kts"
  if ! grep -Fq \
    'id("org.jetbrains.kotlin.android") version "2.2.21"' \
    "$root_build"; then
    echo "Android build is not pinned to the supported Kotlin Gradle plugin" >&2
    return 1
  fi
}

run_stubbed_preflight() {
  (
    # The Android build-script test above sources a second script that also has
    # a main function, so restore the preflight functions in this subshell.
    # shellcheck source=../check-mobile-toolchains.sh
    source "$REPOSITORY_ROOT/scripts/check-mobile-toolchains.sh"
    missing_count=0
    check_command() {
      echo "command:$1"
    }
    check_rust_targets() {
      echo "rust-targets:apple=$check_apple:android=$check_android"
    }
    check_apple_sdks() {
      echo "check:apple-sdks"
    }
    check_gradle_wrapper() {
      echo "check:gradle-wrapper"
    }
    check_android_jdk() {
      echo "check:android-jdk"
    }
    check_android_sdk() {
      echo "check:android-sdk"
    }
    check_android_ndk() {
      echo "check:android-ndk"
    }
    main "$@"
  )
}

assert_output_contains() {
  local output="$1"
  local expected="$2"
  if ! grep -Fq "$expected" <<<"$output"; then
    echo "expected preflight output to contain: $expected" >&2
    return 1
  fi
}

assert_output_omits() {
  local output="$1"
  local unexpected="$2"
  if grep -Fq "$unexpected" <<<"$output"; then
    echo "expected preflight output to omit: $unexpected" >&2
    return 1
  fi
}

test_apple_mode_checks_only_apple_prerequisites() {
  local output
  output="$(run_stubbed_preflight --apple)"

  assert_output_contains "$output" "command:cargo"
  assert_output_contains "$output" "command:xcodebuild"
  assert_output_contains "$output" "rust-targets:apple=1:android=0"
  assert_output_contains "$output" "check:apple-sdks"
  assert_output_contains "$output" "ready for Apple artifact builds"
  assert_output_omits "$output" "check:android-jdk"
  assert_output_omits "$output" "check:android-sdk"
  assert_output_omits "$output" "check:android-ndk"
  assert_output_omits "$output" "check:gradle-wrapper"
}

test_android_mode_checks_only_android_prerequisites() {
  local output
  output="$(run_stubbed_preflight --android)"

  assert_output_contains "$output" "command:cargo"
  assert_output_contains "$output" "rust-targets:apple=0:android=1"
  assert_output_contains "$output" "check:android-jdk"
  assert_output_contains "$output" "check:android-sdk"
  assert_output_contains "$output" "check:android-ndk"
  assert_output_contains "$output" "check:gradle-wrapper"
  assert_output_contains "$output" "ready for Android artifact builds"
  assert_output_omits "$output" "command:xcodebuild"
  assert_output_omits "$output" "command:xcrun"
  assert_output_omits "$output" "command:lipo"
  assert_output_omits "$output" "check:apple-sdks"
}

test_default_mode_checks_both_platforms() {
  local output
  output="$(run_stubbed_preflight)"

  assert_output_contains "$output" "rust-targets:apple=1:android=1"
  assert_output_contains "$output" "check:apple-sdks"
  assert_output_contains "$output" "check:android-sdk"
  assert_output_contains "$output" "ready for Apple and Android artifact builds"
}

test_missing_android_sdk_platform_is_reported
test_android_build_rejects_mismatched_api_level
test_android_build_uses_custom_cargo_target_and_debug_profile_dir
test_android_adapter_verifies_packaged_native_alignment
test_apple_mode_checks_only_apple_prerequisites
test_android_mode_checks_only_android_prerequisites
test_default_mode_checks_both_platforms
echo "check-mobile-toolchains tests passed"
