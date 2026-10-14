#!/bin/bash
set -euo pipefail
CAMPAIGN="${XRAY_DEVICE_WORK_DIR:?set a private campaign output directory}"
cd "$CAMPAIGN/core-source"
test "$(git rev-parse HEAD)" = de33998158e84c03f280f979ba2d4212072e5bc4
test -z "$(git status --porcelain)"
TOOLCHAIN="${ANDROID_HOME:?set Android SDK}/ndk/26.3.11579264/toolchains/llvm/prebuilt/darwin-x86_64/bin"
export CARGO_TARGET_DIR="$CAMPAIGN/cargo"
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export TZ=UTC
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android24-clang"
export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS='-Dwarnings -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384'
cargo build --locked --offline --release --package xray-ffi --target aarch64-linux-android
mkdir -p "$CAMPAIGN/native/include" "$CAMPAIGN/native/jniLibs/arm64-v8a"
cp crates/xray-ffi/include/xray_ffi.h "$CAMPAIGN/native/include/"
cp "$CARGO_TARGET_DIR/aarch64-linux-android/release/libxray_ffi.so" "$CAMPAIGN/native/jniLibs/arm64-v8a/"
"$TOOLCHAIN/llvm-readelf" -lW "$CAMPAIGN/native/jniLibs/arm64-v8a/libxray_ffi.so"
shasum -a 256 "$CAMPAIGN/native/jniLibs/arm64-v8a/libxray_ffi.so" "$CAMPAIGN/native/include/xray_ffi.h"
test -z "$(git status --porcelain)"
