use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xray-ffi should live under workspace/crates")
        .to_path_buf()
}

#[test]
fn ffi_header_declares_lifecycle_error_and_tun_abi() {
    let header = fs::read_to_string(workspace_root().join("crates/xray-ffi/include/xray_ffi.h"))
        .expect("read xray_ffi.h");

    for symbol in [
        "XrayStatus",
        "XrayTunStats",
        "XrayCoreHandle",
        "XrayError",
        "xray_core_new",
        "xray_core_load_config_json",
        "xray_core_start",
        "xray_core_stop",
        "xray_core_free",
        "xray_error_code",
        "xray_error_message",
        "xray_error_free",
        "xray_tun_push_packet",
        "xray_tun_poll_packet",
        "xray_tun_stats",
    ] {
        assert!(header.contains(symbol), "header missing `{symbol}`");
    }
}

#[test]
fn ffi_header_compiles_as_c_harness() {
    compile_c_harness();
}

#[test]
fn native_staticlib_exports_mobile_abi_symbols() {
    assert_native_staticlib_exports_symbols();
}

fn compile_c_harness() {
    let root = workspace_root();
    let out_dir = root.join("target/mobile/harness");
    fs::create_dir_all(&out_dir).expect("create C harness output directory");

    let source_path = out_dir.join("xray_ffi_harness.c");
    let object_path = out_dir.join("xray_ffi_harness.o");
    fs::write(&source_path, C_HARNESS_SOURCE).expect("write C harness source");

    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let output = Command::new(compiler)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-I")
        .arg(root.join("crates/xray-ffi/include"))
        .arg("-c")
        .arg(&source_path)
        .arg("-o")
        .arg(&object_path)
        .output()
        .expect("run C compiler for FFI header harness");

    assert!(
        output.status.success(),
        "C harness compile failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_native_staticlib_exports_symbols() {
    let root = workspace_root();
    let build = Command::new("cargo")
        .current_dir(&root)
        .args(["build", "-p", "xray-ffi", "--release"])
        .output()
        .expect("run cargo build for native xray-ffi staticlib");

    assert_command_success("native xray-ffi release build", &build);

    let library = root.join("target/release/libxray_ffi.a");
    assert!(
        library.exists(),
        "native staticlib missing at {}",
        library.display()
    );

    let symbols = Command::new("nm")
        .arg("-g")
        .arg(&library)
        .output()
        .expect("run nm for native xray-ffi staticlib");

    assert_command_success("native xray-ffi nm symbol scan", &symbols);

    let stdout = String::from_utf8_lossy(&symbols.stdout);
    for symbol in EXPORTED_SYMBOLS {
        assert!(
            contains_exported_symbol(&stdout, symbol),
            "native staticlib missing exported symbol `{symbol}`"
        );
    }
}

fn assert_command_success(description: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{description} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn contains_exported_symbol(nm_stdout: &str, symbol: &str) -> bool {
    let underscored = format!("_{symbol}");
    nm_stdout.lines().any(|line| {
        let Some(name) = line.split_whitespace().last() else {
            return false;
        };
        name == symbol || name == underscored
    })
}

const EXPORTED_SYMBOLS: &[&str] = &[
    "xray_ffi_version_major",
    "xray_core_new",
    "xray_core_load_config_json",
    "xray_core_start",
    "xray_core_stop",
    "xray_core_free",
    "xray_error_code",
    "xray_error_message",
    "xray_error_free",
    "xray_tun_push_packet",
    "xray_tun_poll_packet",
    "xray_tun_stats",
];

const APPLE_TARGETS: &[&str] = &[
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
    "aarch64-apple-tvos",
    "aarch64-apple-tvos-sim",
    "x86_64-apple-tvos",
];

const ANDROID_TARGETS: &[&str] = &[
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "i686-linux-android",
    "x86_64-linux-android",
];

const C_HARNESS_SOURCE: &str = r#"
#include "xray_ffi.h"

#include <stddef.h>
#include <stdint.h>

static void use_xray_ffi_api(void) {
  XrayError *error = NULL;
  XrayCoreHandle *handle = xray_core_new(&error);
  XrayTunStats stats = {0, 0, 0};
  uint8_t packet[1] = {0};
  uint8_t buffer[64] = {0};
  size_t written = 0;

  (void)xray_ffi_version_major();
  (void)xray_core_load_config_json(handle, "{}", &error);
  (void)xray_core_start(handle, &error);
  (void)xray_core_stop(handle, &error);
  (void)xray_tun_push_packet(handle, packet, sizeof(packet), &error);
  (void)xray_tun_poll_packet(handle, buffer, sizeof(buffer), &written, &error);
  (void)xray_tun_stats(handle, &stats, &error);
  (void)xray_error_code(error);
  (void)xray_error_message(error);
  xray_error_free(error);
  xray_core_free(handle);
}

int main(void) {
  use_xray_ffi_api();
  return 0;
}
"#;

#[test]
fn apple_xcframework_script_covers_ios_and_tvos_targets() {
    let script = fs::read_to_string(workspace_root().join("scripts/build-apple-xcframework.sh"))
        .expect("read Apple build script");

    for target in [
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "x86_64-apple-ios",
        "aarch64-apple-tvos",
        "aarch64-apple-tvos-sim",
        "x86_64-apple-tvos",
    ] {
        assert!(script.contains(target), "Apple script missing `{target}`");
    }

    assert!(script.contains("xcodebuild"));
    assert!(script.contains("-create-xcframework"));
    assert!(script.contains("lipo"));
    assert!(script.contains("cargo build --package xray-ffi"));
    assert!(script.contains("TVOS_BUILD_STD"));
    assert!(script.contains("TVOS_RUST_TOOLCHAIN"));
    assert!(script.contains("-Z"));
    assert!(script.contains("build-std"));
    assert!(script.contains("IPHONEOS_DEPLOYMENT_TARGET"));
    assert!(script.contains("TVOS_DEPLOYMENT_TARGET"));
}

#[test]
fn android_script_covers_rust_targets_and_jni_abis() {
    let script = fs::read_to_string(workspace_root().join("scripts/build-android-libs.sh"))
        .expect("read Android build script");

    for target in [
        "aarch64-linux-android",
        "armv7-linux-androideabi",
        "i686-linux-android",
        "x86_64-linux-android",
    ] {
        assert!(script.contains(target), "Android script missing `{target}`");
    }

    for abi in ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"] {
        assert!(script.contains(abi), "Android script missing `{abi}`");
    }

    assert!(script.contains("cargo build --package xray-ffi"));
    assert!(script.contains("jniLibs"));
    assert!(script.contains("ANDROID_NDK_HOME"));
    assert!(script.contains("ANDROID_NDK_ROOT"));
    assert!(script.contains("ANDROID_HOME"));
    assert!(script.contains("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"));
    assert!(script.contains("CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER"));
    assert!(script.contains("CARGO_TARGET_I686_LINUX_ANDROID_LINKER"));
    assert!(script.contains("CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"));
}

#[test]
fn mobile_toolchain_preflight_script_covers_required_targets() {
    let script = fs::read_to_string(workspace_root().join("scripts/check-mobile-toolchains.sh"))
        .expect("read mobile toolchain preflight script");

    for target in APPLE_TARGETS {
        assert!(
            script.contains(target),
            "preflight script missing Apple target `{target}`"
        );
    }

    for target in ANDROID_TARGETS {
        assert!(
            script.contains(target),
            "preflight script missing Android target `{target}`"
        );
    }

    for sdk in [
        "iphoneos",
        "iphonesimulator",
        "appletvos",
        "appletvsimulator",
    ] {
        assert!(script.contains(sdk), "preflight script missing SDK `{sdk}`");
    }

    for command in ["cargo", "rustup", "xcodebuild", "xcrun", "lipo"] {
        assert!(
            script.contains(command),
            "preflight script missing command check `{command}`"
        );
    }

    assert!(script.contains("TVOS_BUILD_STD"));
    assert!(script.contains("TVOS_RUST_TOOLCHAIN"));
    assert!(script.contains("rust-src"));

    for env_var in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_HOME"] {
        assert!(
            script.contains(env_var),
            "preflight script missing Android env var `{env_var}`"
        );
    }

    assert!(script.contains("Library/Android/sdk/ndk"));
    assert!(script.contains("Android/Sdk/ndk"));
}
