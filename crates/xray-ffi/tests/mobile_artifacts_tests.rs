use std::fs;
use std::path::{Path, PathBuf};

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
}
