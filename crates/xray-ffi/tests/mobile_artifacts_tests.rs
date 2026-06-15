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
        "XrayTcpFlowSummaryEvent",
        "XrayTcpRemoteWriteSlowEvent",
        "XrayTcpSlowFlowEvent",
        "XrayTcpSlowFlowKind",
        "XrayUdpSlowFlowEvent",
        "XrayUdpResponseGapEvent",
        "XrayUdpQuicBlockedEvent",
        "XrayCoreHandle",
        "XrayError",
        "xray_core_new",
        "xray_core_set_geodata_search_dir",
        "xray_core_load_config_json",
        "xray_core_start",
        "xray_core_stop",
        "xray_core_free",
        "XraySocketProtectCallback",
        "xray_core_set_socket_protect_callback",
        "XrayTunFdPacketFormat",
        "XrayTunFdClosePolicy",
        "XrayTunRuntimeProfile",
        "xray_core_set_tun_fd",
        "xray_core_set_tun_collect_tcp_timings",
        "xray_core_set_tun_runtime_profile",
        "xray_error_code",
        "xray_error_message",
        "xray_error_free",
        "xray_tun_push_packet",
        "xray_tun_poll_packet",
        "xray_tun_poll_packets",
        "xray_tun_poll_tcp_flow_summary_event",
        "xray_tun_poll_tcp_remote_write_slow_event",
        "xray_tun_poll_tcp_slow_flow_event",
        "xray_tun_poll_udp_slow_flow_event",
        "xray_tun_poll_udp_response_gap_event",
        "xray_tun_poll_udp_quic_blocked_event",
        "xray_tun_stats",
    ] {
        assert!(header.contains(symbol), "header missing `{symbol}`");
    }
    assert!(!header.contains("xray_core_set_tun_block_quic"));

    for field in [
        "tcp_remote_write_wait_events",
        "tcp_remote_write_wait_ms_total",
        "tcp_remote_write_wait_ms_max",
        "tcp_remote_flush_wait_events",
        "tcp_remote_flush_wait_ms_total",
        "tcp_remote_flush_wait_ms_max",
        "duration_ms",
        "messages",
        "ms_to_64kib",
        "ms_to_128kib",
        "ms_to_256kib",
        "ms_to_512kib",
        "ms_to_1mib",
    ] {
        assert!(header.contains(field), "header missing `{field}`");
    }
}

#[test]
fn apple_c_module_map_exports_xrayrust_module() {
    let module_map =
        fs::read_to_string(workspace_root().join("crates/xray-ffi/include/module.modulemap"))
            .expect("read Apple C module map");

    assert!(module_map.contains("module XrayRust"));
    assert!(module_map.contains("umbrella header \"xray_ffi.h\""));
    assert!(module_map.contains("export *"));
}

#[test]
fn apple_adapter_declares_packet_tunnel_pump() {
    let root = workspace_root();
    let package =
        fs::read_to_string(root.join("platform/apple/Package.swift")).expect("read Apple package");
    let core =
        fs::read_to_string(root.join("platform/apple/Sources/XrayMobileAdapter/XrayCore.swift"))
            .expect("read Swift core wrapper");
    let pump = fs::read_to_string(
        root.join("platform/apple/Sources/XrayMobileAdapter/XrayPacketTunnelPump.swift"),
    )
    .expect("read Swift packet tunnel pump");
    let fd_helper = fs::read_to_string(
        root.join("platform/apple/Sources/XrayMobileAdapter/XrayDarwinTunFileDescriptor.swift"),
    )
    .expect("read Swift Darwin TUN fd helper");

    assert!(package.contains("XrayMobileAdapter"));
    assert!(package.contains("XrayRust.xcframework"));
    assert!(core.contains("import XrayRust"));
    assert!(core.contains("xray_core_set_socket_protect_callback"));
    assert!(core.contains("xray_core_set_geodata_search_dir"));
    assert!(core.contains("xray_core_set_tun_fd"));
    assert!(!core.contains("xray_core_set_tun_block_quic"));
    assert!(core.contains("xray_core_set_tun_collect_tcp_timings"));
    assert!(core.contains("xray_core_set_tun_runtime_profile"));
    assert!(core.contains("tunFileDescriptor"));
    assert!(core.contains("xray_tun_push_packet"));
    assert!(core.contains("xray_tun_poll_packet"));
    assert!(core.contains("xray_tun_poll_tcp_flow_summary_event"));
    assert!(core.contains("xray_tun_poll_tcp_slow_flow_event"));
    assert!(core.contains("xray_tun_poll_udp_slow_flow_event"));
    assert!(core.contains("xray_tun_poll_udp_response_gap_event"));
    assert!(core.contains("xray_tun_poll_udp_quic_blocked_event"));
    assert!(fd_helper.contains("XrayDarwinTunFileDescriptor"));
    assert!(fd_helper.contains("discoverUtunFileDescriptor"));
    assert!(fd_helper.contains("getsockopt"));
    assert!(pump.contains("NEPacketTunnelProvider"));
    assert!(pump.contains("packetFlow.readPackets"));
    assert!(pump.contains("packetFlow.writePackets"));
}

#[test]
fn android_adapter_declares_vpn_service_jni_and_socket_protection() {
    let root = workspace_root();
    let settings = fs::read_to_string(root.join("platform/android/settings.gradle.kts"))
        .expect("read Android settings");
    let build = fs::read_to_string(root.join("platform/android/xraymobile/build.gradle.kts"))
        .expect("read Android library build");
    let core = fs::read_to_string(
        root.join("platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt"),
    )
    .expect("read Kotlin core wrapper");
    let service =
        fs::read_to_string(root.join(
            "platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayVpnService.kt",
        ))
        .expect("read Kotlin VPN service");
    let jni = fs::read_to_string(
        root.join("platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp"),
    )
    .expect("read JNI bridge");

    assert!(settings.contains(":xraymobile"));
    assert!(build.contains("com.android.library"));
    assert!(build.contains("externalNativeBuild"));
    assert!(build.contains("ndkVersion"));
    assert!(build.contains("JvmTarget.JVM_1_8"));
    assert!(core.contains("System.loadLibrary(\"xray_ffi\")"));
    assert!(core.contains("nativeSetSocketProtector"));
    assert!(core.contains("nativeSetTunFd"));
    assert!(core.contains("nativeSetTunCollectTcpTimings"));
    assert!(core.contains("nativeSetTunRuntimeProfile"));
    assert!(core.contains("XrayTunRuntimeProfile"));
    assert!(service.contains("VpnService"));
    assert!(service.contains("XrayTunBackend"));
    assert!(service.contains("FileDescriptor"));
    assert!(service.contains("protect(fd)"));
    assert!(service.contains("addDisallowedApplication(packageName)"));
    assert!(service.contains("read(packetBuffer)"));
    assert!(service.contains("pollPacket"));
    assert!(jni.contains("xray_core_set_socket_protect_callback"));
    assert!(jni.contains("xray_core_set_tun_fd"));
    assert!(jni.contains("xray_core_set_tun_collect_tcp_timings"));
    assert!(jni.contains("xray_core_set_tun_runtime_profile"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetSocketProtector"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetTunFd"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetTunCollectTcpTimings"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetTunRuntimeProfile"));
}

#[test]
fn apple_adapter_build_script_covers_swiftpm_host_build() {
    let script = fs::read_to_string(workspace_root().join("scripts/build-apple-adapter.sh"))
        .expect("read Apple adapter build script");

    assert!(script.contains("scripts/build-apple-xcframework.sh"));
    assert!(script.contains("SWIFT_BIN"));
    assert!(script.contains("build --disable-sandbox"));
    assert!(script.contains("--disable-sandbox"));
    assert!(script.contains("CLANG_MODULE_CACHE_PATH"));
    assert!(script.contains("XrayRust.xcframework"));
    assert!(script.contains("platform/apple"));
}

#[test]
fn apple_adapter_link_script_covers_mobile_triples() {
    let script = fs::read_to_string(workspace_root().join("scripts/check-apple-adapter-link.sh"))
        .expect("read Apple adapter link script");

    for triple in [
        "arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}",
        "arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator",
        "x86_64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator",
        "arm64-apple-tvos${TVOS_DEPLOYMENT_TARGET}",
        "arm64-apple-tvos${TVOS_DEPLOYMENT_TARGET}-simulator",
        "x86_64-apple-tvos${TVOS_DEPLOYMENT_TARGET}-simulator",
    ] {
        assert!(
            script.contains(triple),
            "Apple link script missing `{triple}`"
        );
    }

    for sdk in [
        "iphoneos",
        "iphonesimulator",
        "appletvos",
        "appletvsimulator",
    ] {
        assert!(
            script.contains(sdk),
            "Apple link script missing SDK `{sdk}`"
        );
    }

    assert!(script.contains("swift"));
    assert!(script.contains("xcrun --sdk"));
    assert!(script.contains("--sdk"));
    assert!(script.contains("--triple"));
    assert!(script.contains("XrayRust.xcframework"));
    assert!(script.contains("build-apple-xcframework.sh"));
}

#[test]
fn android_adapter_build_script_covers_gradle_sdk_and_artifacts() {
    let script = fs::read_to_string(workspace_root().join("scripts/build-android-adapter.sh"))
        .expect("read Android adapter build script");

    assert!(script.contains("scripts/build-android-libs.sh"));
    assert!(script.contains("ANDROID_HOME"));
    assert!(script.contains("ANDROID_NDK_HOME"));
    assert!(script.contains("GRADLE_USER_HOME"));
    assert!(script.contains("XRAY_FFI_ANDROID_DIR"));
    assert!(script.contains(":xraymobile:assembleDebug"));
    assert!(script.contains("platform/android"));
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
    // `lto = "thin"` archives contain LLVM bitcode objects that the host
    // toolchain's `nm` may not be able to read when its LLVM is older than
    // rustc's; scan a non-LTO build so members are plain machine objects.
    let build = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "xray-ffi",
            "--release",
            "--target-dir",
            "target/ffi-symbol-scan",
            "--config",
            "profile.release.lto=\"off\"",
        ])
        .output()
        .expect("run cargo build for native xray-ffi staticlib");

    assert_command_success("native xray-ffi release build", &build);

    let library = root.join("target/ffi-symbol-scan/release/libxray_ffi.a");
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

    // `nm` exits nonzero when prebuilt std members carry bitcode newer than
    // its LLVM reader; the crate's own machine-code members still get listed,
    // so judge the scan by its output rather than the exit status.
    let stdout = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "native xray-ffi nm symbol scan produced no output\nstderr:\n{}",
        String::from_utf8_lossy(&symbols.stderr)
    );
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
    "xray_core_set_geodata_search_dir",
    "xray_core_load_config_json",
    "xray_core_start",
    "xray_core_stop",
    "xray_core_free",
    "xray_core_set_socket_protect_callback",
    "xray_core_set_tun_fd",
    "xray_core_set_tun_collect_tcp_timings",
    "xray_core_set_tun_runtime_profile",
    "xray_error_code",
    "xray_error_message",
    "xray_error_free",
    "xray_tun_push_packet",
    "xray_tun_poll_packet",
    "xray_tun_poll_packets",
    "xray_tun_poll_tcp_flow_summary_event",
    "xray_tun_poll_tcp_slow_flow_event",
    "xray_tun_poll_udp_slow_flow_event",
    "xray_tun_poll_udp_response_gap_event",
    "xray_tun_poll_udp_quic_blocked_event",
    "xray_tun_stats",
];

const APPLE_TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
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
  XrayTunStats stats = {0};
  XrayTcpFlowSummaryEvent tcp_flow_summary = {0};
  XrayTcpRemoteWriteSlowEvent tcp_remote_write_slow = {0};
  XrayTcpSlowFlowEvent slow_flow = {0};
  XrayUdpSlowFlowEvent udp_slow_flow = {0};
  XrayUdpResponseGapEvent udp_response_gap = {0};
  XrayUdpQuicBlockedEvent udp_quic_blocked = {0};
  uint8_t packet[1] = {0};
  uint8_t buffer[64] = {0};
  char target[256] = {0};
  char outbound[64] = {0};
  size_t written = 0;
  size_t outbound_written = 0;
  size_t packet_lengths[4] = {0};
  size_t packet_count = 0;
  uint64_t stats_probe = 0;

  (void)xray_ffi_version_major();
  (void)xray_core_set_geodata_search_dir(handle, ".", &error);
  (void)xray_core_set_socket_protect_callback(handle, NULL, NULL, &error);
  (void)xray_core_set_tun_fd(
      handle,
      -1,
      XRAY_TUN_FD_PACKET_FORMAT_RAW_IP,
      XRAY_TUN_FD_CLOSE_POLICY_BORROWED,
      &error);
  (void)xray_core_set_tun_collect_tcp_timings(handle, 1, &error);
  (void)xray_core_set_tun_runtime_profile(
      handle,
      XRAY_TUN_RUNTIME_PROFILE_LOW_MEMORY,
      &error);
  (void)xray_core_load_config_json(handle, "{}", &error);
  (void)xray_core_start(handle, &error);
  (void)xray_core_stop(handle, &error);
  (void)xray_tun_push_packet(handle, packet, sizeof(packet), &error);
  (void)xray_tun_poll_packet(handle, buffer, sizeof(buffer), &written, &error);
  (void)xray_tun_poll_packets(
      handle,
      buffer,
      sizeof(buffer),
      packet_lengths,
      4,
      &packet_count,
      0,
      &error);
  (void)xray_tun_poll_tcp_flow_summary_event(
      handle,
      &tcp_flow_summary,
      target,
      sizeof(target),
      &written,
      outbound,
      sizeof(outbound),
      &outbound_written,
      &error);
  (void)xray_tun_poll_tcp_remote_write_slow_event(
      handle,
      &tcp_remote_write_slow,
      target,
      sizeof(target),
      &written,
      outbound,
      sizeof(outbound),
      &outbound_written,
      &error);
  (void)xray_tun_poll_tcp_slow_flow_event(
      handle,
      &slow_flow,
      target,
      sizeof(target),
      &written,
      &error);
  (void)xray_tun_poll_udp_slow_flow_event(
      handle,
      &udp_slow_flow,
      target,
      sizeof(target),
      &written,
      &error);
  (void)xray_tun_poll_udp_response_gap_event(
      handle,
      &udp_response_gap,
      target,
      sizeof(target),
      &written,
      &error);
  (void)xray_tun_poll_udp_quic_blocked_event(
      handle,
      &udp_quic_blocked,
      target,
      sizeof(target),
      &written,
      &error);
  (void)xray_tun_stats(handle, &stats, &error);
  stats_probe += stats.tcp_remote_write_wait_events;
  stats_probe += stats.tcp_remote_write_wait_ms_total;
  stats_probe += stats.tcp_remote_write_wait_ms_max;
  stats_probe += stats.tcp_remote_flush_wait_events;
  stats_probe += stats.tcp_remote_flush_wait_ms_total;
  stats_probe += stats.tcp_remote_flush_wait_ms_max;
  (void)stats_probe;
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
        "aarch64-apple-darwin",
    ] {
        assert!(script.contains(target), "Apple script missing `{target}`");
    }

    assert!(script.contains("MACOS_TARGETS"));
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
        "macosx",
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
