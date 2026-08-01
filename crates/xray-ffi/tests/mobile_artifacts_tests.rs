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
        "XrayTcpOpenErrorEvent",
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
        "xray_core_config_warnings",
        "xray_core_start",
        "xray_core_stop",
        "xray_core_free",
        "XraySocketProtectCallback",
        "xray_core_set_socket_protect_callback",
        "xray_core_set_startup_probe",
        "XrayTunFdPacketFormat",
        "XrayTunFdClosePolicy",
        "XrayTunRuntimeProfile",
        "XrayDnsBootstrapMode",
        "xray_core_set_tun_fd",
        "xray_core_set_tun_collect_tcp_timings",
        "xray_core_set_tun_runtime_profile",
        "xray_core_set_dns_bootstrap_mode",
        "xray_error_code",
        "xray_error_message",
        "xray_error_free",
        "xray_tun_push_packet",
        "xray_tun_poll_packet",
        "xray_tun_poll_packets",
        "xray_tun_poll_tcp_flow_summary_event",
        "xray_tun_poll_tcp_open_error_event",
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
    assert!(header.contains("XRAY_STATUS_INVALID_ARGUMENT = 9"));
    assert!(header.contains("int32_t packet_format,\n    int32_t close_policy,"));
    assert!(header.contains("int32_t profile,\n    XrayError **error);"));
    assert!(header.contains("XRAY_DNS_BOOTSTRAP_MODE_SYSTEM = 0"));
    assert!(header.contains("XRAY_DNS_BOOTSTRAP_MODE_STATIC_ONLY = 1"));

    for field in [
        "struct_size",
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
    assert!(!module_map.contains("framework module"));
    assert!(module_map.contains("umbrella header \"xray_ffi.h\""));
    assert!(module_map.contains("export *"));
}

#[test]
fn apple_secure_config_store_uses_data_protection_keychain() {
    let source = fs::read_to_string(
        workspace_root().join("platform/apple/Sources/XrayAppleShared/XraySecureConfigStore.swift"),
    )
    .expect("read Apple secure config store");

    assert!(source.contains("kSecUseDataProtectionKeychain: true"));
    assert!(source.contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"));
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
    assert!(package.contains(".iOS(.v15)"));
    assert!(!package.contains(".iOS(.v16)"));
    assert!(!package.contains(".iOS(.v13)"));
    assert!(package.contains("XrayRust.xcframework"));
    assert!(core.contains("import XrayRust"));
    assert!(core.contains("xray_ffi_version_major()"));
    assert!(core.contains("expectedFFIMajorVersion: UInt32 = 1"));
    assert!(core.contains("xray_core_set_socket_protect_callback"));
    assert!(core.contains("xray_core_set_geodata_search_dir"));
    assert!(core.contains("XrayStartupProbeOptions"));
    assert!(core.contains("startupProbe"));
    assert!(core.contains("xray_core_set_startup_probe"));
    assert!(core.contains("xray_core_set_tun_fd"));
    assert!(!core.contains("xray_core_set_tun_block_quic"));
    assert!(core.contains("xray_core_set_tun_collect_tcp_timings"));
    assert!(core.contains("xray_core_set_tun_runtime_profile"));
    assert!(core.contains("xray_core_set_dns_bootstrap_mode"));
    assert!(core.contains("tunFileDescriptor"));
    assert!(core.contains("xray_tun_push_packet"));
    assert!(core.contains("xray_tun_poll_packet"));
    assert!(core.contains("xray_tun_poll_tcp_flow_summary_event"));
    assert!(core.contains("xray_tun_poll_tcp_open_error_event"));
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

    let swift_version_check = core
        .find("try Self.validateFFIMajorVersion(xray_ffi_version_major())")
        .expect("Swift adapter should validate the FFI ABI");
    let swift_core_new = core
        .find("guard let handle = xray_core_new(&error)")
        .expect("Swift adapter should create the native core");
    assert!(
        swift_version_check < swift_core_new,
        "Swift adapter must validate the FFI ABI before creating a core"
    );
    let swift_bootstrap_mode = core
        .find("xray_core_set_dns_bootstrap_mode")
        .expect("Swift adapter should configure DNS bootstrap policy");
    let swift_config_load = core
        .find("xray_core_load_config_json")
        .expect("Swift adapter should load native config");
    assert!(
        swift_bootstrap_mode < swift_config_load,
        "Swift adapter must configure DNS bootstrap policy before config load"
    );
}

#[test]
fn apple_secure_config_lifecycle_uses_data_protection_and_cleanup() {
    let root = workspace_root();
    let secure_store = fs::read_to_string(
        root.join("platform/apple/Sources/XrayAppleShared/XraySecureConfigStore.swift"),
    )
    .expect("read Apple secure config store");
    let profile_store = fs::read_to_string(
        root.join("platform/apple/Sources/XrayAppleClient/XrayClientProfileStore.swift"),
    )
    .expect("read Apple profile store");
    let tunnel_controller = fs::read_to_string(
        root.join("platform/apple/Sources/XrayAppleClient/XrayClientTunnelController.swift"),
    )
    .expect("read Apple tunnel controller");

    assert!(secure_store.contains("kSecUseDataProtectionKeychain: true"));
    assert!(profile_store.contains("previousReference != reference"));
    assert!(profile_store.contains("secureConfigStore.remove(reference: previousReference)"));
    assert!(profile_store.contains("Failed to remove obsolete secure profile configuration"));
    assert!(tunnel_controller.contains("XrayTunnelSecureConfigTransaction"));
    assert!(tunnel_controller.contains("XrayTunnelManagerPreferencesTransaction"));
    assert!(tunnel_controller.contains("preferencesTransaction.rollback()"));
    assert!(tunnel_controller.contains("manager.removeFromPreferencesAsync()"));
    assert!(tunnel_controller.contains("secureRollback: secureTransaction.rollback"));
    assert!(tunnel_controller
        .contains("secureTransaction.commit(removingObsoleteReference: obsoleteReference)"));
}

#[test]
fn apple_packet_pump_reuses_poll_storage_and_fails_outside_worker_queue() {
    let root = workspace_root();
    let core =
        fs::read_to_string(root.join("platform/apple/Sources/XrayMobileAdapter/XrayCore.swift"))
            .expect("read Apple core adapter");
    let pump = fs::read_to_string(
        root.join("platform/apple/Sources/XrayMobileAdapter/XrayPacketTunnelPump.swift"),
    )
    .expect("read Apple packet pump");
    let provider = fs::read_to_string(
        root.join("platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift"),
    )
    .expect("read Apple packet tunnel provider");
    let mobile_log = fs::read_to_string(
        root.join("platform/apple/Sources/XrayMobileAdapter/XrayMobileLog.swift"),
    )
    .expect("read Apple mobile log helper");

    assert!(core.contains("XrayPacketBatchPollStorage"));
    assert!(core.contains("multipliedReportingOverflow"));
    assert!(core.contains("maximumPacketBatchBytes"));
    assert!(pump.contains("storage: pollStorage"));
    assert!(pump.contains("recordRecoverablePushFailure"));
    assert!(pump.contains("XrayPacketTunnelTerminalFailureDelivery"));
    assert!(pump.contains("queue.async"));
    assert!(provider.contains("cancelTunnelWithError(error)"));
    assert!(provider.contains("lifecycle.stop(ifCurrent: lifecycleToken)"));
    assert!(core.contains("public enum XrayDNSBootstrapMode"));
    assert!(provider.contains("dnsBootstrapMode: .staticOnly"));
    assert!(provider.contains("resolveAddress: (String) -> [String]?"));
    assert!(provider.contains("dnsBootstrapUpstream(from: rawServer)"));
    assert!(provider.contains("case let .domain(domain, port, rejectsTunnelOwnedAddress):"));
    assert!(provider.contains("if rejectsTunnelOwnedAddress || port == 53"));
    assert!(provider.contains("protectedDNSDomains.contains(domain)"));
    assert!(provider.contains("excludingServerAddresses: resolvedConfig.excludedServerAddresses"));
    assert!(provider.contains("ipv4Settings.excludedRoutes = ipv4ExcludedRoutes"));
    assert!(provider.contains("ipv6Settings.excludedRoutes = ipv6ExcludedRoutes"));
    let apply_network_settings = provider
        .find("setTunnelNetworkSettings(")
        .expect("Apple provider should apply packet-tunnel routes");
    let start_runtime = provider[apply_network_settings..]
        .find("let runtime = try self.makeRuntime(")
        .expect("Apple provider should start the runtime after applying routes");
    assert!(
        start_runtime > 0,
        "Apple core must start only after every bootstrap route is installed"
    );
    assert!(mobile_log.contains("XrayLogSanitizer.sanitize"));
}

#[test]
fn apple_file_logger_uses_secure_persistent_descriptor() {
    let source = fs::read_to_string(
        workspace_root().join("platform/apple/Sources/XrayAppleShared/XrayAppleLog.swift"),
    )
    .expect("read Apple logger");

    for token in [
        "openat(",
        "O_NOFOLLOW",
        "O_NONBLOCK",
        "O_APPEND",
        "fstat(",
        "S_IFREG",
        "fchmod(",
        "fileDescriptor",
    ] {
        assert!(source.contains(token), "Apple logger missing `{token}`");
    }
    assert!(!source.contains("FileHandle(forWritingTo:"));
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
    assert!(build.contains("ndkVersion = \"26.3.11579264\""));
    assert!(!build.contains("\"src/main/jniLibs\""));
    assert!(build.contains("JvmTarget.JVM_1_8"));
    assert!(core.contains("System.loadLibrary(\"xray_ffi\")"));
    assert!(core.contains("nativeSetSocketProtector"));
    assert!(core.contains("XrayStartupProbeOptions"));
    assert!(core.contains("startupProbe"));
    assert!(core.contains("nativeSetStartupProbe"));
    assert!(core.contains("nativeSetTunFd"));
    assert!(core.contains("nativeSetTunCollectTcpTimings"));
    assert!(core.contains("nativeSetTunRuntimeProfile"));
    assert!(core.contains("XrayTunRuntimeProfile"));
    assert!(service.contains("VpnService"));
    assert!(service.contains("startupProbe"));
    assert!(service.contains("XrayTunBackend"));
    assert!(service.contains("FileDescriptor"));
    assert!(service.contains("protect(fd)"));
    assert!(service.contains("addDisallowedApplication(packageName)"));
    assert!(service.contains("read(packetBuffer)"));
    assert!(service.contains("pollPacket"));
    assert!(jni.contains("xray_core_set_socket_protect_callback"));
    assert!(jni.contains("xray_ffi_version_major()"));
    assert!(jni.contains("kExpectedFfiMajorVersion = 1"));
    assert!(jni.contains("xray_core_set_startup_probe"));
    assert!(jni.contains("xray_core_set_tun_fd"));
    assert!(jni.contains("xray_core_set_tun_collect_tcp_timings"));
    assert!(jni.contains("xray_core_set_tun_runtime_profile"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetSocketProtector"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetStartupProbe"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetTunFd"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetTunCollectTcpTimings"));
    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetTunRuntimeProfile"));

    let jni_new = jni
        .find("Java_org_xrayrust_mobile_XrayCore_nativeNew")
        .expect("JNI adapter should define nativeNew");
    let jni_version_check = jni[jni_new..]
        .find("ensure_supported_ffi_abi(env)")
        .expect("JNI adapter should validate the FFI ABI");
    let jni_core_new = jni[jni_new..]
        .find("xray_core_new(&error)")
        .expect("JNI adapter should create the native core");
    assert!(
        jni_version_check < jni_core_new,
        "JNI adapter must validate the FFI ABI before creating a core"
    );
}

#[test]
fn android_core_sets_dns_bootstrap_policy_before_loading_config() {
    let core = fs::read_to_string(
        workspace_root()
            .join("platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt"),
    )
    .expect("read Kotlin core wrapper");

    assert!(core.contains("enum class XrayDnsBootstrapMode"));
    assert!(core.contains("dnsBootstrapMode: XrayDnsBootstrapMode = XrayDnsBootstrapMode.System"));
    assert!(core.contains("System(0)"));
    assert!(core.contains("StaticOnly(1)"));

    let create = core
        .find("fun create(")
        .expect("Kotlin wrapper should define create");
    let create_body = &core[create..];
    let set_policy = create_body
        .find("core.setDnsBootstrapMode(dnsBootstrapMode)")
        .expect("Kotlin wrapper should set the DNS bootstrap policy");
    let load_config = create_body
        .find("core.loadConfig(configJson)")
        .expect("Kotlin wrapper should load the config");
    assert!(
        set_policy < load_config,
        "Kotlin wrapper must set DNS bootstrap policy before loading config"
    );
}

#[test]
fn android_jni_forwards_dns_bootstrap_policy_to_the_c_abi() {
    let jni = fs::read_to_string(
        workspace_root().join("platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp"),
    )
    .expect("read JNI bridge");

    assert!(jni.contains("Java_org_xrayrust_mobile_XrayCore_nativeSetDnsBootstrapMode"));
    assert!(jni.contains("xray_core_set_dns_bootstrap_mode("));
    assert!(jni.contains("static_cast<int32_t>(mode)"));
}

#[test]
fn android_reference_vpn_bootstraps_dns_before_establishing_the_tunnel() {
    let service =
        fs::read_to_string(workspace_root().join(
            "platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayVpnService.kt",
        ))
        .expect("read Kotlin VPN service");
    let bootstrap = fs::read_to_string(workspace_root().join(
        "platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayAndroidDnsBootstrap.kt",
    ))
    .expect("read Android DNS bootstrap preparation");

    for token in [
        "InetAddress.getAllByName(domain)",
        "equals(\"vless\", ignoreCase = true)",
        "exactDnsHostIdentity(key)",
        "':' !in key",
        "canonicalizeExactDnsHostMappingsFromJson(hosts)",
        "exactMappings[existingKey] = AndroidDnsHostTarget.Addresses(addresses)",
        "is JSONArray",
        "JSONArray(values)",
        "resolveSystemBootstrapAddresses(identity)",
        "198.18.0.1",
        "getJSONArray(\"servers\")",
        "dnsServerBootstrapUpstreamDomain(rawServer)",
        "dnsUpstreamPort = upstream.port",
        "validateDnsUpstreamBootstrapAddresses(",
        "rejectsTunnelOwnedAddress = upstream.rejectsTunnelOwnedAddress",
        "is JSONObject -> dnsServerBootstrapDomainFromObject(server)",
        "getJSONObject(\"fakeIp\")",
    ] {
        assert!(
            bootstrap.contains(token),
            "Android DNS bootstrap preparation missing `{token}`"
        );
    }
    assert!(
        !bootstrap.contains("put(\"address\""),
        "Android bootstrap must preserve VLESS domain addresses"
    );
    assert!(
        !bootstrap.contains("firstOrNull"),
        "Android bootstrap must retain every usable system address"
    );
    assert!(service.contains("XrayDnsBootstrapMode.StaticOnly"));
    assert!(service.contains("addDnsServer(XRAY_TUN_DNS_ANCHOR)"));

    let start = service
        .find("open fun startXrayTunnel(")
        .expect("reference VPN should define startXrayTunnel");
    let start_body = &service[start..];
    let prepare = start_body
        .find("prepareAndroidVpnConfig(configJson)")
        .expect("reference VPN should prepare bootstrap mappings");
    let add_dns = start_body
        .find("tunnelBuilder.addDnsServer(XRAY_TUN_DNS_ANCHOR)")
        .expect("reference VPN should install the local DNS anchor");
    let establish = start_body
        .find("tunnelBuilder.establish()")
        .expect("reference VPN should establish the tunnel");
    assert!(
        prepare < add_dns && add_dns < establish,
        "Android DNS bootstrap and Builder DNS setup must finish before establish()"
    );

    let ensure_mapping = bootstrap
        .find("internal fun ensureBootstrapHostMapping(")
        .expect("reference VPN should define bootstrap mapping preparation");
    let ensure_mapping_body = &bootstrap[ensure_mapping..];
    let existing_mapping = ensure_mapping_body
        .find("exactMappings[existingKey]?.let { target ->")
        .expect("reference VPN should preserve an existing exact mapping");
    let insert_mapping = ensure_mapping_body
        .find("exactMappings[existingKey] = AndroidDnsHostTarget.Addresses(addresses)")
        .expect("reference VPN should add an exact bootstrap mapping");
    assert!(
        existing_mapping < insert_mapping,
        "existing exact dns.hosts mappings must win over generated mappings"
    );
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
    assert!(script.contains("XRAY_USE_PREBUILT_ARTIFACTS"));
    assert!(script.contains("EXPECTED_XCFRAMEWORK_PATH"));
    assert!(script.contains("custom XCFRAMEWORK_PATH is unsupported"));
}

#[test]
fn apple_adapter_link_script_covers_mobile_triples() {
    let script = fs::read_to_string(workspace_root().join("scripts/check-apple-adapter-link.sh"))
        .expect("read Apple adapter link script");

    assert!(script.contains(r#"IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}""#));

    for triple in [
        "arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}",
        "arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator",
        "x86_64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator",
        "arm64-apple-tvos${TVOS_DEPLOYMENT_TARGET}",
        "arm64-apple-tvos${TVOS_DEPLOYMENT_TARGET}-simulator",
        "x86_64-apple-tvos${TVOS_DEPLOYMENT_TARGET}-simulator",
        "arm64-apple-macos${MACOSX_DEPLOYMENT_TARGET}",
        "x86_64-apple-macos${MACOSX_DEPLOYMENT_TARGET}",
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
        "macosx",
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
    assert!(script.contains("XRAY_USE_PREBUILT_ARTIFACTS"));
    assert!(script.contains("EXPECTED_XCFRAMEWORK_PATH"));
    assert!(script.contains("custom XCFRAMEWORK_PATH is unsupported"));
    assert!(script.contains("lipo \"$binary\" -verify_arch arm64 x86_64"));
}

#[test]
fn apple_xcode_sample_uses_ios_15_deployment_target() {
    let project = fs::read_to_string(
        workspace_root().join("platform/apple/XrayClient/XrayClient.xcodeproj/project.pbxproj"),
    )
    .expect("read Apple sample project");

    assert!(project.contains("XCLocalSwiftPackageReference \"../../apple\""));
    assert!(project.contains("productName = XrayAppleClient;"));
    assert!(project.contains("productName = XrayAppleTunnel;"));
    assert!(project.contains("IPHONEOS_DEPLOYMENT_TARGET = 15.0;"));
    assert!(!project.contains("IPHONEOS_DEPLOYMENT_TARGET = 13.0;"));
    assert!(!project.contains("IPHONEOS_DEPLOYMENT_TARGET = 16.0;"));
    assert!(!project.contains("IPHONEOS_DEPLOYMENT_TARGET = 16.6;"));
    assert!(!project.contains("IPHONEOS_DEPLOYMENT_TARGET = 26.5;"));
}

#[test]
fn apple_xcode_sample_uses_tvos_17_deployment_target() {
    let project = fs::read_to_string(
        workspace_root().join("platform/apple/XrayClient/XrayClient.xcodeproj/project.pbxproj"),
    )
    .expect("read Apple sample project");

    assert_eq!(project.matches("TVOS_DEPLOYMENT_TARGET = 17.0;").count(), 8);
}

#[test]
fn apple_xcode_sample_uses_macos_13_deployment_target() {
    let project = fs::read_to_string(
        workspace_root().join("platform/apple/XrayClient/XrayClient.xcodeproj/project.pbxproj"),
    )
    .expect("read Apple sample project");

    assert_eq!(
        project.matches("MACOSX_DEPLOYMENT_TARGET = 13.0;").count(),
        4
    );
}

#[test]
fn apple_xcode_sample_has_shared_host_schemes() {
    let root = workspace_root()
        .join("platform/apple/XrayClient/XrayClient.xcodeproj/xcshareddata/xcschemes");

    for (scheme, product) in [
        ("XrayClient.xcscheme", "XrayClient.app"),
        ("XrayClientTv.xcscheme", "XrayClientTv.app"),
        ("XrayClientMac.xcscheme", "XrayClientMac.app"),
    ] {
        let contents = fs::read_to_string(root.join(scheme))
            .unwrap_or_else(|error| panic!("read shared scheme `{scheme}`: {error}"));
        assert!(
            contents.contains(product),
            "shared scheme `{scheme}` does not build `{product}`"
        );
    }
}

#[test]
fn apple_swift_sources_advertise_ios_15_availability() {
    let root = workspace_root();

    for path in [
        "platform/apple/HostApp/XrayClientApp.swift",
        "platform/apple/Sources/XrayAppleClient/XrayClientRootView.swift",
        "platform/apple/Sources/XrayAppleClient/XrayRealityVisionFlowPicker.swift",
        "platform/apple/Sources/XrayAppleClient/XrayClientViewModel.swift",
        "platform/apple/Sources/XrayAppleClient/XrayClientTunnelController.swift",
        "platform/apple/Sources/XrayAppleClient/XrayRealityFingerprintPicker.swift",
        "platform/apple/XrayClient/XrayClient/XrayClientApp.swift",
    ] {
        let source = fs::read_to_string(root.join(path)).expect("read Apple Swift source");
        assert!(
            source.contains("iOS 15.0"),
            "Swift source `{path}` should advertise iOS 15 availability"
        );
        assert!(
            !source.contains("iOS 16.0"),
            "Swift source `{path}` should not require iOS 16"
        );
    }

    for path in [
        "platform/apple/HostApp/PacketTunnelProvider.swift",
        "platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift",
        "platform/apple/XrayClient/Tunnel/PacketTunnelProvider.swift",
    ] {
        let source = fs::read_to_string(root.join(path)).expect("read Apple extension source");
        assert!(
            source.contains("iOSApplicationExtension 15.0"),
            "Swift extension source `{path}` should advertise iOS extension 15 availability"
        );
        assert!(
            !source.contains("iOSApplicationExtension 16.0"),
            "Swift extension source `{path}` should not require iOS extension 16"
        );
    }
}

#[test]
fn android_adapter_build_script_covers_gradle_sdk_and_artifacts() {
    let root = workspace_root();
    let script = fs::read_to_string(root.join("scripts/build-android-adapter.sh"))
        .expect("read Android adapter build script");
    let wrapper =
        fs::read_to_string(root.join("platform/android/gradle/wrapper/gradle-wrapper.properties"))
            .expect("read Gradle wrapper properties");

    assert!(script.contains("scripts/build-android-libs.sh"));
    assert!(script.contains("ANDROID_HOME"));
    assert!(script.contains("ANDROID_NDK_HOME"));
    assert!(script.contains("GRADLE_USER_HOME"));
    assert!(script.contains("XRAY_FFI_ANDROID_DIR"));
    assert!(script.contains(":xraymobile:assembleDebug"));
    assert!(script.contains("platform/android"));
    assert!(script.contains("XRAY_USE_PREBUILT_ARTIFACTS"));
    assert!(script.contains("26.3.11579264"));
    assert!(script.contains("gradlew"));
    assert!(root.join("platform/android/gradlew").is_file());
    assert!(root
        .join("platform/android/gradle/wrapper/gradle-wrapper.jar")
        .is_file());
    assert!(root
        .join("platform/android/gradle/verification-metadata.xml")
        .is_file());
    assert!(wrapper.contains("gradle-8.14.2-bin.zip"));
    assert!(wrapper.contains(
        "distributionSha256Sum=7197a12f450794931532469d4ff21a59ea2c1cd59a3ec3f89c035c3c420a6999"
    ));
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
            "--locked",
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
    "xray_core_config_warnings",
    "xray_core_start",
    "xray_core_stop",
    "xray_core_free",
    "xray_core_set_socket_protect_callback",
    "xray_core_set_file_logging",
    "xray_core_set_startup_probe",
    "xray_core_set_tun_fd",
    "xray_core_set_tun_collect_tcp_timings",
    "xray_core_set_tun_runtime_profile",
    "xray_core_set_dns_bootstrap_mode",
    "xray_error_code",
    "xray_error_message",
    "xray_error_free",
    "xray_tun_push_packet",
    "xray_tun_poll_packet",
    "xray_tun_poll_packets",
    "xray_tun_poll_tcp_flow_summary_event",
    "xray_tun_poll_tcp_open_error_event",
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
  XrayTunStats stats = {.struct_size = sizeof(XrayTunStats)};
  XrayTcpFlowSummaryEvent tcp_flow_summary = {0};
  XrayTcpOpenErrorEvent tcp_open_error = {0};
  XrayTcpRemoteWriteSlowEvent tcp_remote_write_slow = {0};
  XrayTcpSlowFlowEvent slow_flow = {0};
  XrayUdpSlowFlowEvent udp_slow_flow = {0};
  XrayUdpResponseGapEvent udp_response_gap = {0};
  XrayUdpQuicBlockedEvent udp_quic_blocked = {0};
  uint8_t packet[1] = {0};
  uint8_t buffer[64] = {0};
  char target[256] = {0};
  char outbound[64] = {0};
  char message[512] = {0};
  size_t written = 0;
  size_t outbound_written = 0;
  size_t message_written = 0;
  size_t packet_lengths[4] = {0};
  size_t packet_count = 0;
  uint64_t stats_probe = 0;

  (void)xray_ffi_version_major();
  (void)xray_core_set_geodata_search_dir(handle, ".", &error);
  (void)xray_core_set_socket_protect_callback(handle, NULL, NULL, &error);
  (void)xray_core_set_file_logging(handle, ".", 0, &error);
  (void)xray_core_set_startup_probe(
      handle,
      "http://probe.test/health",
      5000,
      NULL,
      &error);
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
  (void)xray_core_set_dns_bootstrap_mode(
      handle,
      XRAY_DNS_BOOTSTRAP_MODE_STATIC_ONLY,
      &error);
  (void)xray_core_load_config_json(handle, "{}", &error);
  (void)xray_core_config_warnings(
      handle,
      message,
      sizeof(message),
      &message_written,
      &error);
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
  (void)xray_tun_poll_tcp_open_error_event(
      handle,
      &tcp_open_error,
      target,
      sizeof(target),
      &written,
      outbound,
      sizeof(outbound),
      &outbound_written,
      message,
      sizeof(message),
      &message_written,
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
        "x86_64-apple-darwin",
    ] {
        assert!(script.contains(target), "Apple script missing `{target}`");
    }

    assert!(script.contains("MACOS_TARGETS"));
    assert!(script.contains("xcodebuild"));
    assert!(script.contains("-create-xcframework"));
    assert!(script.contains("lipo"));
    assert!(script.contains("build --locked"));
    assert!(script.contains("--package xray-ffi"));
    assert!(script.contains("TVOS_BUILD_STD"));
    assert!(script.contains("TVOS_RUST_TOOLCHAIN"));
    assert!(script.contains("nightly-2026-05-22"));
    assert!(script.contains("-Z"));
    assert!(script.contains("build-std"));
    assert!(script.contains("APPLE_CARGO_TARGET_DIR"));
    assert!(script.contains("export CARGO_TARGET_DIR"));
    assert!(script.contains("ios-$IPHONEOS_DEPLOYMENT_TARGET"));
    assert!(script.contains("IPHONEOS_DEPLOYMENT_TARGET"));
    assert!(script.contains(r#"IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}""#));
    assert!(script.contains("TVOS_DEPLOYMENT_TARGET"));
    assert!(script.contains("validate_output_paths"));
    assert!(script.contains("unsafe XCFRAMEWORK_NAME"));
    assert!(script.contains("unsafe OUT_DIR"));
    assert!(script.contains(r#"MACOS_TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin")"#));
}

#[test]
fn apple_xcframework_script_packages_static_libraries_with_headers() {
    let script = fs::read_to_string(workspace_root().join("scripts/build-apple-xcframework.sh"))
        .expect("read Apple build script");

    assert_eq!(script.matches("-library").count(), 5);
    assert_eq!(script.matches("-headers \"$HEADER_DIR\"").count(), 5);
    assert!(script.contains("-library \"$ios_device_lib\" -headers \"$HEADER_DIR\""));
    assert!(script.contains("-library \"$macos_lib\" -headers \"$HEADER_DIR\""));
    assert!(script.contains("validate_headers"));
    assert!(script.contains("verify_xcframework_layout"));
    assert!(script.contains("AvailableLibraries:$index:LibraryPath"));
    assert!(script.contains("AvailableLibraries:$index:HeadersPath"));
    assert!(script.contains("invalid Apple XCFramework slice count: expected 5"));
    assert!(!script.contains("make_static_framework"));
    assert!(!script.contains("-framework"));
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

    assert!(script.contains("cargo build"));
    assert!(script.contains("--locked"));
    assert!(script.contains("--manifest-path \"$WORKSPACE_ROOT/Cargo.toml\""));
    assert!(script.contains("--package xray-ffi"));
    assert!(script.contains("jniLibs"));
    assert!(script.contains("ANDROID_NDK_HOME"));
    assert!(script.contains("ANDROID_NDK_ROOT"));
    assert!(script.contains("ANDROID_HOME"));
    assert!(script.contains("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"));
    assert!(script.contains("CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER"));
    assert!(script.contains("CARGO_TARGET_I686_LINUX_ANDROID_LINKER"));
    assert!(script.contains("CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"));
    assert!(script.contains("PINNED_ANDROID_NDK_VERSION=\"26.3.11579264\""));
    assert!(script.contains("-Wl,-z,max-page-size=$ANDROID_PAGE_SIZE"));
    assert!(script.contains("-Wl,-z,common-page-size=$ANDROID_PAGE_SIZE"));
    assert!(script.contains("verify_elf_alignment"));
    assert!(script.contains("llvm-readelf"));
    assert!(script.contains("0x4000"));
    assert!(script.contains("rm -rf \"$OUT_DIR/jniLibs\""));
    assert!(script.contains("refusing unsafe Android output directory"));
}

#[test]
fn android_jni_library_is_linked_for_sixteen_kibibyte_pages() {
    let cmake = fs::read_to_string(
        workspace_root().join("platform/android/xraymobile/src/main/cpp/CMakeLists.txt"),
    )
    .expect("read Android JNI CMake file");

    assert!(cmake.contains("-Wl,-z,max-page-size=16384"));
    assert!(cmake.contains("-Wl,-z,common-page-size=16384"));
    assert!(cmake.contains("target_link_options"));
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
    assert!(script.contains("PINNED_ANDROID_NDK_VERSION=\"26.3.11579264\""));

    for env_var in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_HOME"] {
        assert!(
            script.contains(env_var),
            "preflight script missing Android env var `{env_var}`"
        );
    }

    assert!(script.contains("Library/Android/sdk/ndk"));
    assert!(script.contains("Android/Sdk/ndk"));
}
