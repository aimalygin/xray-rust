use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use xray_ffi::{
    xray_core_clear_outbound_selector_override, xray_core_close_connection,
    xray_core_config_warnings, xray_core_connection_snapshot_json, xray_core_free,
    xray_core_load_config_json, xray_core_new, xray_core_outbound_accounting_snapshot_json,
    xray_core_outbound_health_snapshot_json, xray_core_outbound_selection_snapshot_json,
    xray_core_replace_routing_policy_json, xray_core_routing_policy_snapshot_json,
    xray_core_set_dns_bootstrap_mode, xray_core_set_file_logging, xray_core_set_geodata_search_dir,
    xray_core_set_geodata_search_dir_exclusive, xray_core_set_outbound_selector_override,
    xray_core_set_socket_protect_callback, xray_core_set_startup_probe,
    xray_core_set_tun_collect_tcp_timings, xray_core_set_tun_fd, xray_core_set_tun_runtime_profile,
    xray_core_start, xray_core_stop, xray_error_code, xray_error_free, xray_error_message,
    xray_ffi_capabilities, xray_ffi_version_major, xray_ffi_version_minor, xray_tun_poll_packet,
    xray_tun_poll_packets, xray_tun_poll_tcp_flow_summary_event,
    xray_tun_poll_tcp_open_error_event, xray_tun_poll_tcp_remote_write_slow_event,
    xray_tun_poll_tcp_slow_flow_event, xray_tun_poll_udp_quic_blocked_event,
    xray_tun_poll_udp_response_gap_event, xray_tun_poll_udp_slow_flow_event, xray_tun_push_packet,
    xray_tun_stats, XrayDnsBootstrapMode, XrayStatus, XrayTcpFlowSummaryEvent,
    XrayTcpOpenErrorEvent, XrayTcpRemoteWriteSlowEvent, XrayTcpSlowFlowEvent, XrayTunFdClosePolicy,
    XrayTunFdPacketFormat, XrayTunRuntimeProfile, XrayTunStats, XrayUdpQuicBlockedEvent,
    XrayUdpResponseGapEvent, XrayUdpSlowFlowEvent, XRAY_FFI_ABI_MAJOR, XRAY_FFI_ABI_MINOR,
    XRAY_FFI_CAPABILITIES, XRAY_FFI_CAPABILITY_CONFIG_WARNINGS,
    XRAY_FFI_CAPABILITY_CONNECTION_MANAGEMENT, XRAY_FFI_CAPABILITY_DNS_BOOTSTRAP_POLICY,
    XRAY_FFI_CAPABILITY_FILE_LOGGING, XRAY_FFI_CAPABILITY_GEODATA_SEARCH,
    XRAY_FFI_CAPABILITY_OUTBOUND_HEALTH, XRAY_FFI_CAPABILITY_OUTBOUND_SELECTION,
    XRAY_FFI_CAPABILITY_ROUTING_POLICY_UPDATE, XRAY_FFI_CAPABILITY_SOCKET_PROTECTION,
    XRAY_FFI_CAPABILITY_STARTUP_PROBE, XRAY_FFI_CAPABILITY_TUN_BATCH_POLL,
    XRAY_FFI_CAPABILITY_TUN_DIAGNOSTIC_EVENTS, XRAY_FFI_CAPABILITY_TUN_FD,
    XRAY_FFI_CAPABILITY_TUN_PACKET_IO, XRAY_FFI_CAPABILITY_TUN_RUNTIME_PROFILES,
    XRAY_FFI_CAPABILITY_TUN_STATS,
};

#[test]
fn ffi_reports_current_abi_version() {
    assert_eq!(xray_ffi_version_major(), XRAY_FFI_ABI_MAJOR);
    assert_eq!(xray_ffi_version_minor(), XRAY_FFI_ABI_MINOR);
}

#[test]
fn ffi_reports_exact_current_capabilities() {
    let expected = XRAY_FFI_CAPABILITY_CONFIG_WARNINGS
        | XRAY_FFI_CAPABILITY_GEODATA_SEARCH
        | XRAY_FFI_CAPABILITY_SOCKET_PROTECTION
        | XRAY_FFI_CAPABILITY_STARTUP_PROBE
        | XRAY_FFI_CAPABILITY_FILE_LOGGING
        | XRAY_FFI_CAPABILITY_TUN_PACKET_IO
        | XRAY_FFI_CAPABILITY_TUN_FD
        | XRAY_FFI_CAPABILITY_TUN_BATCH_POLL
        | XRAY_FFI_CAPABILITY_TUN_RUNTIME_PROFILES
        | XRAY_FFI_CAPABILITY_DNS_BOOTSTRAP_POLICY
        | XRAY_FFI_CAPABILITY_TUN_STATS
        | XRAY_FFI_CAPABILITY_TUN_DIAGNOSTIC_EVENTS
        | XRAY_FFI_CAPABILITY_OUTBOUND_SELECTION
        | XRAY_FFI_CAPABILITY_OUTBOUND_HEALTH
        | XRAY_FFI_CAPABILITY_CONNECTION_MANAGEMENT
        | XRAY_FFI_CAPABILITY_ROUTING_POLICY_UPDATE;

    assert_eq!(XRAY_FFI_CAPABILITIES, expected);
    assert_eq!(xray_ffi_capabilities(), expected);
    assert_eq!(xray_ffi_capabilities() & (1 << 63), 0);
}

#[test]
fn ffi_loads_config_and_returns_handle() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    assert!(err.is_null());

    let raw = CString::new(include_str!(
        "../../../tests/fixtures/configs/vless_reality_vision.json"
    ))
    .unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
        xray_error_free(err);
    }
}

#[test]
fn ffi_loads_tun_config_without_port() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    assert!(err.is_null());

    let raw = CString::new(tun_config_without_port_with_freedom_outbound()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };

    assert_eq!(status, XrayStatus::Ok, "load error: {}", error_message(err));
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_exclusive_geodata_dir_does_not_fall_back_to_executable_dir() {
    let executable_dir = std::env::current_exe()
        .expect("current executable should resolve")
        .parent()
        .expect("current executable should have a parent")
        .to_path_buf();
    let file_name = format!(
        "xray-ffi-exclusive-geosite-{}-{}.dat",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos()
    );
    let fallback_path = executable_dir.join(&file_name);
    std::fs::write(&fallback_path, minimal_geosite_data())
        .expect("fallback geosite fixture should be written");
    let explicit_dir = unique_temp_dir("xray-ffi-exclusive-geodata");
    let explicit_dir_c = CString::new(explicit_dir.to_string_lossy().as_bytes()).unwrap();
    let raw = CString::new(format!(
        r#"{{"outbounds":[{{"tag":"direct","protocol":"freedom"}}],"routing":{{"rules":[{{"type":"field","domain":["ext-domain:{file_name}:test"],"outboundTag":"direct"}}]}}}}"#
    ))
    .unwrap();
    let mut err = std::ptr::null_mut();

    let fallback_core = unsafe { xray_core_new(&mut err) };
    assert_eq!(
        unsafe {
            xray_core_set_geodata_search_dir(fallback_core, explicit_dir_c.as_ptr(), &mut err)
        },
        XrayStatus::Ok
    );
    assert_eq!(
        unsafe { xray_core_load_config_json(fallback_core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok,
        "control load error: {}",
        error_message(err)
    );
    unsafe { xray_core_free(fallback_core) };

    let exclusive_core = unsafe { xray_core_new(&mut err) };
    assert_eq!(
        unsafe {
            xray_core_set_geodata_search_dir_exclusive(
                exclusive_core,
                explicit_dir_c.as_ptr(),
                &mut err,
            )
        },
        XrayStatus::Ok
    );
    assert_eq!(
        unsafe { xray_core_load_config_json(exclusive_core, raw.as_ptr(), &mut err) },
        XrayStatus::ConfigError
    );

    unsafe {
        xray_core_free(exclusive_core);
        xray_error_free(err);
    }
    std::fs::remove_file(fallback_path).expect("fallback geosite fixture should be removed");
    std::fs::remove_dir_all(explicit_dir).expect("explicit geodata fixture should be removed");
}

#[test]
fn ffi_hot_routing_policy_compiles_geodata_from_the_configured_generation() {
    let geodata_dir = unique_temp_dir("xray-ffi-hot-geodata");
    std::fs::write(geodata_dir.join("geosite.dat"), minimal_geosite_data())
        .expect("hot geosite fixture should be written");
    let geodata_dir_c = CString::new(geodata_dir.to_string_lossy().as_bytes()).unwrap();
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert_eq!(
        unsafe {
            xray_core_set_geodata_search_dir_exclusive(core, geodata_dir_c.as_ptr(), &mut err)
        },
        XrayStatus::Ok
    );
    let initial = CString::new(
        r#"{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}"#,
    )
    .unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, initial.as_ptr(), &mut err) },
        XrayStatus::Ok
    );

    let replacement = CString::new(
        r#"{"routing":{"rules":[{"type":"field","domain":["geosite:test"],"outboundTag":"direct"}]}}"#,
    )
    .unwrap();
    assert_eq!(
        unsafe { xray_core_replace_routing_policy_json(core, replacement.as_ptr(), &mut err) },
        XrayStatus::Ok,
        "hot geodata load error: {}",
        error_message(err)
    );
    let snapshot = read_snapshot_json(core, xray_core_routing_policy_snapshot_json, &mut err);
    assert_eq!(snapshot["revision"], 1);
    assert_eq!(snapshot["ruleCount"], 1);

    unsafe { xray_core_free(core) };
    std::fs::remove_dir_all(geodata_dir).expect("hot geodata fixture should be removed");
}

#[test]
fn ffi_rejects_reloading_config_while_core_is_running() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(tun_config_without_port_with_freedom_outbound()).unwrap();

    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    assert_eq!(
        unsafe { xray_core_start(core, &mut err) },
        XrayStatus::Ok,
        "start error: {}",
        error_message(err)
    );

    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "core config is already loaded",
    );
    assert_eq!(
        unsafe { xray_core_stop(core, &mut err) },
        XrayStatus::Ok,
        "stop error: {}",
        error_message(err)
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_exposes_config_warnings_without_truncation() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(config_with_wildcard_listen_warning()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok, "load error: {}", error_message(err));

    let mut warning_len = 0;
    let status = unsafe {
        xray_core_config_warnings(core, std::ptr::null_mut(), 0, &mut warning_len, &mut err)
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(warning_len > 0);

    let mut short = [0 as libc::c_char; 1];
    let status = unsafe {
        xray_core_config_warnings(
            core,
            short.as_mut_ptr(),
            short.len(),
            &mut warning_len,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_error(&mut err, XrayStatus::BufferTooSmall, "bytes are required");

    let mut warning = vec![0 as libc::c_char; warning_len + 1];
    let status = unsafe {
        xray_core_config_warnings(
            core,
            warning.as_mut_ptr(),
            warning.len(),
            &mut warning_len,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    let warning = unsafe { CStr::from_ptr(warning.as_ptr()) }
        .to_str()
        .unwrap();
    assert!(warning.contains("$.inbounds[0].listen"));
    assert!(warning.contains("wildcard listen address"));

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_exposes_atomic_selector_override_and_versioned_snapshot() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(config_with_outbound_selector()).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok,
        "load error: {}",
        error_message(err)
    );

    let initial = read_snapshot_json(core, xray_core_outbound_selection_snapshot_json, &mut err);
    assert_eq!(initial["schemaVersion"], 1);
    assert_eq!(initial["revision"], 0);
    assert_eq!(initial["groups"][0]["tag"], "automatic");
    assert_eq!(initial["groups"][0]["candidates"][0], "proxy-a");
    assert_eq!(initial["groups"][0]["candidates"][1], "proxy-b");
    assert!(initial["groups"][0]["overrideTag"].is_null());

    let group = CString::new("automatic").unwrap();
    let outbound = CString::new("proxy-b").unwrap();
    assert_eq!(
        unsafe {
            xray_core_set_outbound_selector_override(
                core,
                group.as_ptr(),
                outbound.as_ptr(),
                &mut err,
            )
        },
        XrayStatus::Ok
    );
    let selected = read_snapshot_json(core, xray_core_outbound_selection_snapshot_json, &mut err);
    assert_eq!(selected["revision"], 1);
    assert_eq!(selected["groups"][0]["overrideTag"], "proxy-b");

    assert_eq!(
        unsafe { xray_core_clear_outbound_selector_override(core, group.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    let cleared = read_snapshot_json(core, xray_core_outbound_selection_snapshot_json, &mut err);
    assert_eq!(cleared["revision"], 2);
    assert!(cleared["groups"][0]["overrideTag"].is_null());

    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_atomically_replaces_routing_policy_and_preserves_failed_revision() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(config_with_outbound_selector()).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );

    let initial = read_snapshot_json(core, xray_core_routing_policy_snapshot_json, &mut err);
    assert_eq!(initial["revision"], 0);
    assert_eq!(initial["ruleCount"], 1);
    assert_eq!(initial["domainStrategy"], "asIs");
    assert_eq!(
        unsafe { xray_core_start(core, &mut err) },
        XrayStatus::Ok,
        "start error: {}",
        error_message(err)
    );

    let replacement =
        CString::new(r#"{"routing":{"domainStrategy":"IPIfNonMatch","rules":[]}}"#).unwrap();
    assert_eq!(
        unsafe { xray_core_replace_routing_policy_json(core, replacement.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    let replaced = read_snapshot_json(core, xray_core_routing_policy_snapshot_json, &mut err);
    assert_eq!(replaced["revision"], 1);
    assert_eq!(replaced["ruleCount"], 0);
    assert_eq!(replaced["domainStrategy"], "ipIfNonMatch");

    let invalid = CString::new(
        r#"{"routing":{"rules":[{"type":"field","network":"tcp","outboundTag":"missing"}]}}"#,
    )
    .unwrap();
    assert_eq!(
        unsafe { xray_core_replace_routing_policy_json(core, invalid.as_ptr(), &mut err) },
        XrayStatus::ConfigError
    );
    assert_error(&mut err, XrayStatus::ConfigError, "unknown outbound");
    let retained = read_snapshot_json(core, xray_core_routing_policy_snapshot_json, &mut err);
    assert_eq!(retained["revision"], 1);

    assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_selector_override_rejects_non_member() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(config_with_outbound_selector()).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    let group = CString::new("automatic").unwrap();
    let outbound = CString::new("direct").unwrap();

    let status = unsafe {
        xray_core_set_outbound_selector_override(core, group.as_ptr(), outbound.as_ptr(), &mut err)
    };

    assert_eq!(status, XrayStatus::InvalidArgument);
    assert_error(&mut err, XrayStatus::InvalidArgument, "is not a candidate");
    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_health_snapshot_has_stable_redacted_schema() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(config_with_outbound_selector()).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );

    let snapshot = read_snapshot_json(core, xray_core_outbound_health_snapshot_json, &mut err);

    assert_eq!(snapshot["schemaVersion"], 1);
    assert_eq!(snapshot["revision"], 0);
    assert_eq!(snapshot["outbounds"].as_array().unwrap().len(), 3);
    assert!(snapshot["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .all(|status| {
            status["state"] == "unknown"
                && status["delayMs"].is_null()
                && status["lastFailureKind"].is_null()
                && status["httpStatus"].is_null()
        }));

    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_connection_and_accounting_snapshots_have_stable_empty_schema() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let connections = read_snapshot_json(core, xray_core_connection_snapshot_json, &mut err);
    assert_eq!(connections["schemaVersion"], 1);
    assert_eq!(connections["revision"], 0);
    assert_eq!(connections["connections"], serde_json::json!([]));

    let accounting =
        read_snapshot_json(core, xray_core_outbound_accounting_snapshot_json, &mut err);
    assert_eq!(accounting["schemaVersion"], 1);
    assert_eq!(accounting["revision"], 0);
    assert_eq!(accounting["outbounds"], serde_json::json!([]));

    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_connection_snapshot_close_and_accounting_control_live_socks_flow() {
    let inbound_port = reserve_loopback_port();
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_thread = thread::spawn(move || {
        let (mut stream, _) = echo_listener.accept().unwrap();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            stream.write_all(&buffer[..read]).unwrap();
        }
    });

    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(format!(
        r#"{{
          "inbounds": [{{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": {inbound_port},
            "settings": {{ "udp": false }}
          }}],
          "outbounds": [{{ "tag": "direct", "protocol": "freedom" }}]
        }}"#
    ))
    .unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    assert_eq!(
        unsafe { xray_core_start(core, &mut err) },
        XrayStatus::Ok,
        "start error: {}",
        error_message(err)
    );

    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, inbound_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    let SocketAddr::V4(echo_addr) = echo_addr else {
        panic!("echo listener must be IPv4");
    };
    let mut connect = vec![5, 1, 0, 1];
    connect.extend_from_slice(&echo_addr.ip().octets());
    connect.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&connect).unwrap();
    let mut response = [0_u8; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response[..2], &[5, 0]);

    let payload = b"ffi managed connection";
    client.write_all(payload).unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, payload);

    let snapshot = read_snapshot_json(core, xray_core_connection_snapshot_json, &mut err);
    let connection = &snapshot["connections"][0];
    assert_eq!(connection["state"], "active");
    assert_eq!(connection["inboundTag"], "socks-in");
    assert_eq!(connection["outboundTag"], "direct");
    assert_eq!(connection["network"], "tcp");
    assert_eq!(connection["addressType"], "ip");
    assert_eq!(connection["port"], echo_addr.port());
    let connection_id = connection["id"].as_u64().unwrap();

    assert_eq!(
        unsafe { xray_core_close_connection(core, connection_id, &mut err) },
        XrayStatus::Ok
    );
    let mut byte = [0_u8; 1];
    assert_eq!(client.read(&mut byte).unwrap(), 0);

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let snapshot = read_snapshot_json(core, xray_core_connection_snapshot_json, &mut err);
        if snapshot["connections"].as_array().unwrap().is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "connection stayed registered");
        thread::yield_now();
    }
    let accounting =
        read_snapshot_json(core, xray_core_outbound_accounting_snapshot_json, &mut err);
    let direct = &accounting["outbounds"][0];
    assert_eq!(direct["outboundTag"], "direct");
    assert_eq!(direct["openedConnections"], 1);
    assert_eq!(direct["completedConnections"], 1);
    assert_eq!(direct["hostClosedConnections"], 1);
    assert_eq!(direct["uplinkBytes"], payload.len());
    assert_eq!(direct["downlinkBytes"], payload.len());

    assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
    unsafe { xray_core_free(core) };
    echo_thread.join().unwrap();
}

#[test]
fn ffi_close_connection_rejects_zero_and_unknown_ids() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    assert_eq!(
        unsafe { xray_core_close_connection(core, 0, &mut err) },
        XrayStatus::InvalidArgument
    );
    assert_error(&mut err, XrayStatus::InvalidArgument, "must be nonzero");

    assert_eq!(
        unsafe { xray_core_close_connection(core, 42, &mut err) },
        XrayStatus::InvalidArgument
    );
    assert_error(&mut err, XrayStatus::InvalidArgument, "was not found");

    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_outbound_snapshot_validates_two_pass_output_contract() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(config_with_outbound_selector()).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );

    let mut required = 0;
    assert_eq!(
        unsafe {
            xray_core_outbound_selection_snapshot_json(
                core,
                std::ptr::null_mut(),
                1,
                &mut required,
                &mut err,
            )
        },
        XrayStatus::NullArgument
    );
    assert_error(&mut err, XrayStatus::NullArgument, "buffer is null");

    assert_eq!(
        unsafe {
            xray_core_outbound_selection_snapshot_json(
                core,
                std::ptr::null_mut(),
                0,
                &mut required,
                &mut err,
            )
        },
        XrayStatus::Ok
    );
    assert!(required > 0);
    let mut short = vec![0 as libc::c_char; required];
    let mut written = 0;
    assert_eq!(
        unsafe {
            xray_core_outbound_selection_snapshot_json(
                core,
                short.as_mut_ptr(),
                short.len(),
                &mut written,
                &mut err,
            )
        },
        XrayStatus::BufferTooSmall
    );
    assert_eq!(written, required);
    assert_error(&mut err, XrayStatus::BufferTooSmall, "bytes are required");

    assert_eq!(
        unsafe {
            xray_core_outbound_selection_snapshot_json(
                core,
                short.as_mut_ptr(),
                short.len(),
                std::ptr::null_mut(),
                &mut err,
            )
        },
        XrayStatus::NullArgument
    );
    assert_error(&mut err, XrayStatus::NullArgument, "length pointer is null");
    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_reports_null_handle_error() {
    let mut err = std::ptr::null_mut();
    let raw = CString::new("{}").unwrap();

    let status =
        unsafe { xray_core_load_config_json(std::ptr::null_mut(), raw.as_ptr(), &mut err) };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(&mut err, XrayStatus::NullArgument, "core handle is null");
}

#[test]
fn ffi_start_reports_unloaded_core() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_start(core, &mut err) };

    assert_eq!(status, XrayStatus::CoreNotLoaded);
    assert_error(
        &mut err,
        XrayStatus::CoreNotLoaded,
        "core config is not loaded",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_stop_reports_unloaded_core() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_stop(core, &mut err) };

    assert_eq!(status, XrayStatus::CoreNotLoaded);
    assert_error(
        &mut err,
        XrayStatus::CoreNotLoaded,
        "core config is not loaded",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_starts_and_stops_loaded_core() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let raw = CString::new(client_config_with_ephemeral_socks_port()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(
        status,
        XrayStatus::Ok,
        "start error: {}",
        error_message(err)
    );
    assert!(err.is_null());

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_registers_socket_protect_callback_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe {
        xray_core_set_socket_protect_callback(
            core,
            Some(record_socket_protect_call),
            std::ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_rejects_socket_protect_callback_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe {
        xray_core_set_socket_protect_callback(
            core,
            Some(record_socket_protect_call),
            std::ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "socket protect callback must be set before config load",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_file_logging_setter_accepts_directory_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let dir = unique_temp_dir("xray-ffi-file-logging");
    let dir_c = CString::new(dir.to_string_lossy().as_bytes()).unwrap();

    let status = unsafe { xray_core_set_file_logging(core, dir_c.as_ptr(), 1, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let raw = CString::new(tun_config_without_port_with_freedom_outbound()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok, "load error: {}", error_message(err));
    assert!(dir.join("xray-access.log").exists());
    assert!(dir.join("xray-error.log").exists());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_file_logging_setter_rejects_null_directory() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe { xray_core_set_file_logging(core, std::ptr::null(), 1, &mut err) };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "file log directory is null",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_file_logging_setter_rejects_invalid_utf8_directory() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let dir = CString::new(vec![0xff]).unwrap();

    let status = unsafe { xray_core_set_file_logging(core, dir.as_ptr(), 1, &mut err) };

    assert_eq!(status, XrayStatus::InvalidUtf8);
    assert_error(&mut err, XrayStatus::InvalidUtf8, "not valid UTF-8");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_file_logging_setter_rejects_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let dir = unique_temp_dir("xray-ffi-file-logging-loaded");
    let dir_c = CString::new(dir.to_string_lossy().as_bytes()).unwrap();

    let status = unsafe { xray_core_set_file_logging(core, dir_c.as_ptr(), 1, &mut err) };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "file logging must be set before config load",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_accepts_url_timeout_and_tag_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let url = CString::new("https://probe.example/generate_204").unwrap();
    let outbound_tag = CString::new("proxy").unwrap();
    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, outbound_tag.as_ptr(), &mut err)
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_accepts_null_and_empty_outbound_tag() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let url = CString::new("http://probe.test/health").unwrap();
    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, std::ptr::null(), &mut err)
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let empty_tag = CString::new("").unwrap();
    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, empty_tag.as_ptr(), &mut err)
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_rejects_null_handle() {
    let mut err = std::ptr::null_mut();
    let url = CString::new("https://probe.example/generate_204").unwrap();

    let status = unsafe {
        xray_core_set_startup_probe(
            std::ptr::null_mut(),
            url.as_ptr(),
            5_000,
            std::ptr::null(),
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(&mut err, XrayStatus::NullArgument, "core handle is null");
}

#[test]
fn ffi_startup_probe_setter_rejects_null_url() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe {
        xray_core_set_startup_probe(core, std::ptr::null(), 5_000, std::ptr::null(), &mut err)
    };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "startup probe URL is null",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_rejects_empty_url() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let url = CString::new("").unwrap();

    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, std::ptr::null(), &mut err)
    };

    assert_eq!(status, XrayStatus::ConfigError);
    assert_error(
        &mut err,
        XrayStatus::ConfigError,
        "startup probe URL is empty",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_rejects_zero_timeout() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let url = CString::new("https://probe.example/generate_204").unwrap();

    let status =
        unsafe { xray_core_set_startup_probe(core, url.as_ptr(), 0, std::ptr::null(), &mut err) };

    assert_eq!(status, XrayStatus::ConfigError);
    assert_error(
        &mut err,
        XrayStatus::ConfigError,
        "startup probe timeout must be positive",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_rejects_invalid_utf8_url() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let url = CString::new(vec![0xff]).unwrap();

    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, std::ptr::null(), &mut err)
    };

    assert_eq!(status, XrayStatus::InvalidUtf8);
    assert_error(&mut err, XrayStatus::InvalidUtf8, "not valid UTF-8");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_rejects_invalid_utf8_outbound_tag() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let url = CString::new("https://probe.example/generate_204").unwrap();
    let outbound_tag = CString::new(vec![0xff]).unwrap();

    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, outbound_tag.as_ptr(), &mut err)
    };

    assert_eq!(status, XrayStatus::InvalidUtf8);
    assert_error(&mut err, XrayStatus::InvalidUtf8, "not valid UTF-8");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_rejects_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let url = CString::new("https://probe.example/generate_204").unwrap();

    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, std::ptr::null(), &mut err)
    };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "startup probe must be set before config load",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_startup_probe_setter_runs_probe_when_core_starts() {
    let server = spawn_startup_probe_server_once();
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let url = CString::new(format!("http://127.0.0.1:{}/health", server.addr.port())).unwrap();
    let status = unsafe {
        xray_core_set_startup_probe(core, url.as_ptr(), 5_000, std::ptr::null(), &mut err)
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let raw = CString::new(client_config_with_freedom_outbound()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(
        status,
        XrayStatus::Ok,
        "start error: {}",
        error_message(err)
    );
    assert!(err.is_null());
    server.wait();

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[cfg(unix)]
#[test]
fn ffi_registers_tun_fd_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let fds = socket_pair();

    let status = unsafe {
        xray_core_set_tun_fd(
            core,
            fds[0].raw(),
            XrayTunFdPacketFormat::RawIp as libc::c_int,
            XrayTunFdClosePolicy::Borrowed as libc::c_int,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
#[cfg(unix)]
fn ffi_reconfigures_same_owned_tun_fd_without_closing_it() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let pipe = pipe_pair();
    let owned_fd = dup_fd(pipe[0].raw());

    for _ in 0..2 {
        let status = unsafe {
            xray_core_set_tun_fd(
                core,
                owned_fd,
                XrayTunFdPacketFormat::RawIp as libc::c_int,
                XrayTunFdClosePolicy::Owned as libc::c_int,
                &mut err,
            )
        };
        assert_eq!(status, XrayStatus::Ok);
        assert!(err.is_null());
    }
    assert!(fd_is_open(owned_fd));

    unsafe {
        xray_core_free(core);
    }
}

#[test]
#[cfg(unix)]
fn ffi_same_tun_fd_owned_to_borrowed_transfer_does_not_close_reused_fd() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let pipe = pipe_pair();
    let transferred_fd = dup_fd(pipe[0].raw());

    assert_eq!(
        unsafe {
            xray_core_set_tun_fd(
                core,
                transferred_fd,
                XrayTunFdPacketFormat::RawIp as libc::c_int,
                XrayTunFdClosePolicy::Owned as libc::c_int,
                &mut err,
            )
        },
        XrayStatus::Ok
    );
    assert_eq!(
        unsafe {
            xray_core_set_tun_fd(
                core,
                transferred_fd,
                XrayTunFdPacketFormat::DarwinUtun as libc::c_int,
                XrayTunFdClosePolicy::Borrowed as libc::c_int,
                &mut err,
            )
        },
        XrayStatus::Ok
    );
    assert!(fd_is_open(transferred_fd));

    assert_eq!(unsafe { libc::close(transferred_fd) }, 0);
    assert_eq!(
        unsafe { libc::dup2(pipe[1].raw(), transferred_fd) },
        transferred_fd
    );
    assert!(fd_is_open(transferred_fd));

    unsafe {
        xray_core_free(core);
    }
    assert!(fd_is_open(transferred_fd));
    assert_eq!(unsafe { libc::close(transferred_fd) }, 0);
}

#[test]
fn ffi_rejects_invalid_tun_fd_discriminants_without_constructing_rust_enums() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_set_tun_fd(core, 0, i32::MAX, 0, &mut err) };
    assert_eq!(status, XrayStatus::InvalidArgument);
    assert_error(
        &mut err,
        XrayStatus::InvalidArgument,
        "packet format must be",
    );

    let status = unsafe { xray_core_set_tun_fd(core, 0, 0, i32::MIN, &mut err) };
    assert_eq!(status, XrayStatus::InvalidArgument);
    assert_error(
        &mut err,
        XrayStatus::InvalidArgument,
        "close policy must be",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[cfg(unix)]
#[test]
fn ffi_rejects_tun_fd_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let fds = socket_pair();

    let status = unsafe {
        xray_core_set_tun_fd(
            core,
            fds[0].raw(),
            XrayTunFdPacketFormat::RawIp as libc::c_int,
            XrayTunFdClosePolicy::Borrowed as libc::c_int,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "tun fd must be set before config load",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_registers_tun_tcp_timing_collection_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe { xray_core_set_tun_collect_tcp_timings(core, 1, &mut err) };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_rejects_tun_tcp_timing_collection_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe { xray_core_set_tun_collect_tcp_timings(core, 1, &mut err) };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "tun TCP timing collection must be set before config load",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_registers_tun_runtime_profile_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::LowMemory as libc::c_int,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_rejects_invalid_tun_runtime_profile_discriminant() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_set_tun_runtime_profile(core, -1, &mut err) };

    assert_eq!(status, XrayStatus::InvalidArgument);
    assert_error(&mut err, XrayStatus::InvalidArgument, "range 0..=5");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_rejects_tun_runtime_profile_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::Throughput as libc::c_int,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "tun runtime profile must be set before config load",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_registers_dns_bootstrap_mode_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe {
        xray_core_set_dns_bootstrap_mode(
            core,
            XrayDnsBootstrapMode::StaticOnly as libc::c_int,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_rejects_invalid_dns_bootstrap_mode_discriminant() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_set_dns_bootstrap_mode(core, -1, &mut err) };

    assert_eq!(status, XrayStatus::InvalidArgument);
    assert_error(
        &mut err,
        XrayStatus::InvalidArgument,
        "0 (system) or 1 (static only)",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_rejects_dns_bootstrap_mode_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe {
        xray_core_set_dns_bootstrap_mode(
            core,
            XrayDnsBootstrapMode::StaticOnly as libc::c_int,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::RuntimeError);
    assert_error(
        &mut err,
        XrayStatus::RuntimeError,
        "DNS bootstrap mode must be set before config load",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[cfg(unix)]
#[test]
fn ffi_fd_tun_raw_ip_bridges_icmp_echo_reply() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let fds = socket_pair();
    set_nonblocking(fds[1].raw());

    let status = unsafe {
        xray_core_set_tun_fd(
            core,
            fds[0].raw(),
            XrayTunFdPacketFormat::RawIp as libc::c_int,
            XrayTunFdClosePolicy::Borrowed as libc::c_int,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let raw = CString::new(tun_config_with_freedom_outbound()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let request = ipv4_icmp_echo_request([10, 10, 0, 2], [10, 10, 0, 1], 0x1201, 7, b"ffi fd ping");
    write_fd(fds[1].raw(), &request);

    let reply = read_fd_until(fds[1].raw(), is_ipv4_icmp_echo_reply);
    assert_ipv4_icmp_echo_reply(
        &reply,
        [10, 10, 0, 1],
        [10, 10, 0, 2],
        0x1201,
        7,
        b"ffi fd ping",
    );

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[cfg(unix)]
#[test]
fn ffi_fd_tun_darwin_utun_bridges_icmp_echo_reply() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let fds = socket_pair();
    set_nonblocking(fds[1].raw());

    let status = unsafe {
        xray_core_set_tun_fd(
            core,
            fds[0].raw(),
            XrayTunFdPacketFormat::DarwinUtun as libc::c_int,
            XrayTunFdClosePolicy::Borrowed as libc::c_int,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let raw = CString::new(tun_config_with_freedom_outbound()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let request = ipv4_icmp_echo_request([10, 10, 0, 2], [10, 10, 0, 1], 0x1202, 8, b"utun ping");
    write_fd(fds[1].raw(), &darwin_utun_ipv4_packet(&request));

    let reply = read_fd_until(fds[1].raw(), is_darwin_utun_ipv4_icmp_echo_reply);
    assert_eq!(&reply[..4], &[0, 0, 0, libc::AF_INET as u8]);
    assert_ipv4_icmp_echo_reply(
        &reply[4..],
        [10, 10, 0, 1],
        [10, 10, 0, 2],
        0x1202,
        8,
        b"utun ping",
    );

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_push_packet_updates_stats() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let packet = [0x45, 0, 0, 20];

    let status = unsafe { xray_tun_push_packet(core, packet.as_ptr(), packet.len(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let mut stats = XrayTunStats::default();
    let status = unsafe { xray_tun_stats(core, &mut stats, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(stats.inbound_packets, 1);
    assert_eq!(stats.outbound_packets, 0);
    assert_eq!(stats.dropped_packets, 0);
    assert_eq!(stats.inbound_dropped_packets, 0);
    assert_eq!(stats.outbound_dropped_packets, 0);
    assert_eq!(stats.tcp_stack_to_remote_bytes, 0);
    assert_eq!(stats.tcp_remote_written_bytes, 0);
    assert_eq!(stats.tcp_remote_read_bytes, 0);
    assert_eq!(stats.tcp_backpressure_events, 0);
    assert_eq!(stats.tcp_stack_to_remote_backpressure_events, 0);
    assert_eq!(stats.tcp_remote_to_stack_backpressure_events, 0);
    assert_eq!(stats.tcp_remote_write_batches, 0);
    assert_eq!(stats.tcp_remote_write_batch_messages, 0);
    assert_eq!(stats.tcp_remote_write_batch_max_messages, 0);
    assert_eq!(stats.tcp_remote_write_batch_max_bytes, 0);
    assert_eq!(stats.tcp_remote_write_wait_events, 0);
    assert_eq!(stats.tcp_remote_write_wait_ms_total, 0);
    assert_eq!(stats.tcp_remote_write_wait_ms_max, 0);
    assert_eq!(stats.tcp_remote_flush_wait_events, 0);
    assert_eq!(stats.tcp_remote_flush_wait_ms_total, 0);
    assert_eq!(stats.tcp_remote_flush_wait_ms_max, 0);
    assert_eq!(stats.tcp_pending_remote_bytes, 0);
    assert_eq!(stats.tcp_pending_remote_flows, 0);
    assert_eq!(stats.tcp_pending_remote_max_bytes, 0);
    assert_eq!(stats.tcp_pending_upload_bytes, 0);
    assert_eq!(stats.tcp_pending_upload_max_bytes, 0);
    assert_eq!(stats.tcp_pending_total_bytes, 0);
    assert_eq!(stats.tcp_remote_buffer_limit_bytes, 0);
    assert_eq!(stats.tcp_buffer_hard_limit_bytes, 0);
    assert_eq!(stats.tcp_remote_buffer_pressure_active, 0);
    assert_eq!(stats.tcp_remote_write_errors, 0);
    assert_eq!(stats.tcp_remote_closed_events, 0);
    assert_eq!(stats.tcp_remote_read_errors, 0);
    assert_eq!(stats.tcp_open_errors, 0);
    assert_eq!(stats.udp_remote_open_events, 0);
    assert_eq!(stats.udp_remote_udp443_open_events, 0);
    assert_eq!(stats.udp_remote_written_bytes, 0);
    assert_eq!(stats.udp_remote_read_bytes, 0);
    assert_eq!(stats.inbound_queue_depth, 1024);
    assert_eq!(stats.outbound_queue_depth, 4096);
    assert_eq!(stats.inbound_queue_max_packets, 1);
    assert_eq!(stats.outbound_queue_max_packets, 0);
    assert_eq!(stats.tun_fd_write_batches, 0);
    assert_eq!(stats.tun_fd_write_batch_packets, 0);
    assert_eq!(stats.tun_fd_write_batch_max_packets, 0);
    assert_eq!(stats.tun_fd_read_loop_exits, 0);
    assert_eq!(stats.tun_fd_write_loop_exits, 0);
    assert_eq!(stats.tun_fd_transient_io_errors, 0);

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_stats_accepts_legacy_v1_prefix_without_overwriting_tail() {
    const LEGACY_COUNTER_COUNT: usize = 69;
    const GUARD: [u64; 3] = [
        0xa5a5_a5a5_a5a5_a5a5,
        0x5a5a_5a5a_5a5a_5a5a,
        0x0123_4567_89ab_cdef,
    ];

    #[repr(C)]
    struct LegacyXrayTunStats {
        struct_size: usize,
        counters: [u64; LEGACY_COUNTER_COUNT],
    }

    #[repr(C)]
    struct GuardedLegacyXrayTunStats {
        stats: LegacyXrayTunStats,
        guard: [u64; 3],
    }

    let legacy_size = std::mem::size_of::<LegacyXrayTunStats>();
    let current_size = std::mem::size_of::<XrayTunStats>();
    assert_eq!(
        legacy_size,
        std::mem::offset_of!(XrayTunStats, tun_fd_read_loop_exits)
    );
    assert_eq!(current_size, legacy_size + 3 * std::mem::size_of::<u64>());
    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(legacy_size, 560);
        assert_eq!(current_size, 584);
    }

    let mut guarded = GuardedLegacyXrayTunStats {
        stats: LegacyXrayTunStats {
            struct_size: legacy_size,
            counters: [u64::MAX; LEGACY_COUNTER_COUNT],
        },
        guard: GUARD,
    };
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe {
        xray_tun_stats(
            core,
            std::ptr::from_mut(&mut guarded.stats).cast::<XrayTunStats>(),
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());
    assert_eq!(guarded.stats.struct_size, legacy_size);
    assert_eq!(guarded.stats.counters[0], 0);
    assert_eq!(guarded.guard, GUARD);

    // `struct_size` is both the compatibility discriminator and the caller's
    // allocation bound. A legacy host commonly reuses one stats object for
    // every polling interval, so the first call must not replace 560 with the
    // current 584 and turn the second call into an out-of-bounds write.
    guarded.stats.counters.fill(u64::MAX);
    let status = unsafe {
        xray_tun_stats(
            core,
            std::ptr::from_mut(&mut guarded.stats).cast::<XrayTunStats>(),
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());
    assert_eq!(guarded.stats.struct_size, legacy_size);
    assert_eq!(guarded.stats.counters[0], 0);
    assert_eq!(guarded.guard, GUARD);

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_stats_writes_only_current_prefix_of_larger_layout() {
    const EXTENSION: [u64; 3] = [
        0xfedc_ba98_7654_3210,
        0x1122_3344_5566_7788,
        0x8877_6655_4433_2211,
    ];

    #[repr(C)]
    struct ExtendedXrayTunStats {
        current: XrayTunStats,
        extension: [u64; 3],
    }

    let mut extended = ExtendedXrayTunStats {
        current: XrayTunStats {
            struct_size: std::mem::size_of::<ExtendedXrayTunStats>(),
            ..XrayTunStats::default()
        },
        extension: EXTENSION,
    };
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe { xray_tun_stats(core, &mut extended.current, &mut err) };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());
    assert_eq!(
        extended.current.struct_size,
        std::mem::size_of::<ExtendedXrayTunStats>()
    );
    assert_eq!(extended.extension, EXTENSION);

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_push_packet_rejects_null_data() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe { xray_tun_push_packet(core, std::ptr::null(), 20, &mut err) };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(&mut err, XrayStatus::NullArgument, "packet data is null");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_push_packet_checks_mtu_before_reading_caller_memory() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let one_byte = 0_u8;

    let status = unsafe { xray_tun_push_packet(core, &one_byte, 65_536, &mut err) };

    assert_eq!(status, XrayStatus::InvalidArgument);
    assert_error(&mut err, XrayStatus::InvalidArgument, "exceeds mtu");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_stats_rejects_unversioned_output_buffer_before_writing() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut stats = XrayTunStats {
        struct_size: 0,
        inbound_packets: 42,
        ..XrayTunStats::default()
    };

    let status = unsafe { xray_tun_stats(core, &mut stats, &mut err) };

    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_eq!(stats.inbound_packets, 42);
    assert_error(&mut err, XrayStatus::BufferTooSmall, "at least");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_packet_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut written = 7usize;
    let mut buffer = [0_u8; 1500];

    let status = unsafe {
        xray_tun_poll_packet(
            core,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_packet_retains_packet_when_buffer_is_too_small() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let raw = CString::new(tun_config_with_freedom_outbound()).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok,
        "load error: {}",
        error_message(err)
    );
    assert_eq!(
        unsafe { xray_core_start(core, &mut err) },
        XrayStatus::Ok,
        "start error: {}",
        error_message(err)
    );

    let request =
        ipv4_icmp_echo_request([10, 10, 0, 2], [10, 10, 0, 1], 0x1204, 9, b"retained reply");
    assert_eq!(
        unsafe { xray_tun_push_packet(core, request.as_ptr(), request.len(), &mut err) },
        XrayStatus::Ok
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut required = 0usize;
    let mut too_small = [0_u8; 1];
    loop {
        let status = unsafe {
            xray_tun_poll_packet(
                core,
                too_small.as_mut_ptr(),
                too_small.len(),
                &mut required,
                &mut err,
            )
        };
        if status == XrayStatus::BufferTooSmall {
            break;
        }
        assert_eq!(status, XrayStatus::NoPacket);
        assert!(
            Instant::now() < deadline,
            "timed out waiting for ICMP echo reply"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(required > too_small.len());
    assert_error(
        &mut err,
        XrayStatus::BufferTooSmall,
        "exceeds output buffer length",
    );

    let mut reply = vec![0_u8; required];
    let mut written = 0usize;
    let status = unsafe {
        xray_tun_poll_packet(
            core,
            reply.as_mut_ptr(),
            reply.len(),
            &mut written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(written, required);
    assert!(err.is_null());
    assert_ipv4_icmp_echo_reply(
        &reply[..written],
        [10, 10, 0, 1],
        [10, 10, 0, 2],
        0x1204,
        9,
        b"retained reply",
    );

    let batched_request = ipv4_icmp_echo_request(
        [10, 10, 0, 2],
        [10, 10, 0, 1],
        0x1205,
        10,
        b"retained for batch",
    );
    assert_eq!(
        unsafe {
            xray_tun_push_packet(
                core,
                batched_request.as_ptr(),
                batched_request.len(),
                &mut err,
            )
        },
        XrayStatus::Ok
    );
    let mut batched_required = 0usize;
    let batched_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let status = unsafe {
            xray_tun_poll_packet(
                core,
                too_small.as_mut_ptr(),
                too_small.len(),
                &mut batched_required,
                &mut err,
            )
        };
        if status == XrayStatus::BufferTooSmall {
            break;
        }
        assert_eq!(status, XrayStatus::NoPacket);
        assert!(
            Instant::now() < batched_deadline,
            "timed out waiting for second ICMP echo reply"
        );
        thread::sleep(Duration::from_millis(5));
    }

    let mut batch_buffer = vec![0_u8; 1_500];
    let mut batch_length = 0usize;
    let mut packet_count = 0usize;
    let status = unsafe {
        xray_tun_poll_packets(
            core,
            batch_buffer.as_mut_ptr(),
            batch_buffer.len(),
            &mut batch_length,
            1,
            &mut packet_count,
            0,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(packet_count, 1);
    assert_eq!(batch_length, batched_required);
    assert_ipv4_icmp_echo_reply(
        &batch_buffer[..batch_length],
        [10, 10, 0, 1],
        [10, 10, 0, 2],
        0x1205,
        10,
        b"retained for batch",
    );

    assert_eq!(
        unsafe { xray_core_stop(core, &mut err) },
        XrayStatus::Ok,
        "stop error: {}",
        error_message(err)
    );
    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_packets_returns_batched_echo_replies() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let raw = CString::new(tun_config_with_freedom_outbound()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    for sequence in 0..3u16 {
        let request = ipv4_icmp_echo_request(
            [10, 10, 0, 2],
            [10, 10, 0, 1],
            0x1203,
            sequence,
            b"batch ping",
        );
        let status =
            unsafe { xray_tun_push_packet(core, request.as_ptr(), request.len(), &mut err) };
        assert_eq!(status, XrayStatus::Ok);
    }

    let mut buffer = vec![0u8; 3 * 1500];
    let mut lengths = vec![0usize; 3];
    let mut count = 0usize;
    let status = unsafe {
        xray_tun_poll_packets(
            core,
            buffer.as_mut_ptr(),
            buffer.len(),
            lengths.as_mut_ptr(),
            3,
            &mut count,
            1_000,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());
    assert!((1..=3).contains(&count), "unexpected packet count {count}");
    let mut offset = 0;
    for length in &lengths[..count] {
        assert!(*length > 0);
        assert!(is_ipv4_icmp_echo_reply(&buffer[offset..offset + length]));
        offset += length;
    }

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_packets_reports_no_packet_without_waiting() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut buffer = vec![0u8; 1500];
    let mut lengths = vec![0usize; 4];
    let mut count = 7usize;

    let status = unsafe {
        xray_tun_poll_packets(
            core,
            buffer.as_mut_ptr(),
            buffer.len(),
            lengths.as_mut_ptr(),
            4,
            &mut count,
            0,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(count, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_packets_rejects_buffer_below_mtu() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut buffer = vec![0u8; 128];
    let mut lengths = vec![0usize; 4];
    let mut count = 0usize;

    let status = unsafe {
        xray_tun_poll_packets(
            core,
            buffer.as_mut_ptr(),
            buffer.len(),
            lengths.as_mut_ptr(),
            4,
            &mut count,
            0,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_eq!(count, 0);
    unsafe {
        xray_error_free(err);
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_slow_flow_event_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayTcpSlowFlowEvent::default();
    let mut target = [0_i8; 256];
    let mut written = 7usize;

    let status = unsafe {
        xray_tun_poll_tcp_slow_flow_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_udp_slow_flow_event_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayUdpSlowFlowEvent::default();
    let mut target = [0_i8; 256];
    let mut written = 7usize;

    let status = unsafe {
        xray_tun_poll_udp_slow_flow_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_udp_response_gap_event_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayUdpResponseGapEvent::default();
    let mut target = [0_i8; 256];
    let mut written = 7usize;

    let status = unsafe {
        xray_tun_poll_udp_response_gap_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_udp_quic_blocked_event_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayUdpQuicBlockedEvent::default();
    let mut target = [0_i8; 256];
    let mut written = 7usize;

    let status = unsafe {
        xray_tun_poll_udp_quic_blocked_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_flow_summary_event_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayTcpFlowSummaryEvent::default();
    let mut target = [0_i8; 256];
    let mut outbound = [0_i8; 64];
    let mut written = 7usize;
    let mut outbound_written = 9usize;

    let status = unsafe {
        xray_tun_poll_tcp_flow_summary_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert_eq!(outbound_written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_open_error_event_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayTcpOpenErrorEvent::default();
    let mut target = [0_i8; 256];
    let mut outbound = [0_i8; 64];
    let mut message = [0_i8; 512];
    let mut written = 7usize;
    let mut outbound_written = 9usize;
    let mut message_written = 11usize;

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            &mut message_written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert_eq!(outbound_written, 0);
    assert_eq!(message_written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_open_error_event_rejects_null_handle_before_other_arguments() {
    let mut err = std::ptr::null_mut();
    let mut target = [0x7f_i8; 8];
    let mut written = 7usize;

    // Every other argument is also invalid; the handle check must still win.
    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            target.as_mut_ptr(),
            0,
            &mut written,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(&mut err, XrayStatus::NullArgument, "core handle is null");
    assert_eq!(written, 0, "written is reset even when validation fails");
    assert_eq!(target[0], 0x7f, "zero-length buffers are never written to");
}

#[test]
fn ffi_tun_poll_tcp_open_error_event_rejects_null_event_pointer() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut target = [0x7f_i8; 8];
    let mut outbound = [0x7f_i8; 8];
    let mut message = [0x7f_i8; 8];
    let mut written = 7usize;
    let mut outbound_written = 9usize;
    let mut message_written = 11usize;

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            std::ptr::null_mut(),
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            &mut message_written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "TCP open-error event pointer is null",
    );
    // Reset happened for every provided out-param before the failing check.
    assert_eq!((written, outbound_written, message_written), (0, 0, 0));
    assert_eq!((target[0], outbound[0], message[0]), (0, 0, 0));
    assert_eq!((target[1], outbound[1], message[1]), (0x7f, 0x7f, 0x7f));

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_open_error_event_rejects_null_string_arguments_in_order() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayTcpOpenErrorEvent::default();
    let mut target = [0_i8; 8];
    let mut outbound = [0_i8; 8];
    let mut message = [0_i8; 8];
    let mut written = 0usize;
    let mut outbound_written = 0usize;
    let mut message_written = 0usize;

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            std::ptr::null_mut(),
            target.len(),
            std::ptr::null_mut(),
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "TCP open-error target buffer is null",
    );

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            std::ptr::null_mut(),
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "TCP open-error target written pointer is null",
    );

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            std::ptr::null_mut(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            std::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "TCP open-error outbound tag buffer is null",
    );

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            std::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "TCP open-error message written pointer is null",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_open_error_event_checks_all_nulls_before_zero_lengths() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayTcpOpenErrorEvent::default();
    let mut target = [0_i8; 8];
    let mut message = [0_i8; 8];
    let mut written = 0usize;
    let mut outbound_written = 0usize;
    let mut message_written = 0usize;

    // A zero-length target comes first in parameter order, but a null
    // outbound-tag buffer must still be reported ahead of it.
    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            0,
            &mut written,
            std::ptr::null_mut(),
            8,
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "TCP open-error outbound tag buffer is null",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_open_error_event_rejects_zero_lengths_in_order() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayTcpOpenErrorEvent::default();
    let mut target = [0_i8; 8];
    let mut outbound = [0_i8; 8];
    let mut message = [0_i8; 8];
    let mut written = 0usize;
    let mut outbound_written = 0usize;
    let mut message_written = 0usize;

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            0,
            &mut written,
            outbound.as_mut_ptr(),
            0,
            &mut outbound_written,
            message.as_mut_ptr(),
            0,
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_error(
        &mut err,
        XrayStatus::BufferTooSmall,
        "TCP open-error target buffer length is zero",
    );

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            0,
            &mut outbound_written,
            message.as_mut_ptr(),
            0,
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_error(
        &mut err,
        XrayStatus::BufferTooSmall,
        "TCP open-error outbound tag buffer length is zero",
    );

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            0,
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_error(
        &mut err,
        XrayStatus::BufferTooSmall,
        "TCP open-error message buffer length is zero",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_open_error_event_validates_arguments_before_core_state() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let mut event = XrayTcpOpenErrorEvent::default();
    let mut target = [0_i8; 8];
    let mut outbound = [0_i8; 8];
    let mut message = [0_i8; 8];
    let mut written = 0usize;
    let mut outbound_written = 0usize;
    let mut message_written = 0usize;

    // No config loaded, but an invalid buffer argument is reported first.
    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            0,
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::BufferTooSmall);
    assert_error(
        &mut err,
        XrayStatus::BufferTooSmall,
        "TCP open-error target buffer length is zero",
    );

    let status = unsafe {
        xray_tun_poll_tcp_open_error_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            message.as_mut_ptr(),
            message.len(),
            &mut message_written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::CoreNotLoaded);
    assert_error(
        &mut err,
        XrayStatus::CoreNotLoaded,
        "core config is not loaded",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_udp_slow_flow_event_rejects_null_target_written_pointer() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayUdpSlowFlowEvent::default();
    let mut target = [0x7f_i8; 8];

    let status = unsafe {
        xray_tun_poll_udp_slow_flow_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            std::ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "slow-flow target written pointer is null",
    );
    assert_eq!(target[0], 0, "leading NUL is written before validation");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_packet_rejects_null_buffer_and_written_pointer() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut buffer = [0_u8; 16];
    let mut written = 7usize;

    let status = unsafe {
        xray_tun_poll_packet(
            core,
            std::ptr::null_mut(),
            buffer.len(),
            &mut written,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(&mut err, XrayStatus::NullArgument, "packet buffer is null");
    assert_eq!(written, 0);

    let status = unsafe {
        xray_tun_poll_packet(
            core,
            buffer.as_mut_ptr(),
            buffer.len(),
            std::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(
        &mut err,
        XrayStatus::NullArgument,
        "written pointer is null",
    );

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_tun_poll_tcp_remote_write_slow_event_reports_no_packet() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);
    let mut event = XrayTcpRemoteWriteSlowEvent::default();
    let mut target = [0_i8; 256];
    let mut outbound = [0_i8; 64];
    let mut written = 7usize;
    let mut outbound_written = 9usize;

    let status = unsafe {
        xray_tun_poll_tcp_remote_write_slow_event(
            core,
            &mut event,
            target.as_mut_ptr(),
            target.len(),
            &mut written,
            outbound.as_mut_ptr(),
            outbound.len(),
            &mut outbound_written,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(written, 0);
    assert_eq!(outbound_written, 0);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_reports_null_json_error() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_load_config_json(core, std::ptr::null(), &mut err) };

    assert_eq!(status, XrayStatus::NullArgument);
    assert_error(&mut err, XrayStatus::NullArgument, "config JSON is null");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_reports_invalid_utf8_error() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(vec![0xff]).unwrap();

    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };

    assert_eq!(status, XrayStatus::InvalidUtf8);
    assert_error(&mut err, XrayStatus::InvalidUtf8, "not valid UTF-8");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_reports_invalid_config_error() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new("{").unwrap();

    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };

    assert_eq!(status, XrayStatus::ConfigError);
    assert_error(&mut err, XrayStatus::ConfigError, "EOF");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_config_errors_do_not_echo_vless_credentials() {
    const SECRET_UUID: &str = "de305d54-75b4-431b-adb2-eb6b9e546014";
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(format!(
        r#"{{
          "inbounds": [{{"protocol":"socks","listen":"127.0.0.1","port":1080}}],
          "outbounds": [{{
            "protocol":"vless",
            "settings":{{"vnext":[{{"address":"example.test","port":443,"users":[{{"id":"{SECRET_UUID}","encryption":"none"}}]}}]}},
            "streamSettings":{{"network":"unsupported"}}
          }}]
        }}"#
    ))
    .unwrap();

    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };

    assert_eq!(status, XrayStatus::ConfigError);
    let rendered = error_message(err);
    assert!(!rendered.contains(SECRET_UUID));

    unsafe {
        xray_error_free(err);
        xray_core_free(core);
    }
}

#[test]
fn ffi_replaces_reused_error_pointer() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_load_config_json(core, std::ptr::null(), &mut err) };
    assert_eq!(status, XrayStatus::NullArgument);
    assert_error_message(err, "config JSON is null");

    let raw = CString::new("{").unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };

    assert_eq!(status, XrayStatus::ConfigError);
    assert_error(&mut err, XrayStatus::ConfigError, "EOF");

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_error_accessors_handle_null() {
    assert_eq!(unsafe { xray_error_code(std::ptr::null()) }, XrayStatus::Ok);
    assert!(unsafe { xray_error_message(std::ptr::null()) }.is_null());
}

fn assert_error(error: &mut *mut xray_ffi::XrayError, code: XrayStatus, message: &str) {
    assert_eq!(unsafe { xray_error_code(*error) }, code);
    assert_error_message(*error, message);

    unsafe {
        xray_error_free(*error);
    }
    *error = std::ptr::null_mut();
}

fn assert_error_message(error: *const xray_ffi::XrayError, message: &str) {
    let raw_message = unsafe { xray_error_message(error) };
    assert!(!raw_message.is_null());

    let actual = unsafe { CStr::from_ptr(raw_message) }.to_str().unwrap();
    assert!(
        actual.contains(message),
        "expected `{actual}` to contain `{message}`"
    );
}

fn error_message(error: *const xray_ffi::XrayError) -> String {
    let raw_message = unsafe { xray_error_message(error) };
    if raw_message.is_null() {
        return "none".to_owned();
    }

    unsafe { CStr::from_ptr(raw_message) }
        .to_string_lossy()
        .into_owned()
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn reserve_loopback_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind temporary loopback listener")
        .local_addr()
        .expect("read temporary loopback listener address")
        .port()
}

fn minimal_geosite_data() -> Vec<u8> {
    let code = b"TEST";
    let domain = b"example.test";
    let mut domain_message = vec![0x08, 0x02, 0x12, domain.len() as u8];
    domain_message.extend_from_slice(domain);
    let mut site_message = vec![0x0a, code.len() as u8];
    site_message.extend_from_slice(code);
    site_message.extend_from_slice(&[0x12, domain_message.len() as u8]);
    site_message.extend_from_slice(&domain_message);
    let mut data = vec![0x0a, site_message.len() as u8];
    data.extend_from_slice(&site_message);
    data
}

unsafe extern "C" fn record_socket_protect_call(
    _fd: libc::c_int,
    _user_data: *mut libc::c_void,
) -> libc::c_int {
    1
}

fn loaded_core(err: &mut *mut xray_ffi::XrayError) -> *mut xray_ffi::XrayCoreHandle {
    let core = unsafe { xray_core_new(err) };
    assert!(!core.is_null());
    assert!(err.is_null());

    let raw = CString::new(client_config_with_ephemeral_socks_port()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    core
}

fn client_config_with_ephemeral_socks_port() -> String {
    r#"{
      "inbounds": [
        {
          "tag": "socks-in",
          "protocol": "socks",
          "listen": "127.0.0.1",
          "port": 0,
          "settings": { "udp": false }
        }
      ],
      "outbounds": [
        {
          "tag": "proxy",
          "protocol": "vless",
          "settings": {
            "vnext": [
              {
                "address": "127.0.0.1",
                "port": 1,
                "users": [
                  { "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }
                ]
              }
            ]
          },
          "streamSettings": { "network": "tcp", "security": "none" }
        }
      ]
    }"#
    .to_owned()
}

fn client_config_with_freedom_outbound() -> String {
    r#"{
      "inbounds": [
        {
          "tag": "socks-in",
          "protocol": "socks",
          "listen": "127.0.0.1",
          "port": 0,
          "settings": { "udp": false }
        }
      ],
      "outbounds": [
        { "tag": "direct", "protocol": "freedom" }
      ]
    }"#
    .to_owned()
}

fn config_with_outbound_selector() -> String {
    r#"{
      "inbounds": [{
        "tag": "socks-in",
        "protocol": "socks",
        "listen": "127.0.0.1",
        "port": 0
      }],
      "outbounds": [
        {"tag": "proxy-b", "protocol": "freedom"},
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "proxy-a", "protocol": "freedom"}
      ],
      "routing": {
        "balancers": [{
          "tag": "automatic",
          "selector": ["proxy-"],
          "strategy": {"type": "roundRobin"},
          "fallbackTag": "direct"
        }],
        "rules": [{
          "type": "field",
          "network": "tcp",
          "balancerTag": "automatic"
        }]
      }
    }"#
    .to_owned()
}

type SnapshotJsonFn = unsafe extern "C" fn(
    *const xray_ffi::XrayCoreHandle,
    *mut libc::c_char,
    usize,
    *mut usize,
    *mut *mut xray_ffi::XrayError,
) -> XrayStatus;

fn read_snapshot_json(
    core: *mut xray_ffi::XrayCoreHandle,
    snapshot: SnapshotJsonFn,
    error: &mut *mut xray_ffi::XrayError,
) -> serde_json::Value {
    let mut required = 0;
    assert_eq!(
        unsafe { snapshot(core, std::ptr::null_mut(), 0, &mut required, error) },
        XrayStatus::Ok,
        "snapshot size error: {}",
        error_message(*error)
    );
    let mut buffer = vec![0 as libc::c_char; required + 1];
    let mut written = 0;
    assert_eq!(
        unsafe { snapshot(core, buffer.as_mut_ptr(), buffer.len(), &mut written, error,) },
        XrayStatus::Ok,
        "snapshot read error: {}",
        error_message(*error)
    );
    assert_eq!(written, required);
    serde_json::from_slice(
        &buffer[..written]
            .iter()
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>(),
    )
    .expect("valid snapshot JSON")
}

fn config_with_wildcard_listen_warning() -> String {
    r#"{
      "inbounds": [
        {
          "tag": "socks-in",
          "protocol": "socks",
          "listen": "0.0.0.0",
          "port": 0,
          "settings": { "udp": false, "allowUnauthenticatedLan": true }
        }
      ],
      "outbounds": [
        {
          "tag": "proxy",
          "protocol": "vless",
          "settings": {
            "vnext": [
              {
                "address": "example.com",
                "port": 443,
                "users": [
                  { "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }
                ]
              }
            ]
          },
          "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
              "serverName": "example.com"
            }
          }
        }
      ]
    }"#
    .to_owned()
}

fn tun_config_with_freedom_outbound() -> String {
    r#"{
      "inbounds": [
        {
          "tag": "tun-in",
          "protocol": "tun",
          "listen": "127.0.0.1",
          "port": 0,
          "settings": {}
        }
      ],
      "outbounds": [
        { "tag": "direct", "protocol": "freedom" }
      ]
    }"#
    .to_owned()
}

fn tun_config_without_port_with_freedom_outbound() -> String {
    r#"{
      "inbounds": [
        {
          "tag": "tun-in",
          "protocol": "tun",
          "settings": { "userLevel": 0 }
        }
      ],
      "outbounds": [
        { "tag": "direct", "protocol": "freedom" }
      ]
    }"#
    .to_owned()
}

struct StartupProbeServer {
    addr: SocketAddr,
    result: mpsc::Receiver<Result<(), String>>,
    join: thread::JoinHandle<()>,
}

impl StartupProbeServer {
    fn wait(self) {
        let result = self
            .result
            .recv_timeout(Duration::from_secs(3))
            .expect("startup probe server did not report a result");
        self.join
            .join()
            .expect("startup probe server thread panicked");
        result.expect("startup probe server reported an error");
    }
}

fn spawn_startup_probe_server_once() -> StartupProbeServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind startup probe server");
    listener
        .set_nonblocking(true)
        .expect("set startup probe server nonblocking");
    let addr = listener
        .local_addr()
        .expect("read startup probe server local addr");
    let (tx, rx) = mpsc::channel();

    let join = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Err(err) = stream.set_read_timeout(Some(Duration::from_secs(2))) {
                        let _ = tx.send(Err(format!("failed to set probe read timeout: {err}")));
                        return;
                    }
                    let mut request = Vec::new();
                    let mut chunk = [0_u8; 256];
                    loop {
                        let read = match stream.read(&mut chunk) {
                            Ok(read) => read,
                            Err(err) => {
                                let _ =
                                    tx.send(Err(format!("failed to read probe request: {err}")));
                                return;
                            }
                        };
                        if read == 0 {
                            let _ = tx.send(Err(
                                "probe connection closed before full HTTP headers".to_owned(),
                            ));
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                        if request.len() > 4096 {
                            let _ = tx
                                .send(Err("probe request headers exceeded 4096 bytes".to_owned()));
                            return;
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    if !request.starts_with("GET /health HTTP/1.1\r\n") {
                        let _ = tx.send(Err(format!("unexpected probe request: {request:?}")));
                        return;
                    }
                    if let Err(err) =
                        stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    {
                        let _ = tx.send(Err(format!("failed to write probe response: {err}")));
                        return;
                    }
                    let _ = tx.send(Ok(()));
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        let _ = tx.send(Err("timed out waiting for startup probe".to_owned()));
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    let _ = tx.send(Err(format!("failed to accept probe connection: {err}")));
                    return;
                }
            }
        }
    });

    StartupProbeServer {
        addr,
        result: rx,
        join,
    }
}

#[cfg(unix)]
struct FdGuard(libc::c_int);

#[cfg(unix)]
impl FdGuard {
    fn raw(&self) -> libc::c_int {
        self.0
    }
}

#[cfg(unix)]
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(unix)]
fn socket_pair() -> [FdGuard; 2] {
    let mut fds = [-1; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(
        rc,
        0,
        "socketpair failed: {}",
        std::io::Error::last_os_error()
    );
    [FdGuard(fds[0]), FdGuard(fds[1])]
}

#[cfg(unix)]
fn pipe_pair() -> [FdGuard; 2] {
    let mut fds = [-1; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe failed: {}", std::io::Error::last_os_error());
    [FdGuard(fds[0]), FdGuard(fds[1])]
}

#[cfg(unix)]
fn dup_fd(fd: libc::c_int) -> libc::c_int {
    let duplicated = unsafe { libc::dup(fd) };
    assert!(
        duplicated >= 0,
        "dup failed: {}",
        std::io::Error::last_os_error()
    );
    duplicated
}

#[cfg(unix)]
fn fd_is_open(fd: libc::c_int) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

#[cfg(unix)]
fn set_nonblocking(fd: libc::c_int) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(
        flags >= 0,
        "F_GETFL failed: {}",
        std::io::Error::last_os_error()
    );
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_eq!(rc, 0, "F_SETFL failed: {}", std::io::Error::last_os_error());
}

#[cfg(unix)]
fn write_fd(fd: libc::c_int, packet: &[u8]) {
    let written = unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) };
    assert_eq!(
        written,
        packet.len() as libc::ssize_t,
        "write failed: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(unix)]
fn read_fd_until(fd: libc::c_int, mut predicate: impl FnMut(&[u8]) -> bool) -> Vec<u8> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut buffer = vec![0_u8; 65_535];

    loop {
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read > 0 {
            let packet = &buffer[..read as usize];
            if predicate(packet) {
                return packet.to_vec();
            }
        } else {
            let err = std::io::Error::last_os_error();
            assert!(
                err.kind() == std::io::ErrorKind::WouldBlock,
                "read failed: {err}"
            );
        }

        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for fd TUN packet"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn ipv4_icmp_echo_request(
    source: [u8; 4],
    destination: [u8; 4],
    ident: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let icmp = &mut packet[20..];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let icmp_checksum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

fn is_ipv4_icmp_echo_reply(packet: &[u8]) -> bool {
    packet.len() >= 28 && packet[0] >> 4 == 4 && packet[9] == 1 && packet[20] == 0
}

#[cfg(unix)]
fn darwin_utun_ipv4_packet(packet: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(4 + packet.len());
    encoded.extend_from_slice(&[0, 0, 0, libc::AF_INET as u8]);
    encoded.extend_from_slice(packet);
    encoded
}

#[cfg(unix)]
fn is_darwin_utun_ipv4_icmp_echo_reply(packet: &[u8]) -> bool {
    packet.len() > 4
        && packet[..4] == [0, 0, 0, libc::AF_INET as u8]
        && is_ipv4_icmp_echo_reply(&packet[4..])
}

fn assert_ipv4_icmp_echo_reply(
    packet: &[u8],
    source: [u8; 4],
    destination: [u8; 4],
    ident: u16,
    sequence: u16,
    payload: &[u8],
) {
    assert_eq!(packet[0] >> 4, 4);
    assert_eq!(packet[9], 1);
    assert_eq!(&packet[12..16], &source);
    assert_eq!(&packet[16..20], &destination);
    assert_eq!(internet_checksum(&packet[..20]), 0);

    let icmp = &packet[20..];
    assert_eq!(icmp[0], 0);
    assert_eq!(icmp[1], 0);
    assert_eq!(internet_checksum(icmp), 0);
    assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), ident);
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), sequence);
    assert_eq!(&icmp[8..], payload);
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
