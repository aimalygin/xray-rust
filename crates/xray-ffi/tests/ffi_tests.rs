use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new,
    xray_core_set_socket_protect_callback, xray_core_set_startup_probe,
    xray_core_set_tun_collect_tcp_timings, xray_core_set_tun_fd, xray_core_set_tun_runtime_profile,
    xray_core_start, xray_core_stop, xray_error_code, xray_error_free, xray_error_message,
    xray_tun_poll_packet, xray_tun_poll_packets, xray_tun_poll_tcp_flow_summary_event,
    xray_tun_poll_tcp_open_error_event, xray_tun_poll_tcp_remote_write_slow_event,
    xray_tun_poll_tcp_slow_flow_event, xray_tun_poll_udp_quic_blocked_event,
    xray_tun_poll_udp_response_gap_event, xray_tun_poll_udp_slow_flow_event, xray_tun_push_packet,
    xray_tun_stats, XrayStatus, XrayTcpFlowSummaryEvent, XrayTcpOpenErrorEvent,
    XrayTcpRemoteWriteSlowEvent, XrayTcpSlowFlowEvent, XrayTunFdClosePolicy, XrayTunFdPacketFormat,
    XrayTunRuntimeProfile, XrayTunStats, XrayUdpQuicBlockedEvent, XrayUdpResponseGapEvent,
    XrayUdpSlowFlowEvent,
};

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
fn ffi_startup_probe_setter_accepts_url_timeout_and_tag_before_config_load() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let url = CString::new("https://www.google.com/generate_204").unwrap();
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
    let url = CString::new("https://www.google.com/generate_204").unwrap();

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
    let url = CString::new("https://www.google.com/generate_204").unwrap();

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
    let url = CString::new("https://www.google.com/generate_204").unwrap();
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
    let url = CString::new("https://www.google.com/generate_204").unwrap();

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
            XrayTunFdPacketFormat::RawIp,
            XrayTunFdClosePolicy::Borrowed,
            &mut err,
        )
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

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
            XrayTunFdPacketFormat::RawIp,
            XrayTunFdClosePolicy::Borrowed,
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
        xray_core_set_tun_runtime_profile(core, XrayTunRuntimeProfile::LowMemory, &mut err)
    };

    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
    }
}

#[test]
fn ffi_rejects_tun_runtime_profile_after_config_load() {
    let mut err = std::ptr::null_mut();
    let core = loaded_core(&mut err);

    let status = unsafe {
        xray_core_set_tun_runtime_profile(core, XrayTunRuntimeProfile::Throughput, &mut err)
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
            XrayTunFdPacketFormat::RawIp,
            XrayTunFdClosePolicy::Borrowed,
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
            XrayTunFdPacketFormat::DarwinUtun,
            XrayTunFdClosePolicy::Borrowed,
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
    assert_eq!(stats.tcp_remote_buffer_limit_bytes, 0);
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
