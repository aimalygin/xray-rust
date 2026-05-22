use std::ffi::{CStr, CString};

use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new, xray_core_start, xray_core_stop,
    xray_error_code, xray_error_free, xray_error_message, xray_tun_poll_packet,
    xray_tun_push_packet, xray_tun_stats, XrayStatus, XrayTunStats,
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
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

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
