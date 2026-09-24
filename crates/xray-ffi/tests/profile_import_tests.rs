use std::ffi::{CStr, CString};
use std::ptr;

use serde_json::{json, Value};
use xray_ffi::*;

const HY: &str = include_str!("../../../tests/fixtures/profile-import/hysteria2.txt");
const WG: &str = include_str!("../../../tests/fixtures/profile-import/wireguard.conf");

fn request(format: &str, text: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"format":format,"text":text})).unwrap()
}

fn import(input: &[u8]) -> Value {
    let mut written = 0;
    let mut error = ptr::null_mut();
    unsafe {
        assert_eq!(
            xray_profile_import_json(
                input.as_ptr(),
                input.len(),
                ptr::null_mut(),
                0,
                &mut written,
                &mut error
            ),
            XrayStatus::Ok
        );
        assert!(error.is_null());
        assert!(written > 0 && written <= 256 * 1024);
        let required = written;
        let mut short = vec![0x55u8; required];
        assert_eq!(
            xray_profile_import_json(
                input.as_ptr(),
                input.len(),
                short.as_mut_ptr().cast(),
                short.len(),
                &mut written,
                &mut error
            ),
            XrayStatus::BufferTooSmall
        );
        assert_eq!(written, required);
        assert!(short.iter().all(|&b| b == 0x55));
        xray_error_free(error);
        error = ptr::null_mut();
        let mut output = vec![0x55u8; required + 2];
        assert_eq!(
            xray_profile_import_json(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr().cast(),
                required + 1,
                &mut written,
                &mut error
            ),
            XrayStatus::Ok
        );
        assert!(error.is_null());
        assert_eq!(written, required);
        assert_eq!(output[required], 0);
        assert_eq!(output[required + 1], 0x55);
        serde_json::from_slice(&output[..written]).unwrap()
    }
}

#[test]
fn ffi_imports_both_formats_with_exact_sizing_and_loadable_configs() {
    for (format, text) in [("hysteria2", HY), ("wireguard", WG)] {
        let result = import(&request(format, text));
        assert_eq!(result["schemaVersion"], 1);
        let config = CString::new(result["configJSON"].as_str().unwrap()).unwrap();
        unsafe {
            let mut error = ptr::null_mut();
            let core = xray_core_new(&mut error);
            assert!(!core.is_null());
            assert_eq!(
                xray_core_load_config_json(core, config.as_ptr(), &mut error),
                XrayStatus::Ok
            );
            assert!(error.is_null());
            xray_core_free(core);
        }
    }
}

fn rejected(input: &[u8], expected: XrayStatus) {
    let mut error = ptr::null_mut();
    let mut written = 999;
    let mut output = [0x55u8; 16];
    unsafe {
        assert_eq!(
            xray_profile_import_json(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr().cast(),
                output.len(),
                &mut written,
                &mut error
            ),
            expected
        );
        assert_eq!(written, 0);
        assert_eq!(output, [0x55; 16]);
        assert_eq!(xray_error_code(error), expected);
        let message = CStr::from_ptr(xray_error_message(error)).to_str().unwrap();
        assert!(message.len() < 160);
        assert!(!message.contains("secret"));
        assert!(!message.contains("QkJC"));
        xray_error_free(error);
    }
}

#[test]
fn ffi_rejects_invalid_utf8_embedded_nul_and_oversized_requests() {
    rejected(&[0xff], XrayStatus::InvalidUtf8);
    rejected(b"{}\0secret", XrayStatus::ConfigError);
    rejected(
        &request("hysteria2", "hy2://secret%00@server.example"),
        XrayStatus::ConfigError,
    );
    rejected(
        &request("hysteria2", &"secret".repeat(12000)),
        XrayStatus::ConfigError,
    );
    rejected(&vec![b' '; 256 * 1024 + 1], XrayStatus::InvalidArgument);
}

#[test]
fn ffi_checks_pointers_and_span_limit_before_reading_input() {
    let input = request("hysteria2", HY);
    let mut written = 999;
    unsafe {
        assert_eq!(
            xray_profile_import_json(
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &mut written,
                ptr::null_mut()
            ),
            XrayStatus::NullArgument
        );
        assert_eq!(written, 0);
        assert_eq!(
            xray_profile_import_json(
                input.as_ptr(),
                input.len(),
                ptr::null_mut(),
                1,
                &mut written,
                ptr::null_mut()
            ),
            XrayStatus::NullArgument
        );
        assert_eq!(
            xray_profile_import_json(
                input.as_ptr(),
                input.len(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut()
            ),
            XrayStatus::NullArgument
        );
        // No readable allocation of the declared oversized span: the limit must
        // be checked before constructing or dereferencing an input slice.
        assert_eq!(
            xray_profile_import_json(
                ptr::NonNull::<u8>::dangling().as_ptr(),
                usize::MAX,
                ptr::null_mut(),
                0,
                &mut written,
                ptr::null_mut()
            ),
            XrayStatus::InvalidArgument
        );
    }
}

#[test]
fn ffi_rejects_crypto_invalid_peers_before_returning_a_profile() {
    let first_key = WG
        .lines()
        .find_map(|l| l.strip_prefix("PublicKey = "))
        .unwrap();
    for key in [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "secret",
        "ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWU=",
    ] {
        // Third key duplicates the second peer's identity.
        rejected(
            &request("wireguard", &WG.replacen(first_key, key, 1)),
            XrayStatus::ConfigError,
        );
    }
}

#[test]
fn ffi_import_is_handle_free_and_thread_safe() {
    let threads: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                let (format, source) = if i % 2 == 0 {
                    ("hysteria2", HY)
                } else {
                    ("wireguard", WG)
                };
                import(&request(format, source))
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap()["schemaVersion"], 1);
    }
}
