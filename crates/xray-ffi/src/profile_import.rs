use super::*;
use xray_config::profile_import::{import_request, MAX_REQUEST_BYTES};

/// Offline, bounded profile import. See the C header for the request/result
/// schema, limits and capability requirements. Does not create a runtime.
///
/// # Safety
/// `request_json` points to `request_len` readable bytes. `buffer`, when nonnull,
/// points to `buffer_len` writable bytes, disjoint from the request and `written`.
/// `written` points to one writable `usize`. `error`, when nonnull, points to an
/// initialized error slot following the usual FFI ownership contract.
#[no_mangle]
pub unsafe extern "C" fn xray_profile_import_json(
    request_json: *const u8,
    request_len: usize,
    buffer: *mut c_char,
    buffer_len: usize,
    written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            import_inner(
                request_json,
                request_len,
                buffer,
                buffer_len,
                written,
                error,
            )
        })
    }
}

unsafe fn import_inner(
    request_json: *const u8,
    request_len: usize,
    buffer: *mut c_char,
    buffer_len: usize,
    written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }
    if !written.is_null() {
        unsafe {
            *written = 0;
        }
    }
    if written.is_null() || request_json.is_null() || (buffer.is_null() && buffer_len != 0) {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "profile import pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    // Check the declared span limit before constructing a slice or reading it.
    if request_len > MAX_REQUEST_BYTES {
        unsafe {
            set_error(
                error,
                XrayStatus::InvalidArgument,
                "profile import request exceeds 256 KiB",
            );
        }
        return XrayStatus::InvalidArgument;
    }
    let input = unsafe { slice::from_raw_parts(request_json, request_len) };
    let Ok(input) = std::str::from_utf8(input) else {
        unsafe {
            set_error(
                error,
                XrayStatus::InvalidUtf8,
                "profile import request must be UTF-8",
            );
        }
        return XrayStatus::InvalidUtf8;
    };
    let profile = match import_request(input) {
        Ok(profile) => profile,
        Err(e) => {
            unsafe {
                set_error(error, XrayStatus::ConfigError, e.to_string());
            }
            return XrayStatus::ConfigError;
        }
    };
    // Core construction validates crypto identities and typed outbound policy.
    // It does not start workers, listeners, DNS queries or protocol connections.
    let valid = parse_xray_json(&profile.config_json)
        .ok()
        .is_some_and(|parsed| Core::new(parsed.config).is_ok());
    if !valid {
        unsafe {
            set_error(
                error,
                XrayStatus::ConfigError,
                "imported profile failed runtime configuration validation",
            );
        }
        return XrayStatus::ConfigError;
    }
    match profile.to_json() {
        Ok(json) => unsafe {
            write_utf8_output(
                &json,
                "imported profile",
                buffer,
                buffer_len,
                written,
                error,
            )
        },
        Err(e) => {
            unsafe {
                set_error(error, XrayStatus::ConfigError, e.to_string());
            }
            XrayStatus::ConfigError
        }
    }
}
