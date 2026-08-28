#![no_main]

use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new, xray_core_start, xray_core_stop,
    xray_error_free, XrayCoreHandle, XrayError,
};

const SAFE_CONFIG: &str =
    r#"{"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}"#;

fn clear_error(error: &mut *mut XrayError) {
    unsafe {
        xray_error_free(*error);
    }
    *error = std::ptr::null_mut();
}

fn run_operation(
    operation: u8,
    handle: *mut XrayCoreHandle,
    json: &CString,
    error: &mut *mut XrayError,
) {
    unsafe {
        match operation % 3 {
            0 => {
                let _ = xray_core_load_config_json(handle, json.as_ptr(), error);
            }
            1 => {
                let _ = xray_core_start(handle, error);
            }
            _ => {
                let _ = xray_core_stop(handle, error);
            }
        }
    }
    // Every FFI call may replace the owned error. Release it exactly once and
    // null the slot before the next call, whose contract permits a live error
    // pointer and would otherwise attempt to free it again.
    clear_error(error);
}

fuzz_target!(|data: &[u8]| {
    let mut error: *mut XrayError = std::ptr::null_mut();

    // Keep arbitrary JSON away from start/stop: a mutated valid config could
    // otherwise bind listeners, open files, or initiate network activity.
    // Its parser and one-successful-load ownership path still run here.
    let arbitrary_handle = unsafe { xray_core_new(&mut error) };
    clear_error(&mut error);
    if !arbitrary_handle.is_null() {
        let json_bytes = data.split(|byte| *byte == 0).next().unwrap_or_default();
        let json = CString::new(json_bytes).expect("interior NUL bytes were removed");
        unsafe {
            let _ = xray_core_load_config_json(arbitrary_handle, json.as_ptr(), &mut error);
        }
        clear_error(&mut error);
        unsafe {
            xray_core_free(arbitrary_handle);
        }
    }

    // Successful state transitions use a fixed no-inbound config, so the
    // operation sequence cannot acquire external resources or perform I/O.
    let handle = unsafe { xray_core_new(&mut error) };
    clear_error(&mut error);
    if handle.is_null() {
        return;
    }
    let safe_json = CString::new(SAFE_CONFIG).expect("safe config has no NUL bytes");

    // Always cover the core lifecycle and its error transitions, even during a
    // short smoke campaign: reload while running must fail, then stop must
    // clear that error.
    for operation in [0, 1, 0, 2] {
        run_operation(operation, handle, &safe_json, &mut error);
    }

    // Add a bounded, input-directed sequence that exercises repeated starts,
    // stops, reloads, and recovery from each operation's error state.
    for &operation in data.iter().take(8) {
        run_operation(operation, handle, &safe_json, &mut error);
    }

    // Best-effort final stop covers cleanup after any input-directed suffix;
    // freeing the handle remains safe whether stop succeeds or reports an
    // unloaded/already-stopped state.
    run_operation(2, handle, &safe_json, &mut error);

    unsafe {
        xray_core_free(handle);
    }
});
