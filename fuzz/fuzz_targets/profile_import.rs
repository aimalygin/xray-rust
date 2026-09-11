#![no_main]

use libfuzzer_sys::fuzz_target;
use std::ptr;
use xray_config::profile_import::{
    import_profile, import_request, ProfileFormat, MAX_RESULT_BYTES,
};
use xray_ffi::{xray_error_free, xray_profile_import_json, XrayStatus};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for result in [
            import_request(text),
            import_profile(ProfileFormat::Hysteria2, text, None, &[]),
            import_profile(ProfileFormat::Wireguard, text, None, &[]),
        ] {
            if let Ok(profile) = result {
                let config = xray_config::parse_xray_json(&profile.config_json).unwrap();
                assert!(config.diagnostics.is_empty());
                assert!(profile.to_json().unwrap().len() <= MAX_RESULT_BYTES);
            }
        }
    }
    // Valid request seeds reach crypto validation and both output phases;
    // arbitrary bytes cover the bounded UTF-8 and request error boundary.
    unsafe {
        let mut written = 999;
        let mut error = ptr::null_mut();
        let status = xray_profile_import_json(
            data.as_ptr(),
            data.len(),
            ptr::null_mut(),
            0,
            &mut written,
            &mut error,
        );
        xray_error_free(error);
        assert_ne!(status, XrayStatus::Panic);
        if status == XrayStatus::Ok {
            assert!(written > 0 && written <= MAX_RESULT_BYTES);
            let required = written;
            let mut output = vec![0x55u8; required + 2];
            error = ptr::null_mut();
            assert_eq!(
                xray_profile_import_json(
                    data.as_ptr(),
                    data.len(),
                    output.as_mut_ptr().cast(),
                    required + 1,
                    &mut written,
                    &mut error
                ),
                XrayStatus::Ok
            );
            xray_error_free(error);
            assert_eq!(written, required);
            assert_eq!(output[required], 0);
            assert_eq!(output[required + 1], 0x55);
            assert!(std::str::from_utf8(&output[..written]).is_ok());
        } else {
            assert_eq!(written, 0);
        }
    }
});
