use super::*;
use std::net::IpAddr;
use xray_core_rs::{TunAdmissionPolicy, TunFlow, TunFlowAdmission};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XrayTunFlow {
    pub id: u64,
    pub protocol: u8,
    pub address_family: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub reserved: u16,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
}

pub type XrayTunAdmissionCallback =
    Option<unsafe extern "C" fn(*const XrayTunFlow, *mut c_void) -> c_int>;
pub type XrayTunAdmissionRelease = Option<unsafe extern "C" fn(*mut c_void)>;

struct FfiAdmission {
    callback: unsafe extern "C" fn(*const XrayTunFlow, *mut c_void) -> c_int,
    release: unsafe extern "C" fn(*mut c_void),
    user_data: usize,
}

impl Drop for FfiAdmission {
    fn drop(&mut self) {
        // The host transfers ownership only after successful registration. An
        // in-flight callback owns an Arc and can outlive xray_core_free safely.
        unsafe {
            (self.release)(self.user_data as *mut c_void);
        }
    }
}

impl TunFlowAdmission for FfiAdmission {
    fn admit(&self, flow: TunFlow) -> bool {
        let mut raw = XrayTunFlow {
            id: flow.id,
            protocol: flow.protocol,
            address_family: if flow.source.is_ipv4() { 4 } else { 6 },
            source_port: flow.source.port(),
            destination_port: flow.destination.port(),
            reserved: 0,
            source_address: [0; 16],
            destination_address: [0; 16],
        };
        for (address, bytes) in [
            (flow.source.ip(), &mut raw.source_address),
            (flow.destination.ip(), &mut raw.destination_address),
        ] {
            match address {
                IpAddr::V4(ip) => bytes[..4].copy_from_slice(&ip.octets()),
                IpAddr::V6(ip) => bytes.copy_from_slice(&ip.octets()),
            }
        }
        unsafe { (self.callback)(&raw, self.user_data as *mut c_void) == 1 }
    }
}

/// Registers an owned host callback before configuration load (ABI 1.11).
/// A null callback clears the policy and requires null release/user_data.
/// On success, release is called once after the last callback has returned,
/// possibly after core_free, on an arbitrary thread. Failure retains ownership
/// with the caller. The flow pointer is valid only within the callback.
///
/// # Safety
/// Handle/error must be valid, lifecycle calls externally serialized. Both
/// callbacks must be thread-safe, return promptly, never unwind across FFI,
/// and must not invoke core lifecycle operations. Code and user_data must
/// remain valid until release. A timeout does not interrupt host execution.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_tun_admission(
    handle: *mut XrayCoreHandle,
    callback: XrayTunAdmissionCallback,
    release: XrayTunAdmissionRelease,
    user_data: *mut c_void,
    timeout_ms: u32,
    fail_open: c_int,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            clear_error(error);
            let Some(handle) = handle.as_mut() else {
                set_error(error, XrayStatus::NullArgument, "core handle is null");
                return XrayStatus::NullArgument;
            };
            if handle.core.is_some() {
                set_error(
                    error,
                    XrayStatus::RuntimeError,
                    "TUN admission must be set before config load",
                );
                return XrayStatus::RuntimeError;
            }
            let Some(callback) = callback else {
                if release.is_some() || !user_data.is_null() {
                    set_error(
                        error,
                        XrayStatus::InvalidArgument,
                        "clearing TUN admission requires null context and release",
                    );
                    return XrayStatus::InvalidArgument;
                }
                handle.tun_admission = None;
                return XrayStatus::Ok;
            };
            let Some(release) = release else {
                set_error(
                    error,
                    XrayStatus::InvalidArgument,
                    "TUN admission requires a context release callback",
                );
                return XrayStatus::InvalidArgument;
            };
            if !(1..=5000).contains(&timeout_ms) || !matches!(fail_open, 0 | 1) {
                set_error(
                    error,
                    XrayStatus::InvalidArgument,
                    "TUN admission requires timeout 1..5000 ms and fail_open 0 or 1",
                );
                return XrayStatus::InvalidArgument;
            }
            // All fallible validation precedes the ownership transfer.
            handle.tun_admission = Some(
                TunAdmissionPolicy::new(
                    Arc::new(FfiAdmission {
                        callback,
                        release,
                        user_data: user_data as usize,
                    }),
                    Duration::from_millis(u64::from(timeout_ms)),
                    fail_open == 1,
                )
                .expect("validated admission timeout"),
            );
            XrayStatus::Ok
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    unsafe extern "C" fn deny(_: *const XrayTunFlow, _: *mut c_void) -> c_int {
        0
    }
    unsafe extern "C" fn released(data: *mut c_void) {
        unsafe { &*data.cast::<AtomicUsize>() }.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn admission_registration_transfers_ownership_only_on_success() {
        let releases = AtomicUsize::new(0);
        let data = (&releases as *const AtomicUsize).cast_mut().cast();
        unsafe {
            let mut error = ptr::null_mut();
            let core = xray_core_new(&mut error);
            assert!(!core.is_null());
            for (timeout, fail_open) in [(0, 0), (5001, 0), (100, 2)] {
                assert_eq!(
                    xray_core_set_tun_admission(
                        core,
                        Some(deny),
                        Some(released),
                        data,
                        timeout,
                        fail_open,
                        &mut error
                    ),
                    XrayStatus::InvalidArgument
                );
                xray_error_free(error);
                error = ptr::null_mut();
                assert_eq!(releases.load(Ordering::SeqCst), 0);
            }
            assert_eq!(
                xray_core_set_tun_admission(
                    core,
                    Some(deny),
                    Some(released),
                    data,
                    100,
                    0,
                    &mut error
                ),
                XrayStatus::Ok
            );
            assert_eq!(
                xray_core_set_tun_admission(core, None, None, ptr::null_mut(), 0, 0, &mut error),
                XrayStatus::Ok
            );
            assert_eq!(releases.load(Ordering::SeqCst), 1);
            assert_eq!(
                xray_core_set_tun_admission(
                    core,
                    Some(deny),
                    Some(released),
                    data,
                    100,
                    0,
                    &mut error
                ),
                XrayStatus::Ok
            );
            let config = CString::new(
                r#"{"inbounds":[{"protocol":"tun"}],"outbounds":[{"protocol":"freedom"}]}"#,
            )
            .unwrap();
            assert_eq!(
                xray_core_load_config_json(core, config.as_ptr(), &mut error),
                XrayStatus::Ok
            );
            assert_eq!(
                xray_core_set_tun_admission(
                    core,
                    Some(deny),
                    Some(released),
                    data,
                    100,
                    0,
                    &mut error
                ),
                XrayStatus::RuntimeError
            );
            xray_error_free(error);
            assert_eq!(releases.load(Ordering::SeqCst), 1);
            xray_core_free(core);
            assert_eq!(releases.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn admission_wire_tuple_preserves_ipv6_and_host_endian_ports() {
        unsafe extern "C" fn inspect(flow: *const XrayTunFlow, _: *mut c_void) -> c_int {
            let flow = unsafe { &*flow };
            i32::from(
                flow.id == 123
                    && flow.protocol == 6
                    && flow.address_family == 6
                    && flow.source_port == 54321
                    && flow.destination_port == 443
                    && flow.source_address
                        == "2001:db8::1"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets()
                    && flow.destination_address
                        == "2001:db8::2"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
            )
        }
        unsafe extern "C" fn noop(_: *mut c_void) {}
        let policy = FfiAdmission {
            callback: inspect,
            release: noop,
            user_data: 0,
        };
        assert!(policy.admit(TunFlow {
            id: 123,
            protocol: 6,
            source: "[2001:db8::1]:54321".parse().unwrap(),
            destination: "[2001:db8::2]:443".parse().unwrap()
        }));
        assert_eq!(std::mem::size_of::<XrayTunFlow>(), 48);
    }
}
