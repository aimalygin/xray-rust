use bytes::Bytes;
use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use xray_config::parse_xray_json;
use xray_core_rs::{Core, TunFdClosePolicy, TunFdConfig, TunFdPacketFormat, TunFdRuntime};
use xray_transport::{SocketHandle, SocketProtector, SystemDnsResolver, TransportDialer};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayStatus {
    Ok = 0,
    NullArgument = 1,
    InvalidUtf8 = 2,
    ConfigError = 3,
    CoreNotLoaded = 4,
    RuntimeError = 5,
    NoPacket = 6,
    BufferTooSmall = 7,
    TunError = 8,
    Panic = 255,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayTunFdPacketFormat {
    RawIp = 0,
    DarwinUtun = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayTunFdClosePolicy {
    Borrowed = 0,
    Owned = 1,
}

impl From<XrayTunFdPacketFormat> for TunFdPacketFormat {
    fn from(value: XrayTunFdPacketFormat) -> Self {
        match value {
            XrayTunFdPacketFormat::RawIp => Self::RawIp,
            XrayTunFdPacketFormat::DarwinUtun => Self::DarwinUtun,
        }
    }
}

impl From<XrayTunFdClosePolicy> for TunFdClosePolicy {
    fn from(value: XrayTunFdClosePolicy) -> Self {
        match value {
            XrayTunFdClosePolicy::Borrowed => Self::Borrowed,
            XrayTunFdClosePolicy::Owned => Self::Owned,
        }
    }
}

#[repr(C)]
pub struct XrayError {
    code: XrayStatus,
    message: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayTunStats {
    pub inbound_packets: u64,
    pub outbound_packets: u64,
    pub dropped_packets: u64,
    pub inbound_dropped_packets: u64,
    pub outbound_dropped_packets: u64,
    pub tcp_stack_to_remote_bytes: u64,
    pub tcp_remote_written_bytes: u64,
    pub tcp_remote_read_bytes: u64,
    pub tcp_backpressure_events: u64,
    pub tcp_stack_to_remote_backpressure_events: u64,
    pub tcp_remote_to_stack_backpressure_events: u64,
    pub tcp_remote_write_batches: u64,
    pub tcp_remote_write_batch_messages: u64,
    pub tcp_remote_write_batch_max_messages: u64,
    pub tcp_remote_write_batch_max_bytes: u64,
    pub tcp_pending_remote_bytes: u64,
    pub tcp_pending_remote_flows: u64,
    pub tcp_pending_remote_max_bytes: u64,
    pub tcp_remote_buffer_limit_bytes: u64,
    pub tcp_remote_buffer_pressure_active: u64,
    pub tcp_remote_write_errors: u64,
    pub tcp_remote_closed_events: u64,
    pub tcp_remote_read_errors: u64,
    pub tcp_open_errors: u64,
}

pub struct XrayCoreHandle {
    core: Option<Core>,
    runtime: Runtime,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    tun_fd_config: Option<TunFdConfig>,
    tun_fd_runtime: Option<TunFdRuntime>,
}

pub type XraySocketProtectCallback =
    Option<unsafe extern "C" fn(fd: c_int, user_data: *mut c_void) -> c_int>;

struct FfiSocketProtector {
    callback: unsafe extern "C" fn(fd: c_int, user_data: *mut c_void) -> c_int,
    user_data: usize,
}

unsafe impl Send for FfiSocketProtector {}
unsafe impl Sync for FfiSocketProtector {}

impl SocketProtector for FfiSocketProtector {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        let raw = socket.raw();
        let fd = c_int::try_from(raw).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("socket handle {raw} cannot be represented as c_int fd"),
            )
        })?;
        let ok = unsafe { (self.callback)(fd, self.user_data as *mut c_void) };
        if ok == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket protect callback returned false",
            ));
        }

        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn xray_ffi_version_major() -> u32 {
    0
}

/// Allocates a new core handle.
///
/// # Safety
///
/// If `error` is non-null, it must point to an initialized `*mut XrayError`
/// value that is either null or a live error pointer returned by this library.
/// This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_new(error: *mut *mut XrayError) -> *mut XrayCoreHandle {
    match catch_unwind(AssertUnwindSafe(|| unsafe { xray_core_new_inner(error) })) {
        Ok(handle) => handle,
        Err(_) => unsafe {
            set_error(error, XrayStatus::Panic, "panic crossed FFI boundary");
            ptr::null_mut()
        },
    }
}

unsafe fn xray_core_new_inner(error: *mut *mut XrayError) -> *mut XrayCoreHandle {
    unsafe {
        clear_error(error);
    }

    let runtime = match Builder::new_multi_thread()
        .enable_all()
        .thread_name("xray-ffi")
        .worker_threads(runtime_worker_threads())
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::RuntimeError,
                    format!("failed to create tokio runtime: {err}"),
                );
            }
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(XrayCoreHandle {
        core: None,
        runtime,
        socket_protector: None,
        tun_fd_config: None,
        tun_fd_runtime: None,
    }))
}

/// Loads an Xray JSON config into a core handle.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `json` must either be null or point to a valid
/// NUL-terminated C string. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_load_config_json(
    handle: *mut XrayCoreHandle,
    json: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_load_config_json_inner(handle, json, error)
        })
    }
}

unsafe fn xray_core_load_config_json_inner(
    handle: *mut XrayCoreHandle,
    json: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }

    if json.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "config JSON is null");
        }
        return XrayStatus::NullArgument;
    }

    let raw = match unsafe { CStr::from_ptr(json) }.to_str() {
        Ok(raw) => raw,
        Err(err) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::InvalidUtf8,
                    format!("config JSON is not valid UTF-8: {err}"),
                );
            }
            return XrayStatus::InvalidUtf8;
        }
    };

    let parsed = match parse_xray_json(raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::ConfigError,
                    diagnostics_message(err.diagnostics),
                );
            }
            return XrayStatus::ConfigError;
        }
    };

    let transport_dialer =
        match TransportDialer::system_with_socket_protector((*handle).socket_protector.clone()) {
            Ok(dialer) => Arc::new(dialer),
            Err(err) => {
                unsafe {
                    set_error(error, XrayStatus::RuntimeError, err.to_string());
                }
                return XrayStatus::RuntimeError;
            }
        };

    let core = match Core::with_runtime_dependencies(
        parsed.config,
        Arc::new(SystemDnsResolver),
        transport_dialer,
    ) {
        Ok(core) => core,
        Err(err) => {
            unsafe {
                set_error(error, XrayStatus::ConfigError, err.to_string());
            }
            return XrayStatus::ConfigError;
        }
    };

    unsafe {
        (*handle).core = Some(core);
    }

    XrayStatus::Ok
}

/// Registers an outbound socket protection callback for mobile VPN adapters.
///
/// Android callers should set this before loading config so sockets opened by
/// the Rust core can be passed through `VpnService.protect(fd)` before connect
/// or first UDP use. Passing a null callback clears the registration. The
/// callback must be fast and thread-safe; it may be called from runtime worker
/// threads while the core is running.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `user_data` is stored as an opaque pointer and must stay
/// valid for as long as the loaded core may dial outbound sockets. If `error`
/// is non-null, it must point to an initialized `*mut XrayError` value that is
/// either null or a live error pointer returned by this library. This function
/// may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_socket_protect_callback(
    handle: *mut XrayCoreHandle,
    callback: XraySocketProtectCallback,
    user_data: *mut c_void,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_socket_protect_callback_inner(handle, callback, user_data, error)
        })
    }
}

unsafe fn xray_core_set_socket_protect_callback_inner(
    handle: *mut XrayCoreHandle,
    callback: XraySocketProtectCallback,
    user_data: *mut c_void,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    if handle.core.is_some() {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "socket protect callback must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    handle.socket_protector = callback.map(|callback| {
        Arc::new(FfiSocketProtector {
            callback,
            user_data: user_data as usize,
        }) as Arc<dyn SocketProtector>
    });

    XrayStatus::Ok
}

/// Registers a platform TUN file descriptor for direct fd-backed packet I/O.
///
/// This is an optional alternative to `xray_tun_push_packet` and
/// `xray_tun_poll_packet`. Mobile hosts can pass Android `VpnService` fds as
/// `RawIp`, or Darwin utun fds as `DarwinUtun` when the 4-byte utun address
/// family header is present. The fd bridge starts with `xray_core_start` and
/// stops with `xray_core_stop`.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. If `close_policy` is `Owned`, the fd must not be closed
/// by the caller after this function succeeds. If `error` is non-null, it must
/// point to an initialized `*mut XrayError` value that is either null or a live
/// error pointer returned by this library. This function may free and replace
/// that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_tun_fd(
    handle: *mut XrayCoreHandle,
    fd: c_int,
    packet_format: XrayTunFdPacketFormat,
    close_policy: XrayTunFdClosePolicy,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_tun_fd_inner(handle, fd, packet_format, close_policy, error)
        })
    }
}

unsafe fn xray_core_set_tun_fd_inner(
    handle: *mut XrayCoreHandle,
    fd: c_int,
    packet_format: XrayTunFdPacketFormat,
    close_policy: XrayTunFdClosePolicy,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if fd < 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "tun fd must be non-negative",
            );
        }
        return XrayStatus::RuntimeError;
    }

    let handle = unsafe { &mut *handle };
    if handle.core.is_some() {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "tun fd must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    if let Some(old) = handle.tun_fd_config.replace(TunFdConfig::new(
        fd,
        packet_format.into(),
        close_policy.into(),
    )) {
        old.close_if_owned();
    }

    XrayStatus::Ok
}

/// Starts a loaded core.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. If `error` is non-null, it must point to an initialized
/// `*mut XrayError` value that is either null or a live error pointer returned
/// by this library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_start(
    handle: *mut XrayCoreHandle,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe { ffi_status(error, || xray_core_start_inner(handle, error)) }
}

unsafe fn xray_core_start_inner(
    handle: *mut XrayCoreHandle,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    let Some(core) = handle.core.as_mut() else {
        unsafe {
            set_error(
                error,
                XrayStatus::CoreNotLoaded,
                "core config is not loaded",
            );
        }
        return XrayStatus::CoreNotLoaded;
    };

    match handle.runtime.block_on(core.start()) {
        Ok(()) => {
            if let Some(config) = handle.tun_fd_config.take() {
                let tun = core.tun_handle();
                match handle
                    .runtime
                    .block_on(async move { TunFdRuntime::start(config, tun) })
                {
                    Ok(runtime) => handle.tun_fd_runtime = Some(runtime),
                    Err(err) => {
                        let _ = handle.runtime.block_on(core.stop());
                        unsafe {
                            set_error(
                                error,
                                XrayStatus::RuntimeError,
                                format!("failed to start fd-backed TUN: {err}"),
                            );
                        }
                        return XrayStatus::RuntimeError;
                    }
                }
            }
            XrayStatus::Ok
        }
        Err(err) => {
            unsafe {
                set_error(error, XrayStatus::RuntimeError, err.to_string());
            }
            XrayStatus::RuntimeError
        }
    }
}

/// Stops a loaded core.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. If `error` is non-null, it must point to an initialized
/// `*mut XrayError` value that is either null or a live error pointer returned
/// by this library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_stop(
    handle: *mut XrayCoreHandle,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe { ffi_status(error, || xray_core_stop_inner(handle, error)) }
}

unsafe fn xray_core_stop_inner(
    handle: *mut XrayCoreHandle,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    let Some(core) = handle.core.as_mut() else {
        unsafe {
            set_error(
                error,
                XrayStatus::CoreNotLoaded,
                "core config is not loaded",
            );
        }
        return XrayStatus::CoreNotLoaded;
    };

    if let Some(runtime) = handle.tun_fd_runtime.take() {
        handle.runtime.block_on(runtime.stop());
    }

    match handle.runtime.block_on(core.stop()) {
        Ok(()) => XrayStatus::Ok,
        Err(err) => {
            unsafe {
                set_error(error, XrayStatus::RuntimeError, err.to_string());
            }
            XrayStatus::RuntimeError
        }
    }
}

/// Pushes one raw IP packet from the host TUN adapter into the core.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `data` must point to `len` readable bytes unless `len`
/// is zero. If `error` is non-null, it must point to an initialized
/// `*mut XrayError` value that is either null or a live error pointer returned
/// by this library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_push_packet(
    handle: *mut XrayCoreHandle,
    data: *const u8,
    len: usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_push_packet_inner(handle, data, len, error)
        })
    }
}

unsafe fn xray_tun_push_packet_inner(
    handle: *mut XrayCoreHandle,
    data: *const u8,
    len: usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if data.is_null() && len > 0 {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "packet data is null");
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    let Some(core) = handle.core.as_ref() else {
        unsafe {
            set_error(
                error,
                XrayStatus::CoreNotLoaded,
                "core config is not loaded",
            );
        }
        return XrayStatus::CoreNotLoaded;
    };

    let packet = if len == 0 {
        Bytes::new()
    } else {
        let data = unsafe { slice::from_raw_parts(data, len) };
        Bytes::copy_from_slice(data)
    };

    match handle.runtime.block_on(core.tun().push_inbound(packet)) {
        Ok(()) => XrayStatus::Ok,
        Err(err) => {
            unsafe {
                set_error(error, XrayStatus::TunError, err.to_string());
            }
            XrayStatus::TunError
        }
    }
}

/// Polls one raw IP packet emitted by the core for the host TUN adapter.
///
/// This function is nonblocking. If no packet is currently available, it
/// returns `XrayStatus::NoPacket` and writes `0` to `written`.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `buffer` must point to `buffer_len` writable bytes.
/// `written` must point to one writable `usize`. If `error` is non-null, it
/// must point to an initialized `*mut XrayError` value that is either null or a
/// live error pointer returned by this library. This function may free and
/// replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_packet(
    handle: *mut XrayCoreHandle,
    buffer: *mut u8,
    buffer_len: usize,
    written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_packet_inner(handle, buffer, buffer_len, written, error)
        })
    }
}

unsafe fn xray_tun_poll_packet_inner(
    handle: *mut XrayCoreHandle,
    buffer: *mut u8,
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

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if buffer.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "packet buffer is null");
        }
        return XrayStatus::NullArgument;
    }
    if written.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "written pointer is null");
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    let Some(core) = handle.core.as_ref() else {
        unsafe {
            set_error(
                error,
                XrayStatus::CoreNotLoaded,
                "core config is not loaded",
            );
        }
        return XrayStatus::CoreNotLoaded;
    };

    match handle.runtime.block_on(core.tun().try_poll_outbound()) {
        Ok(Some(packet)) if packet.len() <= buffer_len => {
            unsafe {
                ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
                *written = packet.len();
            }
            XrayStatus::Ok
        }
        Ok(Some(packet)) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::BufferTooSmall,
                    format!(
                        "packet length {} exceeds output buffer length {buffer_len}",
                        packet.len()
                    ),
                );
            }
            XrayStatus::BufferTooSmall
        }
        Ok(None) => XrayStatus::NoPacket,
        Err(err) => {
            unsafe {
                set_error(error, XrayStatus::TunError, err.to_string());
            }
            XrayStatus::TunError
        }
    }
}

/// Writes a TUN packet counter snapshot to `stats`.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `stats` must point to writable memory for one
/// `XrayTunStats`. If `error` is non-null, it must point to an initialized
/// `*mut XrayError` value that is either null or a live error pointer returned
/// by this library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_stats(
    handle: *mut XrayCoreHandle,
    stats: *mut XrayTunStats,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe { ffi_status(error, || xray_tun_stats_inner(handle, stats, error)) }
}

unsafe fn xray_tun_stats_inner(
    handle: *mut XrayCoreHandle,
    stats: *mut XrayTunStats,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if stats.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "tun stats pointer is null");
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    let Some(core) = handle.core.as_ref() else {
        unsafe {
            set_error(
                error,
                XrayStatus::CoreNotLoaded,
                "core config is not loaded",
            );
        }
        return XrayStatus::CoreNotLoaded;
    };

    let snapshot = handle.runtime.block_on(core.tun().stats());
    unsafe {
        *stats = XrayTunStats {
            inbound_packets: snapshot.inbound_packets,
            outbound_packets: snapshot.outbound_packets,
            dropped_packets: snapshot.dropped_packets,
            inbound_dropped_packets: snapshot.inbound_dropped_packets,
            outbound_dropped_packets: snapshot.outbound_dropped_packets,
            tcp_stack_to_remote_bytes: snapshot.tcp_stack_to_remote_bytes,
            tcp_remote_written_bytes: snapshot.tcp_remote_written_bytes,
            tcp_remote_read_bytes: snapshot.tcp_remote_read_bytes,
            tcp_backpressure_events: snapshot.tcp_backpressure_events,
            tcp_stack_to_remote_backpressure_events: snapshot
                .tcp_stack_to_remote_backpressure_events,
            tcp_remote_to_stack_backpressure_events: snapshot
                .tcp_remote_to_stack_backpressure_events,
            tcp_remote_write_batches: snapshot.tcp_remote_write_batches,
            tcp_remote_write_batch_messages: snapshot.tcp_remote_write_batch_messages,
            tcp_remote_write_batch_max_messages: snapshot.tcp_remote_write_batch_max_messages,
            tcp_remote_write_batch_max_bytes: snapshot.tcp_remote_write_batch_max_bytes,
            tcp_pending_remote_bytes: snapshot.tcp_pending_remote_bytes,
            tcp_pending_remote_flows: snapshot.tcp_pending_remote_flows,
            tcp_pending_remote_max_bytes: snapshot.tcp_pending_remote_max_bytes,
            tcp_remote_buffer_limit_bytes: snapshot.tcp_remote_buffer_limit_bytes,
            tcp_remote_buffer_pressure_active: if snapshot.tcp_remote_buffer_pressure_active {
                1
            } else {
                0
            },
            tcp_remote_write_errors: snapshot.tcp_remote_write_errors,
            tcp_remote_closed_events: snapshot.tcp_remote_closed_events,
            tcp_remote_read_errors: snapshot.tcp_remote_read_errors,
            tcp_open_errors: snapshot.tcp_open_errors,
        };
    }

    XrayStatus::Ok
}

/// Frees a core handle returned by `xray_core_new`.
///
/// # Safety
///
/// `handle` must be null or a pointer returned by `xray_core_new` that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn xray_core_free(handle: *mut XrayCoreHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        xray_core_free_inner(handle);
    }));
}

unsafe fn xray_core_free_inner(handle: *mut XrayCoreHandle) {
    if !handle.is_null() {
        let mut handle = unsafe { Box::from_raw(handle) };
        if let Some(runtime) = handle.tun_fd_runtime.take() {
            handle.runtime.block_on(runtime.stop());
        }
        if let Some(core) = handle.core.as_mut() {
            let _ = handle.runtime.block_on(core.stop());
        }
        if let Some(config) = handle.tun_fd_config.take() {
            config.close_if_owned();
        }
    }
}

/// Frees an error returned through an FFI error out-parameter.
///
/// # Safety
///
/// `error` must be null or a pointer returned by this library that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn xray_error_free(error: *mut XrayError) {
    if error.is_null() {
        return;
    }

    unsafe {
        free_error(error);
    }
}

/// Returns the status code stored in an error.
///
/// # Safety
///
/// `error` must be null or a valid borrowed pointer returned by this library.
#[no_mangle]
pub unsafe extern "C" fn xray_error_code(error: *const XrayError) -> XrayStatus {
    if error.is_null() {
        return XrayStatus::Ok;
    }

    unsafe { (*error).code }
}

/// Returns a borrowed, read-only error message pointer.
///
/// The returned pointer is owned by `error` and is only valid until
/// `xray_error_free(error)` is called.
///
/// # Safety
///
/// `error` must be null or a valid borrowed pointer returned by this library.
#[no_mangle]
pub unsafe extern "C" fn xray_error_message(error: *const XrayError) -> *const c_char {
    if error.is_null() {
        return ptr::null();
    }

    unsafe { (*error).message.cast_const() }
}

unsafe fn clear_error(error: *mut *mut XrayError) {
    if !error.is_null() {
        unsafe {
            if !(*error).is_null() {
                free_error(*error);
            }
            *error = ptr::null_mut();
        }
    }
}

unsafe fn set_error(error: *mut *mut XrayError, code: XrayStatus, message: impl AsRef<str>) {
    if error.is_null() {
        return;
    }

    unsafe {
        clear_error(error);
    }

    let message = c_string_lossy_without_nuls(message.as_ref());
    let ffi_error = Box::new(XrayError {
        code,
        message: message.into_raw(),
    });

    unsafe {
        *error = Box::into_raw(ffi_error);
    }
}

unsafe fn free_error(error: *mut XrayError) {
    let error = unsafe { Box::from_raw(error) };
    if !error.message.is_null() {
        unsafe {
            drop(CString::from_raw(error.message));
        }
    }
}

unsafe fn ffi_status(
    error: *mut *mut XrayError,
    action: impl FnOnce() -> XrayStatus,
) -> XrayStatus {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(status) => status,
        Err(_) => {
            unsafe {
                set_error(error, XrayStatus::Panic, "panic crossed FFI boundary");
            }
            XrayStatus::Panic
        }
    }
}

fn diagnostics_message(diagnostics: Vec<xray_config::Diagnostic>) -> String {
    let message = diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.message)
        .collect::<Vec<_>>()
        .join("; ");

    if message.is_empty() {
        "config parse error".to_owned()
    } else {
        message
    }
}

fn c_string_lossy_without_nuls(message: &str) -> CString {
    let filtered = message
        .as_bytes()
        .iter()
        .copied()
        .filter(|byte| *byte != 0)
        .collect::<Vec<_>>();

    CString::new(filtered).unwrap_or_else(|_| CString::default())
}

fn runtime_worker_threads() -> usize {
    let available = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2);
    runtime_worker_threads_for_available_parallelism(available)
}

fn runtime_worker_threads_for_available_parallelism(available: usize) -> usize {
    available.clamp(2, 4)
}

#[cfg(test)]
mod tests {
    use super::runtime_worker_threads_for_available_parallelism;

    #[test]
    fn runtime_worker_threads_use_available_parallelism_with_mobile_bounds() {
        assert_eq!(runtime_worker_threads_for_available_parallelism(1), 2);
        assert_eq!(runtime_worker_threads_for_available_parallelism(2), 2);
        assert_eq!(runtime_worker_threads_for_available_parallelism(3), 3);
        assert_eq!(runtime_worker_threads_for_available_parallelism(4), 4);
        assert_eq!(runtime_worker_threads_for_available_parallelism(8), 4);
    }
}
