use bytes::Bytes;
use libc::{c_char, c_int, c_void};
use std::any::Any;
use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};
use xray_config::{
    parse_xray_json, parse_xray_json_with_exclusive_geodata_dirs, parse_xray_json_with_geodata_dirs,
};
use xray_core_rs::{
    Core, DnsBootstrapMode, RuntimeLogConfig, RuntimeLogger, StartupProbeOptions, TunFdClosePolicy,
    TunFdConfig, TunFdPacketFormat, TunFdRuntime, TunRuntimeOptions, TunRuntimeProfile,
};
use xray_transport::{SocketHandle, SocketProtector, TransportDialer};
use xray_tun::TunTcpSlowFlowKind;

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
    InvalidArgument = 9,
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayTunRuntimeProfile {
    Default = 0,
    Mobile = 1,
    Desktop = 2,
    LowMemory = 3,
    Throughput = 4,
    MobilePlus = 5,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayDnsBootstrapMode {
    System = 0,
    StaticOnly = 1,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum XrayTcpSlowFlowKind {
    #[default]
    Unknown = 0,
    Open = 1,
    FirstByte = 2,
}

impl From<TunTcpSlowFlowKind> for XrayTcpSlowFlowKind {
    fn from(value: TunTcpSlowFlowKind) -> Self {
        match value {
            TunTcpSlowFlowKind::Open => Self::Open,
            TunTcpSlowFlowKind::FirstByte => Self::FirstByte,
        }
    }
}

impl TryFrom<c_int> for XrayTunFdPacketFormat {
    type Error = &'static str;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::RawIp),
            1 => Ok(Self::DarwinUtun),
            _ => Err("tun fd packet format must be 0 (raw IP) or 1 (Darwin utun)"),
        }
    }
}

impl TryFrom<c_int> for XrayTunFdClosePolicy {
    type Error = &'static str;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Borrowed),
            1 => Ok(Self::Owned),
            _ => Err("tun fd close policy must be 0 (borrowed) or 1 (owned)"),
        }
    }
}

impl TryFrom<c_int> for XrayTunRuntimeProfile {
    type Error = &'static str;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Default),
            1 => Ok(Self::Mobile),
            2 => Ok(Self::Desktop),
            3 => Ok(Self::LowMemory),
            4 => Ok(Self::Throughput),
            5 => Ok(Self::MobilePlus),
            _ => Err("tun runtime profile must be in the range 0..=5"),
        }
    }
}

impl TryFrom<c_int> for XrayDnsBootstrapMode {
    type Error = &'static str;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::System),
            1 => Ok(Self::StaticOnly),
            _ => Err("dns bootstrap mode must be 0 (system) or 1 (static only)"),
        }
    }
}

impl From<XrayTunFdPacketFormat> for TunFdPacketFormat {
    fn from(value: XrayTunFdPacketFormat) -> Self {
        match value {
            XrayTunFdPacketFormat::RawIp => Self::RawIp,
            XrayTunFdPacketFormat::DarwinUtun => Self::DarwinUtun,
        }
    }
}

impl From<XrayTunRuntimeProfile> for TunRuntimeProfile {
    fn from(value: XrayTunRuntimeProfile) -> Self {
        match value {
            XrayTunRuntimeProfile::Default => Self::Default,
            XrayTunRuntimeProfile::Mobile => Self::Mobile,
            XrayTunRuntimeProfile::Desktop => Self::Desktop,
            XrayTunRuntimeProfile::LowMemory => Self::LowMemory,
            XrayTunRuntimeProfile::Throughput => Self::Throughput,
            XrayTunRuntimeProfile::MobilePlus => Self::MobilePlus,
        }
    }
}

impl From<XrayDnsBootstrapMode> for DnsBootstrapMode {
    fn from(value: XrayDnsBootstrapMode) -> Self {
        match value {
            XrayDnsBootstrapMode::System => Self::System,
            XrayDnsBootstrapMode::StaticOnly => Self::StaticOnly,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrayTunStats {
    /// Size of the caller's `XrayTunStats` allocation in bytes.
    ///
    /// Callers must initialize this to `sizeof(XrayTunStats)` before invoking
    /// `xray_tun_stats`. The callee validates it before writing any fields.
    pub struct_size: usize,
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
    pub tcp_remote_write_wait_events: u64,
    pub tcp_remote_write_wait_ms_total: u64,
    pub tcp_remote_write_wait_ms_max: u64,
    pub tcp_remote_flush_wait_events: u64,
    pub tcp_remote_flush_wait_ms_total: u64,
    pub tcp_remote_flush_wait_ms_max: u64,
    pub tcp_pending_remote_bytes: u64,
    pub tcp_pending_remote_flows: u64,
    pub tcp_pending_remote_max_bytes: u64,
    pub tcp_pending_upload_bytes: u64,
    pub tcp_pending_upload_max_bytes: u64,
    pub tcp_pending_total_bytes: u64,
    pub tcp_remote_buffer_limit_bytes: u64,
    pub tcp_buffer_hard_limit_bytes: u64,
    pub tcp_remote_buffer_pressure_active: u64,
    pub tcp_remote_write_errors: u64,
    pub tcp_remote_closed_events: u64,
    pub tcp_remote_read_errors: u64,
    pub tcp_open_errors: u64,
    pub tcp_open_events: u64,
    pub tcp_open_duration_ms_total: u64,
    pub tcp_open_duration_ms_max: u64,
    pub tcp_first_byte_events: u64,
    pub tcp_first_byte_duration_ms_total: u64,
    pub tcp_first_byte_duration_ms_max: u64,
    pub tcp443_open_events: u64,
    pub tcp443_open_duration_ms_total: u64,
    pub tcp443_open_duration_ms_max: u64,
    pub tcp443_first_byte_events: u64,
    pub tcp443_first_byte_duration_ms_total: u64,
    pub tcp443_first_byte_duration_ms_max: u64,
    pub active_tcp_flows: u64,
    pub active_udp_flows: u64,
    pub udp_flow_limit: u64,
    pub udp_budget_drops: u64,
    pub udp_evicted_flows: u64,
    pub udp_channel_dropped_packets: u64,
    pub udp_remote_open_events: u64,
    pub udp_remote_udp443_open_events: u64,
    pub udp_remote_written_bytes: u64,
    pub udp_remote_read_bytes: u64,
    pub udp_open_errors: u64,
    pub udp_vision_udp443_rejections: u64,
    pub udp_remote_write_errors: u64,
    pub udp_remote_read_errors: u64,
    pub udp_remote_closed_events: u64,
    pub udp_quic_blocked_packets: u64,
    pub inbound_queue_depth: u64,
    pub outbound_queue_depth: u64,
    pub inbound_queue_max_packets: u64,
    pub outbound_queue_max_packets: u64,
    pub tun_fd_write_batches: u64,
    pub tun_fd_write_batch_packets: u64,
    pub tun_fd_write_batch_max_packets: u64,
    pub tun_fd_read_loop_exits: u64,
    pub tun_fd_write_loop_exits: u64,
    pub tun_fd_transient_io_errors: u64,
}

impl Default for XrayTunStats {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>(),
            inbound_packets: 0,
            outbound_packets: 0,
            dropped_packets: 0,
            inbound_dropped_packets: 0,
            outbound_dropped_packets: 0,
            tcp_stack_to_remote_bytes: 0,
            tcp_remote_written_bytes: 0,
            tcp_remote_read_bytes: 0,
            tcp_backpressure_events: 0,
            tcp_stack_to_remote_backpressure_events: 0,
            tcp_remote_to_stack_backpressure_events: 0,
            tcp_remote_write_batches: 0,
            tcp_remote_write_batch_messages: 0,
            tcp_remote_write_batch_max_messages: 0,
            tcp_remote_write_batch_max_bytes: 0,
            tcp_remote_write_wait_events: 0,
            tcp_remote_write_wait_ms_total: 0,
            tcp_remote_write_wait_ms_max: 0,
            tcp_remote_flush_wait_events: 0,
            tcp_remote_flush_wait_ms_total: 0,
            tcp_remote_flush_wait_ms_max: 0,
            tcp_pending_remote_bytes: 0,
            tcp_pending_remote_flows: 0,
            tcp_pending_remote_max_bytes: 0,
            tcp_pending_upload_bytes: 0,
            tcp_pending_upload_max_bytes: 0,
            tcp_pending_total_bytes: 0,
            tcp_remote_buffer_limit_bytes: 0,
            tcp_buffer_hard_limit_bytes: 0,
            tcp_remote_buffer_pressure_active: 0,
            tcp_remote_write_errors: 0,
            tcp_remote_closed_events: 0,
            tcp_remote_read_errors: 0,
            tcp_open_errors: 0,
            tcp_open_events: 0,
            tcp_open_duration_ms_total: 0,
            tcp_open_duration_ms_max: 0,
            tcp_first_byte_events: 0,
            tcp_first_byte_duration_ms_total: 0,
            tcp_first_byte_duration_ms_max: 0,
            tcp443_open_events: 0,
            tcp443_open_duration_ms_total: 0,
            tcp443_open_duration_ms_max: 0,
            tcp443_first_byte_events: 0,
            tcp443_first_byte_duration_ms_total: 0,
            tcp443_first_byte_duration_ms_max: 0,
            active_tcp_flows: 0,
            active_udp_flows: 0,
            udp_flow_limit: 0,
            udp_budget_drops: 0,
            udp_evicted_flows: 0,
            udp_channel_dropped_packets: 0,
            udp_remote_open_events: 0,
            udp_remote_udp443_open_events: 0,
            udp_remote_written_bytes: 0,
            udp_remote_read_bytes: 0,
            udp_open_errors: 0,
            udp_vision_udp443_rejections: 0,
            udp_remote_write_errors: 0,
            udp_remote_read_errors: 0,
            udp_remote_closed_events: 0,
            udp_quic_blocked_packets: 0,
            inbound_queue_depth: 0,
            outbound_queue_depth: 0,
            inbound_queue_max_packets: 0,
            outbound_queue_max_packets: 0,
            tun_fd_write_batches: 0,
            tun_fd_write_batch_packets: 0,
            tun_fd_write_batch_max_packets: 0,
            tun_fd_read_loop_exits: 0,
            tun_fd_write_loop_exits: 0,
            tun_fd_transient_io_errors: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayTcpSlowFlowEvent {
    pub kind: XrayTcpSlowFlowKind,
    pub open_duration_ms: u64,
    pub first_byte_duration_ms: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayTcpFlowSummaryEvent {
    pub closed: u64,
    pub duration_ms: u64,
    pub open_duration_ms: u64,
    pub first_byte_duration_ms: u64,
    pub remote_read_bytes: u64,
    pub ms_to_64kib: u64,
    pub ms_to_128kib: u64,
    pub ms_to_256kib: u64,
    pub ms_to_512kib: u64,
    pub ms_to_1mib: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayTcpRemoteWriteSlowEvent {
    pub duration_ms: u64,
    pub bytes: u64,
    pub messages: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayTcpOpenErrorEvent {
    pub reserved: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayUdpSlowFlowEvent {
    pub first_response_duration_ms: u64,
    pub written_bytes: u64,
    pub read_bytes: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayUdpResponseGapEvent {
    pub response_gap_duration_ms: u64,
    pub written_bytes: u64,
    pub read_bytes: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayUdpQuicBlockedEvent {
    pub bytes: u64,
}

pub struct XrayCoreHandle {
    core: Option<Core>,
    runtime: Runtime,
    pending_outbound_packets: Mutex<VecDeque<Bytes>>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    geodata_search: GeodataSearch,
    startup_probe_options: Option<StartupProbeOptions>,
    file_log_config: Option<RuntimeLogConfig>,
    tun_fd_config: Option<TunFdConfig>,
    tun_fd_runtime: Option<TunFdRuntime>,
    tun_runtime_options: TunRuntimeOptions,
    config_warnings: String,
}

enum GeodataSearch {
    Defaults,
    WithDefaults(PathBuf),
    Exclusive(PathBuf),
}

#[derive(Clone, Copy)]
enum GeodataSearchMode {
    WithDefaults,
    Exclusive,
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
    1
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
        Err(payload) => unsafe {
            set_error(
                error,
                XrayStatus::Panic,
                ffi_panic_message(payload.as_ref()),
            );
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
        pending_outbound_packets: Mutex::new(VecDeque::new()),
        socket_protector: None,
        geodata_search: GeodataSearch::Defaults,
        startup_probe_options: None,
        file_log_config: None,
        tun_fd_config: None,
        tun_fd_runtime: None,
        tun_runtime_options: TunRuntimeOptions::default(),
        config_warnings: String::new(),
    }))
}

/// Sets the geodata search directory used by subsequent config loads.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `dir` must either be null or point to a valid
/// NUL-terminated C string. The directory is prepended before the default
/// geodata search directories, matching Xray-style bundle resource lookup
/// without relying on the process current working directory.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_geodata_search_dir(
    handle: *mut XrayCoreHandle,
    dir: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_geodata_search_dir_inner(
                handle,
                dir,
                GeodataSearchMode::WithDefaults,
                error,
            )
        })
    }
}

/// Sets the only geodata search directory used by subsequent config loads.
///
/// Unlike [`xray_core_set_geodata_search_dir`], this does not fall back to
/// process-wide default directories. A referenced asset missing from `dir`
/// therefore fails config loading instead of mixing geodata generations.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `dir` must either be null or point to a valid
/// NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_geodata_search_dir_exclusive(
    handle: *mut XrayCoreHandle,
    dir: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_geodata_search_dir_inner(handle, dir, GeodataSearchMode::Exclusive, error)
        })
    }
}

unsafe fn xray_core_set_geodata_search_dir_inner(
    handle: *mut XrayCoreHandle,
    dir: *const c_char,
    mode: GeodataSearchMode,
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

    if dir.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "geodata search dir is null",
            );
        }
        return XrayStatus::NullArgument;
    }

    let dir = match unsafe { CStr::from_ptr(dir) }.to_str() {
        Ok(dir) => dir,
        Err(err) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::InvalidUtf8,
                    format!("geodata search dir is not valid UTF-8: {err}"),
                );
            }
            return XrayStatus::InvalidUtf8;
        }
    };

    if dir.is_empty() {
        unsafe {
            set_error(
                error,
                XrayStatus::ConfigError,
                "geodata search dir is empty",
            );
        }
        return XrayStatus::ConfigError;
    }

    let dir = PathBuf::from(dir);
    unsafe {
        (*handle).geodata_search = match mode {
            GeodataSearchMode::WithDefaults => GeodataSearch::WithDefaults(dir),
            GeodataSearchMode::Exclusive => GeodataSearch::Exclusive(dir),
        };
    }

    XrayStatus::Ok
}

/// Enables or disables Xray runtime access/error file logging.
///
/// When enabled, `log_dir` is used to create `xray-access.log` and
/// `xray-error.log` during config load. Set this before loading config.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. When `enabled` is nonzero, `log_dir` must point to a
/// valid NUL-terminated UTF-8 string. If `error` is non-null, it must point to
/// an initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_file_logging(
    handle: *mut XrayCoreHandle,
    log_dir: *const c_char,
    enabled: c_int,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_file_logging_inner(handle, log_dir, enabled, error)
        })
    }
}

unsafe fn xray_core_set_file_logging_inner(
    handle: *mut XrayCoreHandle,
    log_dir: *const c_char,
    enabled: c_int,
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
                "file logging must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    if enabled == 0 {
        handle.file_log_config = None;
        return XrayStatus::Ok;
    }

    if log_dir.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "file log directory is null",
            );
        }
        return XrayStatus::NullArgument;
    }

    let log_dir = match unsafe { CStr::from_ptr(log_dir) }.to_str() {
        Ok(log_dir) => log_dir,
        Err(err) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::InvalidUtf8,
                    format!("file log directory is not valid UTF-8: {err}"),
                );
            }
            return XrayStatus::InvalidUtf8;
        }
    };
    if log_dir.is_empty() {
        unsafe {
            set_error(
                error,
                XrayStatus::ConfigError,
                "file log directory is empty",
            );
        }
        return XrayStatus::ConfigError;
    }

    handle.file_log_config = Some(RuntimeLogConfig::directory(log_dir));
    XrayStatus::Ok
}

/// Loads an Xray JSON config into a new core handle.
///
/// A handle accepts exactly one successful config load. Create a new handle
/// to replace a configuration.
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
    if unsafe { (*handle).core.is_some() } {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "core config is already loaded; create a new handle to replace it",
            );
        }
        return XrayStatus::RuntimeError;
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

    let parsed = unsafe {
        match &(*handle).geodata_search {
            GeodataSearch::Defaults => parse_xray_json(raw),
            GeodataSearch::WithDefaults(dir) => {
                parse_xray_json_with_geodata_dirs(raw, slice::from_ref(dir))
            }
            GeodataSearch::Exclusive(dir) => {
                parse_xray_json_with_exclusive_geodata_dirs(raw, slice::from_ref(dir))
            }
        }
    };
    let parsed = match parsed {
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
    let config_warnings = format_config_diagnostics(&parsed.diagnostics);

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

    let mut core = match Core::with_transport_dialer_and_tun_options(
        parsed.config,
        transport_dialer,
        (*handle).tun_runtime_options,
    ) {
        Ok(core) => core,
        Err(err) => {
            unsafe {
                set_error(error, XrayStatus::ConfigError, err.to_string());
            }
            return XrayStatus::ConfigError;
        }
    };
    if let Some(options) = unsafe { (*handle).startup_probe_options.clone() } {
        core.set_startup_probe(Some(options));
    }
    if let Some(config) = unsafe { (*handle).file_log_config.clone() } {
        let logger = match RuntimeLogger::new(config) {
            Ok(logger) => logger,
            Err(err) => {
                unsafe {
                    set_error(
                        error,
                        XrayStatus::RuntimeError,
                        format!("failed to initialize file logging: {err}"),
                    );
                }
                return XrayStatus::RuntimeError;
            }
        };
        core.set_runtime_logger(logger);
    }

    unsafe {
        (*handle).core = Some(core);
        (*handle).config_warnings = config_warnings;
    }

    XrayStatus::Ok
}

/// Copies warnings produced by the most recent successful config load.
///
/// `written` receives the UTF-8 byte length excluding the trailing NUL. A null
/// `buffer` with `buffer_len == 0` is a size query. Otherwise the buffer must
/// have room for all bytes plus the trailing NUL.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `written` must point to one writable `usize`. When
/// non-null, `buffer` must point to `buffer_len` writable bytes. This function
/// must not run concurrently with lifecycle/configuration calls on `handle`.
#[no_mangle]
pub unsafe extern "C" fn xray_core_config_warnings(
    handle: *const XrayCoreHandle,
    buffer: *mut c_char,
    buffer_len: usize,
    written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_config_warnings_inner(handle, buffer, buffer_len, written, error)
        })
    }
}

unsafe fn xray_core_config_warnings_inner(
    handle: *const XrayCoreHandle,
    buffer: *mut c_char,
    buffer_len: usize,
    written: *mut usize,
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
    if written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "config warnings length pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if buffer.is_null() && buffer_len != 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "config warnings buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }

    let warnings = unsafe { &(*handle).config_warnings };
    unsafe {
        *written = warnings.len();
    }
    if buffer.is_null() {
        return XrayStatus::Ok;
    }
    let required = warnings.len().saturating_add(1);
    if buffer_len < required {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                format!(
                    "config warnings buffer is {buffer_len} bytes; {required} bytes are required"
                ),
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    unsafe {
        ptr::copy_nonoverlapping(warnings.as_ptr(), buffer.cast::<u8>(), warnings.len());
        *buffer.add(warnings.len()) = 0;
    }
    XrayStatus::Ok
}

/// Configures an optional HTTP(S) startup probe.
///
/// The probe is executed by `xray_core_start` after listeners are bound and
/// before start returns success. The request is sent through the configured
/// outbound, and any 2xx/3xx response is considered successful. Set this
/// before loading config.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `url` must point to a valid NUL-terminated UTF-8 string.
/// `outbound_tag` may be null; if non-null, it must point to a valid
/// NUL-terminated UTF-8 string. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_startup_probe(
    handle: *mut XrayCoreHandle,
    url: *const c_char,
    timeout_ms: u64,
    outbound_tag: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_startup_probe_inner(handle, url, timeout_ms, outbound_tag, error)
        })
    }
}

unsafe fn xray_core_set_startup_probe_inner(
    handle: *mut XrayCoreHandle,
    url: *const c_char,
    timeout_ms: u64,
    outbound_tag: *const c_char,
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

    if url.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "startup probe URL is null");
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    if handle.core.is_some() {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "startup probe must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    let url = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(url) => url,
        Err(err) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::InvalidUtf8,
                    format!("startup probe URL is not valid UTF-8: {err}"),
                );
            }
            return XrayStatus::InvalidUtf8;
        }
    };
    if url.is_empty() {
        unsafe {
            set_error(error, XrayStatus::ConfigError, "startup probe URL is empty");
        }
        return XrayStatus::ConfigError;
    }
    if timeout_ms == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::ConfigError,
                "startup probe timeout must be positive",
            );
        }
        return XrayStatus::ConfigError;
    }

    let outbound_tag = if outbound_tag.is_null() {
        None
    } else {
        let outbound_tag = match unsafe { CStr::from_ptr(outbound_tag) }.to_str() {
            Ok(outbound_tag) => outbound_tag,
            Err(err) => {
                unsafe {
                    set_error(
                        error,
                        XrayStatus::InvalidUtf8,
                        format!("startup probe outbound tag is not valid UTF-8: {err}"),
                    );
                }
                return XrayStatus::InvalidUtf8;
            }
        };
        if outbound_tag.is_empty() {
            None
        } else {
            Some(outbound_tag.to_owned())
        }
    };

    handle.startup_probe_options = Some(StartupProbeOptions {
        url: url.to_owned(),
        timeout: Duration::from_millis(timeout_ms),
        outbound_tag,
    });

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
    packet_format: c_int,
    close_policy: c_int,
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
    packet_format: c_int,
    close_policy: c_int,
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
                XrayStatus::InvalidArgument,
                "tun fd must be non-negative",
            );
        }
        return XrayStatus::InvalidArgument;
    }
    let packet_format = match XrayTunFdPacketFormat::try_from(packet_format) {
        Ok(packet_format) => packet_format,
        Err(message) => {
            unsafe {
                set_error(error, XrayStatus::InvalidArgument, message);
            }
            return XrayStatus::InvalidArgument;
        }
    };
    let close_policy = match XrayTunFdClosePolicy::try_from(close_policy) {
        Ok(close_policy) => close_policy,
        Err(message) => {
            unsafe {
                set_error(error, XrayStatus::InvalidArgument, message);
            }
            return XrayStatus::InvalidArgument;
        }
    };

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

    let replacement = TunFdConfig::new(fd, packet_format.into(), close_policy.into());
    if let Some(old) = handle.tun_fd_config.replace(replacement) {
        // Reconfiguring the same descriptor transfers its current ownership
        // policy. Closing the old `Owned` config here would invalidate the
        // replacement and could later close an unrelated descriptor that
        // reused the same numeric fd.
        if old.fd() != fd {
            old.close_if_owned();
        }
    }

    XrayStatus::Ok
}

/// Enables or disables TCP timing diagnostics in the TUN TCP bridge.
///
/// When disabled, the TCP bridge does not read clocks or update timing
/// counters. Set this before loading config.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. If `error` is non-null, it must point to an initialized
/// `*mut XrayError` value that is either null or a live error pointer returned
/// by this library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_tun_collect_tcp_timings(
    handle: *mut XrayCoreHandle,
    collect_tcp_timings: c_int,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_tun_collect_tcp_timings_inner(handle, collect_tcp_timings, error)
        })
    }
}

unsafe fn xray_core_set_tun_collect_tcp_timings_inner(
    handle: *mut XrayCoreHandle,
    collect_tcp_timings: c_int,
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
                "tun TCP timing collection must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    handle.tun_runtime_options.collect_tcp_timings = collect_tcp_timings != 0;
    XrayStatus::Ok
}

/// Selects the TUN runtime performance profile.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. The profile must be one of `XrayTunRuntimeProfile`.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_tun_runtime_profile(
    handle: *mut XrayCoreHandle,
    profile: c_int,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_tun_runtime_profile_inner(handle, profile, error)
        })
    }
}

unsafe fn xray_core_set_tun_runtime_profile_inner(
    handle: *mut XrayCoreHandle,
    profile: c_int,
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
    let profile = match XrayTunRuntimeProfile::try_from(profile) {
        Ok(profile) => profile,
        Err(message) => {
            unsafe {
                set_error(error, XrayStatus::InvalidArgument, message);
            }
            return XrayStatus::InvalidArgument;
        }
    };

    let handle = unsafe { &mut *handle };
    if handle.core.is_some() {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "tun runtime profile must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    handle.tun_runtime_options.profile = profile.into();
    XrayStatus::Ok
}

/// Selects the DNS bootstrap policy used by managed runtime DNS.
///
/// Set this before loading config. `System` is the general-purpose default;
/// tunnel integrations that install a local DNS interception anchor can choose
/// `StaticOnly` after completing any required host-side bootstrap.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. The mode must be one of `XrayDnsBootstrapMode`.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_dns_bootstrap_mode(
    handle: *mut XrayCoreHandle,
    mode: c_int,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_dns_bootstrap_mode_inner(handle, mode, error)
        })
    }
}

unsafe fn xray_core_set_dns_bootstrap_mode_inner(
    handle: *mut XrayCoreHandle,
    mode: c_int,
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
    let mode = match XrayDnsBootstrapMode::try_from(mode) {
        Ok(mode) => mode,
        Err(message) => {
            unsafe {
                set_error(error, XrayStatus::InvalidArgument, message);
            }
            return XrayStatus::InvalidArgument;
        }
    };

    let handle = unsafe { &mut *handle };
    if handle.core.is_some() {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "DNS bootstrap mode must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    handle.tun_runtime_options.dns_bootstrap = mode.into();
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

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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
    let mtu = core.tun().mtu();
    if len > mtu || len > isize::MAX as usize {
        unsafe {
            set_error(
                error,
                XrayStatus::InvalidArgument,
                format!("packet length {len} exceeds mtu {mtu}"),
            );
        }
        return XrayStatus::InvalidArgument;
    }

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
/// If `buffer_len` is too small, it returns `XrayStatus::BufferTooSmall`,
/// writes the required packet length to `written`, and retains the packet for
/// the next `xray_tun_poll_packet` call.
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

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let pending_packet = match handle.pending_outbound_packets.lock() {
        Ok(mut pending_packets) => pending_packets.pop_front(),
        Err(poisoned) => poisoned.into_inner().pop_front(),
    };
    let polled_packet = if let Some(packet) = pending_packet {
        Ok(Some(packet))
    } else {
        handle.runtime.block_on(core.tun().try_poll_outbound())
    };

    match polled_packet {
        Ok(Some(packet)) if packet.len() <= buffer_len => {
            unsafe {
                ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
                *written = packet.len();
            }
            XrayStatus::Ok
        }
        Ok(Some(packet)) => {
            unsafe {
                *written = packet.len();
                set_error(
                    error,
                    XrayStatus::BufferTooSmall,
                    format!(
                        "packet length {} exceeds output buffer length {buffer_len}",
                        packet.len()
                    ),
                );
            }
            match handle.pending_outbound_packets.lock() {
                Ok(mut pending_packets) => pending_packets.push_front(packet),
                Err(poisoned) => poisoned.into_inner().push_front(packet),
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

/// Polls a batch of raw IP packets emitted by the core for the host TUN
/// adapter.
///
/// Waits up to `wait_ms` milliseconds for the first packet (`0` polls without
/// waiting), then drains additional ready packets without waiting. Packets are
/// written back-to-back into `buffer`; `packet_lengths[i]` receives the length
/// of packet `i` and `*packet_count` the number of packets written. At most
/// `min(max_packets, buffer_len / mtu)` packets are returned per call.
///
/// Returns `XRAY_STATUS_NO_PACKET` if no packet arrived within `wait_ms`.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `buffer` must point to `buffer_len` writable bytes.
/// `packet_lengths` must point to `max_packets` writable `usize` values.
/// `packet_count` must point to one writable `usize`. If `error` is non-null,
/// it must point to an initialized `*mut XrayError` value that is either null
/// or a live error pointer returned by this library. This function may free
/// and replace that error pointer.
///
/// This function may be called concurrently with `xray_tun_push_packet`,
/// `xray_tun_poll_packet`, and `xray_tun_stats` on the same handle, but not
/// concurrently with lifecycle functions (`xray_core_load_config_json`,
/// `xray_core_start`, `xray_core_stop`, `xray_core_set_*`, `xray_core_free`).
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_packets(
    handle: *mut XrayCoreHandle,
    buffer: *mut u8,
    buffer_len: usize,
    packet_lengths: *mut usize,
    max_packets: usize,
    packet_count: *mut usize,
    wait_ms: u32,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_packets_inner(
                handle,
                buffer,
                buffer_len,
                packet_lengths,
                max_packets,
                packet_count,
                wait_ms,
                error,
            )
        })
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn xray_tun_poll_packets_inner(
    handle: *mut XrayCoreHandle,
    buffer: *mut u8,
    buffer_len: usize,
    packet_lengths: *mut usize,
    max_packets: usize,
    packet_count: *mut usize,
    wait_ms: u32,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !packet_count.is_null() {
        unsafe {
            *packet_count = 0;
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
    if packet_lengths.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "packet lengths pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if packet_count.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "packet count pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if max_packets == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "max_packets must be nonzero",
            );
        }
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &*handle };
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

    let tun = core.tun();
    // Every outbound packet is bounded by the tun mtu, so reserving one mtu of
    // buffer per packet guarantees the drained batch always fits.
    let effective_max = max_packets.min(buffer_len / tun.mtu().max(1));
    if effective_max == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                format!(
                    "buffer length {buffer_len} is below the tun mtu {}",
                    tun.mtu()
                ),
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    let pending_packet = match handle.pending_outbound_packets.lock() {
        Ok(mut pending_packets) => pending_packets.pop_front(),
        Err(poisoned) => poisoned.into_inner().pop_front(),
    };
    if let Some(packet) = pending_packet {
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
            *packet_lengths = packet.len();
            *packet_count = 1;
        }
        return XrayStatus::Ok;
    }

    let wait = Duration::from_millis(u64::from(wait_ms));
    let batch = handle.runtime.block_on(async {
        tokio::time::timeout(wait, tun.poll_outbound_batch(effective_max)).await
    });

    match batch {
        Err(_) => XrayStatus::NoPacket,
        Ok(Err(err)) => {
            unsafe {
                set_error(error, XrayStatus::TunError, err.to_string());
            }
            XrayStatus::TunError
        }
        Ok(Ok(packets)) if packets.is_empty() => XrayStatus::NoPacket,
        Ok(Ok(packets)) => {
            let mut offset = 0usize;
            let mut written = 0usize;
            for packet in &packets {
                if offset + packet.len() > buffer_len || written >= max_packets {
                    break;
                }
                unsafe {
                    ptr::copy_nonoverlapping(packet.as_ptr(), buffer.add(offset), packet.len());
                    *packet_lengths.add(written) = packet.len();
                }
                offset += packet.len();
                written += 1;
            }
            unsafe {
                *packet_count = written;
            }
            XrayStatus::Ok
        }
    }
}

/// Polls one debug-only TCP slow-flow event from the TUN endpoint.
///
/// Returns `XRAY_STATUS_NO_PACKET` when no event is buffered. `target_buffer`
/// and `outbound_tag_buffer` receive NUL-terminated labels, truncated if needed.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `event`, `target_buffer`, `target_written`,
/// `outbound_tag_buffer`, and `outbound_tag_written` must point to writable
/// memory. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_tcp_slow_flow_event(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpSlowFlowEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_tcp_slow_flow_event_inner(
                handle,
                event,
                target_buffer,
                target_buffer_len,
                target_written,
                error,
            )
        })
    }
}

unsafe fn xray_tun_poll_tcp_slow_flow_event_inner(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpSlowFlowEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !target_written.is_null() {
        unsafe {
            *target_written = 0;
        }
    }
    if !target_buffer.is_null() && target_buffer_len > 0 {
        unsafe {
            *target_buffer = 0;
        }
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if event.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "slow-flow event pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "slow-flow target buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "slow-flow target written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "slow-flow target buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let Some(slow_flow) = core.tun().poll_tcp_slow_flow_event() else {
        return XrayStatus::NoPacket;
    };

    unsafe {
        *event = XrayTcpSlowFlowEvent {
            kind: slow_flow.kind.into(),
            open_duration_ms: slow_flow.open_duration_ms,
            first_byte_duration_ms: slow_flow.first_byte_duration_ms,
        };
        write_c_string_truncated(
            &slow_flow.target,
            target_buffer,
            target_buffer_len,
            target_written,
        );
    }
    XrayStatus::Ok
}

/// Polls one debug-only TCP flow-summary event from the TUN endpoint.
///
/// Returns `XRAY_STATUS_NO_PACKET` when no event is buffered. `target_buffer`
/// receives a NUL-terminated target label, truncated if needed.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `event`, `target_buffer`, and `target_written` must
/// point to writable memory. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_tcp_flow_summary_event(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpFlowSummaryEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    outbound_tag_buffer: *mut c_char,
    outbound_tag_buffer_len: usize,
    outbound_tag_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_tcp_flow_summary_event_inner(
                handle,
                event,
                target_buffer,
                target_buffer_len,
                target_written,
                outbound_tag_buffer,
                outbound_tag_buffer_len,
                outbound_tag_written,
                error,
            )
        })
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn xray_tun_poll_tcp_flow_summary_event_inner(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpFlowSummaryEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    outbound_tag_buffer: *mut c_char,
    outbound_tag_buffer_len: usize,
    outbound_tag_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !target_written.is_null() {
        unsafe {
            *target_written = 0;
        }
    }
    if !target_buffer.is_null() && target_buffer_len > 0 {
        unsafe {
            *target_buffer = 0;
        }
    }
    if !outbound_tag_written.is_null() {
        unsafe {
            *outbound_tag_written = 0;
        }
    }
    if !outbound_tag_buffer.is_null() && outbound_tag_buffer_len > 0 {
        unsafe {
            *outbound_tag_buffer = 0;
        }
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if event.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP flow-summary event pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP flow-summary target buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP flow-summary target written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if outbound_tag_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP flow-summary outbound tag buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if outbound_tag_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP flow-summary outbound tag written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "TCP flow-summary target buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }
    if outbound_tag_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "TCP flow-summary outbound tag buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let Some(summary) = core.tun().poll_tcp_flow_summary_event() else {
        return XrayStatus::NoPacket;
    };

    unsafe {
        *event = XrayTcpFlowSummaryEvent {
            closed: u64::from(summary.closed),
            duration_ms: summary.duration_ms,
            open_duration_ms: summary.open_duration_ms,
            first_byte_duration_ms: summary.first_byte_duration_ms,
            remote_read_bytes: summary.remote_read_bytes,
            ms_to_64kib: summary.ms_to_64kib,
            ms_to_128kib: summary.ms_to_128kib,
            ms_to_256kib: summary.ms_to_256kib,
            ms_to_512kib: summary.ms_to_512kib,
            ms_to_1mib: summary.ms_to_1mib,
        };
        write_c_string_truncated(
            &summary.target,
            target_buffer,
            target_buffer_len,
            target_written,
        );
        write_c_string_truncated(
            summary.outbound_tag.as_deref().unwrap_or(""),
            outbound_tag_buffer,
            outbound_tag_buffer_len,
            outbound_tag_written,
        );
    }
    XrayStatus::Ok
}

/// Polls one debug-only TCP open-error event from the TUN endpoint.
///
/// Returns `XRAY_STATUS_NO_PACKET` when no event is buffered. `target_buffer`,
/// `outbound_tag_buffer`, and `error_message_buffer` receive NUL-terminated
/// strings, truncated if needed.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `event`, string buffers, and written pointers must point
/// to writable memory. If `error` is non-null, it must point to an initialized
/// `*mut XrayError` value that is either null or a live error pointer returned
/// by this library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_tcp_open_error_event(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpOpenErrorEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    outbound_tag_buffer: *mut c_char,
    outbound_tag_buffer_len: usize,
    outbound_tag_written: *mut usize,
    error_message_buffer: *mut c_char,
    error_message_buffer_len: usize,
    error_message_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_tcp_open_error_event_inner(
                handle,
                event,
                target_buffer,
                target_buffer_len,
                target_written,
                outbound_tag_buffer,
                outbound_tag_buffer_len,
                outbound_tag_written,
                error_message_buffer,
                error_message_buffer_len,
                error_message_written,
                error,
            )
        })
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn xray_tun_poll_tcp_open_error_event_inner(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpOpenErrorEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    outbound_tag_buffer: *mut c_char,
    outbound_tag_buffer_len: usize,
    outbound_tag_written: *mut usize,
    error_message_buffer: *mut c_char,
    error_message_buffer_len: usize,
    error_message_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !target_written.is_null() {
        unsafe {
            *target_written = 0;
        }
    }
    if !target_buffer.is_null() && target_buffer_len > 0 {
        unsafe {
            *target_buffer = 0;
        }
    }
    if !outbound_tag_written.is_null() {
        unsafe {
            *outbound_tag_written = 0;
        }
    }
    if !outbound_tag_buffer.is_null() && outbound_tag_buffer_len > 0 {
        unsafe {
            *outbound_tag_buffer = 0;
        }
    }
    if !error_message_written.is_null() {
        unsafe {
            *error_message_written = 0;
        }
    }
    if !error_message_buffer.is_null() && error_message_buffer_len > 0 {
        unsafe {
            *error_message_buffer = 0;
        }
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if event.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP open-error event pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP open-error target buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP open-error target written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if outbound_tag_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP open-error outbound tag buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if outbound_tag_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP open-error outbound tag written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if error_message_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP open-error message buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if error_message_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP open-error message written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "TCP open-error target buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }
    if outbound_tag_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "TCP open-error outbound tag buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }
    if error_message_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "TCP open-error message buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let Some(open_error) = core.tun().poll_tcp_open_error_event() else {
        return XrayStatus::NoPacket;
    };

    unsafe {
        *event = XrayTcpOpenErrorEvent { reserved: 0 };
        write_c_string_truncated(
            &open_error.target,
            target_buffer,
            target_buffer_len,
            target_written,
        );
        write_c_string_truncated(
            open_error.outbound_tag.as_deref().unwrap_or(""),
            outbound_tag_buffer,
            outbound_tag_buffer_len,
            outbound_tag_written,
        );
        write_c_string_truncated(
            &open_error.error,
            error_message_buffer,
            error_message_buffer_len,
            error_message_written,
        );
    }
    XrayStatus::Ok
}

/// Polls one debug-only TCP remote-write slow event from the TUN endpoint.
///
/// Returns `XRAY_STATUS_NO_PACKET` when no event is buffered. `target_buffer`
/// and `outbound_tag_buffer` receive NUL-terminated labels, truncated if needed.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `event`, `target_buffer`, `target_written`,
/// `outbound_tag_buffer`, and `outbound_tag_written` must point to writable
/// memory. If `error` is non-null, it must point to an initialized
/// `*mut XrayError` value that is either null or a live error pointer returned
/// by this library. This function may free and replace that error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_tcp_remote_write_slow_event(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpRemoteWriteSlowEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    outbound_tag_buffer: *mut c_char,
    outbound_tag_buffer_len: usize,
    outbound_tag_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_tcp_remote_write_slow_event_inner(
                handle,
                event,
                target_buffer,
                target_buffer_len,
                target_written,
                outbound_tag_buffer,
                outbound_tag_buffer_len,
                outbound_tag_written,
                error,
            )
        })
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn xray_tun_poll_tcp_remote_write_slow_event_inner(
    handle: *mut XrayCoreHandle,
    event: *mut XrayTcpRemoteWriteSlowEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    outbound_tag_buffer: *mut c_char,
    outbound_tag_buffer_len: usize,
    outbound_tag_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !target_written.is_null() {
        unsafe {
            *target_written = 0;
        }
    }
    if !target_buffer.is_null() && target_buffer_len > 0 {
        unsafe {
            *target_buffer = 0;
        }
    }
    if !outbound_tag_written.is_null() {
        unsafe {
            *outbound_tag_written = 0;
        }
    }
    if !outbound_tag_buffer.is_null() && outbound_tag_buffer_len > 0 {
        unsafe {
            *outbound_tag_buffer = 0;
        }
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if event.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP remote-write slow event pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP remote-write slow target buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP remote-write slow target written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if outbound_tag_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP remote-write slow outbound tag buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if outbound_tag_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "TCP remote-write slow outbound tag written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "TCP remote-write slow target buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }
    if outbound_tag_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "TCP remote-write slow outbound tag buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let Some(slow_write) = core.tun().poll_tcp_remote_write_slow_event() else {
        return XrayStatus::NoPacket;
    };

    unsafe {
        *event = XrayTcpRemoteWriteSlowEvent {
            duration_ms: slow_write.duration_ms,
            bytes: slow_write.bytes,
            messages: slow_write.messages,
        };
        write_c_string_truncated(
            &slow_write.target,
            target_buffer,
            target_buffer_len,
            target_written,
        );
        write_c_string_truncated(
            slow_write.outbound_tag.as_deref().unwrap_or(""),
            outbound_tag_buffer,
            outbound_tag_buffer_len,
            outbound_tag_written,
        );
    }
    XrayStatus::Ok
}

/// Polls one debug-only UDP slow-flow event from the TUN endpoint.
///
/// Returns `XRAY_STATUS_NO_PACKET` when no event is buffered. `target_buffer`
/// receives a NUL-terminated target label, truncated if needed.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `event`, `target_buffer`, and `target_written` must
/// point to writable memory. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_udp_slow_flow_event(
    handle: *mut XrayCoreHandle,
    event: *mut XrayUdpSlowFlowEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_udp_slow_flow_event_inner(
                handle,
                event,
                target_buffer,
                target_buffer_len,
                target_written,
                error,
            )
        })
    }
}

unsafe fn xray_tun_poll_udp_slow_flow_event_inner(
    handle: *mut XrayCoreHandle,
    event: *mut XrayUdpSlowFlowEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !target_written.is_null() {
        unsafe {
            *target_written = 0;
        }
    }
    if !target_buffer.is_null() && target_buffer_len > 0 {
        unsafe {
            *target_buffer = 0;
        }
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if event.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "slow-flow event pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "slow-flow target buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "slow-flow target written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "slow-flow target buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let Some(slow_flow) = core.tun().poll_udp_slow_flow_event() else {
        return XrayStatus::NoPacket;
    };

    unsafe {
        *event = XrayUdpSlowFlowEvent {
            first_response_duration_ms: slow_flow.first_response_duration_ms,
            written_bytes: slow_flow.written_bytes,
            read_bytes: slow_flow.read_bytes,
        };
        write_c_string_truncated(
            &slow_flow.target,
            target_buffer,
            target_buffer_len,
            target_written,
        );
    }
    XrayStatus::Ok
}

/// Polls one debug-only UDP response-gap event from the TUN endpoint.
///
/// Returns `XRAY_STATUS_NO_PACKET` when no event is buffered. `target_buffer`
/// receives a NUL-terminated target label, truncated if needed.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `event`, `target_buffer`, and `target_written` must
/// point to writable memory. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_udp_response_gap_event(
    handle: *mut XrayCoreHandle,
    event: *mut XrayUdpResponseGapEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_udp_response_gap_event_inner(
                handle,
                event,
                target_buffer,
                target_buffer_len,
                target_written,
                error,
            )
        })
    }
}

unsafe fn xray_tun_poll_udp_response_gap_event_inner(
    handle: *mut XrayCoreHandle,
    event: *mut XrayUdpResponseGapEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !target_written.is_null() {
        unsafe {
            *target_written = 0;
        }
    }
    if !target_buffer.is_null() && target_buffer_len > 0 {
        unsafe {
            *target_buffer = 0;
        }
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if event.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "response-gap event pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "response-gap target buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "response-gap target written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "response-gap target buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let Some(response_gap) = core.tun().poll_udp_response_gap_event() else {
        return XrayStatus::NoPacket;
    };

    unsafe {
        *event = XrayUdpResponseGapEvent {
            response_gap_duration_ms: response_gap.response_gap_duration_ms,
            written_bytes: response_gap.written_bytes,
            read_bytes: response_gap.read_bytes,
        };
        write_c_string_truncated(
            &response_gap.target,
            target_buffer,
            target_buffer_len,
            target_written,
        );
    }
    XrayStatus::Ok
}

/// Polls one debug-only UDP QUIC-blocked event from the TUN endpoint.
///
/// Returns `XRAY_STATUS_NO_PACKET` when no event is buffered. `target_buffer`
/// receives a NUL-terminated target label, truncated if needed.
///
/// # Safety
///
/// `handle` must either be null or a pointer returned by `xray_core_new` that
/// has not been freed. `event`, `target_buffer`, and `target_written` must
/// point to writable memory. If `error` is non-null, it must point to an
/// initialized `*mut XrayError` value that is either null or a live error
/// pointer returned by this library. This function may free and replace that
/// error pointer.
#[no_mangle]
pub unsafe extern "C" fn xray_tun_poll_udp_quic_blocked_event(
    handle: *mut XrayCoreHandle,
    event: *mut XrayUdpQuicBlockedEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_tun_poll_udp_quic_blocked_event_inner(
                handle,
                event,
                target_buffer,
                target_buffer_len,
                target_written,
                error,
            )
        })
    }
}

unsafe fn xray_tun_poll_udp_quic_blocked_event_inner(
    handle: *mut XrayCoreHandle,
    event: *mut XrayUdpQuicBlockedEvent,
    target_buffer: *mut c_char,
    target_buffer_len: usize,
    target_written: *mut usize,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }

    if !target_written.is_null() {
        unsafe {
            *target_written = 0;
        }
    }
    if !target_buffer.is_null() && target_buffer_len > 0 {
        unsafe {
            *target_buffer = 0;
        }
    }

    if handle.is_null() {
        unsafe {
            set_error(error, XrayStatus::NullArgument, "core handle is null");
        }
        return XrayStatus::NullArgument;
    }
    if event.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "QUIC-blocked event pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "QUIC-blocked target buffer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_written.is_null() {
        unsafe {
            set_error(
                error,
                XrayStatus::NullArgument,
                "QUIC-blocked target written pointer is null",
            );
        }
        return XrayStatus::NullArgument;
    }
    if target_buffer_len == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                "QUIC-blocked target buffer length is zero",
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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

    let Some(blocked) = core.tun().poll_udp_quic_blocked_event() else {
        return XrayStatus::NoPacket;
    };

    unsafe {
        *event = XrayUdpQuicBlockedEvent {
            bytes: blocked.bytes,
        };
        write_c_string_truncated(
            &blocked.target,
            target_buffer,
            target_buffer_len,
            target_written,
        );
    }
    XrayStatus::Ok
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
    let expected_size = std::mem::size_of::<XrayTunStats>();
    let caller_size = unsafe { (*stats).struct_size };
    if caller_size < expected_size {
        unsafe {
            set_error(
                error,
                XrayStatus::BufferTooSmall,
                format!(
                    "tun stats struct is {caller_size} bytes; at least {expected_size} bytes are required"
                ),
            );
        }
        return XrayStatus::BufferTooSmall;
    }

    // Shared access: data-path entry points may run concurrently with each
    // other (Swift pump push/poll threads); only lifecycle calls take `&mut`.
    let handle = unsafe { &*handle };
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
            struct_size: expected_size,
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
            tcp_remote_write_wait_events: snapshot.tcp_remote_write_wait_events,
            tcp_remote_write_wait_ms_total: snapshot.tcp_remote_write_wait_ms_total,
            tcp_remote_write_wait_ms_max: snapshot.tcp_remote_write_wait_ms_max,
            tcp_remote_flush_wait_events: snapshot.tcp_remote_flush_wait_events,
            tcp_remote_flush_wait_ms_total: snapshot.tcp_remote_flush_wait_ms_total,
            tcp_remote_flush_wait_ms_max: snapshot.tcp_remote_flush_wait_ms_max,
            tcp_pending_remote_bytes: snapshot.tcp_pending_remote_bytes,
            tcp_pending_remote_flows: snapshot.tcp_pending_remote_flows,
            tcp_pending_remote_max_bytes: snapshot.tcp_pending_remote_max_bytes,
            tcp_pending_upload_bytes: snapshot.tcp_pending_upload_bytes,
            tcp_pending_upload_max_bytes: snapshot.tcp_pending_upload_max_bytes,
            tcp_pending_total_bytes: snapshot.tcp_pending_total_bytes,
            tcp_remote_buffer_limit_bytes: snapshot.tcp_remote_buffer_limit_bytes,
            tcp_buffer_hard_limit_bytes: snapshot.tcp_buffer_hard_limit_bytes,
            tcp_remote_buffer_pressure_active: if snapshot.tcp_remote_buffer_pressure_active {
                1
            } else {
                0
            },
            tcp_remote_write_errors: snapshot.tcp_remote_write_errors,
            tcp_remote_closed_events: snapshot.tcp_remote_closed_events,
            tcp_remote_read_errors: snapshot.tcp_remote_read_errors,
            tcp_open_errors: snapshot.tcp_open_errors,
            tcp_open_events: snapshot.tcp_open_events,
            tcp_open_duration_ms_total: snapshot.tcp_open_duration_ms_total,
            tcp_open_duration_ms_max: snapshot.tcp_open_duration_ms_max,
            tcp_first_byte_events: snapshot.tcp_first_byte_events,
            tcp_first_byte_duration_ms_total: snapshot.tcp_first_byte_duration_ms_total,
            tcp_first_byte_duration_ms_max: snapshot.tcp_first_byte_duration_ms_max,
            tcp443_open_events: snapshot.tcp443_open_events,
            tcp443_open_duration_ms_total: snapshot.tcp443_open_duration_ms_total,
            tcp443_open_duration_ms_max: snapshot.tcp443_open_duration_ms_max,
            tcp443_first_byte_events: snapshot.tcp443_first_byte_events,
            tcp443_first_byte_duration_ms_total: snapshot.tcp443_first_byte_duration_ms_total,
            tcp443_first_byte_duration_ms_max: snapshot.tcp443_first_byte_duration_ms_max,
            active_tcp_flows: snapshot.active_tcp_flows,
            active_udp_flows: snapshot.active_udp_flows,
            udp_flow_limit: snapshot.udp_flow_limit,
            udp_budget_drops: snapshot.udp_budget_drops,
            udp_evicted_flows: snapshot.udp_evicted_flows,
            udp_channel_dropped_packets: snapshot.udp_channel_dropped_packets,
            udp_remote_open_events: snapshot.udp_remote_open_events,
            udp_remote_udp443_open_events: snapshot.udp_remote_udp443_open_events,
            udp_remote_written_bytes: snapshot.udp_remote_written_bytes,
            udp_remote_read_bytes: snapshot.udp_remote_read_bytes,
            udp_open_errors: snapshot.udp_open_errors,
            udp_vision_udp443_rejections: snapshot.udp_vision_udp443_rejections,
            udp_remote_write_errors: snapshot.udp_remote_write_errors,
            udp_remote_read_errors: snapshot.udp_remote_read_errors,
            udp_remote_closed_events: snapshot.udp_remote_closed_events,
            udp_quic_blocked_packets: snapshot.udp_quic_blocked_packets,
            inbound_queue_depth: snapshot.inbound_queue_depth,
            outbound_queue_depth: snapshot.outbound_queue_depth,
            inbound_queue_max_packets: snapshot.inbound_queue_max_packets,
            outbound_queue_max_packets: snapshot.outbound_queue_max_packets,
            tun_fd_write_batches: snapshot.tun_fd_write_batches,
            tun_fd_write_batch_packets: snapshot.tun_fd_write_batch_packets,
            tun_fd_write_batch_max_packets: snapshot.tun_fd_write_batch_max_packets,
            tun_fd_read_loop_exits: snapshot.tun_fd_read_loop_exits,
            tun_fd_write_loop_exits: snapshot.tun_fd_write_loop_exits,
            tun_fd_transient_io_errors: snapshot.tun_fd_transient_io_errors,
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

unsafe fn write_c_string_truncated(
    value: &str,
    buffer: *mut c_char,
    buffer_len: usize,
    written: *mut usize,
) {
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(buffer_len.saturating_sub(1));
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), copy_len);
        *buffer.add(copy_len) = 0;
        *written = copy_len;
    }
}

unsafe fn ffi_status(
    error: *mut *mut XrayError,
    action: impl FnOnce() -> XrayStatus,
) -> XrayStatus {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(status) => status,
        Err(payload) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::Panic,
                    ffi_panic_message(payload.as_ref()),
                );
            }
            XrayStatus::Panic
        }
    }
}

fn ffi_panic_message(payload: &(dyn Any + Send)) -> String {
    let detail = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload");
    format!("panic caught at FFI boundary: {detail}")
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

fn format_config_diagnostics(diagnostics: &[xray_config::Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| match diagnostic.path.as_deref() {
            Some(path) => format!("{path}: {}", diagnostic.message),
            None => diagnostic.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("\n")
        .replace('\0', "")
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
    // Modern phones expose 6 cores; capping below that leaves cores idle when
    // many parallel flows (e.g. a speedtest) need TLS and relay work at once.
    available.clamp(2, 6)
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr;

    use super::{
        ffi_panic_message, ffi_status, free_error,
        runtime_worker_threads_for_available_parallelism, xray_core_free, xray_core_new,
        xray_core_set_dns_bootstrap_mode, DnsBootstrapMode, XrayDnsBootstrapMode, XrayError,
        XrayStatus,
    };

    #[test]
    fn runtime_worker_threads_use_available_parallelism_with_mobile_bounds() {
        assert_eq!(runtime_worker_threads_for_available_parallelism(1), 2);
        assert_eq!(runtime_worker_threads_for_available_parallelism(2), 2);
        assert_eq!(runtime_worker_threads_for_available_parallelism(3), 3);
        assert_eq!(runtime_worker_threads_for_available_parallelism(4), 4);
        assert_eq!(runtime_worker_threads_for_available_parallelism(6), 6);
        assert_eq!(runtime_worker_threads_for_available_parallelism(8), 6);
    }

    #[test]
    fn ffi_core_defaults_to_system_dns_resolution() {
        let mut error = ptr::null_mut();
        let handle = unsafe { xray_core_new(&mut error) };

        assert!(!handle.is_null());
        assert!(error.is_null());
        assert_eq!(
            unsafe { (*handle).tun_runtime_options.dns_bootstrap },
            DnsBootstrapMode::System
        );

        unsafe { xray_core_free(handle) };
    }

    #[test]
    fn ffi_core_can_select_static_only_dns_resolution() {
        let mut error = ptr::null_mut();
        let handle = unsafe { xray_core_new(&mut error) };

        let status = unsafe {
            xray_core_set_dns_bootstrap_mode(
                handle,
                XrayDnsBootstrapMode::StaticOnly as libc::c_int,
                &mut error,
            )
        };

        assert_eq!(status, XrayStatus::Ok);
        assert!(error.is_null());
        assert_eq!(
            unsafe { (*handle).tun_runtime_options.dns_bootstrap },
            DnsBootstrapMode::StaticOnly
        );

        unsafe { xray_core_free(handle) };
    }

    #[test]
    fn ffi_panic_message_preserves_string_payload() {
        let payload = "reality state invariant";

        assert_eq!(
            ffi_panic_message(&payload),
            "panic caught at FFI boundary: reality state invariant"
        );
    }

    #[test]
    fn ffi_status_catches_panic_and_returns_payload() {
        let mut error: *mut XrayError = ptr::null_mut();

        let status = unsafe { ffi_status(&mut error, || panic!("injected FFI panic")) };

        assert_eq!(status, XrayStatus::Panic);
        assert!(!error.is_null());
        let message = unsafe { CStr::from_ptr((*error).message) }
            .to_str()
            .unwrap();
        assert_eq!(message, "panic caught at FFI boundary: injected FFI panic");
        unsafe {
            free_error(error);
        }
    }
}
