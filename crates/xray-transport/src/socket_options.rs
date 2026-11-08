//! Xray-core's `streamSettings.sockopt`, applied to each socket an outbound
//! opens, as `applyOutboundSocketOptions` and Go's `net.Dialer` apply them.
//!
//! [`SocketOptionsProtector`] runs where Go's `Dialer.Control` runs: after
//! the platform's own protection and before the socket connects or sends. On
//! Linux and Android, and on Apple platforms, the options go on in Xray-core's
//! order for that platform. The first one that fails stops the rest and is
//! only reported, except binding to an interface, whose failure fails the
//! dial. TCP keepalive then follows Go's dialer: on after 45 seconds idle and
//! every 45 seconds unless the options say otherwise, whatever happened to the
//! options before it.

// Systems Xray-core sets no outbound socket option on compile only the parts
// every system shares.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple")),
    allow(dead_code)
)]

use std::{fmt, io, sync::Arc};

use crate::{SocketHandle, SocketProtector};

/// Go's `Dialer.KeepAliveConfig` defaults in Xray-core's system dialer.
pub const DEFAULT_TCP_KEEPALIVE_SECS: i32 = 45;

/// The socket-level part of one outbound's `sockopt`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketOptions {
    /// `SO_MARK` on Linux and Android; zero sets nothing.
    pub mark: i32,
    /// `tcpFastOpen` as Xray-core stores it: zero when unset, 256 for `true`,
    /// -1 for `false`, otherwise the configured number.
    pub tcp_fast_open: i32,
    /// `tproxy` set to `tproxy` or `redirect`: Linux `IP_TRANSPARENT`.
    pub transparent: bool,
    /// Seconds; zero keeps the 45-second default, negative turns keepalive off.
    pub tcp_keep_alive_idle: i32,
    pub tcp_keep_alive_interval: i32,
    pub tcp_congestion: String,
    pub tcp_window_clamp: i32,
    pub tcp_max_seg: i32,
    /// Milliseconds, Linux `TCP_USER_TIMEOUT`.
    pub tcp_user_timeout: i32,
    /// The device sockets are bound to; empty binds none.
    pub interface: String,
    /// Multipath TCP on Linux and Android, falling back to TCP.
    pub multipath_tcp: bool,
    pub custom: Vec<CustomSocketOption>,
}

/// One `customSockopt` entry, as text read when a socket is set up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustomSocketOption {
    pub system: String,
    pub network: String,
    pub level: String,
    pub opt: String,
    pub value: String,
    pub kind: String,
}

/// Receives an option that failed without failing its dial, as Xray-core
/// logs "failed to apply socket options".
pub type SocketOptionsReport = Arc<dyn Fn(&io::Error) + Send + Sync>;

/// Protects a socket with the platform's protector, then applies `options`.
pub struct SocketOptionsProtector {
    inner: Option<Arc<dyn SocketProtector>>,
    options: Arc<SocketOptions>,
    report: Option<SocketOptionsReport>,
}

impl SocketOptionsProtector {
    pub fn new(
        inner: Option<Arc<dyn SocketProtector>>,
        options: Arc<SocketOptions>,
        report: Option<SocketOptionsReport>,
    ) -> Self {
        Self {
            inner,
            options,
            report,
        }
    }
}

impl fmt::Debug for SocketOptionsProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketOptionsProtector")
            .field("inner", &self.inner.is_some())
            .field("options", &self.options)
            .field("report", &self.report.is_some())
            .finish()
    }
}

impl SocketProtector for SocketOptionsProtector {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        if let Some(inner) = &self.inner {
            inner.protect(socket)?;
        }
        self.options.apply(socket, self.report.as_deref())
    }

    fn multipath_tcp(&self) -> bool {
        self.options.multipath_tcp
    }
}

/// Why an option stopped the others: an interface that cannot be bound fails
/// the dial, as Xray-core's `BindError` does; anything else is only reported.
enum ApplyError {
    Bind(io::Error),
    Other(io::Error),
}

fn option_error(what: impl fmt::Display, error: io::Error) -> ApplyError {
    ApplyError::Other(io::Error::new(error.kind(), format!("{what}: {error}")))
}

fn bind_error(what: impl fmt::Display, error: io::Error) -> ApplyError {
    ApplyError::Bind(io::Error::new(
        error.kind(),
        format!("failed to bind to interface: {what}: {error}"),
    ))
}

/// What Go's dialer tells `Control` about a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketKind {
    tcp: bool,
    ipv6: bool,
}

impl SocketKind {
    /// Go's network name: `tcp4`, `tcp6`, `udp4` or `udp6`.
    fn network(self) -> &'static str {
        match (self.tcp, self.ipv6) {
            (true, false) => "tcp4",
            (true, true) => "tcp6",
            (false, false) => "udp4",
            (false, true) => "udp6",
        }
    }
}

impl SocketOptions {
    /// Xray-core's `ParseTFOValue`: -1 sets nothing, otherwise the value
    /// to set, with a disabled option set to zero.
    fn parsed_tcp_fast_open(&self) -> i32 {
        match self.tcp_fast_open {
            0 => -1,
            value if value < 0 => 0,
            value => value,
        }
    }

    /// Applies the options to `socket`, an unconnected TCP socket or a UDP
    /// socket. Fails when the socket must not be used: a TCP socket whose
    /// keepalive times have opposite signs, or an interface that cannot be
    /// bound.
    pub fn apply(
        &self,
        socket: SocketHandle,
        report: Option<&(dyn Fn(&io::Error) + Send + Sync)>,
    ) -> io::Result<()> {
        #[cfg(unix)]
        {
            let fd = socket.raw() as std::os::fd::RawFd;
            let Some(kind) = sys::socket_kind(fd) else {
                return Ok(());
            };
            // Go multiplies the two int32 values, wrapping as it does.
            if kind.tcp
                && self
                    .tcp_keep_alive_idle
                    .wrapping_mul(self.tcp_keep_alive_interval)
                    < 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: {} {}",
                        self.tcp_keep_alive_idle, self.tcp_keep_alive_interval
                    ),
                ));
            }
            match sys::apply_outbound(fd, kind, self) {
                Ok(()) => {}
                Err(ApplyError::Bind(error)) => return Err(error),
                Err(ApplyError::Other(error)) => {
                    if let Some(report) = report {
                        report(&error);
                    }
                }
            }
            if kind.tcp {
                sys::set_keepalive(fd, self);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (socket, report);
            Ok(())
        }
    }
}

/// Go's `strconv.Atoi` as `customSockopt` uses it, errors ignored: invalid
/// text is zero and an out-of-range number its nearest 64-bit bound.
fn go_atoi(text: &str) -> i64 {
    let (negative, digits) = match text.as_bytes() {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        rest => (false, rest),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return 0;
    }
    let mut value: i128 = 0;
    for digit in digits {
        value = value * 10 + i128::from(digit - b'0');
        if value > i128::from(i64::MAX) + 1 {
            break;
        }
    }
    let value = if negative { -value } else { value };
    value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

#[cfg(unix)]
pub(crate) mod sys {
    use std::{io, os::fd::RawFd};

    use libc::{c_int, c_void, socklen_t};

    use super::{bind_error, go_atoi, option_error, ApplyError, SocketKind, SocketOptions};

    pub(crate) fn set_int(fd: RawFd, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
        // SAFETY: `fd` is a live socket owned by the caller, and the option
        // value is a local `c_int` whose size is passed with it.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&value as *const c_int).cast::<c_void>(),
                std::mem::size_of::<c_int>() as socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Go's `SetsockoptString`: the bytes without a terminator, and no
    /// pointer at all for an empty value.
    fn set_bytes(fd: RawFd, level: c_int, name: c_int, value: &[u8]) -> io::Result<()> {
        let pointer = if value.is_empty() {
            std::ptr::null()
        } else {
            value.as_ptr().cast::<c_void>()
        };
        // SAFETY: `fd` is a live socket owned by the caller, and `pointer`
        // is null or points at `value.len()` readable bytes.
        let result =
            unsafe { libc::setsockopt(fd, level, name, pointer, value.len() as socklen_t) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(crate) fn get_int(fd: RawFd, level: c_int, name: c_int) -> io::Result<c_int> {
        let mut value: c_int = 0;
        let mut length = std::mem::size_of::<c_int>() as socklen_t;
        // SAFETY: `fd` is a live socket, and `value` and `length` are local
        // and describe a writable `c_int`.
        let result = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                (&mut value as *mut c_int).cast::<c_void>(),
                &mut length,
            )
        };
        if result == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Whether `fd` is a TCP or UDP socket, and of which family. Anything
    /// else is left alone.
    pub(super) fn socket_kind(fd: RawFd) -> Option<SocketKind> {
        let tcp = match get_int(fd, libc::SOL_SOCKET, libc::SO_TYPE).ok()? {
            libc::SOCK_STREAM => true,
            libc::SOCK_DGRAM => false,
            _ => return None,
        };
        // SAFETY: `storage` is a zeroed, writable `sockaddr_storage` and
        // `length` holds its size.
        let family = unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let mut length = std::mem::size_of::<libc::sockaddr_storage>() as socklen_t;
            if libc::getsockname(
                fd,
                (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr>(),
                &mut length,
            ) != 0
            {
                return None;
            }
            c_int::from(storage.ss_family)
        };
        let ipv6 = match family {
            libc::AF_INET => false,
            libc::AF_INET6 => true,
            _ => return None,
        };
        Some(SocketKind { tcp, ipv6 })
    }

    /// Go's `runtime.GOOS` for the running platform.
    const GOOS: &str = if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_vendor = "apple") {
        // Go names iOS `ios`; it runs on no other Apple system, whose
        // kernel this one shares.
        "ios"
    } else {
        std::env::consts::OS
    };

    /// `customSockopt`, the same on every platform Xray-core applies it on.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android", target_vendor = "apple")),
        allow(dead_code)
    )]
    fn apply_custom(
        fd: RawFd,
        kind: SocketKind,
        options: &SocketOptions,
    ) -> Result<(), ApplyError> {
        for custom in &options.custom {
            if !custom.system.is_empty() && custom.system != GOOS {
                continue;
            }
            if !kind.network().starts_with(custom.network.as_str()) {
                continue;
            }
            if custom.opt.is_empty() {
                return Err(ApplyError::Other(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No opt!",
                )));
            }
            // Go passes these ints to the system call, which reads 32 bits.
            let opt = go_atoi(&custom.opt) as c_int;
            let level = if custom.level.is_empty() {
                0x6
            } else {
                go_atoi(&custom.level) as c_int
            };
            match custom.kind.as_str() {
                "int" => {
                    let value = go_atoi(&custom.value) as c_int;
                    set_int(fd, level, opt, value).map_err(|error| {
                        option_error(
                            format_args!("failed to set CustomSockoptInt {opt} {value}"),
                            error,
                        )
                    })?;
                }
                "str" => {
                    set_bytes(fd, level, opt, custom.value.as_bytes()).map_err(|error| {
                        option_error(
                            format_args!(
                                "failed to set CustomSockoptString {opt} {}",
                                custom.value
                            ),
                            error,
                        )
                    })?;
                }
                other => {
                    return Err(ApplyError::Other(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown CustomSockopt type: {other}"),
                    )));
                }
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod platform {
        use super::*;

        const SO_MARK: c_int = 36;
        const SO_BINDTODEVICE: c_int = 25;
        const SOL_IP: c_int = 0;
        const SOL_TCP: c_int = 6;
        const TCP_MAXSEG: c_int = 2;
        const TCP_KEEPIDLE: c_int = 4;
        const TCP_KEEPINTVL: c_int = 5;
        const TCP_WINDOW_CLAMP: c_int = 10;
        const TCP_CONGESTION: c_int = 13;
        const TCP_USER_TIMEOUT: c_int = 18;
        const IP_TRANSPARENT: c_int = 19;
        const TCP_FASTOPEN_CONNECT: c_int = 30;

        /// `sockopt_linux.go`'s `applyOutboundSocketOptions`.
        pub(in super::super) fn apply_outbound(
            fd: RawFd,
            kind: SocketKind,
            options: &SocketOptions,
        ) -> Result<(), ApplyError> {
            if options.mark != 0 {
                set_int(fd, libc::SOL_SOCKET, SO_MARK, options.mark)
                    .map_err(|error| option_error("failed to set SO_MARK", error))?;
            }
            if !options.interface.is_empty() {
                set_bytes(
                    fd,
                    libc::SOL_SOCKET,
                    SO_BINDTODEVICE,
                    options.interface.as_bytes(),
                )
                .map_err(|error| bind_error("failed to set Interface", error))?;
            }
            if kind.tcp {
                let mut tfo = options.parsed_tcp_fast_open();
                if tfo > 0 {
                    tfo = 1;
                }
                if tfo >= 0 {
                    set_int(fd, SOL_TCP, TCP_FASTOPEN_CONNECT, tfo).map_err(|error| {
                        option_error(
                            format_args!("failed to set TCP_FASTOPEN_CONNECT {tfo}"),
                            error,
                        )
                    })?;
                }
                if !options.tcp_congestion.is_empty() {
                    set_bytes(
                        fd,
                        SOL_TCP,
                        TCP_CONGESTION,
                        options.tcp_congestion.as_bytes(),
                    )
                    .map_err(|error| option_error("failed to set TCP_CONGESTION", error))?;
                }
                if options.tcp_window_clamp > 0 {
                    set_int(
                        fd,
                        libc::IPPROTO_TCP,
                        TCP_WINDOW_CLAMP,
                        options.tcp_window_clamp,
                    )
                    .map_err(|error| option_error("failed to set TCP_WINDOW_CLAMP", error))?;
                }
                if options.tcp_user_timeout > 0 {
                    set_int(
                        fd,
                        libc::IPPROTO_TCP,
                        TCP_USER_TIMEOUT,
                        options.tcp_user_timeout,
                    )
                    .map_err(|error| option_error("failed to set TCP_USER_TIMEOUT", error))?;
                }
                if options.tcp_max_seg > 0 {
                    set_int(fd, libc::IPPROTO_TCP, TCP_MAXSEG, options.tcp_max_seg)
                        .map_err(|error| option_error("failed to set TCP_MAXSEG", error))?;
                }
            }
            apply_custom(fd, kind, options)?;
            if options.transparent {
                set_int(fd, SOL_IP, IP_TRANSPARENT, 1)
                    .map_err(|error| option_error("failed to set IP_TRANSPARENT", error))?;
            }
            Ok(())
        }

        pub(in super::super) fn set_keepalive_times(
            fd: RawFd,
            idle: c_int,
            interval: c_int,
        ) -> io::Result<()> {
            set_int(fd, libc::IPPROTO_TCP, TCP_KEEPIDLE, idle)?;
            set_int(fd, libc::IPPROTO_TCP, TCP_KEEPINTVL, interval)
        }
    }

    #[cfg(target_vendor = "apple")]
    mod platform {
        use super::*;
        use std::ffi::CString;

        const TCP_KEEPALIVE: c_int = 0x10;
        const TCP_KEEPINTVL: c_int = 0x101;
        const TCP_FASTOPEN: c_int = 0x105;
        const TCP_FASTOPEN_CLIENT: c_int = 0x02;
        const IP_BOUND_IF: c_int = 25;
        const IPV6_BOUND_IF: c_int = 125;

        /// `sockopt_darwin.go`'s `applyOutboundSocketOptions`. The kernel
        /// accepts `TCP_FASTOPEN` only on a listening socket, so a configured
        /// `tcpFastOpen` stops the options after it here as it does there.
        pub(in super::super) fn apply_outbound(
            fd: RawFd,
            kind: SocketKind,
            options: &SocketOptions,
        ) -> Result<(), ApplyError> {
            if kind.tcp {
                let mut tfo = options.parsed_tcp_fast_open();
                if tfo > 0 {
                    tfo = TCP_FASTOPEN_CLIENT;
                }
                if tfo >= 0 {
                    set_int(fd, libc::IPPROTO_TCP, TCP_FASTOPEN, tfo).map_err(ApplyError::Other)?;
                }
                let idle = options.tcp_keep_alive_idle;
                let interval = options.tcp_keep_alive_interval;
                if idle > 0 || interval > 0 {
                    if idle > 0 {
                        set_int(fd, libc::IPPROTO_TCP, TCP_KEEPALIVE, idle)
                            .map_err(|error| option_error("failed to set TCP_KEEPALIVE", error))?;
                    }
                    if interval > 0 {
                        set_int(fd, libc::IPPROTO_TCP, TCP_KEEPINTVL, interval)
                            .map_err(|error| option_error("failed to set TCP_KEEPINTVL", error))?;
                    }
                    set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)
                        .map_err(|error| option_error("failed to set SO_KEEPALIVE", error))?;
                } else if interval < 0 || idle < 0 {
                    set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 0)
                        .map_err(|error| option_error("failed to unset SO_KEEPALIVE", error))?;
                }
            }
            if !options.interface.is_empty() {
                let index = CString::new(options.interface.as_str())
                    .ok()
                    // SAFETY: `name` is a valid NUL-terminated string.
                    .map(|name| unsafe { libc::if_nametoindex(name.as_ptr()) })
                    .filter(|index| *index != 0)
                    .ok_or_else(|| {
                        bind_error(
                            format_args!("failed to get interface {}", options.interface),
                            io::Error::new(io::ErrorKind::NotFound, "no such network interface"),
                        )
                    })?;
                let (level, name, what) = if kind.ipv6 {
                    (
                        libc::IPPROTO_IPV6,
                        IPV6_BOUND_IF,
                        "failed to set IPV6_BOUND_IF",
                    )
                } else {
                    (libc::IPPROTO_IP, IP_BOUND_IF, "failed to set IP_BOUND_IF")
                };
                set_int(fd, level, name, index as c_int)
                    .map_err(|error| bind_error(what, error))?;
            }
            apply_custom(fd, kind, options)
        }

        pub(in super::super) fn set_keepalive_times(
            fd: RawFd,
            idle: c_int,
            interval: c_int,
        ) -> io::Result<()> {
            set_int(fd, libc::IPPROTO_TCP, TCP_KEEPALIVE, idle)?;
            set_int(fd, libc::IPPROTO_TCP, TCP_KEEPINTVL, interval)
        }
    }

    /// Xray-core sets no outbound socket option on other systems.
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    mod platform {
        use super::*;

        pub(in super::super) fn apply_outbound(
            _fd: RawFd,
            _kind: SocketKind,
            _options: &SocketOptions,
        ) -> Result<(), ApplyError> {
            Ok(())
        }

        pub(in super::super) fn set_keepalive_times(
            _fd: RawFd,
            _idle: c_int,
            _interval: c_int,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    pub(super) use platform::apply_outbound;

    /// Go's `TCPConn.SetKeepAliveConfig` as Xray-core's dialer configures it,
    /// whose failure the dialer ignores: on unless a time is negative, then
    /// the idle time and the interval, each 45 seconds unless set.
    pub(super) fn set_keepalive(fd: RawFd, options: &SocketOptions) {
        let idle = options.tcp_keep_alive_idle;
        let interval = options.tcp_keep_alive_interval;
        if idle < 0 || interval < 0 {
            return;
        }
        let seconds = |value: i32| {
            if value > 0 {
                value
            } else {
                super::DEFAULT_TCP_KEEPALIVE_SECS
            }
        };
        if set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1).is_ok() {
            let _ = platform::set_keepalive_times(fd, seconds(idle), seconds(interval));
        }
    }
}

#[cfg(all(test, unix))]
mod socket_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;

    use libc::c_int;

    fn socket(tcp: bool, ipv6: bool) -> socket2::Socket {
        let domain = if ipv6 {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let kind = if tcp {
            socket2::Type::STREAM
        } else {
            socket2::Type::DGRAM
        };
        socket2::Socket::new(domain, kind, None).expect("socket")
    }

    fn handle(socket: &socket2::Socket) -> SocketHandle {
        SocketHandle {
            raw: socket.as_raw_fd() as i64,
        }
    }

    fn get(socket: &socket2::Socket, level: c_int, name: c_int) -> c_int {
        let mut value: c_int = 0;
        let mut length = std::mem::size_of::<c_int>() as libc::socklen_t;
        // SAFETY: a live socket and a local `c_int` of the size passed.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&mut value as *mut c_int).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
        value
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const KEEPALIVE_IDLE: c_int = 4;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const KEEPALIVE_INTERVAL: c_int = 5;
    #[cfg(target_vendor = "apple")]
    const KEEPALIVE_IDLE: c_int = 0x10;
    #[cfg(target_vendor = "apple")]
    const KEEPALIVE_INTERVAL: c_int = 0x101;

    fn keepalive(socket: &socket2::Socket) -> (bool, c_int, c_int) {
        (
            get(socket, libc::SOL_SOCKET, libc::SO_KEEPALIVE) != 0,
            get(socket, libc::IPPROTO_TCP, KEEPALIVE_IDLE),
            get(socket, libc::IPPROTO_TCP, KEEPALIVE_INTERVAL),
        )
    }

    /// Collects what the options report.
    #[derive(Default)]
    struct Reports(Mutex<Vec<String>>);

    impl Reports {
        fn report(&self) -> impl Fn(&io::Error) + Send + Sync + '_ {
            |error| self.0.lock().unwrap().push(error.to_string())
        }

        fn taken(&self) -> Vec<String> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    fn apply(
        options: &SocketOptions,
        socket: &socket2::Socket,
        reports: &Reports,
    ) -> io::Result<()> {
        let report = reports.report();
        options.apply(handle(socket), Some(&report))
    }

    #[test]
    fn every_tcp_socket_keeps_alive_after_45_seconds_and_every_45() {
        for ipv6 in [false, true] {
            let tcp = socket(true, ipv6);
            apply(&SocketOptions::default(), &tcp, &Reports::default()).unwrap();
            assert_eq!(keepalive(&tcp), (true, 45, 45), "ipv6 {ipv6}");
        }
        let udp = socket(false, false);
        apply(&SocketOptions::default(), &udp, &Reports::default()).unwrap();
        assert_eq!(get(&udp, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 0);
    }

    #[test]
    fn keepalive_times_replace_the_defaults_and_a_negative_one_turns_it_off() {
        let times = |idle, interval| SocketOptions {
            tcp_keep_alive_idle: idle,
            tcp_keep_alive_interval: interval,
            ..SocketOptions::default()
        };
        let tcp = socket(true, false);
        apply(&times(30, 0), &tcp, &Reports::default()).unwrap();
        assert_eq!(keepalive(&tcp), (true, 30, 45));
        let tcp = socket(true, false);
        apply(&times(0, 20), &tcp, &Reports::default()).unwrap();
        assert_eq!(keepalive(&tcp), (true, 45, 20));
        for (idle, interval) in [(-1, 0), (0, -1), (-1, -1)] {
            let tcp = socket(true, false);
            apply(&times(idle, interval), &tcp, &Reports::default()).unwrap();
            assert!(!keepalive(&tcp).0, "{idle} {interval}");
        }
    }

    #[test]
    fn keepalive_times_of_opposite_signs_fail_a_tcp_socket_only() {
        let times = |idle, interval| SocketOptions {
            tcp_keep_alive_idle: idle,
            tcp_keep_alive_interval: interval,
            ..SocketOptions::default()
        };
        // Go multiplies the two in 32 bits: 50000² wraps negative, 65536²
        // to zero.
        for (idle, interval) in [(5, -1), (-1, 5), (50_000, 50_000)] {
            let error = apply(
                &times(idle, interval),
                &socket(true, false),
                &Reports::default(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("invalid TcpKeepAliveIdle"));
            apply(
                &times(idle, interval),
                &socket(false, false),
                &Reports::default(),
            )
            .unwrap();
        }
        apply(
            &times(65_536, 65_536),
            &socket(true, false),
            &Reports::default(),
        )
        .unwrap();
    }

    #[test]
    fn an_interface_that_cannot_be_bound_fails_the_socket() {
        let options = SocketOptions {
            interface: "xray-missing0".to_owned(),
            ..SocketOptions::default()
        };
        for tcp in [true, false] {
            let reports = Reports::default();
            let error = apply(&options, &socket(tcp, false), &reports).unwrap_err();
            assert!(
                error.to_string().contains("failed to bind to interface"),
                "{error}"
            );
            assert!(reports.taken().is_empty());
        }
    }

    #[test]
    fn custom_options_apply_in_order_and_one_that_fails_stops_the_rest() {
        let nodelay = |network: &str| CustomSocketOption {
            network: network.to_owned(),
            opt: libc::TCP_NODELAY.to_string(),
            value: "1".to_owned(),
            kind: "int".to_owned(),
            ..CustomSocketOption::default()
        };
        let options = |custom: Vec<CustomSocketOption>| SocketOptions {
            custom,
            ..SocketOptions::default()
        };
        let tcp = socket(true, false);
        let reports = Reports::default();
        apply(&options(vec![nodelay("tcp4")]), &tcp, &reports).unwrap();
        assert_ne!(get(&tcp, libc::IPPROTO_TCP, libc::TCP_NODELAY), 0);
        assert!(reports.taken().is_empty());

        // Another system or network skips an entry; it is not an error.
        let tcp = socket(true, false);
        let other_system = CustomSocketOption {
            system: "plan9".to_owned(),
            ..nodelay("")
        };
        apply(
            &options(vec![other_system, nodelay("tcp6"), nodelay("udp")]),
            &tcp,
            &reports,
        )
        .unwrap();
        assert_eq!(get(&tcp, libc::IPPROTO_TCP, libc::TCP_NODELAY), 0);
        assert!(reports.taken().is_empty());

        for (first, message) in [
            (
                CustomSocketOption {
                    kind: "bool".to_owned(),
                    ..nodelay("")
                },
                "unknown CustomSockopt type: bool",
            ),
            (
                CustomSocketOption {
                    opt: String::new(),
                    ..nodelay("")
                },
                "No opt!",
            ),
        ] {
            let tcp = socket(true, false);
            apply(&options(vec![first, nodelay("")]), &tcp, &reports).unwrap();
            assert_eq!(get(&tcp, libc::IPPROTO_TCP, libc::TCP_NODELAY), 0);
            assert_eq!(reports.taken(), [message]);
            // Keepalive is the dialer's, not one of the options it stopped.
            assert_eq!(keepalive(&tcp), (true, 45, 45));
        }
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_binds_to_an_interface_by_index() {
        let index = {
            let name = std::ffi::CString::new("lo0").unwrap();
            // SAFETY: a valid NUL-terminated name.
            unsafe { libc::if_nametoindex(name.as_ptr()) as c_int }
        };
        let options = SocketOptions {
            interface: "lo0".to_owned(),
            ..SocketOptions::default()
        };
        for tcp in [true, false] {
            let ipv4 = socket(tcp, false);
            apply(&options, &ipv4, &Reports::default()).unwrap();
            assert_eq!(get(&ipv4, libc::IPPROTO_IP, 25), index);
            let ipv6 = socket(tcp, true);
            apply(&options, &ipv6, &Reports::default()).unwrap();
            assert_eq!(get(&ipv6, libc::IPPROTO_IPV6, 125), index);
        }
    }

    /// Apple kernels take `TCP_FASTOPEN` only on a listening socket, so a
    /// configured `tcpFastOpen` stops every option after it on a TCP socket,
    /// as in Xray-core, while a UDP socket never reads it.
    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_tcp_fast_open_stops_the_tcp_options_after_it() {
        for tcp_fast_open in [256, -1, 3] {
            let options = SocketOptions {
                tcp_fast_open,
                interface: "lo0".to_owned(),
                tcp_keep_alive_idle: 30,
                ..SocketOptions::default()
            };
            let reports = Reports::default();
            let tcp = socket(true, false);
            apply(&options, &tcp, &reports).unwrap();
            assert_eq!(get(&tcp, libc::IPPROTO_IP, 25), 0, "{tcp_fast_open}");
            assert_eq!(reports.taken().len(), 1);
            // The dialer still turns keepalive on with the configured idle time.
            assert_eq!(keepalive(&tcp), (true, 30, 45));

            let udp = socket(false, false);
            apply(&options, &udp, &reports).unwrap();
            assert_ne!(get(&udp, libc::IPPROTO_IP, 25), 0);
            assert!(reports.taken().is_empty());
        }
    }

    /// Whether this process may set `SO_MARK`, which takes `CAP_NET_ADMIN`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn may_mark() -> bool {
        let probe = socket(true, false);
        let value: c_int = 1;
        // SAFETY: a live socket and a local `c_int` of the size passed.
        unsafe {
            libc::setsockopt(
                probe.as_raw_fd(),
                libc::SOL_SOCKET,
                36,
                (&value as *const c_int).cast(),
                std::mem::size_of::<c_int>() as libc::socklen_t,
            ) == 0
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_sets_the_tcp_options_in_order() {
        const TCP_USER_TIMEOUT: c_int = 18;
        const TCP_FASTOPEN_CONNECT: c_int = 30;
        let options = SocketOptions {
            tcp_fast_open: 256,
            tcp_congestion: "reno".to_owned(),
            tcp_user_timeout: 5000,
            ..SocketOptions::default()
        };
        let reports = Reports::default();
        let tcp = socket(true, false);
        apply(&options, &tcp, &reports).unwrap();
        assert_eq!(get(&tcp, 6, TCP_FASTOPEN_CONNECT), 1);
        assert_eq!(get(&tcp, libc::IPPROTO_TCP, TCP_USER_TIMEOUT), 5000);
        assert!(reports.taken().is_empty());
        // UDP takes none of them.
        let udp = socket(false, false);
        apply(&options, &udp, &reports).unwrap();
        assert!(reports.taken().is_empty());

        // `false` turns the option off, and an unknown algorithm stops the
        // options after it.
        let options = SocketOptions {
            tcp_fast_open: -1,
            tcp_congestion: "xray-missing".to_owned(),
            tcp_user_timeout: 5000,
            ..SocketOptions::default()
        };
        let tcp = socket(true, false);
        apply(&options, &tcp, &reports).unwrap();
        assert_eq!(get(&tcp, 6, TCP_FASTOPEN_CONNECT), 0);
        assert_eq!(get(&tcp, libc::IPPROTO_TCP, TCP_USER_TIMEOUT), 0);
        assert_eq!(reports.taken().len(), 1);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_mark_comes_first_and_needs_privilege() {
        const SO_MARK: c_int = 36;
        const TCP_USER_TIMEOUT: c_int = 18;
        let options = SocketOptions {
            mark: 77,
            tcp_user_timeout: 5000,
            ..SocketOptions::default()
        };
        let reports = Reports::default();
        let tcp = socket(true, false);
        apply(&options, &tcp, &reports).unwrap();
        if may_mark() {
            assert_eq!(get(&tcp, libc::SOL_SOCKET, SO_MARK), 77);
            assert_eq!(get(&tcp, libc::IPPROTO_TCP, TCP_USER_TIMEOUT), 5000);
            assert!(reports.taken().is_empty());
        } else {
            assert_eq!(get(&tcp, libc::IPPROTO_TCP, TCP_USER_TIMEOUT), 0);
            assert_eq!(reports.taken().len(), 1);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn linux_multipath_tcp_connects_or_falls_back_to_tcp() {
        struct Multipath;
        impl SocketProtector for Multipath {
            fn protect(&self, _socket: SocketHandle) -> io::Result<()> {
                Ok(())
            }
            fn multipath_tcp(&self) -> bool {
                true
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = crate::connect_tcp_stream(address, Some(&Multipath))
            .await
            .unwrap();
        accepted.await.unwrap();
        let protocol = {
            let socket = socket2::SockRef::from(&stream);
            socket.protocol().unwrap()
        };
        assert!(
            protocol == Some(socket2::Protocol::from(262))
                || protocol == Some(socket2::Protocol::TCP),
            "{protocol:?}"
        );
        // A refused connection is retried as TCP and still refused.
        drop(stream);
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = closed.local_addr().unwrap();
        drop(closed);
        assert!(crate::connect_tcp_stream(refused, Some(&Multipath))
            .await
            .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_atoi_reads_what_strconv_reads_and_zeroes_the_rest() {
        assert_eq!(go_atoi("42"), 42);
        assert_eq!(go_atoi("+7"), 7);
        assert_eq!(go_atoi("-0"), 0);
        assert_eq!(go_atoi("-13"), -13);
        assert_eq!(go_atoi(""), 0);
        assert_eq!(go_atoi("+"), 0);
        assert_eq!(go_atoi(" 1"), 0);
        assert_eq!(go_atoi("1_000"), 0);
        assert_eq!(go_atoi("0x10"), 0);
        assert_eq!(go_atoi("99999999999999999999"), i64::MAX);
        assert_eq!(go_atoi("-99999999999999999999"), i64::MIN);
        assert_eq!(go_atoi("-9223372036854775808"), i64::MIN);
    }

    #[test]
    fn parsed_tcp_fast_open_is_xray_cores_parse_tfo_value() {
        let parsed = |tcp_fast_open| {
            SocketOptions {
                tcp_fast_open,
                ..SocketOptions::default()
            }
            .parsed_tcp_fast_open()
        };
        assert_eq!(parsed(0), -1);
        assert_eq!(parsed(-1), 0);
        assert_eq!(parsed(i32::MIN), 0);
        assert_eq!(parsed(256), 256);
        assert_eq!(parsed(5), 5);
    }
}
