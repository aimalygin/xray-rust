use libc::c_int;

use crate::{XrayTunFdClosePolicy, XrayTunFdPacketFormat};

const MAX_IP_PACKET_SIZE: usize = 65_535;

#[derive(Debug)]
pub(crate) struct TunFdConfig {
    fd: c_int,
    packet_format: XrayTunFdPacketFormat,
    close_policy: XrayTunFdClosePolicy,
}

impl TunFdConfig {
    pub(crate) fn new(
        fd: c_int,
        packet_format: XrayTunFdPacketFormat,
        close_policy: XrayTunFdClosePolicy,
    ) -> Self {
        Self {
            fd,
            packet_format,
            close_policy,
        }
    }

    pub(crate) fn close_if_owned(&self) {
        if self.close_policy == XrayTunFdClosePolicy::Owned && self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(unix)]
mod platform {
    use std::borrow::Cow;
    use std::io;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::watch;
    use tokio::task::JoinHandle;
    use xray_tun::{TunEndpoint, TunError};

    use super::{TunFdConfig, MAX_IP_PACKET_SIZE};
    use crate::{XrayTunFdClosePolicy, XrayTunFdPacketFormat};

    const DARWIN_UTUN_HEADER_LEN: usize = 4;

    pub(crate) struct TunFdRuntime {
        shutdown: watch::Sender<bool>,
        read_task: JoinHandle<()>,
        write_task: JoinHandle<()>,
    }

    impl TunFdRuntime {
        pub(crate) fn start(config: TunFdConfig, tun: Arc<TunEndpoint>) -> io::Result<Self> {
            if let Err(err) = set_nonblocking(config.fd) {
                config.close_if_owned();
                return Err(err);
            }
            let packet_format = config.packet_format;
            let fd = Arc::new(AsyncFd::new(TunFd::new(config))?);
            let (shutdown, shutdown_rx) = watch::channel(false);
            let read_task = tokio::spawn(read_loop(
                Arc::clone(&fd),
                Arc::clone(&tun),
                shutdown_rx.clone(),
                packet_format,
            ));
            let write_task = tokio::spawn(write_loop(fd, tun, shutdown_rx, packet_format));

            Ok(Self {
                shutdown,
                read_task,
                write_task,
            })
        }

        pub(crate) async fn stop(self) {
            let _ = self.shutdown.send(true);
            self.read_task.abort();
            self.write_task.abort();
            let _ = self.read_task.await;
            let _ = self.write_task.await;
        }
    }

    struct TunFd {
        fd: RawFd,
        close_policy: XrayTunFdClosePolicy,
    }

    impl TunFd {
        fn new(config: TunFdConfig) -> Self {
            Self {
                fd: config.fd,
                close_policy: config.close_policy,
            }
        }
    }

    impl AsRawFd for TunFd {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    impl Drop for TunFd {
        fn drop(&mut self) {
            if self.close_policy == XrayTunFdClosePolicy::Owned && self.fd >= 0 {
                unsafe {
                    libc::close(self.fd);
                }
                self.fd = -1;
            }
        }
    }

    async fn read_loop(
        fd: Arc<AsyncFd<TunFd>>,
        tun: Arc<TunEndpoint>,
        mut shutdown: watch::Receiver<bool>,
        packet_format: XrayTunFdPacketFormat,
    ) {
        let mut buffer = vec![0_u8; read_buffer_len(packet_format)];

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                packet = read_packet(&fd, packet_format, &mut buffer) => {
                    match packet {
                        Ok(Some(packet)) => match tun.push_inbound(packet).await {
                            Ok(()) | Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {}
                            Err(TunError::QueueClosed) => break,
                        },
                        Ok(None) => {}
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
        }
    }

    async fn write_loop(
        fd: Arc<AsyncFd<TunFd>>,
        tun: Arc<TunEndpoint>,
        mut shutdown: watch::Receiver<bool>,
        packet_format: XrayTunFdPacketFormat,
    ) {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                packet = tun.poll_outbound() => {
                    match packet {
                        Ok(packet) => {
                            if write_packet(&fd, packet_format, &packet).await.is_err() {
                                break;
                            }
                        }
                        Err(TunError::QueueClosed) => break,
                        Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {}
                    }
                }
            }
        }
    }

    async fn read_packet(
        fd: &AsyncFd<TunFd>,
        packet_format: XrayTunFdPacketFormat,
        buffer: &mut [u8],
    ) -> io::Result<Option<Bytes>> {
        loop {
            let mut guard = fd.readable().await?;
            let result = guard.try_io(|inner| {
                let read = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if read < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(read as usize)
                }
            });

            match result {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tun fd reached EOF",
                    ))
                }
                Ok(Ok(len)) => return Ok(decode_packet(packet_format, &buffer[..len])),
                Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(err)) => return Err(err),
                Err(_) => continue,
            }
        }
    }

    async fn write_packet(
        fd: &AsyncFd<TunFd>,
        packet_format: XrayTunFdPacketFormat,
        packet: &[u8],
    ) -> io::Result<()> {
        let packet = encode_packet(packet_format, packet)?;

        loop {
            let mut guard = fd.writable().await?;
            let result = guard.try_io(|inner| {
                let written = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                    )
                };
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                if written as usize != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!(
                            "short tun fd write: wrote {written} of {} bytes",
                            packet.len()
                        ),
                    ));
                }
                Ok(())
            });

            match result {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(err)) => return Err(err),
                Err(_) => continue,
            }
        }
    }

    fn read_buffer_len(packet_format: XrayTunFdPacketFormat) -> usize {
        match packet_format {
            XrayTunFdPacketFormat::RawIp => MAX_IP_PACKET_SIZE,
            XrayTunFdPacketFormat::DarwinUtun => MAX_IP_PACKET_SIZE + DARWIN_UTUN_HEADER_LEN,
        }
    }

    fn decode_packet(packet_format: XrayTunFdPacketFormat, packet: &[u8]) -> Option<Bytes> {
        match packet_format {
            XrayTunFdPacketFormat::RawIp if !packet.is_empty() => {
                Some(Bytes::copy_from_slice(packet))
            }
            XrayTunFdPacketFormat::RawIp => None,
            XrayTunFdPacketFormat::DarwinUtun if packet.len() > DARWIN_UTUN_HEADER_LEN => {
                Some(Bytes::copy_from_slice(&packet[DARWIN_UTUN_HEADER_LEN..]))
            }
            XrayTunFdPacketFormat::DarwinUtun => None,
        }
    }

    fn encode_packet<'a>(
        packet_format: XrayTunFdPacketFormat,
        packet: &'a [u8],
    ) -> io::Result<Cow<'a, [u8]>> {
        match packet_format {
            XrayTunFdPacketFormat::RawIp => Ok(Cow::Borrowed(packet)),
            XrayTunFdPacketFormat::DarwinUtun => {
                let family = match packet.first().map(|byte| byte >> 4) {
                    Some(4) => libc::AF_INET,
                    Some(6) => libc::AF_INET6,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "tun packet is not IPv4 or IPv6",
                        ))
                    }
                };
                let mut encoded = Vec::with_capacity(DARWIN_UTUN_HEADER_LEN + packet.len());
                encoded.extend_from_slice(&[0, 0, 0, family as u8]);
                encoded.extend_from_slice(packet);
                Ok(Cow::Owned(encoded))
            }
        }
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun fd must be non-negative",
            ));
        }

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

#[cfg(not(unix))]
mod platform {
    use std::io;
    use std::sync::Arc;

    use xray_tun::TunEndpoint;

    use super::TunFdConfig;

    pub(crate) struct TunFdRuntime;

    impl TunFdRuntime {
        pub(crate) fn start(config: TunFdConfig, _tun: Arc<TunEndpoint>) -> io::Result<Self> {
            config.close_if_owned();
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fd-backed TUN is only supported on Unix platforms",
            ))
        }

        pub(crate) async fn stop(self) {}
    }
}

pub(crate) use platform::TunFdRuntime;
