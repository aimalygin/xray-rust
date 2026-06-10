use libc::c_int;

const MAX_IP_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunFdPacketFormat {
    RawIp,
    DarwinUtun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunFdClosePolicy {
    Borrowed,
    Owned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunFdConfig {
    fd: c_int,
    packet_format: TunFdPacketFormat,
    close_policy: TunFdClosePolicy,
}

impl TunFdConfig {
    pub fn new(
        fd: c_int,
        packet_format: TunFdPacketFormat,
        close_policy: TunFdClosePolicy,
    ) -> Self {
        Self {
            fd,
            packet_format,
            close_policy,
        }
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    pub fn packet_format(&self) -> TunFdPacketFormat {
        self.packet_format
    }

    pub fn close_policy(&self) -> TunFdClosePolicy {
        self.close_policy
    }

    pub fn close_if_owned(&self) {
        if self.close_policy == TunFdClosePolicy::Owned && self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::watch;
    use tokio::task::JoinHandle;
    use xray_tun::{TunEndpoint, TunError};

    use super::{TunFdConfig, MAX_IP_PACKET_SIZE};
    use crate::{TunFdClosePolicy, TunFdPacketFormat};

    const DARWIN_UTUN_HEADER_LEN: usize = 4;
    const TUN_FD_WRITE_BATCH_MAX_PACKETS: usize = 128;

    pub struct TunFdRuntime {
        shutdown: watch::Sender<bool>,
        read_task: JoinHandle<()>,
        write_task: JoinHandle<()>,
    }

    impl TunFdRuntime {
        pub fn start(config: TunFdConfig, tun: Arc<TunEndpoint>) -> io::Result<Self> {
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

        pub async fn stop(self) {
            let _ = self.shutdown.send(true);
            self.read_task.abort();
            self.write_task.abort();
            let _ = self.read_task.await;
            let _ = self.write_task.await;
        }
    }

    struct TunFd {
        fd: RawFd,
        close_policy: TunFdClosePolicy,
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
            if self.close_policy == TunFdClosePolicy::Owned && self.fd >= 0 {
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
        packet_format: TunFdPacketFormat,
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
        packet_format: TunFdPacketFormat,
    ) {
        let mut batch = Vec::with_capacity(TUN_FD_WRITE_BATCH_MAX_PACKETS);

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
                            batch.clear();
                            batch.push(packet);
                            let queue_closed = drain_outbound_batch(&tun, &mut batch).await;

                            if write_packet_batch(&fd, packet_format, &batch).await.is_err() {
                                break;
                            }
                            tun.record_tun_fd_write_batch(batch.len());
                            if queue_closed {
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

    async fn drain_outbound_batch(tun: &TunEndpoint, batch: &mut Vec<Bytes>) -> bool {
        while batch.len() < TUN_FD_WRITE_BATCH_MAX_PACKETS {
            match tun.try_poll_outbound().await {
                Ok(Some(packet)) => batch.push(packet),
                Ok(None) => return false,
                Err(TunError::QueueClosed) => return true,
                Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => return false,
            }
        }
        false
    }

    async fn read_packet(
        fd: &AsyncFd<TunFd>,
        packet_format: TunFdPacketFormat,
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

    async fn write_packet_batch(
        fd: &AsyncFd<TunFd>,
        packet_format: TunFdPacketFormat,
        packets: &[Bytes],
    ) -> io::Result<()> {
        let mut packet_index = 0;

        while packet_index < packets.len() {
            let mut guard = fd.writable().await?;

            loop {
                let packet = EncodedPacket::new(packet_format, packets[packet_index].as_ref())?;
                let result = guard.try_io(|inner| {
                    let written = packet.write_to_fd(inner.get_ref().as_raw_fd());
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
                    Ok(Ok(())) => {
                        packet_index += 1;
                        if packet_index == packets.len() {
                            return Ok(());
                        }
                    }
                    Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Ok(Err(err)) => return Err(err),
                    Err(_) => break,
                }
            }
        }

        Ok(())
    }

    fn read_buffer_len(packet_format: TunFdPacketFormat) -> usize {
        match packet_format {
            TunFdPacketFormat::RawIp => MAX_IP_PACKET_SIZE,
            TunFdPacketFormat::DarwinUtun => MAX_IP_PACKET_SIZE + DARWIN_UTUN_HEADER_LEN,
        }
    }

    fn decode_packet(packet_format: TunFdPacketFormat, packet: &[u8]) -> Option<Bytes> {
        match packet_format {
            TunFdPacketFormat::RawIp if !packet.is_empty() => Some(Bytes::copy_from_slice(packet)),
            TunFdPacketFormat::RawIp => None,
            TunFdPacketFormat::DarwinUtun if packet.len() > DARWIN_UTUN_HEADER_LEN => {
                Some(Bytes::copy_from_slice(&packet[DARWIN_UTUN_HEADER_LEN..]))
            }
            TunFdPacketFormat::DarwinUtun => None,
        }
    }

    enum EncodedPacket<'a> {
        RawIp(&'a [u8]),
        DarwinUtun { header: [u8; 4], payload: &'a [u8] },
    }

    impl<'a> EncodedPacket<'a> {
        fn new(packet_format: TunFdPacketFormat, packet: &'a [u8]) -> io::Result<Self> {
            match packet_format {
                TunFdPacketFormat::RawIp => Ok(Self::RawIp(packet)),
                TunFdPacketFormat::DarwinUtun => {
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
                    Ok(Self::DarwinUtun {
                        header: [0, 0, 0, family as u8],
                        payload: packet,
                    })
                }
            }
        }

        fn len(&self) -> usize {
            match self {
                Self::RawIp(packet) => packet.len(),
                Self::DarwinUtun { payload, .. } => DARWIN_UTUN_HEADER_LEN + payload.len(),
            }
        }

        #[cfg(test)]
        fn header(&self) -> Option<[u8; 4]> {
            match self {
                Self::RawIp(_) => None,
                Self::DarwinUtun { header, .. } => Some(*header),
            }
        }

        #[cfg(test)]
        fn payload(&self) -> &'a [u8] {
            match self {
                Self::RawIp(packet) => packet,
                Self::DarwinUtun { payload, .. } => payload,
            }
        }

        fn write_to_fd(&self, fd: RawFd) -> libc::ssize_t {
            match self {
                Self::RawIp(packet) => unsafe {
                    libc::write(fd, packet.as_ptr().cast(), packet.len())
                },
                Self::DarwinUtun { header, payload } => {
                    let iov = [
                        libc::iovec {
                            iov_base: header.as_ptr().cast_mut().cast(),
                            iov_len: header.len(),
                        },
                        libc::iovec {
                            iov_base: payload.as_ptr().cast_mut().cast(),
                            iov_len: payload.len(),
                        },
                    ];
                    unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) }
                }
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use xray_tun::TunConfig;

        #[test]
        fn darwin_utun_encoded_packet_borrows_payload_and_adds_family_header() {
            let packet = [0x45, 0x00, 0x00, 0x14];
            let encoded = EncodedPacket::new(TunFdPacketFormat::DarwinUtun, &packet).unwrap();

            assert_eq!(encoded.len(), DARWIN_UTUN_HEADER_LEN + packet.len());
            assert_eq!(encoded.header(), Some([0, 0, 0, libc::AF_INET as u8]));
            assert!(std::ptr::eq(encoded.payload().as_ptr(), packet.as_ptr()));
        }

        #[tokio::test]
        async fn outbound_batch_drains_queued_packets_up_to_limit() {
            let tun = TunEndpoint::new(TunConfig {
                mtu: 1500,
                queue_depth: TUN_FD_WRITE_BATCH_MAX_PACKETS + 2,
            });
            for index in 0..TUN_FD_WRITE_BATCH_MAX_PACKETS + 1 {
                tun.push_outbound(Bytes::from(vec![0x45, index as u8]))
                    .await
                    .unwrap();
            }

            let first = tun.poll_outbound().await.unwrap();
            let mut batch = vec![first];
            let queue_closed = drain_outbound_batch(&tun, &mut batch).await;

            assert!(!queue_closed);
            assert_eq!(batch.len(), TUN_FD_WRITE_BATCH_MAX_PACKETS);
            assert_eq!(
                tun.try_poll_outbound().await.unwrap(),
                Some(Bytes::from(vec![
                    0x45,
                    TUN_FD_WRITE_BATCH_MAX_PACKETS as u8
                ]))
            );
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use std::io;
    use std::sync::Arc;

    use xray_tun::TunEndpoint;

    use super::TunFdConfig;

    pub struct TunFdRuntime;

    impl TunFdRuntime {
        pub fn start(config: TunFdConfig, _tun: Arc<TunEndpoint>) -> io::Result<Self> {
            config.close_if_owned();
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fd-backed TUN is only supported on Unix platforms",
            ))
        }

        pub async fn stop(self) {}
    }
}

pub use platform::TunFdRuntime;
