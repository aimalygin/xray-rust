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
    use std::time::Duration;

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

    /// Transient fd failures start with a short retry delay so brief network
    /// transitions recover quickly, then back off to a bounded one-second poll.
    /// The pump must not give up on them: nobody supervises these tasks, so a
    /// returned loop would leave the host reporting a connected but dead tunnel.
    const TUN_FD_IO_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(10);
    const TUN_FD_IO_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(1);
    const TUN_FD_IO_RETRY_MAX_SHIFT: u32 = 7;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TunFdIoDisposition {
        /// The syscall was interrupted and should be reissued at once. Not a
        /// failure: it neither backs off nor advances the retry state.
        RetryImmediately,
        /// The payload cannot be encoded and never will be. Dropping it is the
        /// only progress available, and it says nothing about the descriptor.
        DropPacket,
        Retry,
        Fatal,
    }

    /// Classifies a pump I/O error. Everything is retryable except conditions
    /// that mean the descriptor itself is gone, because a tunnel that stops
    /// moving packets is far worse than one that retries a doomed read.
    fn io_disposition(error: &io::Error) -> TunFdIoDisposition {
        if error.kind() == io::ErrorKind::Interrupted {
            return TunFdIoDisposition::RetryImmediately;
        }
        if error.kind() == io::ErrorKind::InvalidData {
            return TunFdIoDisposition::DropPacket;
        }
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return TunFdIoDisposition::Fatal;
        }
        match error.raw_os_error() {
            Some(libc::EBADF) | Some(libc::ENXIO) | Some(libc::ENOTCONN) => {
                TunFdIoDisposition::Fatal
            }
            _ => TunFdIoDisposition::Retry,
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TunFdLoopAction {
        Continue,
        BackOff,
        Stop,
    }

    #[derive(Debug)]
    struct PacketBatchWriteError {
        error: io::Error,
        written_packets: usize,
    }

    impl PacketBatchWriteError {
        fn new(written_packets: usize, error: io::Error) -> Self {
            Self {
                error,
                written_packets,
            }
        }
    }

    trait PacketBatchWriter {
        async fn write_batch(
            &mut self,
            packet_format: TunFdPacketFormat,
            packets: &[Bytes],
        ) -> Result<(), PacketBatchWriteError>;
    }

    struct AsyncFdPacketBatchWriter<'a> {
        fd: &'a AsyncFd<TunFd>,
    }

    impl PacketBatchWriter for AsyncFdPacketBatchWriter<'_> {
        async fn write_batch(
            &mut self,
            packet_format: TunFdPacketFormat,
            packets: &[Bytes],
        ) -> Result<(), PacketBatchWriteError> {
            write_packet_batch(self.fd, packet_format, packets).await
        }
    }

    /// Advances the consecutive-failure state for one I/O outcome and reports
    /// what the pump should do next. Only `Retry` advances the backoff: an
    /// interrupt is not a failure, and an unencodable packet says nothing about
    /// the fd. Transient failures never stop an unsupervised pump.
    fn advance_failure_state(
        disposition: TunFdIoDisposition,
        consecutive_errors: &mut u32,
    ) -> TunFdLoopAction {
        match disposition {
            TunFdIoDisposition::RetryImmediately | TunFdIoDisposition::DropPacket => {
                TunFdLoopAction::Continue
            }
            TunFdIoDisposition::Fatal => TunFdLoopAction::Stop,
            TunFdIoDisposition::Retry => {
                *consecutive_errors = (*consecutive_errors).saturating_add(1);
                TunFdLoopAction::BackOff
            }
        }
    }

    fn retry_backoff(consecutive_errors: u32) -> Duration {
        let shift = consecutive_errors
            .saturating_sub(1)
            .min(TUN_FD_IO_RETRY_MAX_SHIFT);
        TUN_FD_IO_RETRY_INITIAL_BACKOFF
            .saturating_mul(1_u32 << shift)
            .min(TUN_FD_IO_RETRY_MAX_BACKOFF)
    }

    /// Classifies one pump I/O failure, records it, and advances its backoff
    /// state. Only a `Retry` reflects on the descriptor, so it is the only
    /// disposition the stats see: an interrupt is not a failure and an
    /// unencodable packet is a data defect. The exit counters stay with the
    /// loops, which are the only ones that know which direction gave up.
    fn observe_io_failure(
        tun: &TunEndpoint,
        error: &io::Error,
        consecutive_errors: &mut u32,
    ) -> TunFdLoopAction {
        let disposition = io_disposition(error);
        if disposition == TunFdIoDisposition::Retry {
            tun.record_tun_fd_transient_io_error();
        }
        advance_failure_state(disposition, consecutive_errors)
    }

    async fn read_loop(
        fd: Arc<AsyncFd<TunFd>>,
        tun: Arc<TunEndpoint>,
        mut shutdown: watch::Receiver<bool>,
        packet_format: TunFdPacketFormat,
    ) {
        let mut buffer = vec![0_u8; read_buffer_len(packet_format)];
        let mut consecutive_errors: u32 = 0;

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                packet = read_packet(&fd, packet_format, &mut buffer) => {
                    match packet {
                        Ok(Some(packet)) => {
                            consecutive_errors = 0;
                            match tun.push_inbound(packet).await {
                                Ok(())
                                | Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {}
                                Err(TunError::QueueClosed) => break,
                            }
                        }
                        Ok(None) => {
                            consecutive_errors = 0;
                        }
                        Err(err) => {
                            match observe_io_failure(&tun, &err, &mut consecutive_errors) {
                                TunFdLoopAction::Continue => {}
                                TunFdLoopAction::BackOff => {
                                    tokio::time::sleep(retry_backoff(consecutive_errors)).await;
                                }
                                TunFdLoopAction::Stop => {
                                    tun.record_tun_fd_read_loop_exit();
                                    break;
                                }
                            }
                        }
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
        let mut next_packet = 0;
        let mut written_packets_in_batch = 0;
        let mut consecutive_errors: u32 = 0;
        let mut writer = AsyncFdPacketBatchWriter { fd: fd.as_ref() };

        loop {
            if next_packet < batch.len() {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    action = write_pending_packet_batch(
                        &mut writer,
                        &tun,
                        packet_format,
                        &batch,
                        &mut next_packet,
                        &mut written_packets_in_batch,
                        &mut consecutive_errors,
                    ) => {
                        match action {
                            TunFdLoopAction::Continue => {}
                            TunFdLoopAction::BackOff => {
                                tokio::time::sleep(retry_backoff(consecutive_errors)).await;
                            }
                            TunFdLoopAction::Stop => {
                                tun.record_tun_fd_write_loop_exit();
                                break;
                            }
                        }
                    }
                }
                continue;
            }

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                result = tun.poll_outbound_batch_into(
                    TUN_FD_WRITE_BATCH_MAX_PACKETS,
                    &mut batch,
                ) => {
                    match result {
                        Ok(()) => {
                            next_packet = 0;
                            written_packets_in_batch = 0;
                        }
                        Err(TunError::QueueClosed) => break,
                        Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {}
                    }
                }
            }
        }
    }

    /// Attempts the currently unwritten slice of one dequeued batch. Progress
    /// is committed to `next_packet` before an error is classified, so the
    /// following loop iteration retries only the unwritten tail and never polls
    /// a new batch over it.
    async fn write_pending_packet_batch<W: PacketBatchWriter>(
        writer: &mut W,
        tun: &TunEndpoint,
        packet_format: TunFdPacketFormat,
        batch: &[Bytes],
        next_packet: &mut usize,
        written_packets_in_batch: &mut usize,
        consecutive_errors: &mut u32,
    ) -> TunFdLoopAction {
        let pending_packets = &batch[*next_packet..];
        match writer.write_batch(packet_format, pending_packets).await {
            Ok(()) => {
                *written_packets_in_batch += pending_packets.len();
                *next_packet = batch.len();
                finish_tun_fd_write_batch(tun, written_packets_in_batch);
                *consecutive_errors = 0;
                TunFdLoopAction::Continue
            }
            Err(PacketBatchWriteError {
                error,
                written_packets,
            }) => {
                let written_packets = written_packets.min(pending_packets.len());
                if written_packets > 0 {
                    *written_packets_in_batch += written_packets;
                    *next_packet += written_packets;
                    *consecutive_errors = 0;
                }

                if *next_packet == batch.len() {
                    finish_tun_fd_write_batch(tun, written_packets_in_batch);
                    return TunFdLoopAction::Continue;
                }

                let disposition = io_disposition(&error);
                let action = observe_io_failure(tun, &error, consecutive_errors);
                if disposition == TunFdIoDisposition::DropPacket {
                    tun.record_tun_fd_outbound_drops(1);
                    *next_packet += 1;
                    if *next_packet == batch.len() {
                        finish_tun_fd_write_batch(tun, written_packets_in_batch);
                    }
                } else if action == TunFdLoopAction::Stop {
                    tun.record_tun_fd_outbound_drops(batch.len() - *next_packet);
                    *next_packet = batch.len();
                    finish_tun_fd_write_batch(tun, written_packets_in_batch);
                }
                action
            }
        }
    }

    fn finish_tun_fd_write_batch(tun: &TunEndpoint, written_packets_in_batch: &mut usize) {
        if *written_packets_in_batch > 0 {
            tun.record_tun_fd_write_batch(*written_packets_in_batch);
            *written_packets_in_batch = 0;
        }
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
    ) -> Result<(), PacketBatchWriteError> {
        let mut packet_index = 0;

        while packet_index < packets.len() {
            let mut guard = fd
                .writable()
                .await
                .map_err(|error| PacketBatchWriteError::new(packet_index, error))?;

            loop {
                let packet = EncodedPacket::new(packet_format, packets[packet_index].as_ref())
                    .map_err(|error| PacketBatchWriteError::new(packet_index, error))?;
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
                    Ok(Err(err)) => {
                        return Err(PacketBatchWriteError::new(packet_index, err));
                    }
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
        use std::collections::VecDeque;

        use super::*;
        use xray_tun::TunConfig;

        enum ScriptedBatchWrite {
            Complete,
            Fail(PacketBatchWriteError),
        }

        struct ScriptedPacketBatchWriter {
            outcomes: VecDeque<ScriptedBatchWrite>,
            calls: Vec<Vec<Bytes>>,
            written: Vec<Bytes>,
        }

        impl ScriptedPacketBatchWriter {
            fn new(outcomes: impl IntoIterator<Item = ScriptedBatchWrite>) -> Self {
                Self {
                    outcomes: outcomes.into_iter().collect(),
                    calls: Vec::new(),
                    written: Vec::new(),
                }
            }
        }

        impl PacketBatchWriter for ScriptedPacketBatchWriter {
            async fn write_batch(
                &mut self,
                _packet_format: TunFdPacketFormat,
                packets: &[Bytes],
            ) -> Result<(), PacketBatchWriteError> {
                self.calls.push(packets.to_vec());
                match self.outcomes.pop_front().expect("missing scripted write") {
                    ScriptedBatchWrite::Complete => {
                        self.written.extend(packets.iter().cloned());
                        Ok(())
                    }
                    ScriptedBatchWrite::Fail(failure) => {
                        assert!(failure.written_packets <= packets.len());
                        self.written
                            .extend(packets[..failure.written_packets].iter().cloned());
                        Err(failure)
                    }
                }
            }
        }

        fn test_packet_batch() -> Vec<Bytes> {
            vec![
                Bytes::from_static(&[0x45, 0x01]),
                Bytes::from_static(&[0x45, 0x02]),
                Bytes::from_static(&[0x45, 0x03]),
            ]
        }

        fn test_tun_endpoint() -> TunEndpoint {
            TunEndpoint::new(TunConfig {
                mtu: 1500,
                queue_depth: 4,
            })
        }

        #[test]
        fn darwin_utun_encoded_packet_borrows_payload_and_adds_family_header() {
            let packet = [0x45, 0x00, 0x00, 0x14];
            let encoded = EncodedPacket::new(TunFdPacketFormat::DarwinUtun, &packet).unwrap();

            assert_eq!(encoded.len(), DARWIN_UTUN_HEADER_LEN + packet.len());
            assert_eq!(encoded.header(), Some([0, 0, 0, libc::AF_INET as u8]));
            assert!(std::ptr::eq(encoded.payload().as_ptr(), packet.as_ptr()));
        }

        #[test]
        fn transient_tun_fd_errors_are_retried_not_fatal() {
            for errno in [
                libc::ENOBUFS,
                libc::ENOMEM,
                libc::ENETDOWN,
                libc::ENETUNREACH,
                libc::EHOSTDOWN,
                libc::EHOSTUNREACH,
                libc::ETIMEDOUT,
                libc::EIO,
            ] {
                assert_eq!(
                    io_disposition(&io::Error::from_raw_os_error(errno)),
                    TunFdIoDisposition::Retry,
                    "errno {errno} must be retried"
                );
            }
        }

        #[test]
        fn a_closed_descriptor_is_fatal() {
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::EBADF)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::ENXIO)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::ENOTCONN)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
                TunFdIoDisposition::Fatal
            );
        }

        #[test]
        fn interrupts_are_retried_without_counting_as_failures() {
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::EINTR)),
                TunFdIoDisposition::RetryImmediately
            );
            assert_eq!(
                io_disposition(&io::Error::new(io::ErrorKind::Interrupted, "eintr")),
                TunFdIoDisposition::RetryImmediately
            );
        }

        #[test]
        fn only_transient_retries_advance_the_backoff_state() {
            let mut consecutive = 0;

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::RetryImmediately, &mut consecutive),
                TunFdLoopAction::Continue
            );
            assert_eq!(consecutive, 0);

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::DropPacket, &mut consecutive),
                TunFdLoopAction::Continue
            );
            assert_eq!(consecutive, 0);

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::Retry, &mut consecutive),
                TunFdLoopAction::BackOff
            );
            assert_eq!(consecutive, 1);

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::Fatal, &mut consecutive),
                TunFdLoopAction::Stop
            );
        }

        #[test]
        fn transient_failures_never_stop_the_unsupervised_pump() {
            let mut consecutive = 0;

            for _ in 0..64 {
                assert_eq!(
                    advance_failure_state(TunFdIoDisposition::Retry, &mut consecutive),
                    TunFdLoopAction::BackOff
                );
            }
            assert_eq!(consecutive, 64);
            assert_eq!(retry_backoff(consecutive), TUN_FD_IO_RETRY_MAX_BACKOFF);

            consecutive = u32::MAX;
            assert_eq!(
                advance_failure_state(TunFdIoDisposition::Retry, &mut consecutive),
                TunFdLoopAction::BackOff
            );
            assert_eq!(consecutive, u32::MAX);
        }

        #[test]
        fn transient_retry_backoff_grows_and_caps_at_one_second() {
            assert_eq!(retry_backoff(0), Duration::from_millis(10));
            assert_eq!(retry_backoff(1), Duration::from_millis(10));
            assert_eq!(retry_backoff(2), Duration::from_millis(20));
            assert_eq!(retry_backoff(7), Duration::from_millis(640));
            assert_eq!(retry_backoff(8), Duration::from_secs(1));
            assert_eq!(retry_backoff(u32::MAX), Duration::from_secs(1));
        }

        #[test]
        fn an_unencodable_packet_is_dropped_not_retried() {
            let malformed = [0x00, 0x00, 0x00, 0x00];
            // `EncodedPacket` is not `Debug`, so `expect_err` is unavailable here.
            let error = match EncodedPacket::new(TunFdPacketFormat::DarwinUtun, &malformed) {
                Ok(_) => panic!("a packet with no IP version must not encode"),
                Err(error) => error,
            };

            assert_eq!(io_disposition(&error), TunFdIoDisposition::DropPacket);
        }

        #[tokio::test]
        async fn transient_write_error_retries_the_same_pending_batch() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    0,
                    io::Error::from_raw_os_error(libc::ENOBUFS),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 0;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::BackOff
            );
            assert_eq!(next_packet, 0);
            assert_eq!(consecutive_errors, 1);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 0);
            assert_eq!(stats.outbound_dropped_packets, 0);

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, batch.len());
            assert_eq!(consecutive_errors, 0);
            assert_eq!(writer.calls, vec![batch.clone(), batch.clone()]);
            assert_eq!(writer.written, batch);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batches, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 3);
            assert_eq!(stats.outbound_dropped_packets, 0);
        }

        #[tokio::test]
        async fn partial_batch_progress_retries_only_the_unwritten_tail() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    1,
                    io::Error::from_raw_os_error(libc::ENOBUFS),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 9;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::BackOff
            );
            assert_eq!(next_packet, 1);
            assert_eq!(
                consecutive_errors, 1,
                "write progress resets the backoff state"
            );

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, batch.len());
            assert_eq!(writer.calls[0], batch);
            assert_eq!(writer.calls[1], batch[1..]);
            assert_eq!(writer.written, batch);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batches, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 3);
            assert_eq!(stats.tun_fd_write_batch_max_packets, 3);
            assert_eq!(stats.outbound_dropped_packets, 0);
        }

        #[tokio::test]
        async fn invalid_packet_drops_only_it_and_keeps_the_later_tail() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    1,
                    io::Error::new(io::ErrorKind::InvalidData, "malformed packet"),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 0;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::DarwinUtun,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, 2, "one packet was written and one dropped");

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::DarwinUtun,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(writer.calls[1], batch[2..]);
            assert_eq!(writer.written, vec![batch[0].clone(), batch[2].clone()]);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 0);
            assert_eq!(stats.tun_fd_write_batch_packets, 2);
            assert_eq!(stats.dropped_packets, 1);
            assert_eq!(stats.outbound_dropped_packets, 1);
        }

        #[tokio::test]
        async fn transient_error_at_the_legacy_cutoff_keeps_the_batch_pending() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    0,
                    io::Error::from_raw_os_error(libc::ENOBUFS),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 63;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::BackOff
            );
            assert_eq!(next_packet, 0);
            assert_eq!(consecutive_errors, 64);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 0);
            assert_eq!(stats.outbound_dropped_packets, 0);

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, batch.len());
            assert_eq!(consecutive_errors, 0);
            assert_eq!(writer.calls, vec![batch.clone(), batch.clone()]);
            assert_eq!(writer.written, batch);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 3);
            assert_eq!(stats.dropped_packets, 0);
            assert_eq!(stats.outbound_dropped_packets, 0);
        }

        #[tokio::test]
        async fn fatal_write_error_counts_the_unwritten_tail_as_dropped() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([ScriptedBatchWrite::Fail(
                PacketBatchWriteError::new(1, io::Error::from_raw_os_error(libc::EBADF)),
            )]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 0;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Stop
            );
            assert_eq!(next_packet, batch.len());

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 0);
            assert_eq!(stats.tun_fd_write_batch_packets, 1);
            assert_eq!(stats.dropped_packets, 2);
            assert_eq!(stats.outbound_dropped_packets, 2);
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

            let mut batch = Vec::with_capacity(TUN_FD_WRITE_BATCH_MAX_PACKETS);
            tun.poll_outbound_batch_into(TUN_FD_WRITE_BATCH_MAX_PACKETS, &mut batch)
                .await
                .unwrap();

            assert_eq!(batch.len(), TUN_FD_WRITE_BATCH_MAX_PACKETS);
            assert_eq!(
                tun.try_poll_outbound().await.unwrap(),
                Some(Bytes::from(vec![
                    0x45,
                    TUN_FD_WRITE_BATCH_MAX_PACKETS as u8
                ]))
            );
        }

        #[tokio::test]
        async fn outbound_batch_reuses_caller_vector_allocation() {
            let tun = TunEndpoint::new(TunConfig {
                mtu: 1500,
                queue_depth: 4,
            });
            let mut batch = Vec::with_capacity(TUN_FD_WRITE_BATCH_MAX_PACKETS);
            let allocation = batch.as_ptr();

            tun.push_outbound(Bytes::from_static(&[0x45, 0x00]))
                .await
                .unwrap();
            tun.poll_outbound_batch_into(TUN_FD_WRITE_BATCH_MAX_PACKETS, &mut batch)
                .await
                .unwrap();
            batch.clear();
            tun.push_outbound(Bytes::from_static(&[0x60, 0x00]))
                .await
                .unwrap();
            tun.poll_outbound_batch_into(TUN_FD_WRITE_BATCH_MAX_PACKETS, &mut batch)
                .await
                .unwrap();

            assert_eq!(batch.as_ptr(), allocation);
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
