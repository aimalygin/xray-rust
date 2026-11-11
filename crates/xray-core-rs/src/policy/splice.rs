//! Linux: the download of a TCP relay, moved in the kernel.
//!
//! Where what the outbound has yet to deliver is a bare TCP socket's bytes
//! and the inbound is a TCP socket too, the bytes go from one to the other
//! through a pipe with `splice(2)` and never enter this process, as
//! Xray-core's `proxy.CopyRawConnIfExist` moves them. That is a freedom
//! outbound from its first byte, and VLESS Vision once its download switched
//! to direct mode. Upload is copied as everywhere else; Xray-core does not
//! splice it either.
//!
//! Xray-core parks its idle timers for 24 hours while it splices and adds the
//! transfer to its counters when it ends. Here every chunk that lands counts
//! as activity and reaches the counters at once, so `connIdle`, the two
//! half-close timeouts and the connection's traffic stay what they are on the
//! copying path.
//!
//! Xray-core's `xray.buf.splice` environment flag (`XRAY_BUF_SPLICE`) turns
//! it off: unset, `auto` and `enable` splice, anything else copies. Xray-core
//! reads the flag for its freedom outbound alone and splices Vision's direct
//! download whatever it says; here it stops both, so one switch takes the
//! kernel path out of a process that must not use it.

use std::ffi::OsStr;
use std::fs::File;
use std::future::poll_fn;
use std::io::{self, IoSlice, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, Interest, ReadBuf};
use tokio::net::tcp::WriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use xray_transport::{BoxedTransportStream, RawRead};

use super::relay_buffer::{RelayBuffer, PROCESS_POOL};
use super::{
    copy_direction_with_counter, relay_until_done_or_idle, CopyActivity, RelayTimeouts,
    MAX_COPY_BUFFER_SIZE, MIN_COPY_BUFFER_SIZE,
};
use crate::connection::ConnectionTraffic;

/// What one `splice` may move, and the pipe size asked for: Go's
/// `maxSpliceSize`, which Xray-core's splice runs with.
const PIPE_CAPACITY: usize = 1024 * 1024;

/// The least a pipe has to hold for splicing through it to beat copying: a
/// pipe of the kernel's default size. Past `fs.pipe-user-pages-soft` (64 MiB
/// of pipes for one user) a process without `CAP_SYS_RESOURCE` gets pipes of
/// two pages, which would move a packet or two with each pair of calls.
const MIN_PIPE_CAPACITY: libc::c_int = 64 * 1024;

/// Xray-core's `UseFreedomSplice` flag and the name `NormalizeEnvName` gives
/// it; `EnvFlag.GetValue` looks the first up, then the second.
const SPLICE_FLAGS: [&str; 2] = ["xray.buf.splice", "XRAY_BUF_SPLICE"];

/// Whether this process splices: Xray-core's `reloadEnvSettings` on the first
/// of [`SPLICE_FLAGS`] that is set, read once.
fn splice_enabled() -> bool {
    #[cfg(test)]
    if let Some(forced) = tests::SPLICE_FLAG.with(std::cell::Cell::get) {
        return forced;
    }
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let value = SPLICE_FLAGS.iter().find_map(std::env::var_os);
        splice_flag_enables(value.as_deref())
    })
}

/// `reloadEnvSettings`: an unset flag, `auto` and `enable` splice; any other
/// value, the empty one included, does not.
fn splice_flag_enables(value: Option<&OsStr>) -> bool {
    match value {
        None => true,
        Some(value) => value == "auto" || value == "enable",
    }
}

/// [`copy_bidirectional_with_idle_timeout_and_traffic`] for a TCP inbound,
/// with the download spliced for as long as the outbound reads a bare socket.
///
/// [`copy_bidirectional_with_idle_timeout_and_traffic`]: super::copy_bidirectional_with_idle_timeout_and_traffic
pub(crate) async fn copy_bidirectional_with_splice(
    inbound: &mut TcpStream,
    outbound: &mut BoxedTransportStream,
    timeouts: RelayTimeouts,
    buffer_size: usize,
    traffic: &ConnectionTraffic,
) -> io::Result<(u64, u64)> {
    let (mut inbound_read, mut inbound_write) = inbound.split();
    let outbound = SharedStream(Mutex::new(outbound));
    let (activity_tx, activity_rx) = mpsc::channel(1);
    let upload_activity = activity_tx.clone();
    let upload = async {
        copy_direction_with_counter(
            &mut inbound_read,
            &mut WriteSide(&outbound),
            upload_activity,
            buffer_size,
            Some(&traffic.uplink_bytes),
        )
        .await
    };
    let download = copy_download(
        &outbound,
        &mut inbound_write,
        activity_tx,
        buffer_size,
        &traffic.downlink_bytes,
    );
    relay_until_done_or_idle(upload, download, activity_rx, timeouts).await
}

/// The outbound stream, which both directions of the one relay task use.
/// Unlike a `tokio::io::split` half it can be asked for its socket.
struct SharedStream<'a>(Mutex<&'a mut BoxedTransportStream>);

impl<'a> SharedStream<'a> {
    fn lock(&self) -> MutexGuard<'_, &'a mut BoxedTransportStream> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn source(&self) -> Source {
        if !splice_enabled() {
            return Source::Decoded;
        }
        match self.lock().raw_read() {
            RawRead::Never => Source::Decoded,
            RawRead::NotYet => Source::Undecided,
            RawRead::Socket(_) => Source::Socket,
        }
    }
}

/// Where the rest of the download comes from.
enum Source {
    /// The stream's own reads, to the end.
    Decoded,
    /// The stream's reads for now.
    Undecided,
    /// The socket under the stream.
    Socket,
}

struct ReadSide<'s, 'a>(&'s SharedStream<'a>);

impl AsyncRead for ReadSide<'_, '_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut ***self.0.lock()).poll_read(cx, output)
    }
}

struct WriteSide<'s, 'a>(&'s SharedStream<'a>);

impl AsyncWrite for WriteSide<'_, '_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut ***self.0.lock()).poll_write(cx, input)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut ***self.0.lock()).poll_write_vectored(cx, inputs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.lock().is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut ***self.0.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut ***self.0.lock()).poll_shutdown(cx)
    }
}

/// What a download delivered so far, told to the connection's counter and
/// to the idle timer as it lands.
struct Delivered<'c, A> {
    total: u64,
    counter: &'c AtomicU64,
    activity: A,
}

impl<A: CopyActivity> Delivered<'_, A> {
    fn add(&mut self, bytes: usize) {
        self.total = self.total.saturating_add(bytes as u64);
        self.counter.fetch_add(bytes as u64, Ordering::Relaxed);
        self.activity.record(bytes);
    }

    /// Copies the rest of the download as a relay without splice does.
    async fn copy_rest(
        self,
        reader: &mut ReadSide<'_, '_>,
        inbound: &mut WriteHalf<'_>,
        buffer_size: usize,
    ) -> io::Result<u64> {
        let counter = Some(self.counter);
        let rest =
            copy_direction_with_counter(reader, inbound, self.activity, buffer_size, counter)
                .await?;
        Ok(self.total.saturating_add(rest))
    }
}

async fn copy_download(
    outbound: &SharedStream<'_>,
    inbound: &mut WriteHalf<'_>,
    activity: impl CopyActivity,
    buffer_size: usize,
    counter: &AtomicU64,
) -> io::Result<u64> {
    let mut reader = ReadSide(outbound);
    let mut delivered = Delivered {
        total: 0,
        counter,
        activity,
    };

    // Until the stream settles on its socket or on decoding to the end, read
    // it as the copying path does, into the same kind of buffer. What it
    // decoded before its socket took over leaves through these reads, ahead
    // of anything spliced. The inbound is a socket, so a write needs no flush.
    let buffer_cap = buffer_size.clamp(MIN_COPY_BUFFER_SIZE, MAX_COPY_BUFFER_SIZE);
    let mut buffer = RelayBuffer::new(buffer_cap, &PROCESS_POOL);
    loop {
        match outbound.source() {
            Source::Socket => break,
            Source::Decoded => {
                drop(buffer);
                return delivered.copy_rest(&mut reader, inbound, buffer_size).await;
            }
            Source::Undecided => {}
        }
        let len = poll_fn(|cx| buffer.poll_read(cx, Pin::new(&mut reader))).await?;
        if len == 0 {
            inbound.shutdown().await?;
            return Ok(delivered.total);
        }
        inbound.write_all(buffer.filled(len)).await?;
        delivered.add(len);
    }
    // The socket takes over: what the process lent goes back to it.
    drop(buffer);

    // No pipe to be had: copy.
    let Ok(pipe) = Pipe::new() else {
        return delivered.copy_rest(&mut reader, inbound, buffer_size).await;
    };
    let mut in_pipe = 0;
    loop {
        let step = poll_fn(|cx| poll_move(cx, outbound, inbound.as_ref(), &pipe, &mut in_pipe));
        match step.await? {
            Step::Moved(bytes) => delivered.add(bytes),
            Step::End => {
                inbound.shutdown().await?;
                return Ok(delivered.total);
            }
            Step::Refused => break,
        }
    }
    // The kernel would not splice these sockets. What the pipe still holds
    // was taken from the outbound socket already, so it goes out ahead of
    // the copying that takes over.
    let mut rescued = vec![0; in_pipe.min(buffer_cap)];
    while in_pipe > 0 {
        let want = rescued.len().min(in_pipe);
        let len = (&pipe.read).read(&mut rescued[..want])?;
        if len == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        inbound.write_all(&rescued[..len]).await?;
        in_pipe -= len;
        delivered.add(len);
    }
    drop((pipe, rescued));
    delivered.copy_rest(&mut reader, inbound, buffer_size).await
}

enum Step {
    /// This many bytes reached the inbound socket.
    Moved(usize),
    /// The outbound socket is at its end and the pipe is empty.
    End,
    /// The kernel would not splice; the pipe may hold bytes.
    Refused,
}

/// Fills the pipe from the outbound socket when it is empty, then moves what
/// it holds into the inbound socket. The pipe is drained before it is filled
/// again, so a fill that finds nothing means the socket has nothing.
fn poll_move(
    cx: &mut Context<'_>,
    outbound: &SharedStream<'_>,
    inbound: &TcpStream,
    pipe: &Pipe,
    in_pipe: &mut usize,
) -> Poll<io::Result<Step>> {
    loop {
        if *in_pipe == 0 {
            let mut outbound = outbound.lock();
            let RawRead::Socket(source) = outbound.raw_read() else {
                return Poll::Ready(Ok(Step::Refused));
            };
            ready!(source.poll_read_ready(cx))?;
            let fill = || splice(source.as_fd(), pipe.write.as_fd(), PIPE_CAPACITY);
            match source.try_io(Interest::READABLE, fill) {
                Ok(0) => return Poll::Ready(Ok(Step::End)),
                Ok(filled) => *in_pipe = filled,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if refused(&error) => return Poll::Ready(Ok(Step::Refused)),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        ready!(inbound.poll_write_ready(cx))?;
        let drain = || splice(pipe.read.as_fd(), inbound.as_fd(), *in_pipe);
        match inbound.try_io(Interest::WRITABLE, drain) {
            Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Ok(moved) => {
                *in_pipe -= moved;
                #[cfg(test)]
                tests::SPLICED.with(|spliced| spliced.set(spliced.get() + moved as u64));
                return Poll::Ready(Ok(Step::Moved(moved)));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if refused(&error) => return Poll::Ready(Ok(Step::Refused)),
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
}

/// Whether the kernel declined to splice these descriptors at all, rather
/// than failed the transfer: no `splice_read` or `splice_write` for the
/// socket's protocol, or a sandbox without the call.
fn refused(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP)
    )
}

fn splice(from: BorrowedFd<'_>, to: BorrowedFd<'_>, len: usize) -> io::Result<usize> {
    #[cfg(test)]
    tests::before_splice()?;
    loop {
        // SAFETY: both descriptors stay open for the call, and a null offset
        // is the one a pipe and a socket take.
        let moved = unsafe {
            libc::splice(
                from.as_raw_fd(),
                std::ptr::null_mut(),
                to.as_raw_fd(),
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if let Ok(moved) = usize::try_from(moved) {
            return Ok(moved);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// The pipe one download is spliced through: two descriptors for as long as
/// the download lasts, and no memory of this process.
struct Pipe {
    read: File,
    write: OwnedFd,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut ends: [RawFd; 2] = [0; 2];
        // SAFETY: `ends` is the two descriptors `pipe2` fills in.
        if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `pipe2` just opened both, and nothing else owns them.
        let (read, write) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        // A larger pipe moves more with each call. The kernel refuses one
        // once the user's pipe pages are spent; the default size works too.
        // SAFETY: `write` is an open pipe, and the size is the int F_SETPIPE_SZ takes.
        unsafe {
            libc::fcntl(
                write.as_raw_fd(),
                libc::F_SETPIPE_SZ,
                PIPE_CAPACITY as libc::c_int,
            )
        };
        // SAFETY: `write` is an open pipe; F_GETPIPE_SZ takes no argument.
        let capacity = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETPIPE_SZ) };
        #[cfg(test)]
        let capacity = tests::PIPE_CAPACITY_SEEN.with(|seen| seen.get().unwrap_or(capacity));
        if !worth_splicing_through(capacity) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(Self {
            read: File::from(read),
            write,
        })
    }
}

fn worth_splicing_through(pipe_capacity: libc::c_int) -> bool {
    pipe_capacity >= MIN_PIPE_CAPACITY
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use xray_proxy::vless::{VisionCommand, VisionPadding};

    use super::*;

    thread_local! {
        /// Bytes `splice` put into an inbound socket on this thread.
        pub(super) static SPLICED: Cell<u64> = const { Cell::new(0) };
        /// How many more `splice` calls succeed before each fails with EINVAL.
        static SPLICES_ALLOWED: Cell<Option<usize>> = const { Cell::new(None) };
        /// The size a new pipe reports on this thread, in place of its own.
        pub(super) static PIPE_CAPACITY_SEEN: Cell<Option<libc::c_int>> = const { Cell::new(None) };
        /// What the splice flag says on this thread, in place of the
        /// environment.
        pub(super) static SPLICE_FLAG: Cell<Option<bool>> = const { Cell::new(None) };
    }

    pub(super) fn before_splice() -> io::Result<()> {
        SPLICES_ALLOWED.with(|allowed| match allowed.get() {
            None => Ok(()),
            Some(0) => Err(io::Error::from_raw_os_error(libc::EINVAL)),
            Some(left) => {
                allowed.set(Some(left - 1));
                Ok(())
            }
        })
    }

    fn spliced() -> u64 {
        SPLICED.with(Cell::get)
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connect = TcpStream::connect(listener.local_addr().unwrap());
        let (connected, accepted) = tokio::join!(connect, listener.accept());
        (connected.unwrap(), accepted.unwrap().0)
    }

    /// Bytes whose value depends on where they sit, so a reordering shows.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| (index.wrapping_mul(31) ^ (index >> 11)) as u8)
            .collect()
    }

    fn timeouts(idle: Duration) -> RelayTimeouts {
        RelayTimeouts::uniform(idle)
    }

    type Relay = tokio::task::JoinHandle<io::Result<(u64, u64)>>;

    fn spawn_relay(
        mut inbound: TcpStream,
        mut outbound: BoxedTransportStream,
        timeouts: RelayTimeouts,
        traffic: Arc<ConnectionTraffic>,
    ) -> Relay {
        tokio::spawn(async move {
            copy_bidirectional_with_splice(
                &mut inbound,
                &mut outbound,
                timeouts,
                128 * 1024,
                &traffic,
            )
            .await
        })
    }

    /// One request up and `response` down through a relay over `outbound`,
    /// each side closing after it sent; returns what the client received.
    async fn exchange(
        outbound: BoxedTransportStream,
        mut server: TcpStream,
        response: Vec<u8>,
    ) -> (Vec<u8>, (u64, u64), Arc<ConnectionTraffic>) {
        let (mut client, inbound) = tcp_pair().await;
        let traffic = Arc::new(ConnectionTraffic::default());
        let relay = spawn_relay(
            inbound,
            outbound,
            timeouts(Duration::from_secs(20)),
            traffic.clone(),
        );
        let server = tokio::spawn(async move {
            let mut request = [0; 7];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
            let mut rest = Vec::new();
            server.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        });
        client.write_all(b"request").await.unwrap();
        let mut received = Vec::new();
        // The download has to end while the upload is still open.
        tokio::time::timeout(Duration::from_secs(30), client.read_to_end(&mut received))
            .await
            .expect("the server's close reaches the client")
            .unwrap();
        client.shutdown().await.unwrap();
        server.await.unwrap();
        let copied = relay.await.unwrap().unwrap();
        (received, copied, traffic)
    }

    #[tokio::test]
    async fn download_from_a_bare_socket_is_spliced_whole() {
        let (outbound, server) = tcp_pair().await;
        let response = pattern(5 * 1024 * 1024 + 123);

        let (received, copied, traffic) =
            exchange(Box::new(outbound), server, response.clone()).await;

        assert!(received == response, "download differs");
        assert_eq!(copied, (7, response.len() as u64));
        assert_eq!(traffic.uplink_bytes.load(Ordering::Relaxed), 7);
        assert_eq!(
            traffic.downlink_bytes.load(Ordering::Relaxed),
            response.len() as u64
        );
        assert_eq!(spliced(), response.len() as u64);
    }

    #[tokio::test]
    async fn stream_that_decodes_to_the_end_is_copied() {
        let (outbound, mut far) = tokio::io::duplex(64 * 1024);
        let (server, mut bridge) = tcp_pair().await;
        // The duplex stands for a stream that never is a socket; the bridge
        // joins it to a server that speaks TCP like the other tests'.
        tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut far, &mut bridge).await;
        });
        let response = pattern(1024 * 1024 + 5);

        let (received, copied, _) = exchange(Box::new(outbound), server, response.clone()).await;

        assert!(received == response, "download differs");
        assert_eq!(copied, (7, response.len() as u64));
        assert_eq!(spliced(), 0);
    }

    #[tokio::test]
    async fn refused_splice_falls_back_to_copying_without_losing_or_reordering() {
        // 0 refuses the first fill; 1 refuses the first drain, with the bytes
        // already in the pipe; the others refuse further into the download.
        for allowed in [0, 1, 2, 3, 8] {
            SPLICED.with(|spliced| spliced.set(0));
            SPLICES_ALLOWED.with(|left| left.set(Some(allowed)));
            let (outbound, server) = tcp_pair().await;
            let response = pattern(3 * 1024 * 1024 + 17);

            let (received, copied, traffic) =
                exchange(Box::new(outbound), server, response.clone()).await;

            assert!(received == response, "download differs after {allowed}");
            assert_eq!(copied, (7, response.len() as u64));
            assert_eq!(
                traffic.downlink_bytes.load(Ordering::Relaxed),
                response.len() as u64
            );
            assert!(spliced() < response.len() as u64, "after {allowed}");
            assert_eq!(spliced() == 0, allowed < 2, "after {allowed}");
        }
        SPLICES_ALLOWED.with(|left| left.set(None));
    }

    #[tokio::test]
    async fn download_is_copied_when_the_kernel_hands_out_a_two_page_pipe() {
        assert!(worth_splicing_through(64 * 1024));
        assert!(!worth_splicing_through(64 * 1024 - 1));
        // What a pipe is past the user's soft limit of pipe pages.
        PIPE_CAPACITY_SEEN.with(|seen| seen.set(Some(8 * 1024)));
        let (outbound, server) = tcp_pair().await;
        let response = pattern(1024 * 1024 + 9);

        let (received, copied, _) = exchange(Box::new(outbound), server, response.clone()).await;

        PIPE_CAPACITY_SEEN.with(|seen| seen.set(None));
        assert!(received == response, "download differs");
        assert_eq!(copied, (7, response.len() as u64));
        assert_eq!(spliced(), 0);
    }

    /// Xray-core's `reloadEnvSettings`: only an unset flag, `auto` and
    /// `enable` splice, compared as they are.
    #[test]
    fn the_splice_flag_reads_as_xray_cores() {
        assert!(splice_flag_enables(None));
        for value in ["auto", "enable"] {
            assert!(splice_flag_enables(Some(OsStr::new(value))), "{value}");
        }
        for value in ["", "disable", "0", "false", "Enable", "AUTO", " enable"] {
            assert!(!splice_flag_enables(Some(OsStr::new(value))), "{value:?}");
        }
        assert_eq!(SPLICE_FLAGS, ["xray.buf.splice", "XRAY_BUF_SPLICE"]);
    }

    /// With the flag off a bare socket's download is copied like any other
    /// stream's, whole and counted.
    #[tokio::test]
    async fn download_is_copied_with_the_splice_flag_off() {
        SPLICE_FLAG.with(|flag| flag.set(Some(false)));
        let (outbound, server) = tcp_pair().await;
        let response = pattern(1024 * 1024 + 11);

        let (received, copied, traffic) =
            exchange(Box::new(outbound), server, response.clone()).await;

        SPLICE_FLAG.with(|flag| flag.set(None));
        assert!(received == response, "download differs");
        assert_eq!(copied, (7, response.len() as u64));
        assert_eq!(
            traffic.downlink_bytes.load(Ordering::Relaxed),
            response.len() as u64
        );
        assert_eq!(spliced(), 0);
    }

    #[tokio::test]
    async fn bytes_vision_decoded_before_direct_precede_the_spliced_ones() {
        const USER: [u8; 16] = [7; 16];
        let (carrier, mut server) = tcp_pair().await;
        let outbound = crate::outbound::vision_stream_for_tests(Box::new(carrier), USER);
        let (mut client, inbound) = tcp_pair().await;
        let traffic = Arc::new(ConnectionTraffic::default());
        let relay = spawn_relay(
            inbound,
            outbound,
            timeouts(Duration::from_secs(20)),
            traffic.clone(),
        );

        // The client speaks first, as it does before any server goes direct.
        client.write_all(b"request").await.unwrap();
        let mut padded_request = [0; 1];
        server.read_exact(&mut padded_request).await.unwrap();

        // A VLESS response header, a Vision block that ends in `Direct`, and
        // from there the raw stream. Its start shares a segment with the
        // block, so Vision reads it into its own buffer before the switch.
        let in_block = pattern(700);
        let raw = pattern(4 * 1024 * 1024 + 321);
        let mut first = vec![0, 0];
        first.extend_from_slice(
            &VisionPadding::new(USER, [0; 4])
                .pad(BytesMut::from(&in_block[..]), VisionCommand::Direct, 0)
                .unwrap(),
        );
        let block_end = first.len();
        first.extend_from_slice(&raw[..12 * 1024]);
        let server = tokio::spawn(async move {
            server.write_all(&first).await.unwrap();
            server.write_all(&raw[12 * 1024..]).await.unwrap();
            server.shutdown().await.unwrap();
            let mut rest = Vec::new();
            server.read_to_end(&mut rest).await.unwrap();
        });

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        client.shutdown().await.unwrap();
        server.await.unwrap();
        let copied = relay.await.unwrap().unwrap();

        let expected = [in_block, pattern(4 * 1024 * 1024 + 321)].concat();
        assert!(received == expected, "download differs");
        assert_eq!(copied, (7, expected.len() as u64));
        assert_eq!(
            traffic.downlink_bytes.load(Ordering::Relaxed),
            expected.len() as u64
        );
        // Vision read 8 KiB at most past the response header: the block and
        // the raw bytes behind it. Those were copied, everything else spliced.
        assert!(block_end < 8 * 1024);
        let copied_first = expected.len() as u64 - spliced();
        assert!(
            (701..=8 * 1024).contains(&copied_first),
            "{copied_first} bytes were copied"
        );
    }

    #[tokio::test]
    async fn held_header_still_leaves_when_the_server_goes_direct_before_any_upload() {
        const USER: [u8; 16] = [7; 16];
        let (carrier, mut server) = tcp_pair().await;
        let outbound = crate::outbound::vision_stream_for_tests(Box::new(carrier), USER);
        let (mut client, inbound) = tcp_pair().await;
        let relay = spawn_relay(
            inbound,
            outbound,
            timeouts(Duration::from_secs(20)),
            Arc::default(),
        );

        // No upload yet, and the server already switched its side to direct.
        let mut direct = vec![0, 0];
        direct.extend_from_slice(
            &VisionPadding::new(USER, [0; 4])
                .pad(BytesMut::from(&b"hello"[..]), VisionCommand::Direct, 0)
                .unwrap(),
        );
        server.write_all(&direct).await.unwrap();
        let mut hello = [0; 5];
        client.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");

        // Reads drive the wait for the first payload. Had the download left
        // them for the socket, the request would never reach the server.
        let mut request = [0; 1];
        tokio::time::timeout(Duration::from_secs(10), server.read_exact(&mut request))
            .await
            .expect("the held request leaves when its wait for a payload ends")
            .unwrap();

        // From there the download is the socket's, but for the one read
        // that was already waiting when the raw bytes came.
        let raw = pattern(256 * 1024);
        server.write_all(&raw).await.unwrap();
        let mut received = vec![0; raw.len()];
        client.read_exact(&mut received).await.unwrap();
        assert!(received == raw, "download differs");
        let read = raw.len() as u64 - spliced();
        let one_read = crate::policy::INITIAL_COPY_BUFFER_SIZE as u64;
        assert!(read <= one_read, "{read} bytes read");
        relay.abort();
    }

    #[tokio::test]
    async fn spliced_bytes_keep_the_connection_from_idling_out() {
        let (outbound, mut server) = tcp_pair().await;
        let (mut client, inbound) = tcp_pair().await;
        let idle = Duration::from_millis(1500);
        let relay = spawn_relay(inbound, Box::new(outbound), timeouts(idle), Arc::default());

        // Only the download moves, in steps shorter than the idle bound, for
        // longer than the bound in all.
        let started = tokio::time::Instant::now();
        let chunk = pattern(32 * 1024);
        let mut received = vec![0; chunk.len()];
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            server.write_all(&chunk).await.unwrap();
            client.read_exact(&mut received).await.unwrap();
            assert!(received == chunk);
        }
        assert!(started.elapsed() > idle);
        assert!(!relay.is_finished());
        assert_eq!(spliced(), 10 * chunk.len() as u64);

        // Then nothing moves, and the bound ends the relay.
        let ended = tokio::time::timeout(Duration::from_secs(10), relay)
            .await
            .expect("idle relay must end");
        assert_eq!(ended.unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
