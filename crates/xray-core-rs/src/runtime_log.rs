use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOG_QUEUE_CAPACITY: usize = 4096;
const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(100);
const LOG_FLUSH_BATCH_SIZE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLogConfig {
    access_path: PathBuf,
    error_path: PathBuf,
}

impl RuntimeLogConfig {
    pub fn directory(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            access_path: dir.join("xray-access.log"),
            error_path: dir.join("xray-error.log"),
        }
    }

    pub fn access_path(&self) -> &Path {
        &self.access_path
    }

    pub fn error_path(&self) -> &Path {
        &self.error_path
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeLogger {
    inner: Option<Arc<RuntimeLoggerInner>>,
}

impl RuntimeLogger {
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn new(config: RuntimeLogConfig) -> io::Result<Self> {
        Self::with_queue_capacity(config, LOG_QUEUE_CAPACITY)
    }

    fn with_queue_capacity(config: RuntimeLogConfig, queue_capacity: usize) -> io::Result<Self> {
        let access = open_log_file(config.access_path())?;
        let error = open_log_file(config.error_path())?;
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let worker = thread::Builder::new()
            .name("xray-runtime-log".to_owned())
            .spawn(move || writer_loop(receiver, access, error))?;

        Ok(Self {
            inner: Some(Arc::new(RuntimeLoggerInner {
                sender: Some(sender),
                dropped_lines: AtomicU64::new(0),
                worker: Some(worker),
            })),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    pub fn dropped_lines(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.dropped_lines.load(Ordering::Relaxed))
    }

    pub fn debug(&self, message: impl FnOnce() -> String) {
        self.write_error("debug", message);
    }

    pub fn error(&self, message: impl FnOnce() -> String) {
        self.write_error("error", message);
    }

    pub fn access(&self, message: impl FnOnce() -> String) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner.enqueue(LogRecord {
            destination: LogDestination::Access,
            level: "access",
            message: message(),
        });
    }

    fn write_error(&self, level: &'static str, message: impl FnOnce() -> String) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner.enqueue(LogRecord {
            destination: LogDestination::Error,
            level,
            message: message(),
        });
    }
}

struct RuntimeLoggerInner {
    sender: Option<SyncSender<LogRecord>>,
    dropped_lines: AtomicU64,
    worker: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for RuntimeLoggerInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeLoggerInner")
            .field("queue_connected", &self.sender.is_some())
            .field("dropped_lines", &self.dropped_lines.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RuntimeLoggerInner {
    fn enqueue(&self, record: LogRecord) {
        let Some(sender) = self.sender.as_ref() else {
            self.dropped_lines.fetch_add(1, Ordering::Relaxed);
            return;
        };
        enqueue_nonblocking(sender, &self.dropped_lines, record);
    }
}

impl Drop for RuntimeLoggerInner {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum LogDestination {
    Access,
    Error,
}

#[derive(Debug)]
struct LogRecord {
    destination: LogDestination,
    level: &'static str,
    message: String,
}

fn enqueue_nonblocking(
    sender: &SyncSender<LogRecord>,
    dropped_lines: &AtomicU64,
    record: LogRecord,
) {
    if matches!(
        sender.try_send(record),
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_))
    ) {
        dropped_lines.fetch_add(1, Ordering::Relaxed);
    }
}

fn writer_loop(
    receiver: Receiver<LogRecord>,
    mut access: BufWriter<File>,
    mut error: BufWriter<File>,
) {
    let mut pending_since_flush = 0usize;

    loop {
        match receiver.recv_timeout(LOG_FLUSH_INTERVAL) {
            Ok(record) => {
                write_record(&mut access, &mut error, record);
                pending_since_flush += 1;

                while pending_since_flush < LOG_FLUSH_BATCH_SIZE {
                    match receiver.try_recv() {
                        Ok(record) => {
                            write_record(&mut access, &mut error, record);
                            pending_since_flush += 1;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            flush_logs(&mut access, &mut error);
                            return;
                        }
                    }
                }

                if pending_since_flush >= LOG_FLUSH_BATCH_SIZE {
                    flush_logs(&mut access, &mut error);
                    pending_since_flush = 0;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if pending_since_flush > 0 {
                    flush_logs(&mut access, &mut error);
                    pending_since_flush = 0;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                flush_logs(&mut access, &mut error);
                return;
            }
        }
    }
}

fn write_record(access: &mut BufWriter<File>, error: &mut BufWriter<File>, record: LogRecord) {
    let writer = match record.destination {
        LogDestination::Access => access,
        LogDestination::Error => error,
    };
    let message = single_line_message(&record.message);
    let _ = writeln!(
        writer,
        "{} {} {}",
        timestamp_millis(),
        record.level,
        message
    );
}

fn single_line_message(message: &str) -> String {
    let mut sanitized = String::with_capacity(message.len());
    for character in message.chars() {
        match character {
            '\n' => sanitized.push_str("\\n"),
            '\r' => sanitized.push_str("\\r"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(sanitized, "\\u{{{:x}}}", u32::from(character));
            }
            character => sanitized.push(character),
        }
    }
    sanitized
}

fn flush_logs(access: &mut BufWriter<File>, error: &mut BufWriter<File>) {
    let _ = access.flush();
    let _ = error.flush();
}

fn open_log_file(path: &Path) -> io::Result<BufWriter<File>> {
    #[cfg(unix)]
    {
        open_log_file_unix(path).map(BufWriter::new)
    }

    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        let file = options.open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime log target is not a regular file",
            ));
        }
        Ok(BufWriter::new(file))
    }
}

#[cfg(unix)]
fn open_log_file_unix(path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    fn open_directory(path: &CString) -> io::Result<File> {
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_DIRECTORY;
        // SAFETY: `path` is NUL-terminated and flags request a read-only
        // directory descriptor. The returned fd is uniquely owned.
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `open` returned a fresh owned fd and this is its sole owner.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    #[cfg(target_vendor = "apple")]
    let normalized_path = normalize_apple_system_directory_alias(path);
    #[cfg(target_vendor = "apple")]
    let path = normalized_path.as_path();

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime log path has no file name",
        )
    })?;
    let starting_path = if parent.is_absolute() { "/" } else { "." };
    let starting_path = CString::new(starting_path).expect("static path contains no NUL");
    let mut current_dir = open_directory(&starting_path)?;

    for component in parent.components() {
        let Component::Normal(component) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime log path may not contain parent or prefix components",
            ));
        };
        let component = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime log directory component contains NUL",
            )
        })?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_DIRECTORY;
        // SAFETY: the directory fd is live and `component` is one
        // NUL-terminated path component. No writable access is requested.
        let mut fd = unsafe { libc::openat(current_dir.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            // SAFETY: both arguments are valid and the mode only grants
            // access to the current user (subject to a stricter umask).
            let mkdir_result =
                unsafe { libc::mkdirat(current_dir.as_raw_fd(), component.as_ptr(), 0o700) };
            if mkdir_result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: same live directory fd and component as above.
            fd = unsafe { libc::openat(current_dir.as_raw_fd(), component.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a fresh owned fd.
        current_dir = unsafe { File::from_raw_fd(fd) };
    }

    let file_name = CString::new(file_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime log file name contains NUL",
        )
    })?;
    let flags = libc::O_WRONLY
        | libc::O_APPEND
        | libc::O_CREAT
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK;
    // SAFETY: the directory fd is live, `file_name` is one NUL-terminated
    // component, and a creation mode is supplied because O_CREAT is set.
    let fd = unsafe { libc::openat(current_dir.as_raw_fd(), file_name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh owned fd and this is its sole owner.
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime log target is not a regular file",
        ));
    }
    // SAFETY: `file` owns a live descriptor. Tightening permissions to 0600
    // prevents a pre-existing log from retaining broader access.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(target_vendor = "apple")]
fn normalize_apple_system_directory_alias(path: &Path) -> PathBuf {
    for alias in ["/var", "/tmp", "/etc"] {
        let alias = Path::new(alias);
        if let Ok(suffix) = path.strip_prefix(alias) {
            return Path::new("/private")
                .join(alias.strip_prefix("/").expect("absolute static alias"))
                .join(suffix);
        }
    }
    path.to_path_buf()
}

fn timestamp_millis() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}.{}", duration.as_secs(), duration.subsec_millis()),
        Err(_) => "0.000".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Instant;

    use super::{RuntimeLogConfig, RuntimeLogger, RuntimeLoggerInner};

    #[test]
    fn disabled_logger_does_not_evaluate_message_closure() {
        let logger = RuntimeLogger::disabled();
        let evaluated = AtomicBool::new(false);

        assert!(!logger.is_enabled());
        logger.debug(|| {
            evaluated.store(true, Ordering::SeqCst);
            "should not be built".to_owned()
        });

        assert!(!evaluated.load(Ordering::SeqCst));
    }

    #[test]
    fn enabled_logger_flushes_debug_and_access_files_on_drop() {
        let dir = unique_temp_dir("xray-runtime-log");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");

        logger.debug(|| "Debug routeDecision target=example.com:443".to_owned());
        logger.error(|| "startup probe failed: tls handshake eof".to_owned());
        logger.access(|| "from 10.0.0.2:49152 accepted example.com:443 proxy".to_owned());
        drop(logger);

        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");
        let access_log =
            std::fs::read_to_string(dir.join("xray-access.log")).expect("access log should exist");
        assert!(error_log.contains("Debug routeDecision"));
        assert!(error_log.contains("startup probe failed"));
        assert!(access_log.contains("accepted example.com:443"));
    }

    #[test]
    fn full_queue_drops_without_blocking_producer() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let logger = RuntimeLogger {
            inner: Some(Arc::new(RuntimeLoggerInner {
                sender: Some(sender),
                dropped_lines: AtomicU64::new(0),
                worker: None,
            })),
        };

        logger.debug(|| "first".to_owned());
        logger.debug(|| "second".to_owned());

        assert_eq!(logger.dropped_lines(), 1);
    }

    #[test]
    fn last_clone_owns_writer_shutdown() {
        let dir = unique_temp_dir("xray-runtime-log-clone");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");
        let clone = logger.clone();
        logger.debug(|| "before first drop".to_owned());
        drop(logger);
        clone.debug(|| "before final drop".to_owned());
        drop(clone);

        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");

        assert!(error_log.contains("before final drop"));
    }

    #[test]
    fn control_characters_cannot_forge_additional_log_records() {
        let dir = unique_temp_dir("xray-runtime-log-control");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");

        logger.error(|| "proxy\n123 error forged\r\u{7}".to_owned());
        drop(logger);

        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");
        assert_eq!(error_log.lines().count(), 1);
        assert!(error_log.contains(r"proxy\n123 error forged\r\u{7}"));
    }

    #[cfg(unix)]
    #[test]
    fn logger_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let dir = unique_temp_dir("xray-runtime-log-symlink");
        let target = dir.join("target");
        std::fs::write(&target, "unchanged").unwrap();
        symlink(&target, dir.join("xray-access.log")).unwrap();

        let error = RuntimeLogger::new(RuntimeLogConfig::directory(&dir)).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn logger_rejects_intermediate_directory_symlink() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("xray-runtime-log-directory-symlink");
        let base = root.join("base");
        let outside = root.join("outside");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, base.join("logs")).unwrap();

        let error = RuntimeLogger::new(RuntimeLogConfig::directory(base.join("logs"))).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!outside.join("xray-access.log").exists());
        assert!(!outside.join("xray-error.log").exists());
    }

    #[cfg(unix)]
    #[test]
    fn logger_rejects_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = unique_temp_dir("xray-runtime-log-fifo");
        let fifo = dir.join("xray-access.log");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo_path` is a live NUL-terminated filesystem path.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);

        let started = Instant::now();
        let error = RuntimeLogger::new(RuntimeLogConfig::directory(&dir)).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(started.elapsed().as_secs() < 1);
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }
}
