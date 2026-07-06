use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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
        Ok(Self {
            inner: Some(Arc::new(RuntimeLoggerInner {
                access: Mutex::new(open_log_file(config.access_path())?),
                error: Mutex::new(open_log_file(config.error_path())?),
            })),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
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
        write_line(&inner.access, "access", message());
    }

    fn write_error(&self, level: &'static str, message: impl FnOnce() -> String) {
        let Some(inner) = &self.inner else {
            return;
        };
        write_line(&inner.error, level, message());
    }
}

#[derive(Debug)]
struct RuntimeLoggerInner {
    access: Mutex<BufWriter<File>>,
    error: Mutex<BufWriter<File>>,
}

fn open_log_file(path: &Path) -> io::Result<BufWriter<File>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path).map(BufWriter::new)
}

fn write_line(writer: &Mutex<BufWriter<File>>, level: &'static str, message: String) {
    let Ok(mut writer) = writer.lock() else {
        return;
    };
    let _ = writeln!(writer, "{} {level} {message}", timestamp_millis());
    let _ = writer.flush();
}

fn timestamp_millis() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}.{}", duration.as_secs(), duration.subsec_millis()),
        Err(_) => "0.000".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{RuntimeLogConfig, RuntimeLogger};

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
    fn enabled_logger_writes_debug_and_access_files() {
        let dir = unique_temp_dir("xray-runtime-log");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");

        assert!(logger.is_enabled());
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
