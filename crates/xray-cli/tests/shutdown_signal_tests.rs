//! `xray-rust run` stops gracefully on SIGINT and on SIGTERM, as Xray-core
//! does: the core's shutdown runs and the process exits with status 0. Under
//! the default disposition SIGTERM would end the process at once, and its wait
//! status would carry the signal instead of an exit code.
#![cfg(unix)]

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const READY_LINE: &str = "bound inbound socks-in at ";

const CONFIG: &str = r#"{
  "inbounds": [
    { "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0 }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": {} }
  ]
}"#;

#[test]
fn run_stops_gracefully_on_sigterm() {
    assert_graceful_stop(libc::SIGTERM, "SIGTERM");
}

#[test]
fn run_stops_gracefully_on_sigint() {
    assert_graceful_stop(libc::SIGINT, "SIGINT");
}

fn assert_graceful_stop(signal: libc::c_int, name: &str) {
    let temp_dir = TempDir::new(&format!("xray-cli-{}", name.to_ascii_lowercase()));
    let config_path = temp_dir.path.join("client.json");
    fs::write(&config_path, CONFIG).expect("write config");
    let stdout_path = temp_dir.path.join("stdout.log");
    let stderr_path = temp_dir.path.join("stderr.log");
    let child = Command::new(env!("CARGO_BIN_EXE_xray-rust"))
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(fs::File::create(&stdout_path).expect("create stdout log"))
        .stderr(fs::File::create(&stderr_path).expect("create stderr log"))
        .spawn()
        .expect("spawn xray-rust");
    let mut child = ChildGuard(child);
    let logs = || {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            fs::read_to_string(&stdout_path).unwrap_or_default(),
            fs::read_to_string(&stderr_path).unwrap_or_default()
        )
    };

    let deadline = Instant::now() + READY_TIMEOUT;
    while !fs::read_to_string(&stderr_path)
        .unwrap_or_default()
        .lines()
        .any(|line| line.starts_with(READY_LINE))
    {
        if let Some(status) = child.0.try_wait().expect("poll xray-rust") {
            panic!("xray-rust exited before it was ready: {status}\n{}", logs());
        }
        assert!(
            Instant::now() < deadline,
            "xray-rust did not report its inbound within {READY_TIMEOUT:?}\n{}",
            logs()
        );
        sleep(POLL_INTERVAL);
    }

    let pid = libc::pid_t::try_from(child.0.id()).expect("pid fits pid_t");
    // SAFETY: kill(2) takes plain integers. The child has not been reaped,
    // so its pid cannot have been reused by another process.
    let rc = unsafe { libc::kill(pid, signal) };
    assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
    let sent = Instant::now();

    let status = wait_until(&mut child.0, sent + STOP_TIMEOUT).unwrap_or_else(|| {
        panic!(
            "xray-rust did not exit within {STOP_TIMEOUT:?} of {name}\n{}",
            logs()
        )
    });
    assert_eq!(
        status.signal(),
        None,
        "{name} killed xray-rust without its graceful shutdown ({status})\n{}",
        logs()
    );
    assert!(
        status.success(),
        "xray-rust exited with {status} after {name}\n{}",
        logs()
    );
    eprintln!("{name}: exit 0 after {:?}", sent.elapsed());
}

fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().expect("poll xray-rust") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        sleep(POLL_INTERVAL);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after the unix epoch")
            .as_nanos();
        for attempt in 0..16 {
            let path =
                env::temp_dir().join(format!("{prefix}-{}-{now}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create temp dir {}: {error}", path.display()),
            }
        }
        panic!("failed to create a unique temp dir for {prefix}");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
