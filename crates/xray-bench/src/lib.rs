use std::fs;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const USAGE: &str = "usage: xray-bench run|compare [options]";

#[derive(Debug, Error)]
pub enum BenchError {
    #[error("{0}")]
    InvalidArguments(String),
    #[error("io error while {action}: {source}")]
    Io {
        action: String,
        source: std::io::Error,
    },
    #[error(
        "process `{program}` failed with status {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    )]
    Process {
        program: String,
        status: String,
        stdout: String,
        stderr: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliArgs {
    Run(BenchOptions),
    Compare(BenchOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    XrayRust,
    XrayCore,
}

impl EngineKind {
    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "xray-rust" => Ok(Self::XrayRust),
            "xray-core" => Ok(Self::XrayCore),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported engine `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadKind {
    Idle,
    TcpFreedom,
}

impl WorkloadKind {
    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "idle" => Ok(Self::Idle),
            "tcp-freedom" => Ok(Self::TcpFreedom),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported workload `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchOptions {
    pub engine: Option<EngineKind>,
    pub workload: WorkloadKind,
    pub duration: Duration,
    pub sample_interval: Duration,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    pub out_dir: PathBuf,
    pub xray_rust_bin: Option<PathBuf>,
    pub xray_core_bin: Option<PathBuf>,
    pub xray_core_dir: Option<PathBuf>,
    pub no_auto_build: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProcessSample {
    pub elapsed_ms: u128,
    pub rss_kib: u64,
    pub cpu_millis: u64,
    pub threads: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BenchResult {
    pub engine: String,
    pub workload: String,
    pub status: String,
    pub duration_ms: u128,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub peak_rss_kib: u64,
    pub cpu_millis: u64,
    pub samples: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadSummary {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub peak_rss_kib: u64,
    pub cpu_millis: u64,
}

#[derive(Debug)]
pub struct RunningEngine {
    pub kind: EngineKind,
    child: Child,
    pub pid: u32,
    pub socks_addr: SocketAddr,
    pub run_dir: PathBuf,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
}

impl Drop for RunningEngine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            engine: None,
            workload: WorkloadKind::Idle,
            duration: Duration::from_secs(2),
            sample_interval: Duration::from_millis(100),
            connections: 1,
            iterations: 1,
            payload_size: 1024,
            out_dir: PathBuf::from("target/benchmarks"),
            xray_rust_bin: None,
            xray_core_bin: None,
            xray_core_dir: None,
            no_auto_build: false,
        }
    }
}

pub fn parse_cli_args<I, S>(args: I) -> Result<CliArgs, BenchError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let _program = args.next();
    let Some(command) = args.next() else {
        return Err(BenchError::InvalidArguments(USAGE.to_owned()));
    };

    let mut options = BenchOptions::default();
    let rest = args.collect::<Vec<_>>();
    let mut index = 0;
    while index < rest.len() {
        let flag = rest[index].as_str();
        index += 1;
        match flag {
            "--engine" => {
                options.engine = Some(EngineKind::parse(required_value(&rest, &mut index, flag)?)?);
            }
            "--workload" => {
                options.workload = WorkloadKind::parse(required_value(&rest, &mut index, flag)?)?;
            }
            "--duration-ms" => {
                options.duration = Duration::from_millis(parse_u64(
                    required_value(&rest, &mut index, flag)?,
                    flag,
                )?);
            }
            "--sample-interval-ms" => {
                options.sample_interval = Duration::from_millis(parse_u64(
                    required_value(&rest, &mut index, flag)?,
                    flag,
                )?);
            }
            "--connections" => {
                options.connections = parse_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--iterations" => {
                options.iterations = parse_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--payload-size" => {
                options.payload_size = parse_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--out-dir" => {
                options.out_dir = PathBuf::from(required_value(&rest, &mut index, flag)?);
            }
            "--xray-rust-bin" => {
                options.xray_rust_bin =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--xray-core-bin" => {
                options.xray_core_bin =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--xray-core-dir" => {
                options.xray_core_dir =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--no-auto-build" => {
                options.no_auto_build = true;
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{USAGE}"
                )));
            }
        }
    }

    match command.as_str() {
        "run" => {
            if options.engine.is_none() {
                return Err(BenchError::InvalidArguments(
                    "run requires --engine xray-rust|xray-core".to_owned(),
                ));
            }
            Ok(CliArgs::Run(options))
        }
        "compare" => {
            options.engine = None;
            Ok(CliArgs::Compare(options))
        }
        other => Err(BenchError::InvalidArguments(format!(
            "unknown command `{other}`\n{USAGE}"
        ))),
    }
}

fn required_value<'a>(
    args: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a str, BenchError> {
    let Some(value) = args.get(*index) else {
        return Err(BenchError::InvalidArguments(format!(
            "missing value for {flag}"
        )));
    };
    if value.starts_with("--") {
        return Err(BenchError::InvalidArguments(format!(
            "missing value for {flag}"
        )));
    }
    *index += 1;
    Ok(value)
}

fn parse_u64(raw: &str, flag: &str) -> Result<u64, BenchError> {
    raw.parse::<u64>()
        .map_err(|_| BenchError::InvalidArguments(format!("invalid integer `{raw}` for {flag}")))
}

fn parse_usize(raw: &str, flag: &str) -> Result<usize, BenchError> {
    raw.parse::<usize>()
        .map_err(|_| BenchError::InvalidArguments(format!("invalid integer `{raw}` for {flag}")))
}

pub fn parse_ps_sample(raw: &str) -> Result<ProcessSample, BenchError> {
    let fields = raw.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 2 {
        return Err(BenchError::InvalidArguments(format!(
            "invalid ps sample `{raw}`"
        )));
    }
    let rss_kib = fields[0].parse::<u64>().map_err(|_| {
        BenchError::InvalidArguments(format!("invalid ps rss field `{}`", fields[0]))
    })?;
    let cpu_millis = parse_ps_time_to_millis(fields[1])?;
    let threads = fields
        .get(2)
        .map(|raw| {
            raw.parse::<u64>().map_err(|_| {
                BenchError::InvalidArguments(format!("invalid ps thread field `{raw}`"))
            })
        })
        .transpose()?;

    Ok(ProcessSample {
        elapsed_ms: 0,
        rss_kib,
        cpu_millis,
        threads,
    })
}

fn parse_ps_time_to_millis(raw: &str) -> Result<u64, BenchError> {
    let (days, time) = match raw.split_once('-') {
        Some((days, time)) => (
            days.parse::<u64>().map_err(|_| {
                BenchError::InvalidArguments(format!("invalid ps day field `{days}`"))
            })?,
            time,
        ),
        None => (0, raw),
    };
    let parts = time.split(':').collect::<Vec<_>>();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [minutes, seconds] => (0, parse_time_part(minutes)?, parse_seconds(seconds)?),
        [hours, minutes, seconds] => (
            parse_time_part(hours)?,
            parse_time_part(minutes)?,
            parse_seconds(seconds)?,
        ),
        _ => {
            return Err(BenchError::InvalidArguments(format!(
                "invalid ps time field `{raw}`"
            )));
        }
    };

    Ok(days * 24 * 60 * 60 * 1000 + hours * 60 * 60 * 1000 + minutes * 60 * 1000 + seconds)
}

fn parse_time_part(raw: &str) -> Result<u64, BenchError> {
    raw.parse::<u64>()
        .map_err(|_| BenchError::InvalidArguments(format!("invalid ps time component `{raw}`")))
}

fn parse_seconds(raw: &str) -> Result<u64, BenchError> {
    let (whole, fractional) = raw.split_once('.').unwrap_or((raw, ""));
    let whole = parse_time_part(whole)?;
    let mut millis = 0;
    for (index, byte) in fractional.as_bytes().iter().take(3).enumerate() {
        if !byte.is_ascii_digit() {
            return Err(BenchError::InvalidArguments(format!(
                "invalid ps second component `{raw}`"
            )));
        }
        let digit = u64::from(byte - b'0');
        millis += match index {
            0 => digit * 100,
            1 => digit * 10,
            _ => digit,
        };
    }
    Ok(whole * 1000 + millis)
}

pub fn write_result_json(path: &Path, result: &BenchResult) -> Result<(), BenchError> {
    let data = serde_json::to_vec_pretty(result).map_err(|error| {
        BenchError::InvalidArguments(format!("failed to encode result json: {error}"))
    })?;
    fs::write(path, data).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to write result json `{}`: {error}",
            path.display()
        ))
    })
}

pub fn write_samples_csv(path: &Path, samples: &[ProcessSample]) -> Result<(), BenchError> {
    let mut csv = String::from("elapsed_ms,rss_kib,cpu_millis,threads\n");
    for sample in samples {
        let threads = sample
            .threads
            .map(|threads| threads.to_string())
            .unwrap_or_default();
        csv.push_str(&format!(
            "{},{},{},{}\n",
            sample.elapsed_ms, sample.rss_kib, sample.cpu_millis, threads
        ));
    }
    fs::write(path, csv).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to write samples csv `{}`: {error}",
            path.display()
        ))
    })
}

pub fn summarize_samples(samples: &[ProcessSample]) -> WorkloadSummary {
    let peak_rss_kib = samples
        .iter()
        .map(|sample| sample.rss_kib)
        .max()
        .unwrap_or_default();
    let cpu_millis = match (samples.first(), samples.last()) {
        (Some(first), Some(last)) => last.cpu_millis.saturating_sub(first.cpu_millis),
        _ => 0,
    };
    WorkloadSummary {
        bytes_sent: 0,
        bytes_received: 0,
        peak_rss_kib,
        cpu_millis,
    }
}

pub async fn run_idle_workload(duration: Duration) -> Result<(u64, u64), BenchError> {
    sleep(duration).await;
    Ok((0, 0))
}

pub async fn run_tcp_freedom_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<(u64, u64), BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding TCP echo server".to_owned(),
            source,
        })?;
    let echo_addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading TCP echo server address".to_owned(),
        source,
    })?;
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    let mut tasks = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        let options = options.clone();
        tasks.push(tokio::spawn(async move {
            run_tcp_freedom_connection(socks_addr, echo_addr, &options).await
        }));
    }

    let mut sent = 0;
    let mut received = 0;
    for task in tasks {
        let (task_sent, task_received) = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("tcp workload task failed: {error}"))
        })??;
        sent += task_sent;
        received += task_received;
    }
    echo_task.abort();

    Ok((sent, received))
}

async fn run_tcp_freedom_connection(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<(u64, u64), BenchError> {
    let mut client = TcpStream::connect(socks_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting to SOCKS inbound at {socks_addr}"),
            source,
        })?;
    socks5_connect(&mut client, echo_addr).await?;

    let payload = vec![0x5a; options.payload_size];
    let mut echoed = vec![0; options.payload_size];
    let mut sent = 0;
    let mut received = 0;
    for _ in 0..options.iterations {
        client
            .write_all(&payload)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing benchmark payload".to_owned(),
                source,
            })?;
        sent += payload.len() as u64;
        client
            .read_exact(&mut echoed)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading benchmark echo".to_owned(),
                source,
            })?;
        if echoed != payload {
            return Err(BenchError::InvalidArguments(
                "echo payload mismatch".to_owned(),
            ));
        }
        received += echoed.len() as u64;
    }

    Ok((sent, received))
}

async fn socks5_connect(client: &mut TcpStream, target: SocketAddr) -> Result<(), BenchError> {
    let SocketAddr::V4(target) = target else {
        return Err(BenchError::InvalidArguments(
            "tcp-freedom workload currently uses IPv4 echo targets".to_owned(),
        ));
    };

    client
        .write_all(&[5, 1, 0])
        .await
        .map_err(|source| BenchError::Io {
            action: "writing SOCKS greeting".to_owned(),
            source,
        })?;
    let mut method = [0; 2];
    client
        .read_exact(&mut method)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS method".to_owned(),
            source,
        })?;
    if method != [5, 0] {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected SOCKS method response {method:?}"
        )));
    }

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client
        .write_all(&request)
        .await
        .map_err(|source| BenchError::Io {
            action: "writing SOCKS connect".to_owned(),
            source,
        })?;
    let mut reply = [0; 10];
    client
        .read_exact(&mut reply)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS connect response".to_owned(),
            source,
        })?;
    if reply[..2] != [5, 0] {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected SOCKS connect response {reply:?}"
        )));
    }

    Ok(())
}

pub async fn sample_while<F, T>(
    pid: u32,
    interval: Duration,
    future: F,
) -> Result<(T, Vec<ProcessSample>), BenchError>
where
    F: Future<Output = Result<T, BenchError>>,
{
    let start = Instant::now();
    let mut samples = Vec::new();
    samples.push(sample_process(pid, start)?);
    let mut future = Box::pin(future);
    loop {
        tokio::select! {
            result = &mut future => {
                let result = result?;
                samples.push(sample_process(pid, start)?);
                return Ok((result, samples));
            }
            () = sleep(interval) => {
                samples.push(sample_process(pid, start)?);
            }
        }
    }
}

fn sample_process(pid: u32, start: Instant) -> Result<ProcessSample, BenchError> {
    let args = ps_args(pid);
    let output = Command::new("ps")
        .args(args)
        .output()
        .map_err(|source| BenchError::Io {
            action: format!("sampling process {pid} with ps"),
            source,
        })?;
    if !output.status.success() {
        return Err(BenchError::Process {
            program: "ps".to_owned(),
            status: output.status.to_string(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let line = raw
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| BenchError::InvalidArguments(format!("ps returned no sample for {pid}")))?;
    let mut sample = parse_ps_sample(line)?;
    sample.elapsed_ms = start.elapsed().as_millis();
    Ok(sample)
}

#[cfg(target_os = "macos")]
fn ps_args(pid: u32) -> Vec<String> {
    vec![
        "-o".to_owned(),
        "rss=".to_owned(),
        "-o".to_owned(),
        "time=".to_owned(),
        "-o".to_owned(),
        "thcount=".to_owned(),
        "-p".to_owned(),
        pid.to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn ps_args(pid: u32) -> Vec<String> {
    vec![
        "-o".to_owned(),
        "rss=".to_owned(),
        "-o".to_owned(),
        "time=".to_owned(),
        "-o".to_owned(),
        "nlwp=".to_owned(),
        "-p".to_owned(),
        pid.to_string(),
    ]
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn ps_args(pid: u32) -> Vec<String> {
    vec![
        "-o".to_owned(),
        "rss=".to_owned(),
        "-o".to_owned(),
        "time=".to_owned(),
        "-p".to_owned(),
        pid.to_string(),
    ]
}

pub fn xray_rust_freedom_config(port: u16) -> String {
    freedom_config(port)
}

pub fn xray_core_freedom_config(port: u16) -> String {
    freedom_config(port)
}

fn freedom_config(port: u16) -> String {
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": {port},
      "settings": {{ "auth": "noauth", "udp": false }}
    }}
  ],
  "outbounds": [
    {{
      "tag": "direct",
      "protocol": "freedom",
      "settings": {{}}
    }}
  ]
}}"#
    )
}

pub fn allocate_loopback_port() -> Result<u16, BenchError> {
    let listener =
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|source| BenchError::Io {
            action: "binding ephemeral loopback port".to_owned(),
            source,
        })?;
    Ok(listener
        .local_addr()
        .map_err(|source| BenchError::Io {
            action: "reading ephemeral loopback port".to_owned(),
            source,
        })?
        .port())
}

pub async fn wait_for_tcp_listener(
    child: &mut Child,
    addr: SocketAddr,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<(), BenchError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().map_err(|source| BenchError::Io {
            action: "checking child process status".to_owned(),
            source,
        })? {
            return Err(BenchError::Process {
                program: "engine".to_owned(),
                status: status.to_string(),
                stdout: fs::read_to_string(stdout_path).unwrap_or_default(),
                stderr: fs::read_to_string(stderr_path).unwrap_or_default(),
            });
        }

        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) if Instant::now() < deadline => {
                sleep(Duration::from_millis(25)).await;
            }
            Err(source) => {
                return Err(BenchError::Io {
                    action: format!("waiting for TCP listener at {addr}"),
                    source,
                });
            }
        }
    }
}

pub fn ensure_xray_rust_binary(options: &BenchOptions) -> Result<PathBuf, BenchError> {
    if let Some(path) = &options.xray_rust_bin {
        return Ok(path.clone());
    }

    let root = workspace_root()?;
    let binary = root
        .join("target")
        .join("debug")
        .join(format!("xray-rust{}", std::env::consts::EXE_SUFFIX));
    if binary.exists() {
        return Ok(binary);
    }
    if options.no_auto_build {
        return Err(BenchError::InvalidArguments(format!(
            "xray-rust binary not found at `{}`",
            binary.display()
        )));
    }

    run_command(
        "cargo",
        Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("xray-cli")
            .arg("--bin")
            .arg("xray-rust")
            .current_dir(&root),
    )?;
    Ok(binary)
}

pub fn ensure_xray_core_binary(
    options: &BenchOptions,
    bin_dir: &Path,
) -> Result<PathBuf, BenchError> {
    if let Some(path) = &options.xray_core_bin {
        return Ok(path.clone());
    }
    if options.no_auto_build {
        return Err(BenchError::InvalidArguments(
            "xray-core binary requires --xray-core-bin when --no-auto-build is set".to_owned(),
        ));
    }

    let checkout = options
        .xray_core_dir
        .clone()
        .or_else(default_xray_core_dir)
        .ok_or_else(|| {
            BenchError::InvalidArguments(
                "xray-core checkout not found; pass --xray-core-dir or --xray-core-bin".to_owned(),
            )
        })?;
    fs::create_dir_all(bin_dir).map_err(|source| BenchError::Io {
        action: format!("creating binary directory `{}`", bin_dir.display()),
        source,
    })?;
    let binary = bin_dir.join(format!("xray-core{}", std::env::consts::EXE_SUFFIX));
    run_command(
        "go",
        Command::new("go")
            .arg("build")
            .arg("-o")
            .arg(&binary)
            .arg("./main")
            .current_dir(&checkout),
    )?;
    Ok(binary)
}

pub async fn start_engine(
    kind: EngineKind,
    options: &BenchOptions,
    run_dir: &Path,
) -> Result<RunningEngine, BenchError> {
    fs::create_dir_all(run_dir).map_err(|source| BenchError::Io {
        action: format!("creating run directory `{}`", run_dir.display()),
        source,
    })?;
    let port = allocate_loopback_port()?;
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config = match kind {
        EngineKind::XrayRust => xray_rust_freedom_config(port),
        EngineKind::XrayCore => xray_core_freedom_config(port),
    };
    let config_path = run_dir.join("config.json");
    fs::write(&config_path, config).map_err(|source| BenchError::Io {
        action: format!("writing config `{}`", config_path.display()),
        source,
    })?;
    let stdout_path = run_dir.join("stdout.log");
    let stderr_path = run_dir.join("stderr.log");
    let binary = match kind {
        EngineKind::XrayRust => ensure_xray_rust_binary(options)?,
        EngineKind::XrayCore => ensure_xray_core_binary(options, &run_dir.join("bin"))?,
    };
    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(fs::File::create(&stdout_path).map_err(
            |source| BenchError::Io {
                action: format!("creating stdout log `{}`", stdout_path.display()),
                source,
            },
        )?))
        .stderr(Stdio::from(fs::File::create(&stderr_path).map_err(
            |source| BenchError::Io {
                action: format!("creating stderr log `{}`", stderr_path.display()),
                source,
            },
        )?))
        .spawn()
        .map_err(|source| BenchError::Io {
            action: format!("spawning `{}`", binary.display()),
            source,
        })?;
    let pid = child.id();
    wait_for_tcp_listener(&mut child, socks_addr, &stdout_path, &stderr_path).await?;

    Ok(RunningEngine {
        kind,
        child,
        pid,
        socks_addr,
        run_dir: run_dir.to_path_buf(),
        stdout_path,
        stderr_path,
    })
}

fn run_command(program: &str, command: &mut Command) -> Result<(), BenchError> {
    let output = command.output().map_err(|source| BenchError::Io {
        action: format!("running `{program}`"),
        source,
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(BenchError::Process {
        program: program.to_owned(),
        status: output.status.to_string(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn workspace_root() -> Result<PathBuf, BenchError> {
    let mut dir = std::env::current_dir().map_err(|source| BenchError::Io {
        action: "reading current directory".to_owned(),
        source,
    })?;
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("crates").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(BenchError::InvalidArguments(
                "failed to find workspace root".to_owned(),
            ));
        }
    }
}

fn default_xray_core_dir() -> Option<PathBuf> {
    let root = workspace_root().ok()?;
    let candidates = [
        root.join("Xray-core"),
        root.parent()?.join("Xray-core"),
        root.parent()?.parent()?.join("Xray-core"),
    ];
    candidates
        .into_iter()
        .find(|path| path.join("go.mod").exists())
}

pub async fn run_cli<I, S>(args: I) -> Result<(), BenchError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let _args = parse_cli_args(args)?;
    Err(BenchError::InvalidArguments(
        "benchmark execution is not implemented yet".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn parses_run_idle_for_xray_rust() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "idle",
            "--duration-ms",
            "250",
            "--sample-interval-ms",
            "50",
            "--out-dir",
            "target/benchmarks/test",
        ])
        .unwrap();

        assert_eq!(
            args,
            CliArgs::Run(BenchOptions {
                engine: Some(EngineKind::XrayRust),
                workload: WorkloadKind::Idle,
                duration: Duration::from_millis(250),
                sample_interval: Duration::from_millis(50),
                connections: 1,
                iterations: 1,
                payload_size: 1024,
                out_dir: PathBuf::from("target/benchmarks/test"),
                xray_rust_bin: None,
                xray_core_bin: None,
                xray_core_dir: None,
                no_auto_build: false,
            })
        );
    }

    #[test]
    fn parses_compare_tcp_freedom() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "tcp-freedom",
            "--connections",
            "2",
            "--iterations",
            "3",
            "--payload-size",
            "64",
            "--xray-core-dir",
            "../Xray-core",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::TcpFreedom);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
        assert_eq!(options.xray_core_dir, Some(PathBuf::from("../Xray-core")));
    }

    #[test]
    fn parses_ps_sample_line_with_thread_count() {
        let sample = parse_ps_sample(" 12345 00:01.23 7").unwrap();
        assert_eq!(sample.rss_kib, 12345);
        assert_eq!(sample.cpu_millis, 1230);
        assert_eq!(sample.threads, Some(7));
    }

    #[test]
    fn parses_ps_time_with_hours() {
        let sample = parse_ps_sample(" 2048 01:02:03 9").unwrap();
        assert_eq!(sample.cpu_millis, 3_723_000);
    }

    #[test]
    fn xray_rust_freedom_config_uses_requested_socks_port() {
        let config = xray_rust_freedom_config(18080);
        assert!(config.contains(r#""protocol": "socks""#));
        assert!(config.contains(r#""port": 18080"#));
        assert!(config.contains(r#""protocol": "freedom""#));
    }

    #[test]
    fn xray_core_freedom_config_uses_requested_socks_port() {
        let config = xray_core_freedom_config(18081);
        assert!(config.contains(r#""protocol": "socks""#));
        assert!(config.contains(r#""port": 18081"#));
        assert!(config.contains(r#""protocol": "freedom""#));
    }

    #[test]
    fn summarizes_samples_with_peak_rss_and_cpu_delta() {
        let samples = vec![
            ProcessSample {
                elapsed_ms: 0,
                rss_kib: 100,
                cpu_millis: 10,
                threads: Some(2),
            },
            ProcessSample {
                elapsed_ms: 10,
                rss_kib: 150,
                cpu_millis: 25,
                threads: Some(2),
            },
        ];
        let summary = summarize_samples(&samples);
        assert_eq!(summary.peak_rss_kib, 150);
        assert_eq!(summary.cpu_millis, 15);
    }
}
