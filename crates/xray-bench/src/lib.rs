use std::collections::VecDeque;
use std::fs;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
#[cfg(unix)]
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(unix)]
use smoltcp::iface::{
    Config as SmolInterfaceConfig, Interface as SmolInterface, SocketHandle, SocketSet,
};
#[cfg(unix)]
use smoltcp::phy::{
    ChecksumCapabilities as SmolChecksumCapabilities, Device as SmolDevice,
    DeviceCapabilities as SmolDeviceCapabilities, Medium as SmolMedium, RxToken as SmolRxToken,
    TxToken as SmolTxToken,
};
#[cfg(unix)]
use smoltcp::socket::tcp as smol_tcp;
#[cfg(unix)]
use smoltcp::time::Instant as SmolInstant;
#[cfg(unix)]
use smoltcp::wire::{
    HardwareAddress as SmolHardwareAddress, IpAddress as SmolIpAddress, IpCidr as SmolIpCidr,
    Ipv4Address as SmolIpv4Address,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, read_udp_packet, read_xudp_packet,
    unpad_vision_block, VisionCommand, VisionPadding,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};

const USAGE: &str = "usage: xray-bench run|compare [options]";
const TEST_VLESS_UUID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const UDP_PROTOCOL: u8 = 17;
const DARWIN_UTUN_HEADER_LEN: usize = 4;

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
    #[error("benchmark run timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u128 },
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
    fn as_str(&self) -> &'static str {
        match self {
            Self::XrayRust => "xray-rust",
            Self::XrayCore => "xray-core",
        }
    }

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
    ManyIdleFlows,
    ReconnectBurst,
    MixedLongLived,
    UdpFreedom,
    TunUdpFreedom,
    TunTcpFreedom,
    UdpVless,
    UdpXudp,
    VisionXudp,
}

impl WorkloadKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::TcpFreedom => "tcp-freedom",
            Self::ManyIdleFlows => "many-idle-flows",
            Self::ReconnectBurst => "reconnect-burst",
            Self::MixedLongLived => "mixed-long-lived",
            Self::UdpFreedom => "udp-freedom",
            Self::TunUdpFreedom => "tun-udp-freedom",
            Self::TunTcpFreedom => "tun-tcp-freedom",
            Self::UdpVless => "udp-vless",
            Self::UdpXudp => "udp-xudp",
            Self::VisionXudp => "vision-xudp",
        }
    }

    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "idle" => Ok(Self::Idle),
            "tcp-freedom" => Ok(Self::TcpFreedom),
            "many-idle-flows" => Ok(Self::ManyIdleFlows),
            "reconnect-burst" => Ok(Self::ReconnectBurst),
            "mixed-long-lived" => Ok(Self::MixedLongLived),
            "udp-freedom" => Ok(Self::UdpFreedom),
            "tun-udp-freedom" => Ok(Self::TunUdpFreedom),
            "tun-tcp-freedom" => Ok(Self::TunTcpFreedom),
            "udp-vless" => Ok(Self::UdpVless),
            "udp-xudp" => Ok(Self::UdpXudp),
            "vision-xudp" => Ok(Self::VisionXudp),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported workload `{other}`"
            ))),
        }
    }

    fn uses_tun_fd(&self) -> bool {
        matches!(self, Self::TunUdpFreedom | Self::TunTcpFreedom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchOptions {
    pub engine: Option<EngineKind>,
    pub workload: WorkloadKind,
    pub duration: Duration,
    pub sample_interval: Duration,
    pub run_timeout: Duration,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    pub runs: usize,
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
    pub cpu_millis_per_gib: Option<u128>,
    pub latency_us: Option<LatencySummary>,
    pub setup_us: Option<FlowSetupSummary>,
    pub samples: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MetricSummary {
    pub min: u128,
    pub median: u128,
    pub p95: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LatencySummary {
    pub min: u128,
    pub median: u128,
    pub p95: u128,
    pub p99: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LatencySummaryAggregate {
    pub min: MetricSummary,
    pub median: MetricSummary,
    pub p95: MetricSummary,
    pub p99: MetricSummary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlowSetupSample {
    pub tcp_connect_us: u128,
    pub socks_setup_us: u128,
    pub total_us: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlowSetupSummary {
    pub tcp_connect_us: LatencySummary,
    pub socks_setup_us: LatencySummary,
    pub total_us: LatencySummary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlowSetupSummaryAggregate {
    pub tcp_connect_us: LatencySummaryAggregate,
    pub socks_setup_us: LatencySummaryAggregate,
    pub total_us: LatencySummaryAggregate,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BenchSummary {
    pub engine: String,
    pub workload: String,
    pub status: String,
    pub runs: usize,
    pub duration_ms: MetricSummary,
    pub peak_rss_kib: MetricSummary,
    pub cpu_millis: MetricSummary,
    pub cpu_millis_per_gib: Option<MetricSummary>,
    pub latency_us: Option<LatencySummaryAggregate>,
    pub setup_us: Option<FlowSetupSummaryAggregate>,
    pub bytes_sent: MetricSummary,
    pub bytes_received: MetricSummary,
    pub results: Vec<BenchResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadSummary {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub peak_rss_kib: u64,
    pub cpu_millis: u64,
}

#[derive(Debug, Default)]
pub struct WorkloadOutcome {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latencies_us: Vec<u128>,
    pub setup_samples: Vec<FlowSetupSample>,
}

impl WorkloadOutcome {
    fn empty() -> Self {
        Self::default()
    }

    fn extend(&mut self, other: Self) {
        self.bytes_sent += other.bytes_sent;
        self.bytes_received += other.bytes_received;
        self.latencies_us.extend(other.latencies_us);
        self.setup_samples.extend(other.setup_samples);
    }
}

#[derive(Debug)]
pub struct RunningEngine {
    pub kind: EngineKind,
    child: Child,
    pub pid: u32,
    pub socks_addr: SocketAddr,
    tun_fd: Option<FdGuard>,
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

impl RunningEngine {
    #[cfg(unix)]
    fn tun_fd(&self) -> Result<RawFd, BenchError> {
        self.tun_fd
            .as_ref()
            .map(FdGuard::raw)
            .ok_or_else(|| BenchError::InvalidArguments("engine has no TUN workload fd".to_owned()))
    }

    #[cfg(not(unix))]
    fn tun_fd(&self) -> Result<i32, BenchError> {
        Err(BenchError::InvalidArguments(
            "tun-udp-freedom workload requires Unix fd support".to_owned(),
        ))
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct FdGuard {
    fd: RawFd,
}

#[cfg(unix)]
impl FdGuard {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    fn raw(&self) -> RawFd {
        self.fd
    }
}

#[cfg(unix)]
impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

#[cfg(not(unix))]
#[derive(Debug)]
struct FdGuard;

#[cfg(unix)]
#[derive(Debug)]
struct TunSocketPair {
    engine_fd: FdGuard,
    workload_fd: FdGuard,
}

#[cfg(unix)]
impl TunSocketPair {
    fn into_workload_fd(self) -> FdGuard {
        self.workload_fd
    }
}

#[cfg(not(unix))]
#[derive(Debug)]
struct TunSocketPair;

#[derive(Debug, Default)]
struct WorkloadFixture {
    vless_addr: Option<SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
}

impl WorkloadFixture {
    async fn start(workload: WorkloadKind) -> Result<Self, BenchError> {
        match workload {
            WorkloadKind::UdpVless => {
                let (vless_addr, task) =
                    spawn_fake_vless_udp_server(VlessUdpServerMode::Udp).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    tasks: vec![task],
                })
            }
            WorkloadKind::UdpXudp => {
                let (vless_addr, task) =
                    spawn_fake_vless_udp_server(VlessUdpServerMode::Xudp).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    tasks: vec![task],
                })
            }
            WorkloadKind::VisionXudp => {
                let (vless_addr, task) =
                    spawn_fake_vless_udp_server(VlessUdpServerMode::VisionXudp).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    tasks: vec![task],
                })
            }
            WorkloadKind::Idle
            | WorkloadKind::TcpFreedom
            | WorkloadKind::ManyIdleFlows
            | WorkloadKind::ReconnectBurst
            | WorkloadKind::MixedLongLived
            | WorkloadKind::UdpFreedom
            | WorkloadKind::TunUdpFreedom
            | WorkloadKind::TunTcpFreedom => Ok(Self::default()),
        }
    }
}

impl Drop for WorkloadFixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VlessUdpServerMode {
    Udp,
    Xudp,
    VisionXudp,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            engine: None,
            workload: WorkloadKind::Idle,
            duration: Duration::from_secs(2),
            sample_interval: Duration::from_millis(100),
            run_timeout: Duration::from_secs(30),
            connections: 1,
            iterations: 1,
            payload_size: 1024,
            runs: 1,
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
            "--run-timeout-ms" => {
                options.run_timeout = Duration::from_millis(parse_nonzero_u64(
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
            "--runs" => {
                options.runs = parse_nonzero_usize(required_value(&rest, &mut index, flag)?, flag)?;
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

fn parse_nonzero_u64(raw: &str, flag: &str) -> Result<u64, BenchError> {
    let value = parse_u64(raw, flag)?;
    if value == 0 {
        return Err(BenchError::InvalidArguments(format!(
            "{flag} must be greater than zero"
        )));
    }
    Ok(value)
}

fn parse_usize(raw: &str, flag: &str) -> Result<usize, BenchError> {
    raw.parse::<usize>()
        .map_err(|_| BenchError::InvalidArguments(format!("invalid integer `{raw}` for {flag}")))
}

fn parse_nonzero_usize(raw: &str, flag: &str) -> Result<usize, BenchError> {
    let value = parse_usize(raw, flag)?;
    if value == 0 {
        return Err(BenchError::InvalidArguments(format!(
            "{flag} must be greater than zero"
        )));
    }
    Ok(value)
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

pub fn write_summary_json(path: &Path, summary: &BenchSummary) -> Result<(), BenchError> {
    let data = serde_json::to_vec_pretty(summary).map_err(|error| {
        BenchError::InvalidArguments(format!("failed to encode summary json: {error}"))
    })?;
    fs::write(path, data).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to write summary json `{}`: {error}",
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

pub fn summarize_results(results: &[BenchResult]) -> Result<BenchSummary, BenchError> {
    let Some(first) = results.first() else {
        return Err(BenchError::InvalidArguments(
            "cannot summarize an empty benchmark result set".to_owned(),
        ));
    };
    if results
        .iter()
        .any(|result| result.engine != first.engine || result.workload != first.workload)
    {
        return Err(BenchError::InvalidArguments(
            "cannot summarize mixed benchmark engines or workloads".to_owned(),
        ));
    }

    let status = if results.iter().all(|result| result.status == "ok") {
        "ok"
    } else {
        "mixed"
    };

    Ok(BenchSummary {
        engine: first.engine.clone(),
        workload: first.workload.clone(),
        status: status.to_owned(),
        runs: results.len(),
        duration_ms: summarize_metric(results.iter().map(|result| result.duration_ms)),
        peak_rss_kib: summarize_metric(
            results.iter().map(|result| u128::from(result.peak_rss_kib)),
        ),
        cpu_millis: summarize_metric(results.iter().map(|result| u128::from(result.cpu_millis))),
        cpu_millis_per_gib: summarize_optional_metric(
            results.iter().map(|result| result.cpu_millis_per_gib),
        ),
        latency_us: summarize_latency_results(results),
        setup_us: summarize_setup_results(results),
        bytes_sent: summarize_metric(results.iter().map(|result| u128::from(result.bytes_sent))),
        bytes_received: summarize_metric(
            results
                .iter()
                .map(|result| u128::from(result.bytes_received)),
        ),
        results: results.to_vec(),
    })
}

pub fn summarize_latency_us(values: impl IntoIterator<Item = u128>) -> Option<LatencySummary> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(LatencySummary {
        min: values.first().copied().unwrap_or_default(),
        median: median(&values),
        p95: percentile_nearest_rank(&values, 95),
        p99: percentile_nearest_rank(&values, 99),
    })
}

pub fn summarize_flow_setup_us(
    samples: impl IntoIterator<Item = FlowSetupSample>,
) -> Option<FlowSetupSummary> {
    let samples = samples.into_iter().collect::<Vec<_>>();
    if samples.is_empty() {
        return None;
    }

    Some(FlowSetupSummary {
        tcp_connect_us: summarize_latency_us(samples.iter().map(|sample| sample.tcp_connect_us))?,
        socks_setup_us: summarize_latency_us(samples.iter().map(|sample| sample.socks_setup_us))?,
        total_us: summarize_latency_us(samples.iter().map(|sample| sample.total_us))?,
    })
}

fn summarize_optional_metric(
    values: impl IntoIterator<Item = Option<u128>>,
) -> Option<MetricSummary> {
    let values = values.into_iter().flatten().collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    Some(summarize_metric(values))
}

fn summarize_latency_aggregates<'a>(
    latencies: impl IntoIterator<Item = &'a LatencySummary>,
) -> LatencySummaryAggregate {
    let latencies = latencies.into_iter().collect::<Vec<_>>();
    LatencySummaryAggregate {
        min: summarize_metric(latencies.iter().map(|latency| latency.min)),
        median: summarize_metric(latencies.iter().map(|latency| latency.median)),
        p95: summarize_metric(latencies.iter().map(|latency| latency.p95)),
        p99: summarize_metric(latencies.iter().map(|latency| latency.p99)),
    }
}

fn summarize_latency_results(results: &[BenchResult]) -> Option<LatencySummaryAggregate> {
    let latencies = results
        .iter()
        .filter_map(|result| result.latency_us.as_ref())
        .collect::<Vec<_>>();
    if latencies.is_empty() {
        return None;
    }

    Some(summarize_latency_aggregates(latencies))
}

fn summarize_setup_results(results: &[BenchResult]) -> Option<FlowSetupSummaryAggregate> {
    let setup = results
        .iter()
        .filter_map(|result| result.setup_us.as_ref())
        .collect::<Vec<_>>();
    if setup.is_empty() {
        return None;
    }

    Some(FlowSetupSummaryAggregate {
        tcp_connect_us: summarize_latency_aggregates(
            setup.iter().map(|summary| &summary.tcp_connect_us),
        ),
        socks_setup_us: summarize_latency_aggregates(
            setup.iter().map(|summary| &summary.socks_setup_us),
        ),
        total_us: summarize_latency_aggregates(setup.iter().map(|summary| &summary.total_us)),
    })
}

fn summarize_metric(values: impl IntoIterator<Item = u128>) -> MetricSummary {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    MetricSummary {
        min: values.first().copied().unwrap_or_default(),
        median: median(&values),
        p95: percentile_nearest_rank(&values, 95),
    }
}

fn median(sorted_values: &[u128]) -> u128 {
    match sorted_values.len() {
        0 => 0,
        len if len % 2 == 1 => sorted_values[len / 2],
        len => (sorted_values[len / 2 - 1] + sorted_values[len / 2]) / 2,
    }
}

fn percentile_nearest_rank(sorted_values: &[u128], percentile: usize) -> u128 {
    if sorted_values.is_empty() {
        return 0;
    }
    let rank = (sorted_values.len() * percentile).div_ceil(100);
    sorted_values[rank.saturating_sub(1)]
}

fn cpu_millis_per_gib(cpu_millis: u64, bytes_sent: u64, bytes_received: u64) -> Option<u128> {
    let bytes = u128::from(bytes_sent) + u128::from(bytes_received);
    if bytes == 0 {
        return None;
    }
    Some((u128::from(cpu_millis) * 1024 * 1024 * 1024).div_ceil(bytes))
}

pub async fn run_idle_workload(duration: Duration) -> Result<WorkloadOutcome, BenchError> {
    sleep(duration).await;
    Ok(WorkloadOutcome::empty())
}

pub async fn run_tcp_freedom_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
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

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("tcp workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }
    echo_task.abort();

    Ok(outcome)
}

pub async fn run_many_idle_flows_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding idle-flow TCP target".to_owned(),
            source,
        })?;
    let target_addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading idle-flow TCP target address".to_owned(),
        source,
    })?;
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut byte = [0; 1];
                let _ = stream.read(&mut byte).await;
            });
        }
    });

    let mut tasks = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        tasks.push(tokio::spawn(async move {
            open_idle_socks_flow(socks_addr, target_addr).await
        }));
    }

    let mut held_flows = Vec::with_capacity(options.connections);
    let mut latencies_us = Vec::with_capacity(options.connections);
    let mut setup_samples = Vec::with_capacity(options.connections);
    for task in tasks {
        let (stream, setup_sample) = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("idle-flow workload task failed: {error}"))
        })??;
        held_flows.push(stream);
        latencies_us.push(setup_sample.total_us);
        setup_samples.push(setup_sample);
    }

    sleep(options.duration).await;
    drop(held_flows);
    accept_task.abort();

    Ok(WorkloadOutcome {
        bytes_sent: 0,
        bytes_received: 0,
        latencies_us,
        setup_samples,
    })
}

pub async fn run_reconnect_burst_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding reconnect-burst TCP target".to_owned(),
            source,
        })?;
    let target_addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading reconnect-burst TCP target address".to_owned(),
        source,
    })?;
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut byte = [0; 1];
                let _ = stream.read(&mut byte).await;
            });
        }
    });

    let mut tasks = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        let options = options.clone();
        tasks.push(tokio::spawn(async move {
            let mut outcome = WorkloadOutcome::empty();
            for _ in 0..options.iterations {
                let (stream, setup_sample) = open_idle_socks_flow(socks_addr, target_addr).await?;
                drop(stream);
                outcome.latencies_us.push(setup_sample.total_us);
                outcome.setup_samples.push(setup_sample);
            }
            Ok::<_, BenchError>(outcome)
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("reconnect-burst workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }
    accept_task.abort();

    Ok(outcome)
}

pub async fn run_mixed_long_lived_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding mixed TCP echo server".to_owned(),
            source,
        })?;
    let tcp_echo_addr = tcp_listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading mixed TCP echo server address".to_owned(),
        source,
    })?;
    let tcp_echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = tcp_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding mixed UDP echo server".to_owned(),
            source,
        })?;
    let udp_echo_addr = udp_socket.local_addr().map_err(|source| BenchError::Io {
        action: "reading mixed UDP echo server address".to_owned(),
        source,
    })?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((len, peer)) = udp_socket.recv_from(&mut buffer).await {
            let _ = udp_socket.send_to(&buffer[..len], peer).await;
        }
    });

    let (tcp_connections, udp_connections) = mixed_connection_counts(options.connections);
    let mut tasks = Vec::with_capacity(tcp_connections + udp_connections);
    for _ in 0..tcp_connections {
        let options = options.clone();
        tasks.push(tokio::spawn(async move {
            run_mixed_long_lived_tcp_connection(socks_addr, tcp_echo_addr, &options).await
        }));
    }
    for _ in 0..udp_connections {
        let options = options.clone();
        tasks.push(tokio::spawn(async move {
            run_mixed_long_lived_udp_connection(socks_addr, udp_echo_addr, &options).await
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("mixed workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }
    tcp_echo_task.abort();
    udp_echo_task.abort();

    Ok(outcome)
}

pub async fn run_udp_freedom_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding UDP echo server".to_owned(),
            source,
        })?;
    let echo_addr = echo_socket.local_addr().map_err(|source| BenchError::Io {
        action: "reading UDP echo server address".to_owned(),
        source,
    })?;
    let echo_task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((len, peer)) = echo_socket.recv_from(&mut buffer).await {
            let _ = echo_socket.send_to(&buffer[..len], peer).await;
        }
    });

    let mut tasks = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        let options = options.clone();
        tasks.push(tokio::spawn(async move {
            run_udp_freedom_connection(socks_addr, echo_addr, &options).await
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("udp workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }
    echo_task.abort();

    Ok(outcome)
}

#[cfg(unix)]
pub async fn run_tun_udp_freedom_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let echo_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding TUN UDP echo server".to_owned(),
            source,
        })?;
    let echo_bind_addr = echo_socket.local_addr().map_err(|source| BenchError::Io {
        action: "reading TUN UDP echo server address".to_owned(),
        source,
    })?;
    let echo_target = SocketAddr::from((local_non_loopback_ipv4()?, echo_bind_addr.port()));
    let echo_task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((len, peer)) = echo_socket.recv_from(&mut buffer).await {
            let _ = echo_socket.send_to(&buffer[..len], peer).await;
        }
    });

    let mut outcome = WorkloadOutcome::empty();
    for connection_index in 0..options.connections {
        let source_port = 40_000 + (connection_index % 20_000) as u16;
        let connection_outcome =
            run_tun_udp_freedom_connection(tun_fd, echo_target, source_port, options).await?;
        outcome.extend(connection_outcome);
    }
    echo_task.abort();

    Ok(outcome)
}

#[cfg(unix)]
pub async fn run_tun_tcp_freedom_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding TUN TCP echo server".to_owned(),
            source,
        })?;
    let echo_bind_addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading TUN TCP echo server address".to_owned(),
        source,
    })?;
    let echo_target = SocketAddr::from((local_non_loopback_ipv4()?, echo_bind_addr.port()));
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

    let mut outcome = WorkloadOutcome::empty();
    for connection_index in 0..options.connections {
        let source_port = 49_152 + (connection_index % 10_000) as u16;
        let connection_outcome =
            run_tun_tcp_freedom_connection(tun_fd, echo_target, source_port, options).await?;
        outcome.extend(connection_outcome);
    }
    echo_task.abort();

    Ok(outcome)
}

#[cfg(not(unix))]
pub async fn run_tun_udp_freedom_workload(
    _tun_fd: i32,
    _options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-udp-freedom workload requires Unix fd support".to_owned(),
    ))
}

#[cfg(not(unix))]
pub async fn run_tun_tcp_freedom_workload(
    _tun_fd: i32,
    _options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-tcp-freedom workload requires Unix fd support".to_owned(),
    ))
}

pub async fn run_udp_vless_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let echo_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    let mut tasks = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        let options = options.clone();
        tasks.push(tokio::spawn(async move {
            run_udp_freedom_connection(socks_addr, echo_addr, &options).await
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("udp vless workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }

    Ok(outcome)
}

pub async fn run_udp_xudp_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let echo_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let mut tasks = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        let options = options.clone();
        tasks.push(tokio::spawn(async move {
            run_udp_freedom_connection(socks_addr, echo_addr, &options).await
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("udp xudp workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }

    Ok(outcome)
}

pub async fn run_vision_xudp_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    run_udp_xudp_workload(socks_addr, options).await
}

async fn run_tcp_freedom_connection(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
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
    let mut latencies_us = Vec::with_capacity(options.iterations);
    for _ in 0..options.iterations {
        let started = Instant::now();
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
        latencies_us.push(started.elapsed().as_micros());
    }

    Ok(WorkloadOutcome {
        bytes_sent: sent,
        bytes_received: received,
        latencies_us,
        setup_samples: Vec::new(),
    })
}

fn mixed_connection_counts(connections: usize) -> (usize, usize) {
    let total = connections.max(2);
    let tcp = total.div_ceil(2);
    let udp = total - tcp;
    (tcp, udp.max(1))
}

fn workload_pace(duration: Duration, iterations: usize) -> Option<Duration> {
    if iterations <= 1 || duration.is_zero() {
        return None;
    }
    Some(duration / iterations as u32)
}

async fn maybe_sleep_pace(pace: Option<Duration>) {
    if let Some(pace) = pace.filter(|pace| !pace.is_zero()) {
        sleep(pace).await;
    }
}

async fn run_mixed_long_lived_tcp_connection(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let (mut client, setup_sample) = open_idle_socks_flow(socks_addr, echo_addr).await?;
    let payload = vec![0x5a; options.payload_size];
    let mut echoed = vec![0; options.payload_size];
    let mut outcome = WorkloadOutcome::empty();
    outcome.latencies_us.push(setup_sample.total_us);
    outcome.setup_samples.push(setup_sample);
    let pace = workload_pace(options.duration, options.iterations);

    for _ in 0..options.iterations {
        let started = Instant::now();
        client
            .write_all(&payload)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing mixed TCP payload".to_owned(),
                source,
            })?;
        outcome.bytes_sent += payload.len() as u64;
        client
            .read_exact(&mut echoed)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading mixed TCP echo".to_owned(),
                source,
            })?;
        if echoed != payload {
            return Err(BenchError::InvalidArguments(
                "mixed TCP echo payload mismatch".to_owned(),
            ));
        }
        outcome.bytes_received += echoed.len() as u64;
        outcome.latencies_us.push(started.elapsed().as_micros());
        maybe_sleep_pace(pace).await;
    }

    Ok(outcome)
}

async fn run_mixed_long_lived_udp_connection(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let mut control = TcpStream::connect(socks_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting to SOCKS inbound at {socks_addr}"),
            source,
        })?;
    let relay_addr = socks5_udp_associate(&mut control).await?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding mixed UDP benchmark client".to_owned(),
            source,
        })?;
    let payload = vec![0x5a; options.payload_size];
    let request = encode_socks5_udp_datagram(echo_addr, &payload)?;
    let mut response = vec![0; request.len() + 64];
    let pace = workload_pace(options.duration, options.iterations);
    let mut outcome = WorkloadOutcome::empty();

    for _ in 0..options.iterations {
        let started = Instant::now();
        socket
            .send_to(&request, relay_addr)
            .await
            .map_err(|source| BenchError::Io {
                action: "sending mixed UDP benchmark payload".to_owned(),
                source,
            })?;
        outcome.bytes_sent += payload.len() as u64;
        let (len, _) = socket
            .recv_from(&mut response)
            .await
            .map_err(|source| BenchError::Io {
                action: "receiving mixed UDP benchmark echo".to_owned(),
                source,
            })?;
        let echoed = decode_socks5_udp_payload(&response[..len])?;
        if echoed != payload {
            return Err(BenchError::InvalidArguments(
                "mixed UDP echo payload mismatch".to_owned(),
            ));
        }
        outcome.bytes_received += echoed.len() as u64;
        outcome.latencies_us.push(started.elapsed().as_micros());
        maybe_sleep_pace(pace).await;
    }

    drop(control);
    Ok(outcome)
}

async fn open_idle_socks_flow(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) -> Result<(TcpStream, FlowSetupSample), BenchError> {
    let started = Instant::now();
    let tcp_started = Instant::now();
    let mut client = TcpStream::connect(socks_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting to SOCKS inbound at {socks_addr}"),
            source,
        })?;
    let tcp_connect_us = tcp_started.elapsed().as_micros();
    let socks_started = Instant::now();
    socks5_connect(&mut client, target_addr).await?;
    Ok((
        client,
        FlowSetupSample {
            tcp_connect_us,
            socks_setup_us: socks_started.elapsed().as_micros(),
            total_us: started.elapsed().as_micros(),
        },
    ))
}

async fn run_udp_freedom_connection(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let mut control = TcpStream::connect(socks_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting to SOCKS inbound at {socks_addr}"),
            source,
        })?;
    let relay_addr = socks5_udp_associate(&mut control).await?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding UDP benchmark client".to_owned(),
            source,
        })?;
    let payload = vec![0x5a; options.payload_size];
    let request = encode_socks5_udp_datagram(echo_addr, &payload)?;
    let mut response = vec![0; request.len() + 64];
    let mut sent = 0;
    let mut received = 0;
    let mut latencies_us = Vec::with_capacity(options.iterations);

    for _ in 0..options.iterations {
        let started = Instant::now();
        socket
            .send_to(&request, relay_addr)
            .await
            .map_err(|source| BenchError::Io {
                action: "sending SOCKS UDP benchmark payload".to_owned(),
                source,
            })?;
        sent += payload.len() as u64;
        let (len, _) = socket
            .recv_from(&mut response)
            .await
            .map_err(|source| BenchError::Io {
                action: "receiving SOCKS UDP benchmark echo".to_owned(),
                source,
            })?;
        let echoed = decode_socks5_udp_payload(&response[..len])?;
        if echoed != payload {
            return Err(BenchError::InvalidArguments(
                "udp echo payload mismatch".to_owned(),
            ));
        }
        received += echoed.len() as u64;
        latencies_us.push(started.elapsed().as_micros());
    }

    drop(control);
    Ok(WorkloadOutcome {
        bytes_sent: sent,
        bytes_received: received,
        latencies_us,
        setup_samples: Vec::new(),
    })
}

#[cfg(unix)]
async fn run_tun_udp_freedom_connection(
    tun_fd: RawFd,
    echo_addr: SocketAddr,
    source_port: u16,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let SocketAddr::V4(echo_addr) = echo_addr else {
        return Err(BenchError::InvalidArguments(
            "tun-udp-freedom workload currently uses IPv4 echo targets".to_owned(),
        ));
    };
    let source_ip = Ipv4Addr::new(10, 10, 0, 2);
    let payload = vec![0x5a; options.payload_size];
    let mut sent = 0;
    let mut received = 0;
    let mut latencies_us = Vec::with_capacity(options.iterations);

    for _ in 0..options.iterations {
        let packet = ipv4_udp_packet(
            source_ip,
            source_port,
            *echo_addr.ip(),
            echo_addr.port(),
            &payload,
        )?;
        let frame = encode_darwin_utun_frame(&packet);
        let started = Instant::now();
        write_tun_frame(tun_fd, &frame)?;
        sent += payload.len() as u64;
        let echoed = read_tun_udp_echo(
            tun_fd,
            *echo_addr.ip(),
            echo_addr.port(),
            source_ip,
            source_port,
            &payload,
        )
        .await?;
        received += echoed.len() as u64;
        latencies_us.push(started.elapsed().as_micros());
    }

    Ok(WorkloadOutcome {
        bytes_sent: sent,
        bytes_received: received,
        latencies_us,
        setup_samples: Vec::new(),
    })
}

#[cfg(unix)]
async fn run_tun_tcp_freedom_connection(
    tun_fd: RawFd,
    echo_addr: SocketAddr,
    source_port: u16,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let mut client = TunTcpBenchmarkClient::new(source_port);
    let setup_started = Instant::now();
    client.connect(echo_addr)?;
    pump_tun_tcp_until(tun_fd, &mut client, TunTcpBenchmarkClient::may_send).await?;
    let setup_us = setup_started.elapsed().as_micros();

    let payload = vec![0x5a; options.payload_size];
    let mut outcome = WorkloadOutcome::empty();
    outcome.latencies_us.push(setup_us);

    for _ in 0..options.iterations {
        client.send_payload(&payload)?;
        let mut received = Vec::with_capacity(payload.len());
        let started = Instant::now();
        pump_tun_tcp_until(tun_fd, &mut client, |client| {
            received.extend_from_slice(&client.recv_available());
            received.len() >= payload.len()
        })
        .await?;
        if received != payload {
            return Err(BenchError::InvalidArguments(
                "TUN TCP echo payload mismatch".to_owned(),
            ));
        }
        outcome.bytes_sent += payload.len() as u64;
        outcome.bytes_received += received.len() as u64;
        outcome.latencies_us.push(started.elapsed().as_micros());
    }

    Ok(outcome)
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

async fn socks5_udp_associate(client: &mut TcpStream) -> Result<SocketAddr, BenchError> {
    client
        .write_all(&[5, 1, 0])
        .await
        .map_err(|source| BenchError::Io {
            action: "writing SOCKS UDP greeting".to_owned(),
            source,
        })?;
    let mut method = [0; 2];
    client
        .read_exact(&mut method)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS UDP method".to_owned(),
            source,
        })?;
    if method != [5, 0] {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected SOCKS UDP method response {method:?}"
        )));
    }

    client
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|source| BenchError::Io {
            action: "writing SOCKS UDP associate".to_owned(),
            source,
        })?;
    let mut head = [0; 4];
    client
        .read_exact(&mut head)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS UDP associate response".to_owned(),
            source,
        })?;
    if head[..3] != [5, 0, 0] {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected SOCKS UDP associate response header {head:?}"
        )));
    }
    match head[3] {
        1 => {
            let mut rest = [0; 6];
            client
                .read_exact(&mut rest)
                .await
                .map_err(|source| BenchError::Io {
                    action: "reading SOCKS UDP IPv4 bind".to_owned(),
                    source,
                })?;
            Ok(SocketAddr::from((
                Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]),
                u16::from_be_bytes([rest[4], rest[5]]),
            )))
        }
        other => Err(BenchError::InvalidArguments(format!(
            "unsupported SOCKS UDP bind address type {other}"
        ))),
    }
}

fn encode_socks5_udp_datagram(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, BenchError> {
    let SocketAddr::V4(target) = target else {
        return Err(BenchError::InvalidArguments(
            "udp-freedom workload currently uses IPv4 echo targets".to_owned(),
        ));
    };
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&target.ip().octets());
    datagram.extend_from_slice(&target.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

fn decode_socks5_udp_payload(datagram: &[u8]) -> Result<&[u8], BenchError> {
    if datagram.len() < 10 {
        return Err(BenchError::InvalidArguments(
            "truncated SOCKS UDP response".to_owned(),
        ));
    }
    if datagram[..4] != [0, 0, 0, 1] {
        return Err(BenchError::InvalidArguments(
            "unexpected SOCKS UDP response header".to_owned(),
        ));
    }
    Ok(&datagram[10..])
}

#[cfg(unix)]
async fn read_tun_udp_echo(
    tun_fd: RawFd,
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    expected_payload: &[u8],
) -> Result<Vec<u8>, BenchError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buffer = vec![0; 65_535 + DARWIN_UTUN_HEADER_LEN];
    loop {
        match read_tun_frame(tun_fd, &mut buffer)? {
            Some(len) => {
                let packet = decode_darwin_utun_frame(&buffer[..len])?;
                if let Some(datagram) = parse_ipv4_udp_datagram(packet) {
                    if datagram.source == source
                        && datagram.source_port == source_port
                        && datagram.destination == destination
                        && datagram.destination_port == destination_port
                        && datagram.payload == expected_payload
                    {
                        return Ok(datagram.payload.to_vec());
                    }
                }
            }
            None if Instant::now() < deadline => {
                sleep(Duration::from_millis(1)).await;
            }
            None => {
                return Err(BenchError::InvalidArguments(
                    "timed out waiting for TUN UDP echo".to_owned(),
                ));
            }
        }
    }
}

#[cfg(unix)]
fn write_tun_frame(fd: RawFd, frame: &[u8]) -> Result<(), BenchError> {
    let written = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
    if written < 0 {
        return Err(BenchError::Io {
            action: "writing benchmark TUN frame".to_owned(),
            source: io::Error::last_os_error(),
        });
    }
    if written as usize != frame.len() {
        return Err(BenchError::InvalidArguments(format!(
            "short TUN frame write: wrote {written} of {} bytes",
            frame.len()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn read_tun_frame(fd: RawFd, buffer: &mut [u8]) -> Result<Option<usize>, BenchError> {
    let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if read < 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::WouldBlock || source.kind() == io::ErrorKind::Interrupted
        {
            return Ok(None);
        }
        return Err(BenchError::Io {
            action: "reading benchmark TUN frame".to_owned(),
            source,
        });
    }
    if read == 0 {
        return Err(BenchError::InvalidArguments(
            "benchmark TUN fd reached EOF".to_owned(),
        ));
    }
    Ok(Some(read as usize))
}

#[cfg(unix)]
fn encode_darwin_utun_frame(packet: &[u8]) -> Vec<u8> {
    let family = match packet.first().map(|byte| byte >> 4) {
        Some(6) => libc::AF_INET6,
        _ => libc::AF_INET,
    };
    let mut frame = Vec::with_capacity(DARWIN_UTUN_HEADER_LEN + packet.len());
    frame.extend_from_slice(&[0, 0, 0, family as u8]);
    frame.extend_from_slice(packet);
    frame
}

#[cfg(unix)]
fn decode_darwin_utun_frame(frame: &[u8]) -> Result<&[u8], BenchError> {
    if frame.len() <= DARWIN_UTUN_HEADER_LEN {
        return Err(BenchError::InvalidArguments(
            "truncated Darwin utun frame".to_owned(),
        ));
    }
    Ok(&frame[DARWIN_UTUN_HEADER_LEN..])
}

#[cfg(unix)]
fn local_non_loopback_ipv4() -> Result<Ipv4Addr, BenchError> {
    let socket =
        std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|source| BenchError::Io {
            action: "binding IPv4 probe socket".to_owned(),
            source,
        })?;
    socket
        .connect((Ipv4Addr::new(8, 8, 8, 8), 80))
        .map_err(|source| BenchError::Io {
            action: "probing local non-loopback IPv4 address".to_owned(),
            source,
        })?;
    let SocketAddr::V4(addr) = socket.local_addr().map_err(|source| BenchError::Io {
        action: "reading local IPv4 probe address".to_owned(),
        source,
    })?
    else {
        return Err(BenchError::InvalidArguments(
            "TUN UDP benchmark requires an IPv4 local address".to_owned(),
        ));
    };
    let ip = *addr.ip();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Err(BenchError::InvalidArguments(format!(
            "TUN UDP benchmark requires a non-loopback local IPv4 address, got {ip}"
        )));
    }
    Ok(ip)
}

#[cfg(unix)]
struct Ipv4UdpDatagram<'a> {
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &'a [u8],
}

#[cfg(unix)]
fn parse_ipv4_udp_datagram(packet: &[u8]) -> Option<Ipv4UdpDatagram<'_>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != UDP_PROTOCOL {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }
    if internet_checksum(&packet[..header_len]) != 0 {
        return None;
    }

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let udp = &udp[..udp_len];
    let checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if checksum != 0 && ipv4_udp_checksum(source, destination, udp) != 0 {
        return None;
    }

    Some(Ipv4UdpDatagram {
        source,
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination,
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..],
    })
}

#[cfg(unix)]
fn ipv4_udp_packet(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, BenchError> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    if total_len > usize::from(u16::MAX) {
        return Err(BenchError::InvalidArguments(format!(
            "TUN UDP payload is too large: {} bytes",
            payload.len()
        )));
    }

    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = UDP_PROTOCOL;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = nonzero_udp_checksum(ipv4_udp_checksum(source, destination, udp));
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    Ok(packet)
}

#[cfg(unix)]
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(unix)]
fn ipv4_udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&[0, UDP_PROTOCOL]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    internet_checksum(&pseudo)
}

#[cfg(unix)]
fn nonzero_udp_checksum(checksum: u16) -> u16 {
    if checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

#[cfg(unix)]
struct TunTcpBenchmarkClient {
    iface: SmolInterface,
    device: TunTcpPacketDevice,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
    source_port: u16,
}

#[cfg(unix)]
impl TunTcpBenchmarkClient {
    fn new(source_port: u16) -> Self {
        let mut device = TunTcpPacketDevice::new(1500);
        let mut iface_config = SmolInterfaceConfig::new(SmolHardwareAddress::Ip);
        iface_config.random_seed = 0x7872_6179_7463_7001;
        let mut iface = SmolInterface::new(iface_config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(SmolIpCidr::new(SmolIpAddress::v4(10, 10, 0, 2), 24))
                .expect("benchmark client has one IP address");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(SmolIpv4Address::new(10, 10, 0, 1))
            .expect("benchmark client default route is valid");

        let tcp_socket = smol_tcp::Socket::new(
            smol_tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            smol_tcp::SocketBuffer::new(vec![0; 64 * 1024]),
        );
        let mut sockets = SocketSet::new(Vec::new());
        let tcp = sockets.add(tcp_socket);

        Self {
            iface,
            device,
            sockets,
            tcp,
            source_port,
        }
    }

    fn connect(&mut self, target: SocketAddr) -> Result<(), BenchError> {
        let SocketAddr::V4(target) = target else {
            return Err(BenchError::InvalidArguments(
                "tun-tcp-freedom workload currently uses IPv4 echo targets".to_owned(),
            ));
        };
        self.sockets
            .get_mut::<smol_tcp::Socket>(self.tcp)
            .connect(
                self.iface.context(),
                (*target.ip(), target.port()),
                self.source_port,
            )
            .map_err(|error| {
                BenchError::InvalidArguments(format!("starting TUN TCP connect: {error}"))
            })
    }

    fn may_send(&mut self) -> bool {
        self.sockets.get::<smol_tcp::Socket>(self.tcp).may_send()
    }

    fn send_payload(&mut self, payload: &[u8]) -> Result<(), BenchError> {
        self.sockets
            .get_mut::<smol_tcp::Socket>(self.tcp)
            .send_slice(payload)
            .map(|_| ())
            .map_err(|error| {
                BenchError::InvalidArguments(format!("sending TUN TCP payload: {error}"))
            })
    }

    fn recv_available(&mut self) -> Vec<u8> {
        let mut received = Vec::new();
        let socket = self.sockets.get_mut::<smol_tcp::Socket>(self.tcp);
        while socket.can_recv() {
            if socket
                .recv(|data| {
                    received.extend_from_slice(data);
                    (data.len(), ())
                })
                .is_err()
            {
                break;
            }
        }
        received
    }

    fn poll(&mut self) {
        let _ = self
            .iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }
}

#[cfg(unix)]
async fn pump_tun_tcp_until(
    tun_fd: RawFd,
    client: &mut TunTcpBenchmarkClient,
    mut is_done: impl FnMut(&mut TunTcpBenchmarkClient) -> bool,
) -> Result<(), BenchError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buffer = vec![0; 65_535 + DARWIN_UTUN_HEADER_LEN];
    loop {
        client.poll();
        while let Some(packet) = client.device.pop_outbound() {
            write_tun_frame(tun_fd, &encode_darwin_utun_frame(&packet))?;
        }
        while let Some(len) = read_tun_frame(tun_fd, &mut buffer)? {
            let packet = decode_darwin_utun_frame(&buffer[..len])?;
            client.device.push_inbound(Bytes::copy_from_slice(packet));
        }
        client.poll();

        if is_done(client) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(BenchError::InvalidArguments(
                "timed out waiting for TUN TCP client state".to_owned(),
            ));
        }
        sleep(Duration::from_millis(1)).await;
    }
}

#[cfg(unix)]
struct TunTcpPacketDevice {
    mtu: usize,
    inbound: VecDeque<Bytes>,
    outbound: VecDeque<Bytes>,
}

#[cfg(unix)]
impl TunTcpPacketDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }

    fn push_inbound(&mut self, packet: Bytes) {
        self.inbound.push_back(packet);
    }

    fn pop_outbound(&mut self) -> Option<Bytes> {
        self.outbound.pop_front()
    }
}

#[cfg(unix)]
impl SmolDevice for TunTcpPacketDevice {
    type RxToken<'a>
        = TunTcpRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunTcpTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            TunTcpRxToken { packet },
            TunTcpTxToken {
                mtu: self.mtu,
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTcpTxToken {
            mtu: self.mtu,
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> SmolDeviceCapabilities {
        let mut capabilities = SmolDeviceCapabilities::default();
        capabilities.medium = SmolMedium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = None;
        capabilities.checksum = SmolChecksumCapabilities::default();
        capabilities
    }
}

#[cfg(unix)]
struct TunTcpRxToken {
    packet: Bytes,
}

#[cfg(unix)]
impl SmolRxToken for TunTcpRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[cfg(unix)]
struct TunTcpTxToken<'a> {
    mtu: usize,
    outbound: &'a mut VecDeque<Bytes>,
}

#[cfg(unix)]
impl SmolTxToken for TunTcpTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len.min(self.mtu)];
        let result = f(&mut packet);
        self.outbound.push_back(Bytes::from(packet));
        result
    }
}

async fn spawn_fake_vless_udp_server(
    mode: VlessUdpServerMode,
) -> Result<(SocketAddr, JoinHandle<()>), BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding fake VLESS UDP server".to_owned(),
            source,
        })?;
    let addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading fake VLESS UDP server address".to_owned(),
        source,
    })?;
    let tls_acceptor = match mode {
        VlessUdpServerMode::VisionXudp => Some(TlsAcceptor::from(fake_tls_server_config()?)),
        VlessUdpServerMode::Udp | VlessUdpServerMode::Xudp => None,
    };

    let task = tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                if let Some(tls_acceptor) = tls_acceptor {
                    let Ok(stream) = tls_acceptor.accept(stream).await else {
                        return;
                    };
                    if let Err(error) = handle_fake_vless_udp_connection(stream, mode).await {
                        eprintln!("fake VLESS UDP server error: {error}");
                    }
                } else if let Err(error) = handle_fake_vless_udp_connection(stream, mode).await {
                    eprintln!("fake VLESS UDP server error: {error}");
                }
            });
        }
    });

    Ok((addr, task))
}

async fn handle_fake_vless_udp_connection<S>(
    mut inbound: S,
    mode: VlessUdpServerMode,
) -> Result<(), BenchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match mode {
        VlessUdpServerMode::Udp => {
            let _target = read_vless_udp_target(&mut inbound).await?;
        }
        VlessUdpServerMode::Xudp | VlessUdpServerMode::VisionXudp => {
            read_vless_mux_header(&mut inbound).await?;
        }
    }
    inbound
        .write_all(&[0, 0])
        .await
        .map_err(|source| BenchError::Io {
            action: "writing fake VLESS UDP response header".to_owned(),
            source,
        })?;

    match mode {
        VlessUdpServerMode::Udp => handle_fake_vless_udp_frames(&mut inbound).await?,
        VlessUdpServerMode::Xudp => handle_fake_vless_xudp_frames(&mut inbound).await?,
        VlessUdpServerMode::VisionXudp => {
            handle_fake_vless_vision_xudp_frames(&mut inbound).await?
        }
    }

    Ok(())
}

async fn handle_fake_vless_udp_frames<S>(inbound: &mut S) -> Result<(), BenchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let payload = match read_udp_packet(inbound).await {
            Ok(payload) => payload,
            Err(_) => break,
        };
        let frame = encode_udp_packet(&payload).map_err(|error| {
            BenchError::InvalidArguments(format!("encoding fake VLESS UDP packet: {error}"))
        })?;
        inbound
            .write_all(&frame)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing fake VLESS UDP echo packet".to_owned(),
                source,
            })?;
    }

    Ok(())
}

async fn handle_fake_vless_xudp_frames<S>(inbound: &mut S) -> Result<(), BenchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let packet = match read_xudp_packet(inbound).await {
            Ok(packet) => packet,
            Err(_) => break,
        };
        let source = packet.source.unwrap_or_else(|| {
            Target::new(
                RoutingTargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
                9,
                RoutingNetwork::Udp,
            )
        });
        let frame = encode_xudp_keep_packet(Some(&source), &packet.payload).map_err(|error| {
            BenchError::InvalidArguments(format!("encoding fake VLESS XUDP packet: {error}"))
        })?;
        inbound
            .write_all(&frame)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing fake VLESS XUDP echo packet".to_owned(),
                source,
            })?;
    }

    Ok(())
}

async fn handle_fake_vless_vision_xudp_frames<S>(inbound: &mut S) -> Result<(), BenchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut read_state = VisionXudpReadState::default();
    let mut padding = VisionPadding::new(TEST_VLESS_UUID, [0, 0, 0, 0]);
    loop {
        let packets = match read_next_vision_xudp_packets(inbound, &mut read_state).await {
            Ok(Some(packets)) => packets,
            Ok(None) => break,
            Err(_) => break,
        };
        for packet in packets {
            let source = packet.source.unwrap_or_else(|| {
                Target::new(
                    RoutingTargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
                    9,
                    RoutingNetwork::Udp,
                )
            });
            let frame =
                encode_xudp_keep_packet(Some(&source), &packet.payload).map_err(|error| {
                    BenchError::InvalidArguments(format!(
                        "encoding fake VLESS Vision XUDP packet: {error}"
                    ))
                })?;
            let padded = padding
                .pad(BytesMut::from(&frame[..]), VisionCommand::Continue, 0)
                .map_err(|error| {
                    BenchError::InvalidArguments(format!("padding fake Vision response: {error}"))
                })?;
            inbound
                .write_all(&padded)
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing fake VLESS Vision XUDP echo packet".to_owned(),
                    source,
                })?;
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct VisionXudpReadState {
    user_id_seen: bool,
    raw_xudp: bool,
}

async fn read_next_vision_xudp_packets<S>(
    inbound: &mut S,
    state: &mut VisionXudpReadState,
) -> Result<Option<Vec<xray_proxy::vless::XudpPacket>>, BenchError>
where
    S: AsyncRead + Unpin,
{
    loop {
        if state.raw_xudp {
            return match read_xudp_packet(inbound).await {
                Ok(packet) => Ok(Some(vec![packet])),
                Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
                Err(source) => Err(BenchError::Io {
                    action: "reading raw fake VLESS Vision XUDP packet".to_owned(),
                    source,
                }),
            };
        }

        let block = match read_vision_block(inbound, &mut state.user_id_seen).await {
            Ok(block) => block,
            Err(BenchError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if matches!(block.command, VisionCommand::End | VisionCommand::Direct) {
            state.raw_xudp = true;
        }

        let packets = read_xudp_packets_from_payload(&block.payload).await?;
        if packets.is_empty() {
            continue;
        }
        return Ok(Some(packets));
    }
}

async fn read_xudp_packets_from_payload(
    payload: &[u8],
) -> Result<Vec<xray_proxy::vless::XudpPacket>, BenchError> {
    let mut cursor = std::io::Cursor::new(payload.to_vec());
    let mut packets = Vec::new();
    while cursor.position() < payload.len() as u64 {
        match read_xudp_packet(&mut cursor).await {
            Ok(packet) => packets.push(packet),
            Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(source) => {
                return Err(BenchError::Io {
                    action: "reading fake VLESS Vision XUDP packet".to_owned(),
                    source,
                })
            }
        }
    }
    Ok(packets)
}

async fn read_vision_block<S>(
    stream: &mut S,
    user_id_seen: &mut bool,
) -> Result<xray_proxy::vless::UnpaddedVisionBlock, BenchError>
where
    S: AsyncRead + Unpin,
{
    let mut frame = Vec::new();
    if !*user_id_seen {
        let mut user_id = [0; 16];
        stream
            .read_exact(&mut user_id)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading Vision user id".to_owned(),
                source,
            })?;
        if user_id != TEST_VLESS_UUID {
            return Err(BenchError::InvalidArguments(
                "unexpected Vision user id".to_owned(),
            ));
        }
        frame.extend_from_slice(&user_id);
        *user_id_seen = true;
    }

    let mut header = [0; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading Vision header".to_owned(),
            source,
        })?;
    frame.extend_from_slice(&header);

    let content_len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    let padding_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut rest = vec![0; content_len + padding_len];
    stream
        .read_exact(&mut rest)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading Vision payload block".to_owned(),
            source,
        })?;
    frame.extend_from_slice(&rest);

    unpad_vision_block(&frame, &TEST_VLESS_UUID).map_err(|error| {
        BenchError::InvalidArguments(format!("unpadding fake Vision request: {error}"))
    })
}

fn fake_tls_server_config() -> Result<Arc<rustls::ServerConfig>, BenchError> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["vless.test".to_owned()]).map_err(|error| {
            BenchError::InvalidArguments(format!("generating fake TLS certificate: {error}"))
        })?;
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| BenchError::InvalidArguments(format!("building TLS versions: {error}")))?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .map_err(|error| BenchError::InvalidArguments(format!("building TLS server: {error}")))?;
    Ok(Arc::new(config))
}

async fn read_vless_mux_header<S>(stream: &mut S) -> Result<(), BenchError>
where
    S: AsyncRead + Unpin,
{
    let command = read_vless_common_header(stream).await?;
    if command != 3 {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected VLESS command {command}"
        )));
    }
    Ok(())
}

async fn read_vless_udp_target<S>(stream: &mut S) -> Result<SocketAddr, BenchError>
where
    S: AsyncRead + Unpin,
{
    let command = read_vless_common_header(stream).await?;
    if command != 2 {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected VLESS command {command}"
        )));
    }
    read_vless_target(stream).await
}

async fn read_vless_common_header<S>(stream: &mut S) -> Result<u8, BenchError>
where
    S: AsyncRead + Unpin,
{
    let mut version = [0; 1];
    stream
        .read_exact(&mut version)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading VLESS version".to_owned(),
            source,
        })?;
    if version[0] != 0 {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected VLESS version {}",
            version[0]
        )));
    }

    let mut uuid = [0; 16];
    stream
        .read_exact(&mut uuid)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading VLESS user id".to_owned(),
            source,
        })?;
    if uuid != TEST_VLESS_UUID {
        return Err(BenchError::InvalidArguments(
            "unexpected VLESS user id".to_owned(),
        ));
    }

    let mut addons_len = [0; 1];
    stream
        .read_exact(&mut addons_len)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading VLESS addons length".to_owned(),
            source,
        })?;
    if addons_len[0] != 0 {
        let mut addons = vec![0; usize::from(addons_len[0])];
        stream
            .read_exact(&mut addons)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading VLESS addons".to_owned(),
                source,
            })?;
    }

    let mut command = [0; 1];
    stream
        .read_exact(&mut command)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading VLESS command".to_owned(),
            source,
        })?;
    Ok(command[0])
}

async fn read_vless_target<S>(stream: &mut S) -> Result<SocketAddr, BenchError>
where
    S: AsyncRead + Unpin,
{
    let mut port = [0; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading VLESS target port".to_owned(),
            source,
        })?;
    let port = u16::from_be_bytes(port);

    let mut addr_type = [0; 1];
    stream
        .read_exact(&mut addr_type)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading VLESS address type".to_owned(),
            source,
        })?;
    match addr_type[0] {
        1 => {
            let mut ip = [0; 4];
            stream
                .read_exact(&mut ip)
                .await
                .map_err(|source| BenchError::Io {
                    action: "reading VLESS IPv4 address".to_owned(),
                    source,
                })?;
            Ok(SocketAddr::from((Ipv4Addr::from(ip), port)))
        }
        other => Err(BenchError::InvalidArguments(format!(
            "unsupported fake VLESS UDP address type {other}"
        ))),
    }
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
    freedom_config(port, false)
}

pub fn xray_core_freedom_config(port: u16) -> String {
    freedom_config(port, false)
}

pub fn xray_rust_config(port: u16, workload: WorkloadKind) -> String {
    match workload {
        WorkloadKind::UdpVless | WorkloadKind::UdpXudp => {
            vless_udp_config(port, SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
        WorkloadKind::VisionXudp => {
            vision_xudp_config(port, SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
        WorkloadKind::TunUdpFreedom | WorkloadKind::TunTcpFreedom => tun_freedom_config(),
        WorkloadKind::Idle
        | WorkloadKind::TcpFreedom
        | WorkloadKind::ManyIdleFlows
        | WorkloadKind::ReconnectBurst
        | WorkloadKind::MixedLongLived
        | WorkloadKind::UdpFreedom => freedom_config(
            port,
            matches!(
                workload,
                WorkloadKind::UdpFreedom | WorkloadKind::MixedLongLived
            ),
        ),
    }
}

pub fn xray_core_config(port: u16, workload: WorkloadKind) -> String {
    xray_rust_config(port, workload)
}

fn engine_config(
    port: u16,
    workload: WorkloadKind,
    fixture: &WorkloadFixture,
) -> Result<String, BenchError> {
    match workload {
        WorkloadKind::UdpVless | WorkloadKind::UdpXudp => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(
                    "vless udp workload requires a fake VLESS server fixture".to_owned(),
                )
            })?;
            Ok(vless_udp_config(port, vless_addr))
        }
        WorkloadKind::VisionXudp => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(
                    "vision-xudp workload requires a fake VLESS server fixture".to_owned(),
                )
            })?;
            Ok(vision_xudp_config(port, vless_addr))
        }
        WorkloadKind::TunUdpFreedom | WorkloadKind::TunTcpFreedom => Ok(tun_freedom_config()),
        WorkloadKind::Idle
        | WorkloadKind::TcpFreedom
        | WorkloadKind::ManyIdleFlows
        | WorkloadKind::ReconnectBurst
        | WorkloadKind::MixedLongLived
        | WorkloadKind::UdpFreedom => Ok(freedom_config(
            port,
            matches!(
                workload,
                WorkloadKind::UdpFreedom | WorkloadKind::MixedLongLived
            ),
        )),
    }
}

fn tun_freedom_config() -> String {
    r#"{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "tun-in",
      "protocol": "tun",
      "listen": "127.0.0.1",
      "port": 0,
      "settings": { "name": "utun9", "MTU": 1500 }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}"#
    .to_owned()
}

fn freedom_config(port: u16, socks_udp: bool) -> String {
    let socks_settings = if socks_udp {
        r#"{ "auth": "noauth", "udp": true, "ip": "127.0.0.1" }"#
    } else {
        r#"{ "auth": "noauth", "udp": false }"#
    };
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": {port},
      "settings": {socks_settings}
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

fn vless_udp_config(port: u16, vless_addr: SocketAddr) -> String {
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": {port},
      "settings": {{ "auth": "noauth", "udp": true, "ip": "127.0.0.1" }}
    }}
  ],
  "outbounds": [
    {{
      "tag": "proxy",
      "protocol": "vless",
      "settings": {{
        "vnext": [
          {{
            "address": "{}",
            "port": {},
            "users": [
              {{
                "id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
                "encryption": "none"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{ "network": "tcp", "security": "none" }}
    }}
  ]
}}"#,
        vless_addr.ip(),
        vless_addr.port()
    )
}

fn vision_xudp_config(port: u16, vless_addr: SocketAddr) -> String {
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": {port},
      "settings": {{ "auth": "noauth", "udp": true, "ip": "127.0.0.1" }}
    }}
  ],
  "outbounds": [
    {{
      "tag": "proxy",
      "protocol": "vless",
      "settings": {{
        "vnext": [
          {{
            "address": "{}",
            "port": {},
            "users": [
              {{
                "id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {{ "serverName": "vless.test", "allowInsecure": true }}
      }}
    }}
  ]
}}"#,
        vless_addr.ip(),
        vless_addr.port()
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

#[cfg(unix)]
fn create_tun_socket_pair() -> Result<TunSocketPair, BenchError> {
    let mut fds = [-1; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    if rc < 0 {
        return Err(BenchError::Io {
            action: "creating benchmark TUN socketpair".to_owned(),
            source: io::Error::last_os_error(),
        });
    }

    if let Err(source) = clear_fd_cloexec(fds[0]) {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(BenchError::Io {
            action: "clearing close-on-exec on benchmark TUN fd".to_owned(),
            source,
        });
    }
    if let Err(source) = set_fd_cloexec(fds[1]) {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(BenchError::Io {
            action: "setting close-on-exec on benchmark-side TUN fd".to_owned(),
            source,
        });
    }
    if let Err(source) = set_fd_nonblocking(fds[1]) {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(BenchError::Io {
            action: "setting benchmark TUN fd nonblocking".to_owned(),
            source,
        });
    }

    Ok(TunSocketPair {
        engine_fd: FdGuard::new(fds[0]),
        workload_fd: FdGuard::new(fds[1]),
    })
}

#[cfg(not(unix))]
fn create_tun_socket_pair() -> Result<TunSocketPair, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-udp-freedom workload requires Unix socketpair support".to_owned(),
    ))
}

#[cfg(unix)]
fn clear_fd_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn set_fd_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn set_fd_nonblocking(fd: RawFd) -> io::Result<()> {
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

#[cfg(unix)]
fn configure_tun_fd_env(command: &mut Command, pair: &TunSocketPair) {
    command
        .env("XRAY_TUN_FD", pair.engine_fd.raw().to_string())
        .env("XRAY_TUN_FD_PACKET_FORMAT", "darwin-utun");
}

#[cfg(not(unix))]
fn configure_tun_fd_env(_command: &mut Command, _pair: &TunSocketPair) {}

#[cfg(unix)]
fn into_tun_workload_fd(pair: TunSocketPair) -> Option<FdGuard> {
    Some(pair.into_workload_fd())
}

#[cfg(not(unix))]
fn into_tun_workload_fd(_pair: TunSocketPair) -> Option<FdGuard> {
    None
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

pub async fn wait_for_process_started(
    child: &mut Child,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<(), BenchError> {
    sleep(Duration::from_millis(150)).await;
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
    Ok(())
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
    let bin_dir = absolute_path(bin_dir)?;
    fs::create_dir_all(&bin_dir).map_err(|source| BenchError::Io {
        action: format!("creating binary directory `{}`", bin_dir.display()),
        source,
    })?;
    let binary = bin_dir.join(format!("xray-core{}", std::env::consts::EXE_SUFFIX));
    if binary.exists() {
        return Ok(binary);
    }
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

fn absolute_path(path: &Path) -> Result<PathBuf, BenchError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|source| BenchError::Io {
        action: "resolving current directory".to_owned(),
        source,
    })?;
    Ok(cwd.join(path))
}

async fn start_engine(
    kind: EngineKind,
    options: &BenchOptions,
    run_dir: &Path,
    binary_dir: &Path,
    fixture: &WorkloadFixture,
) -> Result<RunningEngine, BenchError> {
    fs::create_dir_all(run_dir).map_err(|source| BenchError::Io {
        action: format!("creating run directory `{}`", run_dir.display()),
        source,
    })?;
    let port = allocate_loopback_port()?;
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let tun_pair = if options.workload.uses_tun_fd() {
        Some(create_tun_socket_pair()?)
    } else {
        None
    };
    let config = match kind {
        EngineKind::XrayRust | EngineKind::XrayCore => {
            engine_config(port, options.workload, fixture)?
        }
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
        EngineKind::XrayCore => ensure_xray_core_binary(options, binary_dir)?,
    };
    let stdout = fs::File::create(&stdout_path).map_err(|source| BenchError::Io {
        action: format!("creating stdout log `{}`", stdout_path.display()),
        source,
    })?;
    let stderr = fs::File::create(&stderr_path).map_err(|source| BenchError::Io {
        action: format!("creating stderr log `{}`", stderr_path.display()),
        source,
    })?;
    let mut command = Command::new(&binary);
    command
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(pair) = tun_pair.as_ref() {
        configure_tun_fd_env(&mut command, pair);
    }
    let mut child = command.spawn().map_err(|source| BenchError::Io {
        action: format!("spawning `{}`", binary.display()),
        source,
    })?;
    let pid = child.id();
    let tun_fd = tun_pair.and_then(into_tun_workload_fd);
    if options.workload.uses_tun_fd() {
        wait_for_process_started(&mut child, &stdout_path, &stderr_path).await?;
    } else {
        wait_for_tcp_listener(&mut child, socks_addr, &stdout_path, &stderr_path).await?;
    }

    Ok(RunningEngine {
        kind,
        child,
        pid,
        socks_addr,
        tun_fd,
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
    match parse_cli_args(args)? {
        CliArgs::Run(options) => {
            let engine = options.engine.ok_or_else(|| {
                BenchError::InvalidArguments("run requires --engine xray-rust|xray-core".to_owned())
            })?;
            let run_id = new_run_id();
            let summary = run_engine_series(engine, &options, &run_id).await?;
            print_summary(&summary);
            Ok(())
        }
        CliArgs::Compare(options) => run_compare(options).await,
    }
}

pub async fn run_compare(options: BenchOptions) -> Result<(), BenchError> {
    let run_id = new_run_id();
    let rust_summary = run_engine_series(EngineKind::XrayRust, &options, &run_id).await?;
    print_summary(&rust_summary);
    let xray_summary = run_engine_series(EngineKind::XrayCore, &options, &run_id).await?;
    print_summary(&xray_summary);
    Ok(())
}

pub async fn run_engine_series(
    kind: EngineKind,
    options: &BenchOptions,
    run_id: &str,
) -> Result<BenchSummary, BenchError> {
    let base_dir = run_directory(&options.out_dir, run_id, kind, options.workload);
    fs::create_dir_all(&base_dir).map_err(|source| BenchError::Io {
        action: format!("creating run directory `{}`", base_dir.display()),
        source,
    })?;
    let binary_dir = base_dir.join("bin");
    let mut results = Vec::with_capacity(options.runs);
    for run_index in 1..=options.runs {
        let run_dir = if options.runs == 1 {
            base_dir.clone()
        } else {
            numbered_run_directory(&base_dir, run_index)
        };
        results.push(run_engine_once(kind, options, &run_dir, &binary_dir).await?);
    }
    let summary = summarize_results(&results)?;
    write_summary_json(&base_dir.join("summary.json"), &summary)?;
    Ok(summary)
}

pub async fn run_single_engine(
    kind: EngineKind,
    options: &BenchOptions,
    run_id: &str,
) -> Result<BenchResult, BenchError> {
    let run_dir = run_directory(&options.out_dir, run_id, kind, options.workload);
    let binary_dir = run_dir.join("bin");
    run_engine_once(kind, options, &run_dir, &binary_dir).await
}

async fn run_engine_once(
    kind: EngineKind,
    options: &BenchOptions,
    run_dir: &Path,
    binary_dir: &Path,
) -> Result<BenchResult, BenchError> {
    fs::create_dir_all(run_dir).map_err(|source| BenchError::Io {
        action: format!("creating run directory `{}`", run_dir.display()),
        source,
    })?;
    let fixture = WorkloadFixture::start(options.workload).await?;
    let engine = start_engine(kind, options, run_dir, binary_dir, &fixture).await?;
    let started = Instant::now();
    let workload = async {
        match options.workload {
            WorkloadKind::Idle => run_idle_workload(options.duration).await,
            WorkloadKind::TcpFreedom => run_tcp_freedom_workload(engine.socks_addr, options).await,
            WorkloadKind::ManyIdleFlows => {
                run_many_idle_flows_workload(engine.socks_addr, options).await
            }
            WorkloadKind::ReconnectBurst => {
                run_reconnect_burst_workload(engine.socks_addr, options).await
            }
            WorkloadKind::MixedLongLived => {
                run_mixed_long_lived_workload(engine.socks_addr, options).await
            }
            WorkloadKind::UdpFreedom => run_udp_freedom_workload(engine.socks_addr, options).await,
            WorkloadKind::TunUdpFreedom => {
                run_tun_udp_freedom_workload(engine.tun_fd()?, options).await
            }
            WorkloadKind::TunTcpFreedom => {
                run_tun_tcp_freedom_workload(engine.tun_fd()?, options).await
            }
            WorkloadKind::UdpVless => run_udp_vless_workload(engine.socks_addr, options).await,
            WorkloadKind::UdpXudp => run_udp_xudp_workload(engine.socks_addr, options).await,
            WorkloadKind::VisionXudp => run_vision_xudp_workload(engine.socks_addr, options).await,
        }
    };
    let (workload_outcome, samples) = match timeout(
        options.run_timeout,
        sample_while(engine.pid, options.sample_interval, workload),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(BenchError::Timeout {
                timeout_ms: options.run_timeout.as_millis(),
            })
        }
    };
    let mut summary = summarize_samples(&samples);
    summary.bytes_sent = workload_outcome.bytes_sent;
    summary.bytes_received = workload_outcome.bytes_received;
    let latency_us = summarize_latency_us(workload_outcome.latencies_us);
    let setup_us = summarize_flow_setup_us(workload_outcome.setup_samples);
    let cpu_millis_per_gib = cpu_millis_per_gib(
        summary.cpu_millis,
        summary.bytes_sent,
        summary.bytes_received,
    );

    let result = BenchResult {
        engine: kind.as_str().to_owned(),
        workload: options.workload.as_str().to_owned(),
        status: "ok".to_owned(),
        duration_ms: started.elapsed().as_millis(),
        bytes_sent: summary.bytes_sent,
        bytes_received: summary.bytes_received,
        peak_rss_kib: summary.peak_rss_kib,
        cpu_millis: summary.cpu_millis,
        cpu_millis_per_gib,
        latency_us,
        setup_us,
        samples: samples.len(),
    };
    write_samples_csv(&run_dir.join("samples.csv"), &samples)?;
    write_result_json(&run_dir.join("result.json"), &result)?;
    drop(engine);

    Ok(result)
}

pub fn numbered_run_directory(base: &Path, run_index: usize) -> PathBuf {
    base.join(format!("run-{run_index:03}"))
}

pub fn run_directory(
    base: &Path,
    run_id: &str,
    engine: EngineKind,
    workload: WorkloadKind,
) -> PathBuf {
    base.join(run_id)
        .join(engine.as_str())
        .join(workload.as_str())
}

fn new_run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    millis.to_string()
}

fn print_result(result: &BenchResult) {
    let latency = result
        .latency_us
        .as_ref()
        .map(|latency| {
            format!(
                " latency_us[min/median/p95/p99]={}/{}/{}/{}",
                latency.min, latency.median, latency.p95, latency.p99
            )
        })
        .unwrap_or_default();
    let cpu_per_gib = result
        .cpu_millis_per_gib
        .map(|value| format!(" cpu_millis_per_gib={value}"))
        .unwrap_or_default();
    let setup = result
        .setup_us
        .as_ref()
        .map(|setup| {
            format!(
                " setup_total_us[min/median/p95/p99]={}/{}/{}/{} setup_tcp_us[median]={} setup_socks_us[median]={}",
                setup.total_us.min,
                setup.total_us.median,
                setup.total_us.p95,
                setup.total_us.p99,
                setup.tcp_connect_us.median,
                setup.socks_setup_us.median,
            )
        })
        .unwrap_or_default();
    println!(
        "{} {} status={} peak_rss_kib={} cpu_millis={} bytes_sent={} bytes_received={} samples={}{}{}{}",
        result.engine,
        result.workload,
        result.status,
        result.peak_rss_kib,
        result.cpu_millis,
        result.bytes_sent,
        result.bytes_received,
        result.samples,
        cpu_per_gib,
        latency,
        setup
    );
}

fn print_summary(summary: &BenchSummary) {
    if summary.runs == 1 {
        if let Some(result) = summary.results.first() {
            print_result(result);
            return;
        }
    }
    let cpu_per_gib = summary
        .cpu_millis_per_gib
        .as_ref()
        .map(|metric| {
            format!(
                " cpu_millis_per_gib[min/median/p95]={}/{}/{}",
                metric.min, metric.median, metric.p95
            )
        })
        .unwrap_or_default();
    let latency = summary
        .latency_us
        .as_ref()
        .map(|latency| {
            format!(
                " latency_us[median:min/median/p95]={}/{}/{} latency_us[p95:min/median/p95]={}/{}/{} latency_us[p99:min/median/p95]={}/{}/{}",
                latency.median.min,
                latency.median.median,
                latency.median.p95,
                latency.p95.min,
                latency.p95.median,
                latency.p95.p95,
                latency.p99.min,
                latency.p99.median,
                latency.p99.p95,
            )
        })
        .unwrap_or_default();
    let setup = summary
        .setup_us
        .as_ref()
        .map(|setup| {
            format!(
                " setup_total_us[median:min/median/p95]={}/{}/{} setup_tcp_us[median:min/median/p95]={}/{}/{} setup_socks_us[median:min/median/p95]={}/{}/{}",
                setup.total_us.median.min,
                setup.total_us.median.median,
                setup.total_us.median.p95,
                setup.tcp_connect_us.median.min,
                setup.tcp_connect_us.median.median,
                setup.tcp_connect_us.median.p95,
                setup.socks_setup_us.median.min,
                setup.socks_setup_us.median.median,
                setup.socks_setup_us.median.p95,
            )
        })
        .unwrap_or_default();
    println!(
        "{} {} runs={} status={} duration_ms[min/median/p95]={}/{}/{} peak_rss_kib[min/median/p95]={}/{}/{} cpu_millis[min/median/p95]={}/{}/{} bytes_sent[min/median/p95]={}/{}/{} bytes_received[min/median/p95]={}/{}/{}{}{}{}",
        summary.engine,
        summary.workload,
        summary.runs,
        summary.status,
        summary.duration_ms.min,
        summary.duration_ms.median,
        summary.duration_ms.p95,
        summary.peak_rss_kib.min,
        summary.peak_rss_kib.median,
        summary.peak_rss_kib.p95,
        summary.cpu_millis.min,
        summary.cpu_millis.median,
        summary.cpu_millis.p95,
        summary.bytes_sent.min,
        summary.bytes_sent.median,
        summary.bytes_sent.p95,
        summary.bytes_received.min,
        summary.bytes_received.median,
        summary.bytes_received.p95,
        cpu_per_gib,
        latency,
        setup,
    );
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
                run_timeout: Duration::from_secs(30),
                connections: 1,
                iterations: 1,
                payload_size: 1024,
                runs: 1,
                out_dir: PathBuf::from("target/benchmarks/test"),
                xray_rust_bin: None,
                xray_core_bin: None,
                xray_core_dir: None,
                no_auto_build: false,
            })
        );
    }

    #[test]
    fn parses_run_timeout_ms() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "vision-xudp",
            "--run-timeout-ms",
            "1500",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.run_timeout, Duration::from_millis(1500));
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
        assert_eq!(options.runs, 1);
        assert_eq!(options.xray_core_dir, Some(PathBuf::from("../Xray-core")));
    }

    #[test]
    fn parses_compare_udp_freedom() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "udp-freedom",
            "--connections",
            "2",
            "--iterations",
            "3",
            "--payload-size",
            "64",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::UdpFreedom);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
    }

    #[test]
    fn parses_compare_udp_vless() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "udp-vless",
            "--connections",
            "2",
            "--iterations",
            "3",
            "--payload-size",
            "64",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::UdpVless);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
    }

    #[test]
    fn parses_compare_udp_xudp() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "udp-xudp",
            "--connections",
            "2",
            "--iterations",
            "3",
            "--payload-size",
            "64",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::UdpXudp);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
    }

    #[test]
    fn parses_compare_vision_xudp() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "vision-xudp",
            "--connections",
            "2",
            "--iterations",
            "3",
            "--payload-size",
            "64",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::VisionXudp);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
    }

    #[test]
    fn parses_compare_tun_udp_freedom() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "tun-udp-freedom",
            "--connections",
            "2",
            "--iterations",
            "3",
            "--payload-size",
            "64",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::TunUdpFreedom);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
    }

    #[test]
    fn parses_compare_many_idle_flows() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "many-idle-flows",
            "--connections",
            "100",
            "--duration-ms",
            "1000",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::ManyIdleFlows);
        assert_eq!(options.connections, 100);
        assert_eq!(options.duration, Duration::from_millis(1000));
    }

    #[test]
    fn parses_mobile_scenario_workloads() {
        for (raw, expected) in [
            ("reconnect-burst", WorkloadKind::ReconnectBurst),
            ("mixed-long-lived", WorkloadKind::MixedLongLived),
            ("tun-tcp-freedom", WorkloadKind::TunTcpFreedom),
        ] {
            let args = parse_cli_args(["xray-bench", "compare", "--workload", raw]).unwrap();
            let CliArgs::Compare(options) = args else {
                panic!("expected compare args");
            };
            assert_eq!(options.workload, expected);
        }
    }

    #[test]
    fn tun_tcp_freedom_uses_fd_backed_tun() {
        assert!(WorkloadKind::TunTcpFreedom.uses_tun_fd());
    }

    #[test]
    fn parses_compare_with_repeated_runs() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "tcp-freedom",
            "--runs",
            "5",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.runs, 5);
    }

    #[test]
    fn rejects_zero_runs() {
        let error = parse_cli_args(["xray-bench", "compare", "--runs", "0"]).unwrap_err();
        assert!(error
            .to_string()
            .contains("--runs must be greater than zero"));
    }

    #[tokio::test]
    async fn fake_vision_xudp_reader_skips_empty_padding_blocks() {
        let source = Target::new(
            RoutingTargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
            9,
            RoutingNetwork::Udp,
        );
        let frame = encode_xudp_keep_packet(Some(&source), b"hello vision").unwrap();
        let mut padding = VisionPadding::new(TEST_VLESS_UUID, [0, 0, 0, 0]);
        let empty = padding
            .pad(BytesMut::new(), VisionCommand::Continue, 32)
            .unwrap();
        let payload = padding
            .pad(BytesMut::from(&frame[..]), VisionCommand::Continue, 0)
            .unwrap();
        let mut stream = std::io::Cursor::new([empty.to_vec(), payload.to_vec()].concat());
        let mut state = VisionXudpReadState::default();

        let packets = read_next_vision_xudp_packets(&mut stream, &mut state)
            .await
            .unwrap()
            .expect("xudp packets");

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].payload.as_ref(), b"hello vision");
        assert_eq!(packets[0].source, Some(source));
    }

    #[tokio::test]
    async fn fake_vision_xudp_reader_preserves_batched_xudp_frames() {
        let source = Target::new(
            RoutingTargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
            9,
            RoutingNetwork::Udp,
        );
        let first = encode_xudp_keep_packet(Some(&source), b"first").unwrap();
        let second = encode_xudp_keep_packet(Some(&source), b"second").unwrap();
        let mut batched = Vec::new();
        batched.extend_from_slice(&first);
        batched.extend_from_slice(&second);
        let mut padding = VisionPadding::new(TEST_VLESS_UUID, [0, 0, 0, 0]);
        let payload = padding
            .pad(BytesMut::from(&batched[..]), VisionCommand::Continue, 0)
            .unwrap();
        let mut stream = std::io::Cursor::new(payload.to_vec());
        let mut state = VisionXudpReadState::default();

        let packets = read_next_vision_xudp_packets(&mut stream, &mut state)
            .await
            .unwrap()
            .expect("xudp packets");

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].payload.as_ref(), b"first");
        assert_eq!(packets[1].payload.as_ref(), b"second");
    }

    #[tokio::test]
    async fn fake_vision_xudp_reader_switches_to_raw_after_end_block() {
        let source = Target::new(
            RoutingTargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
            9,
            RoutingNetwork::Udp,
        );
        let padded_frame = encode_xudp_keep_packet(Some(&source), b"padded").unwrap();
        let raw_frame = encode_xudp_keep_packet(Some(&source), b"raw").unwrap();
        let mut padding = VisionPadding::new(TEST_VLESS_UUID, [0, 0, 0, 0]);
        let end_block = padding
            .pad(BytesMut::from(&padded_frame[..]), VisionCommand::End, 0)
            .unwrap();
        let mut stream = std::io::Cursor::new([end_block.to_vec(), raw_frame].concat());
        let mut state = VisionXudpReadState::default();

        let padded_packets = read_next_vision_xudp_packets(&mut stream, &mut state)
            .await
            .unwrap()
            .expect("padded packet");
        let raw_packets = read_next_vision_xudp_packets(&mut stream, &mut state)
            .await
            .unwrap()
            .expect("raw packet");

        assert_eq!(padded_packets[0].payload.as_ref(), b"padded");
        assert_eq!(raw_packets[0].payload.as_ref(), b"raw");
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_ps_args_omit_unsupported_thread_count_column() {
        let args = ps_args(123);
        assert_eq!(
            args,
            vec![
                "-o".to_owned(),
                "rss=".to_owned(),
                "-o".to_owned(),
                "time=".to_owned(),
                "-p".to_owned(),
                "123".to_owned(),
            ]
        );
    }

    #[test]
    fn absolute_path_resolves_relative_paths_from_current_directory() {
        let path = absolute_path(Path::new("target/benchmarks/bin")).unwrap();
        assert!(path.is_absolute());
        assert!(path.ends_with(Path::new("target/benchmarks/bin")));
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
    fn udp_freedom_config_enables_socks_udp() {
        let config = xray_rust_config(18082, WorkloadKind::UdpFreedom);
        assert!(config.contains(r#""protocol": "socks""#));
        assert!(config.contains(r#""udp": true"#));
        assert!(config.contains(r#""protocol": "freedom""#));
    }

    #[test]
    fn udp_vless_config_routes_to_vless_outbound() {
        let config = vless_udp_config(
            18083,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19090)),
        );
        assert!(config.contains(r#""protocol": "socks""#));
        assert!(config.contains(r#""udp": true"#));
        assert!(config.contains(r#""protocol": "vless""#));
        assert!(config.contains(r#""port": 19090"#));
        assert!(config.contains("00010203-0405-0607-0809-0a0b0c0d0e0f"));
    }

    #[test]
    fn vision_xudp_config_enables_tls_vision_flow() {
        let config = vision_xudp_config(
            18084,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19091)),
        );
        assert!(config.contains(r#""protocol": "vless""#));
        assert!(config.contains(r#""flow": "xtls-rprx-vision""#));
        assert!(config.contains(r#""security": "tls""#));
        assert!(config.contains(r#""allowInsecure": true"#));
        assert!(config.contains(r#""port": 19091"#));
    }

    #[test]
    fn tun_udp_freedom_config_uses_tun_inbound_without_socks() {
        let fixture = WorkloadFixture::default();
        let config = engine_config(0, WorkloadKind::TunUdpFreedom, &fixture).unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["protocol"], "tun");
        assert_eq!(value["outbounds"][0]["protocol"], "freedom");
        assert!(!config.contains(r#""protocol": "socks""#));
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

    #[test]
    fn summarizes_latency_samples_with_percentiles() {
        let summary = summarize_latency_us([500, 100, 900, 700, 300]).unwrap();

        assert_eq!(
            summary,
            LatencySummary {
                min: 100,
                median: 500,
                p95: 900,
                p99: 900,
            }
        );
    }

    #[test]
    fn summarizes_flow_setup_samples_with_stage_percentiles() {
        let summary = summarize_flow_setup_us([
            FlowSetupSample {
                tcp_connect_us: 100,
                socks_setup_us: 400,
                total_us: 500,
            },
            FlowSetupSample {
                tcp_connect_us: 200,
                socks_setup_us: 600,
                total_us: 800,
            },
            FlowSetupSample {
                tcp_connect_us: 150,
                socks_setup_us: 500,
                total_us: 650,
            },
        ])
        .unwrap();

        assert_eq!(summary.tcp_connect_us.median, 150);
        assert_eq!(summary.socks_setup_us.median, 500);
        assert_eq!(summary.total_us.median, 650);
    }

    #[test]
    fn mixed_long_lived_config_enables_socks_udp() {
        let config = xray_rust_config(18085, WorkloadKind::MixedLongLived);
        assert!(config.contains(r#""protocol": "socks""#));
        assert!(config.contains(r#""udp": true"#));
        assert!(config.contains(r#""protocol": "freedom""#));
    }

    #[test]
    fn run_directory_contains_engine_and_workload() {
        let dir = run_directory(
            Path::new("target/benchmarks"),
            "123",
            EngineKind::XrayRust,
            WorkloadKind::Idle,
        );
        assert_eq!(dir, PathBuf::from("target/benchmarks/123/xray-rust/idle"));
    }

    #[test]
    fn numbered_run_directory_uses_stable_one_based_padding() {
        let dir = numbered_run_directory(Path::new("target/benchmarks/123/xray-rust/idle"), 2);
        assert_eq!(
            dir,
            PathBuf::from("target/benchmarks/123/xray-rust/idle/run-002")
        );
    }

    #[test]
    fn summarizes_repeated_results_with_min_median_and_p95() {
        let results = vec![
            BenchResult {
                engine: "xray-rust".to_owned(),
                workload: "tcp-freedom".to_owned(),
                status: "ok".to_owned(),
                duration_ms: 40,
                bytes_sent: 1024,
                bytes_received: 1024,
                peak_rss_kib: 3000,
                cpu_millis: 20,
                cpu_millis_per_gib: Some(10_485_760),
                latency_us: Some(LatencySummary {
                    min: 10,
                    median: 20,
                    p95: 30,
                    p99: 40,
                }),
                setup_us: None,
                samples: 2,
            },
            BenchResult {
                engine: "xray-rust".to_owned(),
                workload: "tcp-freedom".to_owned(),
                status: "ok".to_owned(),
                duration_ms: 10,
                bytes_sent: 1024,
                bytes_received: 1024,
                peak_rss_kib: 2700,
                cpu_millis: 10,
                cpu_millis_per_gib: Some(5_242_880),
                latency_us: Some(LatencySummary {
                    min: 5,
                    median: 10,
                    p95: 20,
                    p99: 30,
                }),
                setup_us: None,
                samples: 2,
            },
            BenchResult {
                engine: "xray-rust".to_owned(),
                workload: "tcp-freedom".to_owned(),
                status: "ok".to_owned(),
                duration_ms: 30,
                bytes_sent: 1024,
                bytes_received: 1024,
                peak_rss_kib: 2900,
                cpu_millis: 30,
                cpu_millis_per_gib: Some(15_728_640),
                latency_us: Some(LatencySummary {
                    min: 15,
                    median: 30,
                    p95: 40,
                    p99: 50,
                }),
                setup_us: None,
                samples: 2,
            },
        ];

        let summary = summarize_results(&results).unwrap();

        assert_eq!(summary.engine, "xray-rust");
        assert_eq!(summary.workload, "tcp-freedom");
        assert_eq!(summary.runs, 3);
        assert_eq!(
            summary.duration_ms,
            MetricSummary {
                min: 10,
                median: 30,
                p95: 40,
            }
        );
        assert_eq!(
            summary.peak_rss_kib,
            MetricSummary {
                min: 2700,
                median: 2900,
                p95: 3000,
            }
        );
        assert_eq!(
            summary.cpu_millis,
            MetricSummary {
                min: 10,
                median: 20,
                p95: 30,
            }
        );
        assert_eq!(
            summary.cpu_millis_per_gib,
            Some(MetricSummary {
                min: 5_242_880,
                median: 10_485_760,
                p95: 15_728_640,
            })
        );
        assert_eq!(
            summary.latency_us,
            Some(LatencySummaryAggregate {
                min: MetricSummary {
                    min: 5,
                    median: 10,
                    p95: 15,
                },
                median: MetricSummary {
                    min: 10,
                    median: 20,
                    p95: 30,
                },
                p95: MetricSummary {
                    min: 20,
                    median: 30,
                    p95: 40,
                },
                p99: MetricSummary {
                    min: 30,
                    median: 40,
                    p95: 50,
                },
            })
        );
    }
}
