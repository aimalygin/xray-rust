use std::collections::VecDeque;
use std::fs;
use std::future::Future;
use std::hint::black_box;
use std::io::{self, Write as IoWrite};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
#[cfg(unix)]
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
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
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use xray_config::{
    parse_xray_json, CoreConfig, InboundConfig, InboundProtocol, IpCidr, IpMatcher,
    Network as ConfigNetwork, OutboundConfig, OutboundSettings, RoutingConfig, RoutingRule,
    StreamSecurity, StreamSettings,
};
use xray_core_rs::{Core, OutboundRouter, StartupProbeOptions};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, read_udp_packet, read_xudp_packet,
    unpad_vision_block, VisionCommand, VisionPadding,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_utls::{normalize_reality_supported_fingerprint, XRAY_REALITY_CAPABLE_FINGERPRINTS};

pub mod chart;

const USAGE: &str = "usage: xray-bench run|compare|route-probe|reality-matrix|chart [options]";
const TEST_VLESS_UUID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const TEST_VLESS_UUID_STRING: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
// The PQ benchmark cases need a cover origin that accepts X25519MLKEM;
// RFC 2606 example origins reject the `hellochrome_120_pq` handshake.
const REALITY_SERVER_NAME: &str = "www.google.com";
const REALITY_PRIVATE_KEY: &str = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks";
const REALITY_PUBLIC_KEY: &str = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM";
const REALITY_SHORT_ID_HEX: &str = "0123456789abcdef";
const SING_BOX_BUILD_TAGS: &str = "with_gvisor,with_utls,badlinkname,tfogo_checklinkname0";
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const DARWIN_UTUN_HEADER_LEN: usize = 4;
const REALITY_MATRIX_SOCKS_TAG: &str = "socks-in";
const REALITY_MATRIX_OUTBOUND_TAG: &str = "proxy";
const DEFAULT_REALITY_MATRIX_SMALL_PAYLOAD_SIZE: usize = 1024;
const DEFAULT_REALITY_MATRIX_BODY_BYTES: usize = 1024 * 1024;

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
    RouteProbe(RouteProbeOptions),
    RealityMatrix(RealityMatrixOptions),
    Chart(chart::ChartOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    XrayRust,
    XrayCore,
    SingBox,
}

impl EngineKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::XrayRust => "xray-rust",
            Self::XrayCore => "xray-core",
            Self::SingBox => "sing-box",
        }
    }

    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "xray-rust" => Ok(Self::XrayRust),
            "xray-core" => Ok(Self::XrayCore),
            "sing-box" => Ok(Self::SingBox),
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
    TcpBulkThroughput,
    RoutedTcpFreedom,
    ManyIdleFlows,
    ReconnectBurst,
    MixedLongLived,
    UdpFreedom,
    TunUdpFreedom,
    TunTcpFreedom,
    TunTcpStaleFlows,
    TunRealityBlackhole,
    UdpVless,
    UdpXudp,
    VisionXudp,
    RealityVisionXudp,
    RealityVisionBulk,
}

impl WorkloadKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::TcpFreedom => "tcp-freedom",
            Self::TcpBulkThroughput => "tcp-bulk-throughput",
            Self::RoutedTcpFreedom => "routed-tcp-freedom",
            Self::ManyIdleFlows => "many-idle-flows",
            Self::ReconnectBurst => "reconnect-burst",
            Self::MixedLongLived => "mixed-long-lived",
            Self::UdpFreedom => "udp-freedom",
            Self::TunUdpFreedom => "tun-udp-freedom",
            Self::TunTcpFreedom => "tun-tcp-freedom",
            Self::TunTcpStaleFlows => "tun-tcp-stale-flows",
            Self::TunRealityBlackhole => "tun-reality-blackhole",
            Self::UdpVless => "udp-vless",
            Self::UdpXudp => "udp-xudp",
            Self::VisionXudp => "vision-xudp",
            Self::RealityVisionXudp => "reality-vision-xudp",
            Self::RealityVisionBulk => "reality-vision-bulk-throughput",
        }
    }

    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "idle" => Ok(Self::Idle),
            "tcp-freedom" => Ok(Self::TcpFreedom),
            "tcp-bulk-throughput" => Ok(Self::TcpBulkThroughput),
            "routed-tcp-freedom" => Ok(Self::RoutedTcpFreedom),
            "many-idle-flows" => Ok(Self::ManyIdleFlows),
            "reconnect-burst" => Ok(Self::ReconnectBurst),
            "mixed-long-lived" => Ok(Self::MixedLongLived),
            "udp-freedom" => Ok(Self::UdpFreedom),
            "tun-udp-freedom" => Ok(Self::TunUdpFreedom),
            "tun-tcp-freedom" => Ok(Self::TunTcpFreedom),
            "tun-tcp-stale-flows" => Ok(Self::TunTcpStaleFlows),
            "tun-reality-blackhole" => Ok(Self::TunRealityBlackhole),
            "udp-vless" => Ok(Self::UdpVless),
            "udp-xudp" => Ok(Self::UdpXudp),
            "vision-xudp" => Ok(Self::VisionXudp),
            "reality-vision-xudp" => Ok(Self::RealityVisionXudp),
            "reality-vision-bulk-throughput" => Ok(Self::RealityVisionBulk),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported workload `{other}`"
            ))),
        }
    }

    fn uses_tun_fd(&self) -> bool {
        matches!(
            self,
            Self::TunUdpFreedom
                | Self::TunTcpFreedom
                | Self::TunTcpStaleFlows
                | Self::TunRealityBlackhole
        )
    }

    fn supports_sing_box_process_engine(&self) -> bool {
        matches!(
            self,
            Self::Idle
                | Self::TcpFreedom
                | Self::TcpBulkThroughput
                | Self::ManyIdleFlows
                | Self::ReconnectBurst
                | Self::MixedLongLived
                | Self::UdpFreedom
                | Self::RealityVisionXudp
                | Self::RealityVisionBulk
        )
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
    pub sing_box_bin: Option<PathBuf>,
    pub sing_box_dir: Option<PathBuf>,
    pub tun_profile: Option<String>,
    pub no_auto_build: bool,
    pub geodata_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProbeOptions {
    pub iterations: usize,
    pub rules: usize,
    pub outbounds: usize,
    pub out_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum RealityMatrixTrafficKind {
    StartupProbe,
    TcpConnect,
    TcpEchoSmall,
    TcpEchoBody,
    HttpFirstByte,
    HttpBody,
    UdpXudpEcho,
}

impl RealityMatrixTrafficKind {
    const ALL: [Self; 7] = [
        Self::StartupProbe,
        Self::TcpConnect,
        Self::TcpEchoSmall,
        Self::TcpEchoBody,
        Self::HttpFirstByte,
        Self::HttpBody,
        Self::UdpXudpEcho,
    ];

    fn all() -> &'static [Self] {
        &Self::ALL
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::StartupProbe => "startup-probe",
            Self::TcpConnect => "tcp-connect",
            Self::TcpEchoSmall => "tcp-echo-small",
            Self::TcpEchoBody => "tcp-echo-body",
            Self::HttpFirstByte => "http-first-byte",
            Self::HttpBody => "http-body",
            Self::UdpXudpEcho => "udp-xudp-echo",
        }
    }

    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "startup-probe" | "probe" => Ok(Self::StartupProbe),
            "tcp-connect" => Ok(Self::TcpConnect),
            "tcp-echo-small" => Ok(Self::TcpEchoSmall),
            "tcp-echo-body" => Ok(Self::TcpEchoBody),
            "http-first-byte" => Ok(Self::HttpFirstByte),
            "http-body" => Ok(Self::HttpBody),
            "udp-xudp-echo" | "udp-echo" => Ok(Self::UdpXudpEcho),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported reality-matrix traffic `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityMatrixOptions {
    pub fingerprints: Vec<String>,
    pub traffic: Vec<RealityMatrixTrafficKind>,
    pub iterations: usize,
    pub small_payload_size: usize,
    pub body_bytes: usize,
    pub probe_timeout: Duration,
    pub run_timeout: Duration,
    pub out_dir: PathBuf,
    pub xray_core_bin: Option<PathBuf>,
    pub xray_core_dir: Option<PathBuf>,
    pub trace_traffic: bool,
    pub no_auto_build: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RealityMatrixResult {
    pub run_id: String,
    pub xray_core_server_addr: String,
    pub probe_url: String,
    pub fingerprints: Vec<String>,
    pub traffic: Vec<String>,
    pub cases: Vec<RealityMatrixCaseResult>,
    pub summary: RealityMatrixSummary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RealityMatrixCaseResult {
    pub fingerprint: String,
    pub traffic: String,
    pub status: String,
    pub duration_ms: u128,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_us: Option<LatencySummary>,
    pub setup_us: Option<FlowSetupSummary>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RealityMatrixSummary {
    pub fingerprints: usize,
    pub traffic: usize,
    pub cases: usize,
    pub ok: usize,
    pub failed: usize,
    pub skipped: usize,
}

#[derive(Debug, serde::Serialize)]
struct RealityMatrixTraceEvent<'a> {
    fingerprint: &'a str,
    traffic: &'a str,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iteration: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_sent_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_received_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_connections: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    elapsed_us: u128,
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
    #[serde(default)]
    pub throughput_mbps: Option<u128>,
    #[serde(default)]
    pub connections: u64,
    #[serde(default)]
    pub iterations: u64,
    #[serde(default)]
    pub payload_size: u64,
    pub latency_us: Option<LatencySummary>,
    pub setup_us: Option<FlowSetupSummary>,
    pub samples: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blackhole_connections_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blackhole_connections_active: Option<u64>,
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
    pub socks_method_us: u128,
    pub socks_connect_us: u128,
    pub socks_setup_us: u128,
    pub total_us: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlowSetupSummary {
    pub tcp_connect_us: LatencySummary,
    pub socks_method_us: LatencySummary,
    pub socks_connect_us: LatencySummary,
    pub socks_setup_us: LatencySummary,
    pub total_us: LatencySummary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlowSetupSummaryAggregate {
    pub tcp_connect_us: LatencySummaryAggregate,
    pub socks_method_us: LatencySummaryAggregate,
    pub socks_connect_us: LatencySummaryAggregate,
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
    #[serde(default)]
    pub throughput_mbps: Option<MetricSummary>,
    #[serde(default)]
    pub connections: u64,
    #[serde(default)]
    pub iterations: u64,
    #[serde(default)]
    pub payload_size: u64,
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
    pub blackhole_connections_accepted: Option<u64>,
    pub blackhole_connections_active: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocksSetupStageSample {
    method_us: u128,
    connect_us: u128,
    total_us: u128,
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
        self.blackhole_connections_accepted = other
            .blackhole_connections_accepted
            .or(self.blackhole_connections_accepted);
        self.blackhole_connections_active = other
            .blackhole_connections_active
            .or(self.blackhole_connections_active);
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
    vless_tls_cert_sha256: Option<String>,
    tcp_blackhole_state: Option<Arc<TcpBlackholeState>>,
    tasks: Vec<JoinHandle<()>>,
    processes: Vec<FixtureProcess>,
}

#[derive(Debug, Default)]
pub struct TcpBlackholeState {
    accepted: AtomicU64,
    active: AtomicU64,
}

impl TcpBlackholeState {
    fn snapshot(&self) -> (u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.active.load(Ordering::Relaxed),
        )
    }
}

struct TcpBlackholeConnectionGuard {
    state: Arc<TcpBlackholeState>,
}

impl TcpBlackholeConnectionGuard {
    fn new(state: Arc<TcpBlackholeState>) -> Self {
        state.active.fetch_add(1, Ordering::Relaxed);
        Self { state }
    }
}

impl Drop for TcpBlackholeConnectionGuard {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct FixtureProcess {
    child: Child,
}

impl FixtureProcess {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl WorkloadFixture {
    async fn start(
        workload: WorkloadKind,
        options: &BenchOptions,
        run_dir: &Path,
        binary_dir: &Path,
    ) -> Result<Self, BenchError> {
        match workload {
            WorkloadKind::UdpVless => {
                let (vless_addr, task, _tls_cert_sha256) =
                    spawn_fake_vless_udp_server(VlessUdpServerMode::Udp).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: None,
                    tcp_blackhole_state: None,
                    tasks: vec![task],
                    processes: Vec::new(),
                })
            }
            WorkloadKind::UdpXudp => {
                let (vless_addr, task, _tls_cert_sha256) =
                    spawn_fake_vless_udp_server(VlessUdpServerMode::Xudp).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: None,
                    tcp_blackhole_state: None,
                    tasks: vec![task],
                    processes: Vec::new(),
                })
            }
            WorkloadKind::VisionXudp => {
                let (vless_addr, task, tls_cert_sha256) =
                    spawn_fake_vless_udp_server(VlessUdpServerMode::VisionXudp).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: tls_cert_sha256,
                    tcp_blackhole_state: None,
                    tasks: vec![task],
                    processes: Vec::new(),
                })
            }
            WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulk => {
                let (vless_addr, process) =
                    start_xray_core_reality_vision_server(options, run_dir, binary_dir).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: None,
                    tcp_blackhole_state: None,
                    tasks: Vec::new(),
                    processes: vec![process],
                })
            }
            WorkloadKind::TunRealityBlackhole => {
                let (vless_addr, task, state) = spawn_tcp_blackhole_server().await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: None,
                    tcp_blackhole_state: Some(state),
                    tasks: vec![task],
                    processes: Vec::new(),
                })
            }
            WorkloadKind::Idle
            | WorkloadKind::TcpFreedom
            | WorkloadKind::TcpBulkThroughput
            | WorkloadKind::RoutedTcpFreedom
            | WorkloadKind::ManyIdleFlows
            | WorkloadKind::ReconnectBurst
            | WorkloadKind::MixedLongLived
            | WorkloadKind::UdpFreedom
            | WorkloadKind::TunUdpFreedom
            | WorkloadKind::TunTcpFreedom
            | WorkloadKind::TunTcpStaleFlows => Ok(Self::default()),
        }
    }
}

impl Drop for WorkloadFixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for process in &mut self.processes {
            process.stop();
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
            sing_box_bin: None,
            sing_box_dir: None,
            tun_profile: None,
            no_auto_build: false,
            geodata_dir: None,
        }
    }
}

impl Default for RouteProbeOptions {
    fn default() -> Self {
        Self {
            iterations: 100_000,
            rules: 64,
            outbounds: 8,
            out_dir: PathBuf::from("target/benchmarks"),
        }
    }
}

impl Default for RealityMatrixOptions {
    fn default() -> Self {
        Self {
            fingerprints: XRAY_REALITY_CAPABLE_FINGERPRINTS
                .iter()
                .map(|fingerprint| (*fingerprint).to_owned())
                .collect(),
            traffic: RealityMatrixTrafficKind::all().to_vec(),
            iterations: 1,
            small_payload_size: DEFAULT_REALITY_MATRIX_SMALL_PAYLOAD_SIZE,
            body_bytes: DEFAULT_REALITY_MATRIX_BODY_BYTES,
            probe_timeout: Duration::from_secs(15),
            run_timeout: Duration::from_secs(30),
            out_dir: PathBuf::from("target/benchmarks"),
            xray_core_bin: None,
            xray_core_dir: None,
            trace_traffic: false,
            no_auto_build: false,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RouteProbeResult {
    pub iterations: usize,
    pub rules: usize,
    pub outbounds: usize,
    pub selected: usize,
    pub total_us: u128,
    pub avg_ns: u128,
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
    if command == "route-probe" {
        return parse_route_probe_args(&rest).map(CliArgs::RouteProbe);
    }
    if command == "reality-matrix" {
        return parse_reality_matrix_args(&rest).map(CliArgs::RealityMatrix);
    }
    if command == "chart" {
        return chart::parse_chart_args(&rest).map(CliArgs::Chart);
    }

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
                options.connections =
                    parse_nonzero_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--iterations" => {
                options.iterations =
                    parse_nonzero_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--payload-size" => {
                options.payload_size =
                    parse_nonzero_usize(required_value(&rest, &mut index, flag)?, flag)?;
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
            "--sing-box-bin" => {
                options.sing_box_bin =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--tun-profile" => {
                options.tun_profile = Some(required_value(&rest, &mut index, flag)?.to_owned());
            }
            "--sing-box-dir" => {
                options.sing_box_dir =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--no-auto-build" => {
                options.no_auto_build = true;
            }
            "--geodata-dir" => {
                options.geodata_dir = Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
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
                    "run requires --engine xray-rust|xray-core|sing-box".to_owned(),
                ));
            }
            Ok(CliArgs::Run(options))
        }
        "compare" => {
            options.engine = None;
            Ok(CliArgs::Compare(options))
        }
        "route-probe" => unreachable!("route-probe is parsed before engine benchmark options"),
        "reality-matrix" => {
            unreachable!("reality-matrix is parsed before engine benchmark options")
        }
        other => Err(BenchError::InvalidArguments(format!(
            "unknown command `{other}`\n{USAGE}"
        ))),
    }
}

fn parse_route_probe_args(args: &[String]) -> Result<RouteProbeOptions, BenchError> {
    let mut options = RouteProbeOptions::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--iterations" => {
                options.iterations =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--rules" => {
                options.rules = parse_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--outbounds" => {
                options.outbounds =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--out-dir" => {
                options.out_dir = PathBuf::from(required_value(args, &mut index, flag)?);
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{USAGE}"
                )));
            }
        }
    }
    Ok(options)
}

fn parse_reality_matrix_args(args: &[String]) -> Result<RealityMatrixOptions, BenchError> {
    let mut options = RealityMatrixOptions::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--fingerprints" => {
                options.fingerprints =
                    parse_reality_fingerprints_csv(required_value(args, &mut index, flag)?)?;
            }
            "--traffic" => {
                options.traffic =
                    parse_reality_matrix_traffic_csv(required_value(args, &mut index, flag)?)?;
            }
            "--iterations" => {
                options.iterations =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--small-payload-size" | "--payload-size" => {
                options.small_payload_size =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--body-bytes" => {
                options.body_bytes =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--probe-timeout-ms" => {
                options.probe_timeout = Duration::from_millis(parse_nonzero_u64(
                    required_value(args, &mut index, flag)?,
                    flag,
                )?);
            }
            "--run-timeout-ms" => {
                options.run_timeout = Duration::from_millis(parse_nonzero_u64(
                    required_value(args, &mut index, flag)?,
                    flag,
                )?);
            }
            "--out-dir" => {
                options.out_dir = PathBuf::from(required_value(args, &mut index, flag)?);
            }
            "--xray-core-bin" => {
                options.xray_core_bin =
                    Some(PathBuf::from(required_value(args, &mut index, flag)?));
            }
            "--xray-core-dir" => {
                options.xray_core_dir =
                    Some(PathBuf::from(required_value(args, &mut index, flag)?));
            }
            "--trace-traffic" => {
                options.trace_traffic = true;
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
    Ok(options)
}

fn parse_reality_fingerprints_csv(raw: &str) -> Result<Vec<String>, BenchError> {
    if raw == "all" {
        return Ok(RealityMatrixOptions::default().fingerprints);
    }

    let mut fingerprints = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some(fingerprint) = normalize_reality_supported_fingerprint(item) else {
            return Err(BenchError::InvalidArguments(format!(
                "unsupported REALITY fingerprint `{item}`"
            )));
        };
        if !fingerprints.iter().any(|existing| existing == fingerprint) {
            fingerprints.push(fingerprint.to_owned());
        }
    }
    if fingerprints.is_empty() {
        return Err(BenchError::InvalidArguments(
            "--fingerprints must include at least one fingerprint".to_owned(),
        ));
    }
    Ok(fingerprints)
}

fn parse_reality_matrix_traffic_csv(
    raw: &str,
) -> Result<Vec<RealityMatrixTrafficKind>, BenchError> {
    if raw == "all" {
        return Ok(RealityMatrixTrafficKind::all().to_vec());
    }

    let mut traffic = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let kind = RealityMatrixTrafficKind::parse(item)?;
        if !traffic.contains(&kind) {
            traffic.push(kind);
        }
    }
    if traffic.is_empty() {
        return Err(BenchError::InvalidArguments(
            "--traffic must include at least one traffic kind".to_owned(),
        ));
    }
    Ok(traffic)
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

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), BenchError> {
    let data = serde_json::to_vec_pretty(value)
        .map_err(|error| BenchError::InvalidArguments(format!("failed to encode json: {error}")))?;
    fs::write(path, data).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to write json `{}`: {error}",
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
    if results.iter().any(|result| {
        result.connections != first.connections
            || result.iterations != first.iterations
            || result.payload_size != first.payload_size
    }) {
        return Err(BenchError::InvalidArguments(
            "cannot summarize mixed workload parameters".to_owned(),
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
        throughput_mbps: summarize_optional_metric(
            results.iter().map(|result| result.throughput_mbps),
        ),
        connections: first.connections,
        iterations: first.iterations,
        payload_size: first.payload_size,
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
        socks_method_us: summarize_latency_us(samples.iter().map(|sample| sample.socks_method_us))?,
        socks_connect_us: summarize_latency_us(
            samples.iter().map(|sample| sample.socks_connect_us),
        )?,
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
        socks_method_us: summarize_latency_aggregates(
            setup.iter().map(|summary| &summary.socks_method_us),
        ),
        socks_connect_us: summarize_latency_aggregates(
            setup.iter().map(|summary| &summary.socks_connect_us),
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

fn throughput_mbps(bytes_sent: u64, bytes_received: u64, duration_ms: u128) -> Option<u128> {
    let bytes = u128::from(bytes_sent) + u128::from(bytes_received);
    if bytes == 0 || duration_ms == 0 {
        return None;
    }
    Some((bytes * 8).div_ceil(duration_ms * 1000))
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

pub async fn run_routed_tcp_freedom_workload(
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
    for index in 0..options.connections {
        let options = options.clone();
        let domain = if index % 2 == 0 {
            GEO_HIT_DOMAIN
        } else {
            GEO_MISS_DOMAIN
        };
        tasks.push(tokio::spawn(async move {
            run_routed_connection(socks_addr, domain, echo_addr.port(), &options).await
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("routed workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }
    echo_task.abort();

    Ok(outcome)
}

async fn run_routed_connection(
    socks_addr: SocketAddr,
    domain: &str,
    echo_port: u16,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let setup_started = Instant::now();
    let tcp_started = Instant::now();
    let mut client = TcpStream::connect(socks_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting to SOCKS inbound at {socks_addr}"),
            source,
        })?;
    let tcp_connect_us = tcp_started.elapsed().as_micros();
    let socks = socks5_connect_domain_measured(&mut client, domain, echo_port).await?;
    let setup_sample = FlowSetupSample {
        tcp_connect_us,
        socks_method_us: socks.method_us,
        socks_connect_us: socks.connect_us,
        socks_setup_us: socks.total_us,
        total_us: setup_started.elapsed().as_micros(),
    };

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
        setup_samples: vec![setup_sample],
        ..WorkloadOutcome::default()
    })
}

pub async fn run_tcp_bulk_throughput_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let template = Arc::new(bulk_pattern_template(options.payload_size));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding TCP bulk source server".to_owned(),
            source,
        })?;
    let source_addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading TCP bulk source server address".to_owned(),
        source,
    })?;
    let iterations = options.iterations;
    let source_template = Arc::clone(&template);
    let source_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let template = Arc::clone(&source_template);
            tokio::spawn(async move {
                for _ in 0..iterations {
                    if stream.write_all(&template).await.is_err() {
                        return;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    let mut tasks = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        let template = Arc::clone(&template);
        tasks.push(tokio::spawn(async move {
            run_tcp_bulk_connection(socks_addr, source_addr, &template, iterations).await
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("bulk workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }
    source_task.abort();

    Ok(outcome)
}

async fn run_tcp_bulk_connection(
    socks_addr: SocketAddr,
    source_addr: SocketAddr,
    template: &[u8],
    iterations: usize,
) -> Result<WorkloadOutcome, BenchError> {
    let mut client = TcpStream::connect(socks_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting to SOCKS inbound at {socks_addr}"),
            source,
        })?;
    socks5_connect(&mut client, source_addr).await?;
    let received = read_and_validate_bulk_stream(&mut client, template, iterations).await?;
    Ok(WorkloadOutcome {
        bytes_received: received,
        ..WorkloadOutcome::default()
    })
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
        ..WorkloadOutcome::default()
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
    run_tun_tcp_workload(tun_fd, options, TunTcpFlowDisposition::Abort, false).await
}

#[cfg(unix)]
pub async fn run_tun_tcp_stale_flows_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    run_tun_tcp_workload(tun_fd, options, TunTcpFlowDisposition::SilentDrop, true).await
}

#[cfg(unix)]
pub async fn run_tun_reality_blackhole_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
    blackhole_state: &TcpBlackholeState,
) -> Result<WorkloadOutcome, BenchError> {
    let target = SocketAddr::from((local_non_loopback_ipv4()?, 443));
    let payload = vec![0x5a; options.payload_size];
    let mut outcome = WorkloadOutcome::empty();

    for connection_index in 0..options.connections {
        let source_port = 49_152 + (connection_index % 10_000) as u16;
        let mut client = TunTcpBenchmarkClient::new(source_port);
        let setup_started = Instant::now();
        client.connect(target)?;
        pump_tun_tcp_until(tun_fd, &mut client, TunTcpBenchmarkClient::may_send).await?;
        outcome
            .latencies_us
            .push(setup_started.elapsed().as_micros());

        client.send_payload(&payload)?;
        outcome.bytes_sent += payload.len() as u64;
        pump_tun_tcp_for(tun_fd, &mut client, Duration::from_millis(5)).await?;
    }

    sleep(options.duration).await;
    let (accepted, active) = blackhole_state.snapshot();
    outcome.blackhole_connections_accepted = Some(accepted);
    outcome.blackhole_connections_active = Some(active);
    Ok(outcome)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunTcpFlowDisposition {
    Abort,
    SilentDrop,
}

#[cfg(unix)]
async fn run_tun_tcp_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
    disposition: TunTcpFlowDisposition,
    hold_after_open: bool,
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
            run_tun_tcp_freedom_connection(tun_fd, echo_target, source_port, options, disposition)
                .await
                .map_err(|error| {
                    BenchError::InvalidArguments(format!(
                        "TUN TCP connection {connection_index} (source port {source_port}, target {echo_target}) failed: {error}"
                    ))
                })?;
        outcome.extend(connection_outcome);
    }
    if hold_after_open {
        sleep(options.duration).await;
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

#[cfg(not(unix))]
pub async fn run_tun_tcp_stale_flows_workload(
    _tun_fd: i32,
    _options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-tcp-stale-flows workload requires Unix fd support".to_owned(),
    ))
}

#[cfg(not(unix))]
pub async fn run_tun_reality_blackhole_workload(
    _tun_fd: i32,
    _options: &BenchOptions,
    _blackhole_state: &TcpBlackholeState,
) -> Result<WorkloadOutcome, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-reality-blackhole workload requires Unix fd support".to_owned(),
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

pub async fn run_reality_vision_xudp_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding Reality Vision UDP echo server".to_owned(),
            source,
        })?;
    let echo_addr = echo_socket.local_addr().map_err(|source| BenchError::Io {
        action: "reading Reality Vision UDP echo server address".to_owned(),
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
            BenchError::InvalidArguments(format!(
                "reality vision xudp workload task failed: {error}"
            ))
        })??;
        outcome.extend(task_outcome);
    }
    echo_task.abort();

    Ok(outcome)
}

const BULK_PATTERN_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

fn bulk_pattern_template(payload_size: usize) -> Vec<u8> {
    let mut state = BULK_PATTERN_SEED;
    let mut template = Vec::with_capacity(payload_size);
    for _ in 0..payload_size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        template.push((state >> 32) as u8);
    }
    template
}

async fn read_and_validate_bulk_stream<R>(
    reader: &mut R,
    template: &[u8],
    iterations: usize,
) -> Result<u64, BenchError>
where
    R: AsyncRead + Unpin,
{
    let mut received = 0u64;
    // Chunk == template so validation is one slice comparison per chunk,
    // keeping harness-side CPU out of the measured transfer.
    let mut chunk = vec![0; template.len()];
    for _ in 0..iterations {
        reader
            .read_exact(&mut chunk)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading bulk stream chunk".to_owned(),
                source,
            })?;
        if chunk != template {
            return Err(BenchError::InvalidArguments(
                "bulk stream payload mismatch".to_owned(),
            ));
        }
        received += chunk.len() as u64;
    }
    Ok(received)
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
        ..WorkloadOutcome::default()
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
    let socks = socks5_connect_measured(&mut client, target_addr).await?;
    Ok((
        client,
        FlowSetupSample {
            tcp_connect_us,
            socks_method_us: socks.method_us,
            socks_connect_us: socks.connect_us,
            socks_setup_us: socks.total_us,
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
        ..WorkloadOutcome::default()
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
        ..WorkloadOutcome::default()
    })
}

#[cfg(unix)]
async fn run_tun_tcp_freedom_connection(
    tun_fd: RawFd,
    echo_addr: SocketAddr,
    source_port: u16,
    options: &BenchOptions,
    disposition: TunTcpFlowDisposition,
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

    if disposition == TunTcpFlowDisposition::Abort {
        client.abort();
        pump_tun_tcp_for(tun_fd, &mut client, Duration::from_millis(5)).await?;
    } else {
        // Flush the client's final ACK before dropping its local state. The
        // server-side TUN flow then stays genuinely idle during the hold phase
        // instead of spending the measurement window retransmitting echo data.
        pump_tun_tcp_for(tun_fd, &mut client, Duration::from_millis(5)).await?;
    }

    Ok(outcome)
}

async fn socks5_connect(client: &mut TcpStream, target: SocketAddr) -> Result<(), BenchError> {
    socks5_connect_measured(client, target).await.map(|_| ())
}

async fn socks5_connect_measured(
    client: &mut TcpStream,
    target: SocketAddr,
) -> Result<SocksSetupStageSample, BenchError> {
    let SocketAddr::V4(target) = target else {
        return Err(BenchError::InvalidArguments(
            "tcp-freedom workload currently uses IPv4 echo targets".to_owned(),
        ));
    };

    let started = Instant::now();
    let method_started = Instant::now();
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
    let method_us = method_started.elapsed().as_micros();

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    let connect_started = Instant::now();
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
    let connect_us = connect_started.elapsed().as_micros();

    Ok(SocksSetupStageSample {
        method_us,
        connect_us,
        total_us: started.elapsed().as_micros(),
    })
}

async fn socks5_connect_domain_measured<S>(
    client: &mut S,
    domain: &str,
    port: u16,
) -> Result<SocksSetupStageSample, BenchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if domain.len() > 255 {
        return Err(BenchError::InvalidArguments(
            "SOCKS domain target exceeds 255 bytes".to_owned(),
        ));
    }
    let started = Instant::now();
    let method_started = Instant::now();
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
    let method_us = method_started.elapsed().as_micros();

    let mut request = vec![5, 1, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    let connect_started = Instant::now();
    client
        .write_all(&request)
        .await
        .map_err(|source| BenchError::Io {
            action: "writing SOCKS connect".to_owned(),
            source,
        })?;
    read_socks5_reply(client).await?;
    let connect_us = connect_started.elapsed().as_micros();

    Ok(SocksSetupStageSample {
        method_us,
        connect_us,
        total_us: started.elapsed().as_micros(),
    })
}

async fn read_socks5_reply<S>(client: &mut S) -> Result<(), BenchError>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0; 4];
    client
        .read_exact(&mut head)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS connect response".to_owned(),
            source,
        })?;
    if head[..2] != [5, 0] {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected SOCKS connect response {head:?}"
        )));
    }
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0; 1];
            client
                .read_exact(&mut len)
                .await
                .map_err(|source| BenchError::Io {
                    action: "reading SOCKS reply domain length".to_owned(),
                    source,
                })?;
            len[0] as usize
        }
        other => {
            return Err(BenchError::InvalidArguments(format!(
                "unsupported SOCKS reply address type {other}"
            )));
        }
    };
    let mut rest = vec![0; addr_len + 2];
    client
        .read_exact(&mut rest)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS reply address".to_owned(),
            source,
        })?;
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

    fn abort(&mut self) {
        self.sockets.get_mut::<smol_tcp::Socket>(self.tcp).abort();
    }

    fn accepts_packet(&self, packet: &[u8]) -> bool {
        ipv4_tcp_destination_port(packet) == Some(self.source_port)
    }

    fn poll(&mut self) {
        let _ = self
            .iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }
}

#[cfg(unix)]
fn ipv4_tcp_destination_port(packet: &[u8]) -> Option<u16> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != TCP_PROTOCOL {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 4 {
        return None;
    }
    Some(u16::from_be_bytes([
        packet[header_len + 2],
        packet[header_len + 3],
    ]))
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
        pump_tun_tcp_once(tun_fd, client, &mut buffer)?;

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
async fn pump_tun_tcp_for(
    tun_fd: RawFd,
    client: &mut TunTcpBenchmarkClient,
    duration: Duration,
) -> Result<(), BenchError> {
    let deadline = Instant::now() + duration;
    let mut buffer = vec![0; 65_535 + DARWIN_UTUN_HEADER_LEN];
    loop {
        pump_tun_tcp_once(tun_fd, client, &mut buffer)?;
        if Instant::now() >= deadline {
            return Ok(());
        }
        sleep(Duration::from_millis(1)).await;
    }
}

#[cfg(unix)]
fn pump_tun_tcp_once(
    tun_fd: RawFd,
    client: &mut TunTcpBenchmarkClient,
    buffer: &mut [u8],
) -> Result<(), BenchError> {
    client.poll();
    while let Some(packet) = client.device.pop_outbound() {
        write_tun_frame(tun_fd, &encode_darwin_utun_frame(&packet))?;
    }
    while let Some(len) = read_tun_frame(tun_fd, buffer)? {
        let packet = decode_darwin_utun_frame(&buffer[..len])?;
        if client.accepts_packet(packet) {
            client.device.push_inbound(Bytes::copy_from_slice(packet));
        }
    }
    client.poll();
    Ok(())
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

async fn spawn_tcp_blackhole_server(
) -> Result<(SocketAddr, JoinHandle<()>, Arc<TcpBlackholeState>), BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding TCP blackhole server".to_owned(),
            source,
        })?;
    let addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading TCP blackhole server address".to_owned(),
        source,
    })?;
    let state = Arc::new(TcpBlackholeState::default());
    let task_state = state.clone();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut stream, _peer)) = accepted else {
                        break;
                    };
                    task_state.accepted.fetch_add(1, Ordering::Relaxed);
                    let connection_state = task_state.clone();
                    connections.spawn(async move {
                        let _guard = TcpBlackholeConnectionGuard::new(connection_state);
                        let mut buffer = [0; 4096];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });

    Ok((addr, task, state))
}

async fn spawn_fake_vless_udp_server(
    mode: VlessUdpServerMode,
) -> Result<(SocketAddr, JoinHandle<()>, Option<String>), BenchError> {
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
    let (tls_acceptor, tls_cert_sha256) = match mode {
        VlessUdpServerMode::VisionXudp => {
            let config = fake_tls_server_config()?;
            (
                Some(TlsAcceptor::from(config.config)),
                Some(config.cert_sha256),
            )
        }
        VlessUdpServerMode::Udp | VlessUdpServerMode::Xudp => (None, None),
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

    Ok((addr, task, tls_cert_sha256))
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

struct FakeTlsServerConfig {
    config: Arc<rustls::ServerConfig>,
    cert_sha256: String,
}

fn fake_tls_server_config() -> Result<FakeTlsServerConfig, BenchError> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["vless.test".to_owned()]).map_err(|error| {
            BenchError::InvalidArguments(format!("generating fake TLS certificate: {error}"))
        })?;
    let cert_der = cert.der().clone();
    let cert_sha256 = hex_lower(&Sha256::digest(cert_der.as_ref()));
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| BenchError::InvalidArguments(format!("building TLS versions: {error}")))?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .map_err(|error| BenchError::InvalidArguments(format!("building TLS server: {error}")))?;
    Ok(FakeTlsServerConfig {
        config: Arc::new(config),
        cert_sha256,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulk => {
            reality_vision_xudp_config(port, SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
        WorkloadKind::TunUdpFreedom
        | WorkloadKind::TunTcpFreedom
        | WorkloadKind::TunTcpStaleFlows => tun_freedom_config(),
        WorkloadKind::TunRealityBlackhole => {
            tun_reality_blackhole_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
        WorkloadKind::RoutedTcpFreedom => routed_freedom_config(port, EngineKind::XrayRust),
        WorkloadKind::Idle
        | WorkloadKind::TcpFreedom
        | WorkloadKind::TcpBulkThroughput
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

fn sing_box_config(
    port: u16,
    workload: WorkloadKind,
    fixture: &WorkloadFixture,
) -> Result<String, BenchError> {
    match workload {
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulk => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "{} workload requires a VLESS Reality server fixture",
                    workload.as_str()
                ))
            })?;
            Ok(sing_box_reality_vision_xudp_config(port, vless_addr))
        }
        _ if workload.supports_sing_box_process_engine() => Ok(sing_box_direct_config(port)),
        _ => Err(BenchError::InvalidArguments(format!(
            "unsupported sing-box workload `{}` in process-level comparison",
            workload.as_str()
        ))),
    }
}

fn engine_config(
    engine: EngineKind,
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
            match engine {
                EngineKind::XrayRust => Ok(vision_xudp_config(port, vless_addr)),
                EngineKind::XrayCore => {
                    let cert_sha256 =
                        fixture.vless_tls_cert_sha256.as_deref().ok_or_else(|| {
                            BenchError::InvalidArguments(
                            "xray-core vision-xudp workload requires fake VLESS TLS certificate pin"
                                .to_owned(),
                        )
                        })?;
                    Ok(xray_core_vision_xudp_config(port, vless_addr, cert_sha256))
                }
                EngineKind::SingBox => Err(BenchError::InvalidArguments(
                    "vision-xudp workload is not supported by sing-box process engine".to_owned(),
                )),
            }
        }
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulk => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "{} workload requires a VLESS Reality server fixture",
                    workload.as_str()
                ))
            })?;
            Ok(reality_vision_xudp_config(port, vless_addr))
        }
        WorkloadKind::TunRealityBlackhole => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(
                    "tun-reality-blackhole workload requires a TCP blackhole fixture".to_owned(),
                )
            })?;
            Ok(tun_reality_blackhole_config(vless_addr))
        }
        WorkloadKind::TunUdpFreedom
        | WorkloadKind::TunTcpFreedom
        | WorkloadKind::TunTcpStaleFlows => Ok(tun_freedom_config()),
        WorkloadKind::RoutedTcpFreedom => Ok(routed_freedom_config(port, engine)),
        WorkloadKind::Idle
        | WorkloadKind::TcpFreedom
        | WorkloadKind::TcpBulkThroughput
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

fn sing_box_direct_config(port: u16) -> String {
    format!(
        r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [
    {{
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": {port}
    }}
  ],
  "outbounds": [
    {{
      "type": "direct",
      "tag": "direct"
    }}
  ],
  "route": {{ "final": "direct" }}
}}"#
    )
}

fn sing_box_reality_vision_xudp_config(port: u16, vless_addr: SocketAddr) -> String {
    format!(
        r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [
    {{
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": {port}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "proxy",
      "server": "{}",
      "server_port": {},
      "uuid": "{TEST_VLESS_UUID_STRING}",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "tls": {{
        "enabled": true,
        "server_name": "{REALITY_SERVER_NAME}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{REALITY_PUBLIC_KEY}",
          "short_id": "{REALITY_SHORT_ID_HEX}"
        }}
      }}
    }}
  ],
  "route": {{ "final": "proxy" }}
}}"#,
        vless_addr.ip(),
        vless_addr.port()
    )
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

fn tun_reality_blackhole_config(vless_addr: SocketAddr) -> String {
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "policy": {{
    "levels": {{
      "0": {{ "handshake": 1, "connIdle": 300 }}
    }}
  }},
  "inbounds": [
    {{
      "tag": "tun-in",
      "protocol": "tun",
      "listen": "127.0.0.1",
      "port": 0,
      "settings": {{ "name": "utun9", "MTU": 1500, "userLevel": 0 }}
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
                "id": "{TEST_VLESS_UUID_STRING}",
                "encryption": "none",
                "flow": "xtls-rprx-vision",
                "level": 0
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "serverName": "{REALITY_SERVER_NAME}",
          "fingerprint": "chrome",
          "publicKey": "{REALITY_PUBLIC_KEY}",
          "shortId": "{REALITY_SHORT_ID_HEX}",
          "spiderX": "/"
        }}
      }}
    }}
  ]
}}"#,
        vless_addr.ip(),
        vless_addr.port()
    )
}

const GEO_HIT_DOMAIN: &str = "baidu.com";
const GEO_MISS_DOMAIN: &str = "bench-miss.invalid";

fn routed_freedom_config(port: u16, engine: EngineKind) -> String {
    // xray-rust freedom settings accept no fields; Xray-core needs UseIP so
    // its dns app (hosts-first) resolves instead of the OS resolver.
    let freedom_settings = match engine {
        EngineKind::XrayCore => r#"{ "domainStrategy": "UseIP" }"#,
        _ => "{}",
    };
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "dns": {{
    "hosts": {{
      "full:{GEO_HIT_DOMAIN}": "127.0.0.1",
      "full:{GEO_MISS_DOMAIN}": "127.0.0.1"
    }}
  }},
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
    {{ "tag": "direct", "protocol": "freedom", "settings": {freedom_settings} }},
    {{ "tag": "direct-cn", "protocol": "freedom", "settings": {freedom_settings} }},
    {{ "tag": "direct-ads", "protocol": "freedom", "settings": {freedom_settings} }}
  ],
  "routing": {{
    "rules": [
      {{ "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "direct-ads" }},
      {{ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }},
      {{ "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct-cn" }},
      {{ "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct-cn" }}
    ]
  }}
}}"#
    )
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
    vision_xudp_config_with_tls_settings(
        port,
        vless_addr,
        r#""tlsSettings": { "serverName": "vless.test", "allowInsecure": true }"#,
    )
}

fn xray_core_vision_xudp_config(
    port: u16,
    vless_addr: SocketAddr,
    pinned_peer_cert_sha256: &str,
) -> String {
    vision_xudp_config_with_tls_settings(
        port,
        vless_addr,
        &format!(
            r#""tlsSettings": {{ "serverName": "vless.test", "pinnedPeerCertSha256": "{pinned_peer_cert_sha256}" }}"#
        ),
    )
}

fn vision_xudp_config_with_tls_settings(
    port: u16,
    vless_addr: SocketAddr,
    tls_settings: &str,
) -> String {
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
        {tls_settings}
      }}
    }}
  ]
}}"#,
        vless_addr.ip(),
        vless_addr.port()
    )
}

fn reality_vision_xudp_config(port: u16, vless_addr: SocketAddr) -> String {
    reality_vision_xudp_config_with_fingerprint(port, vless_addr, "chrome")
}

fn reality_vision_xudp_config_with_fingerprint(
    port: u16,
    vless_addr: SocketAddr,
    fingerprint: &str,
) -> String {
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
                "id": "{TEST_VLESS_UUID_STRING}",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "serverName": "{REALITY_SERVER_NAME}",
          "fingerprint": "{fingerprint}",
          "publicKey": "{REALITY_PUBLIC_KEY}",
          "shortId": "{REALITY_SHORT_ID_HEX}",
          "spiderX": "/"
        }}
      }}
    }}
  ]
}}"#,
        vless_addr.ip(),
        vless_addr.port()
    )
}

fn xray_core_reality_vision_server_config(port: u16) -> String {
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {port},
      "protocol": "vless",
      "settings": {{
        "clients": [
          {{
            "id": "{TEST_VLESS_UUID_STRING}",
            "flow": "xtls-rprx-vision"
          }}
        ],
        "decryption": "none"
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "show": true,
          "dest": "{REALITY_SERVER_NAME}:443",
          "serverNames": ["{REALITY_SERVER_NAME}"],
          "privateKey": "{REALITY_PRIVATE_KEY}",
          "shortIds": ["{REALITY_SHORT_ID_HEX}"],
          "type": "tcp"
        }}
      }}
    }}
  ],
  "outbounds": [
    {{
      "protocol": "freedom",
      "settings": {{
        "finalRules": [{{ "action": "allow" }}]
      }}
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

pub async fn wait_for_process_log_contains(
    child: &mut Child,
    stdout_path: &Path,
    stderr_path: &Path,
    pattern: &str,
    wait_timeout: Duration,
) -> Result<(), BenchError> {
    let deadline = Instant::now() + wait_timeout;
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

        let stdout = fs::read_to_string(stdout_path).unwrap_or_default();
        let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
        if stdout.contains(pattern) || stderr.contains(pattern) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(BenchError::Timeout {
                timeout_ms: wait_timeout.as_millis(),
            });
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn start_xray_core_reality_vision_server(
    options: &BenchOptions,
    run_dir: &Path,
    binary_dir: &Path,
) -> Result<(SocketAddr, FixtureProcess), BenchError> {
    let fixture_dir = run_dir.join("fixture").join("reality-vision-server");
    fs::create_dir_all(&fixture_dir).map_err(|source| BenchError::Io {
        action: format!("creating fixture directory `{}`", fixture_dir.display()),
        source,
    })?;
    let port = allocate_loopback_port()?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config_path = fixture_dir.join("config.json");
    fs::write(&config_path, xray_core_reality_vision_server_config(port)).map_err(|source| {
        BenchError::Io {
            action: format!("writing fixture config `{}`", config_path.display()),
            source,
        }
    })?;
    let stdout_path = fixture_dir.join("stdout.log");
    let stderr_path = fixture_dir.join("stderr.log");
    let stdout = fs::File::create(&stdout_path).map_err(|source| BenchError::Io {
        action: format!("creating fixture stdout log `{}`", stdout_path.display()),
        source,
    })?;
    let stderr = fs::File::create(&stderr_path).map_err(|source| BenchError::Io {
        action: format!("creating fixture stderr log `{}`", stderr_path.display()),
        source,
    })?;
    let fixture_binary_dir = binary_dir.join("xray-core-fixture");
    let binary = ensure_xray_core_binary(options, &fixture_binary_dir)?;
    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|source| BenchError::Io {
            action: format!("spawning fixture `{}`", binary.display()),
            source,
        })?;

    wait_for_process_log_contains(
        &mut child,
        &stdout_path,
        &stderr_path,
        "started",
        Duration::from_secs(10),
    )
    .await?;

    Ok((addr, FixtureProcess { child }))
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

pub fn ensure_sing_box_binary(
    options: &BenchOptions,
    bin_dir: &Path,
) -> Result<PathBuf, BenchError> {
    if let Some(path) = &options.sing_box_bin {
        return Ok(path.clone());
    }

    let checkout = options
        .sing_box_dir
        .clone()
        .or_else(default_sing_box_dir)
        .ok_or_else(|| {
            BenchError::InvalidArguments(
                "sing-box checkout not found; pass --sing-box-dir or --sing-box-bin".to_owned(),
            )
        })?;

    let checkout_binary = checkout.join(format!("sing-box{}", std::env::consts::EXE_SUFFIX));
    if checkout_binary.exists() {
        return Ok(checkout_binary);
    }
    if options.no_auto_build {
        return Err(BenchError::InvalidArguments(
            "sing-box binary requires --sing-box-bin when --no-auto-build is set".to_owned(),
        ));
    }

    let bin_dir = absolute_path(bin_dir)?;
    fs::create_dir_all(&bin_dir).map_err(|source| BenchError::Io {
        action: format!("creating binary directory `{}`", bin_dir.display()),
        source,
    })?;
    let binary = bin_dir.join(format!("sing-box{}", std::env::consts::EXE_SUFFIX));
    if binary.exists() {
        return Ok(binary);
    }
    run_command(
        "go",
        Command::new("go")
            .arg("build")
            .arg("-tags")
            .arg(sing_box_build_tags())
            .arg("-o")
            .arg(&binary)
            .arg("./cmd/sing-box")
            .current_dir(&checkout),
    )?;
    Ok(binary)
}

fn sing_box_build_tags() -> &'static str {
    SING_BOX_BUILD_TAGS
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

fn geodata_dir_for(options: &BenchOptions) -> Result<PathBuf, BenchError> {
    options.geodata_dir.clone().ok_or_else(|| {
        BenchError::InvalidArguments(
            "routed-tcp-freedom requires --geodata-dir <dir> containing geosite.dat and geoip.dat"
                .to_owned(),
        )
    })
}

// xray-rust resolves geodata relative to the config file's directory, so the
// files are staged (hardlinked, falling back to copy) into the run dir.
fn stage_geodata(options: &BenchOptions, run_dir: &Path) -> Result<(), BenchError> {
    let geodata_dir = geodata_dir_for(options)?;
    for name in ["geosite.dat", "geoip.dat"] {
        let source_path = geodata_dir.join(name);
        if !source_path.is_file() {
            return Err(BenchError::InvalidArguments(format!(
                "missing geodata file `{}`; pass --geodata-dir pointing at geosite.dat and geoip.dat",
                source_path.display()
            )));
        }
        let destination = run_dir.join(name);
        if destination.exists() {
            continue;
        }
        if fs::hard_link(&source_path, &destination).is_err() {
            fs::copy(&source_path, &destination).map_err(|source| BenchError::Io {
                action: format!(
                    "copying geodata `{}` into `{}`",
                    source_path.display(),
                    destination.display()
                ),
                source,
            })?;
        }
    }
    Ok(())
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
            engine_config(kind, port, options.workload, fixture)?
        }
        EngineKind::SingBox => sing_box_config(port, options.workload, fixture)?,
    };
    let config_path = run_dir.join("config.json");
    fs::write(&config_path, config).map_err(|source| BenchError::Io {
        action: format!("writing config `{}`", config_path.display()),
        source,
    })?;
    if options.workload == WorkloadKind::RoutedTcpFreedom && kind == EngineKind::XrayRust {
        stage_geodata(options, run_dir)?;
    }
    let stdout_path = run_dir.join("stdout.log");
    let stderr_path = run_dir.join("stderr.log");
    let binary = match kind {
        EngineKind::XrayRust => ensure_xray_rust_binary(options)?,
        EngineKind::XrayCore => ensure_xray_core_binary(options, binary_dir)?,
        EngineKind::SingBox => ensure_sing_box_binary(options, binary_dir)?,
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
    command.arg("run");
    match kind {
        EngineKind::XrayRust | EngineKind::XrayCore => {
            command.arg("-config");
        }
        EngineKind::SingBox => {
            command.arg("-c");
        }
    };
    command
        .arg(&config_path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(pair) = tun_pair.as_ref() {
        configure_tun_fd_env(&mut command, pair);
    }
    if let Some(profile) = options.tun_profile.as_deref() {
        command.env("XRAY_TUN_PROFILE", profile);
    }
    if options.workload == WorkloadKind::RoutedTcpFreedom && kind == EngineKind::XrayCore {
        let geodata_dir = geodata_dir_for(options)?;
        command.env("XRAY_LOCATION_ASSET", absolute_path(&geodata_dir)?);
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

fn default_sing_box_dir() -> Option<PathBuf> {
    let root = workspace_root().ok()?;
    let candidates = [
        root.join("sing-box"),
        root.parent()?.join("sing-box"),
        root.parent()?.parent()?.join("sing-box"),
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
                BenchError::InvalidArguments(
                    "run requires --engine xray-rust|xray-core|sing-box".to_owned(),
                )
            })?;
            let run_id = new_run_id();
            let summary = run_engine_series(engine, &options, &run_id).await?;
            print_summary(&summary);
            Ok(())
        }
        CliArgs::Compare(options) => run_compare(options).await,
        CliArgs::RouteProbe(options) => {
            let result = run_route_probe(&options)?;
            print_route_probe_result(&result);
            Ok(())
        }
        CliArgs::RealityMatrix(options) => {
            let result = run_reality_matrix(options).await?;
            print_reality_matrix_result(&result);
            Ok(())
        }
        CliArgs::Chart(options) => chart::run_chart(&options),
    }
}

pub fn run_route_probe(options: &RouteProbeOptions) -> Result<RouteProbeResult, BenchError> {
    let config = Arc::new(route_probe_config(options.rules, options.outbounds)?);
    let outbound_router = OutboundRouter::new(config);
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        443,
        RoutingNetwork::Tcp,
    );
    let inbound_tag = Some("bench-in");
    let started = Instant::now();
    let mut selected = 0;
    for _ in 0..options.iterations {
        let outbound = black_box(&outbound_router)
            .select_tcp_outbound_for_session(inbound_tag, black_box(&target))
            .map_err(|error| {
                BenchError::InvalidArguments(format!("route probe failed: {error}"))
            })?;
        if matches!(black_box(outbound), xray_core_rs::TcpOutbound::Freedom) {
            selected += 1;
        }
    }
    let elapsed = started.elapsed();
    let result = RouteProbeResult {
        iterations: options.iterations,
        rules: options.rules,
        outbounds: options.outbounds,
        selected,
        total_us: elapsed.as_micros(),
        avg_ns: elapsed.as_nanos() / options.iterations as u128,
    };

    let run_dir = options.out_dir.join(new_run_id()).join("route-probe");
    fs::create_dir_all(&run_dir).map_err(|source| BenchError::Io {
        action: format!("creating route-probe directory `{}`", run_dir.display()),
        source,
    })?;
    write_json(&run_dir.join("result.json"), &result)?;
    Ok(result)
}

pub async fn run_reality_matrix(
    options: RealityMatrixOptions,
) -> Result<RealityMatrixResult, BenchError> {
    let run_id = new_run_id();
    let run_dir = options.out_dir.join(&run_id).join("reality-matrix");
    fs::create_dir_all(&run_dir).map_err(|source| BenchError::Io {
        action: format!("creating reality-matrix directory `{}`", run_dir.display()),
        source,
    })?;
    let configs_dir = run_dir.join("configs");
    fs::create_dir_all(&configs_dir).map_err(|source| BenchError::Io {
        action: format!(
            "creating reality-matrix config directory `{}`",
            configs_dir.display()
        ),
        source,
    })?;
    let trace_path = options
        .trace_traffic
        .then(|| run_dir.join("traffic-trace.jsonl"));

    let fixture_options = reality_matrix_fixture_bench_options(&options);
    let binary_dir = run_dir.join("bin");
    let (vless_addr, _server) =
        start_xray_core_reality_vision_server(&fixture_options, &run_dir, &binary_dir).await?;
    let targets = RealityMatrixTargets::start(options.body_bytes, trace_path.clone()).await?;
    let mut cases = Vec::with_capacity(options.fingerprints.len() * options.traffic.len());
    let include_startup_case = options
        .traffic
        .contains(&RealityMatrixTrafficKind::StartupProbe);

    for fingerprint in &options.fingerprints {
        let config_json =
            reality_vision_xudp_config_with_fingerprint(0, vless_addr, fingerprint.as_str());
        let config_path = configs_dir.join(format!("{fingerprint}.json"));
        fs::write(&config_path, &config_json).map_err(|source| BenchError::Io {
            action: format!(
                "writing reality-matrix client config `{}`",
                config_path.display()
            ),
            source,
        })?;

        let config = match parse_reality_matrix_config(&config_json) {
            Ok(config) => config,
            Err(error) => {
                let reason = error.to_string();
                cases.push(failed_reality_matrix_case(
                    fingerprint,
                    RealityMatrixTrafficKind::StartupProbe,
                    Duration::ZERO,
                    reason.clone(),
                ));
                push_skipped_reality_matrix_traffic(&mut cases, fingerprint, &options, &reason);
                continue;
            }
        };

        let mut core = match Core::new(config) {
            Ok(core) => core,
            Err(error) => {
                let reason = format!("failed to create Core: {error}");
                cases.push(failed_reality_matrix_case(
                    fingerprint,
                    RealityMatrixTrafficKind::StartupProbe,
                    Duration::ZERO,
                    reason.clone(),
                ));
                push_skipped_reality_matrix_traffic(&mut cases, fingerprint, &options, &reason);
                continue;
            }
        };

        let startup_case =
            run_reality_matrix_startup_case(&mut core, fingerprint, &targets, &options).await;
        let startup_ok = startup_case.status == "ok";
        if include_startup_case || !startup_ok {
            cases.push(startup_case);
        }
        if !startup_ok {
            let reason = "startup probe failed".to_owned();
            push_skipped_reality_matrix_traffic(&mut cases, fingerprint, &options, &reason);
            continue;
        }

        let Some(socks_addr) = core.inbound_addr(Some(REALITY_MATRIX_SOCKS_TAG)) else {
            let reason = format!("missing `{REALITY_MATRIX_SOCKS_TAG}` inbound after Core start");
            push_skipped_reality_matrix_traffic(&mut cases, fingerprint, &options, &reason);
            let _ = core.stop().await;
            continue;
        };

        for traffic in &options.traffic {
            if *traffic == RealityMatrixTrafficKind::StartupProbe {
                continue;
            }
            let case = run_reality_matrix_traffic_case(
                fingerprint,
                *traffic,
                socks_addr,
                &targets,
                &options,
                trace_path.as_deref(),
            )
            .await;
            cases.push(case);
        }

        core.stop().await.map_err(|error| {
            BenchError::InvalidArguments(format!("failed to stop reality-matrix Core: {error}"))
        })?;
    }

    let summary =
        summarize_reality_matrix_cases(&cases, options.fingerprints.len(), options.traffic.len());
    let result = RealityMatrixResult {
        run_id,
        xray_core_server_addr: vless_addr.to_string(),
        probe_url: targets.probe_url.clone(),
        fingerprints: options.fingerprints.clone(),
        traffic: options
            .traffic
            .iter()
            .map(|traffic| traffic.as_str().to_owned())
            .collect(),
        cases,
        summary,
    };
    write_json(&run_dir.join("result.json"), &result)?;
    Ok(result)
}

fn reality_matrix_fixture_bench_options(options: &RealityMatrixOptions) -> BenchOptions {
    BenchOptions {
        workload: WorkloadKind::RealityVisionXudp,
        run_timeout: options.run_timeout,
        payload_size: options.small_payload_size,
        iterations: options.iterations,
        xray_core_bin: options.xray_core_bin.clone(),
        xray_core_dir: options.xray_core_dir.clone(),
        no_auto_build: options.no_auto_build,
        ..Default::default()
    }
}

fn parse_reality_matrix_config(raw: &str) -> Result<CoreConfig, BenchError> {
    parse_xray_json(raw)
        .map(|parsed| parsed.config)
        .map_err(|error| {
            let diagnostics = error
                .diagnostics
                .iter()
                .map(|diagnostic| match &diagnostic.path {
                    Some(path) => format!("{path}: {}", diagnostic.message),
                    None => diagnostic.message.clone(),
                })
                .collect::<Vec<_>>()
                .join("; ");
            BenchError::InvalidArguments(format!(
                "failed to parse reality-matrix client config: {diagnostics}"
            ))
        })
}

struct RealityMatrixTargets {
    tcp_echo_addr: SocketAddr,
    udp_echo_addr: SocketAddr,
    http_addr: SocketAddr,
    probe_url: String,
    tasks: Vec<JoinHandle<()>>,
}

impl RealityMatrixTargets {
    async fn start(body_bytes: usize, trace_path: Option<PathBuf>) -> Result<Self, BenchError> {
        let (tcp_echo_addr, tcp_task) = spawn_tcp_echo_server(trace_path).await?;
        let (udp_echo_addr, udp_task) = spawn_udp_echo_server().await?;
        let (http_addr, http_task) = spawn_reality_matrix_http_server(body_bytes).await?;
        Ok(Self {
            tcp_echo_addr,
            udp_echo_addr,
            http_addr,
            probe_url: format!("http://127.0.0.1:{}/generate_204", http_addr.port()),
            tasks: vec![tcp_task, udp_task, http_task],
        })
    }
}

impl Drop for RealityMatrixTargets {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn run_reality_matrix_startup_case(
    core: &mut Core,
    fingerprint: &str,
    targets: &RealityMatrixTargets,
    options: &RealityMatrixOptions,
) -> RealityMatrixCaseResult {
    core.set_startup_probe(Some(StartupProbeOptions {
        url: targets.probe_url.clone(),
        timeout: options.probe_timeout,
        outbound_tag: Some(REALITY_MATRIX_OUTBOUND_TAG.to_owned()),
    }));

    let started = Instant::now();
    match timeout(options.run_timeout, core.start()).await {
        Ok(Ok(())) => {
            let elapsed = started.elapsed();
            ok_reality_matrix_case(
                fingerprint,
                RealityMatrixTrafficKind::StartupProbe,
                elapsed,
                WorkloadOutcome {
                    bytes_sent: 0,
                    bytes_received: 0,
                    latencies_us: vec![elapsed.as_micros()],
                    setup_samples: Vec::new(),
                    ..WorkloadOutcome::default()
                },
            )
        }
        Ok(Err(error)) => {
            let _ = core.stop().await;
            failed_reality_matrix_case(
                fingerprint,
                RealityMatrixTrafficKind::StartupProbe,
                started.elapsed(),
                format!("Core startup probe failed: {error}"),
            )
        }
        Err(_) => {
            let _ = core.stop().await;
            failed_reality_matrix_case(
                fingerprint,
                RealityMatrixTrafficKind::StartupProbe,
                started.elapsed(),
                format!(
                    "Core startup timed out after {} ms",
                    options.run_timeout.as_millis()
                ),
            )
        }
    }
}

async fn run_reality_matrix_traffic_case(
    fingerprint: &str,
    traffic: RealityMatrixTrafficKind,
    socks_addr: SocketAddr,
    targets: &RealityMatrixTargets,
    options: &RealityMatrixOptions,
    trace_path: Option<&Path>,
) -> RealityMatrixCaseResult {
    let started = Instant::now();
    match timeout(
        options.run_timeout,
        run_reality_matrix_traffic_outcome(
            fingerprint,
            traffic,
            socks_addr,
            targets,
            options,
            trace_path,
        ),
    )
    .await
    {
        Ok(Ok(outcome)) => ok_reality_matrix_case(fingerprint, traffic, started.elapsed(), outcome),
        Ok(Err(error)) => {
            failed_reality_matrix_case(fingerprint, traffic, started.elapsed(), error.to_string())
        }
        Err(_) => failed_reality_matrix_case(
            fingerprint,
            traffic,
            started.elapsed(),
            format!(
                "traffic case timed out after {} ms",
                options.run_timeout.as_millis()
            ),
        ),
    }
}

async fn run_reality_matrix_traffic_outcome(
    fingerprint: &str,
    traffic: RealityMatrixTrafficKind,
    socks_addr: SocketAddr,
    targets: &RealityMatrixTargets,
    options: &RealityMatrixOptions,
    trace_path: Option<&Path>,
) -> Result<WorkloadOutcome, BenchError> {
    match traffic {
        RealityMatrixTrafficKind::StartupProbe => Ok(WorkloadOutcome::empty()),
        RealityMatrixTrafficKind::TcpConnect => {
            run_reality_matrix_tcp_connect(socks_addr, targets.tcp_echo_addr, options).await
        }
        RealityMatrixTrafficKind::TcpEchoSmall => {
            run_reality_matrix_tcp_echo(
                fingerprint,
                traffic,
                socks_addr,
                targets.tcp_echo_addr,
                options.small_payload_size,
                options.iterations,
                trace_path,
            )
            .await
        }
        RealityMatrixTrafficKind::TcpEchoBody => {
            run_reality_matrix_tcp_echo(
                fingerprint,
                traffic,
                socks_addr,
                targets.tcp_echo_addr,
                options.body_bytes,
                options.iterations,
                trace_path,
            )
            .await
        }
        RealityMatrixTrafficKind::HttpFirstByte => {
            run_reality_matrix_http_first_byte(socks_addr, targets.http_addr, options).await
        }
        RealityMatrixTrafficKind::HttpBody => {
            run_reality_matrix_http_body(socks_addr, targets.http_addr, options).await
        }
        RealityMatrixTrafficKind::UdpXudpEcho => {
            let bench_options = reality_matrix_fixture_bench_options(options);
            run_udp_freedom_connection(socks_addr, targets.udp_echo_addr, &bench_options).await
        }
    }
}

async fn run_reality_matrix_tcp_connect(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    options: &RealityMatrixOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let mut outcome = WorkloadOutcome::empty();
    for _ in 0..options.iterations {
        let (_client, setup_sample) = open_idle_socks_flow(socks_addr, target_addr).await?;
        outcome.latencies_us.push(setup_sample.total_us);
        outcome.setup_samples.push(setup_sample);
    }
    Ok(outcome)
}

async fn run_reality_matrix_tcp_echo(
    fingerprint: &str,
    traffic: RealityMatrixTrafficKind,
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload_size: usize,
    iterations: usize,
    trace_path: Option<&Path>,
) -> Result<WorkloadOutcome, BenchError> {
    let (mut client, setup_sample) = open_idle_socks_flow(socks_addr, target_addr).await?;
    let payload = vec![0x5a; payload_size];
    let mut echoed = vec![0; payload_size];
    let mut outcome = WorkloadOutcome::empty();
    outcome.setup_samples.push(setup_sample);
    let case_started = Instant::now();

    for iteration in 1..=iterations {
        let started = Instant::now();
        append_reality_matrix_trace_event(
            trace_path,
            &RealityMatrixTraceEvent {
                fingerprint,
                traffic: traffic.as_str(),
                event: "iteration_start",
                target: None,
                connection_id: None,
                peer_addr: None,
                iteration: Some(iteration),
                payload_bytes: Some(payload_size),
                bytes: None,
                bytes_sent_total: Some(outcome.bytes_sent),
                bytes_received_total: Some(outcome.bytes_received),
                active_connections: None,
                error: None,
                elapsed_us: case_started.elapsed().as_micros(),
            },
        )?;
        client
            .write_all(&payload)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing reality-matrix TCP payload".to_owned(),
                source,
            })?;
        outcome.bytes_sent += payload.len() as u64;
        append_reality_matrix_trace_event(
            trace_path,
            &RealityMatrixTraceEvent {
                fingerprint,
                traffic: traffic.as_str(),
                event: "iteration_write_done",
                target: None,
                connection_id: None,
                peer_addr: None,
                iteration: Some(iteration),
                payload_bytes: Some(payload_size),
                bytes: None,
                bytes_sent_total: Some(outcome.bytes_sent),
                bytes_received_total: Some(outcome.bytes_received),
                active_connections: None,
                error: None,
                elapsed_us: case_started.elapsed().as_micros(),
            },
        )?;
        client
            .read_exact(&mut echoed)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading reality-matrix TCP echo".to_owned(),
                source,
            })?;
        if echoed != payload {
            return Err(BenchError::InvalidArguments(
                "reality-matrix TCP echo payload mismatch".to_owned(),
            ));
        }
        outcome.bytes_received += echoed.len() as u64;
        outcome.latencies_us.push(started.elapsed().as_micros());
        append_reality_matrix_trace_event(
            trace_path,
            &RealityMatrixTraceEvent {
                fingerprint,
                traffic: traffic.as_str(),
                event: "iteration_read_done",
                target: None,
                connection_id: None,
                peer_addr: None,
                iteration: Some(iteration),
                payload_bytes: Some(payload_size),
                bytes: None,
                bytes_sent_total: Some(outcome.bytes_sent),
                bytes_received_total: Some(outcome.bytes_received),
                active_connections: None,
                error: None,
                elapsed_us: case_started.elapsed().as_micros(),
            },
        )?;
    }

    Ok(outcome)
}

fn reality_matrix_trace_event_json_line(
    event: &RealityMatrixTraceEvent<'_>,
) -> Result<String, BenchError> {
    let mut line = serde_json::to_string(event).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to encode reality-matrix trace event: {error}"
        ))
    })?;
    line.push('\n');
    Ok(line)
}

fn append_reality_matrix_trace_event(
    trace_path: Option<&Path>,
    event: &RealityMatrixTraceEvent<'_>,
) -> Result<(), BenchError> {
    let Some(trace_path) = trace_path else {
        return Ok(());
    };
    let line = reality_matrix_trace_event_json_line(event)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(trace_path)
        .map_err(|source| BenchError::Io {
            action: format!(
                "opening reality-matrix trace file `{}`",
                trace_path.display()
            ),
            source,
        })?;
    file.write_all(line.as_bytes())
        .map_err(|source| BenchError::Io {
            action: format!(
                "writing reality-matrix trace file `{}`",
                trace_path.display()
            ),
            source,
        })
}

#[allow(clippy::too_many_arguments)]
fn append_reality_matrix_tcp_target_trace_event(
    trace_path: Option<&Path>,
    event: &'static str,
    connection_id: u64,
    peer_addr: SocketAddr,
    bytes: Option<usize>,
    bytes_sent_total: u64,
    bytes_received_total: u64,
    active_connections: u64,
    error: Option<String>,
    trace_started: Instant,
) {
    let _ = append_reality_matrix_trace_event(
        trace_path,
        &RealityMatrixTraceEvent {
            fingerprint: "<target>",
            traffic: "tcp-echo-target",
            event,
            target: Some("tcp_echo"),
            connection_id: Some(connection_id),
            peer_addr: Some(peer_addr.to_string()),
            iteration: None,
            payload_bytes: None,
            bytes,
            bytes_sent_total: Some(bytes_sent_total),
            bytes_received_total: Some(bytes_received_total),
            active_connections: Some(active_connections),
            error,
            elapsed_us: trace_started.elapsed().as_micros(),
        },
    );
}

async fn run_reality_matrix_http_first_byte(
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    options: &RealityMatrixOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let mut outcome = WorkloadOutcome::empty();
    for _ in 0..options.iterations {
        let started = Instant::now();
        let (mut client, setup_sample) = open_idle_socks_flow(socks_addr, http_addr).await?;
        let request =
            b"GET /first-byte HTTP/1.1\r\nHost: reality-matrix.local\r\nConnection: close\r\n\r\n";
        client
            .write_all(request)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing reality-matrix HTTP first-byte request".to_owned(),
                source,
            })?;
        let body = read_http_response_body_bytes(&mut client, 1).await?;
        if body != [0x42] {
            return Err(BenchError::InvalidArguments(
                "reality-matrix HTTP first byte mismatch".to_owned(),
            ));
        }
        outcome.bytes_sent += request.len() as u64;
        outcome.bytes_received += body.len() as u64;
        outcome.latencies_us.push(started.elapsed().as_micros());
        outcome.setup_samples.push(setup_sample);
    }
    Ok(outcome)
}

async fn run_reality_matrix_http_body(
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    options: &RealityMatrixOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let mut outcome = WorkloadOutcome::empty();
    for _ in 0..options.iterations {
        let started = Instant::now();
        let (mut client, setup_sample) = open_idle_socks_flow(socks_addr, http_addr).await?;
        let request =
            b"GET /body HTTP/1.1\r\nHost: reality-matrix.local\r\nConnection: close\r\n\r\n";
        client
            .write_all(request)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing reality-matrix HTTP body request".to_owned(),
                source,
            })?;
        let body = read_http_response_body_bytes(&mut client, options.body_bytes).await?;
        if body.iter().any(|byte| *byte != 0x7b) {
            return Err(BenchError::InvalidArguments(
                "reality-matrix HTTP body mismatch".to_owned(),
            ));
        }
        outcome.bytes_sent += request.len() as u64;
        outcome.bytes_received += body.len() as u64;
        outcome.latencies_us.push(started.elapsed().as_micros());
        outcome.setup_samples.push(setup_sample);
    }
    Ok(outcome)
}

async fn spawn_tcp_echo_server(
    trace_path: Option<PathBuf>,
) -> Result<(SocketAddr, JoinHandle<()>), BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding reality-matrix TCP echo server".to_owned(),
            source,
        })?;
    let addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading reality-matrix TCP echo server address".to_owned(),
        source,
    })?;
    let next_connection_id = Arc::new(AtomicU64::new(1));
    let active_connections = Arc::new(AtomicU64::new(0));
    let trace_started = Instant::now();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, peer_addr)) = listener.accept().await {
            let connection_id = next_connection_id.fetch_add(1, Ordering::Relaxed);
            let active = active_connections.fetch_add(1, Ordering::SeqCst) + 1;
            append_reality_matrix_tcp_target_trace_event(
                trace_path.as_deref(),
                "target_accept",
                connection_id,
                peer_addr,
                None,
                0,
                0,
                active,
                None,
                trace_started,
            );
            let trace_path = trace_path.clone();
            let active_connections = active_connections.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0; 64 * 1024];
                let mut bytes_received_total = 0u64;
                let mut bytes_sent_total = 0u64;
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) => {
                            append_reality_matrix_tcp_target_trace_event(
                                trace_path.as_deref(),
                                "target_eof",
                                connection_id,
                                peer_addr,
                                None,
                                bytes_sent_total,
                                bytes_received_total,
                                active_connections.load(Ordering::SeqCst),
                                None,
                                trace_started,
                            );
                            break;
                        }
                        Err(error) => {
                            append_reality_matrix_tcp_target_trace_event(
                                trace_path.as_deref(),
                                "target_read_error",
                                connection_id,
                                peer_addr,
                                None,
                                bytes_sent_total,
                                bytes_received_total,
                                active_connections.load(Ordering::SeqCst),
                                Some(error.to_string()),
                                trace_started,
                            );
                            break;
                        }
                        Ok(len) => {
                            bytes_received_total += len as u64;
                            append_reality_matrix_tcp_target_trace_event(
                                trace_path.as_deref(),
                                "target_read",
                                connection_id,
                                peer_addr,
                                Some(len),
                                bytes_sent_total,
                                bytes_received_total,
                                active_connections.load(Ordering::SeqCst),
                                None,
                                trace_started,
                            );
                            if stream.write_all(&buffer[..len]).await.is_err() {
                                append_reality_matrix_tcp_target_trace_event(
                                    trace_path.as_deref(),
                                    "target_write_error",
                                    connection_id,
                                    peer_addr,
                                    Some(len),
                                    bytes_sent_total,
                                    bytes_received_total,
                                    active_connections.load(Ordering::SeqCst),
                                    None,
                                    trace_started,
                                );
                                break;
                            }
                            bytes_sent_total += len as u64;
                            append_reality_matrix_tcp_target_trace_event(
                                trace_path.as_deref(),
                                "target_write_done",
                                connection_id,
                                peer_addr,
                                Some(len),
                                bytes_sent_total,
                                bytes_received_total,
                                active_connections.load(Ordering::SeqCst),
                                None,
                                trace_started,
                            );
                        }
                    }
                }
                let active = active_connections
                    .fetch_sub(1, Ordering::SeqCst)
                    .saturating_sub(1);
                append_reality_matrix_tcp_target_trace_event(
                    trace_path.as_deref(),
                    "target_closed",
                    connection_id,
                    peer_addr,
                    None,
                    bytes_sent_total,
                    bytes_received_total,
                    active,
                    None,
                    trace_started,
                );
            });
        }
    });
    Ok((addr, task))
}

async fn spawn_udp_echo_server() -> Result<(SocketAddr, JoinHandle<()>), BenchError> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding reality-matrix UDP echo server".to_owned(),
            source,
        })?;
    let addr = socket.local_addr().map_err(|source| BenchError::Io {
        action: "reading reality-matrix UDP echo server address".to_owned(),
        source,
    })?;
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((len, peer)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..len], peer).await;
        }
    });
    Ok((addr, task))
}

async fn spawn_reality_matrix_http_server(
    body_bytes: usize,
) -> Result<(SocketAddr, JoinHandle<()>), BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding reality-matrix HTTP server".to_owned(),
            source,
        })?;
    let addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading reality-matrix HTTP server address".to_owned(),
        source,
    })?;
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let path = match read_http_request_path(&mut stream).await {
                    Some(path) => path,
                    None => return,
                };
                if path == "/generate_204" {
                    let response =
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response).await;
                } else if path == "/first-byte" {
                    let response =
                        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nB";
                    let _ = stream.write_all(response).await;
                } else if path == "/body" {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {body_bytes}\r\nConnection: close\r\n\r\n"
                    );
                    let body = vec![0x7b; body_bytes];
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                } else {
                    let response =
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response).await;
                }
            });
        }
    });
    Ok((addr, task))
}

async fn read_http_request_path(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > 16 * 1024 {
            return None;
        }
    }
    let request = std::str::from_utf8(&buffer).ok()?;
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    (method == "GET").then_some(path.to_owned())
}

async fn read_http_response_body_bytes(
    stream: &mut TcpStream,
    body_bytes: usize,
) -> Result<Vec<u8>, BenchError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0; 4096];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading reality-matrix HTTP response".to_owned(),
                source,
            })?;
        if read == 0 {
            return Err(BenchError::InvalidArguments(
                "HTTP response ended before headers".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_bytes(&buffer, b"\r\n\r\n") {
            break index;
        }
        if buffer.len() > 64 * 1024 {
            return Err(BenchError::InvalidArguments(
                "HTTP response headers exceeded 64KiB".to_owned(),
            ));
        }
    };

    let status_line = buffer[..header_end]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if !status_line.starts_with(b"HTTP/1.1 2") {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected HTTP response status `{}`",
            String::from_utf8_lossy(status_line).trim()
        )));
    }

    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < body_bytes {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading reality-matrix HTTP body".to_owned(),
                source,
            })?;
        if read == 0 {
            return Err(BenchError::InvalidArguments(format!(
                "HTTP body ended after {} of {body_bytes} bytes",
                body.len()
            )));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(body_bytes);
    Ok(body)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn ok_reality_matrix_case(
    fingerprint: &str,
    traffic: RealityMatrixTrafficKind,
    duration: Duration,
    outcome: WorkloadOutcome,
) -> RealityMatrixCaseResult {
    RealityMatrixCaseResult {
        fingerprint: fingerprint.to_owned(),
        traffic: traffic.as_str().to_owned(),
        status: "ok".to_owned(),
        duration_ms: duration.as_millis(),
        bytes_sent: outcome.bytes_sent,
        bytes_received: outcome.bytes_received,
        latency_us: summarize_latency_us(outcome.latencies_us),
        setup_us: summarize_flow_setup_us(outcome.setup_samples),
        error: None,
    }
}

fn failed_reality_matrix_case(
    fingerprint: &str,
    traffic: RealityMatrixTrafficKind,
    duration: Duration,
    error: String,
) -> RealityMatrixCaseResult {
    RealityMatrixCaseResult {
        fingerprint: fingerprint.to_owned(),
        traffic: traffic.as_str().to_owned(),
        status: "failed".to_owned(),
        duration_ms: duration.as_millis(),
        bytes_sent: 0,
        bytes_received: 0,
        latency_us: None,
        setup_us: None,
        error: Some(error),
    }
}

fn skipped_reality_matrix_case(
    fingerprint: &str,
    traffic: RealityMatrixTrafficKind,
    reason: &str,
) -> RealityMatrixCaseResult {
    RealityMatrixCaseResult {
        fingerprint: fingerprint.to_owned(),
        traffic: traffic.as_str().to_owned(),
        status: "skipped".to_owned(),
        duration_ms: 0,
        bytes_sent: 0,
        bytes_received: 0,
        latency_us: None,
        setup_us: None,
        error: Some(reason.to_owned()),
    }
}

fn push_skipped_reality_matrix_traffic(
    cases: &mut Vec<RealityMatrixCaseResult>,
    fingerprint: &str,
    options: &RealityMatrixOptions,
    reason: &str,
) {
    for traffic in &options.traffic {
        if *traffic == RealityMatrixTrafficKind::StartupProbe {
            continue;
        }
        cases.push(skipped_reality_matrix_case(fingerprint, *traffic, reason));
    }
}

fn summarize_reality_matrix_cases(
    cases: &[RealityMatrixCaseResult],
    fingerprint_count: usize,
    traffic_count: usize,
) -> RealityMatrixSummary {
    RealityMatrixSummary {
        fingerprints: fingerprint_count,
        traffic: traffic_count,
        cases: cases.len(),
        ok: cases.iter().filter(|case| case.status == "ok").count(),
        failed: cases.iter().filter(|case| case.status == "failed").count(),
        skipped: cases.iter().filter(|case| case.status == "skipped").count(),
    }
}

fn route_probe_config(rules: usize, outbounds: usize) -> Result<CoreConfig, BenchError> {
    let outbound_count = outbounds.max(1);
    let selected_tag = format!("out-{}", outbound_count - 1);
    let outbounds = (0..outbound_count)
        .map(|index| OutboundConfig {
            tag: Some(format!("out-{index}")),
            stream: StreamSettings {
                network: ConfigNetwork::Tcp,
                security: StreamSecurity::None,
            },
            settings: OutboundSettings::Freedom,
        })
        .collect::<Vec<_>>();

    let mut routing_rules = Vec::with_capacity(rules);
    for index in 0..rules {
        let cidr = if index + 1 == rules {
            IpCidr::full(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        } else {
            IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, (index % 256) as u8, 0, 0)), 16)
                .map_err(|error| BenchError::InvalidArguments(error.to_string()))?
        };
        routing_rules.push(RoutingRule {
            inbound_tags: vec!["bench-in".to_owned()],
            domain_matchers: Vec::new(),
            ip_matchers: vec![IpMatcher::Cidr(cidr)],
            outbound_tag: selected_tag.clone(),
        });
    }

    Ok(CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("bench-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds,
        default_outbound_tag: Some(selected_tag),
        routing: RoutingConfig {
            rules: routing_rules,
            ..Default::default()
        },
        dns: Default::default(),
        policy: Default::default(),
    })
}

pub async fn run_compare(options: BenchOptions) -> Result<(), BenchError> {
    let run_id = new_run_id();
    let rust_summary = run_engine_series(EngineKind::XrayRust, &options, &run_id).await?;
    print_summary(&rust_summary);
    let xray_summary = run_engine_series(EngineKind::XrayCore, &options, &run_id).await?;
    print_summary(&xray_summary);
    if options.workload.supports_sing_box_process_engine() {
        let sing_box_summary = run_engine_series(EngineKind::SingBox, &options, &run_id).await?;
        print_summary(&sing_box_summary);
    } else {
        eprintln!(
            "sing-box {} skipped: workload uses topology outside the process-level sing-box slice",
            options.workload.as_str()
        );
    }
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
    let fixture = WorkloadFixture::start(options.workload, options, run_dir, binary_dir).await?;
    let engine = start_engine(kind, options, run_dir, binary_dir, &fixture).await?;
    let started = Instant::now();
    let workload = async {
        match options.workload {
            WorkloadKind::Idle => run_idle_workload(options.duration).await,
            WorkloadKind::TcpFreedom => run_tcp_freedom_workload(engine.socks_addr, options).await,
            WorkloadKind::TcpBulkThroughput => {
                run_tcp_bulk_throughput_workload(engine.socks_addr, options).await
            }
            WorkloadKind::RoutedTcpFreedom => {
                run_routed_tcp_freedom_workload(engine.socks_addr, options).await
            }
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
            WorkloadKind::TunTcpStaleFlows => {
                run_tun_tcp_stale_flows_workload(engine.tun_fd()?, options).await
            }
            WorkloadKind::TunRealityBlackhole => {
                let blackhole_state = fixture.tcp_blackhole_state.as_deref().ok_or_else(|| {
                    BenchError::InvalidArguments(
                        "tun-reality-blackhole workload is missing fixture state".to_owned(),
                    )
                })?;
                run_tun_reality_blackhole_workload(engine.tun_fd()?, options, blackhole_state).await
            }
            WorkloadKind::UdpVless => run_udp_vless_workload(engine.socks_addr, options).await,
            WorkloadKind::UdpXudp => run_udp_xudp_workload(engine.socks_addr, options).await,
            WorkloadKind::VisionXudp => run_vision_xudp_workload(engine.socks_addr, options).await,
            WorkloadKind::RealityVisionXudp => {
                run_reality_vision_xudp_workload(engine.socks_addr, options).await
            }
            WorkloadKind::RealityVisionBulk => {
                run_tcp_bulk_throughput_workload(engine.socks_addr, options).await
            }
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
    let duration_ms = started.elapsed().as_millis();
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
    let throughput_mbps = throughput_mbps(summary.bytes_sent, summary.bytes_received, duration_ms);

    let result = BenchResult {
        engine: kind.as_str().to_owned(),
        workload: options.workload.as_str().to_owned(),
        status: "ok".to_owned(),
        duration_ms,
        bytes_sent: summary.bytes_sent,
        bytes_received: summary.bytes_received,
        peak_rss_kib: summary.peak_rss_kib,
        cpu_millis: summary.cpu_millis,
        cpu_millis_per_gib,
        throughput_mbps,
        connections: options.connections as u64,
        iterations: options.iterations as u64,
        payload_size: options.payload_size as u64,
        latency_us,
        setup_us,
        samples: samples.len(),
        blackhole_connections_accepted: workload_outcome.blackhole_connections_accepted,
        blackhole_connections_active: workload_outcome.blackhole_connections_active,
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
    let throughput = result
        .throughput_mbps
        .map(|value| format!(" throughput_mbps={value}"))
        .unwrap_or_default();
    let setup = result
        .setup_us
        .as_ref()
        .map(|setup| {
            format!(
                " setup_total_us[min/median/p95/p99]={}/{}/{}/{} setup_tcp_us[median]={} setup_socks_method_us[median]={} setup_socks_connect_us[median]={} setup_socks_us[median]={}",
                setup.total_us.min,
                setup.total_us.median,
                setup.total_us.p95,
                setup.total_us.p99,
                setup.tcp_connect_us.median,
                setup.socks_method_us.median,
                setup.socks_connect_us.median,
                setup.socks_setup_us.median,
            )
        })
        .unwrap_or_default();
    let blackhole = result
        .blackhole_connections_accepted
        .zip(result.blackhole_connections_active)
        .map(|(accepted, active)| {
            format!(" blackhole_connections[accepted/active]={accepted}/{active}")
        })
        .unwrap_or_default();
    println!(
        "{} {} status={} peak_rss_kib={} cpu_millis={} bytes_sent={} bytes_received={} samples={}{}{}{}{}{}",
        result.engine,
        result.workload,
        result.status,
        result.peak_rss_kib,
        result.cpu_millis,
        result.bytes_sent,
        result.bytes_received,
        result.samples,
        cpu_per_gib,
        throughput,
        latency,
        setup,
        blackhole
    );
}

fn print_route_probe_result(result: &RouteProbeResult) {
    println!(
        "route-probe iterations={} rules={} outbounds={} selected={} total_us={} avg_ns={}",
        result.iterations,
        result.rules,
        result.outbounds,
        result.selected,
        result.total_us,
        result.avg_ns
    );
}

fn print_reality_matrix_result(result: &RealityMatrixResult) {
    println!(
        "reality-matrix run_id={} fingerprints={} traffic={} cases={} ok={} failed={} skipped={} xray_core_server={} probe_url={}",
        result.run_id,
        result.summary.fingerprints,
        result.summary.traffic,
        result.summary.cases,
        result.summary.ok,
        result.summary.failed,
        result.summary.skipped,
        result.xray_core_server_addr,
        result.probe_url
    );
    for case in result.cases.iter().filter(|case| case.status != "ok") {
        println!(
            "  {} {} status={} error={}",
            case.fingerprint,
            case.traffic,
            case.status,
            case.error.as_deref().unwrap_or("")
        );
    }
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
    let throughput = summary
        .throughput_mbps
        .as_ref()
        .map(|metric| {
            format!(
                " throughput_mbps[min/median/p95]={}/{}/{}",
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
                " setup_total_us[median:min/median/p95]={}/{}/{} setup_tcp_us[median:min/median/p95]={}/{}/{} setup_socks_method_us[median:min/median/p95]={}/{}/{} setup_socks_connect_us[median:min/median/p95]={}/{}/{} setup_socks_us[median:min/median/p95]={}/{}/{}",
                setup.total_us.median.min,
                setup.total_us.median.median,
                setup.total_us.median.p95,
                setup.tcp_connect_us.median.min,
                setup.tcp_connect_us.median.median,
                setup.tcp_connect_us.median.p95,
                setup.socks_method_us.median.min,
                setup.socks_method_us.median.median,
                setup.socks_method_us.median.p95,
                setup.socks_connect_us.median.min,
                setup.socks_connect_us.median.median,
                setup.socks_connect_us.median.p95,
                setup.socks_setup_us.median.min,
                setup.socks_setup_us.median.median,
                setup.socks_setup_us.median.p95,
            )
        })
        .unwrap_or_default();
    println!(
        "{} {} runs={} status={} duration_ms[min/median/p95]={}/{}/{} peak_rss_kib[min/median/p95]={}/{}/{} cpu_millis[min/median/p95]={}/{}/{} bytes_sent[min/median/p95]={}/{}/{} bytes_received[min/median/p95]={}/{}/{}{}{}{}{}",
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
        throughput,
        latency,
        setup,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    fn geo_encode_varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn geo_field_bytes(field: u8, payload: &[u8], out: &mut Vec<u8>) {
        out.push((field << 3) | 2);
        geo_encode_varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    fn geo_domain_body(domain_type: u8, value: &str) -> Vec<u8> {
        let mut body = vec![0x08, domain_type];
        geo_field_bytes(2, value.as_bytes(), &mut body);
        body
    }

    // Code MUST be the first field: Xray-core's streaming reader requires it.
    fn geo_site_body(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        geo_field_bytes(1, code.as_bytes(), &mut body);
        for domain in domains {
            geo_field_bytes(2, domain, &mut body);
        }
        body
    }

    fn geo_cidr_body(ip: &[u8], prefix: u8) -> Vec<u8> {
        let mut body = Vec::new();
        geo_field_bytes(1, ip, &mut body);
        body.push(0x10);
        geo_encode_varint(u64::from(prefix), &mut body);
        body
    }

    fn geo_ip_body(code: &str, cidrs: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        geo_field_bytes(1, code.as_bytes(), &mut body);
        for cidr in cidrs {
            geo_field_bytes(2, cidr, &mut body);
        }
        body
    }

    fn geo_entry_file(bodies: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for body in bodies {
            bytes.push(0x0A);
            geo_encode_varint(body.len() as u64, &mut bytes);
            bytes.extend_from_slice(body);
        }
        bytes
    }

    fn write_geo_fixture(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        let geosite = geo_entry_file(&[
            geo_site_body(
                "CATEGORY-ADS-ALL",
                &[geo_domain_body(2, "ads-bench.example")],
            ),
            geo_site_body("CN", &[geo_domain_body(2, "baidu.com")]),
        ]);
        std::fs::write(dir.join("geosite.dat"), geosite).unwrap();
        let geoip = geo_entry_file(&[
            geo_ip_body("CN", &[geo_cidr_body(&[114, 114, 114, 0], 24)]),
            geo_ip_body(
                "PRIVATE",
                &[
                    geo_cidr_body(&[10, 0, 0, 0], 8),
                    geo_cidr_body(&[127, 0, 0, 0], 8),
                ],
            ),
        ]);
        std::fs::write(dir.join("geoip.dat"), geoip).unwrap();
    }

    #[test]
    fn geo_fixture_parses_through_real_config_parser() {
        let dir =
            std::env::temp_dir().join(format!("xray-bench-geo-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_geo_fixture(&dir);
        let config = routed_freedom_config(18099, EngineKind::XrayRust);
        let parsed = xray_config::parse_xray_json_with_geodata_dir(&config, &dir);
        assert!(
            parsed.is_ok(),
            "generated geo config must parse with the synthetic fixture: {:?}",
            parsed.err()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
                sing_box_bin: None,
                sing_box_dir: None,
                tun_profile: None,
                no_auto_build: false,
                geodata_dir: None,
            })
        );
    }

    #[test]
    fn parses_tun_profile_arg() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "tun-udp-freedom",
            "--tun-profile",
            "low-memory",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        assert_eq!(options.tun_profile.as_deref(), Some("low-memory"));
    }

    #[test]
    fn parses_run_idle_for_sing_box() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "sing-box",
            "--workload",
            "idle",
            "--sing-box-bin",
            "/private/tmp/sing-box-bench/sing-box",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        assert_eq!(options.engine, Some(EngineKind::SingBox));
        assert_eq!(
            options.sing_box_bin,
            Some(PathBuf::from("/private/tmp/sing-box-bench/sing-box"))
        );
    }

    #[test]
    fn parses_compare_sing_box_binary_and_checkout_options() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "many-idle-flows",
            "--sing-box-bin",
            "/private/tmp/sing-box-bench/sing-box",
            "--sing-box-dir",
            "/private/tmp/sing-box-bench",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(
            options.sing_box_bin,
            Some(PathBuf::from("/private/tmp/sing-box-bench/sing-box"))
        );
        assert_eq!(
            options.sing_box_dir,
            Some(PathBuf::from("/private/tmp/sing-box-bench"))
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
    fn parses_compare_tcp_bulk_throughput() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "tcp-bulk-throughput",
            "--connections",
            "1",
            "--iterations",
            "256",
            "--payload-size",
            "4194304",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::TcpBulkThroughput);
        assert_eq!(options.connections, 1);
        assert_eq!(options.iterations, 256);
        assert_eq!(options.payload_size, 4_194_304);
    }

    #[test]
    fn tcp_bulk_throughput_uses_plain_socks_freedom_config() {
        let fixture = WorkloadFixture::default();
        let config = engine_config(
            EngineKind::XrayRust,
            18087,
            WorkloadKind::TcpBulkThroughput,
            &fixture,
        )
        .unwrap();
        assert!(config.contains(r#""protocol": "socks""#));
        assert!(config.contains(r#""udp": false"#));
        assert!(config.contains(r#""protocol": "freedom""#));
    }

    #[test]
    fn tcp_bulk_throughput_supports_sing_box_compare() {
        assert!(WorkloadKind::TcpBulkThroughput.supports_sing_box_process_engine());
        let fixture = WorkloadFixture::default();
        let config = sing_box_config(18088, WorkloadKind::TcpBulkThroughput, &fixture).unwrap();
        assert!(config.contains(r#""type": "socks""#));
        assert!(config.contains(r#""type": "direct""#));
    }

    #[test]
    fn parses_compare_routed_tcp_freedom_with_geodata_dir() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "routed-tcp-freedom",
            "--connections",
            "4",
            "--iterations",
            "50",
            "--payload-size",
            "1024",
            "--geodata-dir",
            "/tmp/geodata",
        ])
        .unwrap();
        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::RoutedTcpFreedom);
        assert_eq!(options.geodata_dir, Some(PathBuf::from("/tmp/geodata")));
    }

    #[test]
    fn routed_config_carries_rules_hosts_and_engine_specific_freedom() {
        let rust_config = routed_freedom_config(18100, EngineKind::XrayRust);
        let value = serde_json::from_str::<serde_json::Value>(&rust_config).unwrap();
        assert_eq!(value["routing"]["rules"].as_array().unwrap().len(), 4);
        assert_eq!(
            value["routing"]["rules"][0]["domain"][0],
            "geosite:category-ads-all"
        );
        assert_eq!(value["routing"]["rules"][3]["domain"][0], "geosite:cn");
        assert!(value["dns"]["hosts"]["full:baidu.com"].is_string());
        assert!(value["dns"]["hosts"]["full:bench-miss.invalid"].is_string());
        assert_eq!(value["outbounds"][0]["tag"], "direct");
        assert_eq!(value["outbounds"][0]["settings"], serde_json::json!({}));

        let core_config = routed_freedom_config(18100, EngineKind::XrayCore);
        let value = serde_json::from_str::<serde_json::Value>(&core_config).unwrap();
        assert_eq!(value["outbounds"][0]["settings"]["domainStrategy"], "UseIP");
    }

    #[test]
    fn routed_workload_rejects_sing_box_and_requires_geodata() {
        assert!(!WorkloadKind::RoutedTcpFreedom.supports_sing_box_process_engine());
        let fixture = WorkloadFixture::default();
        let error = sing_box_config(18101, WorkloadKind::RoutedTcpFreedom, &fixture).unwrap_err();
        assert!(error.to_string().contains("unsupported sing-box workload"));
        assert!(geodata_dir_for(&BenchOptions::default()).is_err());
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
    fn parses_compare_reality_vision_xudp() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "reality-vision-xudp",
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
        assert_eq!(options.workload, WorkloadKind::RealityVisionXudp);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
    }

    #[test]
    fn parses_compare_reality_vision_bulk_throughput() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "reality-vision-bulk-throughput",
            "--connections",
            "1",
            "--iterations",
            "4",
            "--payload-size",
            "65536",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::RealityVisionBulk);
        assert_eq!(options.connections, 1);
        assert_eq!(options.iterations, 4);
        assert_eq!(options.payload_size, 65536);
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
            ("tun-tcp-stale-flows", WorkloadKind::TunTcpStaleFlows),
            ("tun-reality-blackhole", WorkloadKind::TunRealityBlackhole),
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
        assert!(WorkloadKind::TunTcpStaleFlows.uses_tun_fd());
        assert!(WorkloadKind::TunRealityBlackhole.uses_tun_fd());
    }

    #[cfg(unix)]
    #[test]
    fn tun_tcp_packet_demux_uses_ipv4_tcp_destination_port() {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[9] = TCP_PROTOCOL;
        packet[22..24].copy_from_slice(&49_152_u16.to_be_bytes());

        assert_eq!(ipv4_tcp_destination_port(&packet), Some(49_152));
        packet[9] = UDP_PROTOCOL;
        assert_eq!(ipv4_tcp_destination_port(&packet), None);
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

    #[test]
    fn rejects_zero_connections_iterations_and_payload() {
        for flag in ["--connections", "--iterations", "--payload-size"] {
            let error = parse_cli_args(["xray-bench", "compare", flag, "0"]).unwrap_err();
            assert!(
                error.to_string().contains("must be greater than zero"),
                "{flag}"
            );
        }
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
    fn xray_core_vision_xudp_config_uses_tls_cert_pin() {
        let fixture = WorkloadFixture {
            vless_addr: Some(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19091))),
            vless_tls_cert_sha256: Some(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
            ),
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };
        let config = engine_config(
            EngineKind::XrayCore,
            18084,
            WorkloadKind::VisionXudp,
            &fixture,
        )
        .unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["outbounds"][0]["streamSettings"]["security"], "tls");
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"],
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
        assert!(value["outbounds"][0]["streamSettings"]["tlsSettings"]
            .get("allowInsecure")
            .is_none());
    }

    #[test]
    fn reality_vision_xudp_config_enables_reality_vision_flow() {
        let config = reality_vision_xudp_config(
            18085,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19092)),
        );
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["protocol"], "socks");
        assert_eq!(value["outbounds"][0]["protocol"], "vless");
        assert_eq!(
            value["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["security"],
            "reality"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"],
            REALITY_PUBLIC_KEY
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"],
            REALITY_SHORT_ID_HEX
        );
        assert_eq!(value["outbounds"][0]["settings"]["vnext"][0]["port"], 19092);
    }

    #[test]
    fn xray_core_reality_fixture_config_enables_reality_vision_inbound() {
        let config = xray_core_reality_vision_server_config(19093);
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["protocol"], "vless");
        assert_eq!(
            value["inbounds"][0]["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(
            value["inbounds"][0]["streamSettings"]["security"],
            "reality"
        );
        assert_eq!(
            value["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"],
            REALITY_PRIVATE_KEY
        );
        assert_eq!(value["outbounds"][0]["protocol"], "freedom");
        assert_eq!(
            value["outbounds"][0]["settings"]["finalRules"][0]["action"],
            "allow"
        );
    }

    #[test]
    fn tun_udp_freedom_config_uses_tun_inbound_without_socks() {
        let fixture = WorkloadFixture::default();
        let config = engine_config(
            EngineKind::XrayRust,
            0,
            WorkloadKind::TunUdpFreedom,
            &fixture,
        )
        .unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["protocol"], "tun");
        assert_eq!(value["outbounds"][0]["protocol"], "freedom");
        assert!(!config.contains(r#""protocol": "socks""#));
    }

    #[test]
    fn tun_reality_blackhole_config_uses_tun_reality_and_short_handshake_policy() {
        let fixture = WorkloadFixture {
            vless_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 19095))),
            vless_tls_cert_sha256: None,
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };
        let config = engine_config(
            EngineKind::XrayRust,
            0,
            WorkloadKind::TunRealityBlackhole,
            &fixture,
        )
        .unwrap();
        let parsed = parse_xray_json(&config).unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert!(matches!(
            parsed.config.inbounds[0].protocol,
            InboundProtocol::Tun
        ));
        assert_eq!(value["policy"]["levels"]["0"]["handshake"], 1);
        assert_eq!(value["outbounds"][0]["protocol"], "vless");
        assert_eq!(
            value["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["security"],
            "reality"
        );
        assert_eq!(value["outbounds"][0]["settings"]["vnext"][0]["port"], 19095);
    }

    #[test]
    fn sing_box_freedom_config_uses_sing_box_schema() {
        let fixture = WorkloadFixture::default();
        let config = sing_box_config(18086, WorkloadKind::ManyIdleFlows, &fixture).unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["log"]["level"], "warn");
        assert_eq!(value["inbounds"][0]["type"], "socks");
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(value["inbounds"][0]["listen_port"], 18086);
        assert_eq!(value["outbounds"][0]["type"], "direct");
        assert_eq!(value["route"]["final"], "direct");
    }

    #[test]
    fn sing_box_reality_vision_xudp_config_uses_vless_reality_schema() {
        let fixture = WorkloadFixture {
            vless_addr: Some(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19094))),
            vless_tls_cert_sha256: None,
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };
        let config = sing_box_config(18087, WorkloadKind::RealityVisionXudp, &fixture).unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["type"], "socks");
        assert_eq!(value["outbounds"][0]["type"], "vless");
        assert_eq!(value["outbounds"][0]["server"], "127.0.0.1");
        assert_eq!(value["outbounds"][0]["server_port"], 19094);
        assert_eq!(value["outbounds"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(value["outbounds"][0]["packet_encoding"], "xudp");
        assert_eq!(value["outbounds"][0]["tls"]["enabled"], true);
        assert_eq!(
            value["outbounds"][0]["tls"]["server_name"],
            REALITY_SERVER_NAME
        );
        assert_eq!(value["outbounds"][0]["tls"]["utls"]["enabled"], true);
        assert_eq!(
            value["outbounds"][0]["tls"]["reality"]["public_key"],
            REALITY_PUBLIC_KEY
        );
        assert_eq!(
            value["outbounds"][0]["tls"]["reality"]["short_id"],
            REALITY_SHORT_ID_HEX
        );
    }

    #[test]
    fn sing_box_auto_build_tags_include_utls_for_reality() {
        assert!(sing_box_build_tags()
            .split(',')
            .any(|tag| tag == "with_utls"));
    }

    #[test]
    fn reality_vision_xudp_supports_sing_box_compare() {
        assert!(WorkloadKind::RealityVisionXudp.supports_sing_box_process_engine());
    }

    #[test]
    fn sing_box_tun_workloads_are_explicitly_unsupported() {
        let fixture = WorkloadFixture::default();
        let error = sing_box_config(0, WorkloadKind::TunUdpFreedom, &fixture).unwrap_err();

        assert!(error.to_string().contains("unsupported sing-box workload"));
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
                socks_method_us: 40,
                socks_connect_us: 360,
                socks_setup_us: 400,
                total_us: 500,
            },
            FlowSetupSample {
                tcp_connect_us: 200,
                socks_method_us: 60,
                socks_connect_us: 540,
                socks_setup_us: 600,
                total_us: 800,
            },
            FlowSetupSample {
                tcp_connect_us: 150,
                socks_method_us: 50,
                socks_connect_us: 450,
                socks_setup_us: 500,
                total_us: 650,
            },
        ])
        .unwrap();

        assert_eq!(summary.tcp_connect_us.median, 150);
        assert_eq!(summary.socks_method_us.median, 50);
        assert_eq!(summary.socks_connect_us.median, 450);
        assert_eq!(summary.socks_setup_us.median, 500);
        assert_eq!(summary.total_us.median, 650);
    }

    #[test]
    fn parses_route_probe_command() {
        let args = parse_cli_args([
            "xray-bench",
            "route-probe",
            "--iterations",
            "500",
            "--rules",
            "64",
            "--outbounds",
            "8",
            "--out-dir",
            "target/benchmarks/route-probe",
        ])
        .unwrap();

        assert_eq!(
            args,
            CliArgs::RouteProbe(RouteProbeOptions {
                iterations: 500,
                rules: 64,
                outbounds: 8,
                out_dir: PathBuf::from("target/benchmarks/route-probe"),
            })
        );
    }

    #[test]
    fn parses_reality_matrix_command() {
        let args = parse_cli_args([
            "xray-bench",
            "reality-matrix",
            "--fingerprints",
            "chrome,hellochrome_120_pq",
            "--traffic",
            "startup-probe,tcp-connect,udp-xudp-echo",
            "--iterations",
            "2",
            "--small-payload-size",
            "128",
            "--body-bytes",
            "4096",
            "--probe-timeout-ms",
            "1500",
            "--run-timeout-ms",
            "3000",
            "--out-dir",
            "target/benchmarks/matrix",
            "--xray-core-dir",
            "../Xray-core",
            "--trace-traffic",
            "--no-auto-build",
        ])
        .unwrap();

        assert_eq!(
            args,
            CliArgs::RealityMatrix(RealityMatrixOptions {
                fingerprints: vec!["chrome".to_owned(), "hellochrome_120_pq".to_owned()],
                traffic: vec![
                    RealityMatrixTrafficKind::StartupProbe,
                    RealityMatrixTrafficKind::TcpConnect,
                    RealityMatrixTrafficKind::UdpXudpEcho,
                ],
                iterations: 2,
                small_payload_size: 128,
                body_bytes: 4096,
                probe_timeout: Duration::from_millis(1500),
                run_timeout: Duration::from_millis(3000),
                out_dir: PathBuf::from("target/benchmarks/matrix"),
                xray_core_bin: None,
                xray_core_dir: Some(PathBuf::from("../Xray-core")),
                trace_traffic: true,
                no_auto_build: true,
            })
        );
    }

    #[test]
    fn parses_chart_command() {
        let args = parse_cli_args([
            "xray-bench",
            "chart",
            "--group",
            "target/benchmarks/123",
            "--group",
            "target/benchmarks/456",
            "--out-dir",
            "docs/benchmarks/media",
            "--date",
            "2026-07-29",
            "--hardware",
            "Apple M4 Pro, 24 GB RAM, macOS 15.5",
            "--xray-rust-version",
            "1659143",
            "--xray-core-version",
            "v26.5.9",
            "--sing-box-version",
            "v1.12.0",
        ])
        .unwrap();

        let CliArgs::Chart(options) = args else {
            panic!("expected chart args");
        };
        assert_eq!(options.groups.len(), 2);
        assert_eq!(options.out_dir, PathBuf::from("docs/benchmarks/media"));
    }

    #[test]
    fn reality_matrix_defaults_to_capable_fingerprints_and_all_traffic() {
        let args = parse_cli_args(["xray-bench", "reality-matrix"]).unwrap();
        let CliArgs::RealityMatrix(options) = args else {
            panic!("expected reality matrix args");
        };

        assert!(options.fingerprints.contains(&"chrome".to_owned()));
        assert!(options
            .fingerprints
            .contains(&"hellochrome_120_pq".to_owned()));
        assert!(options
            .traffic
            .contains(&RealityMatrixTrafficKind::StartupProbe));
        assert!(options
            .traffic
            .contains(&RealityMatrixTrafficKind::HttpBody));
        assert!(options
            .traffic
            .contains(&RealityMatrixTrafficKind::UdpXudpEcho));
        assert_eq!(options.probe_timeout, Duration::from_secs(15));
        assert!(!options.trace_traffic);
    }

    #[test]
    fn reality_matrix_trace_event_serializes_as_json_line() {
        let event = RealityMatrixTraceEvent {
            fingerprint: "safari",
            traffic: "tcp-echo-body",
            event: "iteration_read_done",
            target: None,
            connection_id: None,
            peer_addr: None,
            iteration: Some(2),
            payload_bytes: Some(1048576),
            bytes: None,
            bytes_sent_total: Some(2_097_152),
            bytes_received_total: Some(2_097_152),
            active_connections: None,
            error: None,
            elapsed_us: 12_345,
        };

        let line = reality_matrix_trace_event_json_line(&event).unwrap();

        assert!(line.ends_with('\n'));
        assert!(line.contains(r#""fingerprint":"safari""#));
        assert!(line.contains(r#""event":"iteration_read_done""#));
    }

    #[test]
    fn reality_matrix_trace_event_serializes_target_diagnostics() {
        let event = RealityMatrixTraceEvent {
            fingerprint: "<target>",
            traffic: "tcp-echo-target",
            event: "target_read",
            target: Some("tcp_echo"),
            connection_id: Some(7),
            peer_addr: Some("127.0.0.1:44321".to_owned()),
            iteration: None,
            payload_bytes: None,
            bytes: Some(65536),
            bytes_sent_total: Some(131072),
            bytes_received_total: Some(65536),
            active_connections: Some(3),
            error: None,
            elapsed_us: 98_765,
        };

        let line = reality_matrix_trace_event_json_line(&event).unwrap();

        assert!(line.contains(r#""target":"tcp_echo""#));
        assert!(line.contains(r#""connection_id":7"#));
        assert!(line.contains(r#""bytes":65536"#));
        assert!(line.contains(r#""active_connections":3"#));
    }

    #[test]
    fn rejects_reality_matrix_incapable_fingerprint() {
        let error = parse_cli_args(["xray-bench", "reality-matrix", "--fingerprints", "android"])
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("unsupported REALITY fingerprint"));
    }

    #[test]
    fn reality_vision_xudp_config_uses_requested_fingerprint() {
        let config = reality_vision_xudp_config_with_fingerprint(
            18088,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19095)),
            "hellochrome_120_pq",
        );
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(
            value["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"],
            "hellochrome_120_pq"
        );
    }

    #[test]
    fn summarizes_reality_matrix_statuses() {
        let cases = vec![
            RealityMatrixCaseResult {
                fingerprint: "chrome".to_owned(),
                traffic: "startup-probe".to_owned(),
                status: "ok".to_owned(),
                duration_ms: 1,
                bytes_sent: 0,
                bytes_received: 0,
                latency_us: None,
                setup_us: None,
                error: None,
            },
            RealityMatrixCaseResult {
                fingerprint: "chrome".to_owned(),
                traffic: "tcp-connect".to_owned(),
                status: "failed".to_owned(),
                duration_ms: 1,
                bytes_sent: 0,
                bytes_received: 0,
                latency_us: None,
                setup_us: None,
                error: Some("boom".to_owned()),
            },
            RealityMatrixCaseResult {
                fingerprint: "chrome".to_owned(),
                traffic: "http-body".to_owned(),
                status: "skipped".to_owned(),
                duration_ms: 0,
                bytes_sent: 0,
                bytes_received: 0,
                latency_us: None,
                setup_us: None,
                error: Some("startup failed".to_owned()),
            },
        ];

        assert_eq!(
            summarize_reality_matrix_cases(&cases, 1, 3),
            RealityMatrixSummary {
                fingerprints: 1,
                traffic: 3,
                cases: 3,
                ok: 1,
                failed: 1,
                skipped: 1,
            }
        );
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
    fn computes_throughput_mbps_from_bytes_and_duration() {
        assert_eq!(throughput_mbps(0, 0, 1000), None);
        assert_eq!(throughput_mbps(0, 1_073_741_824, 0), None);
        assert_eq!(throughput_mbps(0, 1_073_741_824, 2000), Some(4295));
        // 500 + 500 bytes over 1000ms = 8000 bits/s = 0.008 Mbps, ceil to 1 Mbps.
        assert_eq!(throughput_mbps(500, 500, 1000), Some(1));
    }

    #[test]
    fn deserializes_result_json_without_throughput_field() {
        let raw = r#"{
            "engine": "xray-rust",
            "workload": "tcp-freedom",
            "status": "ok",
            "duration_ms": 10,
            "bytes_sent": 1024,
            "bytes_received": 1024,
            "peak_rss_kib": 3000,
            "cpu_millis": 20,
            "cpu_millis_per_gib": null,
            "latency_us": null,
            "setup_us": null,
            "samples": 2
        }"#;
        let result: BenchResult = serde_json::from_str(raw).unwrap();
        assert_eq!(result.throughput_mbps, None);
        assert_eq!(result.connections, 0);
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
                throughput_mbps: Some(100),
                connections: 1,
                iterations: 10,
                payload_size: 4096,
                latency_us: Some(LatencySummary {
                    min: 10,
                    median: 20,
                    p95: 30,
                    p99: 40,
                }),
                setup_us: None,
                samples: 2,
                blackhole_connections_accepted: None,
                blackhole_connections_active: None,
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
                throughput_mbps: Some(50),
                connections: 1,
                iterations: 10,
                payload_size: 4096,
                latency_us: Some(LatencySummary {
                    min: 5,
                    median: 10,
                    p95: 20,
                    p99: 30,
                }),
                setup_us: None,
                samples: 2,
                blackhole_connections_accepted: None,
                blackhole_connections_active: None,
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
                throughput_mbps: Some(150),
                connections: 1,
                iterations: 10,
                payload_size: 4096,
                latency_us: Some(LatencySummary {
                    min: 15,
                    median: 30,
                    p95: 40,
                    p99: 50,
                }),
                setup_us: None,
                samples: 2,
                blackhole_connections_accepted: None,
                blackhole_connections_active: None,
            },
        ];

        let summary = summarize_results(&results).unwrap();

        assert_eq!(summary.engine, "xray-rust");
        assert_eq!(summary.workload, "tcp-freedom");
        assert_eq!(summary.connections, 1);
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
            summary.throughput_mbps,
            Some(MetricSummary {
                min: 50,
                median: 100,
                p95: 150,
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

    #[test]
    fn deserializes_summary_json_without_params_fields() {
        let raw = r#"{
            "engine": "xray-rust",
            "workload": "tcp-freedom",
            "status": "ok",
            "runs": 1,
            "duration_ms": { "min": 1, "median": 1, "p95": 1 },
            "peak_rss_kib": { "min": 1, "median": 1, "p95": 1 },
            "cpu_millis": { "min": 1, "median": 1, "p95": 1 },
            "cpu_millis_per_gib": null,
            "latency_us": null,
            "setup_us": null,
            "bytes_sent": { "min": 1, "median": 1, "p95": 1 },
            "bytes_received": { "min": 1, "median": 1, "p95": 1 },
            "results": []
        }"#;
        let summary: BenchSummary = serde_json::from_str(raw).unwrap();
        assert_eq!(summary.connections, 0);
        assert_eq!(summary.iterations, 0);
        assert_eq!(summary.payload_size, 0);
    }

    #[test]
    fn summarize_rejects_mixed_workload_parameters() {
        let first = BenchResult {
            engine: "xray-rust".to_owned(),
            workload: "tcp-freedom".to_owned(),
            status: "ok".to_owned(),
            duration_ms: 10,
            bytes_sent: 0,
            bytes_received: 0,
            peak_rss_kib: 1000,
            cpu_millis: 5,
            cpu_millis_per_gib: None,
            throughput_mbps: None,
            connections: 100,
            iterations: 1,
            payload_size: 512,
            latency_us: None,
            setup_us: None,
            samples: 2,
            blackhole_connections_accepted: None,
            blackhole_connections_active: None,
        };
        let mut second = first.clone();
        second.connections = 1000;
        let error = summarize_results(&[first.clone(), second]).unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot summarize mixed workload parameters"));

        let same = summarize_results(&[first.clone(), first.clone()]).unwrap();
        assert_eq!(same.connections, 100);
        assert_eq!(same.payload_size, 512);
    }

    #[test]
    fn bulk_pattern_template_is_deterministic_and_non_constant() {
        let first = bulk_pattern_template(4096);
        let second = bulk_pattern_template(4096);
        assert_eq!(first, second);
        assert_eq!(first.len(), 4096);
        assert!(first.iter().any(|&byte| byte != first[0]));
    }

    #[tokio::test]
    async fn bulk_stream_reader_validates_pattern() {
        let template = bulk_pattern_template(1024);
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let stream = template.repeat(3);
        let write_task = tokio::spawn(async move { writer.write_all(&stream).await });

        let received = read_and_validate_bulk_stream(&mut reader, &template, 3)
            .await
            .unwrap();

        assert_eq!(received, 3 * 1024);
        write_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bulk_stream_reader_rejects_corrupted_pattern() {
        let template = bulk_pattern_template(1024);
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let mut stream = template.repeat(2);
        stream[1500] = stream[1500].wrapping_add(1);
        let write_task = tokio::spawn(async move { writer.write_all(&stream).await });

        let error = read_and_validate_bulk_stream(&mut reader, &template, 2)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("bulk stream payload mismatch"));
        write_task.await.unwrap().unwrap();
    }

    async fn spawn_test_socks5_forwarder() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut client, _peer)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut greeting = [0; 2];
                    client.read_exact(&mut greeting).await.unwrap();
                    let mut methods = vec![0; greeting[1] as usize];
                    client.read_exact(&mut methods).await.unwrap();
                    client.write_all(&[5, 0]).await.unwrap();
                    let mut request = [0; 10];
                    client.read_exact(&mut request).await.unwrap();
                    assert_eq!(request[..4], [5, 1, 0, 1]);
                    let ip = Ipv4Addr::new(request[4], request[5], request[6], request[7]);
                    let port = u16::from_be_bytes([request[8], request[9]]);
                    let mut upstream = TcpStream::connect((ip, port)).await.unwrap();
                    client
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn bulk_workload_moves_validated_bytes_through_socks() {
        let (socks_addr, socks_task) = spawn_test_socks5_forwarder().await;
        let options = BenchOptions {
            workload: WorkloadKind::TcpBulkThroughput,
            connections: 2,
            iterations: 8,
            payload_size: 64 * 1024,
            ..BenchOptions::default()
        };

        let outcome = run_tcp_bulk_throughput_workload(socks_addr, &options)
            .await
            .unwrap();

        assert_eq!(outcome.bytes_received, 2 * 8 * 64 * 1024);
        assert_eq!(outcome.bytes_sent, 0);
        assert!(outcome.latencies_us.is_empty());
        assert!(outcome.setup_samples.is_empty());
        socks_task.abort();
    }

    #[tokio::test]
    async fn socks5_domain_connect_encodes_atyp3_request() {
        let (mut server, mut client_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 5];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[..4], [5, 1, 0, 3]);
            let len = head[4] as usize;
            let mut domain = vec![0; len + 2];
            server.read_exact(&mut domain).await.unwrap();
            assert_eq!(&domain[..len], b"bench-miss.invalid");
            assert_eq!(&domain[len..], &9999u16.to_be_bytes());
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });

        let sample = socks5_connect_domain_measured(&mut client_io, "bench-miss.invalid", 9999)
            .await
            .unwrap();
        assert!(sample.total_us >= sample.connect_us);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_reply_parser_accepts_domain_bound_address() {
        let (mut server, mut client_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 5];
            server.read_exact(&mut head).await.unwrap();
            let len = head[4] as usize;
            let mut rest = vec![0; len + 2];
            server.read_exact(&mut rest).await.unwrap();
            let mut reply = vec![5, 0, 0, 3, 4];
            reply.extend_from_slice(b"echo");
            reply.extend_from_slice(&80u16.to_be_bytes());
            server.write_all(&reply).await.unwrap();
        });

        socks5_connect_domain_measured(&mut client_io, "x.example", 80)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    async fn spawn_test_socks5_domain_forwarder() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut client, _peer)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut greeting = [0; 2];
                    client.read_exact(&mut greeting).await.unwrap();
                    let mut methods = vec![0; greeting[1] as usize];
                    client.read_exact(&mut methods).await.unwrap();
                    client.write_all(&[5, 0]).await.unwrap();
                    let mut head = [0; 4];
                    client.read_exact(&mut head).await.unwrap();
                    assert_eq!(head[..3], [5, 1, 0]);
                    assert_eq!(head[3], 3, "domain forwarder expects ATYP=3");
                    let mut len = [0; 1];
                    client.read_exact(&mut len).await.unwrap();
                    let mut domain = vec![0; len[0] as usize];
                    client.read_exact(&mut domain).await.unwrap();
                    let domain = String::from_utf8(domain).unwrap();
                    assert!(
                        domain == GEO_HIT_DOMAIN || domain == GEO_MISS_DOMAIN,
                        "unexpected domain {domain}"
                    );
                    let mut port = [0; 2];
                    client.read_exact(&mut port).await.unwrap();
                    let port = u16::from_be_bytes(port);
                    let mut upstream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                        .await
                        .unwrap();
                    client
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn routed_workload_collects_setup_and_latency_samples() {
        let (socks_addr, socks_task) = spawn_test_socks5_domain_forwarder().await;
        let options = BenchOptions {
            workload: WorkloadKind::RoutedTcpFreedom,
            connections: 4,
            iterations: 8,
            payload_size: 2048,
            ..BenchOptions::default()
        };

        let outcome = run_routed_tcp_freedom_workload(socks_addr, &options)
            .await
            .unwrap();

        assert_eq!(outcome.bytes_sent, 4 * 8 * 2048);
        assert_eq!(outcome.bytes_received, 4 * 8 * 2048);
        assert_eq!(outcome.setup_samples.len(), 4);
        assert_eq!(outcome.latencies_us.len(), 4 * 8);
        socks_task.abort();
    }
}
