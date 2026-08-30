use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::future::Future;
use std::hint::black_box;
use std::io::{self, Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
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
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use xray_config::{
    compile_dns_domain_matchers, parse_xray_json, CoreConfig, DnsHostTarget, DnsOutboundRule,
    DnsOutboundRuleAction, DnsOutboundSettings, DomainMatcher, InboundConfig, InboundProtocol,
    IpCidr, Network as ConfigNetwork, OutboundConfig, OutboundSettings, RoutingConfig,
    RoutingDomainStrategy, RoutingPortRange, RoutingRule, StreamSecurity, StreamSettings,
    StreamTransport, MAX_CONFIG_DOMAIN_MATCHERS,
};
use xray_core_rs::{
    CompiledDnsOutboundPolicy, Core, DnsOutboundDecision, OutboundRouter, StartupProbeOptions,
};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, read_udp_packet, read_xudp_packet,
    unpad_vision_block, VisionCommand, VisionPadding,
};
use xray_routing::{
    Cidr, DnsIpFilter, DomainHostIndex, DomainMatcherSet, DomainNameMode, IpMatcherSet,
    Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr,
};
use xray_transport::{
    select_name_server_indices, CachingDnsResolver, CompiledNameServerPolicies, DnsLookup,
    DnsResolver, NameServer, NameServerPolicy, TransportError,
};
use xray_utls::{normalize_reality_supported_fingerprint, XRAY_REALITY_CAPABLE_FINGERPRINTS};

pub mod chart;
mod process_metrics;
mod stream_transport;

use process_metrics::current_peak_rss_kib;

pub use stream_transport::{
    StreamBenchScenario, StreamBenchTraffic, StreamBenchTransport, StreamBenchXhttpMode,
    StreamBenchXhttpProfile,
};

const USAGE: &str =
    "usage: xray-bench run|compare|route-probe|dns-policy-probe|reality-matrix|chart [options]";
const TEST_VLESS_UUID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const TEST_VLESS_UUID_STRING: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const PLACEHOLDER_TLS_CERT_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
// The PQ benchmark cases need a cover origin that accepts X25519MLKEM;
// RFC 2606 example origins reject the `hellochrome_120_pq` handshake.
const REALITY_SERVER_NAME: &str = "www.google.com";
const REALITY_PRIVATE_KEY: &str = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks";
const REALITY_PUBLIC_KEY: &str = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM";
const REALITY_SHORT_ID_HEX: &str = "0123456789abcdef";
/// The REALITY server logs `started` when its listener binds, but it cannot
/// serve clients until the library has learned the post-handshake record shape
/// of the real `dest`: a TLS handshake to that host plus a fixed five-second
/// read deadline. Connecting inside that window stalls the first flow — which
/// lands inside the measurement window — and can trip the dest's ten-second
/// incomplete-handshake FIN, killing the flow outright.
const REALITY_FIXTURE_WARMUP: Duration = Duration::from_secs(8);
/// Overrides [`REALITY_FIXTURE_WARMUP`]; the dest handshake latency is
/// network-dependent, so the fixed default may need adjusting per environment.
const REALITY_FIXTURE_WARMUP_MS_ENV: &str = "XRAY_BENCH_REALITY_WARMUP_MS";
const SING_BOX_BUILD_TAGS: &str = "with_gvisor,with_utls,badlinkname,tfogo_checklinkname0";
const XRAY_CORE_ORACLE_VERSION: &str = "26.7.28";
const XRAY_CORE_ORACLE_REVISION: &str = "5ca6f4b7d4dc20a881d4330e498892697627ec0c";
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const DARWIN_UTUN_HEADER_LEN: usize = 4;
#[cfg(unix)]
const DNS_PORT: u16 = 53;
#[cfg(unix)]
const DNS_TYPE_A: u16 = 1;
#[cfg(unix)]
const DNS_TYPE_HTTPS: u16 = 65;
#[cfg(unix)]
const DNS_CLASS_IN: u16 = 1;
#[cfg(unix)]
const TUN_DNS_ANCHOR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
#[cfg(unix)]
const TUN_FAKE_DNS_FIRST_IPV4: Ipv4Addr = Ipv4Addr::new(198, 19, 0, 1);
#[cfg(unix)]
const TUN_FAKE_DNS_DOMAIN: &str = "bench.example";
#[cfg(unix)]
const TUN_FAKE_DNS_MAX_IN_FLIGHT: usize = 32;
#[cfg(unix)]
const TUN_FAKE_DNS_IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const TUN_DNS_PROXY_ANSWER_IPV4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 53);
#[cfg(unix)]
const TUN_DNS_PROXY_DOMAIN: &str = "proxy-bench.example";
#[cfg(unix)]
const TUN_DNS_TCP_MAX_ACTIVE_CONNECTIONS: usize = 16;
#[cfg(unix)]
const TUN_DNS_TCP_MAX_QUEUED_FRAMES: usize = 512;
#[cfg(unix)]
const TUN_DNS_TCP_STALL_TIMEOUT: Duration = Duration::from_secs(5);
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
    DnsPolicyProbe(DnsPolicyProbeOptions),
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
    TunFakeDns,
    TunFakeDnsTcp,
    TunDnsProxy,
    TunTcpFreedom,
    TunTcpStaleFlows,
    TunRealityBlackhole,
    UdpVless,
    UdpXudp,
    VisionXudp,
    RealityVisionXudp,
    RealityVisionBulkThroughput,
    GrpcBulkThroughput,
    StreamTransport,
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
            Self::TunFakeDns => "tun-fake-dns",
            Self::TunFakeDnsTcp => "tun-fake-dns-tcp",
            Self::TunDnsProxy => "tun-dns-proxy",
            Self::TunTcpFreedom => "tun-tcp-freedom",
            Self::TunTcpStaleFlows => "tun-tcp-stale-flows",
            Self::TunRealityBlackhole => "tun-reality-blackhole",
            Self::UdpVless => "udp-vless",
            Self::UdpXudp => "udp-xudp",
            Self::VisionXudp => "vision-xudp",
            Self::RealityVisionXudp => "reality-vision-xudp",
            Self::RealityVisionBulkThroughput => "reality-vision-bulk-throughput",
            Self::GrpcBulkThroughput => "grpc-bulk-throughput",
            Self::StreamTransport => "stream-transport",
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
            "tun-fake-dns" => Ok(Self::TunFakeDns),
            "tun-fake-dns-tcp" => Ok(Self::TunFakeDnsTcp),
            "tun-dns-proxy" => Ok(Self::TunDnsProxy),
            "tun-tcp-freedom" => Ok(Self::TunTcpFreedom),
            "tun-tcp-stale-flows" => Ok(Self::TunTcpStaleFlows),
            "tun-reality-blackhole" => Ok(Self::TunRealityBlackhole),
            "udp-vless" => Ok(Self::UdpVless),
            "udp-xudp" => Ok(Self::UdpXudp),
            "vision-xudp" => Ok(Self::VisionXudp),
            "reality-vision-xudp" => Ok(Self::RealityVisionXudp),
            "reality-vision-bulk-throughput" => Ok(Self::RealityVisionBulkThroughput),
            "grpc-bulk-throughput" => Ok(Self::GrpcBulkThroughput),
            "stream-transport" => Ok(Self::StreamTransport),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported workload `{other}`"
            ))),
        }
    }

    fn uses_tun_fd(&self) -> bool {
        matches!(
            self,
            Self::TunUdpFreedom
                | Self::TunFakeDns
                | Self::TunFakeDnsTcp
                | Self::TunDnsProxy
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
                | Self::RealityVisionBulkThroughput
                | Self::GrpcBulkThroughput
                | Self::StreamTransport
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TunDnsTransport {
    Udp,
    Tcp,
    #[default]
    Both,
}

impl TunDnsTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Both => "both",
        }
    }

    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "both" => Ok(Self::Both),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported TUN DNS transport `{other}`; expected udp|tcp|both"
            ))),
        }
    }

    fn includes_udp(self) -> bool {
        matches!(self, Self::Udp | Self::Both)
    }

    fn includes_tcp(self) -> bool {
        matches!(self, Self::Tcp | Self::Both)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TunDnsUpstreamTransport {
    #[default]
    Classic,
    TcpRouted,
    TcpLocal,
}

impl TunDnsUpstreamTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::TcpRouted => "tcp-routed",
            Self::TcpLocal => "tcp-local",
        }
    }

    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "classic" => Ok(Self::Classic),
            "tcp-routed" => Ok(Self::TcpRouted),
            "tcp-local" => Ok(Self::TcpLocal),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported TUN DNS upstream transport `{other}`; expected classic|tcp-routed|tcp-local"
            ))),
        }
    }

    fn server(self, upstream: SocketAddr) -> String {
        match self {
            Self::Classic => upstream.to_string(),
            Self::TcpRouted => format!("tcp://{upstream}"),
            Self::TcpLocal => format!("tcp+local://{upstream}"),
        }
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
    pub stream_transport: Option<StreamBenchTransport>,
    pub stream_traffic: Option<StreamBenchTraffic>,
    pub xhttp_mode: Option<StreamBenchXhttpMode>,
    pub xhttp_profile: Option<StreamBenchXhttpProfile>,
    pub xhttp_max_post_bytes: Option<usize>,
    pub settle: Duration,
    pub dns_transport: TunDnsTransport,
    pub dns_upstream_transport: TunDnsUpstreamTransport,
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
    pub dns_candidates: usize,
    /// Distinct non-matching CIDRs generated per non-final rule. `1` keeps the
    /// original one-`/16`-per-rule shape; larger values expose the per-matcher
    /// cost of `geoip:`-sized rules.
    pub cidrs_per_rule: usize,
    /// Distinct non-matching `domain:` suffixes generated per non-final rule.
    /// `0` keeps the IP-target probe; larger values switch the target to a
    /// domain and expose the per-matcher cost of `geosite:`-sized rules.
    pub domains_per_rule: usize,
    pub out_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPolicyProbeOptions {
    pub iterations: usize,
    pub servers: usize,
    pub matchers: usize,
    /// Number of synthetic `full:` `dns.hosts` entries to index. `0` skips the
    /// hosts slice and leaves the report unchanged.
    pub hosts: usize,
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

#[derive(
    Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash,
)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum BenchmarkPhase {
    #[default]
    Startup = 0,
    Workload = 1,
    Opening = 2,
    Traffic = 3,
    HeldOpen = 4,
    Settle = 5,
    Complete = 6,
}

impl BenchmarkPhase {
    const ALL: [Self; 7] = [
        Self::Startup,
        Self::Workload,
        Self::Opening,
        Self::Traffic,
        Self::HeldOpen,
        Self::Settle,
        Self::Complete,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Workload => "workload",
            Self::Opening => "opening",
            Self::Traffic => "traffic",
            Self::HeldOpen => "held-open",
            Self::Settle => "settle",
            Self::Complete => "complete",
        }
    }

    fn from_raw(raw: u8) -> Self {
        Self::ALL
            .get(usize::from(raw))
            .copied()
            .unwrap_or(Self::Startup)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BenchmarkPhaseTracker(Arc<AtomicU8>);

impl BenchmarkPhaseTracker {
    pub(crate) fn set(&self, phase: BenchmarkPhase) {
        self.0.store(phase as u8, Ordering::Relaxed);
    }

    fn get(&self) -> BenchmarkPhase {
        BenchmarkPhase::from_raw(self.0.load(Ordering::Relaxed))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProcessSample {
    pub elapsed_ms: u128,
    pub rss_kib: u64,
    pub cpu_millis: u64,
    pub threads: Option<u64>,
    #[serde(default)]
    pub phase: BenchmarkPhase,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PhaseMemorySummary {
    pub phase: BenchmarkPhase,
    pub samples: usize,
    pub first_rss_kib: u64,
    pub median_rss_kib: u64,
    pub peak_rss_kib: u64,
    pub last_rss_kib: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WorkspaceGitProvenance {
    #[serde(default)]
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BenchProvenance {
    #[serde(default)]
    pub harness_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_git: Option<WorkspaceGitProvenance>,
    /// Git state of the checkout used to build the measured engine when that
    /// checkout can be identified independently from the harness workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_source_git: Option<WorkspaceGitProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_binary_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_binary_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_binary_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_binary_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<PathBuf>,
    /// Canonical effective `xray-bench run` arguments. This is a vector rather than a
    /// shell-quoted command so paths and values can be replayed without reparsing a shell string.
    #[serde(default)]
    pub invocation_args: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BenchResult {
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub provenance: BenchProvenance,
    pub engine: String,
    pub workload: String,
    pub status: String,
    pub duration_ms: u128,
    /// Payload-only window, when the workload measured one; `duration_ms` minus this is the
    /// connection-setup cost the run paid before any bytes moved.
    #[serde(default)]
    pub transfer_duration_ms: Option<u128>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_traffic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_max_post_bytes: Option<u64>,
    #[serde(default)]
    pub settle_ms: u128,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_phases: Vec<PhaseMemorySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_write_ops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_write_ops_per_second: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_upstream_transport: Option<String>,
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
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub provenance: BenchProvenance,
    pub engine: String,
    pub workload: String,
    pub status: String,
    pub runs: usize,
    pub duration_ms: MetricSummary,
    #[serde(default)]
    pub transfer_duration_ms: Option<MetricSummary>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_traffic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_max_post_bytes: Option<u64>,
    #[serde(default)]
    pub settle_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_write_ops: Option<MetricSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_write_ops_per_second: Option<MetricSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_upstream_transport: Option<String>,
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
    /// (start, end) of the wall-clock span spent moving payload bytes, excluding connection
    /// setup. Workloads that report it get their throughput measured over this window
    /// instead of the whole run. Each connection starts its own clock at its own first
    /// byte, so merging must union the intervals rather than take the longest duration:
    /// two connections with staggered handshakes can have disjoint windows whose union
    /// exceeds either one's span.
    pub transfer_window: Option<(Instant, Instant)>,
    /// Logical payload-bearing `write_all` calls issued by the packet-up pressure workload.
    /// This is deliberately not labelled as an HTTP request count: XHTTP may batch writes.
    pub uplink_write_ops: Option<u64>,
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
        // Each connection starts its own clock at its own first byte, so the merged window
        // is the union of the per-connection windows, not the longer of the two durations:
        // with staggered handshakes the windows can be disjoint, and the union then spans
        // more wall-clock time than either connection's own window.
        self.transfer_window = match (self.transfer_window, other.transfer_window) {
            (Some((start_a, end_a)), Some((start_b, end_b))) => {
                Some((start_a.min(start_b), end_a.max(end_b)))
            }
            (current, incoming) => current.or(incoming),
        };
        self.uplink_write_ops = match (self.uplink_write_ops, other.uplink_write_ops) {
            (Some(current), Some(incoming)) => Some(current.saturating_add(incoming)),
            (current, incoming) => current.or(incoming),
        };
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
    pub binary_path: PathBuf,
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
    dns_server_addr: Option<SocketAddr>,
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
                    dns_server_addr: None,
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
                    dns_server_addr: None,
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
                    dns_server_addr: None,
                    tcp_blackhole_state: None,
                    tasks: vec![task],
                    processes: Vec::new(),
                })
            }
            WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
                let (vless_addr, process) =
                    start_xray_core_reality_vision_server(options, run_dir, binary_dir).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: None,
                    dns_server_addr: None,
                    tcp_blackhole_state: None,
                    tasks: Vec::new(),
                    processes: vec![process],
                })
            }
            WorkloadKind::GrpcBulkThroughput => {
                let (vless_addr, process) =
                    start_xray_core_grpc_server(options, run_dir, binary_dir).await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: None,
                    dns_server_addr: None,
                    tcp_blackhole_state: None,
                    tasks: Vec::new(),
                    processes: vec![process],
                })
            }
            WorkloadKind::StreamTransport => {
                let scenario = options.stream_scenario()?;
                let fixture =
                    stream_transport::start_fixture(options, scenario, run_dir, binary_dir).await?;
                Ok(Self {
                    vless_addr: Some(fixture.addr),
                    vless_tls_cert_sha256: Some(fixture.cert_sha256),
                    dns_server_addr: None,
                    tcp_blackhole_state: None,
                    tasks: Vec::new(),
                    processes: vec![fixture.process],
                })
            }
            WorkloadKind::TunRealityBlackhole => {
                let (vless_addr, task, state) = spawn_tcp_blackhole_server().await?;
                Ok(Self {
                    vless_addr: Some(vless_addr),
                    vless_tls_cert_sha256: None,
                    dns_server_addr: None,
                    tcp_blackhole_state: Some(state),
                    tasks: vec![task],
                    processes: Vec::new(),
                })
            }
            WorkloadKind::TunDnsProxy => {
                let (dns_server_addr, tasks) = spawn_dns_proxy_servers().await?;
                Ok(Self {
                    vless_addr: None,
                    vless_tls_cert_sha256: None,
                    dns_server_addr: Some(dns_server_addr),
                    tcp_blackhole_state: None,
                    tasks,
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
            | WorkloadKind::TunFakeDns
            | WorkloadKind::TunFakeDnsTcp
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
            stream_transport: None,
            stream_traffic: None,
            xhttp_mode: None,
            xhttp_profile: None,
            xhttp_max_post_bytes: None,
            settle: Duration::ZERO,
            dns_transport: TunDnsTransport::default(),
            dns_upstream_transport: TunDnsUpstreamTransport::default(),
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

impl BenchOptions {
    fn stream_scenario(&self) -> Result<StreamBenchScenario, BenchError> {
        if self.workload != WorkloadKind::StreamTransport {
            return Err(BenchError::InvalidArguments(
                "stream benchmark scenario requested for a different workload".to_owned(),
            ));
        }
        let scenario = StreamBenchScenario::resolve(
            self.stream_transport,
            self.stream_traffic,
            self.xhttp_mode,
            self.xhttp_profile,
        )?;
        if self.xhttp_max_post_bytes.is_some() && !scenario.transport.is_xhttp() {
            return Err(BenchError::InvalidArguments(
                "--xhttp-max-post-bytes requires an XHTTP stream transport".to_owned(),
            ));
        }
        scenario.validate_max_post_bytes(self.payload_size, self.xhttp_max_post_bytes)?;
        Ok(scenario)
    }

    fn validate_stream_options(&self) -> Result<(), BenchError> {
        if self.workload == WorkloadKind::StreamTransport {
            self.stream_scenario().map(|_| ())
        } else if self.stream_transport.is_some()
            || self.stream_traffic.is_some()
            || self.xhttp_mode.is_some()
            || self.xhttp_profile.is_some()
            || self.xhttp_max_post_bytes.is_some()
            || !self.settle.is_zero()
        {
            Err(BenchError::InvalidArguments(
                "--stream-transport, --traffic, --xhttp-mode, --xhttp-profile, --xhttp-max-post-bytes, and --settle-ms require --workload stream-transport".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

impl Default for RouteProbeOptions {
    fn default() -> Self {
        Self {
            iterations: 100_000,
            rules: 64,
            outbounds: 8,
            dns_candidates: 0,
            cidrs_per_rule: 1,
            domains_per_rule: 0,
            out_dir: PathBuf::from("target/benchmarks"),
        }
    }
}

impl Default for DnsPolicyProbeOptions {
    fn default() -> Self {
        Self {
            iterations: 10_000,
            servers: 4,
            matchers: 4_096,
            hosts: 0,
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
    #[serde(default)]
    pub dns_candidates: usize,
    #[serde(default = "default_route_probe_cidrs_per_rule")]
    pub cidrs_per_rule: usize,
    #[serde(default)]
    pub domains_per_rule: usize,
    /// Process peak RSS in KiB once the routing config and router are built.
    #[serde(default)]
    pub peak_rss_kib: u64,
    pub selected: usize,
    pub total_us: u128,
    pub avg_ns: u128,
}

fn default_route_probe_cidrs_per_rule() -> usize {
    1
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DnsPolicyProbeMetric {
    pub selected_per_iteration: usize,
    pub compile_us: u128,
    pub compiled_matchers: usize,
    pub pattern_bytes: usize,
    pub total_us: u128,
    pub avg_ns: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DnsIpFilterProbeMetric {
    pub hit_matched: bool,
    pub miss_rejected: bool,
    pub compile_us: u128,
    pub compiled_matchers: usize,
    pub compiled_ranges: usize,
    pub hit_total_us: u128,
    pub hit_avg_ns: u128,
    pub miss_total_us: u128,
    pub miss_avg_ns: u128,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DnsOutboundPolicyProbeMetric {
    pub decision: String,
    pub compile_us: u128,
    pub total_us: u128,
    pub avg_ns: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DnsOutboundSelectorProbeMetric {
    pub rules: usize,
    pub hit_selected_dns: bool,
    #[serde(default)]
    pub last_hit_selected_dns: bool,
    pub miss_preserved_regular_path: bool,
    #[serde(default)]
    pub semantic_miss_preserved_regular_path: bool,
    pub compile_us: u128,
    pub hit_total_us: u128,
    pub hit_avg_ns: u128,
    #[serde(default)]
    pub last_hit_total_us: u128,
    #[serde(default)]
    pub last_hit_avg_ns: u128,
    pub miss_total_us: u128,
    pub miss_avg_ns: u128,
    #[serde(default)]
    pub semantic_miss_total_us: u128,
    #[serde(default)]
    pub semantic_miss_avg_ns: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DnsHostsProbeMetric {
    pub hosts: usize,
    pub hit_matched: bool,
    pub miss_rejected: bool,
    pub compile_us: u128,
    /// Process peak RSS in KiB once the hosts index is built.
    pub peak_rss_kib: u64,
    pub hit_total_us: u128,
    pub hit_avg_ns: u128,
    pub miss_total_us: u128,
    pub miss_avg_ns: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DnsPolicyProbeResult {
    pub iterations: usize,
    pub servers: usize,
    pub matchers: usize,
    pub common_no_domains: DnsPolicyProbeMetric,
    pub worst_case_matchers: DnsPolicyProbeMetric,
    pub worst_case_ip_filter: DnsIpFilterProbeMetric,
    #[serde(default)]
    pub outbound_common_first_rule: DnsOutboundPolicyProbeMetric,
    #[serde(default)]
    pub outbound_worst_ordered_rule_matchers: DnsOutboundPolicyProbeMetric,
    #[serde(default)]
    pub outbound_selector_prefilter: Vec<DnsOutboundSelectorProbeMetric>,
    #[serde(default)]
    pub hosts: Option<DnsHostsProbeMetric>,
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
    if command == "dns-policy-probe" {
        return parse_dns_policy_probe_args(&rest).map(CliArgs::DnsPolicyProbe);
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
            "--stream-transport" => {
                options.stream_transport = Some(StreamBenchTransport::parse(required_value(
                    &rest, &mut index, flag,
                )?)?);
            }
            "--traffic" => {
                options.stream_traffic = Some(StreamBenchTraffic::parse(required_value(
                    &rest, &mut index, flag,
                )?)?);
            }
            "--xhttp-mode" => {
                options.xhttp_mode = Some(StreamBenchXhttpMode::parse(required_value(
                    &rest, &mut index, flag,
                )?)?);
            }
            "--xhttp-profile" => {
                options.xhttp_profile = Some(StreamBenchXhttpProfile::parse(required_value(
                    &rest, &mut index, flag,
                )?)?);
            }
            "--xhttp-max-post-bytes" => {
                options.xhttp_max_post_bytes = Some(parse_nonzero_usize(
                    required_value(&rest, &mut index, flag)?,
                    flag,
                )?);
            }
            "--settle-ms" => {
                options.settle = Duration::from_millis(parse_u64(
                    required_value(&rest, &mut index, flag)?,
                    flag,
                )?);
            }
            "--transport" | "--dns-transport" => {
                options.dns_transport =
                    TunDnsTransport::parse(required_value(&rest, &mut index, flag)?)?;
            }
            "--dns-upstream-transport" => {
                options.dns_upstream_transport =
                    TunDnsUpstreamTransport::parse(required_value(&rest, &mut index, flag)?)?;
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

    options.validate_stream_options()?;

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
        "dns-policy-probe" => {
            unreachable!("dns-policy-probe is parsed before engine benchmark options")
        }
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
            "--dns-candidates" => {
                options.dns_candidates =
                    parse_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--cidrs-per-rule" => {
                options.cidrs_per_rule =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--domains-per-rule" => {
                options.domains_per_rule =
                    parse_usize(required_value(args, &mut index, flag)?, flag)?;
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

fn parse_dns_policy_probe_args(args: &[String]) -> Result<DnsPolicyProbeOptions, BenchError> {
    let mut options = DnsPolicyProbeOptions::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--iterations" => {
                options.iterations =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--servers" => {
                options.servers =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--matchers" => {
                options.matchers =
                    parse_nonzero_usize(required_value(args, &mut index, flag)?, flag)?;
            }
            "--hosts" => {
                options.hosts = parse_usize(required_value(args, &mut index, flag)?, flag)?;
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
        phase: BenchmarkPhase::Startup,
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
    let mut csv = String::from("elapsed_ms,rss_kib,cpu_millis,threads,phase\n");
    for sample in samples {
        let threads = sample
            .threads
            .map(|threads| threads.to_string())
            .unwrap_or_default();
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            sample.elapsed_ms,
            sample.rss_kib,
            sample.cpu_millis,
            threads,
            sample.phase.as_str()
        ));
    }
    fs::write(path, csv).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to write samples csv `{}`: {error}",
            path.display()
        ))
    })
}

pub fn summarize_memory_phases(samples: &[ProcessSample]) -> Vec<PhaseMemorySummary> {
    BenchmarkPhase::ALL
        .into_iter()
        .filter_map(|phase| {
            let phase_samples = samples
                .iter()
                .filter(|sample| sample.phase == phase)
                .collect::<Vec<_>>();
            let first = phase_samples.first()?;
            let last = phase_samples.last().expect("phase has at least one sample");
            let mut rss = phase_samples
                .iter()
                .map(|sample| sample.rss_kib)
                .collect::<Vec<_>>();
            rss.sort_unstable();
            Some(PhaseMemorySummary {
                phase,
                samples: rss.len(),
                first_rss_kib: first.rss_kib,
                median_rss_kib: rss[rss.len() / 2],
                peak_rss_kib: rss.last().copied().unwrap_or_default(),
                last_rss_kib: last.rss_kib,
            })
        })
        .collect()
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
    if results
        .iter()
        .any(|result| result.run_id != first.run_id || result.provenance != first.provenance)
    {
        return Err(BenchError::InvalidArguments(
            "cannot summarize mixed benchmark provenance".to_owned(),
        ));
    }
    if results.iter().any(|result| {
        result.connections != first.connections
            || result.iterations != first.iterations
            || result.payload_size != first.payload_size
            || result.stream_transport != first.stream_transport
            || result.stream_traffic != first.stream_traffic
            || result.xhttp_mode != first.xhttp_mode
            || result.xhttp_profile != first.xhttp_profile
            || result.xhttp_max_post_bytes != first.xhttp_max_post_bytes
            || result.settle_ms != first.settle_ms
            || result.dns_transport != first.dns_transport
            || result.dns_upstream_transport != first.dns_upstream_transport
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
        run_id: first.run_id.clone(),
        provenance: first.provenance.clone(),
        engine: first.engine.clone(),
        workload: first.workload.clone(),
        status: status.to_owned(),
        runs: results.len(),
        duration_ms: summarize_metric(results.iter().map(|result| result.duration_ms)),
        transfer_duration_ms: summarize_optional_metric(
            results.iter().map(|result| result.transfer_duration_ms),
        ),
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
        stream_transport: first.stream_transport.clone(),
        stream_traffic: first.stream_traffic.clone(),
        xhttp_mode: first.xhttp_mode.clone(),
        xhttp_profile: first.xhttp_profile.clone(),
        xhttp_max_post_bytes: first.xhttp_max_post_bytes,
        settle_ms: first.settle_ms,
        uplink_write_ops: summarize_optional_metric(
            results
                .iter()
                .map(|result| result.uplink_write_ops.map(u128::from)),
        ),
        uplink_write_ops_per_second: summarize_optional_metric(
            results
                .iter()
                .map(|result| result.uplink_write_ops_per_second),
        ),
        dns_transport: first.dns_transport.clone(),
        dns_upstream_transport: first.dns_upstream_transport.clone(),
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

/// Bits per second over the window the bytes actually moved in.
///
/// `window_ms` is the whole run window; `transfer` is the payload-only window when the workload
/// measured one. The transfer window wins, so connection setup is never amortized into the rate.
fn throughput_mbps(
    bytes_sent: u64,
    bytes_received: u64,
    window_ms: u128,
    transfer: Option<Duration>,
) -> Option<u128> {
    let bytes = u128::from(bytes_sent) + u128::from(bytes_received);
    let duration_ms = transfer.map_or(window_ms, |transfer| transfer.as_millis());
    if bytes == 0 || duration_ms == 0 {
        return None;
    }
    Some((bytes * 8).div_ceil(duration_ms * 1000))
}

fn operations_per_second(operations: Option<u64>, transfer: Option<Duration>) -> Option<u128> {
    let operations = u128::from(operations?);
    let duration_ns = transfer?.as_nanos();
    if operations == 0 || duration_ns == 0 {
        return None;
    }
    Some((operations * 1_000_000_000).div_ceil(duration_ns))
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
    // The reader times the transfer itself, so dialing through the engine stays out of the
    // throughput denominator: a slow tunnel handshake must not read as a slow tunnel.
    let transfer = read_and_validate_bulk_stream(&mut client, template, iterations).await?;
    Ok(WorkloadOutcome {
        bytes_received: transfer.bytes,
        transfer_window: transfer.window,
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
#[derive(Debug, Clone, Copy)]
struct TunFdRef(RawFd);

#[cfg(unix)]
impl AsRawFd for TunFdRef {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TunFakeDnsQueryKey {
    client_port: u16,
    transaction_id: u16,
    query_type: u16,
}

#[cfg(unix)]
#[derive(Debug)]
struct PreparedTunFakeDnsQuery {
    key: TunFakeDnsQueryKey,
    query: Vec<u8>,
    expectation: TunFakeDnsExpectation,
    frame: Vec<u8>,
}

#[cfg(unix)]
#[derive(Debug)]
struct PendingTunFakeDnsQuery {
    query: Vec<u8>,
    expectation: TunFakeDnsExpectation,
    started: Instant,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunFakeDnsIoEvent {
    Sent(Instant),
    Received(usize),
}

#[cfg(unix)]
#[derive(Debug)]
struct TunDnsTcpPendingQuery {
    query: Vec<u8>,
    expectation: TunFakeDnsExpectation,
    started: Instant,
}

#[cfg(unix)]
struct TunDnsTcpConnection {
    logical_index: usize,
    source_port: u16,
    domain: &'static str,
    expected_ipv4: Ipv4Addr,
    client: TunTcpBenchmarkClient,
    next_query: usize,
    total_queries: usize,
    pending: Option<TunDnsTcpPendingQuery>,
    receive_buffer: Vec<u8>,
    last_validated_response: Instant,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunDnsTcpIoEvent {
    Sent,
    Received(usize),
    Timer,
}

#[cfg(unix)]
pub async fn run_tun_fake_dns_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    run_tun_dns_udp_workload(
        tun_fd,
        options,
        TUN_FAKE_DNS_DOMAIN,
        TUN_FAKE_DNS_FIRST_IPV4,
    )
    .await
}

#[cfg(unix)]
async fn run_tun_dns_proxy_udp_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    run_tun_dns_udp_workload(
        tun_fd,
        options,
        TUN_DNS_PROXY_DOMAIN,
        TUN_DNS_PROXY_ANSWER_IPV4,
    )
    .await
}

#[cfg(unix)]
async fn run_tun_dns_udp_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
    domain: &'static str,
    expected_ipv4: Ipv4Addr,
) -> Result<WorkloadOutcome, BenchError> {
    let total_queries = options
        .connections
        .checked_mul(options.iterations)
        .and_then(|count| count.checked_mul(2))
        .ok_or_else(|| {
            BenchError::InvalidArguments(
                "TUN DNS query count exceeds addressable memory".to_owned(),
            )
        })?;
    let in_flight_limit = options
        .connections
        .saturating_mul(2)
        .clamp(1, TUN_FAKE_DNS_MAX_IN_FLIGHT);
    // `RunningEngine` owns and closes the descriptor after the workload. This wrapper only
    // registers that live descriptor with Tokio; dropping it must not close the underlying fd.
    let tun = AsyncFd::new(TunFdRef(tun_fd)).map_err(|source| BenchError::Io {
        action: "registering benchmark TUN fd for async readiness".to_owned(),
        source,
    })?;
    let source_ip = Ipv4Addr::new(10, 10, 0, 2);
    let mut pending = HashMap::with_capacity(in_flight_limit);
    let mut prepared = None;
    let mut next_query_index = 0usize;
    let mut completed = 0usize;
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut latencies_us = Vec::with_capacity(total_queries);
    let mut read_buffer = vec![0; 65_535 + DARWIN_UTUN_HEADER_LEN];

    while completed < total_queries {
        if prepared.is_none() && next_query_index < total_queries && pending.len() < in_flight_limit
        {
            prepared = Some(prepare_tun_fake_dns_query(
                next_query_index,
                options.connections,
                source_ip,
                &pending,
                domain,
                expected_ipv4,
            )?);
        }

        let send_frame = prepared.as_ref().map(|query| query.frame.as_slice());
        let wait_duration = tun_fake_dns_wait_duration(&pending);
        let event = timeout(
            wait_duration,
            wait_tun_fake_dns_io(&tun, send_frame, !pending.is_empty(), &mut read_buffer),
        )
        .await
        .map_err(|_| tun_fake_dns_timeout_error(&pending, prepared.as_ref()))??;

        match event {
            TunFakeDnsIoEvent::Sent(started) => {
                let query = prepared.take().ok_or_else(|| {
                    BenchError::InvalidArguments(
                        "TUN DNS write completed without a prepared query".to_owned(),
                    )
                })?;
                sent = sent.saturating_add(query.query.len() as u64);
                if pending
                    .insert(
                        query.key,
                        PendingTunFakeDnsQuery {
                            query: query.query,
                            expectation: query.expectation,
                            started,
                        },
                    )
                    .is_some()
                {
                    return Err(BenchError::InvalidArguments(format!(
                        "duplicate in-flight TUN DNS query port={} id=0x{:04x} type={}",
                        query.key.client_port, query.key.transaction_id, query.key.query_type
                    )));
                }
                next_query_index += 1;
            }
            TunFakeDnsIoEvent::Received(len) => {
                let packet = decode_darwin_utun_frame(&read_buffer[..len])?;
                let Some(datagram) = parse_ipv4_udp_datagram(packet) else {
                    continue;
                };
                if datagram.source != TUN_DNS_ANCHOR
                    || datagram.source_port != DNS_PORT
                    || datagram.destination != source_ip
                {
                    continue;
                }
                let Some(transaction_id) = dns_message_id(datagram.payload) else {
                    continue;
                };
                let Some(query_type) = dns_question_type(datagram.payload) else {
                    if pending.keys().any(|key| {
                        key.client_port == datagram.destination_port
                            && key.transaction_id == transaction_id
                    }) {
                        return Err(BenchError::InvalidArguments(format!(
                            "malformed TUN DNS response question port={} id=0x{transaction_id:04x}",
                            datagram.destination_port
                        )));
                    }
                    continue;
                };
                let key = TunFakeDnsQueryKey {
                    client_port: datagram.destination_port,
                    transaction_id,
                    query_type,
                };
                let Some(query) = pending.remove(&key) else {
                    if pending.keys().any(|pending_key| {
                        pending_key.client_port == key.client_port
                            && pending_key.transaction_id == key.transaction_id
                    }) {
                        return Err(BenchError::InvalidArguments(format!(
                            "TUN DNS response type mismatch port={} id=0x{:04x} type={}",
                            key.client_port, key.transaction_id, key.query_type
                        )));
                    }
                    continue;
                };
                validate_tun_fake_dns_response(&query.query, datagram.payload, query.expectation)?;
                received = received.saturating_add(datagram.payload.len() as u64);
                latencies_us.push(query.started.elapsed().as_micros());
                completed += 1;
            }
        }
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
pub async fn run_tun_dns_proxy_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let mut outcome = WorkloadOutcome::empty();
    if options.dns_transport.includes_udp() {
        outcome.extend(run_tun_dns_proxy_udp_workload(tun_fd, options).await?);
    }
    if options.dns_transport.includes_tcp() {
        outcome.extend(run_tun_dns_proxy_tcp_workload(tun_fd, options).await?);
    }
    Ok(outcome)
}

#[cfg(unix)]
async fn run_tun_dns_proxy_tcp_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    run_tun_dns_tcp_workload(
        tun_fd,
        options,
        TUN_DNS_PROXY_DOMAIN,
        TUN_DNS_PROXY_ANSWER_IPV4,
    )
    .await
}

#[cfg(unix)]
async fn run_tun_fake_dns_tcp_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    run_tun_dns_tcp_workload(
        tun_fd,
        options,
        TUN_FAKE_DNS_DOMAIN,
        TUN_FAKE_DNS_FIRST_IPV4,
    )
    .await
}

#[cfg(unix)]
async fn run_tun_dns_tcp_workload(
    tun_fd: RawFd,
    options: &BenchOptions,
    domain: &'static str,
    expected_ipv4: Ipv4Addr,
) -> Result<WorkloadOutcome, BenchError> {
    let queries_per_connection = options.iterations.checked_mul(2).ok_or_else(|| {
        BenchError::InvalidArguments(
            "TUN DNS TCP query count exceeds addressable memory".to_owned(),
        )
    })?;
    let total_queries = options
        .connections
        .checked_mul(queries_per_connection)
        .ok_or_else(|| {
            BenchError::InvalidArguments(
                "TUN DNS TCP query count exceeds addressable memory".to_owned(),
            )
        })?;
    if options.connections == 0 || queries_per_connection == 0 {
        return Err(BenchError::InvalidArguments(
            "TUN DNS TCP requires non-zero connections and iterations".to_owned(),
        ));
    }

    let tun = AsyncFd::new(TunFdRef(tun_fd)).map_err(|source| BenchError::Io {
        action: "registering benchmark TUN fd for DNS-over-TCP readiness".to_owned(),
        source,
    })?;
    let source_ip = Ipv4Addr::new(10, 10, 0, 2);
    let active_limit = options
        .connections
        .clamp(1, TUN_DNS_TCP_MAX_ACTIVE_CONNECTIONS);
    let mut active = Vec::with_capacity(active_limit);
    let mut next_connection = 0usize;
    let mut completed_connections = 0usize;
    let mut outbound_frames = VecDeque::new();
    let mut read_buffer = vec![0_u8; 65_535 + DARWIN_UTUN_HEADER_LEN];
    let mut outcome = WorkloadOutcome {
        latencies_us: Vec::with_capacity(total_queries),
        ..WorkloadOutcome::default()
    };
    let mut last_validated_response = Instant::now();

    loop {
        while active.len() < active_limit && next_connection < options.connections {
            active.push(TunDnsTcpConnection::new(
                next_connection,
                queries_per_connection,
                domain,
                expected_ipv4,
            )?);
            next_connection += 1;
        }

        let mut connection_index = 0usize;
        while connection_index < active.len() {
            let (finished, validated_response) = active[connection_index].drive(&mut outcome)?;
            drain_tun_dns_tcp_outbound(&mut active[connection_index].client, &mut outbound_frames)?;
            if validated_response {
                last_validated_response = Instant::now();
            }
            if finished {
                active[connection_index].client.abort();
                active[connection_index].client.poll();
                drain_tun_dns_tcp_outbound(
                    &mut active[connection_index].client,
                    &mut outbound_frames,
                )?;
                active.swap_remove(connection_index);
                completed_connections += 1;
            } else {
                connection_index += 1;
            }
        }

        if completed_connections == options.connections && outbound_frames.is_empty() {
            if outcome.latencies_us.len() != total_queries {
                return Err(BenchError::InvalidArguments(format!(
                    "TUN DNS TCP completed {} of {total_queries} queries",
                    outcome.latencies_us.len()
                )));
            }
            return Ok(outcome);
        }
        let stalled_connection = active.iter().find(|connection| connection.is_stalled());
        if stalled_connection.is_some()
            || (active.is_empty() && last_validated_response.elapsed() >= TUN_DNS_TCP_STALL_TIMEOUT)
        {
            let stalled_connection = stalled_connection
                .map(|connection| format!("; stalled connection={}", connection.logical_index))
                .unwrap_or_default();
            return Err(BenchError::InvalidArguments(format!(
                "timed out running TUN DNS TCP: completed {completed_connections}/{} connections and {}/{} queries{stalled_connection}",
                options.connections,
                outcome.latencies_us.len(),
                total_queries
            )));
        }

        let stall_wait = active
            .iter()
            .map(TunDnsTcpConnection::stall_wait_duration)
            .min()
            .unwrap_or_else(|| {
                TUN_DNS_TCP_STALL_TIMEOUT.saturating_sub(last_validated_response.elapsed())
            });
        let wait_duration = tun_dns_tcp_poll_delay(&mut active).min(stall_wait);
        let send_frame = outbound_frames.front().map(Vec::as_slice);
        match wait_tun_dns_tcp_io(
            &tun,
            send_frame,
            !active.is_empty(),
            &mut read_buffer,
            wait_duration,
        )
        .await?
        {
            TunDnsTcpIoEvent::Sent => {
                outbound_frames.pop_front();
            }
            TunDnsTcpIoEvent::Received(len) => {
                let packet = decode_darwin_utun_frame(&read_buffer[..len])?;
                let Some(endpoints) = ipv4_tcp_endpoints(packet) else {
                    continue;
                };
                let Some(connection) = active
                    .iter_mut()
                    .find(|connection| connection.source_port == endpoints.destination_port)
                else {
                    continue;
                };
                if endpoints.source != TUN_DNS_ANCHOR
                    || endpoints.source_port != DNS_PORT
                    || endpoints.destination != source_ip
                {
                    return Err(BenchError::InvalidArguments(format!(
                        "TUN DNS TCP response source mismatch: expected {TUN_DNS_ANCHOR}:{DNS_PORT} -> {source_ip}:{}, got {}:{} -> {}:{}",
                        connection.source_port,
                        endpoints.source,
                        endpoints.source_port,
                        endpoints.destination,
                        endpoints.destination_port
                    )));
                }
                connection
                    .client
                    .device
                    .push_inbound(Bytes::copy_from_slice(packet));
            }
            TunDnsTcpIoEvent::Timer => {}
        }
    }
}

#[cfg(unix)]
impl TunDnsTcpConnection {
    fn new(
        logical_index: usize,
        total_queries: usize,
        domain: &'static str,
        expected_ipv4: Ipv4Addr,
    ) -> Result<Self, BenchError> {
        let source_port = 54_000 + (logical_index % 10_000) as u16;
        let mut client = TunTcpBenchmarkClient::new(source_port);
        client.connect(SocketAddr::from((TUN_DNS_ANCHOR, DNS_PORT)))?;
        Ok(Self {
            logical_index,
            source_port,
            domain,
            expected_ipv4,
            client,
            next_query: 0,
            total_queries,
            pending: None,
            receive_buffer: Vec::new(),
            last_validated_response: Instant::now(),
        })
    }

    fn drive(&mut self, outcome: &mut WorkloadOutcome) -> Result<(bool, bool), BenchError> {
        self.client.poll();
        let received = self.client.recv_available();
        let mut validated_response = false;
        self.receive_buffer.extend_from_slice(&received);

        if let Some(response) = take_dns_tcp_message(&mut self.receive_buffer)? {
            let pending = self.pending.take().ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "TUN DNS TCP connection {} received an unsolicited DNS response",
                    self.logical_index
                ))
            })?;
            validate_tun_fake_dns_response(&pending.query, &response, pending.expectation)?;
            outcome.bytes_received = outcome.bytes_received.saturating_add(response.len() as u64);
            let completed_at = Instant::now();
            outcome.latencies_us.push(
                completed_at
                    .saturating_duration_since(pending.started)
                    .as_micros(),
            );
            self.last_validated_response = completed_at;
            validated_response = true;
        }

        if self.pending.is_none() && self.next_query < self.total_queries && self.client.may_send()
        {
            let query_slot = self.next_query % 2;
            let query_type = if query_slot == 0 {
                DNS_TYPE_A
            } else {
                DNS_TYPE_HTTPS
            };
            let expectation = if query_type == DNS_TYPE_A {
                TunFakeDnsExpectation::A(self.expected_ipv4)
            } else {
                TunFakeDnsExpectation::NoData
            };
            let transaction_id = self
                .source_port
                .wrapping_add(self.next_query as u16)
                .wrapping_add((self.logical_index / 10_000) as u16);
            let query = build_dns_query(transaction_id, self.domain, query_type)?;
            let query_len = u16::try_from(query.len()).map_err(|_| {
                BenchError::InvalidArguments("TUN DNS TCP query exceeds 65535 bytes".to_owned())
            })?;
            let mut frame = Vec::with_capacity(query.len() + 2);
            frame.extend_from_slice(&query_len.to_be_bytes());
            frame.extend_from_slice(&query);
            let started = Instant::now();
            self.client.send_payload(&frame)?;
            outcome.bytes_sent = outcome.bytes_sent.saturating_add(query.len() as u64);
            self.pending = Some(TunDnsTcpPendingQuery {
                query,
                expectation,
                started,
            });
            self.next_query += 1;
            self.client.poll();
        }

        Ok((
            self.next_query == self.total_queries && self.pending.is_none(),
            validated_response,
        ))
    }

    fn stall_started(&self) -> Instant {
        self.pending
            .as_ref()
            .map(|pending| pending.started)
            .unwrap_or(self.last_validated_response)
    }

    fn is_stalled(&self) -> bool {
        self.stall_started().elapsed() >= TUN_DNS_TCP_STALL_TIMEOUT
    }

    fn stall_wait_duration(&self) -> Duration {
        TUN_DNS_TCP_STALL_TIMEOUT.saturating_sub(self.stall_started().elapsed())
    }
}

#[cfg(unix)]
fn take_dns_tcp_message(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, BenchError> {
    let Some(length) = buffer
        .get(..2)
        .map(|prefix| usize::from(u16::from_be_bytes([prefix[0], prefix[1]])))
    else {
        return Ok(None);
    };
    if length == 0 {
        return Err(BenchError::InvalidArguments(
            "TUN DNS TCP received a zero-length DNS message".to_owned(),
        ));
    }
    let frame_len = length + 2;
    if buffer.len() < frame_len {
        return Ok(None);
    }
    let response = buffer[2..frame_len].to_vec();
    buffer.drain(..frame_len);
    Ok(Some(response))
}

#[cfg(unix)]
fn drain_tun_dns_tcp_outbound(
    client: &mut TunTcpBenchmarkClient,
    outbound: &mut VecDeque<Vec<u8>>,
) -> Result<(), BenchError> {
    while let Some(packet) = client.device.pop_outbound() {
        if outbound.len() >= TUN_DNS_TCP_MAX_QUEUED_FRAMES {
            return Err(BenchError::InvalidArguments(format!(
                "TUN DNS TCP exceeded its {TUN_DNS_TCP_MAX_QUEUED_FRAMES}-frame backpressure queue"
            )));
        }
        outbound.push_back(encode_darwin_utun_frame(&packet));
    }
    Ok(())
}

#[cfg(unix)]
fn tun_dns_tcp_poll_delay(active: &mut [TunDnsTcpConnection]) -> Duration {
    let now = SmolInstant::now();
    active
        .iter_mut()
        .filter_map(|connection| connection.client.poll_at())
        .map(|deadline| {
            Duration::from_micros(
                deadline
                    .total_micros()
                    .saturating_sub(now.total_micros())
                    .max(0) as u64,
            )
        })
        .min()
        .unwrap_or(Duration::from_millis(50))
}

#[cfg(unix)]
async fn wait_tun_dns_tcp_io(
    tun: &AsyncFd<TunFdRef>,
    send_frame: Option<&[u8]>,
    can_receive: bool,
    read_buffer: &mut [u8],
    timer: Duration,
) -> Result<TunDnsTcpIoEvent, BenchError> {
    match (send_frame, can_receive) {
        (Some(frame), true) => {
            tokio::select! {
                biased;
                result = write_tun_frame_ready(tun, frame) => {
                    result.map(|_| TunDnsTcpIoEvent::Sent)
                }
                result = read_tun_frame_ready(tun, read_buffer) => {
                    result.map(TunDnsTcpIoEvent::Received)
                }
                () = sleep(timer) => Ok(TunDnsTcpIoEvent::Timer),
            }
        }
        (Some(frame), false) => {
            tokio::select! {
                result = write_tun_frame_ready(tun, frame) => {
                    result.map(|_| TunDnsTcpIoEvent::Sent)
                }
                () = sleep(timer) => Ok(TunDnsTcpIoEvent::Timer),
            }
        }
        (None, true) => {
            tokio::select! {
                result = read_tun_frame_ready(tun, read_buffer) => {
                    result.map(TunDnsTcpIoEvent::Received)
                }
                () = sleep(timer) => Ok(TunDnsTcpIoEvent::Timer),
            }
        }
        (None, false) => {
            sleep(timer).await;
            Ok(TunDnsTcpIoEvent::Timer)
        }
    }
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
pub async fn run_tun_fake_dns_workload(
    _tun_fd: i32,
    _options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-fake-dns workload requires Unix fd support".to_owned(),
    ))
}

#[cfg(not(unix))]
pub async fn run_tun_fake_dns_tcp_workload(
    _tun_fd: i32,
    _options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-fake-dns-tcp workload requires Unix fd support".to_owned(),
    ))
}

#[cfg(not(unix))]
pub async fn run_tun_dns_proxy_workload(
    _tun_fd: i32,
    _options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-dns-proxy workload requires Unix fd support".to_owned(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BulkTransfer {
    bytes: u64,
    /// (first byte in, last validated byte out), or `None` when no bytes moved.
    window: Option<(Instant, Instant)>,
}

async fn read_and_validate_bulk_stream<R>(
    reader: &mut R,
    template: &[u8],
    iterations: usize,
) -> Result<BulkTransfer, BenchError>
where
    R: AsyncRead + Unpin,
{
    let mut received = 0u64;
    // Chunk == template so validation is one slice comparison per chunk,
    // keeping harness-side CPU out of the measured transfer.
    let mut chunk = vec![0; template.len()];
    let mut started: Option<Instant> = None;
    for _ in 0..iterations {
        let mut filled = 0;
        while filled < chunk.len() {
            let read =
                reader
                    .read(&mut chunk[filled..])
                    .await
                    .map_err(|source| BenchError::Io {
                        action: "reading bulk stream chunk".to_owned(),
                        source,
                    })?;
            if read == 0 {
                return Err(BenchError::Io {
                    action: "reading bulk stream chunk".to_owned(),
                    source: io::Error::from(io::ErrorKind::UnexpectedEof),
                });
            }
            // The clock starts when the first byte lands, not when the read is issued:
            // whatever a tunnel spends before it delivers anything is setup latency, and
            // charging it to the transfer would report a slow handshake as a slow stream.
            started.get_or_insert_with(Instant::now);
            filled += read;
        }
        if chunk != template {
            return Err(BenchError::InvalidArguments(
                "bulk stream payload mismatch".to_owned(),
            ));
        }
        received += chunk.len() as u64;
    }
    Ok(BulkTransfer {
        bytes: received,
        window: started.map(|started| (started, Instant::now())),
    })
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunFakeDnsExpectation {
    A(Ipv4Addr),
    NoData,
}

#[cfg(unix)]
fn prepare_tun_fake_dns_query(
    query_index: usize,
    connections: usize,
    source_ip: Ipv4Addr,
    pending: &HashMap<TunFakeDnsQueryKey, PendingTunFakeDnsQuery>,
    domain: &str,
    expected_ipv4: Ipv4Addr,
) -> Result<PreparedTunFakeDnsQuery, BenchError> {
    if connections == 0 {
        return Err(BenchError::InvalidArguments(
            "TUN DNS requires at least one connection".to_owned(),
        ));
    }
    let queries_per_iteration = connections.checked_mul(2).ok_or_else(|| {
        BenchError::InvalidArguments("TUN DNS connection count is too large".to_owned())
    })?;
    let within_iteration = query_index % queries_per_iteration;
    let iteration = query_index / queries_per_iteration;
    // Fill one query per logical connection before scheduling that connection's second
    // query. This makes `--connections` actual concurrent DNS traffic up to the bounded
    // window, instead of filling the window with A/HTTPS pairs from only its first half.
    let query_slot = within_iteration / connections;
    let connection_index = within_iteration % connections;
    let (query_type, expectation) = match query_slot {
        0 => (DNS_TYPE_A, TunFakeDnsExpectation::A(expected_ipv4)),
        _ => (DNS_TYPE_HTTPS, TunFakeDnsExpectation::NoData),
    };
    let source_port = 53_000 + (connection_index % 10_000) as u16;
    let sequence = iteration.wrapping_mul(2).wrapping_add(query_slot);
    let mut transaction_id = source_port
        .wrapping_add(sequence as u16)
        .wrapping_add((connection_index / 10_000) as u16);
    let mut key = None;
    for _ in 0..=u16::MAX {
        let candidate = TunFakeDnsQueryKey {
            client_port: source_port,
            transaction_id,
            query_type,
        };
        if !pending.contains_key(&candidate) {
            key = Some(candidate);
            break;
        }
        transaction_id = transaction_id.wrapping_add(1);
    }
    let key = key.ok_or_else(|| {
        BenchError::InvalidArguments(format!(
            "no free DNS transaction id for benchmark client port {source_port}"
        ))
    })?;
    let query = build_dns_query(key.transaction_id, domain, query_type)?;
    let packet = ipv4_udp_packet(source_ip, source_port, TUN_DNS_ANCHOR, DNS_PORT, &query)?;
    Ok(PreparedTunFakeDnsQuery {
        key,
        query,
        expectation,
        frame: encode_darwin_utun_frame(&packet),
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
fn tun_fake_dns_wait_duration(
    pending: &HashMap<TunFakeDnsQueryKey, PendingTunFakeDnsQuery>,
) -> Duration {
    pending
        .values()
        .map(|query| TUN_FAKE_DNS_IO_TIMEOUT.saturating_sub(query.started.elapsed()))
        .min()
        .unwrap_or(TUN_FAKE_DNS_IO_TIMEOUT)
}

#[cfg(unix)]
fn tun_fake_dns_timeout_error(
    pending: &HashMap<TunFakeDnsQueryKey, PendingTunFakeDnsQuery>,
    prepared: Option<&PreparedTunFakeDnsQuery>,
) -> BenchError {
    if let Some((key, _)) = pending.iter().min_by_key(|(_, query)| query.started) {
        return BenchError::InvalidArguments(format!(
            "timed out waiting for TUN DNS response port={} id=0x{:04x} type={}",
            key.client_port, key.transaction_id, key.query_type
        ));
    }
    if let Some(query) = prepared {
        return BenchError::InvalidArguments(format!(
            "timed out writing TUN DNS query port={} id=0x{:04x} type={}",
            query.key.client_port, query.key.transaction_id, query.key.query_type
        ));
    }
    BenchError::InvalidArguments("TUN DNS workload stalled without pending I/O".to_owned())
}

#[cfg(unix)]
async fn wait_tun_fake_dns_io(
    tun: &AsyncFd<TunFdRef>,
    send_frame: Option<&[u8]>,
    can_receive: bool,
    buffer: &mut [u8],
) -> Result<TunFakeDnsIoEvent, BenchError> {
    match (send_frame, can_receive) {
        (Some(frame), true) => {
            tokio::select! {
                biased;
                // Fill the bounded window while the fd accepts writes. Once the window is
                // full the caller disables this branch; on EAGAIN/ENOBUFS it remains pending
                // and a ready response can still drain backpressure.
                result = write_tun_frame_ready(tun, frame) => {
                    result.map(TunFakeDnsIoEvent::Sent)
                }
                result = read_tun_frame_ready(tun, buffer) => {
                    result.map(TunFakeDnsIoEvent::Received)
                }
            }
        }
        (Some(frame), false) => write_tun_frame_ready(tun, frame)
            .await
            .map(TunFakeDnsIoEvent::Sent),
        (None, true) => read_tun_frame_ready(tun, buffer)
            .await
            .map(TunFakeDnsIoEvent::Received),
        (None, false) => Err(BenchError::InvalidArguments(
            "TUN DNS workload has neither readable nor writable work".to_owned(),
        )),
    }
}

#[cfg(unix)]
async fn write_tun_frame_ready(
    tun: &AsyncFd<TunFdRef>,
    frame: &[u8],
) -> Result<Instant, BenchError> {
    loop {
        let mut ready = tun.writable().await.map_err(|source| BenchError::Io {
            action: "waiting for benchmark TUN fd to become writable".to_owned(),
            source,
        })?;
        match ready.try_io(|inner| try_write_tun_frame(inner.get_ref().as_raw_fd(), frame)) {
            Ok(Ok(started)) => return Ok(started),
            Ok(Err(source)) => {
                return Err(BenchError::Io {
                    action: "writing benchmark TUN frame".to_owned(),
                    source,
                });
            }
            Err(_) => continue,
        }
    }
}

#[cfg(unix)]
async fn read_tun_frame_ready(
    tun: &AsyncFd<TunFdRef>,
    buffer: &mut [u8],
) -> Result<usize, BenchError> {
    loop {
        let mut ready = tun.readable().await.map_err(|source| BenchError::Io {
            action: "waiting for benchmark TUN fd to become readable".to_owned(),
            source,
        })?;
        match ready.try_io(|inner| try_read_tun_frame(inner.get_ref().as_raw_fd(), buffer)) {
            Ok(Ok(len)) => return Ok(len),
            Ok(Err(source)) => {
                return Err(BenchError::Io {
                    action: "reading benchmark TUN frame".to_owned(),
                    source,
                });
            }
            Err(_) => continue,
        }
    }
}

#[cfg(unix)]
fn try_write_tun_frame(fd: RawFd, frame: &[u8]) -> io::Result<Instant> {
    loop {
        let started = Instant::now();
        // SAFETY: `fd` is owned by the live `RunningEngine`; `frame` is readable for its full len.
        let written = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
        if written < 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // macOS can report a full local datagram socket buffer as ENOBUFS even after
            // kqueue advertised writability. Treat it as transient backpressure so AsyncFd
            // clears the readiness bit and waits for the engine to drain its side.
            if source.raw_os_error() == Some(libc::ENOBUFS) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            return Err(source);
        }
        if written as usize != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short TUN frame write: wrote {written} of {} bytes",
                    frame.len()
                ),
            ));
        }
        return Ok(started);
    }
}

#[cfg(unix)]
fn try_read_tun_frame(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `fd` is owned by the live `RunningEngine`; `buffer` is writable for its full len.
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(source);
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "benchmark TUN fd reached EOF",
            ));
        }
        return Ok(read as usize);
    }
}

#[cfg(unix)]
fn build_dns_query(
    transaction_id: u16,
    domain: &str,
    query_type: u16,
) -> Result<Vec<u8>, BenchError> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return Err(BenchError::InvalidArguments(format!(
            "invalid benchmark DNS domain `{domain}`"
        )));
    }

    let mut query = Vec::with_capacity(12 + domain.len() + 6);
    query.extend_from_slice(&transaction_id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(BenchError::InvalidArguments(format!(
                "invalid benchmark DNS label `{label}`"
            )));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(query)
}

#[cfg(unix)]
fn dns_message_id(message: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*message.first()?, *message.get(1)?]))
}

#[cfg(unix)]
fn dns_question_type(message: &[u8]) -> Option<u16> {
    if message.len() < 12 || u16::from_be_bytes([message[4], message[5]]) != 1 {
        return None;
    }
    let mut offset = 12usize;
    loop {
        let label_len = usize::from(*message.get(offset)?);
        offset += 1;
        if label_len == 0 {
            break;
        }
        if label_len & 0xc0 == 0xc0 {
            offset = offset.checked_add(1)?;
            break;
        }
        if label_len > 63 {
            return None;
        }
        offset = offset.checked_add(label_len)?;
        if offset > message.len() {
            return None;
        }
    }
    Some(u16::from_be_bytes([
        *message.get(offset)?,
        *message.get(offset + 1)?,
    ]))
}

#[cfg(unix)]
fn validate_tun_fake_dns_response(
    query: &[u8],
    response: &[u8],
    expectation: TunFakeDnsExpectation,
) -> Result<(), BenchError> {
    if query.len() < 12 || response.len() < query.len() {
        return Err(BenchError::InvalidArguments(
            "truncated TUN DNS response".to_owned(),
        ));
    }
    if response[0..2] != query[0..2] {
        return Err(BenchError::InvalidArguments(
            "TUN DNS transaction id mismatch".to_owned(),
        ));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return Err(BenchError::InvalidArguments(format!(
            "TUN DNS response has unexpected flags 0x{flags:04x}"
        )));
    }
    if u16::from_be_bytes([response[4], response[5]]) != 1 {
        return Err(BenchError::InvalidArguments(
            "TUN DNS response must contain one question".to_owned(),
        ));
    }
    if response[12..query.len()] != query[12..] {
        return Err(BenchError::InvalidArguments(
            "TUN DNS response question mismatch".to_owned(),
        ));
    }

    let answer_count = u16::from_be_bytes([response[6], response[7]]);
    match expectation {
        TunFakeDnsExpectation::NoData if answer_count == 0 => Ok(()),
        TunFakeDnsExpectation::NoData => Err(BenchError::InvalidArguments(format!(
            "TUN DNS NODATA response contains {answer_count} answers"
        ))),
        TunFakeDnsExpectation::A(expected_ip) => {
            if answer_count != 1 {
                return Err(BenchError::InvalidArguments(format!(
                    "TUN DNS A response contains {answer_count} answers"
                )));
            }
            let answer = response.get(query.len()..).ok_or_else(|| {
                BenchError::InvalidArguments("missing TUN DNS A answer".to_owned())
            })?;
            if answer.len() < 16
                || answer[0..2] != [0xc0, 0x0c]
                || u16::from_be_bytes([answer[2], answer[3]]) != DNS_TYPE_A
                || u16::from_be_bytes([answer[4], answer[5]]) != DNS_CLASS_IN
                || u16::from_be_bytes([answer[10], answer[11]]) != 4
            {
                return Err(BenchError::InvalidArguments(
                    "malformed TUN DNS A answer".to_owned(),
                ));
            }
            let actual_ip = Ipv4Addr::new(answer[12], answer[13], answer[14], answer[15]);
            if actual_ip != expected_ip {
                return Err(BenchError::InvalidArguments(format!(
                    "TUN DNS A answer mismatch: expected {expected_ip}, got {actual_ip}"
                )));
            }
            Ok(())
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

    fn poll_at(&mut self) -> Option<SmolInstant> {
        self.iface.poll_at(SmolInstant::now(), &self.sockets)
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4TcpEndpoints {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
}

#[cfg(unix)]
fn ipv4_tcp_endpoints(packet: &[u8]) -> Option<Ipv4TcpEndpoints> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != TCP_PROTOCOL {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 4 {
        return None;
    }
    Some(Ipv4TcpEndpoints {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        source_port: u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
        destination_port: u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
    })
}

#[cfg(unix)]
fn ipv4_tcp_destination_port(packet: &[u8]) -> Option<u16> {
    ipv4_tcp_endpoints(packet).map(|endpoints| endpoints.destination_port)
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

#[cfg(unix)]
fn build_dns_proxy_fixture_response(query: &[u8]) -> Result<Vec<u8>, BenchError> {
    if query.len() < 12 || u16::from_be_bytes([query[2], query[3]]) & 0x8000 != 0 {
        return Err(BenchError::InvalidArguments(
            "DNS proxy fixture received a malformed query".to_owned(),
        ));
    }
    let query_type = dns_question_type(query).ok_or_else(|| {
        BenchError::InvalidArguments("DNS proxy fixture query has no question type".to_owned())
    })?;
    let mut response = query.to_vec();
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    response[2..4].copy_from_slice(&(0x8080 | (request_flags & 0x0100)).to_be_bytes());
    response[6..12].fill(0);
    if query_type == DNS_TYPE_A {
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[
            0xc0,
            0x0c,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            30,
            0,
            4,
            TUN_DNS_PROXY_ANSWER_IPV4.octets()[0],
            TUN_DNS_PROXY_ANSWER_IPV4.octets()[1],
            TUN_DNS_PROXY_ANSWER_IPV4.octets()[2],
            TUN_DNS_PROXY_ANSWER_IPV4.octets()[3],
        ]);
    }
    Ok(response)
}

#[cfg(unix)]
trait DnsProxyFixtureObserver: Clone + Send + Sync + 'static {
    #[inline]
    fn record_udp_query(&self, _query: &[u8]) {}

    #[inline]
    fn record_tcp_query(&self, _query: &[u8]) {}
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
struct IgnoreDnsProxyFixtureQueries;

#[cfg(unix)]
impl DnsProxyFixtureObserver for IgnoreDnsProxyFixtureQueries {}

#[cfg(all(unix, test))]
#[derive(Debug, Default)]
struct DnsProxyFixtureCounters {
    udp_a_queries: AtomicU64,
    udp_https_queries: AtomicU64,
    udp_other_queries: AtomicU64,
    tcp_a_queries: AtomicU64,
    tcp_https_queries: AtomicU64,
    tcp_other_queries: AtomicU64,
}

#[cfg(all(unix, test))]
#[derive(Debug, Default, PartialEq, Eq)]
struct DnsProxyFixtureQueryCounts {
    udp_a_queries: u64,
    udp_https_queries: u64,
    udp_other_queries: u64,
    tcp_a_queries: u64,
    tcp_https_queries: u64,
    tcp_other_queries: u64,
}

#[cfg(all(unix, test))]
impl DnsProxyFixtureCounters {
    fn snapshot(&self) -> DnsProxyFixtureQueryCounts {
        DnsProxyFixtureQueryCounts {
            udp_a_queries: self.udp_a_queries.load(Ordering::Relaxed),
            udp_https_queries: self.udp_https_queries.load(Ordering::Relaxed),
            udp_other_queries: self.udp_other_queries.load(Ordering::Relaxed),
            tcp_a_queries: self.tcp_a_queries.load(Ordering::Relaxed),
            tcp_https_queries: self.tcp_https_queries.load(Ordering::Relaxed),
            tcp_other_queries: self.tcp_other_queries.load(Ordering::Relaxed),
        }
    }

    fn record_query(
        query: &[u8],
        a_queries: &AtomicU64,
        https_queries: &AtomicU64,
        other_queries: &AtomicU64,
    ) {
        let counter = match dns_question_type(query) {
            Some(DNS_TYPE_A) => a_queries,
            Some(DNS_TYPE_HTTPS) => https_queries,
            Some(_) | None => other_queries,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(all(unix, test))]
impl DnsProxyFixtureObserver for Arc<DnsProxyFixtureCounters> {
    fn record_udp_query(&self, query: &[u8]) {
        DnsProxyFixtureCounters::record_query(
            query,
            &self.udp_a_queries,
            &self.udp_https_queries,
            &self.udp_other_queries,
        );
    }

    fn record_tcp_query(&self, query: &[u8]) {
        DnsProxyFixtureCounters::record_query(
            query,
            &self.tcp_a_queries,
            &self.tcp_https_queries,
            &self.tcp_other_queries,
        );
    }
}

#[cfg(unix)]
async fn handle_dns_proxy_tcp_connection<O>(
    mut stream: TcpStream,
    observer: O,
) -> Result<(), BenchError>
where
    O: DnsProxyFixtureObserver,
{
    loop {
        let mut length = [0_u8; 2];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(source) => {
                return Err(BenchError::Io {
                    action: "reading DNS proxy fixture TCP length".to_owned(),
                    source,
                });
            }
        }
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream
            .read_exact(&mut query)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading DNS proxy fixture TCP query".to_owned(),
                source,
            })?;
        observer.record_tcp_query(&query);
        let response = build_dns_proxy_fixture_response(&query)?;
        let response_len = u16::try_from(response.len()).map_err(|_| {
            BenchError::InvalidArguments(
                "DNS proxy fixture TCP response exceeds 65535 bytes".to_owned(),
            )
        })?;
        stream
            .write_all(&response_len.to_be_bytes())
            .await
            .map_err(|source| BenchError::Io {
                action: "writing DNS proxy fixture TCP length".to_owned(),
                source,
            })?;
        stream
            .write_all(&response)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing DNS proxy fixture TCP payload".to_owned(),
                source,
            })?;
    }
}

#[cfg(unix)]
async fn spawn_dns_proxy_servers() -> Result<(SocketAddr, Vec<JoinHandle<()>>), BenchError> {
    spawn_dns_proxy_servers_with_observer(IgnoreDnsProxyFixtureQueries).await
}

#[cfg(unix)]
async fn spawn_dns_proxy_servers_with_observer<O>(
    observer: O,
) -> Result<(SocketAddr, Vec<JoinHandle<()>>), BenchError>
where
    O: DnsProxyFixtureObserver,
{
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding DNS proxy UDP fixture".to_owned(),
            source,
        })?;
    let addr = udp.local_addr().map_err(|source| BenchError::Io {
        action: "reading DNS proxy UDP fixture address".to_owned(),
        source,
    })?;
    let tcp = TcpListener::bind(addr)
        .await
        .map_err(|source| BenchError::Io {
            action: "binding DNS proxy TCP fixture".to_owned(),
            source,
        })?;

    let udp_observer = observer.clone();
    let udp_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; u16::MAX as usize];
        loop {
            let Ok((len, peer)) = udp.recv_from(&mut buffer).await else {
                break;
            };
            udp_observer.record_udp_query(&buffer[..len]);
            let Ok(response) = build_dns_proxy_fixture_response(&buffer[..len]) else {
                continue;
            };
            let _ = udp.send_to(&response, peer).await;
        }
    });
    let tcp_observer = observer;
    let tcp_task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = tcp.accept() => {
                    let Ok((stream, _peer)) = accepted else {
                        break;
                    };
                    let connection_observer = tcp_observer.clone();
                    connections.spawn(async move {
                        if let Err(error) = handle_dns_proxy_tcp_connection(
                            stream,
                            connection_observer,
                        )
                        .await
                        {
                            eprintln!("DNS proxy TCP fixture error: {error}");
                        }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        connections.abort_all();
    });
    Ok((addr, vec![udp_task, tcp_task]))
}

#[cfg(all(unix, test))]
async fn spawn_counted_dns_proxy_servers() -> Result<
    (
        SocketAddr,
        Vec<JoinHandle<()>>,
        Arc<DnsProxyFixtureCounters>,
    ),
    BenchError,
> {
    let counters = Arc::new(DnsProxyFixtureCounters::default());
    let (addr, tasks) = spawn_dns_proxy_servers_with_observer(Arc::clone(&counters)).await?;
    Ok((addr, tasks, counters))
}

#[cfg(not(unix))]
async fn spawn_dns_proxy_servers() -> Result<(SocketAddr, Vec<JoinHandle<()>>), BenchError> {
    Err(BenchError::InvalidArguments(
        "tun-dns-proxy workload requires Unix fd support".to_owned(),
    ))
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
    sample_while_phased(pid, interval, BenchmarkPhaseTracker::default(), future).await
}

async fn sample_while_phased<F, T>(
    pid: u32,
    interval: Duration,
    phase: BenchmarkPhaseTracker,
    future: F,
) -> Result<(T, Vec<ProcessSample>), BenchError>
where
    F: Future<Output = Result<T, BenchError>>,
{
    let start = Instant::now();
    let mut samples = Vec::new();
    samples.push(sample_process(pid, start, phase.get())?);
    let mut future = Box::pin(future);
    loop {
        tokio::select! {
            result = &mut future => {
                let result = result?;
                samples.push(sample_process(pid, start, phase.get())?);
                return Ok((result, samples));
            }
            () = sleep(interval) => {
                samples.push(sample_process(pid, start, phase.get())?);
            }
        }
    }
}

fn sample_process(
    pid: u32,
    start: Instant,
    phase: BenchmarkPhase,
) -> Result<ProcessSample, BenchError> {
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
    sample.phase = phase;
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
        WorkloadKind::VisionXudp => vision_xudp_config(
            port,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
            PLACEHOLDER_TLS_CERT_SHA256,
        ),
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
            reality_vision_xudp_config(port, SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
        WorkloadKind::TunFakeDns | WorkloadKind::TunFakeDnsTcp => tun_fake_dns_config(),
        WorkloadKind::TunDnsProxy => tun_dns_proxy_config(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            TunDnsUpstreamTransport::Classic,
        ),
        WorkloadKind::TunUdpFreedom
        | WorkloadKind::TunTcpFreedom
        | WorkloadKind::TunTcpStaleFlows => tun_freedom_config(),
        WorkloadKind::TunRealityBlackhole => {
            tun_reality_blackhole_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
        WorkloadKind::GrpcBulkThroughput => {
            vless_grpc_config(port, SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
        // The public legacy helper has no transport/traffic axes. Runtime config
        // generation for this parameterized workload goes through `start_engine`.
        WorkloadKind::StreamTransport => freedom_config(port, false),
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
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "{} workload requires a VLESS Reality server fixture",
                    workload.as_str()
                ))
            })?;
            Ok(sing_box_reality_vision_xudp_config(port, vless_addr))
        }
        WorkloadKind::GrpcBulkThroughput => {
            let vless_addr = grpc_fixture_vless_addr(workload, fixture)?;
            Ok(sing_box_vless_grpc_config(port, vless_addr))
        }
        WorkloadKind::StreamTransport => Err(BenchError::InvalidArguments(
            "stream-transport config requires the parameterized benchmark options".to_owned(),
        )),
        _ if workload.supports_sing_box_process_engine() => Ok(sing_box_direct_config(port)),
        _ => Err(BenchError::InvalidArguments(format!(
            "unsupported sing-box workload `{}` in process-level comparison",
            workload.as_str()
        ))),
    }
}

#[cfg(test)]
fn engine_config(
    engine: EngineKind,
    port: u16,
    workload: WorkloadKind,
    fixture: &WorkloadFixture,
) -> Result<String, BenchError> {
    engine_config_with_dns_upstream(
        engine,
        port,
        workload,
        fixture,
        TunDnsUpstreamTransport::Classic,
    )
}

fn engine_config_with_dns_upstream(
    engine: EngineKind,
    port: u16,
    workload: WorkloadKind,
    fixture: &WorkloadFixture,
    dns_upstream_transport: TunDnsUpstreamTransport,
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
                EngineKind::XrayRust | EngineKind::XrayCore => {
                    let cert_sha256 =
                        fixture.vless_tls_cert_sha256.as_deref().ok_or_else(|| {
                            BenchError::InvalidArguments(
                                "vision-xudp workload requires fake VLESS TLS certificate pin"
                                    .to_owned(),
                            )
                        })?;
                    Ok(vision_xudp_config(port, vless_addr, cert_sha256))
                }
                EngineKind::SingBox => Err(BenchError::InvalidArguments(
                    "vision-xudp workload is not supported by sing-box process engine".to_owned(),
                )),
            }
        }
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "{} workload requires a VLESS Reality server fixture",
                    workload.as_str()
                ))
            })?;
            Ok(reality_vision_xudp_config(port, vless_addr))
        }
        WorkloadKind::GrpcBulkThroughput => {
            let vless_addr = grpc_fixture_vless_addr(workload, fixture)?;
            Ok(vless_grpc_config(port, vless_addr))
        }
        WorkloadKind::StreamTransport => Err(BenchError::InvalidArguments(
            "stream-transport config requires the parameterized benchmark options".to_owned(),
        )),
        WorkloadKind::TunRealityBlackhole => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(
                    "tun-reality-blackhole workload requires a TCP blackhole fixture".to_owned(),
                )
            })?;
            Ok(tun_reality_blackhole_config(vless_addr))
        }
        WorkloadKind::TunFakeDns | WorkloadKind::TunFakeDnsTcp => match engine {
            EngineKind::XrayRust => Ok(tun_fake_dns_config()),
            EngineKind::XrayCore | EngineKind::SingBox => Err(BenchError::InvalidArguments(
                "fake-DNS TUN workloads currently support only --engine xray-rust because dns.fakeIp is an xray-rust config extension"
                    .to_owned(),
            )),
        },
        WorkloadKind::TunDnsProxy => match engine {
            EngineKind::XrayRust => {
                let upstream = fixture.dns_server_addr.ok_or_else(|| {
                    BenchError::InvalidArguments(
                        "tun-dns-proxy workload requires a DNS server fixture".to_owned(),
                    )
                })?;
                Ok(tun_dns_proxy_config(upstream, dns_upstream_transport))
            }
            EngineKind::XrayCore | EngineKind::SingBox => Err(BenchError::InvalidArguments(
                "tun-dns-proxy currently supports only --engine xray-rust".to_owned(),
            )),
        },
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

/// The `serviceName` every engine in the gRPC comparison dials.
///
/// It carries no leading `/`, which is the dialect all three clients agree on:
/// Xray escapes such a name whole and appends the `Tun` stream name
/// (`Xray-core/transport/internet/grpc/config.go:17-59`), and sing-box's lite
/// client hardcodes the same shape, `"/" + service_name + "/Tun"`
/// (`transport/v2raygrpclite/client.go:56-59`). A leading-slash custom path
/// would be an Xray-only spelling and would take sing-box out of the run.
const GRPC_BENCH_SERVICE_NAME: &str = "bench";

fn sing_box_vless_grpc_config(port: u16, vless_addr: SocketAddr) -> String {
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
      "transport": {{
        "type": "grpc",
        "service_name": "{GRPC_BENCH_SERVICE_NAME}"
      }}
    }}
  ],
  "route": {{ "final": "proxy" }}
}}"#,
        vless_addr.ip(),
        vless_addr.port()
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

fn tun_fake_dns_config() -> String {
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
  ],
  "dns": {
    "fakeIp": {
      "enabled": true,
      "ipv4Pool": "198.19.0.0/16",
      "poolSize": 32768,
      "ttl": 60
    }
  }
}"#
    .to_owned()
}

fn tun_dns_proxy_config(
    upstream: SocketAddr,
    upstream_transport: TunDnsUpstreamTransport,
) -> String {
    let server = upstream_transport.server(upstream);
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "tun-in",
      "protocol": "tun",
      "listen": "127.0.0.1",
      "port": 0,
      "settings": {{ "name": "utun9", "MTU": 1500 }}
    }}
  ],
  "outbounds": [
    {{
      "tag": "direct",
      "protocol": "freedom",
      "settings": {{}}
    }}
  ],
  "dns": {{
    "servers": ["{server}"]
  }}
}}"#
    )
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

fn vision_xudp_config(port: u16, vless_addr: SocketAddr, pinned_peer_cert_sha256: &str) -> String {
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

/// Read by both the client configs and the sing-box one, so a missing fixture
/// is one error rather than three spellings of it.
fn grpc_fixture_vless_addr(
    workload: WorkloadKind,
    fixture: &WorkloadFixture,
) -> Result<SocketAddr, BenchError> {
    fixture.vless_addr.ok_or_else(|| {
        BenchError::InvalidArguments(format!(
            "{} workload requires a VLESS gRPC server fixture",
            workload.as_str()
        ))
    })
}

/// The client half of the gRPC comparison, in Xray JSON — read by `xray-rust`
/// and Xray-core alike.
///
/// **No `flow`.** Xray's VLESS outbound takes `xtls-rprx-vision` only when the
/// conn is a `*encryption.CommonConn` (VLESS `encryption`, checked first and
/// network-agnostic) or the inner conn is a TLS, uTLS or REALITY one; anything
/// else gets "XTLS only supports TLS and REALITY directly for now."
/// (`Xray-core/proxy/vless/outbound/outbound.go:268-285`). This outbound is
/// `encryption: none` over gRPC, so it is neither — and adding `security: tls`
/// would not help, since the gRPC dialer returns a `HunkConn` or
/// `MultiHunkConn` wrapper rather than the TLS conn
/// (`Xray-core/transport/internet/grpc/dial.go:65,74`). So
/// this cannot be the REALITY configs with the network swapped; it is a
/// separate outbound.
///
/// **`security: none`.** gRPC without TLS is h2c on both ends, which keeps the
/// measurement on the framing rather than on three different TLS stacks. It
/// also removes the reason the REALITY fixture needs a warm-up: see
/// [`start_xray_core_grpc_server`].
fn vless_grpc_config(port: u16, vless_addr: SocketAddr) -> String {
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
                "encryption": "none"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": "grpc",
        "security": "none",
        "grpcSettings": {{ "serviceName": "{GRPC_BENCH_SERVICE_NAME}" }}
      }}
    }}
  ]
}}"#,
        vless_addr.ip(),
        vless_addr.port()
    )
}

/// The Xray-core server fixture the gRPC clients dial.
///
/// `multiMode` is absent by design: the listener registers both stream names on
/// one service descriptor regardless — `Tun` and `TunMulti`
/// (`Xray-core/transport/internet/grpc/hub.go:128`,
/// `transport/internet/grpc/encoding/customSeviceName.go:9-30,57-60`) — so
/// writing it here would document a server requirement that does not exist.
fn xray_core_grpc_server_config(port: u16) -> String {
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
            "id": "{TEST_VLESS_UUID_STRING}"
          }}
        ],
        "decryption": "none"
      }},
      "streamSettings": {{
        "network": "grpc",
        "security": "none",
        "grpcSettings": {{ "serviceName": "{GRPC_BENCH_SERVICE_NAME}" }}
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

/// Resolves the REALITY fixture warm-up duration from an optional raw
/// environment-variable value (milliseconds), falling back to
/// [`REALITY_FIXTURE_WARMUP`] when absent or unparseable.
fn reality_fixture_warmup_from_env(raw: Option<&str>) -> Duration {
    raw.and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(REALITY_FIXTURE_WARMUP)
}

/// Starts the Xray-core VLESS gRPC server the `grpc-bulk-throughput` clients
/// dial.
///
/// **There is no warm-up sleep here, and that is deliberate.** The REALITY
/// fixture next door waits out [`REALITY_FIXTURE_WARMUP`] because the REALITY
/// library must first handshake the real `dest` to learn its post-handshake
/// record shape, and a client arriving inside that window stalls. This inbound
/// is `security: none`; once the listener is bound there is nothing further to
/// learn, so the same sleep would only be eight seconds of an idle process
/// inside a benchmark.
async fn start_xray_core_grpc_server(
    options: &BenchOptions,
    run_dir: &Path,
    binary_dir: &Path,
) -> Result<(SocketAddr, FixtureProcess), BenchError> {
    let fixture_dir = run_dir.join("fixture").join("grpc-server");
    fs::create_dir_all(&fixture_dir).map_err(|source| BenchError::Io {
        action: format!("creating fixture directory `{}`", fixture_dir.display()),
        source,
    })?;
    let port = allocate_loopback_port()?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config_path = fixture_dir.join("config.json");
    fs::write(&config_path, xray_core_grpc_server_config(port)).map_err(|source| {
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

    // `started` only means the listener is bound; see REALITY_FIXTURE_WARMUP.
    let warmup = reality_fixture_warmup_from_env(
        std::env::var(REALITY_FIXTURE_WARMUP_MS_ENV).ok().as_deref(),
    );
    sleep(warmup).await;

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

/// Resolves the pinned Xray-core benchmark oracle.
///
/// A caller-supplied binary can only be tied to the required release and to
/// the binary SHA-256 stored in benchmark provenance; its source revision is
/// not inferable. Auto-builds additionally require the exact pinned checkout
/// revision and the source-tree guards below before rebuilding the scoped
/// output artifact.
pub fn ensure_xray_core_binary(
    options: &BenchOptions,
    bin_dir: &Path,
) -> Result<PathBuf, BenchError> {
    if let Some(path) = &options.xray_core_bin {
        let binary = canonical_xray_core_binary(path)?;
        verify_xray_core_binary(&binary, None)?;
        return Ok(binary);
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
    verify_xray_core_checkout(&checkout)?;
    let bin_dir = absolute_path(bin_dir)?;
    fs::create_dir_all(&bin_dir).map_err(|source| BenchError::Io {
        action: format!("creating binary directory `{}`", bin_dir.display()),
        source,
    })?;
    let binary = xray_core_oracle_binary_path(&bin_dir);
    let mut command = xray_core_go_build_command(&checkout, &binary);
    run_command("go", &mut command)?;
    // Re-check after compilation so a concurrent edit or a Go-side metadata
    // update cannot be attributed to the checkout validated before the build.
    verify_xray_core_checkout(&checkout)?;
    verify_xray_core_binary(&binary, Some(XRAY_CORE_ORACLE_REVISION))?;
    Ok(binary)
}

fn canonical_xray_core_binary(path: &Path) -> Result<PathBuf, BenchError> {
    let binary = fs::canonicalize(path).map_err(|source| BenchError::Io {
        action: format!(
            "resolving caller-supplied Xray-core binary `{}`",
            path.display()
        ),
        source,
    })?;
    let metadata = fs::metadata(&binary).map_err(|source| BenchError::Io {
        action: format!(
            "reading caller-supplied Xray-core binary metadata `{}`",
            binary.display()
        ),
        source,
    })?;
    if !metadata.is_file() {
        return Err(BenchError::InvalidArguments(format!(
            "caller-supplied Xray-core binary `{}` is not a file",
            path.display()
        )));
    }
    Ok(binary)
}

fn xray_core_oracle_binary_path(bin_dir: &Path) -> PathBuf {
    bin_dir.join(format!(
        "xray-core-v{XRAY_CORE_ORACLE_VERSION}-{XRAY_CORE_ORACLE_REVISION}{}",
        std::env::consts::EXE_SUFFIX
    ))
}

fn xray_core_go_build_command(checkout: &Path, binary: &Path) -> Command {
    xray_core_go_build_command_for_env(checkout, binary, std::env::vars_os().map(|(key, _)| key))
}

fn xray_core_go_build_command_for_env(
    checkout: &Path,
    binary: &Path,
    inherited_env_keys: impl IntoIterator<Item = OsString>,
) -> Command {
    let mut command = Command::new("go");
    command
        .arg("build")
        .arg("-o")
        .arg(binary)
        .arg("./main")
        .current_dir(checkout)
        // Ignore both the persistent Go environment and an ambient workspace:
        // either can inject flags, overlays, or dependency replacements while
        // the pinned checkout itself remains clean.
        .env("GOENV", "off")
        .env("GOWORK", "off")
        .env_remove("GOFLAGS")
        .env_remove("GOEXPERIMENT")
        .env_remove("GOTOOLCHAIN");
    for key in inherited_env_keys {
        if is_cgo_env_key(&key) {
            command.env_remove(key);
        }
    }
    command.env("CGO_ENABLED", "0");
    command
}

fn is_cgo_env_key(key: &OsStr) -> bool {
    key.to_string_lossy()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CGO_"))
}

fn verify_xray_core_checkout(checkout: &Path) -> Result<(), BenchError> {
    let revision = required_git_stdout(checkout, &["rev-parse", "--verify", "HEAD"])?;
    // Tracked or staged edits change the pinned source. Untracked paths need a
    // separate allowlist: an untracked Go file can participate in `go build`,
    // while the known local binaries and target tree cannot.
    let tracked_status = xray_core_tracked_status(checkout)?;
    let untracked_paths = xray_core_untracked_paths(checkout)?;
    validate_xray_core_checkout_metadata(checkout, &revision, &tracked_status, &untracked_paths)
}

fn xray_core_tracked_status(checkout: &Path) -> Result<String, BenchError> {
    required_git_stdout(
        checkout,
        &["status", "--porcelain=v1", "--untracked-files=no"],
    )
}

fn xray_core_untracked_paths(checkout: &Path) -> Result<String, BenchError> {
    // Deliberately do not pass `--exclude-standard`: ignored source-like files
    // must not evade the source guard. `--directory` keeps an allowed target/
    // tree bounded instead of listing every cached Go module file.
    required_git_stdout(
        checkout,
        &[
            "ls-files",
            "--others",
            "--directory",
            "--no-empty-directory",
        ],
    )
}

fn validate_xray_core_checkout_metadata(
    checkout: &Path,
    revision: &str,
    tracked_status: &str,
    untracked_paths: &str,
) -> Result<(), BenchError> {
    if revision != XRAY_CORE_ORACLE_REVISION {
        return Err(BenchError::InvalidArguments(format!(
            "xray-core checkout `{}` is at revision `{revision}`; benchmark oracle requires v{XRAY_CORE_ORACLE_VERSION} `{XRAY_CORE_ORACLE_REVISION}`",
            checkout.display()
        )));
    }
    if !tracked_status.trim().is_empty() {
        return Err(BenchError::InvalidArguments(format!(
            "xray-core checkout `{}` has tracked changes; benchmark oracle requires a clean v{XRAY_CORE_ORACLE_VERSION} checkout:\n{}",
            checkout.display(),
            tracked_status.trim()
        )));
    }
    let unexpected_untracked = xray_core_unexpected_untracked_paths(untracked_paths);
    if !unexpected_untracked.is_empty() {
        return Err(BenchError::InvalidArguments(format!(
            "xray-core checkout `{}` has untracked paths that may affect the oracle build; only root xray/xray.exe binaries and target/ are allowed:\n{}",
            checkout.display(),
            unexpected_untracked.join("\n")
        )));
    }
    Ok(())
}

fn xray_core_unexpected_untracked_paths(untracked_paths: &str) -> Vec<&str> {
    untracked_paths
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty() && !is_allowed_xray_core_untracked_path(path))
        .collect()
}

fn is_allowed_xray_core_untracked_path(path: &str) -> bool {
    matches!(path, "xray" | "xray.exe" | "target/")
}

fn xray_core_source_is_dirty(tracked_status: &str, untracked_paths: &str) -> bool {
    !tracked_status.trim().is_empty()
        || !xray_core_unexpected_untracked_paths(untracked_paths).is_empty()
}

fn verify_xray_core_binary(
    binary: &Path,
    required_revision: Option<&str>,
) -> Result<(), BenchError> {
    let output = Command::new(binary)
        .arg("version")
        .output()
        .map_err(|source| BenchError::Io {
            action: format!("reading Xray-core version from `{}`", binary.display()),
            source,
        })?;
    if !output.status.success() {
        return Err(BenchError::Process {
            program: binary.display().to_string(),
            status: output.status.to_string(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    validate_xray_core_version_output(
        binary,
        &String::from_utf8_lossy(&output.stdout),
        required_revision,
    )
}

fn validate_xray_core_version_output(
    binary: &Path,
    stdout: &str,
    required_revision: Option<&str>,
) -> Result<(), BenchError> {
    let first_line = stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .ok_or_else(|| {
            BenchError::InvalidArguments(format!(
                "xray-core binary `{}` returned empty version output",
                binary.display()
            ))
        })?;
    let fields = first_line.split_whitespace().collect::<Vec<_>>();
    if fields.first() != Some(&"Xray") || fields.get(1) != Some(&XRAY_CORE_ORACLE_VERSION) {
        return Err(BenchError::InvalidArguments(format!(
            "xray-core binary `{}` reported `{first_line}`; benchmark oracle requires Xray {XRAY_CORE_ORACLE_VERSION}",
            binary.display()
        )));
    }

    if let Some(revision) = required_revision {
        let expected_short_revision = revision.get(..7).unwrap_or(revision);
        let expected_dirty_short_revision = format!("{expected_short_revision}-dirty");
        let expected_dirty_revision = format!("{revision}-dirty");
        let embedded_revision = fields
            .iter()
            .position(|field| field.starts_with("(go"))
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| fields.get(index))
            .copied();
        if embedded_revision != Some(expected_short_revision)
            && embedded_revision != Some(revision)
            && embedded_revision != Some(expected_dirty_short_revision.as_str())
            && embedded_revision != Some(expected_dirty_revision.as_str())
        {
            return Err(BenchError::InvalidArguments(format!(
                "xray-core binary `{}` reported `{first_line}`; auto-built oracle requires revision `{expected_short_revision}` from `{revision}`",
                binary.display()
            )));
        }
    }
    Ok(())
}

fn required_git_stdout(root: &Path, args: &[&str]) -> Result<String, BenchError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|source| BenchError::Io {
            action: format!("running git {} in `{}`", args.join(" "), root.display()),
            source,
        })?;
    if !output.status.success() {
        return Err(BenchError::Process {
            program: "git".to_owned(),
            status: output.status.to_string(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
    let config = if options.workload == WorkloadKind::StreamTransport {
        stream_transport::engine_config(kind, port, options, options.stream_scenario()?, fixture)?
    } else {
        match kind {
            EngineKind::XrayRust | EngineKind::XrayCore => engine_config_with_dns_upstream(
                kind,
                port,
                options.workload,
                fixture,
                options.dns_upstream_transport,
            )?,
            EngineKind::SingBox => sing_box_config(port, options.workload, fixture)?,
        }
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
    let binary_path = fs::canonicalize(&binary).unwrap_or(binary);
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
        binary_path,
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
            let result = run_route_probe(&options).await?;
            print_route_probe_result(&result);
            Ok(())
        }
        CliArgs::DnsPolicyProbe(options) => {
            let result = run_dns_policy_probe(&options)?;
            print_dns_policy_probe_result(&result);
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

const ROUTE_PROBE_DOMAIN: &str = "route-probe.invalid";
const ROUTE_PROBE_PORT: u16 = 443;
const ROUTE_PROBE_TARGET_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const ROUTE_PROBE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const ROUTE_PROBE_IPV4_MISS_BASE: u32 = 0xc612_0000;
const MAX_ROUTE_PROBE_DNS_CANDIDATES: usize = 4096;
const ROUTE_PROBE_UNMATCHED_TAG: &str = "route-probe-unmatched";
const DNS_POLICY_PROBE_DOMAIN: &str = "selected.policy-probe.invalid";
const MAX_DNS_POLICY_PROBE_SERVERS: usize = 4_096;
const DNS_OUTBOUND_SELECTOR_PROBE_RULE_COUNTS: [usize; 3] = [0, 64, 4_096];
const DNS_OUTBOUND_SELECTOR_FIRST_HIT_DOMAIN: &str = "first.selector-probe.invalid";
const DNS_OUTBOUND_SELECTOR_LAST_HIT_DOMAIN: &str = "last.selector-probe.invalid";
const DNS_OUTBOUND_SELECTOR_SEMANTIC_MISS_DOMAIN: &str = "miss.selector-probe.invalid";

struct RouteProbeDnsResolver {
    result: DnsLookup,
    lookups: AtomicUsize,
}

impl RouteProbeDnsResolver {
    fn new(candidate_count: usize) -> Self {
        let mut addresses = (0..candidate_count.saturating_sub(1))
            .map(|index| {
                let address = Ipv4Addr::from(ROUTE_PROBE_IPV4_MISS_BASE + index as u32);
                SocketAddr::new(IpAddr::V4(address), ROUTE_PROBE_PORT)
            })
            .collect::<Vec<_>>();
        addresses.push(SocketAddr::new(
            IpAddr::V4(ROUTE_PROBE_TARGET_IP),
            ROUTE_PROBE_PORT,
        ));
        Self {
            result: DnsLookup::new(addresses, Some(ROUTE_PROBE_CACHE_TTL)),
            lookups: AtomicUsize::new(0),
        }
    }

    fn record_lookup(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        if domain != ROUTE_PROBE_DOMAIN || port != ROUTE_PROBE_PORT {
            return Err(TransportError::NoResolvedAddress(domain.to_owned(), port));
        }
        self.lookups.fetch_add(1, Ordering::Relaxed);
        Ok(self.result.clone())
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl DnsResolver for RouteProbeDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.record_lookup(domain, port)?
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
    }

    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        self.record_lookup(domain, port)
    }
}

fn route_probe_target(domain_target: bool) -> Target {
    let addr = if domain_target {
        RoutingTargetAddr::Domain(ROUTE_PROBE_DOMAIN.to_owned())
    } else {
        RoutingTargetAddr::Ip(IpAddr::V4(ROUTE_PROBE_TARGET_IP))
    };
    Target::new(addr, ROUTE_PROBE_PORT, RoutingNetwork::Tcp)
}

fn measure_direct_route_probe(
    outbound_router: &OutboundRouter,
    iterations: usize,
    target: &Target,
) -> Result<(usize, Duration), BenchError> {
    let inbound_tag = Some("bench-in");
    let started = Instant::now();
    let mut selected = 0;
    for _ in 0..iterations {
        let outbound = black_box(outbound_router)
            .select_tcp_outbound_for_session(inbound_tag, black_box(target))
            .map_err(|error| {
                BenchError::InvalidArguments(format!("route probe failed: {error}"))
            })?;
        if matches!(black_box(outbound), xray_core_rs::TcpOutbound::Freedom) {
            selected += 1;
        }
    }
    Ok((selected, started.elapsed()))
}

async fn measure_cached_dns_route_probe(
    outbound_router: &OutboundRouter,
    iterations: usize,
    candidate_count: usize,
) -> Result<(usize, Duration), BenchError> {
    let upstream = Arc::new(RouteProbeDnsResolver::new(candidate_count));
    let resolver = CachingDnsResolver::with_ttl(upstream.clone(), ROUTE_PROBE_CACHE_TTL);
    let target = Target::new(
        RoutingTargetAddr::Domain(ROUTE_PROBE_DOMAIN.to_owned()),
        ROUTE_PROBE_PORT,
        RoutingNetwork::Tcp,
    );
    let inbound_tag = Some("bench-in");
    outbound_router
        .select_tcp_outbound_for_session_with_resolver(inbound_tag, &target, &resolver)
        .await
        .map_err(|error| {
            BenchError::InvalidArguments(format!("warming route-probe DNS route: {error}"))
        })?;
    let warm_lookups = upstream.lookups();
    if warm_lookups != 1 {
        return Err(BenchError::InvalidArguments(format!(
            "DNS route probe expected one warm-up lookup, observed {warm_lookups}"
        )));
    }
    let started = Instant::now();
    let mut selected = 0;
    for _ in 0..iterations {
        let outbound = black_box(outbound_router)
            .select_tcp_outbound_for_session_with_resolver(
                inbound_tag,
                black_box(&target),
                black_box(&resolver),
            )
            .await
            .map_err(|error| {
                BenchError::InvalidArguments(format!("DNS route probe failed: {error}"))
            })?;
        if matches!(black_box(outbound), xray_core_rs::TcpOutbound::Freedom) {
            selected += 1;
        }
    }
    let elapsed = started.elapsed();
    let upstream_lookups = upstream.lookups();
    if upstream_lookups != 1 {
        return Err(BenchError::InvalidArguments(format!(
            "DNS route probe expected one warm-up lookup, observed {upstream_lookups}"
        )));
    }
    Ok((selected, elapsed))
}

pub async fn run_route_probe(options: &RouteProbeOptions) -> Result<RouteProbeResult, BenchError> {
    if options.dns_candidates > MAX_ROUTE_PROBE_DNS_CANDIDATES {
        return Err(BenchError::InvalidArguments(format!(
            "route-probe --dns-candidates must not exceed {MAX_ROUTE_PROBE_DNS_CANDIDATES}"
        )));
    }
    if options.dns_candidates > 0 && options.domains_per_rule > 0 {
        return Err(BenchError::InvalidArguments(
            "route-probe --dns-candidates cannot be combined with --domains-per-rule".to_owned(),
        ));
    }
    let mut config = route_probe_config(
        options.rules,
        options.outbounds,
        options.cidrs_per_rule,
        options.domains_per_rule,
    )?;
    if options.dns_candidates > 0 {
        if options.rules == 0 {
            return Err(BenchError::InvalidArguments(
                "route-probe --dns-candidates requires at least one routing rule".to_owned(),
            ));
        }
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        // Make a missing candidate match observable instead of silently using
        // the synthetic config's normal freedom fallback.
        config.default_outbound_tag = Some(ROUTE_PROBE_UNMATCHED_TAG.to_owned());
    }
    let outbound_router = OutboundRouter::new(Arc::new(config));
    let peak_rss_kib = current_peak_rss_kib();
    let (selected, elapsed) = if options.dns_candidates == 0 {
        let target = route_probe_target(options.domains_per_rule > 0);
        measure_direct_route_probe(&outbound_router, options.iterations, &target)?
    } else {
        measure_cached_dns_route_probe(&outbound_router, options.iterations, options.dns_candidates)
            .await?
    };
    let result = RouteProbeResult {
        iterations: options.iterations,
        rules: options.rules,
        outbounds: options.outbounds,
        dns_candidates: options.dns_candidates,
        cidrs_per_rule: options.cidrs_per_rule,
        domains_per_rule: options.domains_per_rule,
        peak_rss_kib,
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

fn dns_policy_probe_servers(server_count: usize) -> Vec<NameServerPolicy> {
    (0..server_count)
        .map(|index| {
            NameServerPolicy::new(NameServer::Domain {
                domain: format!("ns-{index}.policy-probe.invalid"),
                port: 53,
            })
        })
        .collect()
}

fn dns_policy_probe_worst_case_servers(
    server_count: usize,
    matcher_count: usize,
) -> Vec<NameServerPolicy> {
    let mut servers = dns_policy_probe_servers(server_count);
    let Some(last) = servers.last_mut() else {
        return servers;
    };
    let mut domains = DomainMatcherSet::builder();
    for index in 0..matcher_count.saturating_sub(1) {
        domains.insert(
            &DomainMatcher::Full(format!("miss-{index}.policy-probe.invalid")),
            DomainNameMode::Dns,
        );
    }
    domains.insert(
        &DomainMatcher::Full(DNS_POLICY_PROBE_DOMAIN.to_owned()),
        DomainNameMode::Dns,
    );
    last.domains = domains.build().expect("exact DNS policy matchers compile");
    servers
}

fn dns_outbound_probe_common_settings(rule_count: usize) -> DnsOutboundSettings {
    let rules = (0..rule_count)
        .map(|index| DnsOutboundRule {
            action: if index == 0 {
                DnsOutboundRuleAction::Direct
            } else {
                DnsOutboundRuleAction::Return
            },
            r_code: 0,
            qtype_ranges: Vec::new(),
            domain_matchers: compile_dns_domain_matchers(&[DomainMatcher::Full(
                DNS_POLICY_PROBE_DOMAIN.to_owned(),
            )])
            .expect("exact DNS outbound matcher compiles"),
        })
        .collect();
    DnsOutboundSettings {
        rules,
        ..DnsOutboundSettings::default()
    }
}

fn dns_outbound_probe_worst_case_settings(
    rule_count: usize,
    matcher_count: usize,
) -> DnsOutboundSettings {
    // Keyword matchers compile into one automaton per rule, so the worst case
    // keeps the largest keyword list on the final rule to cover that path.
    let mut rules = (0..rule_count.saturating_sub(1))
        .map(|index| DnsOutboundRule {
            action: DnsOutboundRuleAction::Direct,
            r_code: 0,
            qtype_ranges: Vec::new(),
            domain_matchers: compile_dns_domain_matchers(&[DomainMatcher::Keyword(format!(
                "rule-{index}-ordered-miss.invalid"
            ))])
            .expect("keyword DNS outbound matcher compiles"),
        })
        .collect::<Vec<_>>();
    let mut domain_matchers = DomainMatcherSet::builder();
    for index in 0..matcher_count.saturating_sub(1) {
        domain_matchers.insert(
            &DomainMatcher::Keyword(format!("matcher-{index}-ordered-miss.invalid")),
            DomainNameMode::Dns,
        );
    }
    domain_matchers.insert(
        &DomainMatcher::Keyword(DNS_POLICY_PROBE_DOMAIN.to_owned()),
        DomainNameMode::Dns,
    );
    rules.push(DnsOutboundRule {
        action: DnsOutboundRuleAction::Return,
        r_code: 0,
        qtype_ranges: Vec::new(),
        domain_matchers: domain_matchers
            .build()
            .expect("keyword DNS outbound matchers compile"),
    });
    DnsOutboundSettings {
        rules,
        ..DnsOutboundSettings::default()
    }
}

fn dns_policy_probe_a_query(domain: &str) -> Result<Vec<u8>, BenchError> {
    if domain.len().saturating_add(2) > u8::MAX as usize {
        return Err(BenchError::InvalidArguments(format!(
            "DNS policy probe domain `{domain}` exceeds the wire-format limit"
        )));
    }

    let mut query = Vec::with_capacity(12 + domain.len() + 6);
    query.extend_from_slice(&0x5052_u16.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        let label_len = u8::try_from(label.len()).map_err(|_| {
            BenchError::InvalidArguments(format!(
                "DNS policy probe domain `{domain}` contains an oversized label"
            ))
        })?;
        if label_len == 0 || label_len > 63 {
            return Err(BenchError::InvalidArguments(format!(
                "DNS policy probe domain `{domain}` contains an invalid label"
            )));
        }
        query.push(label_len);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn dns_outbound_decision_name(decision: DnsOutboundDecision) -> &'static str {
    match decision {
        DnsOutboundDecision::Direct => "direct",
        DnsOutboundDecision::Drop => "drop",
        DnsOutboundDecision::Return(_) => "return",
        DnsOutboundDecision::Hijack => "hijack",
        DnsOutboundDecision::HijackUnsafe(_) => "hijack-unsafe",
    }
}

fn measure_dns_outbound_policy(
    settings: &DnsOutboundSettings,
    query: &[u8],
    expected: DnsOutboundDecision,
    iterations: usize,
) -> Result<DnsOutboundPolicyProbeMetric, BenchError> {
    let started = Instant::now();
    let policy = CompiledDnsOutboundPolicy::new(settings);
    let compile_us = started.elapsed().as_micros();

    let actual = policy.decide_message(query, false).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "DNS outbound policy probe query was rejected as malformed: {error}"
        ))
    })?;
    if actual != expected {
        return Err(BenchError::InvalidArguments(format!(
            "DNS outbound policy probe returned `{}`, expected `{}`",
            dns_outbound_decision_name(actual),
            dns_outbound_decision_name(expected),
        )));
    }

    let started = Instant::now();
    for _ in 0..iterations {
        let decision = black_box(&policy).decide_message(black_box(query), false);
        let _ = black_box(decision);
    }
    let elapsed = started.elapsed();
    Ok(DnsOutboundPolicyProbeMetric {
        decision: dns_outbound_decision_name(actual).to_owned(),
        compile_us,
        total_us: elapsed.as_micros(),
        avg_ns: elapsed.as_nanos() / iterations as u128,
    })
}

fn dns_outbound_selector_probe_config(rule_count: usize) -> CoreConfig {
    let direct = OutboundConfig {
        tag: Some("direct".to_owned()),
        stream: StreamSettings {
            network: ConfigNetwork::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::None,
            quic_params: None,
            socket_options: None,
        },
        settings: OutboundSettings::Freedom,
    };
    let dns = OutboundConfig {
        tag: Some("dns-out".to_owned()),
        stream: StreamSettings {
            network: ConfigNetwork::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::None,
            quic_params: None,
            socket_options: None,
        },
        settings: OutboundSettings::Dns(DnsOutboundSettings::default()),
    };
    let rules = (0..rule_count)
        .map(|index| {
            let mut domain_matchers = DomainMatcherSet::builder();
            domain_matchers.insert(
                &DomainMatcher::Full(format!("rule-{index}.selector-probe.invalid")),
                DomainNameMode::Routing,
            );
            if index == 0 {
                domain_matchers.insert(
                    &DomainMatcher::Full(DNS_OUTBOUND_SELECTOR_FIRST_HIT_DOMAIN.to_owned()),
                    DomainNameMode::Routing,
                );
            }
            if index + 1 == rule_count {
                domain_matchers.insert(
                    &DomainMatcher::Full(DNS_OUTBOUND_SELECTOR_LAST_HIT_DOMAIN.to_owned()),
                    DomainNameMode::Routing,
                );
            }
            RoutingRule {
                inbound_tags: vec!["bench-in".to_owned()],
                networks: vec![ConfigNetwork::Udp],
                port_ranges: vec![RoutingPortRange::single(53)],
                domain_matchers: domain_matchers
                    .build()
                    .expect("exact DNS selector matchers compile"),
                ip_matchers: Default::default(),
                outbound_tag: "dns-out".to_owned(),
            }
        })
        .collect();

    CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![direct, dns],
        default_outbound_tag: Some("direct".to_owned()),
        routing: RoutingConfig {
            rules,
            ..Default::default()
        },
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn measure_dns_outbound_selector_prefilter(
    rule_count: usize,
    iterations: usize,
) -> Result<DnsOutboundSelectorProbeMetric, BenchError> {
    let config = dns_outbound_selector_probe_config(rule_count);
    let started = Instant::now();
    let router = OutboundRouter::new(Arc::new(config));
    let compile_us = started.elapsed().as_micros();
    let hit_target = Target::new(
        RoutingTargetAddr::Domain(DNS_OUTBOUND_SELECTOR_FIRST_HIT_DOMAIN.to_owned()),
        53,
        RoutingNetwork::Udp,
    );
    let last_hit_target = Target::new(
        RoutingTargetAddr::Domain(DNS_OUTBOUND_SELECTOR_LAST_HIT_DOMAIN.to_owned()),
        53,
        RoutingNetwork::Udp,
    );
    let miss_target = Target::new(
        RoutingTargetAddr::Domain(DNS_OUTBOUND_SELECTOR_FIRST_HIT_DOMAIN.to_owned()),
        443,
        RoutingNetwork::Udp,
    );
    let semantic_miss_target = Target::new(
        RoutingTargetAddr::Domain(DNS_OUTBOUND_SELECTOR_SEMANTIC_MISS_DOMAIN.to_owned()),
        53,
        RoutingNetwork::Udp,
    );
    let hit_selected_dns = router
        .select_dns_outbound_for_session(Some("bench-in"), &hit_target)
        .map_err(|error| {
            BenchError::InvalidArguments(format!(
                "DNS outbound selector hit probe failed with {rule_count} rules: {error}"
            ))
        })?
        .is_some();
    let last_hit_selected_dns = router
        .select_dns_outbound_for_session(Some("bench-in"), &last_hit_target)
        .map_err(|error| {
            BenchError::InvalidArguments(format!(
                "DNS outbound selector last-hit probe failed with {rule_count} rules: {error}"
            ))
        })?
        .is_some();
    let miss_preserved_regular_path = router
        .select_dns_outbound_for_session(Some("bench-in"), &miss_target)
        .map_err(|error| {
            BenchError::InvalidArguments(format!(
                "DNS outbound selector miss probe failed with {rule_count} rules: {error}"
            ))
        })?
        .is_none();
    let semantic_miss_preserved_regular_path = router
        .select_dns_outbound_for_session(Some("bench-in"), &semantic_miss_target)
        .map_err(|error| {
            BenchError::InvalidArguments(format!(
                "DNS outbound selector semantic-miss probe failed with {rule_count} rules: {error}"
            ))
        })?
        .is_none();
    if hit_selected_dns != (rule_count > 0)
        || last_hit_selected_dns != (rule_count > 0)
        || !miss_preserved_regular_path
        || !semantic_miss_preserved_regular_path
    {
        return Err(BenchError::InvalidArguments(format!(
            "DNS outbound selector validation failed with {rule_count} rules: hit_selected_dns={hit_selected_dns}, last_hit_selected_dns={last_hit_selected_dns}, miss_preserved_regular_path={miss_preserved_regular_path}, semantic_miss_preserved_regular_path={semantic_miss_preserved_regular_path}"
        )));
    }

    let started = Instant::now();
    for _ in 0..iterations {
        let selected = black_box(&router)
            .select_dns_outbound_for_session(Some("bench-in"), black_box(&hit_target));
        let _ = black_box(selected);
    }
    let hit_elapsed = started.elapsed();
    let started = Instant::now();
    for _ in 0..iterations {
        let selected = black_box(&router)
            .select_dns_outbound_for_session(Some("bench-in"), black_box(&last_hit_target));
        let _ = black_box(selected);
    }
    let last_hit_elapsed = started.elapsed();
    let started = Instant::now();
    for _ in 0..iterations {
        let selected = black_box(&router)
            .select_dns_outbound_for_session(Some("bench-in"), black_box(&miss_target));
        let _ = black_box(selected);
    }
    let miss_elapsed = started.elapsed();
    let started = Instant::now();
    for _ in 0..iterations {
        let selected = black_box(&router)
            .select_dns_outbound_for_session(Some("bench-in"), black_box(&semantic_miss_target));
        let _ = black_box(selected);
    }
    let semantic_miss_elapsed = started.elapsed();

    Ok(DnsOutboundSelectorProbeMetric {
        rules: rule_count,
        hit_selected_dns,
        last_hit_selected_dns,
        miss_preserved_regular_path,
        semantic_miss_preserved_regular_path,
        compile_us,
        hit_total_us: hit_elapsed.as_micros(),
        hit_avg_ns: hit_elapsed.as_nanos() / iterations as u128,
        last_hit_total_us: last_hit_elapsed.as_micros(),
        last_hit_avg_ns: last_hit_elapsed.as_nanos() / iterations as u128,
        miss_total_us: miss_elapsed.as_micros(),
        miss_avg_ns: miss_elapsed.as_nanos() / iterations as u128,
        semantic_miss_total_us: semantic_miss_elapsed.as_micros(),
        semantic_miss_avg_ns: semantic_miss_elapsed.as_nanos() / iterations as u128,
    })
}

fn measure_dns_policy_selection(
    policies: &CompiledNameServerPolicies,
    compile_us: u128,
    iterations: usize,
) -> DnsPolicyProbeMetric {
    let selected_per_iteration = policies
        .select_indices(DNS_POLICY_PROBE_DOMAIN, false, false)
        .len();
    let started = Instant::now();
    for _ in 0..iterations {
        let selected =
            black_box(policies).select_indices(black_box(DNS_POLICY_PROBE_DOMAIN), false, false);
        black_box(selected);
    }
    let elapsed = started.elapsed();
    DnsPolicyProbeMetric {
        selected_per_iteration,
        compile_us,
        compiled_matchers: policies.matcher_count(),
        pattern_bytes: policies.pattern_bytes(),
        total_us: elapsed.as_micros(),
        avg_ns: elapsed.as_nanos() / iterations as u128,
    }
}

fn measure_dns_ip_filter(
    matcher_count: usize,
    iterations: usize,
) -> Result<DnsIpFilterProbeMetric, BenchError> {
    let target = dns_ip_filter_probe_address(matcher_count - 1);
    let non_match = dns_ip_filter_probe_miss(target);

    let addresses = (0..matcher_count)
        .map(dns_ip_filter_probe_address)
        .collect::<Vec<_>>();
    let started = Instant::now();
    let mut builder = DnsIpFilter::builder();
    for address in addresses {
        builder.custom().insert_ip(address, false);
    }
    let filter = builder.build();
    let compile_us = started.elapsed().as_micros();
    let hit_matched = filter.matches(target);
    let miss_rejected = !filter.matches(non_match);
    if !hit_matched || !miss_rejected {
        return Err(BenchError::InvalidArguments(
            "DNS IP filter probe failed its membership validation".to_owned(),
        ));
    }

    let hit_probes = dns_ip_filter_probe_indices(matcher_count)
        .into_iter()
        .map(dns_ip_filter_probe_address)
        .collect::<Vec<_>>();
    let started = Instant::now();
    for iteration in 0..iterations {
        black_box(black_box(&filter).matches(black_box(hit_probes[iteration & 63])));
    }
    let hit_elapsed = started.elapsed();

    let miss_probes = hit_probes
        .iter()
        .copied()
        .map(dns_ip_filter_probe_miss)
        .collect::<Vec<_>>();
    let started = Instant::now();
    for iteration in 0..iterations {
        black_box(black_box(&filter).matches(black_box(miss_probes[iteration & 63])));
    }
    let miss_elapsed = started.elapsed();
    Ok(DnsIpFilterProbeMetric {
        hit_matched,
        miss_rejected,
        compile_us,
        compiled_matchers: filter.matcher_count(),
        compiled_ranges: filter.compiled_range_count(),
        hit_total_us: hit_elapsed.as_micros(),
        hit_avg_ns: hit_elapsed.as_nanos() / iterations as u128,
        miss_total_us: miss_elapsed.as_micros(),
        miss_avg_ns: miss_elapsed.as_nanos() / iterations as u128,
    })
}

const DNS_IP_FILTER_PROBE_SAMPLES: usize = 64;

fn dns_ip_filter_probe_indices(matcher_count: usize) -> Vec<usize> {
    debug_assert!(matcher_count > 0);
    (0..DNS_IP_FILTER_PROBE_SAMPLES)
        .map(|index| index * matcher_count / DNS_IP_FILTER_PROBE_SAMPLES)
        .collect()
}

fn dns_ip_filter_probe_address(index: usize) -> IpAddr {
    const PERMUTATION_MASK: u32 = (1 << 20) - 1;
    const PERMUTATION_MULTIPLIER: u32 = 0x9e37_79b1;

    let index =
        u32::try_from(index).expect("validated DNS policy probe matcher count should fit u32");
    let slot = index.wrapping_mul(PERMUTATION_MULTIPLIER) & PERMUTATION_MASK;
    let base = u32::from(Ipv4Addr::new(10, 0, 0, 0));
    IpAddr::V4(Ipv4Addr::from(base + slot * 2))
}

fn dns_ip_filter_probe_miss(address: IpAddr) -> IpAddr {
    let IpAddr::V4(address) = address else {
        unreachable!("DNS IP filter probe generates only IPv4 addresses");
    };
    IpAddr::V4(Ipv4Addr::from(u32::from(address) + 1))
}

fn dns_hosts_probe_name(index: usize) -> String {
    format!("host-{index}.hosts-probe.invalid")
}

fn dns_hosts_probe_miss_name(index: usize) -> String {
    format!("miss-{index}.hosts-probe.invalid")
}

fn dns_hosts_probe_target(index: usize) -> IpAddr {
    const RFC5737_BASES: [Ipv4Addr; 3] = [
        Ipv4Addr::new(192, 0, 2, 0),
        Ipv4Addr::new(198, 51, 100, 0),
        Ipv4Addr::new(203, 0, 113, 0),
    ];
    let base = u32::from(RFC5737_BASES[index % RFC5737_BASES.len()]);
    IpAddr::V4(Ipv4Addr::from(
        base + (index / RFC5737_BASES.len()) as u32 % 256,
    ))
}

fn measure_dns_hosts_index(
    host_count: usize,
    iterations: usize,
) -> Result<DnsHostsProbeMetric, BenchError> {
    let started = Instant::now();
    let hosts = (0..host_count)
        .map(|index| {
            (
                DomainMatcher::Full(dns_hosts_probe_name(index)),
                DnsHostTarget::Ip(dns_hosts_probe_target(index)),
            )
        })
        .collect::<DomainHostIndex<_>>();
    let compile_us = started.elapsed().as_micros();
    let peak_rss_kib = current_peak_rss_kib();
    let lookup = |domain: &str| hosts.lookup(domain);

    let last = host_count - 1;
    let hit_matched = lookup(&dns_hosts_probe_name(last))
        == Some(&DnsHostTarget::Ip(dns_hosts_probe_target(last)));
    let miss_rejected = lookup(&dns_hosts_probe_miss_name(last)).is_none();
    if !hit_matched || !miss_rejected {
        return Err(BenchError::InvalidArguments(
            "DNS hosts probe failed its membership validation".to_owned(),
        ));
    }

    let hit_probes = dns_ip_filter_probe_indices(host_count)
        .into_iter()
        .map(dns_hosts_probe_name)
        .collect::<Vec<_>>();
    let started = Instant::now();
    for iteration in 0..iterations {
        black_box(lookup(black_box(&hit_probes[iteration & 63])));
    }
    let hit_elapsed = started.elapsed();

    let miss_probes = dns_ip_filter_probe_indices(host_count)
        .into_iter()
        .map(dns_hosts_probe_miss_name)
        .collect::<Vec<_>>();
    let started = Instant::now();
    for iteration in 0..iterations {
        black_box(lookup(black_box(&miss_probes[iteration & 63])));
    }
    let miss_elapsed = started.elapsed();
    Ok(DnsHostsProbeMetric {
        hosts: host_count,
        hit_matched,
        miss_rejected,
        compile_us,
        peak_rss_kib,
        hit_total_us: hit_elapsed.as_micros(),
        hit_avg_ns: hit_elapsed.as_nanos() / iterations as u128,
        miss_total_us: miss_elapsed.as_micros(),
        miss_avg_ns: miss_elapsed.as_nanos() / iterations as u128,
    })
}

fn measure_dns_policy_probe(
    options: &DnsPolicyProbeOptions,
) -> Result<DnsPolicyProbeResult, BenchError> {
    if options.iterations == 0 {
        return Err(BenchError::InvalidArguments(
            "dns-policy-probe --iterations must be greater than zero".to_owned(),
        ));
    }
    if options.servers == 0 || options.servers > MAX_DNS_POLICY_PROBE_SERVERS {
        return Err(BenchError::InvalidArguments(format!(
            "dns-policy-probe --servers must be between 1 and {MAX_DNS_POLICY_PROBE_SERVERS}"
        )));
    }
    if options.matchers == 0 || options.matchers > MAX_CONFIG_DOMAIN_MATCHERS {
        return Err(BenchError::InvalidArguments(format!(
            "dns-policy-probe --matchers must be between 1 and {MAX_CONFIG_DOMAIN_MATCHERS}"
        )));
    }
    if options.hosts > MAX_CONFIG_DOMAIN_MATCHERS {
        return Err(BenchError::InvalidArguments(format!(
            "dns-policy-probe --hosts must not exceed {MAX_CONFIG_DOMAIN_MATCHERS}"
        )));
    }
    let hosts = (options.hosts > 0)
        .then(|| measure_dns_hosts_index(options.hosts, options.iterations))
        .transpose()?;

    let common = dns_policy_probe_servers(options.servers);
    let expected_common = (0..options.servers).collect::<Vec<_>>();
    let actual_common = select_name_server_indices(&common, DNS_POLICY_PROBE_DOMAIN, false, false);
    if actual_common != expected_common {
        return Err(BenchError::InvalidArguments(format!(
            "DNS policy common-path probe selected {actual_common:?}, expected {expected_common:?}"
        )));
    }

    let worst_case = dns_policy_probe_worst_case_servers(options.servers, options.matchers);
    let mut expected_worst_case = Vec::with_capacity(options.servers);
    expected_worst_case.push(options.servers - 1);
    expected_worst_case.extend(0..options.servers - 1);
    let actual_worst_case =
        select_name_server_indices(&worst_case, DNS_POLICY_PROBE_DOMAIN, false, false);
    if actual_worst_case != expected_worst_case {
        return Err(BenchError::InvalidArguments(format!(
            "DNS policy worst-case probe selected {actual_worst_case:?}, expected {expected_worst_case:?}"
        )));
    }

    let started = Instant::now();
    let common = CompiledNameServerPolicies::new(common);
    let common_compile_us = started.elapsed().as_micros();
    let started = Instant::now();
    let worst_case = CompiledNameServerPolicies::new(worst_case);
    let worst_case_compile_us = started.elapsed().as_micros();
    let outbound_query = dns_policy_probe_a_query(DNS_POLICY_PROBE_DOMAIN)?;
    let outbound_common_settings = dns_outbound_probe_common_settings(options.servers);
    let outbound_common_first_rule = measure_dns_outbound_policy(
        &outbound_common_settings,
        &outbound_query,
        DnsOutboundDecision::Direct,
        options.iterations,
    )?;
    let outbound_worst_settings =
        dns_outbound_probe_worst_case_settings(options.servers, options.matchers);
    let outbound_worst_ordered_rule_matchers = measure_dns_outbound_policy(
        &outbound_worst_settings,
        &outbound_query,
        DnsOutboundDecision::Return(0),
        options.iterations,
    )?;
    let outbound_selector_prefilter = DNS_OUTBOUND_SELECTOR_PROBE_RULE_COUNTS
        .into_iter()
        .map(|rule_count| measure_dns_outbound_selector_prefilter(rule_count, options.iterations))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DnsPolicyProbeResult {
        iterations: options.iterations,
        servers: options.servers,
        matchers: options.matchers,
        common_no_domains: measure_dns_policy_selection(
            &common,
            common_compile_us,
            options.iterations,
        ),
        worst_case_matchers: measure_dns_policy_selection(
            &worst_case,
            worst_case_compile_us,
            options.iterations,
        ),
        worst_case_ip_filter: measure_dns_ip_filter(options.matchers, options.iterations)?,
        outbound_common_first_rule,
        outbound_worst_ordered_rule_matchers,
        outbound_selector_prefilter,
        hosts,
    })
}

pub fn run_dns_policy_probe(
    options: &DnsPolicyProbeOptions,
) -> Result<DnsPolicyProbeResult, BenchError> {
    let result = measure_dns_policy_probe(options)?;
    let run_dir = options.out_dir.join(new_run_id()).join("dns-policy-probe");
    fs::create_dir_all(&run_dir).map_err(|source| BenchError::Io {
        action: format!(
            "creating DNS policy probe directory `{}`",
            run_dir.display()
        ),
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

fn route_probe_config(
    rules: usize,
    outbounds: usize,
    cidrs_per_rule: usize,
    domains_per_rule: usize,
) -> Result<CoreConfig, BenchError> {
    if cidrs_per_rule == 0 {
        return Err(BenchError::InvalidArguments(
            "route-probe --cidrs-per-rule must be at least 1".to_owned(),
        ));
    }
    if rules.saturating_mul(domains_per_rule) > MAX_CONFIG_DOMAIN_MATCHERS {
        return Err(BenchError::InvalidArguments(format!(
            "route-probe rules x --domains-per-rule must not exceed {MAX_CONFIG_DOMAIN_MATCHERS}"
        )));
    }
    let outbound_count = outbounds.max(1);
    let selected_tag = format!("out-{}", outbound_count - 1);
    let outbounds = (0..outbound_count)
        .map(|index| OutboundConfig {
            tag: Some(format!("out-{index}")),
            stream: StreamSettings {
                network: ConfigNetwork::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            settings: OutboundSettings::Freedom,
        })
        .collect::<Vec<_>>();

    let mut routing_rules = Vec::with_capacity(rules);
    for index in 0..rules {
        let final_rule = index + 1 == rules;
        let mut ip_matchers = IpMatcherSet::builder();
        let mut domain_matchers = DomainMatcherSet::builder();
        if domains_per_rule > 0 {
            if final_rule {
                domain_matchers.insert(
                    &DomainMatcher::Full(ROUTE_PROBE_DOMAIN.to_owned()),
                    DomainNameMode::Routing,
                );
            } else {
                for domain_index in 0..domains_per_rule {
                    domain_matchers.insert(
                        &DomainMatcher::Suffix(route_probe_miss_domain(index, domain_index)),
                        DomainNameMode::Routing,
                    );
                }
            }
        } else if final_rule {
            ip_matchers.insert_cidr(Cidr::host(IpAddr::V4(ROUTE_PROBE_TARGET_IP)), false);
        } else {
            for cidr_index in 0..cidrs_per_rule {
                ip_matchers.insert_cidr(
                    route_probe_miss_cidr(index, cidr_index, cidrs_per_rule)?.cidr(),
                    false,
                );
            }
        }
        routing_rules.push(RoutingRule {
            inbound_tags: vec!["bench-in".to_owned()],
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: domain_matchers
                .build()
                .expect("route-probe domain matchers compile"),
            ip_matchers: ip_matchers.build(),
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

/// A `domain:` suffix that never matches [`ROUTE_PROBE_DOMAIN`].
fn route_probe_miss_domain(rule_index: usize, domain_index: usize) -> String {
    format!("miss-{rule_index}-{domain_index}.invalid")
}

/// A CIDR inside `10.0.0.0/8` that never contains [`ROUTE_PROBE_TARGET_IP`].
///
/// With one CIDR per rule this keeps the historical `10.<rule>.0.0/16` shape.
/// With more, every rule gets `cidrs_per_rule` distinct `/28` blocks separated
/// by a one-block gap so that no two blocks overlap or merge into one range.
/// 2^19 such blocks fit inside `10.0.0.0/8`; `rules x cidrs_per_rule` beyond
/// that is rejected here.
fn route_probe_miss_cidr(
    rule_index: usize,
    cidr_index: usize,
    cidrs_per_rule: usize,
) -> Result<IpCidr, BenchError> {
    let (network, prefix) = if cidrs_per_rule == 1 {
        (Ipv4Addr::new(10, (rule_index % 256) as u8, 0, 0), 16)
    } else {
        let block = rule_index * cidrs_per_rule + cidr_index;
        let offset = u32::try_from(block * 32)
            .ok()
            .filter(|offset| *offset < (1 << 24))
            .ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "route-probe miss CIDR {block} does not fit inside 10.0.0.0/8"
                ))
            })?;
        (
            Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 0, 0, 0)) + offset),
            28,
        )
    };
    IpCidr::new(IpAddr::V4(network), prefix)
        .map_err(|error| BenchError::InvalidArguments(error.to_string()))
}

fn harness_build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn workspace_git_provenance() -> Option<WorkspaceGitProvenance> {
    let root = workspace_root().ok()?;
    git_provenance_at(&root)
}

fn git_provenance_at(root: &Path) -> Option<WorkspaceGitProvenance> {
    let revision = git_stdout(root, &["rev-parse", "--verify", "HEAD"])?;
    if revision.is_empty() {
        return None;
    }
    let dirty = git_stdout(
        root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )
    .map(|status| !status.is_empty());
    Some(WorkspaceGitProvenance { revision, dirty })
}

fn xray_core_git_provenance_at(root: &Path) -> Option<WorkspaceGitProvenance> {
    let revision = git_stdout(root, &["rev-parse", "--verify", "HEAD"])?;
    if revision.is_empty() {
        return None;
    }
    let tracked_status = xray_core_tracked_status(root).ok()?;
    let untracked_paths = xray_core_untracked_paths(root).ok()?;
    Some(WorkspaceGitProvenance {
        revision,
        dirty: Some(xray_core_source_is_dirty(&tracked_status, &untracked_paths)),
    })
}

fn engine_source_git_provenance(
    kind: EngineKind,
    options: &BenchOptions,
) -> Option<WorkspaceGitProvenance> {
    let source_dir = match kind {
        EngineKind::XrayRust => workspace_root().ok(),
        EngineKind::XrayCore if options.xray_core_bin.is_some() => None,
        EngineKind::XrayCore => options.xray_core_dir.clone().or_else(default_xray_core_dir),
        EngineKind::SingBox => options.sing_box_dir.clone().or_else(|| {
            options
                .sing_box_bin
                .is_none()
                .then(default_sing_box_dir)
                .flatten()
        }),
    }?;
    match kind {
        EngineKind::XrayCore => xray_core_git_provenance_at(&source_dir),
        EngineKind::XrayRust | EngineKind::SingBox => git_provenance_at(&source_dir),
    }
}

fn git_stdout(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn file_sha256(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hex_lower(&hasher.finalize()))
}

fn push_invocation_value(args: &mut Vec<String>, flag: &str, value: impl Into<String>) {
    args.push(flag.to_owned());
    args.push(value.into());
}

fn push_invocation_path(args: &mut Vec<String>, flag: &str, path: &Path) {
    push_invocation_value(args, flag, path.to_string_lossy().into_owned());
}

fn canonical_run_invocation_args(
    kind: EngineKind,
    options: &BenchOptions,
    engine_binary_path: &Path,
) -> Vec<String> {
    let mut args = vec!["run".to_owned()];
    push_invocation_value(&mut args, "--engine", kind.as_str());
    push_invocation_value(&mut args, "--workload", options.workload.as_str());
    push_invocation_value(
        &mut args,
        "--duration-ms",
        options.duration.as_millis().to_string(),
    );
    push_invocation_value(
        &mut args,
        "--sample-interval-ms",
        options.sample_interval.as_millis().to_string(),
    );
    push_invocation_value(
        &mut args,
        "--run-timeout-ms",
        options.run_timeout.as_millis().to_string(),
    );
    push_invocation_value(&mut args, "--connections", options.connections.to_string());
    push_invocation_value(&mut args, "--iterations", options.iterations.to_string());
    push_invocation_value(
        &mut args,
        "--payload-size",
        options.payload_size.to_string(),
    );
    if let Ok(scenario) = options.stream_scenario() {
        push_invocation_value(&mut args, "--stream-transport", scenario.transport.as_str());
        push_invocation_value(&mut args, "--traffic", scenario.traffic.as_str());
        if let Some(mode) = scenario.xhttp_mode {
            push_invocation_value(&mut args, "--xhttp-mode", mode.as_str());
        }
        if let Some(profile) = scenario.xhttp_profile {
            push_invocation_value(&mut args, "--xhttp-profile", profile.as_str());
        }
        if let Some(max_post_bytes) = options.xhttp_max_post_bytes {
            push_invocation_value(
                &mut args,
                "--xhttp-max-post-bytes",
                max_post_bytes.to_string(),
            );
        }
        push_invocation_value(
            &mut args,
            "--settle-ms",
            options.settle.as_millis().to_string(),
        );
    }
    push_invocation_value(&mut args, "--transport", options.dns_transport.as_str());
    push_invocation_value(
        &mut args,
        "--dns-upstream-transport",
        options.dns_upstream_transport.as_str(),
    );
    push_invocation_value(&mut args, "--runs", options.runs.to_string());
    push_invocation_path(&mut args, "--out-dir", &options.out_dir);

    let xray_rust_bin = (kind == EngineKind::XrayRust)
        .then_some(engine_binary_path)
        .or(options.xray_rust_bin.as_deref());
    if let Some(path) = xray_rust_bin {
        push_invocation_path(&mut args, "--xray-rust-bin", path);
    }
    let xray_core_bin = (kind == EngineKind::XrayCore)
        .then_some(engine_binary_path)
        .or(options.xray_core_bin.as_deref());
    if let Some(path) = xray_core_bin {
        push_invocation_path(&mut args, "--xray-core-bin", path);
    }
    let sing_box_bin = (kind == EngineKind::SingBox)
        .then_some(engine_binary_path)
        .or(options.sing_box_bin.as_deref());
    if let Some(path) = sing_box_bin {
        push_invocation_path(&mut args, "--sing-box-bin", path);
    }
    if let Some(path) = options.xray_core_dir.as_deref() {
        push_invocation_path(&mut args, "--xray-core-dir", path);
    }
    if let Some(path) = options.sing_box_dir.as_deref() {
        push_invocation_path(&mut args, "--sing-box-dir", path);
    }
    if let Some(profile) = options.tun_profile.as_deref() {
        push_invocation_value(&mut args, "--tun-profile", profile);
    }
    if options.no_auto_build {
        args.push("--no-auto-build".to_owned());
    }
    if let Some(path) = options.geodata_dir.as_deref() {
        push_invocation_path(&mut args, "--geodata-dir", path);
    }
    args
}

fn benchmark_provenance(
    kind: EngineKind,
    options: &BenchOptions,
    engine_binary_path: &Path,
) -> BenchProvenance {
    let harness_binary_path = std::env::current_exe()
        .ok()
        .map(|path| fs::canonicalize(&path).unwrap_or(path));
    let engine_binary_path =
        fs::canonicalize(engine_binary_path).unwrap_or_else(|_| engine_binary_path.to_path_buf());
    let harness_binary_sha256 = harness_binary_path.as_deref().and_then(file_sha256);
    let engine_binary_sha256 = file_sha256(&engine_binary_path);
    BenchProvenance {
        harness_profile: harness_build_profile().to_owned(),
        workspace_git: workspace_git_provenance(),
        engine_source_git: engine_source_git_provenance(kind, options),
        harness_binary_path,
        harness_binary_sha256,
        engine_binary_path: Some(engine_binary_path.clone()),
        engine_binary_sha256,
        working_directory: std::env::current_dir().ok(),
        invocation_args: canonical_run_invocation_args(kind, options, &engine_binary_path),
    }
}

pub async fn run_compare(options: BenchOptions) -> Result<(), BenchError> {
    if matches!(
        options.workload,
        WorkloadKind::TunFakeDns | WorkloadKind::TunFakeDnsTcp | WorkloadKind::TunDnsProxy
    ) {
        return Err(BenchError::InvalidArguments(format!(
            "{} is xray-rust-only; use `run --engine xray-rust` instead of `compare`",
            options.workload.as_str()
        )));
    }
    let run_id = new_run_id();
    let rust_summary = run_engine_series(EngineKind::XrayRust, &options, &run_id).await?;
    print_summary(&rust_summary);
    let xray_summary = run_engine_series(EngineKind::XrayCore, &options, &run_id).await?;
    print_summary(&xray_summary);
    if benchmark_supports_sing_box(&options)? {
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

fn benchmark_supports_sing_box(options: &BenchOptions) -> Result<bool, BenchError> {
    if options.workload == WorkloadKind::StreamTransport {
        Ok(options.stream_scenario()?.transport.supports_sing_box())
    } else {
        Ok(options.workload.supports_sing_box_process_engine())
    }
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
        results.push(run_engine_once(kind, options, run_id, &run_dir, &binary_dir).await?);
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
    run_engine_once(kind, options, run_id, &run_dir, &binary_dir).await
}

fn workload_dns_transport(
    workload: WorkloadKind,
    configured_transport: TunDnsTransport,
) -> Option<&'static str> {
    match workload {
        WorkloadKind::TunDnsProxy => Some(configured_transport.as_str()),
        WorkloadKind::TunFakeDns => Some("udp"),
        WorkloadKind::TunFakeDnsTcp => Some("tcp"),
        _ => None,
    }
}

async fn run_engine_once(
    kind: EngineKind,
    options: &BenchOptions,
    run_id: &str,
    run_dir: &Path,
    binary_dir: &Path,
) -> Result<BenchResult, BenchError> {
    if options.workload == WorkloadKind::StreamTransport {
        let scenario = options.stream_scenario()?;
        if !scenario.supports_engine(kind) {
            return Err(BenchError::InvalidArguments(format!(
                "{} does not support the {} stream transport",
                kind.as_str(),
                scenario.transport.as_str()
            )));
        }
    }
    fs::create_dir_all(run_dir).map_err(|source| BenchError::Io {
        action: format!("creating run directory `{}`", run_dir.display()),
        source,
    })?;
    let fixture = WorkloadFixture::start(options.workload, options, run_dir, binary_dir).await?;
    let engine = start_engine(kind, options, run_dir, binary_dir, &fixture).await?;
    let started = Instant::now();
    let phase = BenchmarkPhaseTracker::default();
    let workload_phase = phase.clone();
    let workload = async {
        workload_phase.set(BenchmarkPhase::Workload);
        let outcome = match options.workload {
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
            WorkloadKind::TunFakeDns => run_tun_fake_dns_workload(engine.tun_fd()?, options).await,
            WorkloadKind::TunFakeDnsTcp => {
                run_tun_fake_dns_tcp_workload(engine.tun_fd()?, options).await
            }
            WorkloadKind::TunDnsProxy => {
                run_tun_dns_proxy_workload(engine.tun_fd()?, options).await
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
            // Both run `tcp-bulk-throughput`'s traffic driver unchanged; what
            // differs is the fixture and the outbound it is carried over, which
            // is the point of measuring them separately.
            WorkloadKind::RealityVisionBulkThroughput | WorkloadKind::GrpcBulkThroughput => {
                run_tcp_bulk_throughput_workload(engine.socks_addr, options).await
            }
            WorkloadKind::StreamTransport => {
                stream_transport::run_workload(
                    engine.socks_addr,
                    options,
                    options.stream_scenario()?,
                    workload_phase.clone(),
                )
                .await
            }
        };
        workload_phase.set(BenchmarkPhase::Complete);
        outcome
    };
    let (workload_outcome, samples) = match timeout(
        options.run_timeout,
        sample_while_phased(engine.pid, options.sample_interval, phase, workload),
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
    let transfer_duration = workload_outcome
        .transfer_window
        .map(|(start, end)| end.saturating_duration_since(start));
    let throughput_mbps = throughput_mbps(
        summary.bytes_sent,
        summary.bytes_received,
        duration_ms,
        transfer_duration,
    );
    let uplink_write_ops = workload_outcome.uplink_write_ops;
    let uplink_write_ops_per_second = operations_per_second(uplink_write_ops, transfer_duration);
    let stream_scenario = (options.workload == WorkloadKind::StreamTransport)
        .then(|| options.stream_scenario())
        .transpose()?;
    let xhttp_max_post_bytes = stream_scenario.and_then(|scenario| {
        scenario
            .effective_xhttp_max_post_bytes(options.payload_size, options.xhttp_max_post_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok())
    });
    let provenance = benchmark_provenance(kind, options, &engine.binary_path);

    let result = BenchResult {
        run_id: run_id.to_owned(),
        provenance,
        engine: kind.as_str().to_owned(),
        workload: options.workload.as_str().to_owned(),
        status: "ok".to_owned(),
        duration_ms,
        transfer_duration_ms: transfer_duration.map(|transfer| transfer.as_millis()),
        bytes_sent: summary.bytes_sent,
        bytes_received: summary.bytes_received,
        peak_rss_kib: summary.peak_rss_kib,
        cpu_millis: summary.cpu_millis,
        cpu_millis_per_gib,
        throughput_mbps,
        connections: options.connections as u64,
        iterations: options.iterations as u64,
        payload_size: options.payload_size as u64,
        stream_transport: stream_scenario.map(|scenario| scenario.transport.as_str().to_owned()),
        stream_traffic: stream_scenario.map(|scenario| scenario.traffic.as_str().to_owned()),
        xhttp_mode: stream_scenario
            .and_then(|scenario| scenario.xhttp_mode)
            .map(|mode| mode.as_str().to_owned()),
        xhttp_profile: stream_scenario
            .and_then(|scenario| scenario.xhttp_profile)
            .map(|profile| profile.as_str().to_owned()),
        xhttp_max_post_bytes,
        settle_ms: if options.workload == WorkloadKind::StreamTransport {
            options.settle.as_millis()
        } else {
            0
        },
        memory_phases: summarize_memory_phases(&samples),
        uplink_write_ops,
        uplink_write_ops_per_second,
        dns_transport: workload_dns_transport(options.workload, options.dns_transport)
            .map(str::to_owned),
        dns_upstream_transport: (options.workload == WorkloadKind::TunDnsProxy)
            .then(|| options.dns_upstream_transport.as_str().to_owned()),
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

fn format_benchmark_provenance(run_id: &str, provenance: &BenchProvenance) -> String {
    let mut formatted = String::new();
    if !run_id.is_empty() {
        formatted.push_str(&format!(" run_id={run_id}"));
    }
    if !provenance.harness_profile.is_empty() {
        formatted.push_str(&format!(" harness_profile={}", provenance.harness_profile));
    }
    if let Some(git) = provenance.workspace_git.as_ref() {
        formatted.push_str(&format!(" workspace_git_revision={}", git.revision));
        if let Some(dirty) = git.dirty {
            formatted.push_str(&format!(" workspace_git_dirty={dirty}"));
        }
    }
    if let Some(git) = provenance.engine_source_git.as_ref() {
        formatted.push_str(&format!(" engine_source_git_revision={}", git.revision));
        if let Some(dirty) = git.dirty {
            formatted.push_str(&format!(" engine_source_git_dirty={dirty}"));
        }
    }
    if let Some(sha256) = provenance.harness_binary_sha256.as_deref() {
        formatted.push_str(&format!(" harness_binary_sha256={sha256}"));
    }
    if let Some(path) = provenance.engine_binary_path.as_deref() {
        formatted.push_str(&format!(" engine_binary_path={}", path.display()));
    }
    if let Some(sha256) = provenance.engine_binary_sha256.as_deref() {
        formatted.push_str(&format!(" engine_binary_sha256={sha256}"));
    }
    formatted
}

fn print_result(result: &BenchResult) {
    let stream_scenario = result
        .stream_transport
        .as_deref()
        .zip(result.stream_traffic.as_deref())
        .map(|(transport, traffic)| {
            let mode = result
                .xhttp_mode
                .as_deref()
                .map(|mode| format!(" xhttp_mode={mode}"))
                .unwrap_or_default();
            format!(" stream_transport={transport} traffic={traffic}{mode}")
        })
        .unwrap_or_default();
    let uplink_write_ops = result
        .uplink_write_ops
        .zip(result.uplink_write_ops_per_second)
        .map(|(operations, rate)| {
            format!(" uplink_write_ops={operations} uplink_write_ops_per_second={rate}")
        })
        .unwrap_or_default();
    let dns_transport = result
        .dns_transport
        .as_deref()
        .map(|transport| format!(" transport={transport}"))
        .unwrap_or_default();
    let dns_upstream_transport = result
        .dns_upstream_transport
        .as_deref()
        .map(|transport| format!(" upstream_transport={transport}"))
        .unwrap_or_default();
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
    let provenance = format_benchmark_provenance(&result.run_id, &result.provenance);
    println!(
        "{} {} status={} peak_rss_kib={} cpu_millis={} bytes_sent={} bytes_received={} samples={}{}{}{}{}{}{}{}{}{}{}",
        result.engine,
        result.workload,
        result.status,
        result.peak_rss_kib,
        result.cpu_millis,
        result.bytes_sent,
        result.bytes_received,
        result.samples,
        stream_scenario,
        uplink_write_ops,
        dns_transport,
        dns_upstream_transport,
        cpu_per_gib,
        throughput,
        latency,
        setup,
        blackhole,
        provenance,
    );
}

fn print_route_probe_result(result: &RouteProbeResult) {
    println!(
        "route-probe iterations={} rules={} outbounds={} dns_candidates={} cidrs_per_rule={} domains_per_rule={} peak_rss_kib={} selected={} total_us={} avg_ns={}",
        result.iterations,
        result.rules,
        result.outbounds,
        result.dns_candidates,
        result.cidrs_per_rule,
        result.domains_per_rule,
        result.peak_rss_kib,
        result.selected,
        result.total_us,
        result.avg_ns
    );
}

fn print_dns_policy_probe_result(result: &DnsPolicyProbeResult) {
    println!(
        "dns-policy-probe iterations={} servers={} matchers={} common_selected={} common_compile_us={} common_pattern_bytes={} common_total_us={} common_avg_ns={} worst_selected={} worst_compile_us={} worst_pattern_bytes={} worst_total_us={} worst_avg_ns={} outbound_common_decision={} outbound_common_compile_us={} outbound_common_total_us={} outbound_common_avg_ns={} outbound_worst_decision={} outbound_worst_compile_us={} outbound_worst_total_us={} outbound_worst_avg_ns={} ip_filter_hit_matched={} ip_filter_miss_rejected={} ip_filter_compile_us={} ip_filter_matchers={} ip_filter_ranges={} ip_filter_hit_total_us={} ip_filter_hit_avg_ns={} ip_filter_miss_total_us={} ip_filter_miss_avg_ns={}",
        result.iterations,
        result.servers,
        result.matchers,
        result.common_no_domains.selected_per_iteration,
        result.common_no_domains.compile_us,
        result.common_no_domains.pattern_bytes,
        result.common_no_domains.total_us,
        result.common_no_domains.avg_ns,
        result.worst_case_matchers.selected_per_iteration,
        result.worst_case_matchers.compile_us,
        result.worst_case_matchers.pattern_bytes,
        result.worst_case_matchers.total_us,
        result.worst_case_matchers.avg_ns,
        result.outbound_common_first_rule.decision,
        result.outbound_common_first_rule.compile_us,
        result.outbound_common_first_rule.total_us,
        result.outbound_common_first_rule.avg_ns,
        result.outbound_worst_ordered_rule_matchers.decision,
        result.outbound_worst_ordered_rule_matchers.compile_us,
        result.outbound_worst_ordered_rule_matchers.total_us,
        result.outbound_worst_ordered_rule_matchers.avg_ns,
        result.worst_case_ip_filter.hit_matched,
        result.worst_case_ip_filter.miss_rejected,
        result.worst_case_ip_filter.compile_us,
        result.worst_case_ip_filter.compiled_matchers,
        result.worst_case_ip_filter.compiled_ranges,
        result.worst_case_ip_filter.hit_total_us,
        result.worst_case_ip_filter.hit_avg_ns,
        result.worst_case_ip_filter.miss_total_us,
        result.worst_case_ip_filter.miss_avg_ns,
    );
    for selector in &result.outbound_selector_prefilter {
        println!(
            "dns-policy-probe-selector rules={} hit_selected_dns={} last_hit_selected_dns={} miss_preserved_regular_path={} semantic_miss_preserved_regular_path={} compile_us={} hit_total_us={} hit_avg_ns={} last_hit_total_us={} last_hit_avg_ns={} miss_total_us={} miss_avg_ns={} semantic_miss_total_us={} semantic_miss_avg_ns={}",
            selector.rules,
            selector.hit_selected_dns,
            selector.last_hit_selected_dns,
            selector.miss_preserved_regular_path,
            selector.semantic_miss_preserved_regular_path,
            selector.compile_us,
            selector.hit_total_us,
            selector.hit_avg_ns,
            selector.last_hit_total_us,
            selector.last_hit_avg_ns,
            selector.miss_total_us,
            selector.miss_avg_ns,
            selector.semantic_miss_total_us,
            selector.semantic_miss_avg_ns,
        );
    }
    if let Some(hosts) = &result.hosts {
        println!(
            "dns-policy-probe-hosts hosts={} hit_matched={} miss_rejected={} hosts_compile_us={} peak_rss_kib={} hosts_hit_total_us={} hosts_hit_avg_ns={} hosts_miss_total_us={} hosts_miss_avg_ns={}",
            hosts.hosts,
            hosts.hit_matched,
            hosts.miss_rejected,
            hosts.compile_us,
            hosts.peak_rss_kib,
            hosts.hit_total_us,
            hosts.hit_avg_ns,
            hosts.miss_total_us,
            hosts.miss_avg_ns,
        );
    }
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
    let stream_scenario = summary
        .stream_transport
        .as_deref()
        .zip(summary.stream_traffic.as_deref())
        .map(|(transport, traffic)| {
            let mode = summary
                .xhttp_mode
                .as_deref()
                .map(|mode| format!(" xhttp_mode={mode}"))
                .unwrap_or_default();
            format!(" stream_transport={transport} traffic={traffic}{mode}")
        })
        .unwrap_or_default();
    let uplink_write_ops = summary
        .uplink_write_ops
        .as_ref()
        .zip(summary.uplink_write_ops_per_second.as_ref())
        .map(|(operations, rate)| {
            format!(
                " uplink_write_ops[min/median/p95]={}/{}/{} uplink_write_ops_per_second[min/median/p95]={}/{}/{}",
                operations.min,
                operations.median,
                operations.p95,
                rate.min,
                rate.median,
                rate.p95,
            )
        })
        .unwrap_or_default();
    let dns_transport = summary
        .dns_transport
        .as_deref()
        .map(|transport| format!(" transport={transport}"))
        .unwrap_or_default();
    let dns_upstream_transport = summary
        .dns_upstream_transport
        .as_deref()
        .map(|transport| format!(" upstream_transport={transport}"))
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
    let provenance = format_benchmark_provenance(&summary.run_id, &summary.provenance);
    println!(
        "{} {} runs={} status={} duration_ms[min/median/p95]={}/{}/{} peak_rss_kib[min/median/p95]={}/{}/{} cpu_millis[min/median/p95]={}/{}/{} bytes_sent[min/median/p95]={}/{}/{} bytes_received[min/median/p95]={}/{}/{}{}{}{}{}{}{}{}{}{}",
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
        stream_scenario,
        uplink_write_ops,
        dns_transport,
        dns_upstream_transport,
        cpu_per_gib,
        throughput,
        latency,
        setup,
        provenance,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn xray_core_output_path_is_scoped_to_the_pinned_oracle() {
        let path = xray_core_oracle_binary_path(Path::new("target/bench-bin"));

        assert_eq!(
            path,
            PathBuf::from(format!(
                "target/bench-bin/xray-core-v{XRAY_CORE_ORACLE_VERSION}-{XRAY_CORE_ORACLE_REVISION}{}",
                std::env::consts::EXE_SUFFIX
            ))
        );
        assert!(!path.ends_with(format!("xray-core{}", std::env::consts::EXE_SUFFIX)));
    }

    #[test]
    fn xray_core_go_build_command_sanitizes_source_affecting_environment() {
        let checkout = Path::new("Xray-core");
        let binary = Path::new("target/bench-bin/xray-core");
        let command = xray_core_go_build_command_for_env(
            checkout,
            binary,
            [
                OsString::from("HOME"),
                OsString::from("CGO_CFLAGS"),
                OsString::from("cgo_ldflags"),
                OsString::from("CGO_ENABLED"),
            ],
        );
        let args = command.get_args().collect::<Vec<_>>();
        let env = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().to_ascii_uppercase(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<HashMap<_, _>>();

        assert_eq!(command.get_program(), OsStr::new("go"));
        assert_eq!(command.get_current_dir(), Some(checkout));
        assert_eq!(
            args,
            [
                OsStr::new("build"),
                OsStr::new("-o"),
                binary.as_os_str(),
                OsStr::new("./main"),
            ]
        );
        assert_eq!(
            env.get("GOENV").and_then(|value| value.as_deref()),
            Some("off")
        );
        assert_eq!(
            env.get("GOWORK").and_then(|value| value.as_deref()),
            Some("off")
        );
        assert_eq!(env.get("GOFLAGS"), Some(&None));
        assert_eq!(env.get("GOEXPERIMENT"), Some(&None));
        assert_eq!(env.get("GOTOOLCHAIN"), Some(&None));
        assert_eq!(env.get("CGO_CFLAGS"), Some(&None));
        assert_eq!(env.get("CGO_LDFLAGS"), Some(&None));
        assert_eq!(
            env.get("CGO_ENABLED").and_then(|value| value.as_deref()),
            Some("0")
        );
        assert!(!env.contains_key("HOME"));
    }

    #[test]
    fn caller_supplied_xray_core_binary_must_resolve_to_a_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "xray-bench-explicit-binary-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("xray");
        fs::write(&binary, b"not executed by this test").unwrap();

        let canonical = canonical_xray_core_binary(&binary).unwrap();
        assert_eq!(canonical, fs::canonicalize(&binary).unwrap());
        assert!(canonical_xray_core_binary(&root)
            .unwrap_err()
            .to_string()
            .contains("is not a file"));
        assert!(canonical_xray_core_binary(&root.join("missing")).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn xray_core_checkout_metadata_requires_the_exact_clean_revision() {
        let checkout = Path::new("Xray-core");

        assert!(validate_xray_core_checkout_metadata(
            checkout,
            XRAY_CORE_ORACLE_REVISION,
            "",
            "target/\nxray"
        )
        .is_ok());

        let wrong_revision = validate_xray_core_checkout_metadata(
            checkout,
            "1bdb488c9ec09ea51e6899697d5b7437f3cf6eb2",
            "",
            "",
        )
        .unwrap_err();
        assert!(wrong_revision
            .to_string()
            .contains(XRAY_CORE_ORACLE_REVISION));

        let tracked_change = validate_xray_core_checkout_metadata(
            checkout,
            XRAY_CORE_ORACLE_REVISION,
            " M go.mod",
            "",
        )
        .unwrap_err();
        assert!(tracked_change.to_string().contains("tracked changes"));

        let untracked_source = validate_xray_core_checkout_metadata(
            checkout,
            XRAY_CORE_ORACLE_REVISION,
            "",
            "target/\nxray\nlocal_override.go",
        )
        .unwrap_err();
        assert!(untracked_source.to_string().contains("local_override.go"));
    }

    #[test]
    fn xray_core_source_dirty_ignores_only_guarded_build_artifacts() {
        assert!(!xray_core_source_is_dirty("", "target/\nxray\nxray.exe"));
        assert!(xray_core_source_is_dirty(" M go.mod", "target/\nxray"));
        assert!(xray_core_source_is_dirty("", "target/\nlocal_override.go"));
    }

    #[test]
    fn explicit_xray_core_binary_never_claims_checkout_provenance() {
        let options = BenchOptions {
            xray_core_bin: Some(PathBuf::from("/tmp/xray-core")),
            xray_core_dir: Some(PathBuf::from("Xray-core")),
            ..BenchOptions::default()
        };

        assert_eq!(
            engine_source_git_provenance(EngineKind::XrayCore, &options),
            None
        );
    }

    #[test]
    fn xray_core_checkout_status_allows_only_known_untracked_artifacts() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let checkout = std::env::temp_dir().join(format!(
            "xray-bench-checkout-status-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(checkout.join("target")).unwrap();
        required_git_stdout(&checkout, &["init", "--quiet"]).unwrap();
        fs::write(checkout.join("target/oracle"), b"untracked build product").unwrap();
        fs::write(checkout.join("xray"), b"local binary").unwrap();

        let untracked_only = xray_core_tracked_status(&checkout).unwrap();
        assert!(untracked_only.is_empty());
        let allowed_paths = xray_core_untracked_paths(&checkout).unwrap();
        assert!(validate_xray_core_checkout_metadata(
            Path::new("Xray-core"),
            XRAY_CORE_ORACLE_REVISION,
            "",
            &allowed_paths,
        )
        .is_ok());

        fs::write(checkout.join("local_override.go"), b"package main").unwrap();
        let source_paths = xray_core_untracked_paths(&checkout).unwrap();
        let untracked_source = validate_xray_core_checkout_metadata(
            Path::new("Xray-core"),
            XRAY_CORE_ORACLE_REVISION,
            "",
            &source_paths,
        )
        .unwrap_err();
        assert!(untracked_source.to_string().contains("local_override.go"));

        fs::write(checkout.join("tracked.txt"), b"staged source").unwrap();
        required_git_stdout(&checkout, &["add", "tracked.txt"]).unwrap();
        let tracked = xray_core_tracked_status(&checkout).unwrap();
        fs::remove_dir_all(&checkout).unwrap();

        assert!(tracked.contains("tracked.txt"));
    }

    #[test]
    fn xray_core_version_output_requires_the_pinned_release() {
        let binary = Path::new("/tmp/xray-core");
        let pinned = "Xray 26.7.28 (Xray, Penetrates Everything.) 5ca6f4b (go1.26.0 darwin/arm64)\nA unified platform for anti-censorship.\n";

        assert!(validate_xray_core_version_output(binary, pinned, None).is_ok());
        assert!(
            validate_xray_core_version_output(binary, pinned, Some(XRAY_CORE_ORACLE_REVISION))
                .is_ok()
        );

        let old = "Xray 26.5.9 (Xray, Penetrates Everything.) 1bdb488 (go1.26.0 darwin/arm64)\n";
        let error = validate_xray_core_version_output(binary, old, None).unwrap_err();
        assert!(error.to_string().contains("requires Xray 26.7.28"));
    }

    #[test]
    fn auto_built_xray_core_version_output_requires_the_pinned_revision() {
        let binary = Path::new("/tmp/xray-core");
        let wrong_revision =
            "Xray 26.7.28 (Xray, Penetrates Everything.) deadbee (go1.26.0 darwin/arm64)\n";

        let error = validate_xray_core_version_output(
            binary,
            wrong_revision,
            Some(XRAY_CORE_ORACLE_REVISION),
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires revision `5ca6f4b`"));

        // A caller-supplied official binary must report the pinned release,
        // but it may not carry the checkout's VCS build token.
        let custom = "Xray 26.7.28 (Xray, Penetrates Everything.) Custom (go1.26.0 darwin/arm64)\n";
        assert!(validate_xray_core_version_output(binary, custom, None).is_ok());

        // Go includes untracked checkout artifacts in its VCS dirty bit. The
        // auto-build path has already verified exact HEAD and no tracked or
        // staged edits, so this form is still the pinned source oracle.
        let untracked_dirty =
            "Xray 26.7.28 (Xray, Penetrates Everything.) 5ca6f4b-dirty (go1.26.0 darwin/arm64)\n";
        assert!(validate_xray_core_version_output(
            binary,
            untracked_dirty,
            Some(XRAY_CORE_ORACLE_REVISION)
        )
        .is_ok());
    }

    fn minimal_bench_result() -> BenchResult {
        BenchResult {
            run_id: String::new(),
            provenance: BenchProvenance::default(),
            engine: "xray-rust".to_owned(),
            workload: "tcp-freedom".to_owned(),
            status: "ok".to_owned(),
            duration_ms: 10,
            transfer_duration_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
            peak_rss_kib: 1_000,
            cpu_millis: 5,
            cpu_millis_per_gib: None,
            throughput_mbps: None,
            connections: 1,
            iterations: 1,
            payload_size: 512,
            stream_transport: None,
            stream_traffic: None,
            xhttp_mode: None,
            xhttp_profile: None,
            xhttp_max_post_bytes: None,
            settle_ms: 0,
            memory_phases: Vec::new(),
            uplink_write_ops: None,
            uplink_write_ops_per_second: None,
            dns_transport: None,
            dns_upstream_transport: None,
            latency_us: None,
            setup_us: None,
            samples: 2,
            blackhole_connections_accepted: None,
            blackhole_connections_active: None,
        }
    }

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
                stream_transport: None,
                stream_traffic: None,
                xhttp_mode: None,
                xhttp_profile: None,
                xhttp_max_post_bytes: None,
                settle: Duration::ZERO,
                dns_transport: TunDnsTransport::Both,
                dns_upstream_transport: TunDnsUpstreamTransport::Classic,
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
    fn parses_stream_transport_axes_without_changing_legacy_workloads() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "stream-transport",
            "--stream-transport",
            "xhttp-h2",
            "--traffic",
            "full-duplex",
            "--xhttp-mode",
            "stream-up",
            "--connections",
            "32",
            "--iterations",
            "4096",
            "--payload-size",
            "65536",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::StreamTransport);
        assert_eq!(
            options.stream_transport,
            Some(StreamBenchTransport::XhttpHttp2)
        );
        assert_eq!(options.stream_traffic, Some(StreamBenchTraffic::FullDuplex));
        assert_eq!(options.xhttp_mode, Some(StreamBenchXhttpMode::StreamUp));
        assert_eq!(
            (
                options.connections,
                options.iterations,
                options.payload_size
            ),
            (32, 4096, 65536)
        );
    }

    #[test]
    fn parses_xhttp_h3_stream_transport_axis() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "stream-transport",
            "--stream-transport",
            "xhttp-h3",
            "--traffic",
            "download",
            "--xhttp-mode",
            "stream-one",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        assert_eq!(
            (
                options.stream_transport,
                options.stream_traffic,
                options.xhttp_mode,
            ),
            (
                Some(StreamBenchTransport::XhttpHttp3),
                Some(StreamBenchTraffic::Download),
                Some(StreamBenchXhttpMode::StreamOne),
            )
        );
    }

    #[test]
    fn parses_legacy_xhttp_memory_profile_with_held_open_and_settle() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "stream-transport",
            "--traffic",
            "held-open",
            "--xhttp-profile",
            "legacy-extra-h1-packet-up",
            "--settle-ms",
            "750",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        let scenario = options.stream_scenario().unwrap();
        assert_eq!(scenario.transport, StreamBenchTransport::XhttpHttp1);
        assert_eq!(scenario.traffic, StreamBenchTraffic::HeldOpen);
        assert_eq!(
            scenario.xhttp_profile,
            Some(StreamBenchXhttpProfile::LegacyExtraH1PacketUp)
        );
        assert_eq!(
            scenario.effective_xhttp_max_post_bytes(options.payload_size, None),
            Some(500_000)
        );
        assert_eq!(options.settle, Duration::from_millis(750));
    }

    #[test]
    fn parses_xhttp_max_post_bytes_independently_from_payload_size() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "stream-transport",
            "--stream-transport",
            "xhttp-h1",
            "--traffic",
            "packet-up",
            "--payload-size",
            "16384",
            "--xhttp-max-post-bytes",
            "500000",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        assert_eq!(options.payload_size, 16_384);
        assert_eq!(options.xhttp_max_post_bytes, Some(500_000));
    }

    #[test]
    fn rejects_xhttp_memory_flags_outside_their_transport_scope() {
        let wrong_transport = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "stream-transport",
            "--stream-transport",
            "ws",
            "--traffic",
            "held-open",
            "--xhttp-max-post-bytes",
            "500000",
        ])
        .unwrap_err();
        assert!(wrong_transport
            .to_string()
            .contains("requires an XHTTP stream transport"));

        let wrong_workload = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "idle",
            "--settle-ms",
            "100",
        ])
        .unwrap_err();
        assert!(wrong_workload
            .to_string()
            .contains("require --workload stream-transport"));
    }

    #[test]
    fn xhttp_h3_compare_explicitly_skips_sing_box() {
        let options = BenchOptions {
            workload: WorkloadKind::StreamTransport,
            stream_transport: Some(StreamBenchTransport::XhttpHttp3),
            stream_traffic: Some(StreamBenchTraffic::Upload),
            xhttp_mode: Some(StreamBenchXhttpMode::PacketUp),
            ..BenchOptions::default()
        };

        assert!(!benchmark_supports_sing_box(&options).unwrap());
    }

    #[test]
    fn rejects_stream_axes_on_legacy_workloads() {
        let error = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "grpc-bulk-throughput",
            "--stream-transport",
            "grpc",
            "--traffic",
            "download",
        ])
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("require --workload stream-transport"));
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
        assert_eq!(options.workload, WorkloadKind::RealityVisionBulkThroughput);
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
    fn parses_run_tun_fake_dns() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "tun-fake-dns",
            "--connections",
            "2",
            "--iterations",
            "3",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        assert_eq!(options.engine, Some(EngineKind::XrayRust));
        assert_eq!(options.workload, WorkloadKind::TunFakeDns);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
    }

    #[test]
    fn parses_run_tun_fake_dns_tcp() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "tun-fake-dns-tcp",
            "--connections",
            "2",
            "--iterations",
            "3",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        assert_eq!(options.engine, Some(EngineKind::XrayRust));
        assert_eq!(options.workload, WorkloadKind::TunFakeDnsTcp);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
    }

    #[test]
    fn parses_run_tun_dns_proxy_transport() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "tun-dns-proxy",
            "--connections",
            "8",
            "--iterations",
            "25",
            "--transport",
            "tcp",
            "--dns-upstream-transport",
            "tcp-local",
        ])
        .unwrap();

        let CliArgs::Run(options) = args else {
            panic!("expected run args");
        };
        assert_eq!(options.workload, WorkloadKind::TunDnsProxy);
        assert_eq!(options.connections, 8);
        assert_eq!(options.iterations, 25);
        assert_eq!(options.dns_transport, TunDnsTransport::Tcp);
        assert_eq!(
            options.dns_upstream_transport,
            TunDnsUpstreamTransport::TcpLocal
        );
    }

    #[test]
    fn rejects_unknown_tun_dns_proxy_transport() {
        let error = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "tun-dns-proxy",
            "--transport",
            "quic",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("expected udp|tcp|both"));
    }

    #[test]
    fn rejects_unknown_tun_dns_proxy_upstream_transport() {
        let error = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "tun-dns-proxy",
            "--dns-upstream-transport",
            "quic",
        ])
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("expected classic|tcp-routed|tcp-local"));
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
        assert!(WorkloadKind::TunFakeDns.uses_tun_fd());
        assert!(WorkloadKind::TunFakeDnsTcp.uses_tun_fd());
        assert!(WorkloadKind::TunDnsProxy.uses_tun_fd());
        assert!(WorkloadKind::TunTcpFreedom.uses_tun_fd());
        assert!(WorkloadKind::TunTcpStaleFlows.uses_tun_fd());
        assert!(WorkloadKind::TunRealityBlackhole.uses_tun_fd());
    }

    #[cfg(unix)]
    #[test]
    fn tun_fake_dns_query_validation_accepts_a_and_https_nodata() {
        let a_query = build_dns_query(0x1203, TUN_FAKE_DNS_DOMAIN, DNS_TYPE_A).unwrap();
        let mut a_response = a_query.clone();
        a_response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        a_response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        a_response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 19, 0, 1]);
        validate_tun_fake_dns_response(
            &a_query,
            &a_response,
            TunFakeDnsExpectation::A(TUN_FAKE_DNS_FIRST_IPV4),
        )
        .unwrap();

        let https_query = build_dns_query(0x1204, TUN_FAKE_DNS_DOMAIN, DNS_TYPE_HTTPS).unwrap();
        let mut https_response = https_query.clone();
        https_response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        validate_tun_fake_dns_response(
            &https_query,
            &https_response,
            TunFakeDnsExpectation::NoData,
        )
        .unwrap();
    }

    #[cfg(unix)]
    async fn handle_fragmented_dns_tcp_test_connection(
        mut stream: TcpStream,
        queries_per_connection: usize,
        fixture_counters: Arc<DnsProxyFixtureCounters>,
    ) -> Result<Vec<(u16, u16)>, BenchError> {
        stream.set_nodelay(true).map_err(|source| BenchError::Io {
            action: "enabling TCP_NODELAY on fragmented DNS fixture connection".to_owned(),
            source,
        })?;
        let mut observed = Vec::with_capacity(queries_per_connection);
        for _ in 0..queries_per_connection {
            let mut length = [0_u8; 2];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|source| BenchError::Io {
                    action: "reading fragmented DNS fixture TCP length".to_owned(),
                    source,
                })?;
            let query_len = usize::from(u16::from_be_bytes(length));
            if query_len == 0 {
                return Err(BenchError::InvalidArguments(
                    "fragmented DNS fixture received a zero-length query".to_owned(),
                ));
            }
            let mut query = vec![0_u8; query_len];
            stream
                .read_exact(&mut query)
                .await
                .map_err(|source| BenchError::Io {
                    action: "reading fragmented DNS fixture TCP query".to_owned(),
                    source,
                })?;
            let transaction_id = dns_message_id(&query).ok_or_else(|| {
                BenchError::InvalidArguments(
                    "fragmented DNS fixture query has no transaction id".to_owned(),
                )
            })?;
            let query_type = dns_question_type(&query).ok_or_else(|| {
                BenchError::InvalidArguments(
                    "fragmented DNS fixture query has no question type".to_owned(),
                )
            })?;
            fixture_counters.record_tcp_query(&query);
            observed.push((transaction_id, query_type));

            let response = build_dns_proxy_fixture_response(&query)?;
            let response_len = u16::try_from(response.len()).map_err(|_| {
                BenchError::InvalidArguments(
                    "fragmented DNS fixture response exceeds 65535 bytes".to_owned(),
                )
            })?;
            let response_len = response_len.to_be_bytes();

            // Stagger independent connections so their responses do not follow accept order,
            // then split both the length prefix and payload across distinct TCP writes.
            sleep(Duration::from_millis(u64::from(transaction_id % 4))).await;
            stream
                .write_all(&response_len[..1])
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing fragmented DNS fixture TCP length prefix".to_owned(),
                    source,
                })?;
            sleep(Duration::from_millis(1)).await;
            stream
                .write_all(&response_len[1..])
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing fragmented DNS fixture TCP length suffix".to_owned(),
                    source,
                })?;
            let split = response.len() / 2;
            stream
                .write_all(&response[..split])
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing fragmented DNS fixture TCP payload prefix".to_owned(),
                    source,
                })?;
            sleep(Duration::from_millis(1)).await;
            stream
                .write_all(&response[split..])
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing fragmented DNS fixture TCP payload suffix".to_owned(),
                    source,
                })?;
        }
        Ok(observed)
    }

    #[cfg(unix)]
    async fn spawn_fragmented_dns_hybrid_test_server(
        expected_connections: usize,
        queries_per_connection: usize,
    ) -> Result<
        (
            SocketAddr,
            JoinHandle<Result<Vec<Vec<(u16, u16)>>, BenchError>>,
            JoinHandle<()>,
            Arc<DnsProxyFixtureCounters>,
        ),
        BenchError,
    > {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|source| BenchError::Io {
                action: "binding fragmented DNS fixture".to_owned(),
                source,
            })?;
        let addr = udp.local_addr().map_err(|source| BenchError::Io {
            action: "reading fragmented DNS fixture address".to_owned(),
            source,
        })?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| BenchError::Io {
                action: "binding fragmented DNS TCP fixture".to_owned(),
                source,
            })?;
        let fixture_counters = Arc::new(DnsProxyFixtureCounters::default());
        let udp_counters = Arc::clone(&fixture_counters);
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; u16::MAX as usize];
            loop {
                let Ok((len, peer)) = udp.recv_from(&mut buffer).await else {
                    break;
                };
                udp_counters.record_udp_query(&buffer[..len]);
                let Ok(response) = build_dns_proxy_fixture_response(&buffer[..len]) else {
                    continue;
                };
                let _ = udp.send_to(&response, peer).await;
            }
        });
        let tcp_counters = Arc::clone(&fixture_counters);
        let tcp_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            for _ in 0..expected_connections {
                let (stream, _) = listener.accept().await.map_err(|source| BenchError::Io {
                    action: "accepting fragmented DNS fixture connection".to_owned(),
                    source,
                })?;
                connections.spawn(handle_fragmented_dns_tcp_test_connection(
                    stream,
                    queries_per_connection,
                    Arc::clone(&tcp_counters),
                ));
            }

            let mut observed = Vec::with_capacity(expected_connections);
            while let Some(result) = connections.join_next().await {
                observed.push(result.map_err(|source| {
                    BenchError::InvalidArguments(format!(
                        "fragmented DNS fixture task failed: {source}"
                    ))
                })??);
            }
            Ok(observed)
        });
        Ok((addr, tcp_task, udp_task, fixture_counters))
    }

    #[cfg(unix)]
    fn spawn_tun_core_test_bridge(
        engine_fd: FdGuard,
        core: &Core,
    ) -> Result<JoinHandle<Result<(), BenchError>>, BenchError> {
        set_fd_nonblocking(engine_fd.raw()).map_err(|source| BenchError::Io {
            action: "setting test Core TUN fd nonblocking".to_owned(),
            source,
        })?;
        let fd =
            Arc::new(
                AsyncFd::new(TunFdRef(engine_fd.raw())).map_err(|source| BenchError::Io {
                    action: "registering test Core TUN fd".to_owned(),
                    source,
                })?,
            );
        let inbound = core.tun_handle();
        let outbound = core.tun_handle();

        Ok(tokio::spawn(async move {
            let _engine_fd = engine_fd;
            let read_fd = Arc::clone(&fd);
            let write_fd = Arc::clone(&fd);
            let inbound_loop = async move {
                let mut buffer = vec![0_u8; 65_535 + DARWIN_UTUN_HEADER_LEN];
                loop {
                    let len = read_tun_frame_ready(&read_fd, &mut buffer).await?;
                    let packet = decode_darwin_utun_frame(&buffer[..len])?;
                    inbound
                        .push_inbound(Bytes::copy_from_slice(packet))
                        .await
                        .map_err(|source| {
                            BenchError::InvalidArguments(format!(
                                "test Core rejected an inbound TUN packet: {source}"
                            ))
                        })?;
                }
                #[allow(unreachable_code)]
                Ok::<(), BenchError>(())
            };
            let outbound_loop = async move {
                loop {
                    let packet = outbound.poll_outbound().await.map_err(|source| {
                        BenchError::InvalidArguments(format!(
                            "test Core stopped producing outbound TUN packets: {source}"
                        ))
                    })?;
                    let frame = encode_darwin_utun_frame(&packet);
                    write_tun_frame_ready(&write_fd, &frame).await?;
                }
                #[allow(unreachable_code)]
                Ok::<(), BenchError>(())
            };
            tokio::try_join!(inbound_loop, outbound_loop).map(|_| ())
        }))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dns_proxy_fixture_answers_matching_udp_and_tcp_queries() {
        let (addr, tasks) = spawn_dns_proxy_servers().await.unwrap();
        let query = build_dns_query(0x3412, TUN_DNS_PROXY_DOMAIN, DNS_TYPE_A).unwrap();

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        udp.send_to(&query, addr).await.unwrap();
        let mut udp_buffer = [0_u8; 512];
        let (udp_len, udp_source) = timeout(Duration::from_secs(1), udp.recv_from(&mut udp_buffer))
            .await
            .unwrap()
            .unwrap();
        validate_tun_fake_dns_response(
            &query,
            &udp_buffer[..udp_len],
            TunFakeDnsExpectation::A(TUN_DNS_PROXY_ANSWER_IPV4),
        )
        .unwrap();

        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tcp.write_all(&query).await.unwrap();
        let tcp_len = tcp.read_u16().await.unwrap();
        let mut tcp_response = vec![0_u8; usize::from(tcp_len)];
        tcp.read_exact(&mut tcp_response).await.unwrap();
        validate_tun_fake_dns_response(
            &query,
            &tcp_response,
            TunFakeDnsExpectation::A(TUN_DNS_PROXY_ANSWER_IPV4),
        )
        .unwrap();

        assert_eq!(udp_source, addr);
        for task in tasks {
            task.abort();
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tun_dns_proxy_tcp_runs_bounded_waves_and_validates_fragmented_responses() {
        let connections = 20usize;
        let iterations = 2usize;
        let queries_per_connection = iterations * 2;
        let (upstream, mut fixture_task, udp_fixture_task, fixture_counters) =
            spawn_fragmented_dns_hybrid_test_server(connections, iterations)
                .await
                .unwrap();
        let parsed = parse_xray_json(&tun_dns_proxy_config(
            upstream,
            TunDnsUpstreamTransport::Classic,
        ))
        .unwrap();
        let mut core = Core::new(parsed.config).unwrap();
        core.start().await.unwrap();

        let TunSocketPair {
            engine_fd,
            workload_fd,
        } = create_tun_socket_pair().unwrap();
        let bridge_task = spawn_tun_core_test_bridge(engine_fd, &core).unwrap();
        let options = BenchOptions {
            workload: WorkloadKind::TunDnsProxy,
            connections,
            iterations,
            dns_transport: TunDnsTransport::Tcp,
            ..BenchOptions::default()
        };

        let workload_result = timeout(
            Duration::from_secs(4),
            run_tun_dns_proxy_workload(workload_fd.raw(), &options),
        )
        .await;
        let fixture_result = timeout(Duration::from_secs(1), &mut fixture_task).await;
        if fixture_result.is_err() {
            fixture_task.abort();
        }
        udp_fixture_task.abort();
        bridge_task.abort();
        let _ = bridge_task.await;
        core.stop().await.unwrap();

        let outcome = workload_result
            .expect("TCP scheduler must not hang")
            .expect("TCP scheduler workload must succeed");
        let observed = fixture_result
            .expect("all fragmented DNS fixture connections must finish")
            .expect("fragmented DNS fixture task must not panic")
            .expect("fragmented DNS fixture must accept valid framing");

        assert_eq!(observed.len(), connections);
        for connection_queries in &observed {
            assert_eq!(connection_queries.len(), iterations);
            assert_eq!(
                connection_queries
                    .iter()
                    .map(|(_, query_type)| *query_type)
                    .collect::<Vec<_>>(),
                vec![DNS_TYPE_HTTPS; iterations]
            );
            assert!(connection_queries
                .windows(2)
                .all(|pair| pair[1].0 == pair[0].0.wrapping_add(2)));
        }

        let mut observed_queries = observed.into_iter().flatten().collect::<Vec<_>>();
        observed_queries.sort_unstable();
        let mut expected_queries = Vec::with_capacity(connections * iterations);
        for logical_index in 0..connections {
            let source_port = 54_000_u16 + u16::try_from(logical_index).unwrap();
            for query_index in (1..queries_per_connection).step_by(2) {
                expected_queries.push((
                    source_port.wrapping_add(u16::try_from(query_index).unwrap()),
                    DNS_TYPE_HTTPS,
                ));
            }
        }
        expected_queries.sort_unstable();
        assert_eq!(observed_queries, expected_queries);
        assert_eq!(
            fixture_counters.snapshot(),
            DnsProxyFixtureQueryCounts {
                udp_a_queries: 1,
                tcp_https_queries: u64::try_from(connections * iterations).unwrap(),
                ..DnsProxyFixtureQueryCounts::default()
            },
            "Classic managed A queries must use one cached/single-flight UDP lookup while raw HTTPS remains on each client DNS/TCP session"
        );

        let a_query = build_dns_query(1, TUN_DNS_PROXY_DOMAIN, DNS_TYPE_A).unwrap();
        let https_query = build_dns_query(2, TUN_DNS_PROXY_DOMAIN, DNS_TYPE_HTTPS).unwrap();
        let a_response = build_dns_proxy_fixture_response(&a_query).unwrap();
        let https_response = build_dns_proxy_fixture_response(&https_query).unwrap();
        let expected_iterations = u64::try_from(connections * iterations).unwrap();
        assert_eq!(
            outcome.bytes_sent,
            expected_iterations * u64::try_from(a_query.len() + https_query.len()).unwrap()
        );
        assert_eq!(
            outcome.bytes_received,
            expected_iterations * u64::try_from(a_response.len() + https_response.len()).unwrap()
        );
        assert_eq!(
            outcome.latencies_us.len(),
            connections * queries_per_connection
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tun_dns_proxy_udp_measures_routed_and_local_tcp_upstreams() {
        for upstream_transport in [
            TunDnsUpstreamTransport::TcpRouted,
            TunDnsUpstreamTransport::TcpLocal,
        ] {
            let (upstream, fixture_tasks, fixture_counters) =
                spawn_counted_dns_proxy_servers().await.unwrap();
            let parsed =
                parse_xray_json(&tun_dns_proxy_config(upstream, upstream_transport)).unwrap();
            let mut core = Core::new(parsed.config).unwrap();
            core.start().await.unwrap();

            let TunSocketPair {
                engine_fd,
                workload_fd,
            } = create_tun_socket_pair().unwrap();
            let bridge_task = spawn_tun_core_test_bridge(engine_fd, &core).unwrap();
            let options = BenchOptions {
                workload: WorkloadKind::TunDnsProxy,
                connections: 2,
                iterations: 2,
                dns_transport: TunDnsTransport::Udp,
                dns_upstream_transport: upstream_transport,
                ..BenchOptions::default()
            };

            let outcome = timeout(
                Duration::from_secs(4),
                run_tun_dns_proxy_workload(workload_fd.raw(), &options),
            )
            .await
            .expect("UDP-to-TCP DNS benchmark path must not hang")
            .expect("UDP-to-TCP DNS benchmark path must succeed");
            let query_counts = fixture_counters.snapshot();

            bridge_task.abort();
            let _ = bridge_task.await;
            core.stop().await.unwrap();
            for task in fixture_tasks {
                task.abort();
            }

            assert!(outcome.bytes_sent > 0);
            assert!(outcome.bytes_received > outcome.bytes_sent);
            assert_eq!(outcome.latencies_us.len(), 8);
            assert_eq!(
                query_counts,
                DnsProxyFixtureQueryCounts {
                    tcp_a_queries: 1,
                    tcp_https_queries: 4,
                    ..DnsProxyFixtureQueryCounts::default()
                },
                "managed A must use one cached/single-flight lookup and every raw HTTPS query must use the selected TCP upstream mode {upstream_transport:?}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tun_fake_dns_io_fills_window_when_a_response_is_already_ready() {
        let TunSocketPair {
            engine_fd,
            workload_fd,
        } = create_tun_socket_pair().unwrap();
        let tun = AsyncFd::new(TunFdRef(workload_fd.raw())).unwrap();
        let immediate_response = [0_u8; DARWIN_UTUN_HEADER_LEN];
        write_tun_frame(engine_fd.raw(), &immediate_response).unwrap();
        let readable = timeout(Duration::from_secs(1), tun.readable())
            .await
            .unwrap()
            .unwrap();
        drop(readable);
        let mut read_buffer = [0_u8; 64];
        let mut engine_buffer = [0_u8; 64];

        for marker in 0_u8..8 {
            let frame = [0, 0, 0, marker];
            let event = timeout(
                Duration::from_secs(1),
                wait_tun_fake_dns_io(&tun, Some(&frame), true, &mut read_buffer),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(event, TunFakeDnsIoEvent::Sent(_)));
            assert_eq!(
                read_tun_frame(engine_fd.raw(), &mut engine_buffer).unwrap(),
                Some(frame.len())
            );
            assert_eq!(&engine_buffer[..frame.len()], &frame);
        }
    }

    #[cfg(unix)]
    fn tun_fake_dns_test_response_frame(
        frame: &[u8],
    ) -> Result<(Vec<u8>, TunFakeDnsQueryKey), BenchError> {
        let packet = decode_darwin_utun_frame(frame)?;
        let datagram = parse_ipv4_udp_datagram(packet).ok_or_else(|| {
            BenchError::InvalidArguments("test received malformed TUN DNS packet".to_owned())
        })?;
        let transaction_id = dns_message_id(datagram.payload).ok_or_else(|| {
            BenchError::InvalidArguments("test received DNS query without an id".to_owned())
        })?;
        let query_type = dns_question_type(datagram.payload).ok_or_else(|| {
            BenchError::InvalidArguments("test received DNS query without a type".to_owned())
        })?;
        let mut response = datagram.payload.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        if query_type == DNS_TYPE_A {
            response[6..8].copy_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 19, 0, 1]);
        }
        let response_packet = ipv4_udp_packet(
            datagram.destination,
            datagram.destination_port,
            datagram.source,
            datagram.source_port,
            &response,
        )?;
        Ok((
            encode_darwin_utun_frame(&response_packet),
            TunFakeDnsQueryKey {
                client_port: datagram.source_port,
                transaction_id,
                query_type,
            },
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tun_fake_dns_workload_sends_concurrent_queries_and_demuxes_reordered_responses() {
        let pair = create_tun_socket_pair().unwrap();
        let TunSocketPair {
            engine_fd,
            workload_fd,
        } = pair;
        let responder =
            std::thread::spawn(move || -> Result<Vec<TunFakeDnsQueryKey>, BenchError> {
                let mut buffer = vec![0; 65_535 + DARWIN_UTUN_HEADER_LEN];
                let mut frames = Vec::with_capacity(8);
                while frames.len() < 8 {
                    if let Some(len) = read_tun_frame(engine_fd.raw(), &mut buffer)? {
                        frames.push(buffer[..len].to_vec());
                    }
                }

                let mut keys = Vec::with_capacity(frames.len());
                for frame in frames.into_iter().rev() {
                    let (response, key) = tun_fake_dns_test_response_frame(&frame)?;
                    write_tun_frame(engine_fd.raw(), &response)?;
                    keys.push(key);
                }
                Ok(keys)
            });
        let options = BenchOptions {
            workload: WorkloadKind::TunFakeDns,
            connections: 4,
            iterations: 1,
            ..BenchOptions::default()
        };

        let outcome = timeout(
            Duration::from_secs(2),
            run_tun_fake_dns_workload(workload_fd.raw(), &options),
        )
        .await;
        drop(workload_fd);
        let mut keys = responder.join().unwrap().unwrap();
        let outcome = outcome.unwrap().unwrap();

        keys.sort_by_key(|key| (key.client_port, key.query_type));
        let expected_keys = (0_u16..4)
            .flat_map(|connection_index| {
                let client_port = 53_000_u16 + connection_index;
                [DNS_TYPE_A, DNS_TYPE_HTTPS].map(move |query_type| TunFakeDnsQueryKey {
                    client_port,
                    transaction_id: client_port
                        .wrapping_add(u16::from(query_type == DNS_TYPE_HTTPS)),
                    query_type,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(keys, expected_keys);
        assert_eq!(outcome.latencies_us.len(), 8);
    }

    #[cfg(unix)]
    fn tun_dns_proxy_test_response_frame(
        frame: &[u8],
    ) -> Result<(Vec<u8>, TunFakeDnsQueryKey), BenchError> {
        let packet = decode_darwin_utun_frame(frame)?;
        let datagram = parse_ipv4_udp_datagram(packet).ok_or_else(|| {
            BenchError::InvalidArguments("test received malformed proxied DNS packet".to_owned())
        })?;
        let transaction_id = dns_message_id(datagram.payload).ok_or_else(|| {
            BenchError::InvalidArguments("test received proxied DNS query without an id".to_owned())
        })?;
        let query_type = dns_question_type(datagram.payload).ok_or_else(|| {
            BenchError::InvalidArguments(
                "test received proxied DNS query without a type".to_owned(),
            )
        })?;
        let response = build_dns_proxy_fixture_response(datagram.payload)?;
        let response_packet = ipv4_udp_packet(
            datagram.destination,
            datagram.destination_port,
            datagram.source,
            datagram.source_port,
            &response,
        )?;
        Ok((
            encode_darwin_utun_frame(&response_packet),
            TunFakeDnsQueryKey {
                client_port: datagram.source_port,
                transaction_id,
                query_type,
            },
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tun_dns_proxy_udp_sends_connections_concurrently_and_demuxes_reordered_responses() {
        let TunSocketPair {
            engine_fd,
            workload_fd,
        } = create_tun_socket_pair().unwrap();
        let responder =
            std::thread::spawn(move || -> Result<Vec<TunFakeDnsQueryKey>, BenchError> {
                let mut buffer = vec![0; 65_535 + DARWIN_UTUN_HEADER_LEN];
                let mut frames = Vec::with_capacity(8);
                while frames.len() < 8 {
                    if let Some(len) = read_tun_frame(engine_fd.raw(), &mut buffer)? {
                        frames.push(buffer[..len].to_vec());
                    }
                }

                let mut keys = Vec::with_capacity(frames.len());
                for frame in frames.into_iter().rev() {
                    let (response, key) = tun_dns_proxy_test_response_frame(&frame)?;
                    write_tun_frame(engine_fd.raw(), &response)?;
                    keys.push(key);
                }
                Ok(keys)
            });
        let options = BenchOptions {
            workload: WorkloadKind::TunDnsProxy,
            connections: 4,
            iterations: 1,
            dns_transport: TunDnsTransport::Udp,
            ..BenchOptions::default()
        };

        let outcome = timeout(
            Duration::from_secs(2),
            run_tun_dns_proxy_workload(workload_fd.raw(), &options),
        )
        .await;
        drop(workload_fd);
        let keys = responder.join().unwrap().unwrap();
        let outcome = outcome.unwrap().unwrap();

        assert_eq!(keys.len(), 8);
        assert_eq!(outcome.latencies_us.len(), 8);
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
    fn tun_fake_dns_config_enables_fake_ip_for_xray_rust_only() {
        let fixture = WorkloadFixture::default();
        let config = engine_config(
            EngineKind::XrayRust,
            0,
            WorkloadKind::TunFakeDnsTcp,
            &fixture,
        )
        .unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["protocol"], "tun");
        assert_eq!(value["dns"]["fakeIp"]["enabled"], true);
        assert_eq!(value["dns"]["fakeIp"]["ipv4Pool"], "198.19.0.0/16");
        assert_eq!(value["dns"]["fakeIp"]["poolSize"], 32_768);
        assert_eq!(value["dns"]["fakeIp"]["ttl"], 60);

        let error = engine_config(
            EngineKind::XrayCore,
            0,
            WorkloadKind::TunFakeDnsTcp,
            &fixture,
        )
        .unwrap_err();
        assert!(error.to_string().contains("only --engine xray-rust"));
    }

    #[test]
    fn tun_dns_proxy_config_encodes_selected_upstream_transport_for_xray_rust_only() {
        let fixture = WorkloadFixture {
            vless_addr: None,
            vless_tls_cert_sha256: None,
            dns_server_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 19_053))),
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };
        for (transport, expected) in [
            (TunDnsUpstreamTransport::Classic, "127.0.0.1:19053"),
            (TunDnsUpstreamTransport::TcpRouted, "tcp://127.0.0.1:19053"),
            (
                TunDnsUpstreamTransport::TcpLocal,
                "tcp+local://127.0.0.1:19053",
            ),
        ] {
            let config = engine_config_with_dns_upstream(
                EngineKind::XrayRust,
                0,
                WorkloadKind::TunDnsProxy,
                &fixture,
                transport,
            )
            .unwrap();
            parse_xray_json(&config).unwrap();
            let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

            assert_eq!(value["inbounds"][0]["protocol"], "tun");
            assert_eq!(value["dns"]["servers"][0], expected);
        }
        let error = engine_config(EngineKind::XrayCore, 0, WorkloadKind::TunDnsProxy, &fixture)
            .unwrap_err();
        assert!(error.to_string().contains("only --engine xray-rust"));
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
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        assert!(config.contains(r#""protocol": "vless""#));
        assert!(config.contains(r#""flow": "xtls-rprx-vision""#));
        assert!(config.contains(r#""security": "tls""#));
        assert!(config.contains(
            r#""pinnedPeerCertSha256": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff""#
        ));
        assert!(!config.contains("allowInsecure"));
        assert!(config.contains(r#""port": 19091"#));
    }

    #[test]
    fn process_vision_xudp_config_uses_tls_cert_pin() {
        let fixture = WorkloadFixture {
            vless_addr: Some(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19091))),
            vless_tls_cert_sha256: Some(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
            ),
            dns_server_addr: None,
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };
        let config = engine_config(
            EngineKind::XrayRust,
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
    fn reality_fixture_warmup_from_env_parses_override_or_falls_back_to_default() {
        assert_eq!(
            reality_fixture_warmup_from_env(None),
            REALITY_FIXTURE_WARMUP
        );
        assert_eq!(
            reality_fixture_warmup_from_env(Some("2500")),
            Duration::from_millis(2500)
        );
        assert_eq!(
            reality_fixture_warmup_from_env(Some("garbage")),
            REALITY_FIXTURE_WARMUP
        );
        assert_eq!(
            reality_fixture_warmup_from_env(Some("")),
            REALITY_FIXTURE_WARMUP
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
            dns_server_addr: None,
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
            dns_server_addr: None,
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
    fn reality_vision_bulk_reuses_reality_vision_configs() {
        let fixture = WorkloadFixture {
            vless_addr: Some(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19094))),
            vless_tls_cert_sha256: None,
            dns_server_addr: None,
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };
        let sb =
            sing_box_config(18091, WorkloadKind::RealityVisionBulkThroughput, &fixture).unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&sb).unwrap();
        assert_eq!(value["outbounds"][0]["type"], "vless");

        let xr = engine_config(
            EngineKind::XrayRust,
            18092,
            WorkloadKind::RealityVisionBulkThroughput,
            &fixture,
        )
        .unwrap();
        assert!(xr.contains("xtls-rprx-vision"));
    }

    #[test]
    fn parses_compare_grpc_bulk_throughput() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "grpc-bulk-throughput",
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
        assert_eq!(options.workload, WorkloadKind::GrpcBulkThroughput);
        assert_eq!(options.workload.as_str(), "grpc-bulk-throughput");
    }

    #[test]
    fn grpc_bulk_throughput_dials_vless_over_grpc_on_both_xray_engines() {
        let fixture = WorkloadFixture {
            vless_addr: Some(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19096))),
            vless_tls_cert_sha256: None,
            dns_server_addr: None,
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };

        for engine in [EngineKind::XrayRust, EngineKind::XrayCore] {
            let config = engine_config(engine, 18093, WorkloadKind::GrpcBulkThroughput, &fixture)
                .unwrap_or_else(|error| panic!("{} config: {error}", engine.as_str()));
            let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

            assert_eq!(value["inbounds"][0]["protocol"], "socks");
            assert_eq!(value["inbounds"][0]["settings"]["udp"], false);
            assert_eq!(value["outbounds"][0]["protocol"], "vless");
            assert_eq!(value["outbounds"][0]["settings"]["vnext"][0]["port"], 19096);
            assert_eq!(value["outbounds"][0]["streamSettings"]["network"], "grpc");
            assert_eq!(value["outbounds"][0]["streamSettings"]["security"], "none");
            assert_eq!(
                value["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"],
                GRPC_BENCH_SERVICE_NAME
            );
            // `xtls-rprx-vision` over gRPC is refused by Xray's VLESS outbound
            // (`Xray-core/proxy/vless/outbound/outbound.go:268-285`) and by
            // `validate_connector_flow` on our side, so a flow leaking in from
            // the REALITY configs would break the run rather than slow it. The
            // Xray-side refusal is not a dial failure: the gRPC dial succeeds
            // and the outbound logs `tunneling request to ...`
            // (`outbound.go:209`) before `Process` inspects the conn shape and
            // gives up.
            assert!(value["outbounds"][0]["settings"]["vnext"][0]["users"][0]
                .get("flow")
                .is_none());
        }
    }

    #[test]
    fn grpc_bulk_throughput_sing_box_config_uses_grpc_transport() {
        // `sing_box_config` is not exhaustive: without an explicit arm here a
        // workload that claims sing-box support falls through to the direct
        // config, and `run_compare` would publish a three-engine chart whose
        // sing-box bar never touched the transport under test.
        assert!(WorkloadKind::GrpcBulkThroughput.supports_sing_box_process_engine());

        let fixture = WorkloadFixture {
            vless_addr: Some(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 19097))),
            vless_tls_cert_sha256: None,
            dns_server_addr: None,
            tcp_blackhole_state: None,
            tasks: Vec::new(),
            processes: Vec::new(),
        };
        let config = sing_box_config(18094, WorkloadKind::GrpcBulkThroughput, &fixture).unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["type"], "socks");
        assert_eq!(value["outbounds"][0]["type"], "vless");
        assert_eq!(value["outbounds"][0]["server"], "127.0.0.1");
        assert_eq!(value["outbounds"][0]["server_port"], 19097);
        assert_eq!(value["outbounds"][0]["transport"]["type"], "grpc");
        assert_eq!(
            value["outbounds"][0]["transport"]["service_name"],
            GRPC_BENCH_SERVICE_NAME
        );
        assert_eq!(value["route"]["final"], "proxy");
    }

    #[test]
    fn grpc_bulk_throughput_sing_box_config_needs_the_server_fixture() {
        let error = sing_box_config(
            18095,
            WorkloadKind::GrpcBulkThroughput,
            &WorkloadFixture::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("grpc-bulk-throughput"));
    }

    #[test]
    fn xray_core_grpc_fixture_serves_the_service_name_the_clients_dial() {
        let config = xray_core_grpc_server_config(19098);
        let value = serde_json::from_str::<serde_json::Value>(&config).unwrap();

        assert_eq!(value["inbounds"][0]["protocol"], "vless");
        assert_eq!(value["inbounds"][0]["port"], 19098);
        assert_eq!(value["inbounds"][0]["streamSettings"]["network"], "grpc");
        assert_eq!(value["inbounds"][0]["streamSettings"]["security"], "none");
        assert_eq!(
            value["inbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"],
            GRPC_BENCH_SERVICE_NAME
        );
        assert!(value["inbounds"][0]["settings"]["clients"][0]
            .get("flow")
            .is_none());
        assert_eq!(value["outbounds"][0]["protocol"], "freedom");
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
                phase: BenchmarkPhase::Startup,
            },
            ProcessSample {
                elapsed_ms: 10,
                rss_kib: 150,
                cpu_millis: 25,
                threads: Some(2),
                phase: BenchmarkPhase::Traffic,
            },
        ];
        let summary = summarize_samples(&samples);
        assert_eq!(summary.peak_rss_kib, 150);
        assert_eq!(summary.cpu_millis, 15);
    }

    #[test]
    fn summarizes_memory_by_phase_and_writes_phase_csv_column() {
        let samples = vec![
            ProcessSample {
                elapsed_ms: 0,
                rss_kib: 100,
                cpu_millis: 10,
                threads: Some(2),
                phase: BenchmarkPhase::Opening,
            },
            ProcessSample {
                elapsed_ms: 10,
                rss_kib: 140,
                cpu_millis: 11,
                threads: Some(2),
                phase: BenchmarkPhase::HeldOpen,
            },
            ProcessSample {
                elapsed_ms: 20,
                rss_kib: 160,
                cpu_millis: 12,
                threads: Some(2),
                phase: BenchmarkPhase::HeldOpen,
            },
            ProcessSample {
                elapsed_ms: 30,
                rss_kib: 120,
                cpu_millis: 13,
                threads: Some(2),
                phase: BenchmarkPhase::Settle,
            },
        ];
        let phases = summarize_memory_phases(&samples);
        assert_eq!(
            phases,
            vec![
                PhaseMemorySummary {
                    phase: BenchmarkPhase::Opening,
                    samples: 1,
                    first_rss_kib: 100,
                    median_rss_kib: 100,
                    peak_rss_kib: 100,
                    last_rss_kib: 100,
                },
                PhaseMemorySummary {
                    phase: BenchmarkPhase::HeldOpen,
                    samples: 2,
                    first_rss_kib: 140,
                    median_rss_kib: 160,
                    peak_rss_kib: 160,
                    last_rss_kib: 160,
                },
                PhaseMemorySummary {
                    phase: BenchmarkPhase::Settle,
                    samples: 1,
                    first_rss_kib: 120,
                    median_rss_kib: 120,
                    peak_rss_kib: 120,
                    last_rss_kib: 120,
                },
            ]
        );

        let path = std::env::temp_dir().join(format!(
            "xray-bench-phase-samples-{}.csv",
            std::process::id()
        ));
        write_samples_csv(&path, &samples).unwrap();
        let csv = fs::read_to_string(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert!(csv.starts_with("elapsed_ms,rss_kib,cpu_millis,threads,phase\n"));
        assert!(csv.contains("10,140,11,2,held-open\n"));
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
                dns_candidates: 0,
                cidrs_per_rule: 1,
                domains_per_rule: 0,
                out_dir: PathBuf::from("target/benchmarks/route-probe"),
            })
        );
    }

    #[test]
    fn parses_route_probe_cidrs_per_rule() {
        let args =
            parse_cli_args(["xray-bench", "route-probe", "--cidrs-per-rule", "5000"]).unwrap();

        let CliArgs::RouteProbe(options) = args else {
            panic!("expected route-probe arguments");
        };
        assert_eq!(options.cidrs_per_rule, 5000);

        let error = parse_cli_args(["xray-bench", "route-probe", "--cidrs-per-rule", "0"])
            .expect_err("zero CIDRs per rule must be rejected");
        assert!(matches!(error, BenchError::InvalidArguments(_)));
    }

    #[test]
    fn route_probe_miss_cidrs_never_contain_the_target_and_do_not_touch() {
        let target = IpAddr::V4(ROUTE_PROBE_TARGET_IP);
        let single = route_probe_miss_cidr(3, 0, 1).unwrap();
        assert_eq!(single.network(), IpAddr::V4(Ipv4Addr::new(10, 3, 0, 0)));
        assert_eq!(single.prefix(), 16);
        assert!(!single.matches(&target));

        let mut networks = Vec::new();
        for rule_index in 0..3 {
            for cidr_index in 0..5 {
                let cidr = route_probe_miss_cidr(rule_index, cidr_index, 5).unwrap();
                assert_eq!(cidr.prefix(), 28);
                assert!(!cidr.matches(&target));
                let IpAddr::V4(network) = cidr.network() else {
                    panic!("expected an IPv4 network");
                };
                networks.push(u32::from(network));
            }
        }
        networks.sort_unstable();
        networks.dedup();
        assert_eq!(networks.len(), 15);
        for pair in networks.windows(2) {
            // A /28 spans 16 addresses; a gap of another 16 keeps blocks from merging.
            assert!(pair[1] - pair[0] >= 32);
        }

        let config = route_probe_config(4, 2, 5, 0).unwrap();
        for rule in &config.routing.rules[..3] {
            assert!(!rule.matches_ip(Some(&target)));
            assert_eq!(rule.ip_matchers.range_count(), 5);
            assert!(rule.domain_matchers.is_empty());
        }
        assert!(config.routing.rules[3].matches_ip(Some(&target)));
        assert!(route_probe_config(1 << 15, 2, 17, 0).is_err());
        assert!(route_probe_config(4, 2, 0, 0).is_err());
    }

    #[test]
    fn parses_route_probe_domains_per_rule() {
        let args =
            parse_cli_args(["xray-bench", "route-probe", "--domains-per-rule", "5000"]).unwrap();

        let CliArgs::RouteProbe(options) = args else {
            panic!("expected route-probe arguments");
        };
        assert_eq!(options.domains_per_rule, 5000);

        let zero =
            parse_cli_args(["xray-bench", "route-probe", "--domains-per-rule", "0"]).unwrap();
        let CliArgs::RouteProbe(zero) = zero else {
            panic!("expected route-probe arguments");
        };
        assert_eq!(zero.domains_per_rule, 0);
    }

    #[test]
    fn route_probe_domain_rules_miss_until_the_final_exact_rule() {
        let config = route_probe_config(4, 2, 5, 3).unwrap();
        for (rule_index, rule) in config.routing.rules[..3].iter().enumerate() {
            assert!(rule.ip_matchers.is_empty());
            assert!(!rule.matches_domain(Some(ROUTE_PROBE_DOMAIN)));
            assert!(rule.matches_domain(Some(&format!(
                "host.{}",
                route_probe_miss_domain(rule_index, 2)
            ))));
        }
        let last = &config.routing.rules[3];
        assert!(last.ip_matchers.is_empty());
        assert!(last.matches_domain(Some(ROUTE_PROBE_DOMAIN)));
        assert!(!last.matches_domain(Some("sub.route-probe.invalid")));
        assert!(route_probe_config(1 << 15, 2, 1, 8).is_err());

        let router = OutboundRouter::new(Arc::new(config));
        let target = route_probe_target(true);
        let (selected, _) = measure_direct_route_probe(&router, 3, &target).unwrap();
        assert_eq!(selected, 3);
    }

    #[test]
    fn parses_route_probe_dns_candidates() {
        let args = parse_cli_args(["xray-bench", "route-probe", "--dns-candidates", "8"]).unwrap();

        let CliArgs::RouteProbe(options) = args else {
            panic!("expected route-probe arguments");
        };
        assert_eq!(options.dns_candidates, 8);
    }

    #[test]
    fn parses_dns_policy_probe_command() {
        let args = parse_cli_args([
            "xray-bench",
            "dns-policy-probe",
            "--iterations",
            "500",
            "--servers",
            "8",
            "--matchers",
            "16384",
            "--hosts",
            "50000",
            "--out-dir",
            "target/benchmarks/dns-policy-probe",
        ])
        .unwrap();

        assert_eq!(
            args,
            CliArgs::DnsPolicyProbe(DnsPolicyProbeOptions {
                iterations: 500,
                servers: 8,
                matchers: 16_384,
                hosts: 50_000,
                out_dir: PathBuf::from("target/benchmarks/dns-policy-probe"),
            })
        );
    }

    #[test]
    fn dns_hosts_probe_validates_membership_and_is_skipped_by_default() {
        let metric = measure_dns_hosts_index(1_000, 2).unwrap();
        assert!(metric.hit_matched && metric.miss_rejected);
        assert_eq!(metric.hosts, 1_000);

        let result = measure_dns_policy_probe(&DnsPolicyProbeOptions {
            iterations: 1,
            servers: 1,
            matchers: 1,
            hosts: 0,
            out_dir: PathBuf::from("target/benchmarks/test"),
        })
        .unwrap();
        assert_eq!(result.hosts, None);
        assert!(serde_json::to_string(&result)
            .unwrap()
            .contains("\"hosts\":null"));
    }

    #[test]
    fn dns_policy_probe_exercises_common_and_worst_case_selection() {
        let result = measure_dns_policy_probe(&DnsPolicyProbeOptions {
            iterations: 3,
            servers: 4,
            matchers: 4_096,
            hosts: 0,
            out_dir: PathBuf::from("target/benchmarks/test"),
        })
        .unwrap();

        assert_eq!(
            (
                result.iterations,
                result.servers,
                result.matchers,
                result.common_no_domains.selected_per_iteration,
                result.common_no_domains.compiled_matchers,
                result.worst_case_matchers.selected_per_iteration,
                result.worst_case_matchers.compiled_matchers,
                result.worst_case_ip_filter.hit_matched,
                result.worst_case_ip_filter.miss_rejected,
                result.worst_case_ip_filter.compiled_matchers,
                result.worst_case_ip_filter.compiled_ranges,
            ),
            (3, 4, 4_096, 4, 0, 4, 4_096, true, true, 4_096, 4_096,)
        );
        assert_eq!(result.outbound_common_first_rule.decision, "direct");
        assert_eq!(
            result.outbound_worst_ordered_rule_matchers.decision,
            "return"
        );
        assert_eq!(
            result
                .outbound_selector_prefilter
                .iter()
                .map(|metric| (
                    metric.rules,
                    metric.hit_selected_dns,
                    metric.last_hit_selected_dns,
                    metric.miss_preserved_regular_path,
                    metric.semantic_miss_preserved_regular_path,
                ))
                .collect::<Vec<_>>(),
            vec![
                (0, false, false, true, true),
                (64, true, true, true, true),
                (4_096, true, true, true, true),
            ]
        );
    }

    #[test]
    fn dns_outbound_policy_probe_reuses_server_and_matcher_options() {
        let common = dns_outbound_probe_common_settings(8);
        let worst = dns_outbound_probe_worst_case_settings(8, 16_384);

        assert_eq!(common.rules.len(), 8);
        assert_eq!(worst.rules.len(), 8);
        assert_eq!(
            worst.rules.last().unwrap().domain_matchers.matcher_count(),
            16_384
        );
    }

    #[test]
    fn dns_policy_probe_result_deserializes_without_outbound_metrics() {
        let result = measure_dns_policy_probe(&DnsPolicyProbeOptions {
            iterations: 1,
            servers: 2,
            matchers: 4,
            hosts: 0,
            out_dir: PathBuf::from("target/benchmarks/test"),
        })
        .unwrap();
        let mut value = serde_json::to_value(result).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("outbound_common_first_rule");
        object.remove("outbound_worst_ordered_rule_matchers");
        object.remove("outbound_selector_prefilter");

        let deserialized: DnsPolicyProbeResult = serde_json::from_value(value).unwrap();

        assert_eq!(
            deserialized.outbound_common_first_rule,
            DnsOutboundPolicyProbeMetric::default()
        );
        assert_eq!(
            deserialized.outbound_worst_ordered_rule_matchers,
            DnsOutboundPolicyProbeMetric::default()
        );
        assert!(deserialized.outbound_selector_prefilter.is_empty());
    }

    #[test]
    fn dns_outbound_selector_metric_deserializes_without_linear_path_metrics() {
        let value = serde_json::json!({
            "rules": 64,
            "hit_selected_dns": true,
            "miss_preserved_regular_path": true,
            "compile_us": 10,
            "hit_total_us": 20,
            "hit_avg_ns": 30,
            "miss_total_us": 40,
            "miss_avg_ns": 50
        });

        let metric: DnsOutboundSelectorProbeMetric = serde_json::from_value(value).unwrap();

        assert!(!metric.last_hit_selected_dns);
        assert!(!metric.semantic_miss_preserved_regular_path);
        assert_eq!(metric.last_hit_total_us, 0);
        assert_eq!(metric.last_hit_avg_ns, 0);
        assert_eq!(metric.semantic_miss_total_us, 0);
        assert_eq!(metric.semantic_miss_avg_ns, 0);
    }

    #[test]
    fn dns_policy_probe_rejects_matcher_counts_above_config_budget() {
        let error = measure_dns_policy_probe(&DnsPolicyProbeOptions {
            iterations: 1,
            servers: 1,
            matchers: MAX_CONFIG_DOMAIN_MATCHERS + 1,
            hosts: 0,
            out_dir: PathBuf::from("target/benchmarks/test"),
        })
        .unwrap_err();

        assert!(error.to_string().contains("--matchers must be between"));
    }

    #[test]
    fn dns_ip_filter_probe_indices_cover_large_matcher_sets() {
        let indices = dns_ip_filter_probe_indices(104_729);

        assert_eq!(indices.len(), DNS_IP_FILTER_PROBE_SAMPLES);
        assert!(indices.windows(2).all(|window| window[0] < window[1]));
        assert!(indices.iter().all(|index| *index < 104_729));
    }

    #[test]
    fn direct_route_probe_remains_the_zero_candidate_baseline() {
        let config = Arc::new(route_probe_config(4, 2, 1, 0).unwrap());
        let router = OutboundRouter::new(config);

        let target = route_probe_target(false);
        let (selected, _) = measure_direct_route_probe(&router, 3, &target).unwrap();

        assert_eq!(selected, 3);
    }

    #[tokio::test]
    async fn cached_dns_route_probe_matches_the_final_candidate_from_the_warmed_cache() {
        let mut config = route_probe_config(4, 2, 1, 0).unwrap();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.default_outbound_tag = Some(ROUTE_PROBE_UNMATCHED_TAG.to_owned());
        let router = OutboundRouter::new(Arc::new(config));

        let (selected, _) = measure_cached_dns_route_probe(&router, 3, 4).await.unwrap();

        assert_eq!(selected, 3);
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
            "v26.7.28",
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
        assert_eq!(throughput_mbps(0, 0, 1000, None), None);
        assert_eq!(throughput_mbps(0, 1_073_741_824, 0, None), None);
        assert_eq!(throughput_mbps(0, 1_073_741_824, 2000, None), Some(4295));
        // 500 + 500 bytes over 1000ms = 8000 bits/s = 0.008 Mbps, ceil to 1 Mbps.
        assert_eq!(throughput_mbps(500, 500, 1000, None), Some(1));
    }

    #[test]
    fn throughput_prefers_the_transfer_window_over_the_whole_run_window() {
        let one_gib = 1_073_741_824;
        // 1 GiB moved in 1s, inside a 6s run window: the rate is the transfer rate.
        assert_eq!(
            throughput_mbps(0, one_gib, 6000, Some(Duration::from_secs(1))),
            Some(8590)
        );
        // Without a transfer window the whole run window is the only thing we have.
        assert_eq!(throughput_mbps(0, one_gib, 6000, None), Some(1432));
        // A transfer window shorter than a millisecond is not a measurable rate.
        assert_eq!(
            throughput_mbps(0, one_gib, 6000, Some(Duration::from_micros(500))),
            None
        );
        assert_eq!(
            throughput_mbps(0, 0, 6000, Some(Duration::from_secs(1))),
            None
        );
    }

    #[test]
    fn extending_outcomes_merges_transfer_windows_as_an_interval_union() {
        let base = Instant::now();

        let mut none_then_some = WorkloadOutcome::empty();
        none_then_some.extend(WorkloadOutcome {
            transfer_window: Some((base, base + Duration::from_secs(3))),
            ..WorkloadOutcome::default()
        });
        assert_eq!(
            none_then_some.transfer_window,
            Some((base, base + Duration::from_secs(3)))
        );

        let mut some_then_none = WorkloadOutcome {
            transfer_window: Some((base, base + Duration::from_secs(3))),
            ..WorkloadOutcome::default()
        };
        some_then_none.extend(WorkloadOutcome::empty());
        assert_eq!(
            some_then_none.transfer_window,
            Some((base, base + Duration::from_secs(3)))
        );

        // Overlapping windows: connection A runs [0s, 5s]; connection B starts mid-flight
        // at 2s and runs to 6s. The union [0s, 6s] is wider than either individual span
        // (5s and 4s).
        let mut overlapping = WorkloadOutcome {
            transfer_window: Some((base, base + Duration::from_secs(5))),
            ..WorkloadOutcome::default()
        };
        overlapping.extend(WorkloadOutcome {
            transfer_window: Some((base + Duration::from_secs(2), base + Duration::from_secs(6))),
            ..WorkloadOutcome::default()
        });
        assert_eq!(
            overlapping.transfer_window,
            Some((base, base + Duration::from_secs(6)))
        );

        // Disjoint windows: connection A's clock runs [0s, 2s]; connection B starts its own
        // clock later, at 5s, and runs to 8s. A max-span rule would report
        // max(2s, 3s) = 3s; the correct union span is the full 0..8s range, which exceeds
        // either individual span and which a max-span rule could never produce.
        let mut disjoint = WorkloadOutcome {
            transfer_window: Some((base, base + Duration::from_secs(2))),
            ..WorkloadOutcome::default()
        };
        disjoint.extend(WorkloadOutcome {
            transfer_window: Some((base + Duration::from_secs(5), base + Duration::from_secs(8))),
            ..WorkloadOutcome::default()
        });
        let (start, end) = disjoint.transfer_window.unwrap();
        assert_eq!(start, base);
        assert_eq!(end, base + Duration::from_secs(8));
        let merged_span = end.duration_since(start);
        assert_eq!(merged_span, Duration::from_secs(8));
        assert!(merged_span > Duration::from_secs(2), "exceeds A's own span");
        assert!(merged_span > Duration::from_secs(3), "exceeds B's own span");

        let mut neither = WorkloadOutcome::empty();
        neither.extend(WorkloadOutcome::empty());
        assert_eq!(neither.transfer_window, None);
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
        assert_eq!(result.transfer_duration_ms, None);
        assert_eq!(result.connections, 0);
        assert_eq!(result.dns_transport, None);
        assert_eq!(result.dns_upstream_transport, None);
        assert_eq!(result.run_id, "");
        assert_eq!(result.provenance, BenchProvenance::default());
    }

    #[test]
    fn records_dns_upstream_transport_in_result_and_summary_json() {
        let result = BenchResult {
            run_id: String::new(),
            provenance: BenchProvenance::default(),
            engine: "xray-rust".to_owned(),
            workload: "tun-dns-proxy".to_owned(),
            status: "ok".to_owned(),
            duration_ms: 10,
            transfer_duration_ms: None,
            bytes_sent: 64,
            bytes_received: 80,
            peak_rss_kib: 3000,
            cpu_millis: 2,
            cpu_millis_per_gib: None,
            throughput_mbps: None,
            connections: 1,
            iterations: 1,
            payload_size: 1024,
            stream_transport: None,
            stream_traffic: None,
            xhttp_mode: None,
            xhttp_profile: None,
            xhttp_max_post_bytes: None,
            settle_ms: 0,
            memory_phases: Vec::new(),
            uplink_write_ops: None,
            uplink_write_ops_per_second: None,
            dns_transport: Some("udp".to_owned()),
            dns_upstream_transport: Some("tcp-routed".to_owned()),
            latency_us: None,
            setup_us: None,
            samples: 1,
            blackhole_connections_accepted: None,
            blackhole_connections_active: None,
        };
        let summary = summarize_results(std::slice::from_ref(&result)).unwrap();
        let result_json = serde_json::to_value(&result).unwrap();
        let summary_json = serde_json::to_value(&summary).unwrap();

        assert_eq!(result_json["dns_upstream_transport"], "tcp-routed");
        assert_eq!(summary_json["dns_transport"], "udp");
        assert_eq!(summary_json["dns_upstream_transport"], "tcp-routed");
    }

    #[test]
    fn stream_result_and_summary_preserve_axes_and_write_operation_metric() {
        let first = BenchResult {
            workload: "stream-transport".to_owned(),
            stream_transport: Some("xhttp-h3".to_owned()),
            stream_traffic: Some("packet-up".to_owned()),
            xhttp_mode: Some("packet-up".to_owned()),
            xhttp_profile: Some("legacy-extra-h1-packet-up".to_owned()),
            xhttp_max_post_bytes: Some(500_000),
            settle_ms: 2_000,
            uplink_write_ops: Some(100),
            uplink_write_ops_per_second: Some(2_000),
            ..minimal_bench_result()
        };
        let second = BenchResult {
            uplink_write_ops: Some(120),
            uplink_write_ops_per_second: Some(3_000),
            ..first.clone()
        };

        let summary = summarize_results(&[first, second]).unwrap();
        assert_eq!(summary.stream_transport.as_deref(), Some("xhttp-h3"));
        assert_eq!(summary.stream_traffic.as_deref(), Some("packet-up"));
        assert_eq!(summary.xhttp_mode.as_deref(), Some("packet-up"));
        assert_eq!(
            summary.xhttp_profile.as_deref(),
            Some("legacy-extra-h1-packet-up")
        );
        assert_eq!(summary.xhttp_max_post_bytes, Some(500_000));
        assert_eq!(summary.settle_ms, 2_000);
        assert_eq!(
            summary.uplink_write_ops,
            Some(MetricSummary {
                min: 100,
                median: 110,
                p95: 120,
            })
        );
        assert_eq!(
            summary.uplink_write_ops_per_second,
            Some(MetricSummary {
                min: 2_000,
                median: 2_500,
                p95: 3_000,
            })
        );
    }

    #[test]
    fn packet_write_rate_uses_the_payload_transfer_window() {
        assert_eq!(
            operations_per_second(Some(250), Some(Duration::from_millis(100))),
            Some(2_500)
        );
        assert_eq!(
            operations_per_second(Some(0), Some(Duration::from_secs(1))),
            None
        );
        assert_eq!(operations_per_second(Some(1), None), None);
    }

    #[test]
    fn labels_dns_client_transport_for_each_dns_workload() {
        assert_eq!(
            [
                workload_dns_transport(WorkloadKind::TunFakeDns, TunDnsTransport::Both),
                workload_dns_transport(WorkloadKind::TunFakeDnsTcp, TunDnsTransport::Both),
                workload_dns_transport(WorkloadKind::TunDnsProxy, TunDnsTransport::Both),
                workload_dns_transport(WorkloadKind::TcpFreedom, TunDnsTransport::Both),
            ],
            [Some("udp"), Some("tcp"), Some("both"), None]
        );
    }

    #[test]
    fn summary_preserves_run_provenance() {
        let provenance = BenchProvenance {
            harness_profile: "release".to_owned(),
            workspace_git: Some(WorkspaceGitProvenance {
                revision: "0123456789abcdef".to_owned(),
                dirty: Some(true),
            }),
            engine_source_git: Some(WorkspaceGitProvenance {
                revision: "fedcba9876543210".to_owned(),
                dirty: Some(false),
            }),
            harness_binary_path: Some(PathBuf::from("/tmp/xray-bench")),
            harness_binary_sha256: Some("harness-sha256".to_owned()),
            engine_binary_path: Some(PathBuf::from("/tmp/xray-rust")),
            engine_binary_sha256: Some("engine-sha256".to_owned()),
            working_directory: Some(PathBuf::from("/tmp/workspace")),
            invocation_args: vec![
                "run".to_owned(),
                "--engine".to_owned(),
                "xray-rust".to_owned(),
            ],
        };
        let result = BenchResult {
            run_id: "run-42".to_owned(),
            provenance: provenance.clone(),
            ..minimal_bench_result()
        };

        let summary = summarize_results(&[result]).unwrap();

        assert_eq!(
            (summary.run_id, summary.provenance),
            ("run-42".to_owned(), provenance)
        );
    }

    #[test]
    fn provenance_serializes_binary_sha256_fields() {
        let provenance = BenchProvenance {
            engine_source_git: Some(WorkspaceGitProvenance {
                revision: "4c384271".to_owned(),
                dirty: Some(false),
            }),
            harness_binary_sha256: Some("harness-sha256".to_owned()),
            engine_binary_sha256: Some("engine-sha256".to_owned()),
            ..BenchProvenance::default()
        };

        let json = serde_json::to_value(&provenance).unwrap();

        assert_eq!(json["harness_binary_sha256"], "harness-sha256");
        assert_eq!(json["engine_binary_sha256"], "engine-sha256");
        assert_eq!(json["engine_source_git"]["revision"], "4c384271");
        assert_eq!(json["engine_source_git"]["dirty"], false);
    }

    #[test]
    fn provenance_deserializes_without_binary_sha256_fields() {
        let provenance: BenchProvenance = serde_json::from_str(
            r#"{"harness_profile":"release","harness_binary_path":"/tmp/xray-bench","engine_binary_path":"/tmp/xray-rust"}"#,
        )
        .unwrap();

        assert_eq!(provenance.harness_binary_sha256, None);
        assert_eq!(provenance.engine_binary_sha256, None);
        assert_eq!(provenance.engine_source_git, None);
    }

    #[test]
    fn file_sha256_hashes_streamed_file_contents() {
        let path =
            std::env::temp_dir().join(format!("xray-bench-known-sha256-{}", std::process::id()));
        fs::write(&path, b"abc").unwrap();

        let sha256 = file_sha256(&path);
        fs::remove_file(path).unwrap();

        assert_eq!(
            sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn file_sha256_returns_none_when_file_cannot_be_opened() {
        let path =
            std::env::temp_dir().join(format!("xray-bench-missing-sha256-{}", std::process::id()));
        let _ = fs::remove_file(&path);

        assert_eq!(file_sha256(&path), None);
    }

    #[test]
    fn canonical_invocation_replays_effective_options_without_shell_parsing() {
        let engine_binary = PathBuf::from("/tmp/bin with spaces/xray-rust");
        let options = BenchOptions {
            workload: WorkloadKind::TunDnsProxy,
            duration: Duration::from_millis(1_234),
            sample_interval: Duration::from_millis(17),
            run_timeout: Duration::from_millis(98_765),
            connections: 32,
            iterations: 777,
            payload_size: 4_096,
            dns_transport: TunDnsTransport::Tcp,
            dns_upstream_transport: TunDnsUpstreamTransport::TcpRouted,
            runs: 5,
            out_dir: PathBuf::from("/tmp/results with spaces"),
            xray_core_bin: Some(PathBuf::from("/tmp/xray core")),
            xray_core_dir: Some(PathBuf::from("/tmp/xray core source")),
            sing_box_bin: Some(PathBuf::from("/tmp/sing box")),
            sing_box_dir: Some(PathBuf::from("/tmp/sing box source")),
            tun_profile: Some("mobile".to_owned()),
            no_auto_build: true,
            geodata_dir: Some(PathBuf::from("/tmp/geo data")),
            ..BenchOptions::default()
        };
        let invocation =
            canonical_run_invocation_args(EngineKind::XrayRust, &options, &engine_binary);
        let parsed =
            parse_cli_args(std::iter::once("xray-bench".to_owned()).chain(invocation)).unwrap();
        let CliArgs::Run(replayed) = parsed else {
            panic!("canonical process invocation must parse as `run`");
        };
        let mut expected = options;
        expected.engine = Some(EngineKind::XrayRust);
        expected.xray_rust_bin = Some(engine_binary);

        assert_eq!(replayed, expected);
    }

    #[test]
    fn canonical_invocation_records_xhttp_h3_axes() {
        let engine_binary = PathBuf::from("/tmp/xray-rust");
        let options = BenchOptions {
            workload: WorkloadKind::StreamTransport,
            stream_transport: Some(StreamBenchTransport::XhttpHttp3),
            stream_traffic: Some(StreamBenchTraffic::PacketUp),
            xhttp_mode: Some(StreamBenchXhttpMode::PacketUp),
            connections: 32,
            iterations: 400,
            payload_size: 16_384,
            ..BenchOptions::default()
        };

        let invocation =
            canonical_run_invocation_args(EngineKind::XrayRust, &options, &engine_binary);
        let parsed =
            parse_cli_args(std::iter::once("xray-bench".to_owned()).chain(invocation)).unwrap();
        let CliArgs::Run(replayed) = parsed else {
            panic!("canonical stream invocation must parse as `run`");
        };

        assert_eq!(replayed.stream_transport, options.stream_transport);
        assert_eq!(replayed.stream_traffic, options.stream_traffic);
        assert_eq!(replayed.xhttp_mode, options.xhttp_mode);
        assert_eq!((replayed.connections, replayed.iterations), (32, 400));
    }

    #[test]
    fn canonical_invocation_records_legacy_xhttp_memory_axes() {
        let options = BenchOptions {
            workload: WorkloadKind::StreamTransport,
            stream_traffic: Some(StreamBenchTraffic::HeldOpen),
            xhttp_profile: Some(StreamBenchXhttpProfile::LegacyExtraH1PacketUp),
            xhttp_max_post_bytes: Some(500_000),
            settle: Duration::from_millis(5_000),
            ..BenchOptions::default()
        };
        let invocation = canonical_run_invocation_args(
            EngineKind::XrayRust,
            &options,
            Path::new("/tmp/xray-rust"),
        );
        let parsed =
            parse_cli_args(std::iter::once("xray-bench".to_owned()).chain(invocation)).unwrap();
        let CliArgs::Run(replayed) = parsed else {
            panic!("canonical stream invocation must parse as `run`");
        };

        let scenario = replayed.stream_scenario().unwrap();
        assert_eq!(scenario.transport, StreamBenchTransport::XhttpHttp1);
        assert_eq!(scenario.traffic, StreamBenchTraffic::HeldOpen);
        assert_eq!(scenario.xhttp_profile, options.xhttp_profile);
        assert_eq!(replayed.xhttp_max_post_bytes, Some(500_000));
        assert_eq!(replayed.settle, Duration::from_millis(5_000));
    }

    #[test]
    fn formatted_provenance_identifies_the_measured_binary_and_source() {
        let provenance = BenchProvenance {
            harness_profile: "release".to_owned(),
            workspace_git: Some(WorkspaceGitProvenance {
                revision: "abc123".to_owned(),
                dirty: Some(false),
            }),
            engine_source_git: Some(WorkspaceGitProvenance {
                revision: "def456".to_owned(),
                dirty: Some(true),
            }),
            harness_binary_sha256: Some("harness-sha256".to_owned()),
            engine_binary_path: Some(PathBuf::from("/tmp/xray-rust")),
            engine_binary_sha256: Some("engine-sha256".to_owned()),
            ..BenchProvenance::default()
        };

        assert_eq!(
            format_benchmark_provenance("run-42", &provenance),
            " run_id=run-42 harness_profile=release workspace_git_revision=abc123 workspace_git_dirty=false engine_source_git_revision=def456 engine_source_git_dirty=true harness_binary_sha256=harness-sha256 engine_binary_path=/tmp/xray-rust engine_binary_sha256=engine-sha256"
        );
    }

    #[test]
    fn summarizes_repeated_results_with_min_median_and_p95() {
        let results = vec![
            BenchResult {
                run_id: String::new(),
                provenance: BenchProvenance::default(),
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
                transfer_duration_ms: Some(30),
                connections: 1,
                iterations: 10,
                payload_size: 4096,
                stream_transport: None,
                stream_traffic: None,
                xhttp_mode: None,
                xhttp_profile: None,
                xhttp_max_post_bytes: None,
                settle_ms: 0,
                memory_phases: Vec::new(),
                uplink_write_ops: None,
                uplink_write_ops_per_second: None,
                dns_transport: None,
                dns_upstream_transport: None,
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
                run_id: String::new(),
                provenance: BenchProvenance::default(),
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
                transfer_duration_ms: Some(8),
                connections: 1,
                iterations: 10,
                payload_size: 4096,
                stream_transport: None,
                stream_traffic: None,
                xhttp_mode: None,
                xhttp_profile: None,
                xhttp_max_post_bytes: None,
                settle_ms: 0,
                memory_phases: Vec::new(),
                uplink_write_ops: None,
                uplink_write_ops_per_second: None,
                dns_transport: None,
                dns_upstream_transport: None,
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
                run_id: String::new(),
                provenance: BenchProvenance::default(),
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
                transfer_duration_ms: None,
                connections: 1,
                iterations: 10,
                payload_size: 4096,
                stream_transport: None,
                stream_traffic: None,
                xhttp_mode: None,
                xhttp_profile: None,
                xhttp_max_post_bytes: None,
                settle_ms: 0,
                memory_phases: Vec::new(),
                uplink_write_ops: None,
                uplink_write_ops_per_second: None,
                dns_transport: None,
                dns_upstream_transport: None,
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
        // Runs without a transfer window are skipped, like every other optional metric.
        assert_eq!(
            summary.transfer_duration_ms,
            Some(MetricSummary {
                min: 8,
                median: 19,
                p95: 30,
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
        assert_eq!(summary.dns_transport, None);
        assert_eq!(summary.transfer_duration_ms, None);
        assert_eq!(summary.dns_upstream_transport, None);
        assert_eq!(summary.run_id, "");
        assert_eq!(summary.provenance, BenchProvenance::default());
    }

    #[test]
    fn deserializes_summary_json_without_throughput_field() {
        // Mirrors deserializes_result_json_without_throughput_field: BenchSummary is what
        // the chart command consumes, and the publishing recipe explicitly mixes run
        // groups written by different harness vintages, so a summary.json predating
        // transfer_duration_ms and throughput_mbps must still parse.
        let raw = r#"{
            "engine": "xray-rust",
            "workload": "tcp-freedom",
            "status": "ok",
            "runs": 5,
            "duration_ms": { "min": 1, "median": 2, "p95": 3 },
            "peak_rss_kib": { "min": 1, "median": 2, "p95": 3 },
            "cpu_millis": { "min": 1, "median": 2, "p95": 3 },
            "cpu_millis_per_gib": null,
            "latency_us": null,
            "setup_us": null,
            "bytes_sent": { "min": 1, "median": 2, "p95": 3 },
            "bytes_received": { "min": 1, "median": 2, "p95": 3 },
            "results": []
        }"#;
        let summary: BenchSummary = serde_json::from_str(raw).unwrap();
        assert_eq!(summary.throughput_mbps, None);
        assert_eq!(summary.transfer_duration_ms, None);
        assert_eq!(summary.connections, 0);
        assert_eq!(summary.iterations, 0);
        assert_eq!(summary.payload_size, 0);
        assert_eq!(summary.dns_transport, None);
        assert_eq!(summary.dns_upstream_transport, None);
    }

    #[test]
    fn summarize_rejects_mixed_workload_parameters() {
        let first = BenchResult {
            run_id: String::new(),
            provenance: BenchProvenance::default(),
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
            transfer_duration_ms: None,
            connections: 100,
            iterations: 1,
            payload_size: 512,
            stream_transport: None,
            stream_traffic: None,
            xhttp_mode: None,
            xhttp_profile: None,
            xhttp_max_post_bytes: None,
            settle_ms: 0,
            memory_phases: Vec::new(),
            uplink_write_ops: None,
            uplink_write_ops_per_second: None,
            dns_transport: None,
            dns_upstream_transport: None,
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
    fn summarize_rejects_mixed_run_provenance() {
        let first = BenchResult {
            run_id: "run-42".to_owned(),
            provenance: BenchProvenance {
                harness_profile: "release".to_owned(),
                ..BenchProvenance::default()
            },
            ..minimal_bench_result()
        };
        let mut second = first.clone();
        second.provenance.harness_profile = "debug".to_owned();

        let error = summarize_results(&[first, second]).unwrap_err();

        assert!(error
            .to_string()
            .contains("cannot summarize mixed benchmark provenance"));
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

        let transfer = read_and_validate_bulk_stream(&mut reader, &template, 3)
            .await
            .unwrap();

        assert_eq!(transfer.bytes, 3 * 1024);
        write_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bulk_transfer_window_starts_at_the_first_byte() {
        let template = bulk_pattern_template(1024);
        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let stream = template.repeat(2);
        // A tunnel that answers the SOCKS request first and only then completes its handshake
        // delivers nothing for a while: that wait is setup latency, not a slow transfer.
        let write_task = tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            writer.write_all(&stream).await
        });

        let call_started = Instant::now();
        let transfer = read_and_validate_bulk_stream(&mut reader, &template, 2)
            .await
            .unwrap();
        let whole_call = call_started.elapsed();

        assert_eq!(transfer.bytes, 2 * 1024);
        let (window_start, window_end) =
            transfer.window.expect("bytes moved, so there is a window");
        let window = window_end.duration_since(window_start);
        assert!(whole_call >= Duration::from_millis(300));
        assert!(
            window < Duration::from_millis(150),
            "transfer window {window:?} must exclude the 300ms wait before the first byte \
             (whole call {whole_call:?})"
        );
        write_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bulk_transfer_reports_no_window_when_no_bytes_move() {
        let template = bulk_pattern_template(1024);
        let (_writer, mut reader) = tokio::io::duplex(64 * 1024);

        let transfer = read_and_validate_bulk_stream(&mut reader, &template, 0)
            .await
            .unwrap();

        assert_eq!(transfer.bytes, 0);
        assert_eq!(transfer.window, None);
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
