use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use super::{
    allocate_loopback_port, bulk_pattern_template, ensure_xray_core_binary, hex_lower,
    socks5_connect_measured, wait_for_process_log_contains, BenchError, BenchOptions, EngineKind,
    FixtureProcess, FlowSetupSample, WorkloadFixture, WorkloadOutcome,
};

const BENCH_SERVER_NAME: &str = "vless.test";
const BENCH_PATH: &str = "/bench";
const BENCH_GRPC_SERVICE: &str = "bench";
const READY_BYTE: u8 = 0x52;
const COMPLETE_BYTE: u8 = 0x43;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamBenchTransport {
    WebSocket,
    HttpUpgrade,
    Grpc,
    XhttpHttp1,
    XhttpHttp2,
    XhttpHttp3,
}

impl StreamBenchTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebSocket => "ws",
            Self::HttpUpgrade => "httpupgrade",
            Self::Grpc => "grpc",
            Self::XhttpHttp1 => "xhttp-h1",
            Self::XhttpHttp2 => "xhttp-h2",
            Self::XhttpHttp3 => "xhttp-h3",
        }
    }

    pub(crate) fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "ws" | "websocket" => Ok(Self::WebSocket),
            "httpupgrade" => Ok(Self::HttpUpgrade),
            "grpc" => Ok(Self::Grpc),
            "xhttp-h1" | "xhttp-http1" => Ok(Self::XhttpHttp1),
            "xhttp-h2" | "xhttp-http2" => Ok(Self::XhttpHttp2),
            "xhttp-h3" | "xhttp-http3" => Ok(Self::XhttpHttp3),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported stream transport `{other}`; expected ws|httpupgrade|grpc|xhttp-h1|xhttp-h2|xhttp-h3"
            ))),
        }
    }

    pub fn is_xhttp(self) -> bool {
        matches!(self, Self::XhttpHttp1 | Self::XhttpHttp2 | Self::XhttpHttp3)
    }

    pub fn supports_sing_box(self) -> bool {
        matches!(self, Self::WebSocket | Self::HttpUpgrade | Self::Grpc)
    }

    fn alpn(self) -> &'static str {
        match self {
            Self::Grpc | Self::XhttpHttp2 => "h2",
            Self::XhttpHttp3 => "h3",
            Self::WebSocket | Self::HttpUpgrade | Self::XhttpHttp1 => "http/1.1",
        }
    }

    fn xray_network(self) -> &'static str {
        match self {
            Self::WebSocket => "ws",
            Self::HttpUpgrade => "httpupgrade",
            Self::Grpc => "grpc",
            Self::XhttpHttp1 | Self::XhttpHttp2 | Self::XhttpHttp3 => "xhttp",
        }
    }

    fn fixture_startup(self) -> FixtureStartup {
        // Xray's exact `alpn: ["h3"]` branch binds QUIC on UDP, so its port
        // reservation and readiness path must not rely on a TCP connection.
        if self == Self::XhttpHttp3 {
            FixtureStartup::UdpProcessLog("started")
        } else {
            FixtureStartup::TcpProcessLog("started")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureStartup {
    TcpProcessLog(&'static str),
    UdpProcessLog(&'static str),
}

impl FixtureStartup {
    fn allocate_port(self) -> Result<u16, BenchError> {
        match self {
            Self::TcpProcessLog(_) => allocate_loopback_port(),
            Self::UdpProcessLog(_) => allocate_loopback_udp_port(),
        }
    }

    fn readiness_log(self) -> &'static str {
        match self {
            Self::TcpProcessLog(pattern) | Self::UdpProcessLog(pattern) => pattern,
        }
    }
}

fn allocate_loopback_udp_port() -> Result<u16, BenchError> {
    let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|source| BenchError::Io {
        action: "binding ephemeral UDP loopback port".to_owned(),
        source,
    })?;
    Ok(socket
        .local_addr()
        .map_err(|source| BenchError::Io {
            action: "reading ephemeral UDP loopback port".to_owned(),
            source,
        })?
        .port())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamBenchTraffic {
    Upload,
    Download,
    FullDuplex,
    PacketUp,
}

impl StreamBenchTraffic {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::FullDuplex => "full-duplex",
            Self::PacketUp => "packet-up",
        }
    }

    pub(crate) fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "upload" => Ok(Self::Upload),
            "download" => Ok(Self::Download),
            "full-duplex" | "duplex" => Ok(Self::FullDuplex),
            "packet-up" => Ok(Self::PacketUp),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported stream traffic `{other}`; expected upload|download|full-duplex|packet-up"
            ))),
        }
    }

    fn has_uplink(self) -> bool {
        matches!(self, Self::Upload | Self::FullDuplex | Self::PacketUp)
    }

    fn has_downlink(self) -> bool {
        matches!(self, Self::Download | Self::FullDuplex)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamBenchXhttpMode {
    PacketUp,
    StreamUp,
    StreamOne,
}

impl StreamBenchXhttpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PacketUp => "packet-up",
            Self::StreamUp => "stream-up",
            Self::StreamOne => "stream-one",
        }
    }

    pub(crate) fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "packet-up" => Ok(Self::PacketUp),
            "stream-up" => Ok(Self::StreamUp),
            "stream-one" => Ok(Self::StreamOne),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported XHTTP mode `{other}`; expected packet-up|stream-up|stream-one"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamBenchScenario {
    pub transport: StreamBenchTransport,
    pub traffic: StreamBenchTraffic,
    pub xhttp_mode: Option<StreamBenchXhttpMode>,
}

impl StreamBenchScenario {
    pub(crate) fn resolve(
        transport: Option<StreamBenchTransport>,
        traffic: Option<StreamBenchTraffic>,
        xhttp_mode: Option<StreamBenchXhttpMode>,
    ) -> Result<Self, BenchError> {
        let transport = transport.ok_or_else(|| {
            BenchError::InvalidArguments(
                "stream-transport workload requires --stream-transport".to_owned(),
            )
        })?;
        let traffic = traffic.ok_or_else(|| {
            BenchError::InvalidArguments("stream-transport workload requires --traffic".to_owned())
        })?;
        let xhttp_mode = if transport.is_xhttp() {
            Some(xhttp_mode.unwrap_or(StreamBenchXhttpMode::PacketUp))
        } else if xhttp_mode.is_some() {
            return Err(BenchError::InvalidArguments(
                "--xhttp-mode is valid only with xhttp-h1, xhttp-h2, or xhttp-h3".to_owned(),
            ));
        } else {
            None
        };
        if traffic == StreamBenchTraffic::PacketUp
            && (xhttp_mode != Some(StreamBenchXhttpMode::PacketUp) || !transport.is_xhttp())
        {
            return Err(BenchError::InvalidArguments(
                "--traffic packet-up requires an XHTTP transport in packet-up mode".to_owned(),
            ));
        }
        Ok(Self {
            transport,
            traffic,
            xhttp_mode,
        })
    }

    pub(crate) fn validate_payload_size(self, payload_size: usize) -> Result<(), BenchError> {
        if self.transport.is_xhttp() && i32::try_from(payload_size).is_err() {
            return Err(BenchError::InvalidArguments(
                "XHTTP benchmark payload size must fit signed 32-bit scMaxEachPostBytes".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn supports_engine(self, engine: EngineKind) -> bool {
        engine != EngineKind::SingBox || self.transport.supports_sing_box()
    }
}

pub(super) struct StreamTransportFixture {
    pub addr: SocketAddr,
    pub cert_sha256: String,
    pub process: FixtureProcess,
}

pub(super) async fn start_fixture(
    options: &BenchOptions,
    scenario: StreamBenchScenario,
    run_dir: &Path,
    binary_dir: &Path,
) -> Result<StreamTransportFixture, BenchError> {
    scenario.validate_payload_size(options.payload_size)?;
    let fixture_dir = run_dir
        .join("fixture")
        .join(format!("{}-server", scenario.transport.as_str()));
    fs::create_dir_all(&fixture_dir).map_err(|source| BenchError::Io {
        action: format!("creating fixture directory `{}`", fixture_dir.display()),
        source,
    })?;

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![BENCH_SERVER_NAME.to_owned()]).map_err(|error| {
            BenchError::InvalidArguments(format!(
                "generating stream-transport TLS certificate: {error}"
            ))
        })?;
    let cert_sha256 = hex_lower(&Sha256::digest(cert.der().as_ref()));
    let key_der = signing_key.serialize_der();
    let cert_path = fixture_dir.join("certificate.pem");
    let key_path = fixture_dir.join("private-key.pem");
    fs::write(&cert_path, pem_block("CERTIFICATE", cert.der().as_ref())).map_err(|source| {
        BenchError::Io {
            action: format!("writing fixture certificate `{}`", cert_path.display()),
            source,
        }
    })?;
    fs::write(&key_path, pem_block("PRIVATE KEY", &key_der)).map_err(|source| BenchError::Io {
        action: format!("writing fixture private key `{}`", key_path.display()),
        source,
    })?;
    let cert_path = fs::canonicalize(&cert_path).map_err(|source| BenchError::Io {
        action: format!(
            "canonicalizing fixture certificate `{}`",
            cert_path.display()
        ),
        source,
    })?;
    let key_path = fs::canonicalize(&key_path).map_err(|source| BenchError::Io {
        action: format!(
            "canonicalizing fixture private key `{}`",
            key_path.display()
        ),
        source,
    })?;

    let fixture_startup = scenario.transport.fixture_startup();
    let port = fixture_startup.allocate_port()?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let config = xray_server_config(port, scenario, options.payload_size, &cert_path, &key_path)?;
    let config_path = fixture_dir.join("config.json");
    fs::write(&config_path, config).map_err(|source| BenchError::Io {
        action: format!("writing fixture config `{}`", config_path.display()),
        source,
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
    let binary = ensure_xray_core_binary(options, &binary_dir.join("xray-core-fixture"))?;
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
        fixture_startup.readiness_log(),
        std::time::Duration::from_secs(10),
    )
    .await?;

    Ok(StreamTransportFixture {
        addr,
        cert_sha256,
        process: FixtureProcess { child },
    })
}

pub(super) fn engine_config(
    engine: EngineKind,
    port: u16,
    options: &BenchOptions,
    scenario: StreamBenchScenario,
    fixture: &WorkloadFixture,
) -> Result<String, BenchError> {
    scenario.validate_payload_size(options.payload_size)?;
    if !scenario.supports_engine(engine) {
        return Err(BenchError::InvalidArguments(format!(
            "sing-box does not support the {} stream transport",
            scenario.transport.as_str()
        )));
    }
    let vless_addr = fixture.vless_addr.ok_or_else(|| {
        BenchError::InvalidArguments(
            "stream-transport workload requires a VLESS server fixture".to_owned(),
        )
    })?;
    let cert_sha256 = fixture.vless_tls_cert_sha256.as_deref().ok_or_else(|| {
        BenchError::InvalidArguments(
            "stream-transport workload requires a TLS certificate pin".to_owned(),
        )
    })?;

    match engine {
        EngineKind::XrayRust | EngineKind::XrayCore => xray_client_config(
            engine,
            port,
            vless_addr,
            cert_sha256,
            scenario,
            options.payload_size,
        ),
        EngineKind::SingBox => sing_box_client_config(port, vless_addr, scenario),
    }
}

pub(super) async fn run_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
    scenario: StreamBenchScenario,
) -> Result<WorkloadOutcome, BenchError> {
    scenario.validate_payload_size(options.payload_size)?;
    let template = Arc::new(bulk_pattern_template(options.payload_size));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding stream-transport target server".to_owned(),
            source,
        })?;
    let target_addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading stream-transport target server address".to_owned(),
        source,
    })?;
    let server_template = Arc::clone(&template);
    let connections = options.connections;
    let iterations = options.iterations;
    let traffic = scenario.traffic;
    let server_task = tokio::spawn(async move {
        run_target_server(listener, traffic, server_template, iterations, connections).await
    });

    let mut clients = JoinSet::new();
    for _ in 0..options.connections {
        let template = Arc::clone(&template);
        clients.spawn(run_client_flow(
            socks_addr,
            target_addr,
            traffic,
            template,
            options.iterations,
        ));
    }

    let mut outcome = WorkloadOutcome::empty();
    while let Some(result) = clients.join_next().await {
        match result {
            Ok(Ok(flow)) => outcome.extend(flow),
            Ok(Err(error)) => {
                server_task.abort();
                return Err(error);
            }
            Err(error) => {
                server_task.abort();
                return Err(BenchError::InvalidArguments(format!(
                    "stream-transport workload task failed: {error}"
                )));
            }
        }
    }
    server_task.await.map_err(|error| {
        BenchError::InvalidArguments(format!("stream-transport target task failed: {error}"))
    })??;
    Ok(outcome)
}

async fn run_target_server(
    listener: TcpListener,
    traffic: StreamBenchTraffic,
    template: Arc<Vec<u8>>,
    iterations: usize,
    connections: usize,
) -> Result<(), BenchError> {
    let mut workers = JoinSet::new();
    for _ in 0..connections {
        let (stream, _) = listener.accept().await.map_err(|source| BenchError::Io {
            action: "accepting stream-transport target connection".to_owned(),
            source,
        })?;
        let template = Arc::clone(&template);
        workers.spawn(async move { run_target_flow(stream, traffic, &template, iterations).await });
    }
    while let Some(result) = workers.join_next().await {
        result.map_err(|error| {
            BenchError::InvalidArguments(format!("stream-transport target flow failed: {error}"))
        })??;
    }
    Ok(())
}

async fn run_target_flow(
    mut stream: TcpStream,
    traffic: StreamBenchTraffic,
    template: &[u8],
    iterations: usize,
) -> Result<(), BenchError> {
    stream
        .write_all(&[READY_BYTE])
        .await
        .map_err(|source| BenchError::Io {
            action: "writing stream-transport ready marker".to_owned(),
            source,
        })?;
    match traffic {
        StreamBenchTraffic::Upload | StreamBenchTraffic::PacketUp => {
            read_pattern(
                &mut stream,
                template,
                iterations,
                "reading benchmark upload",
            )
            .await?;
            stream
                .write_all(&[COMPLETE_BYTE])
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing stream-transport completion marker".to_owned(),
                    source,
                })?;
        }
        StreamBenchTraffic::Download => {
            write_pattern(
                &mut stream,
                template,
                iterations,
                "writing benchmark download",
            )
            .await?;
        }
        StreamBenchTraffic::FullDuplex => {
            let (mut reader, mut writer) = stream.split();
            tokio::try_join!(
                read_pattern(
                    &mut reader,
                    template,
                    iterations,
                    "reading benchmark duplex upload"
                ),
                write_pattern(
                    &mut writer,
                    template,
                    iterations,
                    "writing benchmark duplex download"
                )
            )?;
            writer
                .write_all(&[COMPLETE_BYTE])
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing stream-transport duplex completion marker".to_owned(),
                    source,
                })?;
        }
    }
    stream.shutdown().await.map_err(|source| BenchError::Io {
        action: "shutting down stream-transport target".to_owned(),
        source,
    })
}

async fn run_client_flow(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    traffic: StreamBenchTraffic,
    template: Arc<Vec<u8>>,
    iterations: usize,
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
    let socks = socks5_connect_measured(&mut client, target_addr).await?;
    let mut ready = [0_u8; 1];
    client
        .read_exact(&mut ready)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading stream-transport ready marker".to_owned(),
            source,
        })?;
    if ready[0] != READY_BYTE {
        return Err(BenchError::InvalidArguments(
            "invalid stream-transport ready marker".to_owned(),
        ));
    }
    // Several engines acknowledge SOCKS before the transport handshake and
    // remote VLESS CONNECT have finished. Preserve the SOCKS-stage fields,
    // but make `total_us` the first end-to-end readiness point so lazy dialing
    // cannot disappear between setup and the payload-only transfer window.
    let setup_sample = FlowSetupSample {
        tcp_connect_us,
        socks_method_us: socks.method_us,
        socks_connect_us: socks.connect_us,
        socks_setup_us: socks.total_us,
        total_us: setup_started.elapsed().as_micros(),
    };

    let started = Instant::now();
    let bytes_per_direction = checked_payload_bytes(template.len(), iterations)?;
    match traffic {
        StreamBenchTraffic::Upload | StreamBenchTraffic::PacketUp => {
            run_client_upload(&mut client, &template, iterations).await?;
        }
        StreamBenchTraffic::Download => {
            read_pattern(
                &mut client,
                &template,
                iterations,
                "reading benchmark download",
            )
            .await?;
        }
        StreamBenchTraffic::FullDuplex => {
            let (mut reader, mut writer) = client.into_split();
            run_client_full_duplex(&mut reader, &mut writer, &template, iterations).await?;
        }
    }
    let ended = Instant::now();
    Ok(WorkloadOutcome {
        bytes_sent: if traffic.has_uplink() {
            bytes_per_direction
        } else {
            0
        },
        bytes_received: if traffic.has_downlink() {
            bytes_per_direction
        } else {
            0
        },
        setup_samples: vec![setup_sample],
        transfer_window: Some((started, ended)),
        uplink_write_ops: (traffic == StreamBenchTraffic::PacketUp).then_some(iterations as u64),
        ..WorkloadOutcome::default()
    })
}

async fn run_client_upload<S>(
    client: &mut S,
    template: &[u8],
    iterations: usize,
) -> Result<(), BenchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_pattern(
        &mut *client,
        template,
        iterations,
        "writing benchmark upload",
    )
    .await?;
    // The target knows the exact payload length. A write-side shutdown is not
    // a portable half-close: framed transports such as WebSocket can close the
    // whole session and discard the completion marker.
    read_completion_marker(client).await
}

async fn run_client_full_duplex<R, W>(
    reader: &mut R,
    writer: &mut W,
    template: &[u8],
    iterations: usize,
) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::try_join!(
        async {
            read_pattern(
                reader,
                template,
                iterations,
                "reading benchmark duplex download",
            )
            .await?;
            read_completion_marker(reader).await
        },
        async {
            write_pattern(
                writer,
                template,
                iterations,
                "writing benchmark duplex upload",
            )
            .await?;
            // Keep the transport open until the read side receives the target's
            // marker; dropping both halves afterwards performs final cleanup.
            Ok::<(), BenchError>(())
        }
    )?;
    Ok(())
}

async fn read_completion_marker<R>(reader: &mut R) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
{
    let mut marker = [0_u8; 1];
    reader
        .read_exact(&mut marker)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading stream-transport completion marker".to_owned(),
            source,
        })?;
    if marker[0] != COMPLETE_BYTE {
        return Err(BenchError::InvalidArguments(
            "invalid stream-transport completion marker".to_owned(),
        ));
    }
    Ok(())
}

async fn read_pattern<R>(
    reader: &mut R,
    template: &[u8],
    iterations: usize,
    action: &'static str,
) -> Result<u64, BenchError>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = vec![0_u8; template.len()];
    let mut bytes = 0_u64;
    for _ in 0..iterations {
        reader
            .read_exact(&mut chunk)
            .await
            .map_err(|source| BenchError::Io {
                action: action.to_owned(),
                source,
            })?;
        if chunk != template {
            return Err(BenchError::InvalidArguments(
                "stream-transport payload mismatch".to_owned(),
            ));
        }
        bytes = bytes.saturating_add(chunk.len() as u64);
    }
    Ok(bytes)
}

async fn write_pattern<W>(
    writer: &mut W,
    template: &[u8],
    iterations: usize,
    action: &'static str,
) -> Result<u64, BenchError>
where
    W: AsyncWrite + Unpin,
{
    let mut bytes = 0_u64;
    for _ in 0..iterations {
        writer
            .write_all(template)
            .await
            .map_err(|source| BenchError::Io {
                action: action.to_owned(),
                source,
            })?;
        bytes = bytes.saturating_add(template.len() as u64);
    }
    Ok(bytes)
}

fn checked_payload_bytes(payload_size: usize, iterations: usize) -> Result<u64, BenchError> {
    payload_size
        .checked_mul(iterations)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| {
            BenchError::InvalidArguments("stream-transport bytes per flow overflow u64".to_owned())
        })
}

fn xray_client_config(
    engine: EngineKind,
    port: u16,
    vless_addr: SocketAddr,
    cert_sha256: &str,
    scenario: StreamBenchScenario,
    payload_size: usize,
) -> Result<String, BenchError> {
    let tls_settings = match engine {
        EngineKind::XrayRust => json!({
            "serverName": BENCH_SERVER_NAME,
            "allowInsecure": true,
            "fingerprint": "chrome",
            "alpn": [scenario.transport.alpn()]
        }),
        EngineKind::XrayCore => json!({
            "serverName": BENCH_SERVER_NAME,
            "pinnedPeerCertSha256": cert_sha256,
            "fingerprint": "chrome",
            "alpn": [scenario.transport.alpn()]
        }),
        EngineKind::SingBox => {
            return Err(BenchError::InvalidArguments(
                "internal error: Xray config requested for sing-box".to_owned(),
            ))
        }
    };
    let mut stream_settings = json!({
        "network": scenario.transport.xray_network(),
        "security": "tls",
        "tlsSettings": tls_settings
    });
    if engine == EngineKind::XrayRust && scenario.transport == StreamBenchTransport::XhttpHttp3 {
        stream_settings["finalmask"] = json!({ "quicParams": {} });
    }
    insert_xray_transport_settings(&mut stream_settings, scenario, payload_size)?;
    serialize_config(json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": port,
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": vless_addr.ip().to_string(),
                    "port": vless_addr.port(),
                    "users": [{
                        "id": super::TEST_VLESS_UUID_STRING,
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    }))
}

fn sing_box_client_config(
    port: u16,
    vless_addr: SocketAddr,
    scenario: StreamBenchScenario,
) -> Result<String, BenchError> {
    let transport = match scenario.transport {
        StreamBenchTransport::WebSocket => json!({
            "type": "ws",
            "path": BENCH_PATH,
            "headers": { "Host": BENCH_SERVER_NAME }
        }),
        StreamBenchTransport::HttpUpgrade => json!({
            "type": "httpupgrade",
            "host": BENCH_SERVER_NAME,
            "path": BENCH_PATH
        }),
        StreamBenchTransport::Grpc => json!({
            "type": "grpc",
            "service_name": BENCH_GRPC_SERVICE
        }),
        StreamBenchTransport::XhttpHttp1
        | StreamBenchTransport::XhttpHttp2
        | StreamBenchTransport::XhttpHttp3 => {
            return Err(BenchError::InvalidArguments(
                "sing-box does not support XHTTP".to_owned(),
            ))
        }
    };
    serialize_config(json!({
        "log": { "level": "warn" },
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": port
        }],
        "outbounds": [{
            "type": "vless",
            "tag": "proxy",
            "server": vless_addr.ip().to_string(),
            "server_port": vless_addr.port(),
            "uuid": super::TEST_VLESS_UUID_STRING,
            "tls": {
                "enabled": true,
                "server_name": BENCH_SERVER_NAME,
                "insecure": true,
                "alpn": [scenario.transport.alpn()],
                "utls": { "enabled": true, "fingerprint": "chrome" }
            },
            "transport": transport
        }],
        "route": { "final": "proxy" }
    }))
}

fn xray_server_config(
    port: u16,
    scenario: StreamBenchScenario,
    payload_size: usize,
    cert_path: &Path,
    key_path: &Path,
) -> Result<String, BenchError> {
    let mut stream_settings = json!({
        "network": scenario.transport.xray_network(),
        "security": "tls",
        "tlsSettings": {
            "alpn": [scenario.transport.alpn()],
            "certificates": [{
                "certificateFile": cert_path.to_string_lossy(),
                "keyFile": key_path.to_string_lossy()
            }]
        }
    });
    insert_xray_transport_settings(&mut stream_settings, scenario, payload_size)?;
    serialize_config(json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": super::TEST_VLESS_UUID_STRING }],
                "decryption": "none"
            },
            "streamSettings": stream_settings
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": { "finalRules": [{ "action": "allow" }] }
        }]
    }))
}

fn insert_xray_transport_settings(
    stream_settings: &mut Value,
    scenario: StreamBenchScenario,
    payload_size: usize,
) -> Result<(), BenchError> {
    let (key, settings) = match scenario.transport {
        StreamBenchTransport::WebSocket => (
            "wsSettings",
            json!({ "host": BENCH_SERVER_NAME, "path": BENCH_PATH }),
        ),
        StreamBenchTransport::HttpUpgrade => (
            "httpupgradeSettings",
            json!({ "host": BENCH_SERVER_NAME, "path": BENCH_PATH }),
        ),
        StreamBenchTransport::Grpc => {
            ("grpcSettings", json!({ "serviceName": BENCH_GRPC_SERVICE }))
        }
        StreamBenchTransport::XhttpHttp1
        | StreamBenchTransport::XhttpHttp2
        | StreamBenchTransport::XhttpHttp3 => {
            let post_bytes = i32::try_from(payload_size).map_err(|_| {
                BenchError::InvalidArguments(
                    "XHTTP benchmark payload size must fit signed 32-bit scMaxEachPostBytes"
                        .to_owned(),
                )
            })?;
            let mode = scenario.xhttp_mode.ok_or_else(|| {
                BenchError::InvalidArguments("XHTTP benchmark mode is missing".to_owned())
            })?;
            (
                "xhttpSettings",
                json!({
                    "host": BENCH_SERVER_NAME,
                    "path": BENCH_PATH,
                    "mode": mode.as_str(),
                    "scMaxEachPostBytes": post_bytes
                }),
            )
        }
    };
    stream_settings[key] = settings;
    Ok(())
}

fn serialize_config(value: Value) -> Result<String, BenchError> {
    serde_json::to_string_pretty(&value).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "serializing stream-transport benchmark config: {error}"
        ))
    })
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let encoded = base64_standard(der);
    let mut pem = String::with_capacity(encoded.len() + label.len() * 2 + 32);
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend(chunk.iter().copied().map(char::from));
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

fn base64_standard(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        output.push(char::from(TABLE[(b0 >> 2) as usize]));
        output.push(char::from(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]));
        if chunk.len() > 1 {
            output.push(char::from(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(TABLE[(b2 & 0x3f) as usize]));
        } else {
            output.push('=');
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use tokio::io::ReadBuf;

    use super::*;

    struct ShutdownSensitiveState {
        expected_upload_bytes: usize,
        uploaded_bytes: usize,
        response: Vec<u8>,
        response_offset: usize,
        write_shutdown: bool,
        read_waker: Option<Waker>,
    }

    struct ShutdownSensitiveReader {
        state: Arc<Mutex<ShutdownSensitiveState>>,
    }

    impl AsyncRead for ShutdownSensitiveReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            if state.write_shutdown {
                return Poll::Ready(Ok(()));
            }
            if state.uploaded_bytes < state.expected_upload_bytes {
                state.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let start = state.response_offset;
            let end = state
                .response
                .len()
                .min(start.saturating_add(buffer.remaining()));
            buffer.put_slice(&state.response[start..end]);
            state.response_offset = end;
            Poll::Ready(Ok(()))
        }
    }

    struct ShutdownSensitiveWriter {
        state: Arc<Mutex<ShutdownSensitiveState>>,
    }

    impl AsyncWrite for ShutdownSensitiveWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            let read_waker = {
                let mut state = self.state.lock().unwrap();
                if state.write_shutdown {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "test writer is shut down",
                    )));
                }
                state.uploaded_bytes = state.uploaded_bytes.saturating_add(buffer.len());
                (state.uploaded_bytes >= state.expected_upload_bytes)
                    .then(|| state.read_waker.take())
                    .flatten()
            };
            if let Some(waker) = read_waker {
                waker.wake();
            }
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let read_waker = {
                let mut state = self.state.lock().unwrap();
                state.write_shutdown = true;
                state.read_waker.take()
            };
            if let Some(waker) = read_waker {
                waker.wake();
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn full_duplex_waits_for_completion_before_closing_writer() {
        let template = [0x11, 0x22, 0x33];
        let iterations = 2;
        let mut response = template.repeat(iterations);
        response.push(COMPLETE_BYTE);
        let state = Arc::new(Mutex::new(ShutdownSensitiveState {
            expected_upload_bytes: template.len() * iterations,
            uploaded_bytes: 0,
            response,
            response_offset: 0,
            write_shutdown: false,
            read_waker: None,
        }));
        let mut reader = ShutdownSensitiveReader {
            state: Arc::clone(&state),
        };
        let mut writer = ShutdownSensitiveWriter {
            state: Arc::clone(&state),
        };

        run_client_full_duplex(&mut reader, &mut writer, &template, iterations)
            .await
            .unwrap();

        assert!(!state.lock().unwrap().write_shutdown);
    }

    #[test]
    fn packet_up_requires_xhttp_packet_mode() {
        let error = StreamBenchScenario::resolve(
            Some(StreamBenchTransport::Grpc),
            Some(StreamBenchTraffic::PacketUp),
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("requires an XHTTP transport"));
    }

    #[test]
    fn xhttp_h3_defaults_to_packet_up_mode() {
        let scenario = StreamBenchScenario::resolve(
            Some(StreamBenchTransport::XhttpHttp3),
            Some(StreamBenchTraffic::Download),
            None,
        )
        .unwrap();

        assert_eq!(scenario.xhttp_mode, Some(StreamBenchXhttpMode::PacketUp));
    }

    #[test]
    fn xray_xhttp_h2_config_pins_h2_and_selected_mode() {
        let scenario = StreamBenchScenario::resolve(
            Some(StreamBenchTransport::XhttpHttp2),
            Some(StreamBenchTraffic::FullDuplex),
            Some(StreamBenchXhttpMode::StreamUp),
        )
        .unwrap();
        let config = xray_client_config(
            EngineKind::XrayRust,
            1080,
            "127.0.0.1:443".parse().unwrap(),
            "unused",
            scenario,
            16_384,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();

        assert_eq!(
            value["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"][0],
            "h2"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"],
            "stream-up"
        );
    }

    #[test]
    fn xray_rust_xhttp_h3_config_pins_h3_and_default_quic_params() {
        let scenario = StreamBenchScenario::resolve(
            Some(StreamBenchTransport::XhttpHttp3),
            Some(StreamBenchTraffic::FullDuplex),
            Some(StreamBenchXhttpMode::StreamOne),
        )
        .unwrap();
        let config = xray_client_config(
            EngineKind::XrayRust,
            1080,
            "127.0.0.1:443".parse().unwrap(),
            "unused",
            scenario,
            16_384,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();

        assert_eq!(
            value["outbounds"][0]["streamSettings"],
            json!({
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": BENCH_SERVER_NAME,
                    "allowInsecure": true,
                    "fingerprint": "chrome",
                    "alpn": ["h3"]
                },
                "finalmask": { "quicParams": {} },
                "xhttpSettings": {
                    "host": BENCH_SERVER_NAME,
                    "path": BENCH_PATH,
                    "mode": "stream-one",
                    "scMaxEachPostBytes": 16_384
                }
            })
        );
    }

    #[test]
    fn xray_core_xhttp_h3_fixture_schema_selects_h3() {
        let scenario = StreamBenchScenario::resolve(
            Some(StreamBenchTransport::XhttpHttp3),
            Some(StreamBenchTraffic::Download),
            Some(StreamBenchXhttpMode::StreamUp),
        )
        .unwrap();
        let config = xray_server_config(
            443,
            scenario,
            4096,
            Path::new("bench-cert.pem"),
            Path::new("bench-key.pem"),
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();

        assert_eq!(
            value["inbounds"][0]["streamSettings"],
            json!({
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificateFile": "bench-cert.pem",
                        "keyFile": "bench-key.pem"
                    }]
                },
                "xhttpSettings": {
                    "host": BENCH_SERVER_NAME,
                    "path": BENCH_PATH,
                    "mode": "stream-up",
                    "scMaxEachPostBytes": 4096
                }
            })
        );
    }

    #[test]
    fn fixture_pem_encoding_matches_xray_file_schema() {
        assert_eq!(
            pem_block("CERTIFICATE", &[0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff]),
            "-----BEGIN CERTIFICATE-----\nAAEC/f7/\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn xhttp_h3_fixture_uses_udp_port_and_process_log_readiness() {
        assert_eq!(
            StreamBenchTransport::XhttpHttp3.fixture_startup(),
            FixtureStartup::UdpProcessLog("started")
        );
    }

    #[test]
    fn xray_core_client_pins_the_generated_fixture_certificate() {
        let scenario = StreamBenchScenario::resolve(
            Some(StreamBenchTransport::WebSocket),
            Some(StreamBenchTraffic::Upload),
            None,
        )
        .unwrap();
        let config = xray_client_config(
            EngineKind::XrayCore,
            1080,
            "127.0.0.1:443".parse().unwrap(),
            "fixture-sha256",
            scenario,
            4096,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();
        let tls = &value["outbounds"][0]["streamSettings"]["tlsSettings"];

        assert_eq!(tls["pinnedPeerCertSha256"], "fixture-sha256");
        assert_eq!(tls["alpn"][0], "http/1.1");
        assert!(tls.get("allowInsecure").is_none());
    }

    #[test]
    fn xhttp_packet_size_is_bound_to_one_benchmark_write() {
        let scenario = StreamBenchScenario::resolve(
            Some(StreamBenchTransport::XhttpHttp1),
            Some(StreamBenchTraffic::PacketUp),
            Some(StreamBenchXhttpMode::PacketUp),
        )
        .unwrap();
        let config = xray_client_config(
            EngineKind::XrayRust,
            1080,
            "127.0.0.1:443".parse().unwrap(),
            "unused",
            scenario,
            16_384,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&config).unwrap();
        let settings = &value["outbounds"][0]["streamSettings"]["xhttpSettings"];

        assert_eq!(settings["mode"], "packet-up");
        assert_eq!(settings["scMaxEachPostBytes"], 16_384);
    }

    #[test]
    fn sing_box_support_is_explicit_per_transport() {
        assert!(StreamBenchTransport::WebSocket.supports_sing_box());
        assert!(StreamBenchTransport::HttpUpgrade.supports_sing_box());
        assert!(StreamBenchTransport::Grpc.supports_sing_box());
        assert!(!StreamBenchTransport::XhttpHttp1.supports_sing_box());
        assert!(!StreamBenchTransport::XhttpHttp2.supports_sing_box());
        assert!(!StreamBenchTransport::XhttpHttp3.supports_sing_box());
    }
}
