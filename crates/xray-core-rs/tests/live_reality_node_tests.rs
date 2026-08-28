use std::env;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Duration, Instant};
use xray_config::{parse_xray_json, CoreConfig, InboundProtocol, OutboundSettings, StreamSecurity};
use xray_core_rs::{Core, RuntimeLogConfig, RuntimeLogger};

const LIVE_SOCKS_TAG: &str = "live_socks";
const LIVE_TARGETS_ENV: &str = "XRAY_REALITY_LIVE_TARGETS";

#[tokio::test]
#[ignore = "requires live config, XRAY_REALITY_LIVE_TARGETS, and external network access"]
async fn rust_core_live_reality_node_opens_parallel_speedtest_tcp_flows() {
    timeout(
        Duration::from_secs(selected_live_test_timeout_secs()),
        run_rust_core_live_reality_node_burst(WorkloadMode::ConnectOnly),
    )
    .await
    .expect("live Rust core connect-only burst timeout");
}

#[tokio::test]
#[ignore = "requires live config, XRAY_REALITY_LIVE_TARGETS, and external network access"]
async fn rust_core_live_reality_node_reads_parallel_speedtest_http_responses() {
    timeout(
        Duration::from_secs(selected_live_test_timeout_secs()),
        run_rust_core_live_reality_node_burst(WorkloadMode::HttpFirstByte),
    )
    .await
    .expect("live Rust core HTTP burst timeout");
}

#[tokio::test]
#[ignore = "requires live config, XRAY_REALITY_LIVE_TARGETS, Xray-core, Go, and external network access"]
async fn rust_core_live_reality_node_downloads_parallel_speedtest_http_bodies() {
    timeout(
        Duration::from_secs(selected_live_test_timeout_secs()),
        run_rust_core_live_reality_node_burst(WorkloadMode::HttpBody),
    )
    .await
    .expect("live Rust core HTTP body burst timeout");
}

#[tokio::test]
#[ignore = "requires live config, XRAY_REALITY_LIVE_TARGETS, Xray-core, Go, and external network access"]
async fn xray_core_live_reality_node_reads_parallel_speedtest_http_responses() {
    timeout(
        Duration::from_secs(selected_live_test_timeout_secs()),
        run_xray_core_live_reality_node_burst(WorkloadMode::HttpFirstByte),
    )
    .await
    .expect("live Xray-core HTTP burst timeout");
}

#[tokio::test]
#[ignore = "requires live config, XRAY_REALITY_LIVE_TARGETS, Xray-core, Go, and external network access"]
async fn xray_core_live_reality_node_downloads_parallel_speedtest_http_bodies() {
    timeout(
        Duration::from_secs(selected_live_test_timeout_secs()),
        run_xray_core_live_reality_node_burst(WorkloadMode::HttpBody),
    )
    .await
    .expect("live Xray-core HTTP body burst timeout");
}

async fn run_rust_core_live_reality_node_burst(mode: WorkloadMode) {
    let config = live_core_config();
    describe_live_config(&config);
    let mut core = Core::new(config).expect("create live Rust core");
    let log_dir = create_temp_dir("xray-rust-live-reality-logs");
    core.set_runtime_logger(
        RuntimeLogger::new(RuntimeLogConfig::directory(&log_dir.path))
            .expect("create live Rust runtime logger"),
    );

    timeout(Duration::from_secs(10), core.start())
        .await
        .expect("start live Rust core timeout")
        .expect("start live Rust core");
    let socks_addr = core
        .inbound_addr(Some(LIVE_SOCKS_TAG))
        .expect("live SOCKS inbound addr");

    let result = run_parallel_live_workload(socks_addr, mode).await;
    core.stop().await.expect("stop live Rust core");

    if let Err(failures) = result {
        panic!(
            "{} live flow(s) failed: {failures:?}\n{}",
            failures.len(),
            rust_runtime_logs(&log_dir.path)
        );
    }
}

async fn run_xray_core_live_reality_node_burst(mode: WorkloadMode) {
    let checkout = resolve_xray_checkout();
    let mut process = start_xray_core_live_client(&checkout).await;

    if let Err(failures) = run_parallel_live_workload(process.addr, mode).await {
        panic!(
            "{} live Xray-core flow(s) failed: {failures:?}\n{}",
            failures.len(),
            process.logs()
        );
    }

    process.stop();
}

fn live_core_config() -> CoreConfig {
    let raw = load_live_config_json();
    let normalized = normalize_live_config_json(&raw, 0);
    let parsed = parse_xray_json(&normalized).expect("live xray JSON should parse");
    assert!(
        parsed.diagnostics.is_empty(),
        "live xray JSON parsed with diagnostics: {:?}",
        parsed.diagnostics
    );

    let config = parsed.config;
    assert_eq!(config.inbounds.len(), 1, "live test uses one SOCKS inbound");
    assert_eq!(config.inbounds[0].tag.as_deref(), Some(LIVE_SOCKS_TAG));
    assert_eq!(config.inbounds[0].protocol, InboundProtocol::Socks);
    assert!(
        config.outbounds.iter().any(|outbound| {
            matches!(outbound.settings, OutboundSettings::Vless(_))
                && matches!(outbound.stream.security, StreamSecurity::Reality(_))
        }),
        "live config must contain a VLESS REALITY outbound"
    );
    config
}

fn load_live_config_json() -> String {
    if let Ok(raw) = env::var("XRAY_REALITY_LIVE_CONFIG_JSON") {
        return raw;
    }
    if let Ok(path) = env::var("XRAY_REALITY_LIVE_CONFIG_PATH") {
        return fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("read XRAY_REALITY_LIVE_CONFIG_PATH `{path}`: {error}")
        });
    }

    panic!(
        "set XRAY_REALITY_LIVE_CONFIG_JSON or XRAY_REALITY_LIVE_CONFIG_PATH to the full xray node config"
    );
}

fn normalize_live_config_json(raw: &str, socks_port: u16) -> String {
    let mut value = serde_json::from_str::<Value>(raw).expect("live config must be valid JSON");
    let proxy_tag = first_outbound_tag(&value);
    let fingerprint_override = env::var("XRAY_REALITY_LIVE_FINGERPRINT").ok();
    apply_live_fingerprint_override(&mut value, fingerprint_override.as_deref());

    value["inbounds"] = json!([
        {
            "tag": LIVE_SOCKS_TAG,
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks"
        }
    ]);
    value["routing"] = json!({
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": [LIVE_SOCKS_TAG],
                "outboundTag": proxy_tag
            }
        ]
    });
    value["log"] = json!({ "loglevel": "debug" });

    serde_json::to_string_pretty(&value).expect("serialize normalized live config")
}

fn apply_live_fingerprint_override(value: &mut Value, fingerprint: Option<&str>) {
    let Some(fingerprint) = fingerprint.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };
    let Some(outbounds) = value.get_mut("outbounds").and_then(Value::as_array_mut) else {
        return;
    };

    for outbound in outbounds {
        let Some(stream_settings) = outbound.get_mut("streamSettings") else {
            continue;
        };
        let security_is_reality = stream_settings
            .get("security")
            .and_then(Value::as_str)
            .is_some_and(|security| security.eq_ignore_ascii_case("reality"));
        if !security_is_reality && stream_settings.get("realitySettings").is_none() {
            continue;
        }

        stream_settings["realitySettings"]["fingerprint"] = json!(fingerprint);
    }
}

fn first_outbound_tag(value: &Value) -> String {
    value
        .get("outbounds")
        .and_then(Value::as_array)
        .and_then(|outbounds| outbounds.first())
        .and_then(|outbound| outbound.get("tag"))
        .and_then(Value::as_str)
        .unwrap_or("proxy")
        .to_owned()
}

fn describe_live_config(config: &CoreConfig) {
    let reality_outbound_count = config
        .outbounds
        .iter()
        .filter(|outbound| {
            matches!(outbound.settings, OutboundSettings::Vless(_))
                && matches!(outbound.stream.security, StreamSecurity::Reality(_))
        })
        .count();
    eprintln!("live REALITY config loaded: realityOutbounds={reality_outbound_count}");
}

async fn run_parallel_live_workload(
    socks_addr: SocketAddr,
    mode: WorkloadMode,
) -> Result<(), Vec<String>> {
    let targets = selected_live_targets();
    let flow_count = selected_live_flow_count();
    let mut handles = Vec::with_capacity(flow_count);

    eprintln!(
        "running live {:?} burst flows={} targetCount={}",
        mode,
        flow_count,
        targets.len()
    );

    for index in 0..flow_count {
        let target = targets[index % targets.len()].clone();
        handles.push(tokio::spawn(async move {
            run_live_flow(socks_addr, target, mode, index).await
        }));
        sleep(selected_live_flow_spacing()).await;
    }

    let mut failures = Vec::new();
    for handle in handles {
        match timeout(
            Duration::from_secs(selected_live_flow_timeout_secs()),
            handle,
        )
        .await
        {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => failures.push(error),
            Ok(Err(error)) => failures.push(format!("join flow task: {error}")),
            Err(error) => failures.push(format!("flow task timeout: {error}")),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

async fn run_live_flow(
    socks_addr: SocketAddr,
    target: LiveTarget,
    mode: WorkloadMode,
    index: usize,
) -> Result<(), String> {
    let mut client = timeout(
        Duration::from_secs(selected_live_connect_timeout_secs()),
        TcpStream::connect(socks_addr),
    )
    .await
    .map_err(|error| format!("flow {index}: connect SOCKS timeout: {error}"))?
    .map_err(|error| format!("flow {index}: connect SOCKS: {error}"))?;

    timeout(
        Duration::from_secs(selected_live_connect_timeout_secs()),
        socks5_connect(&mut client, &target),
    )
    .await
    .map_err(|error| format!("flow {index}: SOCKS CONNECT timeout: {error}"))?
    .map_err(|error| format!("flow {index}: SOCKS CONNECT: {error}"))?;

    if mode == WorkloadMode::ConnectOnly {
        return Ok(());
    }

    let request = live_http_request(&target);
    timeout(Duration::from_secs(5), client.write_all(request.as_bytes()))
        .await
        .map_err(|error| format!("flow {index}: write HTTP request timeout: {error}"))?
        .map_err(|error| format!("flow {index}: write HTTP request: {error}"))?;

    match mode {
        WorkloadMode::ConnectOnly => {}
        WorkloadMode::HttpFirstByte => {
            let mut first_byte = [0; 1];
            timeout(
                Duration::from_secs(selected_live_first_byte_timeout_secs()),
                client.read_exact(&mut first_byte),
            )
            .await
            .map_err(|error| format!("flow {index}: read first byte timeout: {error}"))?
            .map_err(|error| format!("flow {index}: read first byte: {error}"))?;
        }
        WorkloadMode::HttpBody => {
            let min_body_bytes = selected_live_http_read_bytes();
            let read_bytes = timeout(
                Duration::from_secs(selected_live_body_timeout_secs()),
                read_live_http_body_until_min_bytes(&mut client, min_body_bytes),
            )
            .await
            .map_err(|error| {
                format!("flow {index}: read HTTP body timeout minBytes={min_body_bytes}: {error}")
            })?
            .map_err(|error| format!("flow {index}: read HTTP body: {error}"))?;
            eprintln!("flow {index}: read at least {read_bytes} HTTP body bytes");
        }
    }

    Ok(())
}

async fn read_live_http_body_until_min_bytes<R>(
    reader: &mut R,
    min_body_bytes: usize,
) -> Result<usize, String>
where
    R: AsyncRead + Unpin,
{
    let mut header_buffer = Vec::with_capacity(16 * 1024);
    let mut read_buffer = [0; 16 * 1024];
    let mut body_bytes = 0usize;
    let mut saw_headers = false;

    while body_bytes < min_body_bytes {
        let read = reader
            .read(&mut read_buffer)
            .await
            .map_err(|error| format!("read response bytes: {error}"))?;
        if read == 0 {
            return Err(format!(
                "response closed after {body_bytes} body bytes, expected at least {min_body_bytes}"
            ));
        }

        if saw_headers {
            body_bytes = body_bytes.saturating_add(read);
            continue;
        }

        header_buffer.extend_from_slice(&read_buffer[..read]);
        if header_buffer.len() > 64 * 1024 {
            return Err("HTTP response header exceeded 64KiB".to_owned());
        }

        let Some(header_end) = http_header_end(&header_buffer) else {
            continue;
        };
        validate_http_status(&header_buffer[..header_end])?;
        body_bytes = body_bytes.saturating_add(header_buffer.len() - header_end - 4);
        header_buffer.clear();
        saw_headers = true;
    }

    Ok(body_bytes)
}

fn http_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn validate_http_status(header: &[u8]) -> Result<(), String> {
    let header = String::from_utf8_lossy(header);
    let status_line = header.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("missing HTTP status in `{status_line}`"))?;
    if matches!(status.parse::<u16>(), Ok(200..=299)) {
        return Ok(());
    }
    Err(format!("unexpected HTTP status line `{status_line}`"))
}

fn live_http_request(target: &LiveTarget) -> String {
    let path = env::var("XRAY_REALITY_LIVE_HTTP_PATH").unwrap_or_else(|_| "/".to_owned());
    format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray-rust-live-reality-test/1\r\nConnection: close\r\n\r\n",
        target.host_header()
    )
}

async fn socks5_connect(client: &mut TcpStream, target: &LiveTarget) -> Result<(), String> {
    client
        .write_all(&[5, 1, 0])
        .await
        .map_err(|error| format!("write SOCKS greeting: {error}"))?;
    let mut method = [0; 2];
    client
        .read_exact(&mut method)
        .await
        .map_err(|error| format!("read SOCKS method: {error}"))?;
    if method != [5, 0] {
        return Err(format!("unexpected SOCKS method reply: {method:?}"));
    }

    let mut request = vec![5, 1, 0];
    match target {
        LiveTarget::Ip(addr) => match addr {
            SocketAddr::V4(addr) => {
                request.push(1);
                request.extend_from_slice(&addr.ip().octets());
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                request.push(4);
                request.extend_from_slice(&addr.ip().octets());
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        LiveTarget::Domain { domain, port } => {
            let domain_len = u8::try_from(domain.len())
                .map_err(|_| format!("SOCKS domain is too long: {domain}"))?;
            request.push(3);
            request.push(domain_len);
            request.extend_from_slice(domain.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    client
        .write_all(&request)
        .await
        .map_err(|error| format!("write SOCKS CONNECT: {error}"))?;

    read_socks5_reply(client).await
}

async fn read_socks5_reply(client: &mut TcpStream) -> Result<(), String> {
    let mut reply_header = [0; 4];
    client
        .read_exact(&mut reply_header)
        .await
        .map_err(|error| format!("read SOCKS reply header: {error}"))?;
    if reply_header[0] != 5 || reply_header[2] != 0 {
        return Err(format!("unexpected SOCKS reply header: {reply_header:?}"));
    }
    if reply_header[1] != 0 {
        return Err(format!("SOCKS CONNECT rejected: {reply_header:?}"));
    }

    match reply_header[3] {
        1 => {
            let mut bind = [0; 6];
            client
                .read_exact(&mut bind)
                .await
                .map_err(|error| format!("read SOCKS IPv4 bind: {error}"))?;
        }
        3 => {
            let mut len = [0; 1];
            client
                .read_exact(&mut len)
                .await
                .map_err(|error| format!("read SOCKS domain bind length: {error}"))?;
            let mut bind = vec![0; usize::from(len[0]) + 2];
            client
                .read_exact(&mut bind)
                .await
                .map_err(|error| format!("read SOCKS domain bind: {error}"))?;
        }
        4 => {
            let mut bind = [0; 18];
            client
                .read_exact(&mut bind)
                .await
                .map_err(|error| format!("read SOCKS IPv6 bind: {error}"))?;
        }
        address_type => {
            return Err(format!(
                "unsupported SOCKS bind address type {address_type}"
            ))
        }
    }

    Ok(())
}

fn selected_live_targets() -> Vec<LiveTarget> {
    live_targets_from_env(env::var(LIVE_TARGETS_ENV)).unwrap_or_else(|error| panic!("{error}"))
}

fn live_targets_from_env(raw: Result<String, env::VarError>) -> Result<Vec<LiveTarget>, String> {
    let raw = raw.map_err(|_| {
        format!("set {LIVE_TARGETS_ENV} to an explicit comma-separated list of host:port targets")
    })?;
    let targets = raw
        .split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .enumerate()
        .map(|(index, target)| {
            parse_live_target(target)
                .map_err(|error| format!("{LIVE_TARGETS_ENV} target #{}: {error}", index + 1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if targets.is_empty() {
        return Err(format!("{LIVE_TARGETS_ENV} must not be empty"));
    }
    Ok(targets)
}

fn parse_live_target(raw: &str) -> Result<LiveTarget, String> {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(LiveTarget::Ip(addr));
    }

    let Some((domain, port)) = raw.rsplit_once(':') else {
        return Err("must be host:port".to_owned());
    };
    let port = port
        .parse::<u16>()
        .map_err(|error| format!("has an invalid port: {error}"))?;
    if domain.is_empty() {
        return Err("has an empty host".to_owned());
    }
    Ok(LiveTarget::Domain {
        domain: domain.to_owned(),
        port,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LiveTarget {
    Ip(SocketAddr),
    Domain { domain: String, port: u16 },
}

impl LiveTarget {
    fn host_header(&self) -> String {
        match self {
            Self::Ip(addr) => addr.ip().to_string(),
            Self::Domain { domain, port } => {
                if *port == 80 {
                    domain.clone()
                } else {
                    format!("{domain}:{port}")
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkloadMode {
    ConnectOnly,
    HttpFirstByte,
    HttpBody,
}

fn selected_live_flow_count() -> usize {
    let flow_count = env::var("XRAY_REALITY_LIVE_BURST_FLOWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(32);
    assert!(
        (1..=256).contains(&flow_count),
        "XRAY_REALITY_LIVE_BURST_FLOWS must be between 1 and 256"
    );
    flow_count
}

fn selected_live_flow_spacing() -> Duration {
    let millis = env::var("XRAY_REALITY_LIVE_FLOW_SPACING_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Duration::from_millis(millis)
}

fn selected_live_connect_timeout_secs() -> u64 {
    env::var("XRAY_REALITY_LIVE_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15)
}

fn selected_live_first_byte_timeout_secs() -> u64 {
    env::var("XRAY_REALITY_LIVE_FIRST_BYTE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(20)
}

fn selected_live_body_timeout_secs() -> u64 {
    env::var("XRAY_REALITY_LIVE_BODY_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60)
}

fn selected_live_http_read_bytes() -> usize {
    env::var("XRAY_REALITY_LIVE_HTTP_READ_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1024 * 1024)
}

fn selected_live_flow_timeout_secs() -> u64 {
    env::var("XRAY_REALITY_LIVE_FLOW_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(45)
}

fn selected_live_test_timeout_secs() -> u64 {
    env::var("XRAY_REALITY_LIVE_TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(240)
}

async fn start_xray_core_live_client(xray_checkout: &Path) -> LiveXrayProcess {
    let temp_dir = create_temp_dir("xray-core-live-reality");
    let binary = temp_dir
        .path
        .join(format!("xray{}", env::consts::EXE_SUFFIX));
    let config_path = temp_dir.path.join("client.json");
    let stdout_path = temp_dir.path.join("xray-client.stdout.log");
    let stderr_path = temp_dir.path.join("xray-client.stderr.log");
    let port = allocate_loopback_port();
    let config = normalize_live_config_json(&load_live_config_json(), port);
    fs::write(&config_path, config).expect("write normalized live xray config");

    let build_output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&binary)
        .arg("./main")
        .current_dir(xray_checkout)
        .output()
        .expect("start go build for Xray-core live client");
    assert!(
        build_output.status.success(),
        "go build ./main failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).expect("create xray client stdout log"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("create xray client stderr log"),
        ))
        .spawn()
        .expect("start xray live client process");

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    wait_for_tcp_listener(&mut child, addr, &stdout_path, &stderr_path).await;

    LiveXrayProcess {
        child,
        _temp_dir: temp_dir,
        addr,
        stdout_path,
        stderr_path,
    }
}

async fn wait_for_tcp_listener(
    child: &mut Child,
    addr: SocketAddr,
    stdout_path: &Path,
    stderr_path: &Path,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("check xray live process status") {
            let stdout = fs::read_to_string(stdout_path).unwrap_or_default();
            let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
            panic!(
                "xray live client exited before listening on {addr}: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        }

        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("xray live client did not listen on {addr}: {error}"),
        }
    }
}

fn resolve_xray_checkout() -> PathBuf {
    let checkout = if let Ok(path) = env::var("XRAY_CORE_CHECKOUT") {
        PathBuf::from(path)
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate lives under workspace/crates/xray-core-rs")
            .join("Xray-core")
    };
    const EXPECTED: &str = "5ca6f4b7d4dc20a881d4330e498892697627ec0c";
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&checkout)
        .output()
        .expect("read Xray-core checkout revision");
    assert!(
        output.status.success(),
        "git rev-parse failed for Xray-core"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        EXPECTED,
        "live REALITY oracle checkout must be pinned to v26.7.28"
    );
    checkout
}

fn allocate_loopback_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn create_temp_dir(prefix: &str) -> TempDir {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = env::temp_dir().join(format!("{prefix}-{stamp}-{}", std::process::id()));
    fs::create_dir(&path).expect("create temp dir");
    TempDir { path }
}

fn rust_runtime_logs(dir: &Path) -> String {
    format!(
        "rust xray-access.log:\n{}\nrust xray-error.log:\n{}",
        fs::read_to_string(dir.join("xray-access.log")).unwrap_or_default(),
        fs::read_to_string(dir.join("xray-error.log")).unwrap_or_default()
    )
}

struct TempDir {
    path: PathBuf,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct LiveXrayProcess {
    child: Child,
    _temp_dir: TempDir,
    addr: SocketAddr,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl LiveXrayProcess {
    fn logs(&self) -> String {
        format!(
            "xray stdout:\n{}\nxray stderr:\n{}",
            fs::read_to_string(&self.stdout_path).unwrap_or_default(),
            fs::read_to_string(&self.stderr_path).unwrap_or_default()
        )
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for LiveXrayProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn live_targets_require_an_explicit_environment_value() {
        let error = live_targets_from_env(Err(env::VarError::NotPresent)).unwrap_err();

        assert_eq!(
            error,
            "set XRAY_REALITY_LIVE_TARGETS to an explicit comma-separated list of host:port targets"
        );
    }

    #[test]
    fn apply_live_fingerprint_override_updates_reality_outbounds() {
        let mut value = json!({
            "outbounds": [
                {
                    "protocol": "vless",
                    "streamSettings": {
                        "security": "reality",
                        "realitySettings": {
                            "fingerprint": "hellofirefox_99"
                        }
                    }
                },
                {
                    "protocol": "freedom"
                }
            ]
        });

        apply_live_fingerprint_override(&mut value, Some("chrome"));

        assert_eq!(
            value["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"],
            json!("chrome")
        );
        assert_eq!(value["outbounds"][1]["protocol"], json!("freedom"));
    }

    #[tokio::test]
    async fn read_live_http_body_until_min_bytes_accepts_split_header_and_body() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello ")
                .await
                .unwrap();
            server.write_all(b"world!").await.unwrap();
        });

        let bytes = read_live_http_body_until_min_bytes(&mut client, 11)
            .await
            .unwrap();

        assert!(bytes >= 11, "read {bytes} body bytes");
    }

    #[tokio::test]
    async fn read_live_http_body_until_min_bytes_rejects_error_status() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\noops!")
                .await
                .unwrap();
        });

        let error = read_live_http_body_until_min_bytes(&mut client, 1)
            .await
            .unwrap_err();

        assert!(error.contains("404"), "{error}");
    }
}
