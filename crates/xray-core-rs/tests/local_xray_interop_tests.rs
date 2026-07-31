use std::env;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration, Instant};
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    RealitySettings, RealityShortId, RoutingConfig, StreamSecurity, StreamSettings, TargetAddr,
    TlsSettings, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::Core;
use xray_transport::{SystemDnsResolver, TlsConnector, TransportDialer};

const TEST_UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const TLS_SERVER_NAME: &str = "vless.test";
// The PQ interop oracle needs a cover origin that accepts X25519MLKEM;
// RFC 2606 example origins reject the `hellochrome_120_pq` handshake.
const REALITY_SERVER_NAME: &str = "www.google.com";
const INNER_TLS_SERVER_NAME: &str = "inner.test";
const REALITY_PRIVATE_KEY: &str = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks";
const REALITY_PUBLIC_KEY_BASE64: &str = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM";
const DEFAULT_REALITY_SERVER_WARMUP_TIMEOUT: Duration = Duration::from_secs(30);
const REALITY_PUBLIC_KEY: [u8; 32] = [
    19, 159, 86, 142, 123, 217, 113, 3, 46, 238, 212, 123, 252, 24, 50, 135, 39, 46, 17, 208, 82,
    248, 43, 74, 197, 242, 38, 68, 39, 64, 188, 83,
];
const REALITY_SHORT_ID: [u8; 8] = [1, 35, 69, 103, 137, 171, 205, 239];
const REALITY_SHORT_ID_HEX: &str = "0123456789abcdef";

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp() {
    timeout(Duration::from_secs(120), run_local_xray_vless_interop())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tls() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_vless_tls_interop(None),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tls_vision() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_vless_tls_interop(Some("xtls-rprx-vision")),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn inner_tls_session_survives_vision_direct_switch_through_local_xray_reality_vision() {
    timeout(
        Duration::from_secs(180),
        run_local_xray_reality_vision_inner_tls_interop("chrome"),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_vless_reality_vision_interop("chrome"),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision_selected_fingerprints(
) {
    timeout(Duration::from_secs(240), async {
        for fingerprint in selected_reality_interop_fingerprints() {
            eprintln!("running REALITY Vision interop fingerprint={fingerprint}");
            run_local_xray_vless_reality_vision_interop(&fingerprint).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_clients_open_parallel_echo_flows_through_local_xray_vless_reality_vision_selected_fingerprints(
) {
    timeout(Duration::from_secs(240), async {
        let flow_count = selected_reality_interop_burst_flow_count();
        for fingerprint in selected_reality_interop_burst_fingerprints() {
            eprintln!(
                "running REALITY Vision burst interop fingerprint={fingerprint} flows={flow_count}"
            );
            run_local_xray_vless_reality_vision_burst_interop(&fingerprint, flow_count).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn xray_core_socks_clients_open_parallel_echo_flows_through_local_xray_vless_reality_vision_selected_fingerprints(
) {
    timeout(Duration::from_secs(240), async {
        let flow_count = selected_reality_interop_burst_flow_count();
        for fingerprint in selected_reality_interop_burst_fingerprints() {
            eprintln!(
                "running Xray-core client REALITY Vision burst interop fingerprint={fingerprint} flows={flow_count}"
            );
            run_xray_core_client_vless_reality_vision_burst_interop(&fingerprint, flow_count).await;
        }
    })
    .await
    .unwrap();
}

async fn run_local_xray_vless_interop() {
    let xray_checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::None,
                flow: None,
            },
        ),
    )
    .await
    .expect("start xray timeout");

    let rust_config = rust_core_config_with_security(xray.addr, StreamSecurity::None, None);
    run_local_xray_vless_interop_scenario(xray, rust_config, None).await;
}

async fn run_local_xray_vless_tls_interop(flow: Option<&'static str>) {
    let xray_checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Tls,
                flow,
            },
        ),
    )
    .await
    .expect("start xray timeout");
    let tls_client_config = Arc::clone(
        xray.tls_client_config
            .as_ref()
            .expect("TLS Xray server should expose trusted client config"),
    );
    let rust_config = rust_core_config_with_security(
        xray.addr,
        StreamSecurity::Tls(TlsSettings {
            server_name: Some(TLS_SERVER_NAME.to_owned()),
            fingerprint: None,
            allow_insecure: false,
        }),
        flow,
    );
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(tls_client_config));

    run_local_xray_vless_interop_scenario(xray, rust_config, Some(dialer)).await;
}

fn selected_reality_interop_fingerprints() -> Vec<String> {
    if let Ok(raw) = env::var("XRAY_REALITY_INTEROP_FINGERPRINTS") {
        return raw
            .split(',')
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }

    [
        "chrome",
        "helloios_13",
        "hello360_11_0",
        "hellochrome_120_pq",
        "hellofirefox_99",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

fn selected_reality_interop_burst_fingerprints() -> Vec<String> {
    if let Ok(raw) = env::var("XRAY_REALITY_INTEROP_BURST_FINGERPRINTS") {
        return raw
            .split(',')
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }

    vec!["hellofirefox_99".to_owned()]
}

fn selected_reality_interop_burst_flow_count() -> usize {
    let flow_count = env::var("XRAY_REALITY_INTEROP_BURST_FLOWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(32);
    assert!(
        (1..=256).contains(&flow_count),
        "XRAY_REALITY_INTEROP_BURST_FLOWS must be between 1 and 256"
    );
    flow_count
}

fn selected_reality_server_warmup_timeout() -> Duration {
    env::var("XRAY_REALITY_INTEROP_SERVER_WARMUP_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_REALITY_SERVER_WARMUP_TIMEOUT)
}

async fn warm_up_reality_server_detector(xray: &XrayServer, fingerprint: &str) {
    let rust_config = rust_reality_vision_core_config(xray.addr, fingerprint);
    match timeout(
        selected_reality_server_warmup_timeout(),
        run_rust_core_socks_echo_probe(rust_config),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("REALITY server warmup probe failed: {error}");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("REALITY server warmup probe timed out: {error}");
        }
    }
}

async fn run_local_xray_vless_reality_vision_interop(fingerprint: &str) {
    let xray_checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Reality,
                flow: Some("xtls-rprx-vision"),
            },
        ),
    )
    .await
    .expect("start xray timeout");
    warm_up_reality_server_detector(&xray, fingerprint).await;
    let rust_config = rust_reality_vision_core_config(xray.addr, fingerprint);

    run_local_xray_vless_interop_scenario(xray, rust_config, None).await;
}

async fn run_local_xray_reality_vision_inner_tls_interop(fingerprint: &str) {
    let xray_checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Reality,
                flow: Some("xtls-rprx-vision"),
            },
        ),
    )
    .await
    .expect("start xray timeout");
    warm_up_reality_server_detector(&xray, fingerprint).await;
    let rust_config = rust_reality_vision_core_config(xray.addr, fingerprint);

    run_inner_tls_interop_scenario(xray, rust_config).await;
}

/// Carry a real TLS session inside the tunnel, which is what makes Vision
/// engage direct mode: the peer stops wrapping the downlink in REALITY TLS
/// part way through while it keeps decrypting the uplink. Echo workloads never
/// reach this state because a non-TLS payload resolves to `VisionCommand::End`.
async fn run_inner_tls_interop_scenario(xray: XrayServer, rust_config: CoreConfig) {
    let (tls_echo_addr, inner_client_config, echo_handle) = spawn_inner_tls_echo_server().await;
    let mut core = Core::new(rust_config).expect("create rust core");

    timeout(Duration::from_secs(5), core.start())
        .await
        .expect("start rust core timeout")
        .expect("start rust core");
    let socks_addr = core
        .inbound_addr(Some("socks-in"))
        .expect("bound socks addr");

    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .expect("connect rust socks timeout")
        .expect("connect rust socks");
    match timeout(
        Duration::from_secs(5),
        socks5_connect(&mut client, tls_echo_addr),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("socks connect failed: {error}");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("socks connect timeout: {error}");
        }
    }

    let server_name = rustls::pki_types::ServerName::try_from(INNER_TLS_SERVER_NAME)
        .expect("inner tls server name");
    let connector = tokio_rustls::TlsConnector::from(inner_client_config);
    let mut tls = match timeout(
        Duration::from_secs(20),
        connector.connect(server_name, client),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("inner tls handshake failed: {error}");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("inner tls handshake timeout: {error}");
        }
    };

    // Several round trips: the peer switches its downlink to direct mode part
    // way through, and every later uplink write still has to be encrypted.
    for round in 0..4 {
        let payload = format!("inner tls round {round}");
        if let Err(error) = timeout(Duration::from_secs(10), tls.write_all(payload.as_bytes()))
            .await
            .expect("write inner tls payload timeout")
        {
            eprintln!("{}", xray.logs());
            panic!("write inner tls payload failed in round {round}: {error}");
        }
        timeout(Duration::from_secs(10), tls.flush())
            .await
            .expect("flush inner tls payload timeout")
            .expect("flush inner tls payload");

        let mut echoed = vec![0; payload.len()];
        match timeout(Duration::from_secs(15), tls.read_exact(&mut echoed)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                eprintln!("{}", xray.logs());
                panic!("read inner tls echo failed in round {round}: {error}");
            }
            Err(error) => {
                eprintln!("{}", xray.logs());
                panic!("read inner tls echo timeout in round {round}: {error}");
            }
        }
        assert_eq!(echoed, payload.as_bytes());
    }

    drop(tls);
    core.stop().await.expect("stop rust core");
    drop(xray);
    timeout(Duration::from_secs(5), echo_handle)
        .await
        .expect("inner tls echo task should finish")
        .expect("inner tls echo task should not panic");
}

async fn run_local_xray_vless_reality_vision_burst_interop(fingerprint: &str, flow_count: usize) {
    let xray_checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Reality,
                flow: Some("xtls-rprx-vision"),
            },
        ),
    )
    .await
    .expect("start xray timeout");
    warm_up_reality_server_detector(&xray, fingerprint).await;
    let rust_config = rust_reality_vision_core_config(xray.addr, fingerprint);

    run_local_xray_vless_parallel_interop_scenario(xray, rust_config, flow_count).await;
}

async fn run_xray_core_client_vless_reality_vision_burst_interop(
    fingerprint: &str,
    flow_count: usize,
) {
    let xray_checkout = resolve_xray_checkout();
    let server = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Reality,
                flow: Some("xtls-rprx-vision"),
            },
        ),
    )
    .await
    .expect("start xray server timeout");
    let client = timeout(
        Duration::from_secs(60),
        start_xray_vless_client(&xray_checkout, server.addr, fingerprint),
    )
    .await
    .expect("start xray client timeout");

    match timeout(
        selected_reality_server_warmup_timeout(),
        run_socks_echo_probe(client.addr),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("xray server logs:\n{}", server.logs());
            eprintln!("xray client logs:\n{}", client.logs());
            panic!("Xray-core client REALITY warmup probe failed: {error}");
        }
        Err(error) => {
            eprintln!("xray server logs:\n{}", server.logs());
            eprintln!("xray client logs:\n{}", client.logs());
            panic!("Xray-core client REALITY warmup probe timed out: {error}");
        }
    }

    if let Err(failures) = run_parallel_socks_echo_workload(client.addr, flow_count).await {
        eprintln!("xray server logs:\n{}", server.logs());
        eprintln!("xray client logs:\n{}", client.logs());
        panic!("{} parallel flow(s) failed: {failures:?}", failures.len());
    }

    drop(client);
    drop(server);
}

async fn run_local_xray_vless_interop_scenario(
    xray: XrayServer,
    rust_config: CoreConfig,
    transport_dialer: Option<TransportDialer>,
) {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = match transport_dialer {
        Some(dialer) => Core::with_runtime_dependencies(
            rust_config,
            Arc::new(SystemDnsResolver),
            Arc::new(dialer),
        ),
        None => Core::new(rust_config),
    }
    .expect("create rust core");

    timeout(Duration::from_secs(5), core.start())
        .await
        .expect("start rust core timeout")
        .expect("start rust core");
    let socks_addr = core
        .inbound_addr(Some("socks-in"))
        .expect("bound socks addr");

    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .expect("connect rust socks timeout")
        .expect("connect rust socks");
    match timeout(
        Duration::from_secs(5),
        socks5_connect(&mut client, echo_addr),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("socks connect failed: {error}");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("socks connect timeout: {error}");
        }
    }

    let payload = b"hello local xray interop";
    timeout(Duration::from_secs(5), client.write_all(payload))
        .await
        .expect("write payload timeout")
        .expect("write payload");
    let mut echoed = vec![0; payload.len()];
    match timeout(Duration::from_secs(15), client.read_exact(&mut echoed)).await {
        Ok(result) => {
            result.expect("read echo");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("read echo timeout: {error}");
        }
    }
    assert_eq!(echoed, payload);

    drop(client);
    core.stop().await.expect("stop rust core");
    drop(xray);
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .expect("echo task should finish")
        .expect("echo task should not panic");
}

async fn run_local_xray_vless_parallel_interop_scenario(
    xray: XrayServer,
    rust_config: CoreConfig,
    flow_count: usize,
) {
    let mut core = Core::new(rust_config).expect("create rust core");

    timeout(Duration::from_secs(5), core.start())
        .await
        .expect("start rust core timeout")
        .expect("start rust core");
    let socks_addr = core
        .inbound_addr(Some("socks-in"))
        .expect("bound socks addr");

    if let Err(failures) = run_parallel_socks_echo_workload(socks_addr, flow_count).await {
        core.stop().await.expect("stop rust core");
        eprintln!("{}", xray.logs());
        panic!("{} parallel flow(s) failed: {failures:?}", failures.len());
    }

    core.stop().await.expect("stop rust core");
    drop(xray);
}

async fn run_parallel_socks_echo_workload(
    socks_addr: SocketAddr,
    flow_count: usize,
) -> Result<(), Vec<String>> {
    let (echo_addr, echo_handle) = spawn_multi_echo_server(flow_count).await;
    let mut handles = Vec::with_capacity(flow_count);
    for index in 0..flow_count {
        handles.push(tokio::spawn(async move {
            run_socks_echo_flow(socks_addr, echo_addr, index).await
        }));
    }

    let mut failures = Vec::new();
    for handle in handles {
        match timeout(Duration::from_secs(20), handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => failures.push(error),
            Ok(Err(error)) => failures.push(format!("join flow task: {error}")),
            Err(error) => failures.push(format!("flow task timeout: {error}")),
        }
    }

    if !failures.is_empty() {
        echo_handle.abort();
        let _ = echo_handle.await;
        return Err(failures);
    }

    timeout(Duration::from_secs(5), echo_handle)
        .await
        .expect("multi echo task should finish")
        .expect("multi echo task should not panic");
    Ok(())
}

async fn run_rust_core_socks_echo_probe(rust_config: CoreConfig) -> Result<(), String> {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = match Core::new(rust_config) {
        Ok(core) => core,
        Err(error) => {
            echo_handle.abort();
            let _ = echo_handle.await;
            return Err(format!("create rust core: {error}"));
        }
    };

    match timeout(Duration::from_secs(10), core.start()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            echo_handle.abort();
            let _ = echo_handle.await;
            return Err(format!("start rust core: {error}"));
        }
        Err(error) => {
            echo_handle.abort();
            let _ = echo_handle.await;
            return Err(format!("start rust core timeout: {error}"));
        }
    }

    let result = match core.inbound_addr(Some("socks-in")) {
        Some(socks_addr) => run_socks_echo_flow(socks_addr, echo_addr, 0).await,
        None => Err("missing `socks-in` inbound after Core start".to_owned()),
    };
    let stop_result = core
        .stop()
        .await
        .map_err(|error| format!("stop rust core: {error}"));

    match result {
        Ok(()) => {
            timeout(Duration::from_secs(5), echo_handle)
                .await
                .map_err(|error| format!("echo task timeout: {error}"))?
                .map_err(|error| format!("echo task panic: {error}"))?;
        }
        Err(error) => {
            echo_handle.abort();
            let _ = echo_handle.await;
            stop_result?;
            return Err(error);
        }
    }

    stop_result
}

async fn run_socks_echo_probe(socks_addr: SocketAddr) -> Result<(), String> {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let result = run_socks_echo_flow(socks_addr, echo_addr, 0).await;

    match result {
        Ok(()) => {
            timeout(Duration::from_secs(5), echo_handle)
                .await
                .map_err(|error| format!("echo task timeout: {error}"))?
                .map_err(|error| format!("echo task panic: {error}"))?;
            Ok(())
        }
        Err(error) => {
            echo_handle.abort();
            let _ = echo_handle.await;
            Err(error)
        }
    }
}

async fn run_socks_echo_flow(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    index: usize,
) -> Result<(), String> {
    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .map_err(|error| format!("flow {index}: connect rust socks timeout: {error}"))?
        .map_err(|error| format!("flow {index}: connect rust socks: {error}"))?;
    timeout(
        Duration::from_secs(10),
        socks5_connect(&mut client, echo_addr),
    )
    .await
    .map_err(|error| format!("flow {index}: socks connect timeout: {error}"))?
    .map_err(|error| format!("flow {index}: socks connect: {error}"))?;

    let payload = format!("hello local xray burst flow {index}");
    timeout(Duration::from_secs(5), client.write_all(payload.as_bytes()))
        .await
        .map_err(|error| format!("flow {index}: write payload timeout: {error}"))?
        .map_err(|error| format!("flow {index}: write payload: {error}"))?;
    let mut echoed = vec![0; payload.len()];
    timeout(Duration::from_secs(15), client.read_exact(&mut echoed))
        .await
        .map_err(|error| format!("flow {index}: read echo timeout: {error}"))?
        .map_err(|error| format!("flow {index}: read echo: {error}"))?;
    if echoed != payload.as_bytes() {
        return Err(format!("flow {index}: echoed payload mismatch"));
    }

    Ok(())
}

struct TempDir {
    path: PathBuf,
}

struct XrayServer {
    child: Child,
    _temp_dir: TempDir,
    addr: SocketAddr,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    tls_client_config: Option<Arc<rustls::ClientConfig>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XrayInboundSecurity {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Copy)]
struct XrayVlessServerConfig {
    security: XrayInboundSecurity,
    flow: Option<&'static str>,
}

struct GeneratedTlsIdentity {
    cert_path: PathBuf,
    key_path: PathBuf,
    client_config: Arc<rustls::ClientConfig>,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

impl Drop for XrayServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl XrayServer {
    fn logs(&self) -> String {
        format!(
            "xray stdout:\n{}\nxray stderr:\n{}",
            fs::read_to_string(&self.stdout_path).unwrap_or_default(),
            fs::read_to_string(&self.stderr_path).unwrap_or_default()
        )
    }
}

fn resolve_xray_checkout() -> PathBuf {
    if let Some(path) = env::var_os("XRAY_CORE_CHECKOUT") {
        let path = PathBuf::from(path);
        assert!(
            path.join("go.mod").exists(),
            "XRAY_CORE_CHECKOUT must point at Xray-core"
        );
        return path;
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should be inside workspace/crates")
        .to_path_buf();
    let checkout = workspace_root.join("Xray-core");
    assert!(
        checkout.join("go.mod").exists(),
        "missing Xray-core checkout; set XRAY_CORE_CHECKOUT"
    );
    checkout
}

fn create_temp_dir(prefix: &str) -> TempDir {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();

    for attempt in 0..16 {
        let path = env::temp_dir().join(format!("{prefix}-{}-{now}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return TempDir { path },
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create temp dir {path:?}: {error}"),
        }
    }

    panic!("failed to create unique temp dir for {prefix}");
}

fn allocate_loopback_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn generate_tls_identity(temp_dir: &TempDir, server_name: &str) -> GeneratedTlsIdentity {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![server_name.to_owned()])
            .expect("generate self-signed certificate");
    let cert_der = cert.der().clone();
    let key_der = signing_key.serialize_der();
    let cert_path = temp_dir.path.join("server.crt.pem");
    let key_path = temp_dir.path.join("server.key.pem");

    fs::write(&cert_path, pem_block("CERTIFICATE", cert_der.as_ref())).expect("write tls cert");
    fs::write(&key_path, pem_block("PRIVATE KEY", &key_der)).expect("write tls key");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add generated cert root");
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider should support default TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();

    GeneratedTlsIdentity {
        cert_path,
        key_path,
        client_config: Arc::new(client_config),
    }
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let encoded = base64_standard(der);
    let mut pem = String::with_capacity(encoded.len() + label.len() * 2 + 32);
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is utf8"));
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

        output.push(TABLE[(b0 >> 2) as usize] as char);
        output.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn write_xray_vless_config(
    path: &Path,
    port: u16,
    server_config: &XrayVlessServerConfig,
    tls_identity: Option<&GeneratedTlsIdentity>,
) {
    let client = match server_config.flow {
        Some(flow) => format!(r#"{{ "id": "{TEST_UUID}", "flow": "{flow}" }}"#),
        None => format!(r#"{{ "id": "{TEST_UUID}" }}"#),
    };
    let stream_settings = match server_config.security {
        XrayInboundSecurity::None => String::new(),
        XrayInboundSecurity::Tls => {
            let identity = tls_identity.expect("TLS config requires generated identity");
            let cert_path = identity.cert_path.to_string_lossy();
            let key_path = identity.key_path.to_string_lossy();
            format!(
                r#",
      "streamSettings": {{
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {{
          "certificates": [
            {{
              "certificateFile": "{cert_path}",
              "keyFile": "{key_path}"
            }}
          ]
        }}
      }}"#
            )
        }
        XrayInboundSecurity::Reality => format!(
            r#",
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
      }}"#
        ),
    };
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {port},
      "protocol": "vless",
      "settings": {{
        "clients": [{client}],
        "decryption": "none"
      }}{stream_settings}
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
    );
    fs::write(path, config).expect("write xray config");
}

fn write_xray_vless_client_config(
    path: &Path,
    socks_port: u16,
    server_addr: SocketAddr,
    fingerprint: &str,
) {
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": {socks_port},
      "protocol": "socks"
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
                "id": "{TEST_UUID}",
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
          "publicKey": "{REALITY_PUBLIC_KEY_BASE64}",
          "shortId": "{REALITY_SHORT_ID_HEX}",
          "spiderX": "/"
        }}
      }}
    }}
  ]
}}"#,
        server_addr.ip(),
        server_addr.port()
    );
    fs::write(path, config).expect("write xray client config");
}

async fn start_xray_vless_server(
    xray_checkout: &Path,
    server_config: XrayVlessServerConfig,
) -> XrayServer {
    let temp_dir = create_temp_dir("xray-rust-local-interop");
    let binary = temp_dir
        .path
        .join(format!("xray{}", env::consts::EXE_SUFFIX));
    let config_path = temp_dir.path.join("server.json");
    let stdout_path = temp_dir.path.join("xray.stdout.log");
    let stderr_path = temp_dir.path.join("xray.stderr.log");
    let port = allocate_loopback_port();
    let tls_identity = match server_config.security {
        XrayInboundSecurity::None => None,
        XrayInboundSecurity::Tls => Some(generate_tls_identity(&temp_dir, TLS_SERVER_NAME)),
        XrayInboundSecurity::Reality => None,
    };
    let tls_client_config = tls_identity
        .as_ref()
        .map(|identity| Arc::clone(&identity.client_config));
    write_xray_vless_config(&config_path, port, &server_config, tls_identity.as_ref());

    let build_output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&binary)
        .arg("./main")
        .current_dir(xray_checkout)
        .output()
        .expect("start go build for Xray-core");
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
            fs::File::create(&stdout_path).expect("create xray stdout log"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("create xray stderr log"),
        ))
        .spawn()
        .expect("start xray process");

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    wait_for_tcp_listener(&mut child, addr, &stdout_path, &stderr_path).await;

    XrayServer {
        child,
        _temp_dir: temp_dir,
        addr,
        stdout_path,
        stderr_path,
        tls_client_config,
    }
}

async fn start_xray_vless_client(
    xray_checkout: &Path,
    server_addr: SocketAddr,
    fingerprint: &str,
) -> XrayServer {
    let temp_dir = create_temp_dir("xray-core-client-local-interop");
    let binary = temp_dir
        .path
        .join(format!("xray{}", env::consts::EXE_SUFFIX));
    let config_path = temp_dir.path.join("client.json");
    let stdout_path = temp_dir.path.join("xray-client.stdout.log");
    let stderr_path = temp_dir.path.join("xray-client.stderr.log");
    let port = allocate_loopback_port();
    write_xray_vless_client_config(&config_path, port, server_addr, fingerprint);

    let build_output = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&binary)
        .arg("./main")
        .current_dir(xray_checkout)
        .output()
        .expect("start go build for Xray-core client");
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
        .expect("start xray client process");

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    wait_for_tcp_listener(&mut child, addr, &stdout_path, &stderr_path).await;

    XrayServer {
        child,
        _temp_dir: temp_dir,
        addr,
        stdout_path,
        stderr_path,
        tls_client_config: None,
    }
}

async fn wait_for_tcp_listener(
    child: &mut Child,
    addr: SocketAddr,
    stdout_path: &Path,
    stderr_path: &Path,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("check xray process status") {
            let stdout = fs::read_to_string(stdout_path).unwrap_or_default();
            let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
            panic!(
                "xray exited before listening on {addr}: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
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
            Err(error) => panic!("xray did not listen on {addr}: {error}"),
        }
    }
}

fn rust_core_config_with_security(
    xray_addr: SocketAddr,
    security: StreamSecurity,
    flow: Option<&str>,
) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![OutboundConfig {
            tag: Some("proxy".to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                security,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(xray_addr.ip()),
                port: xray_addr.port(),
                users: vec![VlessUser {
                    id: TEST_UUID.parse().expect("static uuid"),
                    encryption: "none".to_owned(),
                    flow: flow.map(ToOwned::to_owned),
                    level: 0,
                }],
            }),
        }],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn rust_reality_vision_core_config(xray_addr: SocketAddr, fingerprint: &str) -> CoreConfig {
    rust_core_config_with_security(
        xray_addr,
        StreamSecurity::Reality(RealitySettings {
            server_name: REALITY_SERVER_NAME.to_owned(),
            fingerprint: fingerprint.to_owned(),
            public_key: REALITY_PUBLIC_KEY,
            short_id: RealityShortId::try_from_slice(&REALITY_SHORT_ID)
                .expect("static REALITY short id"),
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        }),
        Some("xtls-rprx-vision"),
    )
}

async fn spawn_inner_tls_echo_server() -> (
    SocketAddr,
    Arc<rustls::ClientConfig>,
    tokio::task::JoinHandle<()>,
) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![INNER_TLS_SERVER_NAME.to_owned()])
            .expect("generate inner tls certificate");
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
    );

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add inner tls root");
    let client_config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider should support default TLS versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("inner tls server certificate");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind inner tls echo");
    let addr = listener.local_addr().expect("inner tls echo local addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept inner tls client");
        let mut stream = acceptor.accept(stream).await.expect("inner tls handshake");
        let mut buffer = [0; 4096];
        loop {
            let read = match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            if stream.write_all(&buffer[..read]).await.is_err() {
                break;
            }
            if stream.flush().await.is_err() {
                break;
            }
        }
    });
    (addr, client_config, handle)
}

async fn spawn_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo");
    let addr = listener.local_addr().expect("echo local addr");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept echo");
        let (mut read_half, mut write_half) = stream.split();
        tokio::io::copy(&mut read_half, &mut write_half)
            .await
            .expect("echo copy");
    });
    (addr, handle)
}

async fn spawn_multi_echo_server(
    expected_connections: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo");
    let addr = listener.local_addr().expect("echo local addr");
    let handle = tokio::spawn(async move {
        let mut handles = Vec::with_capacity(expected_connections);
        for _ in 0..expected_connections {
            let (mut stream, _) = listener.accept().await.expect("accept echo");
            handles.push(tokio::spawn(async move {
                let (mut read_half, mut write_half) = stream.split();
                tokio::io::copy(&mut read_half, &mut write_half)
                    .await
                    .expect("echo copy");
            }));
        }
        for handle in handles {
            handle.await.expect("echo connection task should not panic");
        }
    });
    (addr, handle)
}

async fn socks5_connect(client: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
    let SocketAddr::V4(target) = target else {
        return Err("local interop test uses IPv4 targets only".to_owned());
    };

    client
        .write_all(&[5, 1, 0])
        .await
        .map_err(|error| format!("write socks greeting: {error}"))?;
    let mut method = [0; 2];
    client
        .read_exact(&mut method)
        .await
        .map_err(|error| format!("read socks method: {error}"))?;
    if method != [5, 0] {
        return Err(format!("unexpected socks method reply: {method:?}"));
    }

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client
        .write_all(&request)
        .await
        .map_err(|error| format!("write socks connect: {error}"))?;

    let mut reply_header = [0; 4];
    client
        .read_exact(&mut reply_header)
        .await
        .map_err(|error| format!("read socks reply: {error}"))?;
    if reply_header[0] != 5 || reply_header[2] != 0 {
        return Err(format!("unexpected socks connect reply: {reply_header:?}"));
    }
    if reply_header[1] != 0 {
        return Err(format!("socks connect rejected: {reply_header:?}"));
    }

    match reply_header[3] {
        1 => {
            let mut bind = [0; 6];
            client
                .read_exact(&mut bind)
                .await
                .map_err(|error| format!("read socks IPv4 bind: {error}"))?;
        }
        3 => {
            let mut len = [0; 1];
            client
                .read_exact(&mut len)
                .await
                .map_err(|error| format!("read socks domain bind length: {error}"))?;
            let mut bind = vec![0; usize::from(len[0]) + 2];
            client
                .read_exact(&mut bind)
                .await
                .map_err(|error| format!("read socks domain bind: {error}"))?;
        }
        4 => {
            let mut bind = [0; 18];
            client
                .read_exact(&mut bind)
                .await
                .map_err(|error| format!("read socks IPv6 bind: {error}"))?;
        }
        address_type => {
            return Err(format!(
                "unsupported socks bind address type {address_type}"
            ));
        }
    }

    Ok(())
}
