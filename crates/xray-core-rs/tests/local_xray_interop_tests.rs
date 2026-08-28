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
    CoreConfig, GrpcSettings, HttpUpgradeSettings, InboundConfig, InboundProtocol, Network,
    OutboundConfig, OutboundSettings, RealitySettings, RealityShortId, RoutingConfig,
    StreamSecurity, StreamSettings, StreamTransport, TargetAddr, TlsSettings,
    VlessOutboundSettings, VlessUser, WebSocketSettings, XhttpMode, XhttpSettings,
    XhttpUplinkDataPlacement, XhttpXmuxSettings,
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
                transport: XrayInboundTransport::Raw,
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
                transport: XrayInboundTransport::Raw,
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
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
        }),
        flow,
    );
    let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
        tls_client_config,
    ));

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
        "hellochrome_133",
        "hellofirefox_148",
        "hellosafari_26_3",
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

/// Drives one echo flow through `probe_config` before the scenario proper, so
/// the Go REALITY listener's first, slow contact with the real `dest` is not
/// on the clock the scenario is measured against.
///
/// **The config is a parameter rather than built here**, which it was until
/// gRPC arrived: the built one was a Vision one, so a scenario over any other
/// stream transport would have warmed the server up by dialling a profile the
/// inbound does not serve, and failed in the warmup with the scenario's own
/// pairing never tried.
async fn warm_up_reality_server_detector(xray: &XrayServer, probe_config: CoreConfig) {
    let warmup_timeout = selected_reality_server_warmup_timeout();
    let first = timeout(
        warmup_timeout,
        run_rust_core_socks_echo_probe(probe_config.clone()),
    )
    .await;
    if matches!(first, Ok(Ok(()))) {
        return;
    }

    // The first connection is intentionally the one that makes Xray contact
    // the live cover origin and train its REALITY detector. That connection
    // may be consumed by detector warm-up and end with an early EOF even
    // though the listener is ready for the next client. Require a fresh probe
    // to pass; a persistent protocol failure still fails the test.
    eprintln!("REALITY detector warmup did not complete on the first probe; retrying once");
    match timeout(warmup_timeout, run_rust_core_socks_echo_probe(probe_config)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("REALITY server warmup retry failed after {first:?}: {error}");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("REALITY server warmup retry timed out after {first:?}: {error}");
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
                transport: XrayInboundTransport::Raw,
                flow: Some("xtls-rprx-vision"),
            },
        ),
    )
    .await
    .expect("start xray timeout");
    warm_up_reality_server_detector(
        &xray,
        rust_reality_vision_core_config(xray.addr, fingerprint),
    )
    .await;
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
                transport: XrayInboundTransport::Raw,
                flow: Some("xtls-rprx-vision"),
            },
        ),
    )
    .await
    .expect("start xray timeout");
    warm_up_reality_server_detector(
        &xray,
        rust_reality_vision_core_config(xray.addr, fingerprint),
    )
    .await;
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

    let client = open_socks_flow(&xray, socks_addr, tls_echo_addr).await;

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
                transport: XrayInboundTransport::Raw,
                flow: Some("xtls-rprx-vision"),
            },
        ),
    )
    .await
    .expect("start xray timeout");
    warm_up_reality_server_detector(
        &xray,
        rust_reality_vision_core_config(xray.addr, fingerprint),
    )
    .await;
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
                transport: XrayInboundTransport::Raw,
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

    let mut client = open_socks_flow(&xray, socks_addr, echo_addr).await;

    let payload = b"hello local xray interop";
    timeout(Duration::from_secs(5), client.write_all(payload))
        .await
        .expect("write payload timeout")
        .expect("write payload");
    let mut echoed = vec![0; payload.len()];
    match timeout(Duration::from_secs(15), client.read_exact(&mut echoed)).await {
        Ok(Ok(_)) => {}
        // A tunnel the far side tore down arrives here as a bare
        // `UnexpectedEof`, which names nothing; whatever the Go process
        // thought is in its log. Printed on this arm as well as the timeout
        // one, or every such failure costs a rerun to find out anything.
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("read echo failed: {error}");
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

async fn run_parallel_socks_exact_echo_workload(
    socks_addr: SocketAddr,
    flow_count: usize,
) -> Result<(), Vec<String>> {
    const PAYLOAD_BYTES: usize = 4 * 1024;

    let (echo_addr, echo_handle) = spawn_multi_exact_echo_server(flow_count, PAYLOAD_BYTES).await;
    let mut handles = Vec::with_capacity(flow_count);
    for index in 0..flow_count {
        handles.push(tokio::spawn(async move {
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

            let payload = bulk_interop_payload(PAYLOAD_BYTES);
            timeout(Duration::from_secs(10), client.write_all(&payload))
                .await
                .map_err(|error| format!("flow {index}: write payload timeout: {error}"))?
                .map_err(|error| format!("flow {index}: write payload: {error}"))?;
            let mut echoed = vec![0; payload.len()];
            timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
                .await
                .map_err(|error| format!("flow {index}: read echo timeout: {error}"))?
                .map_err(|error| format!("flow {index}: read echo: {error}"))?;
            if echoed != payload {
                return Err(format!("flow {index}: echoed payload mismatch"));
            }
            Ok(())
        }));
    }

    let mut failures = Vec::new();
    for handle in handles {
        match timeout(Duration::from_secs(30), handle).await {
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
        .expect("multi exact echo task should finish")
        .expect("multi exact echo task should not panic");
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

/// The stream transport the Go inbound is configured with.
///
/// Which of these may be paired with `XrayInboundSecurity::Reality` is not a
/// free choice: Xray allows REALITY over `tcp`, `splithttp` and `grpc` and
/// refuses everything else with "REALITY only supports RAW, XHTTP and gRPC for
/// now" (`Xray-core/infra/conf/transport_internet.go:1989`). So the pairing is
/// unreachable for the two HTTP/1.1 transports below and reachable for
/// [`Self::Xhttp`] and [`Self::Grpc`], which is the rule the compatibility
/// matrix reproduces.
#[derive(Debug, Clone, Copy)]
enum XrayInboundTransport {
    Raw,
    WebSocket {
        path: &'static str,
    },
    HttpUpgrade {
        path: &'static str,
    },
    Xhttp {
        path: &'static str,
        mode: &'static str,
        /// Exact server ALPN for the TLS H1/H2 interop matrix. REALITY ignores
        /// this because Xray's version decision always selects HTTP/2 there.
        tls_alpn: Option<&'static str>,
    },
    /// `multiMode` is deliberately not a field. The listener never reads it:
    /// it registers both stream names on one service descriptor —
    /// `getTunStreamName()` and `getTunMultiStreamName()`, i.e. `Tun` and
    /// `TunMulti` for a name without a leading `/`
    /// (`Xray-core/transport/internet/grpc/hub.go:128`,
    /// `encoding/customSeviceName.go:9-30,57-60`) — so a server config
    /// carrying it would document a requirement that does not exist.
    Grpc {
        service_name: &'static str,
    },
}

#[derive(Debug, Clone, Copy)]
struct XrayVlessServerConfig {
    security: XrayInboundSecurity,
    transport: XrayInboundTransport,
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
        assert_xray_checkout_revision(&path);
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
    assert_xray_checkout_revision(&checkout);
    checkout
}

fn assert_xray_checkout_revision(checkout: &Path) {
    const EXPECTED: &str = "5ca6f4b7d4dc20a881d4330e498892697627ec0c";
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(checkout)
        .output()
        .expect("read Xray-core checkout revision");
    assert!(
        output.status.success(),
        "git rev-parse failed for Xray-core"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        EXPECTED,
        "Xray-core interop checkout must be pinned to v26.7.28"
    );
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

fn allocate_loopback_udp_port() -> u16 {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral UDP port")
        .local_addr()
        .expect("read local UDP addr")
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
    // The network and its settings block come from the transport, the security
    // block from the security. A raw, unsecured inbound keeps emitting no
    // streamSettings at all, which is what the pre-existing scenarios expect.
    let (network, transport_settings) = match server_config.transport {
        XrayInboundTransport::Raw => ("tcp", String::new()),
        XrayInboundTransport::WebSocket { path } => (
            "ws",
            format!(
                r#",
        "wsSettings": {{ "path": "{path}" }}"#
            ),
        ),
        XrayInboundTransport::HttpUpgrade { path } => (
            "httpupgrade",
            format!(
                r#",
        "httpupgradeSettings": {{ "path": "{path}" }}"#
            ),
        ),
        XrayInboundTransport::Xhttp { path, mode, .. } => (
            "xhttp",
            format!(
                r#",
        "xhttpSettings": {{
          "path": "{path}",
          "mode": "{mode}",
          "xPaddingBytes": 64,
          "uplinkHTTPMethod": "POST",
          "sessionIDPlacement": "path",
          "seqPlacement": "path",
          "uplinkDataPlacement": "body",
          "uplinkChunkSize": 4096,
          "scMaxEachPostBytes": 4096,
          "scMinPostsIntervalMs": 1,
          "xmux": {{
            "maxConcurrency": 1,
            "hMaxRequestTimes": 64,
            "hMaxReusableSecs": 3600
          }}
        }}"#
            ),
        ),
        // `network` is the only mandatory half: `grpcSettings` is an optional
        // pointer (`Xray-core/infra/conf/transport_internet.go:1950,2044`) and
        // every field in it has a usable zero — an absent block leaves
        // `serviceName` empty, which serves `//Tun`. It is pinned anyway so a
        // successful flow says something about the `:path` we built.
        XrayInboundTransport::Grpc { service_name } => (
            "grpc",
            format!(
                r#",
        "grpcSettings": {{ "serviceName": "{service_name}" }}"#
            ),
        ),
    };
    let security_settings = match server_config.security {
        XrayInboundSecurity::None => r#""security": "none""#.to_owned(),
        XrayInboundSecurity::Tls => {
            let identity = tls_identity.expect("TLS config requires generated identity");
            let cert_path = identity.cert_path.to_string_lossy();
            let key_path = identity.key_path.to_string_lossy();
            let alpn = match server_config.transport {
                XrayInboundTransport::Xhttp {
                    tls_alpn: Some(alpn),
                    ..
                } => format!(r#""alpn": ["{alpn}"],"#),
                _ => String::new(),
            };
            format!(
                r#""security": "tls",
        "tlsSettings": {{
          {alpn}
          "certificates": [
            {{
              "certificateFile": "{cert_path}",
              "keyFile": "{key_path}"
            }}
          ]
        }}"#
            )
        }
        XrayInboundSecurity::Reality => format!(
            r#""security": "reality",
        "realitySettings": {{
          "show": true,
          "dest": "{REALITY_SERVER_NAME}:443",
          "serverNames": ["{REALITY_SERVER_NAME}"],
          "privateKey": "{REALITY_PRIVATE_KEY}",
          "shortIds": ["{REALITY_SHORT_ID_HEX}"],
          "type": "tcp"
        }}"#
        ),
    };
    let stream_settings = if matches!(server_config.transport, XrayInboundTransport::Raw)
        && matches!(server_config.security, XrayInboundSecurity::None)
    {
        String::new()
    } else {
        format!(
            r#",
      "streamSettings": {{
        "network": "{network}",
        {security_settings}{transport_settings}
      }}"#
        )
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
    let uses_udp_listener = matches!(
        server_config.transport,
        XrayInboundTransport::Xhttp {
            tls_alpn: Some("h3"),
            ..
        }
    );
    let port = if uses_udp_listener {
        allocate_loopback_udp_port()
    } else {
        allocate_loopback_port()
    };
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
    if uses_udp_listener {
        wait_for_udp_listener(&mut child, addr, &stdout_path, &stderr_path).await;
    } else {
        wait_for_tcp_listener(&mut child, addr, &stdout_path, &stderr_path).await;
    }

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

async fn wait_for_udp_listener(
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
                "xray exited before listening on UDP {addr}: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        }

        match std::net::UdpSocket::bind(addr) {
            Err(error) if error.kind() == ErrorKind::AddrInUse => return,
            Ok(probe) if Instant::now() < deadline => {
                drop(probe);
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(50)).await;
            }
            Ok(probe) => {
                drop(probe);
                let stdout = fs::read_to_string(stdout_path).unwrap_or_default();
                let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
                panic!("xray did not bind UDP {addr}\nstdout:\n{stdout}\nstderr:\n{stderr}");
            }
            Err(error) => panic!("could not probe Xray UDP listener {addr}: {error}"),
        }
    }
}

fn rust_core_config_with_security(
    xray_addr: SocketAddr,
    security: StreamSecurity,
    flow: Option<&str>,
) -> CoreConfig {
    rust_core_config_with_transport(xray_addr, security, flow, StreamTransport::Raw)
}

fn rust_core_config_with_transport(
    xray_addr: SocketAddr,
    security: StreamSecurity,
    flow: Option<&str>,
    transport: StreamTransport,
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
                transport,
                security,
                quic_params: None,
                socket_options: None,
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
        reality_security(fingerprint),
        Some("xtls-rprx-vision"),
    )
}

/// The client half of the REALITY inbound `start_xray_vless_server` writes.
///
/// Extracted from `rust_reality_vision_core_config` when gRPC needed the same
/// settings without the flow: that helper hardcodes `xtls-rprx-vision`, and
/// Vision cannot ride gRPC.
fn reality_security(fingerprint: &str) -> StreamSecurity {
    StreamSecurity::Reality(RealitySettings {
        server_name: REALITY_SERVER_NAME.to_owned(),
        fingerprint: fingerprint.to_owned(),
        public_key: REALITY_PUBLIC_KEY,
        short_id: RealityShortId::try_from_slice(&REALITY_SHORT_ID)
            .expect("static REALITY short id"),
        spider_x: "/".to_owned(),
        mldsa65_verify: None,
    })
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

async fn spawn_exact_echo_server(
    expected_bytes: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind exact echo");
    let addr = listener.local_addr().expect("exact echo local addr");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept exact echo");
        let mut payload = vec![0; expected_bytes];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read exact echo payload");
        stream
            .write_all(&payload)
            .await
            .expect("write exact echo payload");
        stream.flush().await.expect("flush exact echo payload");
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

async fn spawn_multi_exact_echo_server(
    expected_connections: usize,
    expected_bytes: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind multi exact echo");
    let addr = listener.local_addr().expect("multi exact echo local addr");
    let handle = tokio::spawn(async move {
        let mut handles = Vec::with_capacity(expected_connections);
        for _ in 0..expected_connections {
            let (mut stream, _) = listener.accept().await.expect("accept exact echo");
            handles.push(tokio::spawn(async move {
                let mut payload = vec![0; expected_bytes];
                stream
                    .read_exact(&mut payload)
                    .await
                    .expect("read multi exact echo payload");
                stream
                    .write_all(&payload)
                    .await
                    .expect("write multi exact echo payload");
                stream
                    .flush()
                    .await
                    .expect("flush multi exact echo payload");
            }));
        }
        for handle in handles {
            handle
                .await
                .expect("exact echo connection task should not panic");
        }
    });
    (addr, handle)
}

/// Opens one SOCKS flow at `socks_addr` and asks it for `target`, printing the
/// Go process's log if either step fails.
///
/// Two scenario runners had this verbatim before the gRPC bulk one would have
/// been a third. The parallel runner's version is a Result-returning form that
/// names the flow it belongs to, so it is not one of them.
async fn open_socks_flow(
    xray: &XrayServer,
    socks_addr: SocketAddr,
    target: SocketAddr,
) -> TcpStream {
    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .expect("connect rust socks timeout")
        .expect("connect rust socks");
    match timeout(Duration::from_secs(5), socks5_connect(&mut client, target)).await {
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
    client
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

// ---- ws and httpupgrade -----------------------------------------------------
//
// The wire format for both transports is asserted against our own reading of
// Xray in the unit tests; these prove it against the reference implementation
// itself, which is the only place a divergence in header order, frame
// boundaries or early-data encoding actually shows up.

const WS_PATH: &str = "/interop-ws";
const HTTPUPGRADE_PATH: &str = "/interop-upgrade";

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_ws() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_stream_transport_interop(
            XrayInboundTransport::WebSocket { path: WS_PATH },
            StreamTransport::WebSocket(WebSocketSettings {
                path: WS_PATH.to_owned(),
                ..WebSocketSettings::default()
            }),
            false,
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_tls() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_stream_transport_interop(
            XrayInboundTransport::WebSocket { path: WS_PATH },
            StreamTransport::WebSocket(WebSocketSettings {
                path: WS_PATH.to_owned(),
                ..WebSocketSettings::default()
            }),
            true,
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_early_data() {
    // The VLESS request header plus the first payload is well under 2 KiB, so
    // this exercises the path where the whole first write travels inside
    // Sec-WebSocket-Protocol and no frame is sent for it.
    timeout(
        Duration::from_secs(120),
        run_local_xray_stream_transport_interop(
            XrayInboundTransport::WebSocket {
                path: "/interop-ws?ed=2048",
            },
            StreamTransport::WebSocket(WebSocketSettings {
                path: WS_PATH.to_owned(),
                early_data_bytes: 2048,
                ..WebSocketSettings::default()
            }),
            false,
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_stream_transport_interop(
            XrayInboundTransport::HttpUpgrade {
                path: HTTPUPGRADE_PATH,
            },
            StreamTransport::HttpUpgrade(HttpUpgradeSettings {
                path: HTTPUPGRADE_PATH.to_owned(),
                ..HttpUpgradeSettings::default()
            }),
            false,
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_early_data() {
    // Xray's outbound uses `ed` to return before the 101, but its inbound can
    // leave application bytes that arrived with the upgrade request stranded
    // in a bufio.Reader. We intentionally wait for the response: the config is
    // accepted, and the real-Xray round trip pins that no VLESS bytes are lost.
    timeout(
        Duration::from_secs(120),
        run_local_xray_stream_transport_interop(
            XrayInboundTransport::HttpUpgrade {
                path: "/interop-upgrade?ed=2048",
            },
            StreamTransport::HttpUpgrade(HttpUpgradeSettings {
                path: HTTPUPGRADE_PATH.to_owned(),
                early_data_bytes: 2048,
                ..HttpUpgradeSettings::default()
            }),
            false,
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_tls() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_stream_transport_interop(
            XrayInboundTransport::HttpUpgrade {
                path: HTTPUPGRADE_PATH,
            },
            StreamTransport::HttpUpgrade(HttpUpgradeSettings {
                path: HTTPUPGRADE_PATH.to_owned(),
                ..HttpUpgradeSettings::default()
            }),
            true,
        ),
    )
    .await
    .unwrap();
}

async fn run_local_xray_stream_transport_interop(
    inbound: XrayInboundTransport,
    outbound: StreamTransport,
    over_tls: bool,
) {
    let xray_checkout = resolve_xray_checkout();
    let security = if over_tls {
        XrayInboundSecurity::Tls
    } else {
        XrayInboundSecurity::None
    };
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security,
                transport: inbound,
                // Vision cannot ride these transports; the compatibility
                // matrix refuses the pairing on both sides.
                flow: None,
            },
        ),
    )
    .await
    .expect("start xray timeout");

    let (client_security, dialer) = if over_tls {
        (
            StreamSecurity::Tls(TlsSettings {
                server_name: Some(TLS_SERVER_NAME.to_owned()),
                // Use the production shaping path here. A pinned rustls config
                // bypasses both fingerprint shaping and the transport-aware
                // ALPN gate, so it cannot catch an h2 selection followed by an
                // HTTP/1.1 WebSocket/Upgrade request.
                fingerprint: Some("chrome".to_owned()),
                allow_insecure: true,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
            }),
            None,
        )
    } else {
        (StreamSecurity::None, None)
    };

    let rust_config = rust_core_config_with_transport(xray.addr, client_security, None, outbound);
    run_local_xray_vless_interop_scenario(xray, rust_config, dialer).await;
}

// ---- xhttp -----------------------------------------------------------------

const XHTTP_PATH: &str = "/interop-xhttp/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XhttpInteropSecurity {
    H1None,
    H1Tls,
    H2Tls,
    H2Reality,
    H3Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XhttpInteropCase {
    id: &'static str,
    security: XhttpInteropSecurity,
    mode: XhttpMode,
}

const XHTTP_INTEROP_CASES: [XhttpInteropCase; 15] = [
    XhttpInteropCase {
        id: "h1-none-packet-up",
        security: XhttpInteropSecurity::H1None,
        mode: XhttpMode::PacketUp,
    },
    XhttpInteropCase {
        id: "h1-none-stream-up",
        security: XhttpInteropSecurity::H1None,
        mode: XhttpMode::StreamUp,
    },
    XhttpInteropCase {
        id: "h1-none-stream-one",
        security: XhttpInteropSecurity::H1None,
        mode: XhttpMode::StreamOne,
    },
    XhttpInteropCase {
        id: "h1-tls-packet-up",
        security: XhttpInteropSecurity::H1Tls,
        mode: XhttpMode::PacketUp,
    },
    XhttpInteropCase {
        id: "h1-tls-stream-up",
        security: XhttpInteropSecurity::H1Tls,
        mode: XhttpMode::StreamUp,
    },
    XhttpInteropCase {
        id: "h1-tls-stream-one",
        security: XhttpInteropSecurity::H1Tls,
        mode: XhttpMode::StreamOne,
    },
    XhttpInteropCase {
        id: "h2-tls-packet-up",
        security: XhttpInteropSecurity::H2Tls,
        mode: XhttpMode::PacketUp,
    },
    XhttpInteropCase {
        id: "h2-tls-stream-up",
        security: XhttpInteropSecurity::H2Tls,
        mode: XhttpMode::StreamUp,
    },
    XhttpInteropCase {
        id: "h2-tls-stream-one",
        security: XhttpInteropSecurity::H2Tls,
        mode: XhttpMode::StreamOne,
    },
    XhttpInteropCase {
        id: "h2-reality-packet-up",
        security: XhttpInteropSecurity::H2Reality,
        mode: XhttpMode::PacketUp,
    },
    XhttpInteropCase {
        id: "h2-reality-stream-up",
        security: XhttpInteropSecurity::H2Reality,
        mode: XhttpMode::StreamUp,
    },
    XhttpInteropCase {
        id: "h2-reality-stream-one",
        security: XhttpInteropSecurity::H2Reality,
        mode: XhttpMode::StreamOne,
    },
    XhttpInteropCase {
        id: "h3-tls-packet-up",
        security: XhttpInteropSecurity::H3Tls,
        mode: XhttpMode::PacketUp,
    },
    XhttpInteropCase {
        id: "h3-tls-stream-up",
        security: XhttpInteropSecurity::H3Tls,
        mode: XhttpMode::StreamUp,
    },
    XhttpInteropCase {
        id: "h3-tls-stream-one",
        security: XhttpInteropSecurity::H3Tls,
        mode: XhttpMode::StreamOne,
    },
];

/// Runs every reachable H1/H2/H3 security × upload-mode pairing by default:
/// cleartext H1, TLS-pinned H1/H2/H3, and REALITY H2.
/// `XRAY_XHTTP_INTEROP_CASES` may select a comma-separated subset by the
/// stable ids above; `all` is accepted only by itself. Keeping the selection
/// inside one ignored test prevents `cargo test --ignored` from launching a
/// process per matrix row and overlapping the REALITY cover-origin probes.
#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases() {
    timeout(Duration::from_secs(3_600), async {
        for case in selected_xhttp_interop_cases() {
            eprintln!("running XHTTP interop case={}", case.id);
            timeout(Duration::from_secs(180), run_local_xray_xhttp_interop(case))
                .await
                .unwrap_or_else(|error| panic!("XHTTP case {} timed out: {error}", case.id));
        }
    })
    .await
    .expect("the selected XHTTP matrix completes");
}

fn selected_xhttp_interop_cases() -> Vec<XhttpInteropCase> {
    let Ok(raw) = env::var("XRAY_XHTTP_INTEROP_CASES") else {
        return XHTTP_INTEROP_CASES.to_vec();
    };
    let requested: Vec<_> = raw.split(',').map(str::trim).collect();
    assert!(
        !requested.is_empty() && requested.iter().all(|id| !id.is_empty()),
        "XRAY_XHTTP_INTEROP_CASES must not be empty"
    );
    if requested == ["all"] {
        return XHTTP_INTEROP_CASES.to_vec();
    }
    assert!(
        !requested.contains(&"all"),
        "XRAY_XHTTP_INTEROP_CASES=all cannot be combined with case ids"
    );

    let mut selected = Vec::with_capacity(requested.len());
    for id in requested {
        let case = XHTTP_INTEROP_CASES
            .iter()
            .find(|case| case.id == id)
            .copied()
            .unwrap_or_else(|| panic!("unknown XRAY_XHTTP_INTEROP_CASES id {id:?}"));
        assert!(
            !selected.contains(&case),
            "duplicate XRAY_XHTTP_INTEROP_CASES id {id:?}"
        );
        selected.push(case);
    }
    selected
}

async fn run_local_xray_xhttp_interop(case: XhttpInteropCase) {
    let xray_checkout = resolve_xray_checkout();
    let (server_security, tls_alpn, client_security) = match case.security {
        XhttpInteropSecurity::H1None => (XrayInboundSecurity::None, None, StreamSecurity::None),
        XhttpInteropSecurity::H1Tls => (
            XrayInboundSecurity::Tls,
            Some("http/1.1"),
            StreamSecurity::Tls(TlsSettings {
                server_name: Some(TLS_SERVER_NAME.to_owned()),
                fingerprint: Some("chrome".to_owned()),
                allow_insecure: true,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: vec!["http/1.1".to_owned()],
            }),
        ),
        XhttpInteropSecurity::H2Tls => (
            XrayInboundSecurity::Tls,
            Some("h2"),
            StreamSecurity::Tls(TlsSettings {
                server_name: Some(TLS_SERVER_NAME.to_owned()),
                fingerprint: Some("chrome".to_owned()),
                allow_insecure: true,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: vec!["h2".to_owned()],
            }),
        ),
        XhttpInteropSecurity::H2Reality => (
            XrayInboundSecurity::Reality,
            None,
            reality_security("chrome"),
        ),
        XhttpInteropSecurity::H3Tls => (
            XrayInboundSecurity::Tls,
            Some("h3"),
            StreamSecurity::Tls(TlsSettings {
                server_name: Some(TLS_SERVER_NAME.to_owned()),
                fingerprint: Some("chrome".to_owned()),
                allow_insecure: true,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: vec!["h3".to_owned()],
            }),
        ),
    };
    let mode = xhttp_mode_name(case.mode);
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security: server_security,
                transport: XrayInboundTransport::Xhttp {
                    path: XHTTP_PATH,
                    mode,
                    tls_alpn,
                },
                flow: None,
            },
        ),
    )
    .await
    .expect("start XHTTP Xray server timeout");

    let rust_config = rust_xhttp_core_config(xray.addr, client_security, case.mode);
    if case.security == XhttpInteropSecurity::H2Reality {
        // The first REALITY contact may wait for the cover-origin detector.
        // Warm it with the exact XHTTP mode being tested, never with the raw
        // Vision helper whose transport this inbound does not serve.
        warm_up_reality_server_detector(
            &xray,
            rust_xhttp_core_config(xray.addr, reality_security("chrome"), case.mode),
        )
        .await;
    }
    run_local_xray_xhttp_interop_scenario(xray, rust_config, case.mode).await;
}

fn rust_xhttp_core_config(
    xray_addr: SocketAddr,
    security: StreamSecurity,
    mode: XhttpMode,
) -> CoreConfig {
    let exact = |value| xray_config::XhttpRange {
        from: value,
        to: value,
    };
    rust_core_config_with_transport(
        xray_addr,
        security,
        None,
        StreamTransport::Xhttp(Box::new(XhttpSettings {
            path: XHTTP_PATH.to_owned(),
            mode,
            x_padding_bytes: exact(64),
            uplink_http_method: "POST".to_owned(),
            session_placement: xray_config::XhttpPlacement::Path,
            seq_placement: xray_config::XhttpPlacement::Path,
            uplink_data_placement: XhttpUplinkDataPlacement::Body,
            uplink_chunk_size: exact(4_096),
            sc_max_each_post_bytes: exact(4_096),
            sc_min_posts_interval_ms: exact(1),
            xmux: XhttpXmuxSettings {
                max_concurrency: exact(1),
                // The v26.7.28 default is maxConnections=3. Keep this
                // interop scenario on its explicit maxConcurrency policy.
                max_connections: exact(0),
                h_max_request_times: exact(64),
                h_max_reusable_secs: exact(3_600),
                ..XhttpXmuxSettings::default()
            },
            ..XhttpSettings::default()
        })),
    )
}

const fn xhttp_mode_name(mode: XhttpMode) -> &'static str {
    match mode {
        XhttpMode::Auto => "auto",
        XhttpMode::PacketUp => "packet-up",
        XhttpMode::StreamUp => "stream-up",
        XhttpMode::StreamOne => "stream-one",
    }
}

async fn run_local_xray_xhttp_interop_scenario(
    xray: XrayServer,
    rust_config: CoreConfig,
    mode: XhttpMode,
) {
    let mut core = Core::new(rust_config).expect("create Rust XHTTP core");
    timeout(Duration::from_secs(5), core.start())
        .await
        .expect("start Rust XHTTP core timeout")
        .expect("start Rust XHTTP core");
    let socks_addr = core
        .inbound_addr(Some("socks-in"))
        .expect("bound XHTTP SOCKS addr");

    // More than one packet-up post, and enough stream data to cross h2 flow
    // control windows. The directions run concurrently so stream-up/one are
    // tested as duplex transports rather than as request-then-response RPCs.
    let payload_len = match mode {
        XhttpMode::PacketUp => 64 * 1024,
        XhttpMode::Auto | XhttpMode::StreamUp | XhttpMode::StreamOne => 256 * 1024,
    };
    let payload = bulk_interop_payload(payload_len);
    // packet-up has no terminal POST/session marker in the upstream protocol,
    // so a target that waits for TCP EOF can never finish. Use a finite target
    // there and retain the EOF-driven echo server for the streaming modes.
    let (echo_addr, echo_handle) = if mode == XhttpMode::PacketUp {
        spawn_exact_echo_server(payload.len()).await
    } else {
        spawn_echo_server().await
    };
    let mut client = open_socks_flow(&xray, socks_addr, echo_addr).await;
    let mut echoed = vec![0; payload.len()];
    let transfer = async {
        let (mut reader, mut writer) = client.split();
        let (written, read) = tokio::join!(
            async {
                writer.write_all(&payload).await?;
                writer.flush().await?;
                writer.shutdown().await
            },
            reader.read_exact(&mut echoed),
        );
        written.map_err(|error| format!("write XHTTP bulk payload: {error}"))?;
        read.map_err(|error| format!("read XHTTP bulk echo: {error}"))?;
        Ok::<(), String>(())
    };
    if let Err(error) = timeout(Duration::from_secs(60), transfer)
        .await
        .map_err(|error| format!("XHTTP bulk transfer timeout: {error}"))
        .and_then(|result| result)
    {
        eprintln!("{}", xray.logs());
        panic!("XHTTP bulk flow failed: {error}");
    }
    if echoed != payload {
        let mismatch = echoed
            .iter()
            .zip(payload.iter())
            .position(|(echoed, sent)| echoed != sent)
            .unwrap_or(echoed.len().min(payload.len()));
        eprintln!("{}", xray.logs());
        panic!(
            "XHTTP bulk echo differs at byte {mismatch} of {}",
            payload.len()
        );
    }
    drop(client);
    timeout(Duration::from_secs(5), echo_handle)
        .await
        .expect("XHTTP echo task should finish")
        .expect("XHTTP echo task should not panic");

    // Do not write a single application byte before the target greets us.
    // The only uplink at this point is the VLESS request header. H1/H3 accept
    // writes into a bounded worker pipe, so this pins the logical stream's
    // read-side flush: a server-first protocol must not deadlock waiting for a
    // header that was accepted locally but never delivered to Xray.
    run_xhttp_greeting_first_flow(&xray, socks_addr).await;

    // Two simultaneous flows make the live peer exercise xmux pool reuse and
    // connection fan-out instead of proving only a fresh single flow.
    let parallel_result = if mode == XhttpMode::PacketUp {
        run_parallel_socks_exact_echo_workload(socks_addr, 2).await
    } else {
        run_parallel_socks_echo_workload(socks_addr, 2).await
    };
    if let Err(failures) = parallel_result {
        eprintln!("{}", xray.logs());
        panic!(
            "{} parallel XHTTP flow(s) failed: {failures:?}",
            failures.len()
        );
    }

    core.stop().await.expect("stop Rust XHTTP core");
    drop(xray);
}

async fn run_xhttp_greeting_first_flow(xray: &XrayServer, socks_addr: SocketAddr) {
    const GREETING: &[u8] = b"xhttp-server-first";
    const CLIENT_MARKER: &[u8] = b"client-after-greeting";
    const ACK: &[u8] = b"xhttp-ack";

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind XHTTP greeting-first server");
    let target = listener.local_addr().expect("XHTTP greeting-first addr");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("accept XHTTP greeting-first flow");
        stream
            .write_all(GREETING)
            .await
            .expect("write XHTTP greeting before reading payload");
        stream
            .flush()
            .await
            .expect("flush XHTTP greeting before reading payload");
        let mut marker = [0u8; CLIENT_MARKER.len()];
        stream
            .read_exact(&mut marker)
            .await
            .expect("read client marker after XHTTP greeting");
        assert_eq!(marker, CLIENT_MARKER);
        stream
            .write_all(ACK)
            .await
            .expect("write XHTTP greeting ACK");
        stream.flush().await.expect("flush XHTTP greeting ACK");
    });

    let mut client = open_socks_flow(xray, socks_addr, target).await;
    let mut greeting = [0u8; GREETING.len()];
    match timeout(Duration::from_secs(30), client.read_exact(&mut greeting)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("read server-first XHTTP greeting: {error}");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("server-first XHTTP greeting timeout: {error}");
        }
    }
    assert_eq!(greeting, GREETING);
    client
        .write_all(CLIENT_MARKER)
        .await
        .expect("write marker after XHTTP greeting");
    client
        .shutdown()
        .await
        .expect("half-close greeting-first XHTTP upload");
    let mut ack = [0u8; ACK.len()];
    client
        .read_exact(&mut ack)
        .await
        .expect("read XHTTP greeting ACK");
    assert_eq!(ack, ACK);
    drop(client);
    timeout(Duration::from_secs(5), server)
        .await
        .expect("XHTTP greeting-first server should finish")
        .expect("XHTTP greeting-first server should not panic");
}

// ---- grpc -------------------------------------------------------------------
//
// The `:path`, the `Hunk` framing and the HEADERS block are all pinned against
// a Go oracle in `crates/xray-transport/tests/stream_grpc_tests.rs`, which
// proves we look like grpc-go. These prove a real Xray inbound accepts us and
// relays bytes, which is a different claim: the oracle cannot notice a header
// grpc-go sends that its *server* also insists on, nor a `serviceName` we
// escape into a service the server never registered.

/// The `serviceName` both ends are configured with.
///
/// The space is load-bearing. Both ends run the name through Go's
/// `url.PathEscape` (`Xray-core/transport/internet/grpc/config.go:17-33`), so
/// a plain identifier would prove nothing about our port of it; `%20` is a
/// byte outside the keep-set, and getting it wrong means the server answers
/// UNIMPLEMENTED.
const GRPC_SERVICE_NAME: &str = "interop grpc";

/// The fingerprint the gRPC TLS scenario shapes its ClientHello with.
///
/// **Not cosmetic: without it the handshake fails.** A gRPC inbound hands
/// grpc-go the TLS credentials (`transport/internet/grpc/hub.go:84`), and
/// grpc-go's `ServerHandshake` closes any connection whose
/// `NegotiatedProtocol` came back empty — `GRPC_ENFORCE_ALPN_ENABLED` defaults
/// to true (`grpc@v1.81.0/credentials/tls.go:168-183`,
/// `internal/envconfig/envconfig.go:53`) — and the server offers only `h2`,
/// because `hub.go:84` passes `tls.WithNextProto("h2")`. It is also silent
/// about it: "gRPC server may silently ignore TLS errors", as the line above
/// it says, so the failure reaches the client as a bare EOF part-way through
/// the tunnel.
///
/// A parsed profile always shapes, and the modern browser profiles carry
/// `["h2", "http/1.1"]`: an absent `tlsSettings.fingerprint` means `chrome`
/// (`crates/xray-config/src/model.rs`, `TlsSettings::fingerprint`), so a real
/// gRPC TLS outbound offers `h2` without anyone configuring it. Naming one
/// here is what puts this test on that path rather than beside it; the
/// unshaped path this suite's other TLS scenarios take sends no ALPN
/// extension at all. See `run_local_xray_grpc_interop` for why the
/// pinned-certificate dialer cannot be used with it.
///
/// Not *every* profile carries it: `helloandroid_11_okhttp`,
/// `hello360_7_5` and `hellorandomizednoalpn` do not, nor do their aliases
/// `android`, `360`, `hello360_auto` and `randomizednoalpn`. No gRPC TLS
/// inbound is reachable on those — for xray-core either, so it is parity
/// rather than a gap. uTLS emits the parrot's own extension list and nothing
/// else, and its `ALPNExtension` overwrites `NextProtos` rather than deferring
/// to it (`utls@v1.8.3-.../u_tls_extensions.go:613-621`), so a Go client on
/// the same fingerprint negotiates an empty protocol against a
/// `NextProtos: ["h2"]` server and grpc-go closes on it. The three `360` names
/// never get that far here: `build_client_config` refuses them outright,
/// because rustls implements none of the cipher suites that parrot offers
/// (`crates/xray-transport/src/tls.rs`, `reject_unnegotiable_fingerprint`).
///
/// The TLS-1.2-era parrots that *do* carry `h2` reach the inbound as well,
/// which they did not while a profile declaring no `supported_versions`
/// extension still got a rustls config offering TLS 1.3 — the server then
/// answered with TLS 1.2, and rustls read the RFC 8446 §4.1.3 downgrade
/// sentinel in that ServerHello as an attack
/// (`AttemptedDowngradeToTls12WhenTls13IsSupported`). Such a config is capped
/// at TLS 1.2 now, so nothing claims a version the hello never mentioned.
/// `helloios_11_1` and `helloios_12_1` advertise `h2` first
/// (`utls@v1.8.3-.../u_parrots.go:1639,1701`, and `PROFILE_34`/`PROFILE_35` in
/// `crates/xray-transport/src/utls_profiles.rs` carry the same list), and
/// substituting either name below passes this scenario — measured on both —
/// which means `h2` negotiated over TLS 1.2 against the server `hub.go:84`
/// builds, the same pairing uTLS reaches. `chrome` stays because it is the
/// shape an unset `tlsSettings.fingerprint` sends.
const GRPC_TLS_FINGERPRINT: &str = "chrome";

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_grpc_interop(XrayInboundSecurity::None),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc_tls() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_grpc_interop(XrayInboundSecurity::Tls),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc_reality() {
    timeout(
        Duration::from_secs(180),
        run_local_xray_grpc_interop(XrayInboundSecurity::Reality),
    )
    .await
    .unwrap();
}

/// A tunnel whose *peer* speaks first, against a real Xray inbound. Every echo
/// scenario above writes before it reads, and that is what makes this one a
/// separate test rather than a variation.
///
/// The VLESS request header is written and then nothing else is, until the
/// server answers. Over gRPC that header is a `Hunk` handed to `h2`, which
/// takes it only once the connection task has granted stream capacity — after
/// the write has been asked for. `GrpcStream::poll_write` therefore does not
/// report a write until the whole frame is h2's; when it did report earlier,
/// the header sat in the adapter, the inbound had nothing to dial the target
/// off, and this flow deadlocked while every echo scenario passed, because
/// their next write carried the previous one out for them.
///
/// SSH, SMTP, IMAP and FTP all greet the client first, so this is the shape of
/// a whole class of tunnels rather than a corner.
#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reads_a_server_greeting_through_local_xray_vless_grpc() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_grpc_server_speaks_first_interop(),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_streams_bulk_echo_through_local_xray_vless_grpc_multi_mode() {
    timeout(
        Duration::from_secs(180),
        run_local_xray_grpc_multi_mode_interop(),
    )
    .await
    .unwrap();
}

async fn run_local_xray_grpc_interop(security: XrayInboundSecurity) {
    let xray = start_xray_grpc_server(security).await;

    let rust_config = rust_grpc_core_config(xray.addr, grpc_client_security(security), false);
    if security == XrayInboundSecurity::Reality {
        // Warmed with a gRPC profile, not the Vision one the REALITY helpers
        // build: the inbound serves gRPC and nothing else, so a Vision probe
        // fails in the warmup and the scenario's own pairing is never tried.
        warm_up_reality_server_detector(
            &xray,
            rust_grpc_core_config(xray.addr, grpc_client_security(security), false),
        )
        .await;
    }
    // No dialer override, so the Core builds `TransportDialer::system()` and
    // the handshake runs through the shaped path -- which is the whole point:
    // `TlsConnector::with_pinned_client_config` ignores the fingerprint and
    // sends an unshaped ClientHello, so the pinned-root dialer the other TLS
    // scenarios use cannot offer ALPN at all. Trading the pinned root for
    // `allowInsecure` is what buys the shaping; the certificate is a
    // throwaway self-signed one either way.
    run_local_xray_vless_interop_scenario(xray, rust_config, None).await;
}

/// The only end-to-end proof of the multi-element `MultiHunk` read path, and
/// the reason it moves a megabyte rather than a greeting.
///
/// Our writer never batches — one `poll_write` is one element — so the uplink
/// stays single-element whatever the size. The *server* batches: Xray reads
/// the echo server with a `readv` reader whose allocation strategy doubles up
/// to eight 8 KiB buffers (`Xray-core/common/buf/readv_reader.go:22-44`,
/// `common/buf/buffer.go:13`), and `WriteMultiBuffer` puts one element per
/// buffer into a single `MultiHunk`
/// (`transport/internet/grpc/encoding/multiconn.go:115-134`). So a downlink
/// that stays ahead of the reader produces exactly the message a single-mode
/// decoder would silently truncate to its last element.
///
/// Confirmed to reach that state rather than assumed: with `parse_hunk`
/// temporarily made to assign in multi mode instead of appending — the bug the
/// mode exists to prevent — this scenario fails and the other three gRPC ones
/// still pass. It fails by starving rather than by corrupting, because a
/// dropped element is payload that never arrives: the read never reaches a
/// megabyte and the transfer times out. That is why the byte comparison below
/// is not the whole assertion, and why a generous timeout is one.
async fn run_local_xray_grpc_multi_mode_interop() {
    let xray = start_xray_grpc_server(XrayInboundSecurity::None).await;
    let rust_config = rust_grpc_core_config(xray.addr, StreamSecurity::None, true);
    run_local_xray_grpc_bulk_interop_scenario(xray, rust_config).await;
}

async fn run_local_xray_grpc_server_speaks_first_interop() {
    const GREETING: &[u8] = b"220 interop.invalid ESMTP ready\r\n";

    let xray = start_xray_grpc_server(XrayInboundSecurity::None).await;
    let rust_config = rust_grpc_core_config(xray.addr, StreamSecurity::None, false);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind greeting server");
    let greeting_addr = listener.local_addr().expect("greeting local addr");
    let greeting_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept greeting");
        stream.write_all(GREETING).await.expect("write greeting");
        stream.flush().await.expect("flush greeting");
        // Held open so the read below cannot be satisfied by an EOF.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let mut core = Core::new(rust_config).expect("create rust core");
    timeout(Duration::from_secs(5), core.start())
        .await
        .expect("start rust core timeout")
        .expect("start rust core");
    let socks_addr = core
        .inbound_addr(Some("socks-in"))
        .expect("bound socks addr");

    let mut client = open_socks_flow(&xray, socks_addr, greeting_addr).await;
    let mut greeting = vec![0; GREETING.len()];
    // The client writes nothing at all before this read, which is the whole
    // assertion: any byte it sent would carry the request header out for it.
    match timeout(Duration::from_secs(20), client.read_exact(&mut greeting)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("read greeting: {error}");
        }
        Err(_) => {
            eprintln!("{}", xray.logs());
            panic!("the greeting never arrived: the request header never reached the inbound");
        }
    }
    assert_eq!(greeting, GREETING);

    drop(client);
    core.stop().await.expect("stop rust core");
    drop(xray);
    greeting_handle.abort();
}

async fn start_xray_grpc_server(security: XrayInboundSecurity) -> XrayServer {
    let xray_checkout = resolve_xray_checkout();
    timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security,
                transport: XrayInboundTransport::Grpc {
                    service_name: GRPC_SERVICE_NAME,
                },
                // Vision cannot ride gRPC: `validate_connector_flow` refuses
                // the pairing when we build the outbound, and Xray refuses it
                // too, so an interop scenario for it would be theatre.
                flow: None,
            },
        ),
    )
    .await
    .expect("start xray timeout")
}

fn grpc_client_security(security: XrayInboundSecurity) -> StreamSecurity {
    match security {
        XrayInboundSecurity::None => StreamSecurity::None,
        XrayInboundSecurity::Tls => StreamSecurity::Tls(TlsSettings {
            server_name: Some(TLS_SERVER_NAME.to_owned()),
            fingerprint: Some(GRPC_TLS_FINGERPRINT.to_owned()),
            allow_insecure: true,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            // Left empty on purpose. An `alpn` of `["h2"]` would also reach
            // the server, but by a route no profile takes: the shaped path
            // narrows the profile's list only for exactly `["http/1.1"]`
            // (`crates/xray-transport/src/utls_tls.rs`, `alpn_override_for`),
            // so an explicit list here would be inert *and* would hide the
            // fact that the profile is what supplies `h2`.
            alpn: Vec::new(),
        }),
        // The same fingerprint the base Vision REALITY scenario uses; REALITY
        // negotiates no ALPN of its own, so nothing here turns on the choice.
        XrayInboundSecurity::Reality => reality_security("chrome"),
    }
}

/// `multi_mode` has no server-side counterpart here, and that is not an
/// omission. The listener never reads the field: it registers `Tun` and
/// `TunMulti` on one service descriptor whatever the setting
/// (`Xray-core/transport/internet/grpc/hub.go:128`,
/// `encoding/customSeviceName.go:9-30,57-60`), so for a `serviceName` without
/// a leading `/` — where the two stream names are those constants
/// (`transport/internet/grpc/config.go:36-59`) — a client in either mode
/// reaches a handler. A custom path is where the two sides must agree, because
/// there the names come from the config's last segment split on `|`.
fn rust_grpc_core_config(
    xray_addr: SocketAddr,
    security: StreamSecurity,
    multi_mode: bool,
) -> CoreConfig {
    rust_core_config_with_transport(
        xray_addr,
        security,
        None,
        StreamTransport::Grpc(GrpcSettings {
            service_name: GRPC_SERVICE_NAME.to_owned(),
            multi_mode,
            ..GrpcSettings::default()
        }),
    )
}

/// One megabyte, which is what makes the server batch. Eight 8 KiB buffers is
/// the readv reader's ceiling, so anything past a few hundred kilobytes is
/// well into the regime; a megabyte crosses loopback in well under a second
/// and leaves room for the transfer to be slow without the scenario being
/// flaky.
const GRPC_BULK_PAYLOAD_LEN: usize = 1024 * 1024;

/// Writes and reads [`GRPC_BULK_PAYLOAD_LEN`] bytes at once through the
/// tunnel, and reports the first byte that came back wrong.
///
/// The two directions run concurrently because they have to: a megabyte does
/// not fit in the socket buffers between here and the echo server, so writing
/// it all before reading any of it deadlocks. And the comparison is a
/// first-difference search rather than `assert_eq!`, which on a mismatch would
/// try to print two megabytes of hex.
async fn run_local_xray_grpc_bulk_interop_scenario(xray: XrayServer, rust_config: CoreConfig) {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::new(rust_config).expect("create rust core");

    timeout(Duration::from_secs(5), core.start())
        .await
        .expect("start rust core timeout")
        .expect("start rust core");
    let socks_addr = core
        .inbound_addr(Some("socks-in"))
        .expect("bound socks addr");

    let mut client = open_socks_flow(&xray, socks_addr, echo_addr).await;

    let payload = bulk_interop_payload(GRPC_BULK_PAYLOAD_LEN);
    let mut echoed = vec![0; payload.len()];
    let (mut reader, mut writer) = client.split();
    let transfer = async {
        let (written, read) = tokio::join!(
            async {
                writer.write_all(&payload).await?;
                writer.flush().await
            },
            reader.read_exact(&mut echoed),
        );
        written.map_err(|error| format!("write bulk payload: {error}"))?;
        read.map_err(|error| format!("read bulk echo: {error}"))?;
        Ok::<(), String>(())
    };
    match timeout(Duration::from_secs(60), transfer).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("{}", xray.logs());
            panic!("bulk echo failed: {error}");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            panic!("bulk echo timeout: {error}");
        }
    }

    if let Some(index) = echoed
        .iter()
        .zip(payload.iter())
        .position(|(echoed, sent)| echoed != sent)
    {
        eprintln!("{}", xray.logs());
        panic!(
            "bulk echo differs at byte {index} of {}: {:#04x} != {:#04x}",
            payload.len(),
            echoed[index],
            payload[index]
        );
    }

    drop(client);
    core.stop().await.expect("stop rust core");
    drop(xray);
    timeout(Duration::from_secs(5), echo_handle)
        .await
        .expect("echo task should finish")
        .expect("echo task should not panic");
}

/// A deterministic filler with no short repeating run, so a tunnel that
/// reordered, duplicated or truncated a chunk cannot land on matching bytes by
/// luck the way a constant or a low-period pattern would.
fn bulk_interop_payload(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}
