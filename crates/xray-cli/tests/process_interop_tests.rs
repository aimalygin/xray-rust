use std::env;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration, Instant};

const TEST_UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const REALITY_SERVER_NAME: &str = "www.example.com";
const REALITY_PRIVATE_KEY: &str = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks";
const REALITY_PUBLIC_KEY: &str = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM";
const REALITY_SHORT_ID_HEX: &str = "0123456789abcdef";

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, xray-rust binary, and loopback process execution"]
async fn xray_rust_process_reaches_echo_server_through_local_xray_vless_tcp() {
    timeout(
        Duration::from_secs(120),
        run_xray_rust_process_interop(XrayInboundSecurity::None),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, xray-rust binary, and loopback process execution"]
async fn xray_rust_process_reaches_echo_server_through_local_xray_vless_reality_vision() {
    timeout(
        Duration::from_secs(120),
        run_xray_rust_process_interop(XrayInboundSecurity::Reality),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn xray_rust_process_reaches_echo_server_through_freedom_outbound() {
    timeout(
        Duration::from_secs(20),
        run_xray_rust_process_freedom_interop(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn xray_rust_process_http_connect_reaches_echo_server_through_freedom_outbound() {
    timeout(
        Duration::from_secs(20),
        run_xray_rust_process_http_freedom_interop(),
    )
    .await
    .unwrap();
}

async fn run_xray_rust_process_interop(security: XrayInboundSecurity) {
    let xray_checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(
            &xray_checkout,
            XrayVlessServerConfig {
                security,
                flow: security.flow(),
            },
        ),
    )
    .await
    .expect("start xray timeout");
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let client_temp_dir = create_temp_dir("xray-rust-cli-process-interop");
    let client_config_path = client_temp_dir.path.join("client.json");
    write_xray_rust_client_config(&client_config_path, xray.addr, security);
    let (xray_rust, socks_addr) = start_xray_rust_process(client_temp_dir, &client_config_path)
        .await
        .expect("start xray-rust process");

    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .expect("connect xray-rust socks timeout")
        .expect("connect xray-rust socks");
    timeout(
        Duration::from_secs(5),
        socks5_connect(&mut client, echo_addr),
    )
    .await
    .expect("socks connect timeout");

    let payload = b"hello xray-rust process interop";
    timeout(Duration::from_secs(5), client.write_all(payload))
        .await
        .expect("write payload timeout")
        .expect("write payload");
    let mut echoed = vec![0; payload.len()];
    match timeout(Duration::from_secs(5), client.read_exact(&mut echoed)).await {
        Ok(result) => {
            result.expect("read echo");
        }
        Err(error) => {
            eprintln!("{}", xray.logs());
            eprintln!("{}", xray_rust.logs());
            panic!("read echo timeout: {error}");
        }
    }
    assert_eq!(echoed, payload);

    drop(client);
    drop(xray_rust);
    drop(xray);
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .expect("echo task should finish")
        .expect("echo task should not panic");
}

async fn run_xray_rust_process_freedom_interop() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let client_temp_dir = create_temp_dir("xray-rust-cli-freedom-process-interop");
    let client_config_path = client_temp_dir.path.join("client.json");
    write_xray_rust_freedom_client_config(&client_config_path);
    let (xray_rust, socks_addr) = start_xray_rust_process(client_temp_dir, &client_config_path)
        .await
        .expect("start xray-rust process");

    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .expect("connect xray-rust socks timeout")
        .expect("connect xray-rust socks");
    timeout(
        Duration::from_secs(5),
        socks5_connect(&mut client, echo_addr),
    )
    .await
    .expect("socks connect timeout");

    let payload = b"hello xray-rust freedom process";
    timeout(Duration::from_secs(5), client.write_all(payload))
        .await
        .expect("write payload timeout")
        .expect("write payload");
    let mut echoed = vec![0; payload.len()];
    match timeout(Duration::from_secs(5), client.read_exact(&mut echoed)).await {
        Ok(result) => {
            result.expect("read echo");
        }
        Err(error) => {
            eprintln!("{}", xray_rust.logs());
            panic!("read echo timeout: {error}");
        }
    }
    assert_eq!(echoed, payload);

    drop(client);
    drop(xray_rust);
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .expect("echo task should finish")
        .expect("echo task should not panic");
}

async fn run_xray_rust_process_http_freedom_interop() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let client_temp_dir = create_temp_dir("xray-rust-cli-http-freedom-process-interop");
    let client_config_path = client_temp_dir.path.join("client.json");
    write_xray_rust_http_freedom_client_config(&client_config_path);
    let (xray_rust, http_addr) =
        start_xray_rust_process_for_inbound(client_temp_dir, &client_config_path, "http-in")
            .await
            .expect("start xray-rust process");

    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(http_addr))
        .await
        .expect("connect xray-rust http timeout")
        .expect("connect xray-rust http");
    timeout(Duration::from_secs(5), http_connect(&mut client, echo_addr))
        .await
        .expect("http connect timeout");

    let payload = b"hello xray-rust http freedom process";
    timeout(Duration::from_secs(5), client.write_all(payload))
        .await
        .expect("write payload timeout")
        .expect("write payload");
    let mut echoed = vec![0; payload.len()];
    match timeout(Duration::from_secs(5), client.read_exact(&mut echoed)).await {
        Ok(result) => {
            result.expect("read echo");
        }
        Err(error) => {
            eprintln!("{}", xray_rust.logs());
            panic!("read echo timeout: {error}");
        }
    }
    assert_eq!(echoed, payload);

    drop(client);
    drop(xray_rust);
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .expect("echo task should finish")
        .expect("echo task should not panic");
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
}

struct XrayRustProcess {
    child: Child,
    _temp_dir: TempDir,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XrayInboundSecurity {
    None,
    Reality,
}

impl XrayInboundSecurity {
    fn flow(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Reality => Some("xtls-rprx-vision"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct XrayVlessServerConfig {
    security: XrayInboundSecurity,
    flow: Option<&'static str>,
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

impl Drop for XrayRustProcess {
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

impl XrayRustProcess {
    fn logs(&self) -> String {
        format!(
            "xray-rust stdout:\n{}\nxray-rust stderr:\n{}",
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

fn write_xray_vless_config(path: &Path, port: u16, server_config: &XrayVlessServerConfig) {
    let client = match server_config.flow {
        Some(flow) => format!(r#"{{ "id": "{TEST_UUID}", "flow": "{flow}" }}"#),
        None => format!(r#"{{ "id": "{TEST_UUID}" }}"#),
    };
    let stream_settings = match server_config.security {
        XrayInboundSecurity::None => String::new(),
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

fn write_xray_rust_client_config(
    path: &Path,
    xray_addr: SocketAddr,
    security: XrayInboundSecurity,
) {
    let flow = security
        .flow()
        .map(|flow| format!(r#", "flow": "{flow}""#))
        .unwrap_or_default();
    let stream_settings = match security {
        XrayInboundSecurity::None => r#""streamSettings": { "network": "tcp" }"#.to_owned(),
        XrayInboundSecurity::Reality => format!(
            r#""streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "serverName": "{REALITY_SERVER_NAME}",
          "fingerprint": "chrome",
          "publicKey": "{REALITY_PUBLIC_KEY}",
          "shortId": "{REALITY_SHORT_ID_HEX}",
          "spiderX": "/"
        }}
      }}"#
        ),
    };
    let config = format!(
        r#"{{
  "inbounds": [
    {{
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 0
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
                "encryption": "none"{flow}
              }}
            ]
          }}
        ]
      }},
      {stream_settings}
    }}
  ]
}}"#,
        xray_addr.ip(),
        xray_addr.port(),
    );
    fs::write(path, config).expect("write xray-rust client config");
}

fn write_xray_rust_freedom_client_config(path: &Path) {
    let config = r#"{
  "inbounds": [
    {
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 0
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}"#;
    fs::write(path, config).expect("write xray-rust freedom client config");
}

fn write_xray_rust_http_freedom_client_config(path: &Path) {
    let config = r#"{
  "inbounds": [
    {
      "tag": "http-in",
      "protocol": "http",
      "listen": "127.0.0.1",
      "port": 0
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}"#;
    fs::write(path, config).expect("write xray-rust http freedom client config");
}

async fn start_xray_vless_server(
    xray_checkout: &Path,
    server_config: XrayVlessServerConfig,
) -> XrayServer {
    let temp_dir = create_temp_dir("xray-rust-cli-xray-server");
    let binary = temp_dir
        .path
        .join(format!("xray{}", env::consts::EXE_SUFFIX));
    let config_path = temp_dir.path.join("server.json");
    let stdout_path = temp_dir.path.join("xray.stdout.log");
    let stderr_path = temp_dir.path.join("xray.stderr.log");
    let port = allocate_loopback_port();
    write_xray_vless_config(&config_path, port, &server_config);

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
    }
}

async fn start_xray_rust_process(
    temp_dir: TempDir,
    config_path: &Path,
) -> Result<(XrayRustProcess, SocketAddr), String> {
    start_xray_rust_process_for_inbound(temp_dir, config_path, "socks-in").await
}

async fn start_xray_rust_process_for_inbound(
    temp_dir: TempDir,
    config_path: &Path,
    inbound_tag: &str,
) -> Result<(XrayRustProcess, SocketAddr), String> {
    let stdout_path = temp_dir.path.join("xray-rust.stdout.log");
    let stderr_path = temp_dir.path.join("xray-rust.stderr.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_xray-rust"))
        .arg("run")
        .arg("-config")
        .arg(config_path)
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).expect("create xray-rust stdout log"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("create xray-rust stderr log"),
        ))
        .spawn()
        .expect("start xray-rust process");
    let inbound_addr =
        wait_for_xray_rust_inbound_addr(&mut child, &stdout_path, &stderr_path, inbound_tag)
            .await?;

    Ok((
        XrayRustProcess {
            child,
            _temp_dir: temp_dir,
            stdout_path,
            stderr_path,
        },
        inbound_addr,
    ))
}

async fn wait_for_tcp_listener(
    child: &mut Child,
    addr: SocketAddr,
    stdout_path: &Path,
    stderr_path: &Path,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("check process status") {
            let stdout = fs::read_to_string(stdout_path).unwrap_or_default();
            let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
            panic!(
                "process exited before listening on {addr}: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
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
            Err(error) => panic!("process did not listen on {addr}: {error}"),
        }
    }
}

async fn wait_for_xray_rust_inbound_addr(
    child: &mut Child,
    stdout_path: &Path,
    stderr_path: &Path,
    inbound_tag: &str,
) -> Result<SocketAddr, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("check xray-rust status") {
            return Err(format!(
                "xray-rust exited before reporting inbound addr: {status}\nstdout:\n{}\nstderr:\n{}",
                fs::read_to_string(stdout_path).unwrap_or_default(),
                fs::read_to_string(stderr_path).unwrap_or_default()
            ));
        }

        let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
        if let Some(addr) = parse_bound_inbound_addr(&stderr, inbound_tag) {
            return Ok(addr);
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "xray-rust did not report inbound addr for {inbound_tag}\nstdout:\n{}\nstderr:\n{}",
                fs::read_to_string(stdout_path).unwrap_or_default(),
                stderr
            ));
        }

        sleep(Duration::from_millis(50)).await;
    }
}

fn parse_bound_inbound_addr(log: &str, inbound_tag: &str) -> Option<SocketAddr> {
    let prefix = format!("bound inbound {inbound_tag} at ");
    log.lines().find_map(|line| {
        line.strip_prefix(&prefix)
            .and_then(|addr| addr.parse().ok())
    })
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

async fn socks5_connect(client: &mut TcpStream, target: SocketAddr) {
    let SocketAddr::V4(target) = target else {
        panic!("local interop test uses IPv4 targets only");
    };

    client
        .write_all(&[5, 1, 0])
        .await
        .expect("write socks greeting");
    let mut method = [0; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read socks method");
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client
        .write_all(&request)
        .await
        .expect("write socks connect");

    let mut reply = [0; 10];
    client
        .read_exact(&mut reply)
        .await
        .expect("read socks reply");
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

async fn http_connect(client: &mut TcpStream, target: SocketAddr) {
    let authority = target.to_string();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client
        .write_all(request.as_bytes())
        .await
        .expect("write http connect");

    let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let mut response = vec![0; expected.len()];
    client
        .read_exact(&mut response)
        .await
        .expect("read http connect response");
    assert_eq!(response, expected);
}
