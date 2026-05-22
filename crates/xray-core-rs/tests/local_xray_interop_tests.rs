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
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    StreamSecurity, StreamSettings, TargetAddr, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::Core;

const TEST_UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp() {
    timeout(Duration::from_secs(120), run_local_xray_vless_interop())
        .await
        .unwrap();
}

async fn run_local_xray_vless_interop() {
    let xray_checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server(&xray_checkout),
    )
    .await
    .expect("start xray timeout");

    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::new(rust_core_config(xray.addr)).expect("create rust core");

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
    timeout(
        Duration::from_secs(5),
        socks5_connect(&mut client, echo_addr),
    )
    .await
    .expect("socks connect timeout");

    let payload = b"hello local xray interop";
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

fn write_xray_vless_config(path: &Path, port: u16) {
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {port},
      "protocol": "vless",
      "settings": {{
        "clients": [{{ "id": "{TEST_UUID}" }}],
        "decryption": "none"
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
    );
    fs::write(path, config).expect("write xray config");
}

async fn start_xray_vless_server(xray_checkout: &Path) -> XrayServer {
    let temp_dir = create_temp_dir("xray-rust-local-interop");
    let binary = temp_dir
        .path
        .join(format!("xray{}", env::consts::EXE_SUFFIX));
    let config_path = temp_dir.path.join("server.json");
    let stdout_path = temp_dir.path.join("xray.stdout.log");
    let stderr_path = temp_dir.path.join("xray.stderr.log");
    let port = allocate_loopback_port();
    write_xray_vless_config(&config_path, port);

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

fn rust_core_config(xray_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![OutboundConfig {
            tag: Some("proxy".to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                security: StreamSecurity::None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(xray_addr.ip()),
                port: xray_addr.port(),
                users: vec![VlessUser {
                    id: TEST_UUID.parse().expect("static uuid"),
                    encryption: "none".to_owned(),
                    flow: None,
                }],
            }),
        }],
        default_outbound_tag: None,
    }
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
