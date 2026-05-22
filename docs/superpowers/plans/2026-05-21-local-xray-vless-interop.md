# Local Xray VLESS Interop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and run the first local cross-process interoperability test proving the Rust SOCKS -> VLESS/TCP path can proxy through a local Go Xray-core VLESS inbound to an echo server.

**Architecture:** Add one ignored Rust integration test in `crates/xray-core-rs/tests/local_xray_interop_tests.rs`. The test builds the cloned Xray-core binary into a temporary directory, writes a minimal VLESS inbound JSON config, launches Xray, starts the Rust core, and verifies end-to-end byte echo through SOCKS. Stop immediately after the local connection test passes, per the user's instruction.

**Tech Stack:** Rust 2021, Tokio, std process/filesystem APIs, existing `xray-core-rs`, `xray-config`, Go Xray-core checkout, Cargo ignored integration test.

---

## File Structure

- Create `crates/xray-core-rs/tests/local_xray_interop_tests.rs`: ignored integration harness, Xray process guard, temp directory guard, SOCKS client helper, local echo server, and Rust core config builder.
- Defer `README.md` and `docs/verification.md` updates until the next slice because this autonomous run must stop after the first successful local connection test.

## Task 1: Add Failing Local Interop Test Skeleton

**Files:**
- Create: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Write the failing test skeleton**

Create `crates/xray-core-rs/tests/local_xray_interop_tests.rs` with this content:

```rust
use tokio::time::{timeout, Duration};

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp() {
    timeout(Duration::from_secs(120), run_local_xray_vless_interop()).await.unwrap();
}

async fn run_local_xray_vless_interop() {
    let xray_checkout = resolve_xray_checkout();
    let _xray = start_xray_vless_server(&xray_checkout).await;
}
```

This intentionally references `resolve_xray_checkout` and `start_xray_vless_server` before they exist.

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp
```

Expected: FAIL at compile time with missing function errors for `resolve_xray_checkout` and `start_xray_vless_server`.

- [ ] **Step 3: Commit RED skeleton**

```bash
git add crates/xray-core-rs/tests/local_xray_interop_tests.rs
git commit -m "test(core): add local xray interop skeleton"
```

## Task 2: Implement Local Xray Process Harness

**Files:**
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Replace imports and add constants/guards**

Replace the initial `use tokio::time::{timeout, Duration};` line with the following imports and definitions:

```rust
use std::env;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration, Instant};

const TEST_UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";

struct TempDir {
    path: PathBuf,
}

struct XrayServer {
    child: Child,
    _temp_dir: TempDir,
    addr: SocketAddr,
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
```

- [ ] **Step 2: Implement checkout resolution and temp directories**

Add:

```rust
fn resolve_xray_checkout() -> PathBuf {
    if let Some(path) = env::var_os("XRAY_CORE_CHECKOUT") {
        let path = PathBuf::from(path);
        assert!(path.join("go.mod").exists(), "XRAY_CORE_CHECKOUT must point at Xray-core");
        return path;
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should be inside workspace/crates")
        .to_path_buf();
    let checkout = workspace_root.join("Xray-core");
    assert!(checkout.join("go.mod").exists(), "missing Xray-core checkout; set XRAY_CORE_CHECKOUT");
    checkout
}

fn create_temp_dir(prefix: &str) -> TempDir {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path = env::temp_dir().join(format!("{prefix}-{}-{now}", std::process::id()));
    fs::create_dir(&path).expect("create temp dir");
    TempDir { path }
}
```

- [ ] **Step 3: Implement port allocation and Xray config writing**

Add:

```rust
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
    {{ "protocol": "freedom", "settings": {{}} }}
  ]
}}"#
    );
    fs::write(path, config).expect("write xray config");
}
```

- [ ] **Step 4: Implement build/start/wait**

Add:

```rust
async fn start_xray_vless_server(xray_checkout: &Path) -> XrayServer {
    let temp_dir = create_temp_dir("xray-rust-local-interop");
    let binary = temp_dir.path.join("xray");
    let config_path = temp_dir.path.join("server.json");
    let port = allocate_loopback_port();
    write_xray_vless_config(&config_path, port);

    let build_status = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&binary)
        .arg("./main")
        .current_dir(xray_checkout)
        .status()
        .expect("start go build for Xray-core");
    assert!(build_status.success(), "go build ./main should succeed");

    let child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start xray process");

    let server = XrayServer {
        child,
        _temp_dir: temp_dir,
        addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    };
    wait_for_tcp_listener(server.addr).await;
    server
}

async fn wait_for_tcp_listener(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
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
```

- [ ] **Step 5: Run targeted test**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp
```

Expected: PASS if Xray-core builds and starts. This only proves the process harness compiles and can launch Xray; the real connection assertion comes in Task 3.

## Task 3: Complete End-to-End SOCKS -> Rust -> Xray -> Echo Flow

**Files:**
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Add Rust core and IO imports**

Add:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    StreamSecurity, StreamSettings, TargetAddr, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::Core;
```

- [ ] **Step 2: Build Rust core config**

Add:

```rust
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
```

- [ ] **Step 3: Add echo server and SOCKS helper**

Add:

```rust
async fn spawn_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind echo");
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

    client.write_all(&[5, 1, 0]).await.expect("write socks greeting");
    let mut method = [0; 2];
    client.read_exact(&mut method).await.expect("read socks method");
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.expect("write socks connect");

    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.expect("read socks reply");
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}
```

- [ ] **Step 4: Wire the scenario**

Replace `run_local_xray_vless_interop` with:

```rust
async fn run_local_xray_vless_interop() {
    let xray_checkout = resolve_xray_checkout();
    let xray = start_xray_vless_server(&xray_checkout).await;
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::new(rust_core_config(xray.addr)).expect("create rust core");

    core.start().await.expect("start rust core");
    let socks_addr = core.inbound_addr(Some("socks-in")).expect("bound socks addr");

    let mut client = TcpStream::connect(socks_addr).await.expect("connect rust socks");
    socks5_connect(&mut client, echo_addr).await;

    let payload = b"hello local xray interop";
    client.write_all(payload).await.expect("write payload");
    let mut echoed = vec![0; payload.len()];
    client.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(echoed, payload);

    drop(client);
    core.stop().await.expect("stop rust core");
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .expect("echo task should finish")
        .expect("echo task should not panic");
    drop(xray);
}
```

- [ ] **Step 5: Run targeted local interop test**

Run with loopback/process permissions:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp
```

Expected: PASS. This is the milestone where we stop and report after verification.

- [ ] **Step 6: Commit harness before stopping**

```bash
git add crates/xray-core-rs/tests/local_xray_interop_tests.rs
git commit -m "test(core): add local xray vless interop"
```
