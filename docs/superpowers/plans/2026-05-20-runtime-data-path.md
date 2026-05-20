# Runtime Data Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first executable client data path: SOCKS5 inbound through the Rust runtime into VLESS over raw TCP and back.

**Architecture:** Keep the live path narrow and explicit. Extend SOCKS5 helpers for real streaming handshakes, add a raw TCP VLESS outbound dialer in `xray-core-rs`, then wire `Core::start()` to bind SOCKS5 listeners and supervise Tokio tasks. TLS/REALITY/Vision configs must fail explicitly rather than falling back to plaintext.

**Tech Stack:** Rust 2021, Tokio TCP/listeners/tasks, existing `xray-config`, `xray-proxy`, `xray-routing`, `xray-transport`, `thiserror`.

---

## File Structure

- `crates/xray-proxy/src/inbound/socks.rs`: split SOCKS5 parsing into reusable greeting/request helpers and add reply writers.
- `crates/xray-proxy/tests/inbound_parser_tests.rs`: parser/reply coverage for the new SOCKS5 helpers.
- `crates/xray-core-rs/src/lib.rs`: expose runtime lifecycle fields, `inbound_addr`, and expanded `CoreError`.
- `crates/xray-core-rs/src/outbound.rs`: select supported VLESS/TCP outbounds and open streams with a VLESS header.
- `crates/xray-core-rs/src/socks.rs`: bind/serve SOCKS5 connections and relay streams.
- `crates/xray-core-rs/tests/core_lifecycle_tests.rs`: update lifecycle config to raw TCP and cover listener address behavior.
- `crates/xray-core-rs/tests/runtime_data_path_tests.rs`: end-to-end SOCKS5 -> VLESS/TCP -> echo test with a fake VLESS server.
- `crates/xray-core-rs/Cargo.toml`: move `tokio.workspace = true` from dev-dependencies to production dependencies when runtime code starts using Tokio types.

---

## Task 1: Streaming SOCKS5 Helpers

**Files:**
- Modify: `crates/xray-proxy/src/inbound/socks.rs`
- Modify: `crates/xray-proxy/tests/inbound_parser_tests.rs`

- [ ] **Step 1: Write failing tests for split SOCKS5 handshake and replies**

Add these tests to `crates/xray-proxy/tests/inbound_parser_tests.rs`:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use xray_proxy::inbound::socks::{
    negotiate_socks5_no_auth, parse_socks5_request, write_socks5_failure,
    write_socks5_success, SocksParseError,
};

#[tokio::test]
async fn socks5_negotiate_no_auth_writes_method_selection() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5_no_auth(server).await });

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0]);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn socks5_negotiate_rejects_when_no_auth_is_absent() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5_no_auth(server).await });

    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0xff]);
    assert_eq!(
        server_task.await.unwrap(),
        Err(SocksParseError::NoAcceptableMethods)
    );
}

#[tokio::test]
async fn socks5_request_parser_reads_connect_after_greeting() {
    let bytes = [
        5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
        0xbb,
    ];
    let target = parse_socks5_request(&bytes[..]).await.unwrap();

    assert_eq!(target.port, 443);
}

#[tokio::test]
async fn socks5_reply_writers_emit_ipv4_success_and_failure() {
    let mut output = Vec::new();

    write_socks5_success(&mut output).await.unwrap();
    write_socks5_failure(&mut output).await.unwrap();

    assert_eq!(
        output,
        vec![
            5, 0, 0, 1, 0, 0, 0, 0, 0, 0, // success
            5, 1, 0, 1, 0, 0, 0, 0, 0, 0, // general failure
        ]
    );
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p xray-proxy --test inbound_parser_tests socks5_
```

Expected: FAIL because `negotiate_socks5_no_auth`, `parse_socks5_request`, reply writers, and `NoAcceptableMethods` do not exist.

- [ ] **Step 3: Implement the SOCKS5 helpers**

Update `crates/xray-proxy/src/inbound/socks.rs` with this shape:

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_routing::{Network, Target, TargetAddr};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SocksParseError {
    #[error("unsupported socks version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported socks command {0}")]
    UnsupportedCommand(u8),
    #[error("invalid socks reserved byte {0}")]
    InvalidReserved(u8),
    #[error("unsupported socks address type {0}")]
    UnsupportedAddressType(u8),
    #[error("invalid socks domain")]
    InvalidDomain,
    #[error("no acceptable socks authentication methods")]
    NoAcceptableMethods,
    #[error("io error")]
    Io,
}

pub async fn negotiate_socks5_no_auth<S>(mut stream: S) -> Result<(), SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if version != 5 {
        return Err(SocksParseError::UnsupportedVersion(version));
    }

    let method_count = stream.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let mut methods = vec![0; usize::from(method_count)];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| SocksParseError::Io)?;

    if methods.contains(&0) {
        stream
            .write_all(&[5, 0])
            .await
            .map_err(|_| SocksParseError::Io)?;
        Ok(())
    } else {
        stream
            .write_all(&[5, 0xff])
            .await
            .map_err(|_| SocksParseError::Io)?;
        Err(SocksParseError::NoAcceptableMethods)
    }
}

pub async fn parse_socks5_request<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<Target, SocksParseError> {
    let request_version = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if request_version != 5 {
        return Err(SocksParseError::UnsupportedVersion(request_version));
    }

    let command = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if command != 1 {
        return Err(SocksParseError::UnsupportedCommand(command));
    }

    let reserved = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if reserved != 0 {
        return Err(SocksParseError::InvalidReserved(reserved));
    }

    let address_type = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let addr = match address_type {
        1 => {
            let mut octets = [0; 4];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(|_| SocksParseError::Io)?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        3 => {
            let len = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
            if len == 0 {
                return Err(SocksParseError::InvalidDomain);
            }

            let mut domain = vec![0; usize::from(len)];
            reader
                .read_exact(&mut domain)
                .await
                .map_err(|_| SocksParseError::Io)?;
            TargetAddr::Domain(
                String::from_utf8(domain).map_err(|_| SocksParseError::InvalidDomain)?,
            )
        }
        4 => {
            let mut octets = [0; 16];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(|_| SocksParseError::Io)?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => return Err(SocksParseError::UnsupportedAddressType(other)),
    };
    let port = reader.read_u16().await.map_err(|_| SocksParseError::Io)?;

    Ok(Target::new(addr, port, Network::Tcp))
}

pub async fn parse_socks5_connect<S>(mut stream: S) -> Result<Target, SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_socks5_no_auth(&mut stream).await?;
    parse_socks5_request(&mut stream).await
}

pub async fn write_socks5_success<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<(), SocksParseError> {
    writer
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|_| SocksParseError::Io)
}

pub async fn write_socks5_failure<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<(), SocksParseError> {
    writer
        .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|_| SocksParseError::Io)
}
```

Update existing tests that pass a byte slice containing both greeting and request so they call `parse_socks5_request` with only the request bytes when they only want request parsing. Keep at least one `parse_socks5_connect` test using `tokio::io::duplex` so the method-selection write path is covered.

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p xray-proxy --test inbound_parser_tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-proxy/src/inbound/socks.rs crates/xray-proxy/tests/inbound_parser_tests.rs
git commit -m "feat(proxy): add streaming socks5 handshake helpers"
```

---

## Task 2: Raw VLESS TCP Outbound Dialer

**Files:**
- Create: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/Cargo.toml`
- Test: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write failing outbound selection tests**

Create `crates/xray-core-rs/tests/runtime_data_path_tests.rs` with these first tests:

```rust
use std::net::{IpAddr, Ipv4Addr};

use xray_config::{
    CoreConfig, Network, OutboundConfig, OutboundSettings, StreamSecurity, StreamSettings,
    TargetAddr, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{select_vless_tcp_outbound, CoreError};
use uuid::Uuid;

fn vless_outbound(security: StreamSecurity, server: TargetAddr) -> OutboundConfig {
    OutboundConfig {
        tag: Some("proxy".to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security,
        },
        settings: OutboundSettings::Vless(VlessOutboundSettings {
            server,
            port: 443,
            users: vec![VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: None,
            }],
        }),
    }
}

#[test]
fn selects_raw_tcp_vless_outbound_with_ip_server() {
    let config = CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )],
        default_outbound_tag: None,
    };

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server.port, 443);
}

#[test]
fn rejects_reality_outbound_for_raw_tcp_runtime_path() {
    let config = CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![vless_outbound(
            StreamSecurity::Reality(xray_config::RealitySettings {
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: [1; 32],
                short_id: xray_config::RealityShortId::try_from_slice(&[2, 3, 4, 5]).unwrap(),
                spider_x: "/".to_owned(),
            }),
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )],
        default_outbound_tag: None,
    };

    assert_eq!(
        select_vless_tcp_outbound(&config).unwrap_err(),
        CoreError::UnsupportedOutboundSecurity
    );
}

#[test]
fn rejects_domain_vless_server_until_dns_exists() {
    let config = CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Domain("server.example".to_owned()),
        )],
        default_outbound_tag: None,
    };

    assert_eq!(
        select_vless_tcp_outbound(&config).unwrap_err(),
        CoreError::UnsupportedOutboundServerAddress
    );
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests
```

Expected: FAIL because `select_vless_tcp_outbound` and the new `CoreError` variants do not exist.

- [ ] **Step 3: Implement outbound selection and dialer**

Add `crates/xray-core-rs/src/outbound.rs`:

```rust
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use xray_config::{CoreConfig, Network, OutboundSettings, StreamSecurity, TargetAddr, VlessUser};
use xray_proxy::vless::{encode_request_header, VlessCommand, VlessRequest};
use xray_routing::{Target, Target as RoutingTarget, TargetAddr as RoutingTargetAddr};
use xray_transport::{ConnectorConfig, TcpConnector, TransportConnector};

use crate::CoreError;

#[derive(Debug, Clone)]
pub struct VlessTcpOutbound {
    pub server: RoutingTarget,
    pub user: VlessUser,
}

pub fn select_vless_tcp_outbound(config: &CoreConfig) -> Result<VlessTcpOutbound, CoreError> {
    let outbound = config.outbounds.first().ok_or(CoreError::NoSupportedOutbound)?;
    if outbound.stream.network != Network::Tcp {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }
    if outbound.stream.security != StreamSecurity::None {
        return Err(CoreError::UnsupportedOutboundSecurity);
    }

    let OutboundSettings::Vless(settings) = &outbound.settings;
    let server_addr = match &settings.server {
        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
        TargetAddr::Domain(_) => return Err(CoreError::UnsupportedOutboundServerAddress),
    };
    let user = settings
        .users
        .first()
        .cloned()
        .ok_or(CoreError::NoSupportedOutbound)?;

    Ok(VlessTcpOutbound {
        server: RoutingTarget::new(server_addr, settings.port, xray_routing::Network::Tcp),
        user,
    })
}

pub async fn open_vless_tcp_stream(
    outbound: &VlessTcpOutbound,
    target: &Target,
) -> Result<TcpStream, CoreError> {
    let connector = TcpConnector::new(ConnectorConfig::Tcp);
    let mut stream = connector
        .connect(&outbound.server)
        .await
        .map_err(CoreError::Transport)?;

    let header = encode_request_header(&VlessRequest {
        user_id: outbound.user.id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: outbound.user.flow.clone(),
    })
    .map_err(CoreError::VlessHeader)?;

    stream
        .write_all(&header)
        .await
        .map_err(CoreError::Io)?;

    Ok(stream)
}
```

Update `crates/xray-core-rs/src/lib.rs`:

```rust
mod outbound;

pub use outbound::{open_vless_tcp_stream, select_vless_tcp_outbound, VlessTcpOutbound};

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("core is already running")]
    AlreadyRunning,
    #[error("core is already stopped")]
    AlreadyStopped,
    #[error("no supported inbound configured")]
    NoSupportedInbound,
    #[error("no supported outbound configured")]
    NoSupportedOutbound,
    #[error("unsupported outbound network")]
    UnsupportedOutboundNetwork,
    #[error("unsupported outbound security")]
    UnsupportedOutboundSecurity,
    #[error("unsupported outbound server address")]
    UnsupportedOutboundServerAddress,
    #[error("transport error: {0}")]
    Transport(#[from] xray_transport::TransportError),
    #[error("vless header error: {0}")]
    VlessHeader(#[from] xray_proxy::vless::WireError),
    #[error("io error: {0}")]
    Io(std::io::Error),
}
```

Keep `PartialEq, Eq` only if tests require it. If `std::io::Error` prevents deriving equality, use `matches!` in tests for non-eq variants and derive equality only for comparable variants is not possible; prefer dropping `PartialEq, Eq` from `CoreError` and updating existing lifecycle tests to use `matches!`.

Update `crates/xray-core-rs/Cargo.toml` by moving Tokio into production dependencies:

```toml
[dependencies]
tokio.workspace = true

[dev-dependencies]
# Remove tokio from this section after it is present under [dependencies].
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests
cargo test -p xray-core-rs --test core_lifecycle_tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-core-rs/Cargo.toml crates/xray-core-rs/src/lib.rs crates/xray-core-rs/src/outbound.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs crates/xray-core-rs/tests/core_lifecycle_tests.rs
git commit -m "feat(core): select raw vless tcp outbound"
```

---

## Task 3: Core SOCKS5 Runtime Listener

**Files:**
- Create: `crates/xray-core-rs/src/socks.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/tests/core_lifecycle_tests.rs`

- [ ] **Step 1: Write failing lifecycle listener tests**

Update `crates/xray-core-rs/tests/core_lifecycle_tests.rs` to use a raw TCP config and add listener address assertions:

```rust
use std::net::{IpAddr, Ipv4Addr};

use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    StreamSecurity, StreamSettings, TargetAddr, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{Core, CoreError, CoreState};
use uuid::Uuid;

fn runtime_config() -> CoreConfig {
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
                server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 9,
                users: vec![VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: None,
                }],
            }),
        }],
        default_outbound_tag: None,
    }
}

#[tokio::test]
async fn core_start_binds_socks_listener_and_exposes_addr() {
    let mut core = Core::new(runtime_config()).unwrap();

    core.start().await.unwrap();
    let addr = core.inbound_addr(Some("socks-in")).unwrap();

    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(addr.port(), 0);

    core.stop().await.unwrap();
}

#[tokio::test]
async fn core_start_fails_without_supported_socks_inbound() {
    let mut config = runtime_config();
    config.inbounds.clear();
    let mut core = Core::new(config).unwrap();

    assert!(matches!(core.start().await, Err(CoreError::NoSupportedInbound)));
    assert_eq!(core.state(), CoreState::Created);
}
```

Keep existing lifecycle tests for `Created -> Running -> Stopped`, double start, and stopped terminal behavior, but construct the core with `runtime_config()` instead of the REALITY fixture.

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p xray-core-rs --test core_lifecycle_tests
```

Expected: FAIL because `inbound_addr` and real listener binding do not exist.

- [ ] **Step 3: Implement SOCKS runtime task supervision**

Add `crates/xray-core-rs/src/socks.rs`:

```rust
use std::sync::Arc;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use xray_config::CoreConfig;
use xray_proxy::inbound::socks::{
    negotiate_socks5_no_auth, parse_socks5_request, write_socks5_failure, write_socks5_success,
};

use crate::outbound::{open_vless_tcp_stream, select_vless_tcp_outbound};

pub async fn serve_socks_listener(
    listener: TcpListener,
    config: Arc<CoreConfig>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else {
                    continue;
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    handle_socks_connection(stream, config).await;
                });
            }
        }
    }
}

async fn handle_socks_connection(mut inbound: TcpStream, config: Arc<CoreConfig>) {
    if negotiate_socks5_no_auth(&mut inbound).await.is_err() {
        return;
    }

    let target = match parse_socks5_request(&mut inbound).await {
        Ok(target) => target,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    let outbound = match select_vless_tcp_outbound(&config) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    let mut outbound_stream = match open_vless_tcp_stream(&outbound, &target).await {
        Ok(stream) => stream,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    if write_socks5_success(&mut inbound).await.is_err() {
        return;
    }

    let _ = copy_bidirectional(&mut inbound, &mut outbound_stream).await;
}
```

This version may spawn per-connection tasks from the listener. Because `Core::stop()` aborts listener tasks, connection tasks can outlive the listener only until their sockets close; Task 4's end-to-end test exercises the normal completed relay path. A later hardening task can replace per-connection `tokio::spawn` with a `JoinSet` if we need graceful connection draining.

Update `crates/xray-core-rs/src/lib.rs`:

```rust
mod socks;

use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use xray_config::{InboundProtocol, CoreConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundInbound {
    pub tag: Option<String>,
    pub addr: SocketAddr,
}

struct RuntimeState {
    inbounds: Vec<BoundInbound>,
    tasks: Vec<JoinHandle<()>>,
}

pub struct Core {
    config: CoreConfig,
    state: CoreState,
    shutdown: Shutdown,
    tun: TunEndpoint,
    runtime: Option<RuntimeState>,
}

pub fn inbound_addr(&self, tag: Option<&str>) -> Option<SocketAddr> {
    self.runtime.as_ref()?.inbounds.iter().find_map(|inbound| {
        if inbound.tag.as_deref() == tag {
            Some(inbound.addr)
        } else {
            None
        }
    })
}
```

In `Core::start()`:

```rust
let mut bound = Vec::new();
let mut tasks = Vec::new();
let config = Arc::new(self.config.clone());

for inbound in &self.config.inbounds {
    if inbound.protocol != InboundProtocol::Socks {
        continue;
    }
    let listener = TcpListener::bind((inbound.listen.as_str(), inbound.port))
        .await
        .map_err(CoreError::Io)?;
    let addr = listener.local_addr().map_err(CoreError::Io)?;
    bound.push(BoundInbound {
        tag: inbound.tag.clone(),
        addr,
    });
    let shutdown = self.shutdown.subscribe();
    let config_for_task = Arc::clone(&config);
    tasks.push(tokio::spawn(async move {
        socks::serve_socks_listener(listener, config_for_task, shutdown).await;
    }));
}

if bound.is_empty() {
    return Err(CoreError::NoSupportedInbound);
}

self.runtime = Some(RuntimeState { inbounds: bound, tasks });
self.state = CoreState::Running;
```

In `Core::stop()`:

```rust
self.shutdown.signal();
if let Some(runtime) = self.runtime.take() {
    for task in runtime.tasks {
        task.abort();
        let _ = task.await;
    }
}
self.tun.close();
self.state = CoreState::Stopped;
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p xray-core-rs --test core_lifecycle_tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-core-rs/src/lib.rs crates/xray-core-rs/src/socks.rs crates/xray-core-rs/tests/core_lifecycle_tests.rs
git commit -m "feat(core): bind socks runtime listener"
```

---

## Task 4: End-to-End SOCKS5 to VLESS TCP Data Path

**Files:**
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`
- Modify: runtime files only if the E2E test exposes gaps.

- [ ] **Step 1: Add failing E2E test**

Append this test structure to `crates/xray-core-rs/tests/runtime_data_path_tests.rs`:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use xray_core_rs::Core;

#[tokio::test]
async fn socks_client_reaches_echo_target_through_vless_tcp_outbound() {
    let echo_addr = spawn_echo_server().await;
    let vless_addr = spawn_fake_vless_server().await;
    let mut config = runtime_config_with_vless_server(vless_addr);

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello runtime").await.unwrap();
    let mut echoed = vec![0; "hello runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello runtime");
    core.stop().await.unwrap();
}
```

Add helpers in the same test file:

```rust
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });
    addr
}

async fn spawn_fake_vless_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_header(&mut inbound).await;
        let mut outbound = TcpStream::connect(target).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    });
    addr
}

async fn socks5_connect(client: &mut TcpStream, target: std::net::SocketAddr) {
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1];
    match target.ip() {
        std::net::IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(_) => panic!("test uses ipv4"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
}
```

Implement `read_vless_header` in the test file by reading:

- version byte and assert `0`.
- 16-byte UUID and assert the configured UUID.
- addons length and skip that many bytes.
- command and assert `1`.
- port.
- address type and address.

Return a `SocketAddr` for IPv4 targets.

- [ ] **Step 2: Run E2E test and verify it fails**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
```

Expected: FAIL if Task 3 did not fully connect/relay yet; otherwise it may pass. If it passes immediately because Task 3 already implemented the full path, document that in the task notes and continue.

- [ ] **Step 3: Confirm and fix the exact runtime relay paths**

Confirm these runtime paths are present. Add only the missing lines needed to satisfy this checklist:

- If SOCKS method negotiation hangs, check `negotiate_socks5_no_auth`.
- If success reply arrives before outbound header, move `write_socks5_success` after `open_vless_tcp_stream`.
- If bytes do not echo, ensure `copy_bidirectional` is called after success reply and both streams are mutable.
- If fake VLESS header parsing fails, confirm `open_vless_tcp_stream` passes the SOCKS target into `encode_request_header`.

Do not add HTTP, REALITY, DNS, or TUN behavior in this task.

- [ ] **Step 4: Run focused E2E and core tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests
cargo test -p xray-core-rs --test core_lifecycle_tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-core-rs/src crates/xray-core-rs/tests/runtime_data_path_tests.rs crates/xray-core-rs/tests/core_lifecycle_tests.rs
git commit -m "test(core): prove socks to vless tcp data path"
```

---

## Task 5: Final Verification and Documentation

**Files:**
- Modify: `docs/verification.md`
- Modify: `README.md`

- [ ] **Step 1: Update docs for runtime data path**

Add to `docs/verification.md` under local Rust checks:

```markdown
Run the first live runtime data-path test:

```sh
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
```
```

Update `README.md` first implementation status to say the raw TCP VLESS data path is executable for test/local SOCKS5 traffic, while TLS/REALITY/Vision live traffic remains future work.

- [ ] **Step 2: Run full verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go test ./testing/scenarios -run TestVlessXtlsVisionReality -count=1
```

Expected:

- Rust commands PASS.
- Go oracle PASS when the environment permits loopback binding and Go build cache access.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/verification.md
git commit -m "docs: document runtime data path verification"
```

---

## Self-Review Notes

Spec coverage:

- SOCKS5 listener and method negotiation: Task 1 and Task 3.
- VLESS/TCP outbound with existing wire encoder: Task 2 and Task 4.
- No TLS/REALITY/Vision live path: Task 2 rejection tests and Task 4 non-goals.
- Runtime lifecycle and shutdown: Task 3 and Task 4.
- End-to-end echo proof: Task 4.
- Verification documentation: Task 5.

Known residual work after this plan:

- HTTP CONNECT listener.
- DNS resolver for VLESS server domains.
- REALITY/TLS protected connector implementation.
- Vision traffic wrapping in the live relay.
- TUN data path.
- FFI start/stop and packet APIs.
