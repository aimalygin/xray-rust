# Runtime Domain Target Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that resolver-injected outbound server DNS does not resolve or rewrite SOCKS domain targets before VLESS header encoding.

**Architecture:** Keep runtime behavior unchanged unless the new test exposes a regression. Add protocol-observing test helpers in `runtime_data_path_tests.rs`, and add small documentation comments for resolver scope and port contract.

**Tech Stack:** Rust 2021, Tokio, SOCKS5 test helpers, VLESS wire parsing in integration tests, existing `xray-core-rs`, `xray-routing`, and `xray-transport`.

---

## File Structure

- `crates/xray-core-rs/tests/runtime_data_path_tests.rs`: add a domain-target runtime E2E, SOCKS domain CONNECT helper, and a VLESS target parser helper.
- `crates/xray-core-rs/src/lib.rs`: add a narrow rustdoc comment for `Core::with_dns_resolver` and a short comment for the stale server-address error variant.
- `crates/xray-transport/src/lib.rs`: add a rustdoc comment documenting the `DnsResolver` port/return-address contract.

---

## Task 1: Domain Target Runtime E2E

**Files:**
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write failing domain-target E2E**

Add this test and scenario after `socks_client_reaches_echo_target_through_domain_vless_server`:

```rust
#[tokio::test]
async fn socks_client_preserves_domain_target_through_domain_vless_server() {
    timeout(
        Duration::from_secs(2),
        run_domain_target_preservation_scenario(),
    )
    .await
    .unwrap();
}

async fn run_domain_target_preservation_scenario() {
    let expected_target = Target::new(
        RoutingTargetAddr::Domain("example.com".to_owned()),
        443,
        RoutingNetwork::Tcp,
    );
    let (vless_addr, vless_handle) =
        spawn_vless_target_assertion_server(expected_target).await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_config_with_vless_domain_server("vless.test", vless_addr.port());

    let mut core = Core::with_dns_resolver(config, std::sync::Arc::new(resolver)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect_domain(&mut client, "example.com", 443).await;

    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}
```

- [ ] **Step 2: Run test and verify RED**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_preserves_domain_target_through_domain_vless_server
```

Expected: FAIL to compile because `spawn_vless_target_assertion_server` and `socks5_connect_domain` do not exist.

- [ ] **Step 3: Add VLESS target assertion server**

Add this helper near `spawn_fake_vless_server`:

```rust
async fn spawn_vless_target_assertion_server(expected_target: Target) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_target(&mut inbound).await;
        assert_eq!(target, expected_target);
    });
    (addr, handle)
}
```

Add this VLESS target parser before `read_vless_header`:

```rust
async fn read_vless_target(stream: &mut TcpStream) -> Target {
    let version = stream.read_u8().await.unwrap();
    assert_eq!(version, 0);

    let mut uuid = [0; 16];
    stream.read_exact(&mut uuid).await.unwrap();
    assert_eq!(uuid, TEST_UUID_BYTES);

    let addons_len = stream.read_u8().await.unwrap();
    assert_eq!(addons_len, 0);
    let mut addons = vec![0; usize::from(addons_len)];
    stream.read_exact(&mut addons).await.unwrap();

    let command = stream.read_u8().await.unwrap();
    assert_eq!(command, 1);

    let port = stream.read_u16().await.unwrap();
    let address_type = stream.read_u8().await.unwrap();
    let addr = match address_type {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await.unwrap();
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        2 => {
            let len = stream.read_u8().await.unwrap();
            let mut domain = vec![0; usize::from(len)];
            stream.read_exact(&mut domain).await.unwrap();
            RoutingTargetAddr::Domain(String::from_utf8(domain).unwrap())
        }
        3 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await.unwrap();
            RoutingTargetAddr::Ip(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        other => panic!("unsupported VLESS address type {other}"),
    };

    Target::new(addr, port, RoutingNetwork::Tcp)
}
```

Change `read_vless_header` to reuse the parser:

```rust
async fn read_vless_header(stream: &mut TcpStream) -> SocketAddr {
    let target = read_vless_target(stream).await;
    let RoutingTargetAddr::Ip(ip) = target.addr else {
        panic!("this E2E expects an IP VLESS target");
    };
    SocketAddr::new(ip, target.port)
}
```

- [ ] **Step 4: Add SOCKS domain CONNECT helper**

Add this helper after `socks5_connect`:

```rust
async fn socks5_connect_domain(client: &mut TcpStream, domain: &str, port: u16) {
    let domain_len = u8::try_from(domain.len()).unwrap();

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 3, domain_len];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}
```

- [ ] **Step 5: Run focused tests and verify GREEN**

Run with loopback permission:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_preserves_domain_target_through_domain_vless_server
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_domain_vless_server
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/xray-core-rs/tests/runtime_data_path_tests.rs
git commit -m "test(core): preserve socks domain target through dns runtime"
```

---

## Task 2: Resolver Scope Comments

**Files:**
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-transport/src/lib.rs`

- [ ] **Step 1: Add resolver contract rustdoc**

Update `crates/xray-transport/src/lib.rs` above `DnsResolver`:

```rust
/// Resolves a domain and configured port into the concrete socket address to dial.
///
/// Callers pass the configured port and dial the returned `SocketAddr` as-is.
/// This keeps platform-specific DNS and deterministic test resolvers explicit.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError>;
}
```

- [ ] **Step 2: Add Core resolver scope rustdoc and stale variant comment**

Update `crates/xray-core-rs/src/lib.rs` around `CoreError::UnsupportedOutboundServerAddress`:

```rust
    // Reserved for future config address kinds; current VLESS TCP selection supports IP and domain servers.
    #[error("outbound server address is not supported")]
    UnsupportedOutboundServerAddress,
```

Add this comment to `Core::with_dns_resolver`:

```rust
    /// Creates a core with an injected DNS resolver.
    ///
    /// The resolver is currently used by runtime outbound dialers to resolve
    /// configured outbound server domains. It is not a full Xray DNS policy hook.
    pub fn with_dns_resolver(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, CoreError> {
```

- [ ] **Step 3: Run docs/code quality checks**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/xray-core-rs/src/lib.rs crates/xray-transport/src/lib.rs
git commit -m "docs(core): clarify dns resolver scope"
```

---

## Task 3: Full Verification

**Files:**
- No source changes unless verification exposes a blocker.

- [ ] **Step 1: Run full Rust verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
```

Expected: PASS. The full test suite needs loopback bind/connect permission for SOCKS runtime tests in this sandbox.

- [ ] **Step 2: Commit any verification-only fix**

If Step 1 exposes a formatter or clippy issue, fix the specific issue and commit it with a narrow message. If no issue appears, do not create a commit.

- [ ] **Step 3: Final status check**

Run:

```bash
git status --short
```

Expected: no output.

---

## Self-Review Notes

Spec coverage:

- Domain SOCKS target stays encoded as domain in VLESS header: Task 1.
- Fake resolver does not handle SOCKS target domain: Task 1 uses `StaticDnsResolver`, which only resolves `vless.test`.
- Existing IP-target and domain-outbound E2E coverage remains: Task 1 focused tests.
- Resolver scope and port contract comments: Task 2.
- Stale error variant is not removed in this behavior slice: Task 2 comment only.
- Full verification: Task 3.

Known residual work after this plan:

- Remove or replace `UnsupportedOutboundServerAddress` in a later API cleanup.
- Add HTTP CONNECT runtime domain-target preservation once HTTP runtime exists.
- Implement REALITY/TLS live transport and Vision wrapping.
