# Outbound DNS Resolution Design

## Goal

Allow the Rust runtime to use VLESS outbound server addresses configured as domains, while preserving the current raw TCP data path and the explicit rejection of TLS, REALITY, and Vision live traffic.

The immediate supported path becomes:

```text
SOCKS5 client -> xray-core-rs runtime -> resolve VLESS server domain -> VLESS over raw TCP -> fake or real TCP server
```

This resolves only the outbound server address. A domain requested by the SOCKS5 client remains a domain in the VLESS request header and is still handled by the remote VLESS side, matching the current VLESS wire encoder behavior.

## Non-Goals

- No DNS app compatibility, DNS routing rules, fake DNS, hosts file rules, or Xray `domainStrategy` behavior.
- No DNS cache, TTL handling, Happy Eyeballs, or address racing.
- No TLS, REALITY, or Vision live connector implementation.
- No resolution of SOCKS5 target domains before encoding the VLESS request header.
- No change to `TcpConnector` accepting only IP targets.

## Architecture

DNS resolution should be an explicit dependency, not an ad hoc call hidden inside the TCP connector.

Add a small resolver boundary in `xray-transport`:

```rust
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str, port: u16) -> Result<std::net::SocketAddr, TransportError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemDnsResolver;
```

`SystemDnsResolver` uses `tokio::net::lookup_host((domain, port))` and returns the first resolved address. If lookup fails, it returns a DNS transport error. If lookup returns no addresses, it returns an explicit no-address error.

`TcpConnector` remains strict: it still rejects `TargetAddr::Domain` with `TransportError::NeedsDns`. That keeps the transport connector honest and prevents accidental DNS behavior in lower-level connector tests.

## Core Integration

`xray-core-rs` owns the runtime DNS dependency.

`Core::new(config)` should continue to work and use `SystemDnsResolver`. Add a constructor for tests and embedders:

```rust
pub fn with_dns_resolver(
    config: CoreConfig,
    dns_resolver: std::sync::Arc<dyn xray_transport::DnsResolver>,
) -> Result<Self, CoreError>
```

`Core` stores the resolver as an `Arc<dyn DnsResolver>`, passes it to SOCKS listener tasks, and connection handlers pass it to the outbound dialer. This keeps future mobile integration open: iOS, Android, or host apps can later provide platform-aware DNS without changing the runtime data-path shape.

`select_vless_tcp_outbound` should no longer reject `TargetAddr::Domain` for the VLESS server. It should preserve the configured server as a routing `Target` with either `TargetAddr::Ip` or `TargetAddr::Domain`.

The outbound dialer should resolve only the outbound server target:

```text
VlessTcpOutbound.server = server.example:443
SOCKS target = example.org:80

resolve server.example:443 -> 127.0.0.1:12345
TcpConnector connects to 127.0.0.1:12345
VLESS header encodes example.org:80
```

For testability, expose an internal/public helper with an explicit resolver:

```rust
pub async fn open_vless_tcp_stream_with_resolver(
    outbound: &VlessTcpOutbound,
    target: &xray_routing::Target,
    dns_resolver: &dyn xray_transport::DnsResolver,
) -> Result<tokio::net::TcpStream, CoreError>
```

`open_vless_tcp_stream` can remain the convenience production function that uses `SystemDnsResolver`, but runtime code should call the resolver-injected helper so `Core::with_dns_resolver` is meaningful.

## Security and Downgrade Behavior

DNS must not weaken the previous plaintext-downgrade protections.

The runtime must still reject:

- `StreamSecurity::Tls`
- `StreamSecurity::Reality`
- any non-`None` VLESS user `flow`, including `xtls-rprx-vision`
- non-TCP stream networks

These rejections should happen before DNS resolution or TCP connection attempts. A protected config must not trigger DNS and then fall into raw TCP.

`open_vless_tcp_stream_with_resolver` should keep the defensive flow check before resolving or connecting, preserving the invariant even if a `VlessTcpOutbound` is constructed inside tests.

## Error Handling

Add transport-level DNS errors:

```rust
#[error("dns lookup failed for {domain}:{port}: {source}")]
Dns {
    domain: String,
    port: u16,
    source: std::io::Error,
},

#[error("dns lookup returned no addresses for {0}:{1}")]
NoResolvedAddress(String, u16),
```

`CoreError::Transport` already wraps `xray_transport::TransportError`, so SOCKS connection handlers can continue mapping DNS failures to a SOCKS5 general failure reply for that connection.

Startup should not resolve outbound domains. Resolution is per connection for this slice. A later cache or preflight validation layer can be added without changing public config parsing.

## Testing

Use deterministic fake resolvers in `xray-core-rs` tests rather than relying on external DNS.

Required tests:

1. `select_vless_tcp_outbound` accepts a domain VLESS server and preserves the domain target.
2. A fake resolver maps `vless.test` to the fake VLESS server address, and the existing SOCKS -> VLESS -> echo E2E passes with the outbound server configured as `TargetAddr::Domain("vless.test")`.
3. A fake resolver returning `TransportError::NoResolvedAddress` makes `open_vless_tcp_stream_with_resolver` return `CoreError::Transport`.
4. TLS, REALITY, and Vision-flow rejection tests remain in place and do not require DNS.
5. Existing `TcpConnector` tests keep proving that a raw connector refuses unresolved domain targets.

The E2E test should keep bounded `tokio::time::timeout` wrapping and should still await fake server tasks so failures do not disappear after the client assertion.

## Documentation

Update `README.md` and `docs/verification.md` to say the raw TCP VLESS runtime path supports IP outbound servers and deterministic resolver-injected domain server tests. Do not claim full Xray DNS behavior or REALITY interoperability.

## Future Extension Path

This design leaves room for:

- platform-specific mobile DNS resolvers;
- DNS cache and address selection policy;
- Xray-compatible DNS app and routing rules;
- REALITY/TLS connectors that reuse the same resolved outbound target path;
- resolving protected server domains without changing inbound SOCKS/HTTP handling.
