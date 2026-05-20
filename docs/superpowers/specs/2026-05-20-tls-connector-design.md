# TLS Connector Design

## Goal

Add the first live protected transport path by implementing TLS over the existing boxed transport stream boundary.

This slice should let a VLESS TCP outbound with `streamSettings.security = "tls"` open a real TLS connection, write the existing VLESS request header over that protected stream, and keep the SOCKS relay unchanged.

## Non-Goals

- No REALITY live connector.
- No Vision wrapping in the relay.
- No uTLS or browser fingerprint emulation.
- No ALPN, custom certificate chains, pinned certificates, insecure mode, custom verification, session tickets, or Xray TLS option parity beyond `serverName`.
- No change to VLESS header encoding.
- No change to the SOCKS copy loop.
- No platform-native TLS backend or OpenSSL dependency.

## Transport Architecture

`xray-transport` will own the TLS transport implementation.

Add a `TlsConnector` that:

- accepts `TlsClientConfig`;
- accepts only already resolved IP targets at connect time;
- returns `BoxedTransportStream`;
- creates a TCP connection first;
- wraps the TCP stream with `tokio-rustls`;
- uses `TlsClientConfig.server_name` for SNI and certificate name verification;
- returns `TransportError::NeedsDns` for domain targets, matching `TcpConnector`.

`TcpConnector` remains raw TCP only and must continue to reject `ConnectorConfig::Tls(_)` and `ConnectorConfig::Reality(_)`. This keeps plaintext downgrade prevention explicit.

Add a small `TransportDialer` in `xray-transport`:

```rust
pub struct TransportDialer {
    tls: TlsConnector,
}

impl TransportDialer {
    pub fn system() -> Result<Self, TransportError>;

    pub async fn connect(
        &self,
        config: &ConnectorConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError>;
}
```

`TransportDialer::connect` selects:

- `ConnectorConfig::Tcp` -> `TcpConnector::new(ConnectorConfig::Tcp).connect(target)`;
- `ConnectorConfig::Tls(config)` -> `self.tls.connect(target, config)`;
- `ConnectorConfig::Reality(_)` -> `TransportError::UnsupportedConnectorConfig("reality")`.

The dialer is intentionally small. Its job is only to hide transport selection from core and provide a future slot for REALITY without changing runtime relay code.

## TLS Root Store

Use `rustls` and `tokio-rustls`, with `webpki-roots` as the default root source.

Reasons:

- no OpenSSL or platform TLS binding;
- predictable cross-compilation path for iOS, tvOS, Android, macOS, Linux, and Windows;
- compatible with the existing mobile-first memory/resource constraints.

`rustls` 0.23 defaults to `aws-lc-rs`. For this mobile-first baseline, configure the workspace `rustls` and `tokio-rustls` dependencies with `default-features = false` and the `ring` provider feature. This avoids the `aws-lc-sys`/CMake default path while keeping the provider choice explicit. If later mobile build-matrix testing or FIPS requirements favor `aws-lc-rs`, that decision should stay behind the same `TlsConnector` boundary.

Build the default `rustls::ClientConfig` once per `TlsConnector` and store it behind `Arc<rustls::ClientConfig>`. Do not rebuild the root store per connection.

For tests, expose a constructor that accepts a custom `Arc<rustls::ClientConfig>`:

```rust
impl TlsConnector {
    pub fn system() -> Result<Self, TransportError>;

    pub fn with_client_config(client_config: Arc<rustls::ClientConfig>) -> Self;
}
```

This lets integration tests trust a local self-signed test certificate without weakening production verification.

## Server Name Rules

`TlsClientConfig.server_name` remains a required `String` at the transport layer.

Core derives it from config:

1. If `tlsSettings.serverName` exists and is non-empty, use it.
2. If `tlsSettings.serverName` is absent and the outbound server address is a domain, use that domain.
3. If the outbound server address is an IP and `serverName` is absent or empty, reject the outbound.

Transport validates the final `server_name` with `rustls::pki_types::ServerName`. Invalid names return a transport error before network I/O.

## Fingerprint Handling

The existing config parser stores `tlsSettings.fingerprint`, but this slice must not claim browser fingerprint compatibility.

Core behavior:

- `security: "tls"` with no `fingerprint` is accepted when `serverName` rules pass.
- `security: "tls"` with any `fingerprint` value is rejected with `CoreError::UnsupportedOutboundSecurity`.

This avoids silently treating Xray fingerprinted TLS as ordinary rustls TLS.

REALITY keeps its existing fingerprint-specific parser behavior and remains rejected by the runtime path.

## Core Integration

`VlessTcpOutbound` should carry the selected `ConnectorConfig`:

```rust
pub struct VlessTcpOutbound {
    server: Target,
    user: VlessUser,
    transport: ConnectorConfig,
}
```

`select_vless_tcp_outbound` behavior becomes:

- `StreamSecurity::None` -> `ConnectorConfig::Tcp`;
- `StreamSecurity::Tls(settings)` -> derive `TlsClientConfig` and reject unsupported fingerprints;
- `StreamSecurity::Reality(_)` -> `CoreError::UnsupportedOutboundSecurity`;
- non-TCP network -> `CoreError::UnsupportedOutboundNetwork`;
- VLESS flow -> `CoreError::UnsupportedOutboundFlow`.

`open_vless_tcp_stream_with_resolver` keeps the same high-level order:

1. reject unsupported VLESS flow before DNS or network I/O;
2. resolve only the configured outbound server domain;
3. call `TransportDialer` with the selected `ConnectorConfig`;
4. write the VLESS request header with the original SOCKS target unchanged;
5. return `BoxedTransportStream`.

The SOCKS runtime should not need a semantic rewrite. It should still relay with:

```rust
copy_bidirectional(&mut inbound, &mut outbound_stream).await
```

`Core` will store an `Arc<TransportDialer>` alongside the existing injected DNS resolver. `Core::new` and `Core::with_dns_resolver` use `TransportDialer::system()`. Add a constructor for tests and future embedders that need custom TLS roots:

```rust
pub fn with_runtime_dependencies(
    config: CoreConfig,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
) -> Result<Self, CoreError>
```

This keeps production behavior simple while allowing the TLS runtime E2E test to use a self-signed local certificate without disabling verification.

## Error Handling

Transport should use precise recoverable errors instead of panics.

Add transport errors as needed:

- invalid TLS server name;
- TLS handshake/connect failure, wrapping the underlying `std::io::Error`.

Production code must not use `unwrap` or `expect`.

Test helpers may use `expect` for setup failures.

## Testing

Use TDD around the live TLS boundary.

Transport tests:

1. A TLS echo server using a local self-signed certificate and a client `TlsConnector` with a custom root store proves round-trip bytes over `BoxedTransportStream`.
2. `TlsConnector` returns `TransportError::NeedsDns` for domain targets.
3. `TlsConnector` rejects invalid server names before network I/O.
4. `TcpConnector` still rejects `ConnectorConfig::Tls(_)`, preserving no plaintext downgrade.

Core tests:

1. `select_vless_tcp_outbound` accepts TLS without `fingerprint`.
2. TLS `serverName` defaults from a domain outbound server.
3. TLS with IP outbound server and no `serverName` is rejected.
4. TLS with any `fingerprint` is rejected.
5. REALITY and Vision-flow rejection tests continue to pass.

Runtime E2E:

1. SOCKS client connects through VLESS-over-TLS to an echo target.
2. The fake VLESS TLS server asserts the VLESS target header is unchanged.
3. The test uses injected DNS and a test-only TLS root store; it does not require internet access.

Required verification:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
```

The full test suite needs loopback bind/connect permission in this sandbox.

The Go oracle is not required for this slice if VLESS header bytes remain unchanged. If header construction changes, run the Go oracle before merging.

## Future Extension Path

After this slice:

1. REALITY can become another `BoxedTransportStream` producer.
2. REALITY can reuse the TLS connector pieces only where wire-compatible and explicit.
3. Vision can wrap the established protected stream without changing SOCKS relay.
4. More Xray TLS options can be added one by one behind explicit config support and compatibility tests.
