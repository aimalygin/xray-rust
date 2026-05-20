# Transport Stream Abstraction Design

## Goal

Prepare the live runtime path for TLS and REALITY connectors without changing current behavior.

The current VLESS outbound dialer returns `tokio::net::TcpStream`, and the SOCKS runtime relays directly against that concrete type. That is fine for raw TCP, but it forces future TLS and REALITY support either to rewrite the runtime relay or to leak protected transport details into core. This slice introduces a small common byte-stream boundary so raw TCP, TLS, and REALITY can later return the same runtime stream type.

## Non-Goals

- No TLS live connector implementation.
- No REALITY live connector implementation.
- No Vision wrapping in the relay.
- No change to config parsing or accepted protected configs.
- No plaintext downgrade: TLS, REALITY, and Vision-flow runtime configs remain rejected until their live path exists.
- No new buffering layer, copy-loop optimization, or platform-specific zero-copy behavior.

## Recommended Shape

Add a boxed stream boundary in `xray-transport`:

```rust
pub trait TransportStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T> TransportStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

pub type BoxedTransportStream = Box<dyn TransportStream>;
```

This avoids Rust trait-object limitations around directly writing `dyn AsyncRead + AsyncWrite + ...`, and it keeps `tokio::io::copy_bidirectional` usable because the boxed stream remains `AsyncRead + AsyncWrite + Unpin`.

Update the connector boundary so `TransportConnector::connect` returns `BoxedTransportStream` instead of an associated concrete stream type. `TcpConnector` boxes its `TcpStream` after connecting. Existing DNS and downgrade behavior remains the same:

- IP target with `ConnectorConfig::Tcp` connects and returns a boxed TCP stream.
- Domain target still returns `TransportError::NeedsDns`.
- `ConnectorConfig::Tls(_)` still returns `UnsupportedConnectorConfig("tls")`.
- `ConnectorConfig::Reality(_)` still returns `UnsupportedConnectorConfig("reality")`.

## Core Integration

Update `xray-core-rs` VLESS outbound helpers to return `BoxedTransportStream`:

```rust
pub async fn open_vless_tcp_stream_with_resolver(
    outbound: &VlessTcpOutbound,
    target: &xray_routing::Target,
    dns_resolver: &dyn xray_transport::DnsResolver,
) -> Result<xray_transport::BoxedTransportStream, CoreError>
```

The function still:

1. rejects unsupported flow before DNS or network I/O;
2. resolves only the configured outbound server target;
3. connects through the raw TCP connector;
4. writes the VLESS request header with the SOCKS target unchanged;
5. returns the connected stream for the runtime relay.

`open_vless_tcp_stream` remains the convenience helper using `SystemDnsResolver`, but returns the boxed stream type.

`crates/xray-core-rs/src/socks.rs` should not need a semantic rewrite. It receives the boxed outbound stream and still calls:

```rust
copy_bidirectional(&mut inbound, &mut outbound_stream).await
```

The important result is that future TLS or REALITY connectors can become another boxed transport producer while the SOCKS runtime stays unchanged.

## Error Handling and Security

This slice is behavior-preserving.

Protected stream configs must still fail before connection:

- `StreamSecurity::Tls(_)`
- `StreamSecurity::Reality(_)`
- non-empty VLESS `flow`, including `xtls-rprx-vision`

The existing tests that prove raw TCP does not silently accept TLS/REALITY configs remain part of the verification set. The abstraction must not be used as an excuse to route protected configs into raw TCP.

## Testing

Use TDD around the type boundary:

1. Add a transport test proving `TcpConnector::connect` returns a stream that can be used as a boxed `TransportStream` in a loopback echo exchange.
2. Update existing transport tests so DNS and protected-connector rejection behavior remains unchanged.
3. Update `xray-core-rs` tests as needed for the new return type.
4. Run the runtime data-path E2E tests to prove SOCKS -> VLESS raw TCP behavior still works with the boxed stream.

Required verification:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
```

The full test suite needs loopback bind/connect permission in this sandbox.

The Go oracle is not required for this foundation slice because no wire protocol behavior should change. If any VLESS header construction or REALITY logic changes, run the Go oracle before merging.

## Future Extension Path

After this slice, the next slices can be smaller and cleaner:

1. Add a TLS connector that returns `BoxedTransportStream`.
2. Allow `StreamSecurity::Tls(_)` selection only when the TLS connector exists.
3. Add a REALITY connector that returns `BoxedTransportStream`.
4. Allow `StreamSecurity::Reality(_)` selection only when the REALITY connector exists.
5. Add Vision wrapping around the established protected stream.

The runtime relay should not have to know which protected transport produced the stream.
