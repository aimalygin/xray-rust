# Runtime Data Path Design

## Goal

Build the first executable client data path for the Rust mobile/client core:

```text
SOCKS5 client -> xray-core-rs runtime -> VLESS over raw TCP -> test VLESS server -> echo target
```

This phase proves that the crate boundaries from the first slice can carry real bytes end to end. It deliberately stays below TLS, REALITY, Vision traffic wrapping, TUN integration, and mobile start/stop FFI. Those remain future phases once the plain TCP path is observable and testable.

## Approach

Use a narrow vertical slice:

1. Runtime listens on configured local SOCKS5 inbounds.
2. A SOCKS5 CONNECT request becomes a `Session`/`Target`.
3. Static routing selects the first/default VLESS outbound.
4. The runtime opens a raw TCP connection to the configured VLESS server.
5. It writes the VLESS TCP request header with the inbound target.
6. It relays client and outbound streams with bounded Tokio copy tasks.
7. `Core::stop()` signals shutdown, closes listeners, and waits for tasks to finish or aborts them.

The end-to-end test uses a fake VLESS TCP server rather than Go Xray-core. The fake server validates the VLESS header, connects to a local echo server, and relays payload bytes. Go Xray-core remains the oracle for protocol behavior, but the real REALITY/Vision compatibility test waits until the protected connector exists.

## Non-Goals

- No TLS or REALITY connection implementation.
- No plaintext fallback for `security = "tls"` or `security = "reality"`.
- No HTTP CONNECT listener in the first implementation task, although the design leaves the same handler shape available for HTTP next.
- No TUN packet routing in this phase.
- No public mobile FFI start/stop functions yet.
- No DNS resolver. The VLESS server address must be an IP address for this phase; domain targets requested by the SOCKS5 client are still encoded into the VLESS header.

## Core API Changes

`Core` remains the owner of runtime state. The new API surface should stay small:

- `Core::start()` binds SOCKS5 listeners and starts accept loops.
- `Core::stop()` signals shutdown and joins or aborts runtime tasks.
- `Core::inbound_addr(tag: Option<&str>) -> Option<SocketAddr>` returns the bound listener address. This lets tests and embedders use port `0` without racing on port selection.

Lifecycle rules remain:

- `Created -> Running -> Stopped`.
- Double start returns `AlreadyRunning`.
- Start after stop remains `AlreadyStopped`.
- A failed start must leave the core in `Created` and must clean up any partially started listeners/tasks.

## Runtime Components

### Inbound Listener

Add a SOCKS5 listener module under `xray-core-rs` or `xray-runtime`, whichever keeps dependencies cleanest after inspection. The listener:

- Binds `InboundConfig.listen:port`.
- Stores its actual `SocketAddr`.
- Accepts connections until shutdown.
- Parses SOCKS5 CONNECT using the existing `xray_proxy::inbound::parse_socks5_connect`.
- Sends a SOCKS5 success reply only after the outbound stream has connected and the VLESS header has been written.
- Sends a failure reply and closes on parse, route, or outbound errors.

### Outbound Dialer

For this phase, support only:

- `OutboundSettings::Vless`.
- `StreamSecurity::None`.
- `Network::Tcp`.
- Server address as `TargetAddr::Ip`.
- First VLESS user.

Unsupported combinations must return explicit errors before any network downgrade. This follows the existing `TcpConnector` protected-config guard.

### Relay

Use `tokio::io::copy_bidirectional` or a small equivalent wrapper. The relay should:

- Avoid buffering entire streams.
- End when either side closes.
- Respect shutdown by closing/aborting the owning connection task.
- Not spawn unbounded detached work that survives `Core::stop()`.

## Error Handling

Add `CoreError` variants for:

- Bind/listener failure.
- No supported inbound.
- No supported outbound.
- Unsupported outbound security/network/server address.
- Outbound connect failure.
- VLESS header encoding failure.
- Runtime task join failure if needed.

Connection-level errors should close that connection without stopping the whole core. Startup errors should fail `Core::start()`.

## Testing

Use TDD with three layers:

1. Unit tests for outbound selection and unsupported-mode errors.
2. Runtime lifecycle tests proving listeners bind on port `0`, expose `inbound_addr`, stop cleanly, and preserve terminal stopped semantics.
3. End-to-end integration test:
   - Start local echo server.
   - Start fake VLESS server that validates the VLESS header and proxies to the echo server.
   - Start `Core` with a SOCKS5 inbound on `127.0.0.1:0` and VLESS outbound to the fake server.
   - Connect with a SOCKS5 client, request the echo target, send bytes, and assert the same bytes return.

The test must fail before production code exists, then pass with the minimal runtime implementation.

## Compatibility Notes

The VLESS header must continue to be produced by `xray_proxy::vless::encode_request_header`; no duplicate wire encoding should appear in runtime code.

REALITY and Vision are intentionally absent from the live data path in this phase. The runtime must reject those configs for live connection attempts rather than silently sending plaintext.

## Open Extension Points

- HTTP CONNECT can reuse the same session/outbound relay after adding an HTTP success response.
- REALITY can replace the raw TCP connector behind the outbound dialer without changing inbound handling.
- TUN can feed `Session` and packet streams into the same routing/outbound layer once the stream path is stable.
- FFI start/stop can call the `Core` lifecycle once runtime semantics are proven.
