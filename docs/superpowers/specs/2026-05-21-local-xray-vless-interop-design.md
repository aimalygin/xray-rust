# Local Xray VLESS Interop Design

## Goal

Build the first real local cross-process connection test:

`SOCKS client -> Rust core SOCKS inbound -> Rust VLESS/TCP outbound -> local Xray-core VLESS inbound -> Xray freedom outbound -> local echo server`

The test proves that the current Rust VLESS/TCP client path can talk to the latest cloned Go Xray-core over the wire. It is intentionally scoped to raw VLESS/TCP without TLS, REALITY, or Vision because the live REALITY TLS provider is not implemented yet. This gives us a trustworthy local launch point without closing the path to TLS, REALITY, Vision, mobile, or tvOS support.

## Context

The repository already has in-process runtime tests that use a fake VLESS server. Those tests validate the Rust runtime data path but do not validate protocol interoperability against Xray-core. The cloned `Xray-core` directory is an ignored oracle checkout, so linked git worktrees do not contain it by default.

Xray-core can be launched from a JSON config via:

`xray run -config <config.json>`

Its JSON config can expose a VLESS inbound with a fixed UUID and route to a freedom outbound, which will connect to the target requested by the Rust VLESS client.

## Approach Options

1. Rust integration test starts a local Xray binary from JSON config.
   This is the chosen approach. It keeps the harness in Rust, exercises the actual Rust core, uses Xray-core exactly as an external process, and avoids adding Go helper modules to the Rust workspace.

2. Go helper program builds protobuf configs and starts Xray internals.
   This would reuse Xray-core test infrastructure more directly, but it couples the Rust harness to Go protobuf internals and requires a second local Go module.

3. Keep using only Xray-core Go scenario tests.
   This verifies Go Xray-core behavior, but it still does not prove the Rust client can interoperate with Xray-core.

## Architecture

The harness lives as an ignored Rust integration test in `crates/xray-core-rs/tests/local_xray_interop_tests.rs`. It is ignored by default because it builds and runs the Go Xray-core binary, opens loopback listeners, and is slower than the normal unit suite.

The test resolves the Xray-core checkout in this order:

1. `XRAY_CORE_CHECKOUT`
2. `<workspace root>/Xray-core`

This matters because normal repository checkouts can keep the ignored `Xray-core` folder beside the Rust workspace, while feature worktrees can point back to the original checkout with an environment variable.

## Test Flow

1. Allocate a local TCP port for Xray-core.
2. Start an async local echo server on `127.0.0.1:0`.
3. Build the Xray-core binary into a temporary directory with `go build -o <tmp>/xray ./main`.
4. Write a minimal Xray JSON server config:
   - VLESS inbound on `127.0.0.1:<xray_port>`
   - client UUID `00010203-0405-0607-0809-0a0b0c0d0e0f`
   - decryption `none`
   - freedom outbound
5. Start `xray run -config <config.json>` and wait until the VLESS port accepts TCP.
6. Start the Rust `Core` with:
   - SOCKS inbound on `127.0.0.1:0`
   - VLESS/TCP outbound to the Xray VLESS inbound
   - same UUID and `encryption = "none"`
7. Act as a SOCKS5 client, connect through the Rust core to the echo server, send a payload, and assert the same bytes are returned.
8. Stop Rust core, kill Xray, and remove temporary files.

## Error Handling

The Xray child process is owned by a small test guard that kills the process on drop. If startup polling fails, the panic includes the child process status when available. Temporary directories are created under the OS temp directory and removed on guard drop.

The SOCKS and echo pieces use short Tokio timeouts to keep failures bounded. A failed SOCKS reply, missing echo, Xray build error, or Xray startup failure fails the test directly.

## Compatibility Scope

This milestone proves:

- Rust VLESS/TCP request header and stream forwarding are compatible with local Xray-core VLESS inbound.
- Rust SOCKS inbound can drive a real proxied TCP session through Xray-core.
- The test harness can build and run the cloned Xray-core as a local oracle.

It does not claim:

- TLS/uTLS parity.
- REALITY live handshakes.
- Vision packet semantics.
- UDP, routing policies, DNS policy parity, mobile packaging, or tvOS packaging.

Those remain open and are easier to add once this process-level interop harness exists.

## Verification

Default verification remains:

`cargo fmt --all -- --check`

`cargo clippy --workspace --all-targets --locked -- -D warnings`

`cargo test --workspace --all-targets`

The new local interop verification is explicit:

`XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp`

