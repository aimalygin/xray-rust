# Runnable Core Binary Design

## Context

The current core can be exercised as a Rust library and has local Xray interop coverage for VLESS over TCP, TLS, TLS+Vision, and REALITY+Vision. The next milestone is a process-level binary that can be launched like Xray:

```bash
xray-rust run -config config.json
```

This should not move protocol logic into the CLI. The binary is a thin runtime shell over the existing config parser and `xray_core_rs::Core`.

## Goals

- Provide the first runnable `xray-rust` executable.
- Support the already-proven path: SOCKS inbound to VLESS outbound over TCP, TLS, TLS+Vision, and REALITY+Vision.
- Keep lifecycle behavior explicit and reusable for later mobile embedding.
- Add process-level interop tests where a SOCKS client talks to a spawned `xray-rust` process instead of calling `Core::new` in-process.
- Keep config semantics aligned with the existing `xray-config` parser.

## Non-Goals

- No daemon/service manager integration.
- No hot reload.
- No stats API, observability API, or admin API.
- No TUN integration in this milestone.
- No mobile FFI changes in this milestone, though the lifecycle boundaries should serve the future FFI layer.

## Architecture

Add a new workspace crate:

```text
crates/xray-cli
```

The crate produces a binary named `xray-rust`. It depends on:

- `xray-config` for JSON parsing.
- `xray-core-rs` for runtime execution.
- `tokio` for async main, signal handling, and task waiting.
- `thiserror` for CLI-level errors.

The binary should remain small:

```text
main.rs
  parse args
  load config file
  construct Core
  start Core
  wait for shutdown signal
  stop Core
```

## CLI Contract

Supported command:

```bash
xray-rust run -config /path/to/config.json
```

Accepted aliases:

```bash
xray-rust run --config /path/to/config.json
```

Initial behavior:

- Unknown commands return a non-zero exit code and a short usage message.
- Missing `-config` returns a non-zero exit code and a short usage message.
- Config parse errors return a non-zero exit code with the parser error.
- Runtime start errors return a non-zero exit code with the core error.
- `Ctrl+C` performs graceful `Core::stop()`.

No new argument parsing dependency is required for the first version. A tiny manual parser is enough for `run -config`, keeps dependency weight low, and can be replaced later if the CLI grows.

## Lifecycle

The CLI owns exactly one `Core`.

Startup:

1. Read config file into memory.
2. Parse JSON with `xray_config`.
3. Construct `Core::new(config)`.
4. Call `core.start().await`.
5. Print a concise startup line to stderr with bound inbound addresses if available.

Shutdown:

1. Wait for `tokio::signal::ctrl_c()`.
2. Call `core.stop().await`.
3. Return exit code `0` if shutdown succeeds.

If signal support is unavailable on a target, the implementation should expose the error clearly. Later mobile embedding will not use process signals; it will call lifecycle methods directly.

## Error Handling

Create a CLI error enum with variants for:

- Invalid arguments.
- File read failure.
- Config parse failure.
- Core construction failure.
- Core start failure.
- Signal wait failure.
- Core stop failure.

Errors should be displayed without debug dumps by default. The first binary is a developer-facing tool, but it should still have predictable output that tests can assert.

## Testing

Unit tests:

- Argument parser accepts `run -config file.json`.
- Argument parser accepts `run --config file.json`.
- Argument parser rejects unknown commands.
- Argument parser rejects missing config path.

Integration tests:

- Build or locate the `xray-rust` binary with Cargo test support.
- Spawn local Xray as the upstream VLESS server using the existing interop harness.
- Spawn `xray-rust run -config generated-client.json`.
- Connect to the `xray-rust` SOCKS inbound as a real TCP client.
- Verify echo through at least:
  - VLESS TCP.
  - VLESS REALITY+Vision.

The existing in-process interop tests stay in place because they are faster and give cleaner failure boundaries. The process-level tests prove the runnable binary and shutdown behavior.

## Compatibility And Future Path

This milestone deliberately keeps protocol and transport logic out of the CLI. Future Android, iOS, and tvOS layers should use the same core lifecycle semantics rather than invoking the process binary. The CLI validates the runtime surface we will later expose over FFI:

- load config
- start
- inspect bound inbounds
- stop

Keeping that boundary small reduces the chance of rewriting lifecycle code when mobile support begins.
