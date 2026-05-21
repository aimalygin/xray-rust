# Vision Runtime Wrapper Design

## Goal

Add the first runtime-facing Vision boundary so `xtls-rprx-vision` can be carried by a protected stream once REALITY live connect exists, while keeping raw TCP/TLS Vision and live REALITY launch gated.

## Scope

This slice implements a Rust Vision stream wrapper and changes core selection rules. It does not implement the live REALITY connector, does not launch a local Xray-core server, and does not un-ignore `tests/compat/vless_reality_vision.rs`.

## Architecture

`xray-proxy::vless` already owns Vision block padding and unpadding. This slice keeps runtime framing there by adding a small `VisionStream<S>` wrapper around any `AsyncRead + AsyncWrite + Unpin` stream.

Outbound writes convert caller payload bytes into Vision padded blocks using `VisionPadding`. Inbound reads parse complete Vision blocks from the inner stream and return only unpadded payload bytes to the caller. The wrapper owns bounded read/write buffers and does not inspect TLS internals.

`xray-core-rs` keeps VLESS header construction in `open_vless_tcp_stream_with_resolver_and_dialer`. The flow gate changes from "any flow is unsupported" to:

- no flow: supported for TCP, TLS, and selected REALITY configs;
- `xtls-rprx-vision` with REALITY security: selected and allowed to reach the transport boundary;
- `xtls-rprx-vision` with raw TCP or plain TLS: rejected;
- any other flow: rejected by config parsing before runtime.

The live REALITY connector still returns `UnsupportedConnectorConfig("reality")`, so this slice cannot accidentally run a partial non-REALITY Vision session.

## Error Handling

Vision stream parsing returns `std::io::Error` with `InvalidData` for malformed Vision blocks. Existing `VisionError` variants remain deterministic for unit tests. Runtime selection continues to use `CoreError::UnsupportedOutboundFlow` for unsupported flow/security combinations.

## Memory And Mobile Constraints

The wrapper buffers only one encoded block plus pending decoded payload. It accepts caller-provided write chunks without allocating unbounded queues. Future tuning can lower copy size or add platform-specific zero-copy paths behind the same wrapper boundary.

## Tests

Required tests:

- `xray-proxy` duplex tests proving `VisionStream` writes padded bytes that `unpad_vision_block` can decode.
- `xray-proxy` duplex tests proving `VisionStream` reads padded bytes and returns raw payload.
- `xray-core-rs` selection tests proving `VLESS + REALITY + Vision` no longer fails at flow selection.
- Guard tests proving raw TCP/TLS Vision remain rejected, `TransportDialer::Reality` remains rejected, and the ignored compatibility shell remains ignored.

## Verification

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

The first local `VLESS + REALITY + Vision` Xray-core server run remains deferred until the live REALITY connector exists.
