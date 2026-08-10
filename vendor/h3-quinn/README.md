# h3-quinn

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/hyperium/h3/workflows/CI/badge.svg)](https://github.com/hyperium/h3/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/h3-quinn.svg)](https://crates.io/crates/h3-quinn)
[![Documentation](https://docs.rs/h3-quinn/badge.svg)](https://docs.rs/h3-quinn)

QUIC transport implementation for [h3](https://github.com/hyperium/h3) based on [Quinn](https://github.com/quinn-rs/quinn).

## Vendoring note

This directory is a source copy of the crates.io `h3-quinn` 0.0.10 release,
used through the workspace's `[patch.crates-io]` entry. The only code change is
in `RecvStream`: it keeps the Quinn receive stream in the adapter while
polling the cancellation-safe `read_chunk` future. Upstream 0.0.10 temporarily
moves that stream into a pending future, so an immediate HTTP/3
`STOP_SENDING(H3_REQUEST_CANCELLED)` unwraps an empty `Option` and panics.

The focused regressions
`h3_quinn_recv_stream_remains_stoppable_after_a_pending_read` and
`response_drop_after_upload_fin_cancels_stream_and_reuses_connection` in
`crates/xray-transport/tests/stream_xhttp_h3_tests.rs` pin both the adapter
behavior and the end-to-end connection-reuse contract. Keep this patch local
until the same cancellation fix is available in a compatible upstream
release, then remove the path override and this vendored copy together.

## Overview

`h3-quinn` provides the integration between the `h3` HTTP/3 implementation and the `quinn` QUIC transport library. This creates a fully functional HTTP/3 client and server using Quinn as the underlying QUIC implementation.

## Features

- Complete implementation of the `h3` QUIC transport traits
- Full support for HTTP/3 client and server functionality
- Optional tracing support
- Optional datagram support

## License

This project is licensed under the [MIT license](LICENSE).

## See Also

- [h3](https://github.com/hyperium/h3) - The core HTTP/3 implementation
- [Quinn](https://github.com/quinn-rs/quinn) - The QUIC implementation used by this crate
