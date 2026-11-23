# xray-h3-quinn

xray-h3-quinn is a fork of [h3-quinn](https://github.com/hyperium/h3) 0.0.10, published for
[xray-rust](https://github.com/aimalygin/xray-rust). It is not affiliated with
or endorsed by the h3 project: please report its bugs
[to xray-rust](https://github.com/aimalygin/xray-rust/issues), not upstream.

The library is still named `h3_quinn`:

```toml
h3-quinn = { package = "xray-h3-quinn", version = "0.0.1000" }
```

It is built on `xray-h3` and `xray-quinn` where upstream uses h3 and quinn.
The `datagram` feature is not in this fork: it needs h3-datagram, which is
built on upstream's h3.

The patch number of a version is h3-quinn's patch release times 100 plus the
fork's release: `0.0.1000` is h3-quinn 0.0.10, fork release 0.
`XRAY-PATCH.md` in this package describes every change, and `XRAY-PATCH.diff`
is the whole difference from the crates.io archive of h3-quinn 0.0.10.

Everything below is upstream's own README.

---

# h3-quinn

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/hyperium/h3/workflows/CI/badge.svg)](https://github.com/hyperium/h3/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/h3-quinn.svg)](https://crates.io/crates/h3-quinn)
[![Documentation](https://docs.rs/h3-quinn/badge.svg)](https://docs.rs/h3-quinn)

QUIC transport implementation for [h3](https://github.com/hyperium/h3) based on [Quinn](https://github.com/quinn-rs/quinn).

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
