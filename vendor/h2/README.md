# xray-h2

xray-h2 is a fork of [h2](https://github.com/hyperium/h2) 0.4.20, published for
[xray-rust](https://github.com/aimalygin/xray-rust). It is not affiliated with
or endorsed by the h2 project: please report its bugs
[to xray-rust](https://github.com/aimalygin/xray-rust/issues), not upstream.

The library is still named `h2`:

```toml
h2 = { package = "xray-h2", version = "0.4.2000" }
```

The patch number of a version is h2's patch release times 100 plus the
fork's release: `0.4.2000` is h2 0.4.20, fork release 0.
`XRAY-PATCH.md` in this package describes every change, and `XRAY-PATCH.diff`
is the whole difference from the crates.io archive of h2 0.4.20.

Everything below is upstream's own README.

---

# H2

A Tokio aware, HTTP/2 client & server implementation for Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/h2.svg)](https://crates.io/crates/h2)
[![Documentation](https://docs.rs/h2/badge.svg)][dox]

More information about this crate can be found in the [crate documentation][dox].

[dox]: https://docs.rs/h2

## Features

* Client and server HTTP/2 implementation.
* Implements the full HTTP/2 specification.
* Passes [h2spec](https://github.com/summerwind/h2spec).
* Focus on performance and correctness.
* Built on [Tokio](https://tokio.rs).

## Non goals

This crate is intended to only be an implementation of the HTTP/2
specification. It does not handle:

* Managing TCP connections
* HTTP 1.0 upgrade
* TLS
* Any feature not described by the HTTP/2 specification.

This crate is now used by [hyper](https://github.com/hyperium/hyper), which will provide all of these features.

## Usage

To use `h2`, first add this to your `Cargo.toml`:

```toml
[dependencies]
h2 = "0.4"
```

Next, add this to your crate:

```rust
extern crate h2;

use h2::server::Connection;

fn main() {
    // ...
}
```

## FAQ

**Is this an embedded Java SQL database engine?**

[No](https://www.h2database.com).
