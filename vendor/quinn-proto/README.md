# xray-quinn-proto

xray-quinn-proto is a fork of [quinn-proto](https://github.com/quinn-rs/quinn) 0.11.19, published for
[xray-rust](https://github.com/aimalygin/xray-rust). It is not affiliated with
or endorsed by the Quinn project: please report its bugs
[to xray-rust](https://github.com/aimalygin/xray-rust/issues), not upstream.

The library is still named `quinn_proto`:

```toml
quinn-proto = { package = "xray-quinn-proto", version = "0.11.1900" }
```

Its TLS is [shaped-rustls](https://crates.io/crates/shaped-rustls), a fork of
rustls, where upstream uses rustls.

The patch number of a version is quinn-proto's patch release times 100 plus the
fork's release: `0.11.1900` is quinn-proto 0.11.19, fork release 0.
`XRAY-PATCH.md` in this package describes every change, and `XRAY-PATCH.diff`
is the whole difference from the crates.io archive of quinn-proto 0.11.19.
