# tokio-rustls 0.26.4 on the shaped-rustls package

Source: the crates.io `tokio-rustls` **0.26.4** archive,
SHA256 `1729aa945f29d91ba541258c8df89027d5792d85a8841fb65e8bf0f4ede4ef61`,
without its `tests` directory. Upstream licenses and the published lockfile
remain intact. `XRAY-PATCH.diff` reconstructs the local copy from that archive
with zero fuzz; `scripts/check-vendored-sources.sh` verifies the archive and
the exact reconstruction, and checks that the copy builds on the reconstructed
fork.

## What this copy is for

Nothing in production reads through it. The client side of TLS is
`crates/xray-transport/src/tls_stream.rs`. This crate provides `TlsAcceptor`
for the TLS servers of the workspace's tests and of `xray-bench`.

Those servers have to speak the same `rustls` types as the clients under
test: one `ServerConfig` often serves a TCP listener and a QUIC endpoint, and
several tests hand the server the fork's certificate compressors. The
workspace takes the rustls fork under its own package name, `shaped-rustls`,
and crates.io's tokio-rustls depends on the `rustls` package, so this copy
depends on `shaped-rustls` instead. With it the build holds one TLS library,
as it did when `[patch.crates-io]` put the fork under the name `rustls`.

The workspace names this copy by path and without a version, so a published
crate's manifest drops it together with the other dev-dependencies.

## Changes

`XRAY-PATCH.diff` touches `Cargo.toml` alone; every source file is upstream's.

- The `rustls` dependency is the `shaped-rustls` package at
  `../shaped-rustls`, version `0.23.4600` (rustls 0.23.46).
- The five `[[test]]` targets and the dev-dependencies are removed with the
  `tests` directory they belong to. That directory holds upstream's test
  certificates and their private key, which this repository does not carry;
  the crate's own unit tests read it, so they are not run against this copy.
  The workspace's test suites are what exercises it.

Remove this directory when the tests build their servers on something else,
or when a tokio-rustls built on `shaped-rustls` is available from a registry.
