# shaped-rustls: the rustls fork under the TLS and QUIC clients

TLS, REALITY and QUIC client sessions are built on
[shaped-rustls](https://github.com/aimalygin/shaped-rustls), a fork of rustls
with an API for shaping the ClientHello: a customizer for the extension list
and its order, advertise-only cipher suites, GREASE positions, and a finalizer
that seals the hello REALITY sends. Upstream rustls has no such API.

## How the workspace takes it

The fork is the crates.io package
[`shaped-rustls`](https://crates.io/crates/shaped-rustls). Its library is
still named `rustls`, so the workspace writes `rustls::` as it would with
upstream:

```toml
rustls = { package = "shaped-rustls", version = "0.23.4600", ... }
```

The vendored quinn, quinn-proto and tokio-rustls name the same package where
upstream's manifests name `rustls`; that is one manifest hunk in each
`XRAY-PATCH.diff`. No `[patch.crates-io]` entry is involved, and the upstream
`rustls` package is not in the build: `Cargo.lock` has no package of that
name.

`Cargo.lock` pins the release by checksum, like any other registry package.

## Versions

A version is `0.23.PPRR`: upstream rustls patch release `PP`, fork release
`RR`. `0.23.4600` is rustls 0.23.46 with the shaping API.

| Release | rustls | Fork commit | Tag |
| --- | --- | --- | --- |
| 0.23.4600 | 0.23.46 | `474a31b7cb158a681970d048734abc7d7b4d1adc` | `shaped-rustls-0.23.4600` |

The crate archive of 0.23.4600 has SHA-256
`bca996193e4d5b1769d8518203ab6b77d3d28599b42779a38778595dc2ab33cf`, the
checksum in `Cargo.lock`. Its `src` and `build.rs` are that commit's, file for
file; the package leaves out `src/testdata` and the tests.

## Advisories

RustSec advisories are filed against `rustls`, and `cargo audit` does not
connect them to a package named `shaped-rustls`.
`scripts/check-vendored-advisories.sh` reads the fork's version from
`Cargo.lock` and audits the rustls release it carries: `0.23.4600` as rustls
`0.23.46`. A fork release that backports a fix ahead of taking the upstream
release is acknowledged in that script.

## Two properties of the fork

- An unknown extension in a TLS 1.3 certificate entry is ignored, where
  upstream rustls rejects the message, with or without a ClientHello
  customizer. A shaped hello can offer extensions rustls does not implement,
  and a peer may answer one there; Go's `crypto/tls` ignores them too.
- The fork needs Rust 1.85, because its `aws_lc_rs` feature depends on the
  `shake` crate. This workspace's toolchain is newer.

## Moving to a newer release

1. Set the new version in the root `Cargo.toml` and in the manifests of
   `vendor/quinn`, `vendor/quinn-proto` and `vendor/tokio-rustls`, and make the
   same change in the manifest hunk of each crate's `XRAY-PATCH.diff`.
2. `cargo update -p shaped-rustls --precise <version>`.
3. Run the byte oracles, which fail on any change to a ClientHello:
   `cargo test -p xray-transport --test utls_tls_shaping_tests --test
   reality_rustls_tests --test chrome_parrot_tests --test
   reality_clienthello_tests --test utls_hello_retry_tests --test
   shaped_rustls_tests`.
4. Run `scripts/check-vendored-sources.sh`, which tests the vendored quinn and
   quinn-proto on the release `Cargo.lock` names, and
   `scripts/check-vendored-advisories.sh`.
5. Add the release to the table above.

## Trying a fork change before it is released

In a local checkout, point the workspace at a clone of the fork and do not
commit it:

```toml
[patch.crates-io]
shaped-rustls = { path = "/path/to/shaped-rustls/rustls" }
```

The patch has to live in the root manifest of the build, so it reaches the
vendored quinn, quinn-proto and tokio-rustls as well.
