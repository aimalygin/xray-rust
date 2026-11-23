# Publishing Rust crates and documentation

The intended public entry points are `xray-core-rs` for Rust embedders,
`xray-ffi` for C ABI consumers, and `xray-cli` for `cargo install`. Supporting
workspace libraries must be published first because crates.io packages cannot
depend on unpublished path-only crates.

## Current blocker

The transport layer uses the `shaped-rustls` fork of rustls. Its ClientHello
customization API is required for the documented TLS and REALITY fingerprint
behavior and is not present in upstream `rustls`. The workspace depends on it
under its own package name, from crates.io, so rustls no longer stands in the
way ([shaped-rustls.md](shaped-rustls.md)).

The workspace also builds on its own copies of h2, h3, smoltcp, GotaTun,
quinn, quinn-proto and h3-quinn, kept in `vendor/` with local changes, and
calls APIs that exist only in those copies
([vendored-forks.md](vendored-forks.md)).

Each of the seven is a package of its own, `xray-h2`, `xray-h3`,
`xray-h3-quinn`, `xray-quinn`, `xray-quinn-proto`, `xray-smoltcp` and
`xray-gotatun`, which the workspace names by path and version, and the root
manifest has no `[patch.crates-io]` section. All seven are on crates.io, and
CI holds each copy in `vendor/` to the package of its version, so they no
longer stand in the way.

blake3 was one of those copies, for one added method: key derivation with a
byte context. `xray-vless-encryption` now computes the context key itself and
hands it to the registry crate
([vless-encryption-design.md](vless-encryption-design.md)), so blake3 is an
ordinary dependency.

Cargo removes local paths when creating a registry package, so a crates.io
package cannot rely on the copies in `vendor/`: it builds on the registry
packages of the same versions. What stands in the way now is the workspace
itself, steps 5 to 7 below. `cargo publish --no-verify` is not an acceptable
workaround for any of them.

The safe path is:

1. publish the fork under an unambiguous package name, preserving its
   upstream licenses and fork disclosure. Done: `shaped-rustls` 0.23.4600 on
   crates.io is the fork's revision `474a31b7` (rustls 0.23.46);
2. depend on that package by its own name. Done:
   `rustls = { package = "shaped-rustls", version = "0.23.4600", ... }`, a
   registry dependency with no `[patch.crates-io]` entry and no vendored
   copy. No Tokio adapter has to be published with it: the client
   side of TLS is `crates/xray-transport/src/tls_stream.rs`, over
   `rustls::ClientConnection`, so on the TCP path no crates.io package sits
   between the workspace's code and the fork. `tokio-rustls` is only a
   dev-dependency (and a dependency of the unpublished `xray-bench`), for the
   server side of tests: a vendored copy built on `shaped-rustls`, named by
   path without a version, which a published manifest drops;
3. publish the adapted QUIC dependency surface: the vendored quinn and
   quinn-proto depend on `shaped-rustls` and carry other local changes as
   well. Done: `xray-quinn-proto` 0.11.1900 and `xray-quinn` 0.11.1200 are on
   crates.io, with `xray-h3-quinn` 0.0.1000 on top;
4. do the same for the other overridden crates: send upstream what upstream
   can take, and publish the rest under names of their own. The publishing
   is done: `xray-h2` 0.4.2000, `xray-h3` 0.0.800, `xray-smoltcp` 0.14.0 and
   `xray-gotatun` 0.9.100 are on crates.io. Sending upstream what upstream
   can take remains open and blocks nothing;
5. give every internal `xray-*` path dependency a matching registry version;
6. package and publish the workspace in dependency order;
7. verify every package with `cargo publish --dry-run` and build documentation
   using the same features and target selected for docs.rs.

## Intended publication order

After every dependency is registry-resolvable, publish synchronized versions
in this order:

1. `xray-utls`, `xray-routing`, `xray-runtime`, and `xray-tun`;
2. `xray-config` and `xray-proxy`;
3. `xray-transport`;
4. `xray-core-rs`;
5. `xray-ffi` and `xray-cli`.

`xray-bench` remains repository-only. Registry versions are immutable, so the
first publication must use a fresh release tag created after all package
metadata and dependency versions are committed.

## Documentation

CI builds the complete workspace API documentation with warnings denied:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Docs.rs automatically builds libraries published to crates.io. Before the
first upload, each public crate must include a README, homepage, repository,
license, keywords, categories, and a canonical `documentation` URL. Add
`[package.metadata.docs.rs]` only where a crate needs non-default features or a
specific target; unnecessary all-feature builds should be avoided because they
can pull platform-only dependencies into the docs.rs sandbox.

## Owner credentials

The final upload requires a crates.io account with a verified email and a
scoped API token. Store the token in a protected GitHub environment rather
than committing it or placing it in a repository URL. Do not publish until the
package archive, dependency order, generated documentation, and release tag
have all been reviewed together.
