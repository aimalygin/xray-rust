# Publishing Rust crates and documentation

The intended public entry points are `xray-core-rs` for Rust embedders,
`xray-ffi` for C ABI consumers, and `xray-cli` for `cargo install`. Supporting
workspace libraries must be published first because crates.io packages cannot
depend on unpublished path-only crates.

## Current blocker

The transport layer uses the pinned `shaped-rustls` fork through a workspace
`[patch.crates-io]`. Its ClientHello customization API is required for the
documented TLS and REALITY fingerprint behavior and is not present in upstream
`rustls` 0.23.40.

Cargo removes local path overrides when creating a registry package, and a
crates.io package cannot rely on the Git revision used by this workspace.
Publishing `xray-transport`, `xray-core-rs`, or `xray-ffi` in the current shape
would therefore produce a package that fails its registry build and fails on
docs.rs. `cargo publish --no-verify` is not an acceptable workaround.

The safe path is:

1. publish the fork under an unambiguous package name such as
   `shaped-rustls`, preserving its upstream licenses and fork disclosure;
2. publish a matching Tokio adapter that depends on that package;
3. keep QUIC/HTTP3 on upstream `rustls` types or publish the additional adapted
   QUIC dependency surface;
4. give every internal `xray-*` path dependency a matching registry version;
5. package and publish the workspace in dependency order;
6. verify every package with `cargo publish --dry-run` and build documentation
   using the same features and target selected for docs.rs.

## Intended publication order

After the TLS dependency is registry-resolvable, publish synchronized versions
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
