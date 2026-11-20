# Publishing Rust crates and documentation

The intended public entry points are `xray-core-rs` for Rust embedders,
`xray-ffi` for C ABI consumers, and `xray-cli` for `cargo install`. Supporting
workspace libraries must be published first because crates.io packages cannot
depend on unpublished path-only crates.

## Current blocker

The transport layer uses the `shaped-rustls` fork, vendored and put in place
of `rustls` through a workspace `[patch.crates-io]`. Its ClientHello
customization API is required for the documented TLS and REALITY fingerprint
behavior and is not present in upstream `rustls`.

The fork is not the only override. `[patch.crates-io]` also replaces quinn,
quinn-proto, h3, h3-quinn, h2, smoltcp and blake3 with vendored copies that
carry local changes, and `xray-wireguard` takes a patched gotatun by path. The
workspace calls APIs that exist only in those copies.

Cargo removes local path overrides when creating a registry package, and a
crates.io package cannot rely on the vendored copies used by this workspace.
Publishing `xray-transport`, `xray-core-rs`, or `xray-ffi` in the current shape
would therefore produce a package that fails its registry build and fails on
docs.rs. `cargo publish --no-verify` is not an acceptable workaround.

The safe path is:

1. publish the fork under an unambiguous package name such as
   `shaped-rustls`, preserving its upstream licenses and fork disclosure.
   The fork's own manifest carries that name since its revision `474a31b7`
   (rustls 0.23.46) and passes `cargo publish --dry-run`; it is not on
   crates.io yet, and this workspace still builds it under the name `rustls`
   (`vendor/shaped-rustls/XRAY-PATCH.md` says why);
2. publish a matching Tokio adapter that depends on that package;
3. keep QUIC/HTTP3 on upstream `rustls` types or publish the additional adapted
   QUIC dependency surface;
4. do the same for the other overridden crates: send upstream what upstream
   can take, and publish the rest under names of their own;
5. give every internal `xray-*` path dependency a matching registry version;
6. package and publish the workspace in dependency order;
7. verify every package with `cargo publish --dry-run` and build documentation
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
