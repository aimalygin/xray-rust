# Verification Matrix

This project is the first Rust mobile/client core slice aimed at protocol compatibility with Xray-core. Verification is split between local Rust checks, lightweight compatibility smoke coverage, and the read-only Go Xray-core oracle checkout.

## Local Rust Checks

Run these from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
```

The clippy command uses `--locked` and denies warnings so local verification matches the strict form expected before committing documentation or code changes.

Run the first live Rust runtime data-path test:

```sh
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
```

Run the resolver-injected domain outbound server data-path test:

```sh
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_domain_vless_server
```

These prove the current local/test paths: SOCKS5 client traffic enters `xray-core-rs`, is encoded as VLESS over raw TCP, reaches a fake VLESS server configured either as an IP outbound server or through a resolver-injected domain outbound server, and returns bytes from an echo target. They do not prove full Xray DNS behavior, TLS, REALITY, or Vision live interoperability yet.

## Go Xray-core Oracle

`Xray-core/` is a read-only checkout of the Go reference implementation. It is ignored by the root Git repository and used as a compatibility oracle, not edited as part of this Rust workspace.

Run the current VLESS XTLS Vision REALITY oracle scenario from the repository root:

```sh
cd Xray-core
go test ./testing/scenarios -run TestVlessXtlsVisionReality -count=1
```

This validates the reference scenario itself. Rust client interoperability against that scenario is a future phase once the REALITY connector is complete and wired into an executable harness.

## Compatibility Harness Status

Current Rust compatibility coverage:

```sh
cargo test -p xray-core-rs compat_smoke
```

When the ignored `Xray-core/` checkout is present, this smoke test verifies that the oracle checkout contains expected reference files. In a clean checkout without `Xray-core/`, the smoke test prints a skip message and passes so the default workspace test suite does not depend on ignored local files.

To require the oracle checkout during local compatibility work:

```sh
XRAY_RUST_REQUIRE_XRAY_CORE=1 cargo test -p xray-core-rs compat_smoke
```

An ignored Rust shell exists at `tests/compat/vless_reality_vision.rs` for the future REALITY connector phase. It currently lives at workspace-root `tests/compat` and is not wired as a Cargo test target, so it is not CI coverage yet. In particular, this command is not currently valid:

```sh
cargo test --test vless_reality_vision -- --ignored
```

Cargo reports no test target with that name until a future task wires the compatibility harness into the workspace.
