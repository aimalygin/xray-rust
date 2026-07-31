# Contributing

Thanks for helping improve `xray-rust`. The project is experimental and keeps
security, protocol compatibility, and bounded resource use ahead of feature
breadth.

## Development setup

- Use the Rust toolchain pinned in `rust-toolchain.toml`.
- Keep `Cargo.lock` updated and committed.
- Run commands from the repository root.
- Never commit production endpoints, VPN profiles, credentials, private keys,
  personal signing settings, or unredacted logs.

The default Rust validation is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- \
  -D warnings -W clippy::perf -W clippy::suspicious
cargo test --workspace --all-targets --locked
bash scripts/tests/check-mobile-toolchains.test.sh
bash scripts/tests/check-public-fixtures.test.sh
```

Platform changes should also run the relevant checks documented in
`docs/mobile-testing.md`.

Before publishing or rewriting a branch, scan all reachable history as
documented in `docs/verification.md`. The history scan fails if a retired
live-profile value is carried by any commit other than the two pre-release
commits grandfathered in `scripts/tests/check-json-fixture-safety.py`; that
disclosure is recorded in `SECURITY.md`. Do not extend the allowlist to cover
new commits — remove the value instead.

## Pull requests

- Keep each change focused and explain its user-visible behavior.
- Add a regression test for bug and security fixes.
- Add or update a benchmark for performance claims.
- Document compatibility changes and rejected configuration fields.
- Describe any FFI ABI, lifecycle, ownership, or threading impact.
- Use synthetic values from RFC documentation ranges in examples and tests.
- Update user-facing documentation in the same pull request.

Performance pull requests should include the command, workload, build profile,
hardware context, and before/after measurements. Do not infer improvements from
debug builds.

Security reports belong in the private process described in `SECURITY.md`, not
in a public pull request.
