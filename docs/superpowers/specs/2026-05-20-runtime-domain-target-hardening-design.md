# Runtime Domain Target Hardening Design

## Goal

Make the outbound DNS slice harder to regress before moving into TLS, REALITY, and Vision runtime work.

The runtime already supports resolver-injected VLESS outbound server domains. This follow-up proves and documents the adjacent invariant: DNS is used only for the configured outbound server. A domain requested by the SOCKS client remains a domain in the VLESS request header and is not resolved by the local runtime resolver.

## Non-Goals

- No full Xray DNS app behavior, routing DNS policy, fake DNS, DNS cache, or `domainStrategy` support.
- No TLS, REALITY, or Vision live transport implementation.
- No HTTP CONNECT runtime listener changes.
- No broad runtime refactor.
- No public API cleanup beyond comments or documentation directly related to this invariant.

## Recommended Approach

Use a test-first hardening slice.

Add a runtime data-path E2E test where:

- the VLESS outbound server is configured as `TargetAddr::Domain("vless.test")`;
- an injected fake resolver resolves only `vless.test`;
- the SOCKS client requests a domain target such as `example.com:443`;
- the fake VLESS server reads the VLESS request header and asserts that the target is still `TargetAddr::Domain("example.com")`;
- the fake resolver would fail the test if the runtime tried to resolve the SOCKS target locally.

This keeps the architecture unchanged unless the test reveals a bug. The runtime should continue to pass the parsed SOCKS target unchanged to the VLESS request encoder.

## Components

### Runtime Test Helpers

Extend `crates/xray-core-rs/tests/runtime_data_path_tests.rs` with domain-target helpers rather than changing production code first.

Add a SOCKS helper that can send a SOCKS5 domain CONNECT request:

```text
client greeting -> no-auth method
CONNECT domain example.com port 443
expect SOCKS success reply
```

Add a VLESS header reader helper that returns an `xray_routing::Target`, not only an IPv4 `SocketAddr`. The current helper can remain for the existing echo E2E, but the new helper should understand at least VLESS address types already emitted by the encoder:

- IPv4
- IPv6 if cheap to support while parsing
- domain

The new domain-target E2E does not need a live echo target. It can stop after the fake VLESS server validates the VLESS header and the SOCKS client receives the success reply. That directly tests the target encoding invariant without adding extra moving pieces.

### Resolver Guard

Keep `StaticDnsResolver` deterministic and narrow. For this test, it should return an address only when called with `vless.test` and the configured outbound server port. Any other domain, including `example.com`, returns `TransportError::NoResolvedAddress`.

The test should fail if runtime code accidentally attempts to resolve the SOCKS target domain through the injected resolver.

### Core API Documentation

Add a short rustdoc comment to `Core::with_dns_resolver` explaining that the resolver is currently used for outbound server resolution in the runtime path. It is not a full Xray DNS policy hook yet.

Document the `DnsResolver` port contract in `xray-transport`: the resolver receives the configured port, and returned `SocketAddr` is the concrete address the connector will dial. This intentionally allows deterministic tests and future platform resolvers to return a concrete endpoint, while making the behavior explicit.

### Stale Error Variant

`CoreError::UnsupportedOutboundServerAddress` is now stale because the current model has only IP and domain server addresses, and both are supported for VLESS TCP selection.

For this slice, do not remove it unless it is clearly mechanical and risk-free. Removing a public error variant is API cleanup, and it can be handled in a later small cleanup pass. If touched, prefer a comment that explains it is reserved for future unsupported address kinds or pending API cleanup.

## Testing

Use TDD:

1. Add the new domain-target runtime E2E and run it to confirm the expected failure.
2. Implement the smallest helper/production change needed to pass.
3. Run focused tests:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_preserves_domain_target_through_domain_vless_server
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_domain_vless_server
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
```

The runtime tests require loopback bind/connect permission in this sandbox.

Then run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
```

The Go oracle is not required for this narrow Rust runtime invariant unless production protocol code changes beyond test helpers and comments.

## Success Criteria

- A SOCKS domain target remains a domain target in the VLESS request header when the outbound VLESS server itself is resolved through the injected resolver.
- The fake resolver is not called for the SOCKS target domain.
- Existing IP-target and domain-outbound runtime E2E tests still pass.
- Docs/comments clarify resolver scope without claiming full Xray DNS behavior.
