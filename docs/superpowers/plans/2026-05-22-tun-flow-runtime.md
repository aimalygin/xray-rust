# TUN Flow Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing mobile TUN packet boundary into a runnable TCP packet-to-session runtime.

**Architecture:** Add a focused `xray-core-rs::tun` module backed by `smoltcp`. The module consumes `TunEndpoint` packets, maintains per-flow TCP sockets, routes accepted sessions through the existing outbound selector, and writes response packets back to `TunEndpoint`.

**Tech Stack:** Rust, Tokio, `smoltcp` `Medium::Ip`, existing `xray-tun`, existing TCP outbound runtime, C ABI packet push/poll.

---

## Files

- Modify: `Cargo.toml`
  - Add workspace `smoltcp` dependency with minimal IP/TCP features.
- Modify: `Cargo.lock`
  - Lock the new dependency.
- Modify: `crates/xray-core-rs/Cargo.toml`
  - Add `smoltcp` and `bytes`.
- Modify: `crates/xray-core-rs/src/lib.rs`
  - Share `TunEndpoint` with runtime tasks and start TUN inbounds.
- Create: `crates/xray-core-rs/src/tun.rs`
  - Implement packet device, TCP flow detection, stack loop, and outbound bridge tasks.
- Modify: `crates/xray-core-rs/tests/core_lifecycle_tests.rs`
  - Add TUN-only lifecycle coverage.
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`
  - Add smoltcp client-driven TUN TCP echo test.
- Modify: `tests/fixtures/configs/mobile_vless_reality_vision_split_routing.json`
  - Add a `tun` inbound so the practical mobile fixture exercises the new path.
- Modify: `docs/mobile-testing.md`
  - Document the new TCP TUN runtime and remaining UDP/XUDP limits.

## Task 1: TUN-Only Lifecycle

- [ ] Add a failing `core_starts_with_only_tun_inbound` test in `core_lifecycle_tests.rs`.
- [ ] Run `cargo test -p xray-core-rs --test core_lifecycle_tests core_starts_with_only_tun_inbound`.
- [ ] Change `Core::start` so TUN inbounds count as supported runtime work.
- [ ] Run the lifecycle test again and keep the whole lifecycle suite green.
- [ ] Commit with `feat(core): start tun inbound runtime`.

## Task 2: Stack Dependency And Device Skeleton

- [ ] Add `smoltcp` with `std`, `medium-ip`, `proto-ipv4`, `proto-ipv6`, and `socket-tcp`.
- [ ] Create `tun.rs` with a bounded `PacketDevice` implementing `smoltcp::phy::Device`.
- [ ] Add unit tests for device receive/transmit packet movement.
- [ ] Run `cargo test -p xray-core-rs tun::`.
- [ ] Commit with `feat(core): add tun packet device`.

## Task 3: TCP Stack Accepts TUN Packets

- [ ] Add a failing data-path test that drives a smoltcp client SYN into `Core::tun()` and expects a SYN/ACK packet.
- [ ] Implement dynamic TCP listen socket creation from IPv4/IPv6 SYN packets.
- [ ] Pump outbound stack packets into `TunEndpoint::push_outbound`.
- [ ] Run the SYN/ACK test until it passes.
- [ ] Commit with `feat(core): accept tcp sessions from tun packets`.

## Task 4: TCP TUN To Outbound Bridge

- [ ] Extend the data-path test to send a payload to a local echo server through TUN and assert the echoed bytes return to the smoltcp client.
- [ ] Implement per-flow outbound bridge tasks using `select_tcp_outbound_for_session` and `open_tcp_stream_with_resolver_and_dialer`.
- [ ] Add bounded stack-to-remote and remote-to-stack channels.
- [ ] Close flow sockets and bridge tasks when either side closes.
- [ ] Run `cargo test -p xray-core-rs --test runtime_data_path_tests tun_tcp_freedom_echoes_payload`.
- [ ] Commit with `feat(core): bridge tun tcp flows to outbounds`.

## Task 5: Mobile Readiness Verification

- [ ] Add a `tun-in` inbound to the mobile split-routing fixture.
- [ ] Update `docs/mobile-testing.md` to say TCP TUN is runnable and list UDP/XUDP as the next TUN parity step.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo test -p xray-core-rs --all-targets`.
- [ ] Run `cargo test -p xray-ffi --test mobile_artifacts_tests -- --nocapture`.
- [ ] Run `cargo clippy -p xray-core-rs -p xray-ffi --all-targets --locked -- -D warnings`.
- [ ] Commit with `test(mobile): verify tun runtime readiness`.

## Self-Review

- The plan covers the TCP mobile TUN runtime from lifecycle through packet echo.
- The existing FFI push/poll ABI remains unchanged.
- The plan intentionally keeps UDP/XUDP as follow-up parity work because Vision UDP requires Mux/XUDP support.
