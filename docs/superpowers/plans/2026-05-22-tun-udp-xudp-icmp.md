# TUN UDP/XUDP/ICMP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the mobile TUN runtime with ICMP echo replies, UDP forwarding, VLESS UDP framing, and Vision XUDP framing.

**Architecture:** Extend `xray-core-rs::tun` with packet-level ICMP and UDP handling before the existing smoltcp TCP path. Add reusable VLESS UDP/XUDP frame helpers in `xray-proxy`, and add UDP outbound selection/opening helpers in `xray-core-rs::outbound`.

**Tech Stack:** Rust, Tokio, smoltcp wire packet builders, existing TUN FFI queue, existing VLESS/TLS/REALITY/Vision stream wrappers.

---

## Files

- Modify: `crates/xray-proxy/src/vless/mod.rs`
  - Export UDP/XUDP helpers.
- Create: `crates/xray-proxy/src/vless/udp.rs`
  - Encode/decode VLESS UDP length frames and XUDP frames.
- Modify: `crates/xray-proxy/tests/vless_wire_tests.rs`
  - Cover VLESS UDP and XUDP wire compatibility.
- Modify: `crates/xray-core-rs/src/outbound.rs`
  - Add UDP outbound selector and VLESS UDP stream opening helper.
- Modify: `crates/xray-core-rs/src/tun.rs`
  - Parse ICMP/UDP TUN packets, spawn UDP bridge tasks, and emit raw UDP replies.
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`
  - Add ICMP, UDP Freedom, VLESS UDP, Vision XUDP, and routing tests.
- Modify: `docs/mobile-testing.md`
  - Update readiness notes after UDP/XUDP/ICMP pass.

## Task 1: VLESS UDP/XUDP Wire Helpers

- [ ] Add failing tests for length-prefixed VLESS UDP frames and XUDP `New`/`Keep` frames.
- [ ] Implement `encode_udp_packet`, `read_udp_packet`, `encode_xudp_new_packet`, `encode_xudp_keep_packet`, and `read_xudp_packet`.
- [ ] Run `cargo test -p xray-proxy --test vless_wire_tests`.
- [ ] Commit with `feat(proxy): add vless udp xudp frames`.

## Task 2: ICMP Echo

- [ ] Add failing TUN ICMPv4 and ICMPv6 echo tests in `runtime_data_path_tests.rs`.
- [ ] Implement local echo reply builders in `xray-core-rs::tun`.
- [ ] Run `cargo test -p xray-core-rs --test runtime_data_path_tests tun_icmp`.
- [ ] Commit with `feat(core): reply to tun icmp echo`.

## Task 3: UDP Freedom

- [ ] Add a failing TUN UDP Freedom echo test.
- [ ] Implement UDP packet parser, raw UDP response packet builder, UDP flow map, and Freedom UDP bridge task.
- [ ] Run `cargo test -p xray-core-rs --test runtime_data_path_tests tun_udp_client_reaches_echo_target_through_freedom_outbound`.
- [ ] Commit with `feat(core): bridge tun udp freedom flows`.

## Task 4: VLESS UDP

- [ ] Add a fake VLESS UDP server test that expects command `Udp` and length-prefixed packets.
- [ ] Add UDP outbound selection and VLESS UDP stream opening helpers.
- [ ] Implement VLESS UDP bridge task using the proxy UDP frame helpers.
- [ ] Run `cargo test -p xray-core-rs --test runtime_data_path_tests tun_udp_client_reaches_echo_target_through_vless_udp_outbound`.
- [ ] Commit with `feat(core): bridge tun udp vless flows`.

## Task 5: Vision XUDP

- [ ] Add a fake protected Vision/XUDP server test that expects VLESS command `Mux` and XUDP `New` frames.
- [ ] Reuse existing Vision stream wrapper for the UDP body when the outbound flow is `xtls-rprx-vision`.
- [ ] Decode XUDP `Keep` responses and emit raw UDP packets back to the client.
- [ ] Run `cargo test -p xray-core-rs --test runtime_data_path_tests tun_udp_client_uses_xudp_for_vision_flow`.
- [ ] Commit with `feat(core): support tun vision xudp flows`.

## Task 6: Verification And Mobile Artifacts

- [ ] Update `docs/mobile-testing.md`.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo test -p xray-proxy --all-targets`.
- [ ] Run `cargo test -p xray-core-rs --all-targets`.
- [ ] Run `cargo test -p xray-ffi --test mobile_artifacts_tests -- --nocapture`.
- [ ] Run `cargo clippy -p xray-proxy -p xray-core-rs -p xray-ffi --all-targets --locked -- -D warnings`.
- [ ] Run `scripts/check-mobile-toolchains.sh`.
- [ ] Run `scripts/build-apple-xcframework.sh`.
- [ ] Run `scripts/build-android-libs.sh`.
- [ ] Commit with `test(mobile): verify tun udp xudp icmp readiness`.

## Self-Review

- The plan covers ICMP, Freedom UDP, VLESS UDP, Vision XUDP, tests, docs, and mobile builds.
- The existing C ABI remains unchanged.
- The XUDP scope is intentionally the Xray-compatible UDP frame path, not generalized Mux multiplexing.
