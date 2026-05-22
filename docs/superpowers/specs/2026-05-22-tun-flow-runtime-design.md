# TUN Flow Runtime Design

## Problem

The current TUN support is only a bounded packet queue exposed through FFI. Mobile adapters can push and poll packets, but the core does not yet translate IP packets into routed outbound sessions. A config with only a `tun` inbound also cannot start because `Core::start` skips TUN inbounds.

## Goal

Build the first mobile-runnable TUN runtime:

- A `tun` inbound starts the core even when there are no SOCKS/HTTP listeners.
- Raw IPv4 TCP packets pushed through `xray_tun_push_packet` are accepted by an in-process TCP/IP stack.
- Accepted TCP sessions are routed with the same routing rules used by SOCKS/HTTP.
- Routed sessions reuse the existing TCP outbounds, including Freedom and VLESS over TCP/TLS/REALITY/Vision.
- Response packets are emitted through `xray_tun_poll_packet` for the platform VPN adapter to write back to the OS packet tunnel.

## Non-Goals For This Milestone

- Do not create native OS TUN interfaces inside the Rust core. iOS/tvOS `NEPacketTunnelProvider` and Android `VpnService` own the OS adapter and feed packets through the existing FFI boundary.
- Do not implement VLESS Mux/XUDP in this milestone. UDP through Vision in xray-core depends on that layer.
- Do not expose a new C ABI unless packet driving cannot be done with the current push/poll functions.

## Architecture

Use `smoltcp` as the userspace IP/TCP stack. The core owns a stack task per TUN inbound. The task consumes inbound packets from `TunEndpoint`, injects them into a `smoltcp` `Medium::Ip` device, dynamically creates TCP listening sockets for destination endpoints observed in SYN packets, and bridges accepted sockets to the selected outbound stream.

The stack task is intentionally transport-neutral at the packet boundary:

```text
mobile VPN adapter
  -> xray_tun_push_packet(raw IP)
  -> TunEndpoint inbound queue
  -> smoltcp IP/TCP stack
  -> routing by inboundTag + target IP/CIDR
  -> Freedom or VLESS TCP outbound
  -> remote target/proxy
  -> smoltcp response packets
  -> TunEndpoint outbound queue
  -> xray_tun_poll_packet(raw IP)
```

## Runtime Boundaries

- `xray-tun` remains a queue and statistics boundary.
- `xray-core-rs::tun` owns packet parsing, `smoltcp` device integration, TCP socket management, and bridge tasks.
- `xray-core-rs::outbound` remains the only module that selects and opens configured outbounds.
- FFI remains a thin adapter around `Core::tun()`.

## Resource Model

- Use bounded queues for packets and per-flow bridge channels.
- Allocate socket buffers per active flow, not per inbound packet.
- Avoid unbounded task fan-out by creating one outbound bridge task per accepted TCP flow.
- Drop malformed or unsupported packets without panicking.
- Wake the stack on inbound packets, remote data, and timer deadlines.

## Completion Gates

- `Core::start` succeeds with a TUN-only config.
- A test smoltcp client can complete a TCP handshake through `Core::tun()`.
- A test smoltcp client can send bytes through TUN to a local Freedom echo server and receive the echo back as raw IP packets.
- Existing SOCKS/HTTP runtime tests still pass.
- FFI/mobile artifact tests still pass.

## Follow-Up Parity Work

After the TCP TUN path is verified, the remaining TUN parity items are:

- UDP session handling and direct Freedom UDP egress.
- VLESS UDP length-prefixed framing for non-Vision flows.
- VLESS Vision XUDP/Mux support for UDP over Vision.
- ICMP echo response support.
- Configurable TUN MTU, stack addresses, idle timeouts, and DNS behavior.
