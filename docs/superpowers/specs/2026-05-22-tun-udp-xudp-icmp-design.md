# TUN UDP/XUDP/ICMP Design

## Problem

The TUN runtime now handles TCP packets from mobile packet tunnels, but a practical mobile VPN path also needs UDP and ICMP. Xray-core uses different UDP transports depending on the outbound:

- Freedom UDP sends datagrams directly.
- VLESS UDP without Vision uses VLESS command `Udp` and two-byte length-prefixed datagrams over the protected outbound stream.
- VLESS Vision UDP is not sent as plain VLESS UDP. Xray-core rewrites it to VLESS command `Mux` and sends XUDP frames in the stream body.

## Goal

Finish the mobile-runnable TUN packet dispatcher for UDP and ICMP:

- Reply to ICMP echo requests locally for IPv4 and IPv6.
- Parse UDP packets from raw IPv4/IPv6 TUN packets.
- Route UDP sessions with the existing routing rules by `inboundTag` and destination IP/CIDR.
- Support UDP over Freedom with direct `tokio::net::UdpSocket` flows.
- Support VLESS UDP length-prefixed packet streams.
- Support VLESS Vision UDP as Xray-compatible XUDP frames over VLESS `Mux`.
- Emit UDP replies back as raw IP packets through the existing `TunEndpoint` outbound queue.

## Architecture

Keep `xray-tun` as the packet queue and keep the C ABI unchanged. Extend `xray-core-rs::tun` so it recognizes non-TCP packets before feeding TCP packets into smoltcp:

```text
mobile raw IP packet
  -> TUN queue
  -> ICMP echo local reply, or
  -> UDP parser + routing + outbound UDP flow, or
  -> existing smoltcp TCP path
```

UDP flows are keyed by client endpoint and destination endpoint. Each flow owns a bounded channel to an async bridge task. Freedom flows own a UDP socket. VLESS flows own one outbound stream and use either VLESS UDP packet framing or XUDP framing depending on the selected outbound user flow.

Protocol-specific VLESS UDP/XUDP encoding lives in `xray-proxy::vless`, not in the TUN runtime, so it can be reused by future SOCKS UDP or local interop tests.

## Resource Model

- Bounded channels for all UDP flow inputs and stack events.
- One async task per active UDP flow, matching the current TCP flow model.
- Datagram payloads are copied only at the packet boundary and channel boundary.
- Malformed packets, unsupported fragments, and oversized protocol frames are dropped without panics.

## Completion Gates

- ICMPv4 and ICMPv6 echo request packets receive correct echo replies.
- TUN UDP reaches a local UDP echo server through Freedom.
- TUN UDP reaches a fake Xray-compatible VLESS UDP server using length-prefixed datagrams.
- TUN UDP over Vision writes XUDP `New` frames over VLESS `Mux` and reads XUDP `Keep` responses.
- Existing TCP TUN tests still pass.
- Mobile FFI artifact tests and Apple/Android artifact builds still pass.

## Non-Goals

- No native OS adapter code in this repository.
- No geosite/geoip data loading changes.
- No UDP transparent DNS app behavior beyond forwarding the datagrams routed by config.
- No full Xray Mux session multiplexing beyond the XUDP frame shape required for Vision UDP.
