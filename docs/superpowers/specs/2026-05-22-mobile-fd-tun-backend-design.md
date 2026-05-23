# Mobile FD TUN Backend Design

## Context

The current mobile path uses a platform packet pump: Apple reads and writes `NEPacketTunnelFlow`, Android reads and writes `VpnService`'s `ParcelFileDescriptor`, and both cross the FFI boundary once per packet through `xray_tun_push_packet` and `xray_tun_poll_packet`.

That path is portable and safe as a default, but it adds extra Swift/Kotlin/JNI work and copies around every packet. Xray-core also supports a fd-backed path where mobile code provides an OS tunnel fd and the core reads and writes it directly.

## Goal

Add an optional fd-backed TUN backend without removing the existing packet pump backend.

## Architecture

The Rust core keeps a single internal `TunEndpoint`. Packet API and fd-backed API are only different host-side adapters feeding that endpoint:

- Packet API: host code pushes and polls raw IP packets through the existing C ABI.
- FD backend: host code gives Rust a file descriptor, and Rust runs read and write tasks that bridge the fd to `TunEndpoint`.

The routing, TCP/UDP/ICMP, VLESS UDP, XUDP, Vision, and outbound socket protection paths remain shared.

## FFI

Add `xray_core_set_tun_fd` before config load:

- `fd`: platform tunnel file descriptor.
- `packet_format`: `raw_ip` for Android and generic TUN fds, `darwin_utun` for Darwin utun fds with a 4-byte address-family prefix.
- `close_policy`: `borrowed` when the platform owner closes the fd, `owned` when Rust should close it.

The function must reject null handles and calls after config load. The fd backend starts when `xray_core_start` starts the loaded core and stops before `xray_core_stop` shuts the core down.

## Mobile Adapters

Android:

- Keep the existing packet-pump mode.
- Add an fd-backed mode that passes `ParcelFileDescriptor.fd` to Rust and skips Kotlin packet pump threads.
- Keep `VpnService.protect(fd)` socket protection.

Apple:

- Keep `NEPacketTunnelFlow` packet pump as the default path.
- Add optional `tunFileDescriptor` init parameters to `XrayCore`.
- Add a small Darwin helper that can discover an existing utun fd for advanced integrations.

## Error Handling

FD setup errors return `XRAY_STATUS_RUNTIME_ERROR`. Background fd task I/O errors stop that task, while queue-full drops are counted by the existing `TunEndpoint` and do not crash the core.

## Testing

- FFI tests cover registering the fd before config load and rejecting it after config load.
- Unix FFI runtime test uses `socketpair` as a packet-like fd and verifies an ICMP echo request written to the fd returns an echo reply from the Rust TUN runtime.
- Header and mobile artifact tests verify the new C symbols and adapter APIs are exported.
- Existing packet API tests must continue to pass.
