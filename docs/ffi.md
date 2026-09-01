# C ABI

The canonical interface is
[`crates/xray-ffi/include/xray_ffi.h`](../crates/xray-ffi/include/xray_ffi.h).
This page explains its lifecycle and ownership rules; the header remains the
source of truth for declarations and enum values.

## ABI version

Call `xray_ffi_version_major()` and `xray_ffi_version_minor()` before creating a
handle. The current ABI version is `1.1`. The checked-in Swift and JNI adapters
reject any major other than `1` and require minor `1` or newer.

An incompatible function signature, enum representation, ownership rule, or
required struct layout requires a major version change. Consumers should
compile against the header shipped with the exact native artifact and should
not infer compatibility from the Rust crate version.

Within one major, the minor version is additive. A newer minor may add symbols,
enum values, capability bits, or append-only fields governed by an explicit
size negotiation rule. It does not remove or reinterpret an older surface.

`xray_ffi_capabilities()` returns a 64-bit mask describing the optional
surfaces present in the loaded library. Use the `XRAY_FFI_CAPABILITY_*` values
from the header and preserve/ignore unknown bits. A capability bit is added in
the same change as its optional API; it does not override major/minor
compatibility checks.

## Recommended lifecycle

1. Verify `xray_ffi_version_major()` and require a sufficient
   `xray_ffi_version_minor()`.
2. Read `xray_ffi_capabilities()` and select only supported optional surfaces.
3. Allocate a handle with `xray_core_new`.
4. Configure optional pre-load settings:
   - geodata search directory;
   - file logging;
   - startup probe;
   - socket-protection callback;
   - direct TUN fd and its ownership;
   - TCP timing collection;
   - TUN runtime profile.
5. Call `xray_core_load_config_json` exactly once successfully.
6. Read `xray_core_config_warnings` and surface non-empty diagnostics.
7. Call `xray_core_start`.
8. Use the packet, statistics, and diagnostic-event APIs.
9. Call `xray_core_stop`.
10. Release the handle with `xray_core_free`.

A handle does not support config replacement. Create a new handle for a new
config or a fresh lifecycle. `xray_core_free(NULL)` is allowed and attempts to
stop a live core before releasing it.

## Handles and errors

- `XrayCoreHandle *` is an owning opaque pointer returned by
  `xray_core_new`. Free it exactly once with `xray_core_free`; all other handle
  arguments are borrowed and become invalid after that call.
- Initialize every `XrayError *` slot to `NULL` before passing its address.
  A call may clear/free the previous library-created error in that slot and
  replace it.
- A non-null `XrayError *` is owned by the caller and must be released exactly
  once with `xray_error_free`.
- `xray_error_message` returns a borrowed, read-only NUL-terminated pointer. It
  remains valid only until the owning error is freed or its slot is reused by a
  later call.
- Input strings and packet buffers are borrowed for the duration of the call.
  Output buffers remain caller-owned.

Always check the returned `XrayStatus`; the error pointer adds detail but is not
a substitute for the status. `XRAY_STATUS_NO_PACKET` is an expected polling
result rather than a failure. `XRAY_STATUS_PANIC` indicates that the FFI panic
boundary caught an unexpected Rust panic.

## Configuration warnings

`xray_core_config_warnings` uses a size-query pattern:

1. pass `buffer = NULL` and `buffer_len = 0`;
2. allocate `written + 1` bytes;
3. call again to receive UTF-8 plus the trailing NUL.

`written` excludes the trailing NUL. The function is valid only after a
successful config load and must not overlap lifecycle/configuration operations.

## Threading

Serialize all configuration and lifecycle calls for a handle:

- `xray_core_load_config_json`;
- `xray_core_start` / `xray_core_stop`;
- every `xray_core_set_*` call;
- `xray_core_free`.

The header explicitly permits `xray_tun_poll_packets` to run concurrently with
`xray_tun_push_packet`, `xray_tun_poll_packet`, and `xray_tun_stats` on the same
handle. None of those data-path calls may overlap lifecycle/configuration/free.
Use separate output buffers, counters, and `XrayError *` slots for concurrent
calls.

The socket-protection callback may execute on runtime worker threads while the
core is running. It must be fast and thread-safe. Its `user_data` pointer is
borrowed by the core and must stay valid for as long as the loaded core can dial
outbound sockets.

## Packet APIs

`xray_tun_push_packet` copies one raw IP packet into the bounded inbound queue.

`xray_tun_poll_packet` is nonblocking:

- `XRAY_STATUS_OK` returns one packet;
- `XRAY_STATUS_NO_PACKET` writes zero to `written`;
- `XRAY_STATUS_BUFFER_TOO_SMALL` writes the required size and retains the
  packet for the next poll.

`xray_tun_poll_packets` waits up to `wait_ms` for the first packet, then drains
ready packets without waiting. Packets are packed back-to-back; use
`packet_lengths` to split them. The effective batch is bounded by both
`max_packets` and `buffer_len / mtu`.

The event poll functions are diagnostic queues and return
`XRAY_STATUS_NO_PACKET` when empty. Their string outputs are NUL-terminated and
may be truncated to the caller's buffer.

Before `xray_tun_stats`, initialize:

```c
XrayTunStats stats = {0};
stats.struct_size = sizeof(stats);
```

Within ABI major 1, `XrayTunStats` is append-only. The library accepts the
original prefix ending with `tun_fd_write_batch_max_packets` (560 bytes on the
supported 64-bit targets) and writes at most
`min(stats.struct_size, sizeof(XrayTunStats))` bytes. The current layout is 584
bytes on those targets; an older caller receives every field in its prefix and
the allocation size in `struct_size` is preserved, so the same object remains
safe to reuse. A future caller's unknown tail remains untouched. Buffers shorter
than the original prefix are rejected with `XRAY_STATUS_BUFFER_TOO_SMALL`.

This prefix rule applies only to append-only growth of `XrayTunStats`. Do not
reuse a header from a different ABI major.

## Direct TUN file descriptors

`xray_core_set_tun_fd` must run before config load. Packet formats are:

- `XRAY_TUN_FD_PACKET_FORMAT_RAW_IP` for Android-style raw IP;
- `XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN` when packets include Darwin's
  four-byte address-family header.

Ownership policies:

- `BORROWED`: the caller keeps ownership and must keep the fd valid until the
  core has stopped/freed its fd runtime;
- `OWNED`: ownership transfers after a successful call; the caller must not
  close the fd.

Replacing a configured fd with a different one closes the old fd when its
policy was `OWNED`. Reconfiguring the same numeric fd transfers its packet
format and close policy without closing it.

The fd bridge starts and stops with the core. Do not simultaneously run a host
packet pump against the same TUN interface.

## Socket protection

Android VPN hosts should register
`xray_core_set_socket_protect_callback` before config load. The core invokes it
before outbound TCP connect or first UDP use. A callback return value of zero
rejects protection and causes the outbound operation to fail; nonzero means
success.

The callback does not transfer ownership of the socket fd. It may use the fd
only for the duration of the callback.

## Status values

The ABI currently defines:

| Status | Meaning |
| --- | --- |
| `OK` | Operation completed |
| `NULL_ARGUMENT` / `INVALID_ARGUMENT` / `INVALID_UTF8` | Caller contract violation |
| `CONFIG_ERROR` | Config or pre-load option was rejected |
| `CORE_NOT_LOADED` | Operation requires a successful config load |
| `RUNTIME_ERROR` / `TUN_ERROR` | Runtime or packet-path failure |
| `NO_PACKET` | Poll queue is empty or wait timed out |
| `BUFFER_TOO_SMALL` | Caller must provide more output storage |
| `PANIC` | Panic caught at the FFI boundary |

Use the numeric constants from the header rather than duplicating them in a
foreign-language adapter. The checked-in Swift and JNI wrappers demonstrate
the intended mapping.
