# C ABI

The canonical interface is
[`crates/xray-ffi/include/xray_ffi.h`](../crates/xray-ffi/include/xray_ffi.h).
This page explains its lifecycle and ownership rules; the header remains the
source of truth for declarations and enum values.

## ABI version

Call `xray_ffi_version_major()` and `xray_ffi_version_minor()` before creating a
handle. The current ABI version is `1.3`. The checked-in Swift and JNI adapters
reject any major other than `1` and require minor `1` or newer. Their selector
and health methods require the corresponding ABI 1.2 capability bits; their
connection-management methods require the ABI 1.3 capability bit before
calling optional symbols.

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
8. Use the packet, statistics, diagnostic-event, selector-override,
   outbound-snapshot, and connection-management APIs.
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

## Outbound selection and health

ABI 1.2 adds two independent capabilities:

| Capability | Optional surface |
| --- | --- |
| `XRAY_FFI_CAPABILITY_OUTBOUND_SELECTION` | Atomic selector override/clear and selection snapshots |
| `XRAY_FFI_CAPABILITY_OUTBOUND_HEALTH` | Read-only outbound health snapshots |

`xray_core_set_outbound_selector_override` validates that both tags name a
loaded selector group and one of its configured members, then atomically
redirects new flows. Existing flows and compiled/shared outbound handlers are
unchanged. `xray_core_clear_outbound_selector_override` restores the group's
configured strategy. Both calls are valid before or after `xray_core_start`.

`xray_core_outbound_selection_snapshot_json` and
`xray_core_outbound_health_snapshot_json` use the same two-pass UTF-8 buffer
contract as configuration warnings. Their documents are versioned separately
from the C ABI so fields can be evolved deliberately. Schema version 1 is:

```json
{
  "schemaVersion": 1,
  "revision": 2,
  "groups": [
    {
      "tag": "automatic",
      "candidates": ["proxy-a", "proxy-b"],
      "overrideTag": "proxy-b"
    }
  ]
}
```

```json
{
  "schemaVersion": 1,
  "revision": 4,
  "outbounds": [
    {
      "tag": "proxy-a",
      "state": "unhealthy",
      "delayMs": null,
      "lastTryUnixMs": 1788220800000,
      "lastSeenUnixMs": null,
      "consecutiveFailures": 2,
      "lastFailureKind": "httpStatus",
      "httpStatus": 503
    }
  ]
}
```

Health states are `unknown`, `healthy`, and `unhealthy`. Failure kinds are
`timeout`, `transport`, `tls`, `io`, `malformedHttpResponse`, and
`httpStatus`; nullable measurement/failure fields are emitted explicitly as
JSON `null`. Snapshot contents are redacted: they expose configured outbound
tags and typed probe results, not target URLs, endpoint addresses, free-form
errors, or credentials. Consumers must reject an unsupported `schemaVersion`
rather than guessing its meaning. The checked-in Swift and Kotlin models do
this decoding and expose equivalent public operations.

## Connection management

ABI 1.3 adds `XRAY_FFI_CAPABILITY_CONNECTION_MANAGEMENT`. When present, hosts
may call `xray_core_connection_snapshot_json`,
`xray_core_outbound_accounting_snapshot_json`, and
`xray_core_close_connection`. Both snapshots use the same two-pass UTF-8
contract as the outbound snapshots and currently use schema version 1.

The connection document is an ID-sorted point-in-time inventory:

```json
{
  "schemaVersion": 1,
  "revision": 9,
  "connections": [
    {
      "id": 17,
      "state": "active",
      "inboundTag": "tun-in",
      "outboundTag": "direct",
      "network": "udp",
      "addressType": "ip",
      "address": "127.0.0.1",
      "port": 53,
      "startedUnixMs": 1788220800000
    }
  ]
}
```

States are `opening` and `active`; networks are `tcp` and `udp`; address types
are `ip` and `domain`. Tags are nullable. Targets are intentionally visible to
the owning host because per-connection display and close are the purpose of the
surface; credentials and free-form transport errors are not included.

The accounting document keeps cumulative totals after flows leave the active
inventory:

```json
{
  "schemaVersion": 1,
  "revision": 10,
  "outbounds": [
    {
      "outboundTag": "direct",
      "openedConnections": 3,
      "completedConnections": 2,
      "hostClosedConnections": 1,
      "uplinkBytes": 64,
      "downlinkBytes": 96
    }
  ]
}
```

`xray_core_close_connection` accepts a nonzero ID from a recent connection
snapshot. It marks the host-close request before signalling cancellation, so a
concurrent flow exit is still attributed correctly. Zero and IDs that are no
longer registered return `XRAY_STATUS_INVALID_ARGUMENT`. A successful call is
idempotent only while that entry remains registered; callers should refresh the
snapshot rather than retrying a disappeared ID. The current registry covers
routed SOCKS TCP/UDP, HTTP TCP, and TUN TCP/UDP sessions. Each SOCKS UDP
`(client, target)` flow owns a separate ID; closing the TCP `UDP ASSOCIATE`
control connection still removes all of its child flows.

## Threading

Serialize all configuration and lifecycle calls for a handle:

- `xray_core_load_config_json`;
- `xray_core_start` / `xray_core_stop`;
- every pre-load `xray_core_set_*` call;
- `xray_core_free`.

The selector override/clear and connection-close calls are the exception: they
use the shared runtime gate and may overlap packet/statistics calls, snapshot
reads, and each other. All four snapshot calls have the same shared-call
behavior. None of these shared calls may overlap load/start/stop/free.

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
may be truncated to the caller's buffer. The checked-in Swift and Kotlin
adapters both expose typed bounded-drain methods for TCP slow-flow, flow-summary,
remote-write-slow, and open-error events plus UDP slow-flow, response-gap, and
QUIC-blocked events. These methods require the existing
`XRAY_FFI_CAPABILITY_TUN_DIAGNOSTIC_EVENTS` bit; the Kotlin/JNI projection does
not change the C ABI version.

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
