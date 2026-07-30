# Profile-Aware Inbound Admission Design

## Goal

Make the local SOCKS/HTTP inbound connection cap follow the runtime profile
instead of a single hardcoded constant, and replace the silent connection drop
at the cap with a protocol-level refusal so clients can distinguish "server
full" from "server crashed".

## Problem

Two independent limits exist today and they disagree:

- TUN path: `TunRuntimeProfile` tunes `max_active_flows` from 256 (Mobile,
  LowMemory) through 2048 (Desktop) to 4096 (Throughput), plus queue depths
  and per-flow buffers.
- Local SOCKS/HTTP inbounds: `ConnectionAdmission::new(DEFAULT_MAX_INBOUND_CONNECTIONS)`
  with `DEFAULT_MAX_INBOUND_CONNECTIONS = 1024`, identical for every profile
  (`crates/xray-core-rs/src/socks.rs`, `http.rs`).

So `--tun-profile throughput` widens the packet path to 4096 flows while the
proxy inbound still refuses the 1025th client. Measured 2026-07-30 at 1500
concurrent idle SOCKS flows: xray-rust resets connections past 1024
(`Connection reset by peer` at the SOCKS method exchange) while Xray-core and
sing-box, which have no default inbound cap, serve all 1500.

Second defect: past the cap the accepted stream is dropped immediately
(`admission.try_acquire()` returns `None` → `continue`), so the peer sees a
TCP reset with no SOCKS reply. A client cannot tell an overloaded proxy from a
dead one.

## Scope

- Per-profile inbound admission limits, applied to the SOCKS and HTTP
  inbounds.
- A SOCKS5 refusal reply (and HTTP equivalent) when the cap is reached,
  instead of dropping the connection.
- Profile plumbing so inbound listeners can see the profile at all.
- Rename the profile type to drop its TUN-only name.

Out of scope: config-file/JSON control of the cap (the runtime profile stays
the single knob), per-inbound overrides, dynamic resizing at runtime, changes
to any TUN flow budget, changes to the fd-limit story.

## Per-Profile Limits

| Profile | Inbound cap | Rationale |
| --- | --- | --- |
| `LowMemory` | 256 | Matches its 256 TUN flow budget; smallest hosts. |
| `Mobile` | 1024 | Current behavior preserved — this is today's default value. |
| `Default` | 1024 | Same as Mobile (Default aliases mobile-ish behavior today). |
| `MobilePlus` | 1536 | Sits between Mobile and Desktop, mirroring its 384-flow TUN budget being between Mobile's 256 and Desktop's 2048. |
| `Desktop` | 8192 | Desktop hosts routinely raise fd limits; 8192 covers browser-scale fan-out. |
| `Throughput` | 65536 | Effectively unlimited for any real workload while keeping a bound. |

`Throughput` is deliberately a very large number rather than "no check". The
admission permit is what produces a clean, explainable refusal; with the check
removed entirely the failure mode at fd exhaustion becomes `accept()` errors
in a hot loop (the current listener does `Err(_) => continue`), which is worse
than a bounded refusal. 65536 exceeds the default macOS/Linux soft fd limits
this project targets, so the kernel is the real ceiling and the cap only
guards pathological cases.

## Refusal Instead of Silent Drop

When `try_acquire()` fails:

- SOCKS5: complete the method negotiation as usual, then reply to the request
  with `REP = 0x01` (general SOCKS server failure) and a zeroed
  `BND.ADDR`/`BND.PORT`, then close. Existing helper `write_socks5_failure` is
  already used for other rejection paths and is reused here.
- HTTP `CONNECT`: reply `503 Service Unavailable` with `Connection: close`.
- Both paths log the rejection through the existing runtime logger at the same
  level as other access rejections, including the current active count and the
  cap so operators can see which limit was hit.

Cost: an over-cap connection now performs a short read/write before closing
instead of an immediate drop. This is bounded by the existing handshake
timeout and is the point of the change — the refusal must be observable.

## Profile Plumbing and Rename

`TunRuntimeProfile` and `TunRuntimeOptions` are renamed to
`RuntimeProfile`/`RuntimeOptions`, since the profile now governs both the TUN
path and inbound admission. Deprecated type aliases keep the old names
compiling for one release; the FFI symbol names and the `XRAY_TUN_PROFILE`
environment variable and `--tun-profile` CLI flag keep their current spelling
(they are a public contract; renaming them is a separate, breaking change).
Accepted profile strings are unchanged.

The profile must reach `serve_socks_listener` and the HTTP equivalent. Today
it lives in `TunRuntimeOptions` consumed only by the TUN task, so `Core`
threads the resolved profile into the inbound listener setup alongside the
existing `EffectivePolicy`. `ConnectionAdmission::new` is then constructed
from `profile.max_inbound_connections()`.

## Testing

- Unit: `RuntimeProfile::max_inbound_connections()` returns the table above
  for every variant (exhaustive match, no wildcard, so a new profile fails to
  compile until it declares a limit).
- Unit: profile string parsing unchanged (existing tests keep passing under
  the aliases).
- Integration: a SOCKS inbound built with a tiny cap (1) accepts the first
  connection and answers the second with `REP = 0x01` rather than resetting;
  assert the exact reply bytes.
- Integration: same for HTTP returning `503`.
- Integration: the admission permit is released when a connection closes, so a
  refused-then-retried client succeeds after the first flow ends.
- Benchmark-facing: `many-idle-flows --connections 1500` under
  `XRAY_TUN_PROFILE=desktop` completes with `status=ok` (documents the fix and
  gives the benchmark harness a way to chart xray-rust above 1000 flows).

## Boundaries

All changes live in `crates/xray-core-rs` (profile type, admission
construction, refusal replies) plus the deprecated aliases re-exported where
the old names were public. No changes to `xray-config`, the TUN flow budgets,
or the benchmark harness beyond documenting the new capability.
