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
- A new `Server` profile whose cap AND relay-buffer floor are sized for many
  mostly-idle connections.
- A profile-dependent initial relay copy buffer, because the cap is only
  honest if the memory it implies is affordable.
- Rename the profile type to drop its TUN-only name.

Out of scope: config-file/JSON control of the cap (the runtime profile stays
the single knob), per-inbound overrides, dynamic resizing at runtime, changes
to any TUN flow budget, changes to the fd-limit story, and SOCKS5
authentication — see "Server Deployment Prerequisites" below.

## Memory Model (why the caps are what they are)

Measured 2026-07-30 (Apple M3 Pro, release build, `many-idle-flows`): idle RSS
3.58 MiB, 1000 held SOCKS flows 41.5 MiB — about **38 KiB of resident memory
per idle flow**. The dominant term is the relay copy buffer:
`INITIAL_COPY_BUFFER_SIZE` is 16 KiB and each flow owns one per direction, so
32 KiB is committed before a single payload byte moves (`crates/xray-core-rs/src/policy.rs`).

That slope is right for a mobile client (fast bulk ramp-up, few flows) and
wrong for a server (thousands of mostly-idle flows). A cap therefore cannot be
chosen independently of the buffer floor: at 38 KiB/flow a 65536 cap implies
~2.5 GB, which is not a bound anyone can honor. Hence a `Server` profile that
lowers the initial buffer to 4 KiB per direction (~8 KiB/flow plus task
overhead ≈ 12 KiB/flow measured-slope estimate), keeping the adaptive doubling
already implemented so bulk transfers still reach the 128 KiB cap.

## Per-Profile Limits

| Profile | Inbound cap | Initial copy buffer (per direction) | Implied RSS at cap | Rationale |
| --- | --- | --- | --- | --- |
| `LowMemory` | 256 | 4 KiB | ~7 MiB | Matches its 256 TUN flow budget; smallest hosts. |
| `Mobile` | 1024 | 16 KiB | ~42 MiB | Current behavior preserved exactly — this is today's constant. |
| `Default` | 1024 | 16 KiB | ~42 MiB | Same as Mobile. |
| `MobilePlus` | 1536 | 16 KiB | ~62 MiB | Mirrors its TUN budget sitting between Mobile and Desktop. |
| `Desktop` | 8192 | 16 KiB | ~315 MiB | Desktop hosts raise fd limits; covers browser-scale fan-out. |
| `Throughput` | 8192 | 16 KiB | ~315 MiB | Optimized for few flows at maximum Gbps, not for flow count; large buffers are the point here. |
| `Server` | 16384 | 4 KiB | ~200 MiB | Many mostly-idle flows; small floor keeps the cap affordable, adaptive growth still serves active transfers. |

Every cap is now backed by an RSS figure derived from the measured slope. No
profile uses "no check": the admission permit is what produces a clean,
explainable refusal, and removing it makes the failure mode at fd exhaustion a
hot `accept()` error loop (the listener currently does `Err(_) => continue`),
which is strictly worse than a bounded refusal.

`Throughput` deliberately does NOT get the largest cap. It exists to maximize
per-connection speed with large buffers; stretching it to server-scale flow
counts would contradict its own buffer policy. Server-scale flow counts are
what `Server` is for.

## Server Deployment Prerequisites (documented, not implemented here)

Raising the cap does not by itself make a public server deployment safe. Two
gaps must be closed first, and this spec explicitly does not close them:

1. **No inbound authentication.** The SOCKS inbound accepts only
   `"auth": "noauth"` (`crates/xray-config/src/parser.rs` rejects any other
   value), so an inbound bound to a public interface is an open relay. Until
   SOCKS5 user/password authentication exists, the `Server` profile must be
   documented as "for inbounds reachable only from a trusted network", and
   `docs/status.md` keeps listing authenticated inbound as unimplemented.
2. **Listener backlog and fd limits are untuned.** Nothing sets a listen
   backlog, so bursts are bounded by the OS default (`kern.ipc.somaxconn` is
   128 on macOS) well before the admission cap is reached, and nothing checks
   `RLIMIT_NOFILE` at startup. A follow-up should set an explicit backlog and
   warn when the soft fd limit is below the profile's cap.

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

- Unit: `RuntimeProfile::max_inbound_connections()` and
  `RuntimeProfile::initial_copy_buffer_size()` return the table above for
  every variant (exhaustive matches, no wildcard, so a new profile fails to
  compile until it declares both).
- Unit: for every profile, `cap × 2 × initial_copy_buffer_size` stays under a
  declared per-profile RSS budget constant — this is the test that keeps a
  future cap change from silently outrunning its memory model.
- Integration: a relay under the `Server` profile starts at 4 KiB per
  direction and still grows to the 128 KiB cap under bulk transfer (the
  existing adaptive doubling is unchanged).
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
