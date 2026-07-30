# Remove the Inbound Connection Cap

## Decision

The SOCKS/HTTP inbound connection cap (`ConnectionAdmission` with
`DEFAULT_MAX_INBOUND_CONNECTIONS = 1024`) is removed entirely. The ceiling for
concurrent inbound connections is the process's file-descriptor limit — the
same de-facto bound Xray-core and sing-box obey, with the same operator lever
(`ulimit -n` / systemd `LimitNOFILE`).

This supersedes the earlier profile-aware admission design
(`2026-07-30-profile-aware-inbound-admission-design.md`, now deleted), which
review found unimplementable as written: its `Server` profile had no selection
path, its admission domain was per-listener while its budgets were
process-wide, and its memory model contradicted its own measured slope. None
of that complexity is needed once the cap itself is gone.

## Rationale

- The cap was the only place xray-rust was artificially below the reference
  engines: measured 2026-07-30, xray-rust reset the 1025th idle SOCKS flow
  while Xray-core and sing-box served all 1500 (neither has an application
  cap on inbound connections).
- The local SOCKS/HTTP inbound is a client-side loopback surface; its
  concurrency is driven by local applications, and the memory that actually
  needs bounding on constrained devices (the TUN packet path with fixed
  smoltcp buffers) is already governed by the TUN runtime profiles.
- Verified from source (Xray-core v26.7.28, sing-box v1.13.15): neither Go
  engine caps inbound TCP connections; both rely on the fd limit, which the
  Go runtime (since 1.19) raises from the soft to the hard limit at startup.

## Changes

1. **Cap removed.** `ConnectionAdmission`, its permit/counters, and
   `DEFAULT_MAX_INBOUND_CONNECTIONS` are deleted; the SOCKS and HTTP accept
   loops admit every accepted stream (`crates/xray-core-rs/src/policy.rs`,
   `socks.rs`, `http.rs`).
2. **Accept backoff.** With the cap gone, fd exhaustion would turn the old
   `Err(_) => continue` accept loops into busy spins. Accept errors now sleep
   through `AcceptBackoff` (10 ms doubling to a 1 s cap, reset on the next
   successful accept), mirroring Go's `net/http` temporary-error backoff that
   protects the reference engines. The transition into backoff is logged once
   through the runtime logger; the sleep remains responsive to shutdown.
3. **CLI raises the fd limit.** `xray_cli::raise_nofile_limit()` lifts the
   soft `RLIMIT_NOFILE` to the hard limit at startup (clamped to
   `kern.maxfilesperproc` on macOS), matching the Go runtime so identical
   hosts get identical ceilings. Library/FFI consumers manage their own
   limits; the raise is CLI-only by design.

## Explicitly kept

The SOCKS UDP budgets (`SOCKS_UDP_MAX_FLOWS_PER_ASSOCIATION = 128`,
`SOCKS_UDP_MAX_FLOWS_GLOBAL = 1024`, pending-opens 64) stay. They bound a
real per-flow socket cost that exists because the current relay creates one
outbound socket per (client, target) pair; sing-box bounds the analogous
state the same way (udpnat2's hardcoded 1024-entry LRU). Known follow-ups,
out of scope here: log (or evict-oldest across associations) when the global
UDP budget is exhausted, and the larger "UDP relay v2" question of moving to
one socket per association/outbound for cone-NAT parity.

## Verification

- Unit: `AcceptBackoff` escalation/cap/reset (`policy.rs` tests).
- Unit: `raise_nofile_limit` lifts the soft limit and is idempotent
  (`crates/xray-cli/tests/cli_args_tests.rs`); verified by hand from a
  256-fd shell: soft 256 → 61440 (`kern.maxfilesperproc`).
- Benchmark: `many-idle-flows --connections 1500` completes with `status=ok`
  (previously refused past 1024).
