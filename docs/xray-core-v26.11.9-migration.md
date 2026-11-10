# Xray-core v26.11.9 migration

Source baseline: v26.10.31 (`a4a3dff5b20c2faae567b742c172c7b95e75c083`).
Target: v26.11.9 (`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`), with Go
1.27.3. The range has 24 commits. `go.mod` moves uTLS to the official
`refraction-networking/utls` at `a13c59ffe98b` (20261108164504), REALITY to
`4bb46b2afd8b` (20261108101329), `golang.org/x/net` to v0.62.0,
`google.golang.org/grpc` to v1.85.0 and `klauspost/cpuid` to v2.4.2.
`golang.org/x/crypto` stays at v0.58.0. Dated benchmark and device reports
keep their original source identities.

## Changes that affect the Rust client

- **Freedom `finalRules`** (#7329, `infra/conf/freedom.go`). `blockDelay` is
  renamed `delay`; the old name still works, with a deprecation warning, and
  takes the place of `delay` when both are set. A new `logLevel` (`none`,
  `debug`, `info`, `warning`, `error`, matched without case, `info` when
  empty) sets the severity Xray-core logs a rule's blocked connections at;
  any other value is refused. An allow rule with a delay or a nonempty level
  is refused, so an allow rule with `blockDelay`, which v26.10.31 took, now
  fails. The parser follows all of it, including Go's order: an allow rule
  refuses an unknown level before the level is read. xray-rust writes no log
  line for a blocked connection, so `logLevel` changes nothing else. The
  default rules now log at `warning`. One of them applies here: the rule
  that blocks every destination for the connections a VLESS reverse proxy's
  portal opens through the bridge, which carries that level too. The others
  arise for server inbounds (and, upstream, for the MASQUE inbound, which is
  what "the default safe policy on MASQUE" means), none of which xray-rust
  has.
- **uTLS draws behind ChromeParrot.** The new uTLS reads 16 bytes of GREASE
  seeds per hello instead of 10 (eight slots instead of five) and takes the
  ECH GREASE key from `crypto/hpke`. The Chrome QUIC ClientHello carries no
  GREASE value and quic-go's ChromeParrot code is unchanged, but every random
  read after the seeds moved. `tests/fixtures/chrome-parrot/initials.json` is
  therefore regenerated from v26.11.9's own Hysteria dialer; the Rust side
  replays the new reads to the same transport parameters, datagrams and
  ClientHello without a change.
- **Mux defaults** (`app/proxyman/outbound/handler.go`). Every TCP
  `concurrency` from zero up to 128 runs as 128 children per parent, a larger
  value stays, and a parent hands out 1024 children over its life instead of
  128, for TCP and XUDP alike. The pools now do the same: a TCP concurrency of
  0 to 128 is 128, both concurrencies take any 16-bit value as Xray-core's
  JSON does (xray-rust capped them at 64 before), and the lifetime child IDs
  of a parent rise to 1024. The four opening parents and sixteen live parents
  per pool stay xray-rust's own bounds. The new `MutexWriter`, which keeps
  Xray-core's sessions from writing to a parent at once, has no counterpart
  to add: one task writes each parent's frames.

## Reviewed without a change

- WireGuard gives up on a domain endpoint's lookup at the connection's
  deadline (#7323). The Rust outbound already resolves its endpoints inside
  the dialing caller's deadline and cancellation, and within ten seconds.
- `TimeoutWrapperReader` returns `ErrReadTimeout` (#7327). It wraps the TUN
  inbound's reader (and server inbounds'), so TUN sniffing and the first
  payload wait now time out as other inbounds' pipes do. xray-rust's
  sniffing and first-payload waits do not depend on the inbound.
- The UdpHop mask no longer logs a closed hop socket's read error (#7319);
  xray-rust's mask writes no such log.
- The `log.loglevel` field is now spelled `logLevel` in Xray-core's struct
  tag. Go matches JSON keys without case, so both spellings keep working, as
  they do here.
- Not applicable: geodata downloads of `.dat.gz` for XTLS/Xray-rules-dat
  (#7334; xray-rust downloads no geodata), closing an inbound added at run
  time that fails to start (#7223; no API adds inbounds here), Windows TUN and
  WFP changes, Android packed relocations and Docker workflow bumps, and the
  XDRIVE `local` service's retry of Windows sharing violations.
- gRPC v1.85.0 and x/net v0.62.0 change no byte the gRPC oracle records: the
  five `tests/fixtures/grpc` fixtures differ only in the module versions they
  name. grpc-go's server keeps its ping policy (`handlePing` is unchanged);
  its client now closes a connection whose reads stay throttled for ten
  seconds, which concerns grpc-go clients, not the Rust one. x/net's `http2`
  package is unchanged.

## Still out of scope

The items the v26.10.31 record lists as planned separately remain so, apart
from those 0.10.0 has since brought.

## Evidence

Local evidence on macOS arm64 (Rust 1.96.0, Go 1.27.3), against a clean
checkout of the target built with Go 1.27.3:

- Go-oracle fixtures (`scripts/verify-oracle-fixtures.sh`): 34 checked, 21
  reproduced exactly, 8 apart from the date-seeded browser-version draw, and
  the 5 gRPC fixtures after their recorded module versions moved; none failed.
  The BBR trace reproduces byte for byte apart from the source line naming
  the release.
- `tests/fixtures/freedom/config-verdicts.json` (28 cases) and
  `tests/fixtures/mux/config-verdicts.json` (11 cases) record what
  `xray run -test` of v26.11.9 says of each configuration;
  `scripts/check-xray-verdicts.sh` rechecks them in the `go-oracles` job, and
  the parser agrees with every verdict but the recorded deliberate
  differences (a negative or wrapped delay).
