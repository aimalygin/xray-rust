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

- **Chrome 155 is the default fingerprint** (#7135, then official uTLS
  20261108164504). `chrome`, `hellochrome_auto` and an empty `fingerprint`
  are uTLS's `HelloChrome_Auto`, which is now `HelloChrome_155`; the new name
  `hellochrome_155` joins `ModernFingerprints`, so `random` draws from twelve
  names. Chrome 155 is Chrome 133's hello with GREASE and ML-DSA 44/65/87
  ahead of the signature algorithms and a `trust_anchors` extension (`0xca34`)
  with 28 fixed Chrome Root Store trust anchor IDs. xray-rust sends the same
  hello (a new profile; `trust_anchors` byte for byte), keeps Chrome 133
  under `hellochrome_133` with a raw fixture of its own, and holds the pinned
  binary's own hellos for `""`, `chrome`, `hellochrome_155` and
  `hellochrome_133` to the fixtures in the `go-oracles` job
  (`scripts/check-xray-default-fingerprint.sh`). See
  [TLS ClientHello shaping](config-compatibility.md#tls-clienthello-shaping).
  The uTLS oracle module now builds with Xray-core's own graph (x/crypto
  0.58.0) and `godebug cryptocustomrand=1`: with the `go 1.27` directive that
  uTLS requires, Go would otherwise ignore the oracle's deterministic reader
  in `crypto/ecdh`. ECH GREASE keys now come from `crypto/hpke`, which reads no
  injected randomness, so the oracles pin that key to the zero-key point the
  fixtures always held.
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

- **XDRIVE on Google Drive** (#7340, #7352). The client follows the new
  `drive.go`, `slots.go`, `xdrive.go`, `params.go` and `client.go`: rings as
  deep as `concurrency` (64 by default for Drive, with a 10 ms flush and
  200 ms polls; at most 256), two spare rings made ahead of time, the dial
  returning at once and announcing the session after its first segment with
  that segment inline (`first`), at most twelve slot writes on their way and
  bursts in inline segments, a reader that reads three segments ahead, polls
  the head with up to three reads, hedges slow bodies and fails on a slot
  that holds a broken frame or body for a minute; on the Drive side, one
  shared token fetch with background refresh, backoff after failures and a
  hard stop on refused credentials, a cooldown after throttling, a reserved
  lane for watermarks and the head, per-try timeouts that retire a
  stalled connection, a 32 MiB answer cap and parallel deletes. The wire
  stays compatible both ways: the new client meets v26.10.31's server
  (which ignores `first`; the segment still goes to slot 0) and v26.11.9's.
  See [XDRIVE](config-compatibility.md#xdrive).

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
- REALITY 20261108101329 bounds the server's probe of its target and lets it
  probe without a server name; nothing changes for a client.
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

- Chrome 155: `scripts/verify-oracle-fixtures.sh` reproduces all 35 fixtures
  (20 REALITY, 3 new or moved: the three `chrome` ones and
  `clienthello_raw_hellochrome_133.json`), identically when the oracles run as
  linux/amd64; `scripts/check-xray-default-fingerprint.sh` finds the pinned
  binary sending the fixtures' shapes for `""`, `chrome`, `hellochrome_155`
  and `hellochrome_133`. Live REALITY Vision against the v26.11.9 server
  passes with `chrome`, `hellochrome_155`, `hellochrome_133`, Firefox 148,
  Safari 26.3, Chrome 131, `random` and `randomized`, and the full VLESS
  encryption matrix (168 TLS and REALITY profiles on the default fingerprint)
  and the v0.8 carrier matrix pass.
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
