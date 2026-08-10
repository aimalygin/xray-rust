# gRPC `user_agent`: refuse an unsendable one when the outbound is built

## The problem

`grpcSettings.user_agent` reaches `GrpcConfig` as unvalidated free-form JSON.
The config parser only drops it when empty
(`crates/xray-config/src/parser.rs:2876-2883`), and `resolve_user_agent`
(`crates/xray-transport/src/stream/grpc/config.rs:198-206`) passes anything that
is not `chrome`/`firefox`/`edge`/`golang` through verbatim. `build_grpc_call`
then turns it into an `http::HeaderValue`, which rejects control characters —
so a `user_agent` holding `\r\n` or a DEL byte is accepted at startup and fails
*every* gRPC flow at dial time with "could not build the gRPC request".

The sibling field already argues the other way. `GrpcConfig::authority` is
parsed into an `http::uri::Authority` when the outbound is built, precisely so
that a static config error is reported once at startup rather than once per
dial.

## What xray-core actually does

Measured, not read off the source, because a brief that reasons about Go from
source has been wrong here before. One real grpc-go v1.81.0 dial per case, over
a tapped `net.Pipe` into a real `grpc.NewServer`, through the oracle module in
`tools/reality-oracle/grpc`; fifteen cases.

| `user_agent` byte | client validates | reaches the wire | grpc-go server |
| --- | --- | --- | --- |
| `\x00` `\x01` `\n` `\r` `\x1f` `\x7f` | no | byte-for-byte | RST_STREAM PROTOCOL_ERROR, handler never entered |
| HTAB, leading/trailing SP or HTAB | no | byte-for-byte | accepted |
| bytes ≥ `0x80` (`例え`, raw `\x80`) | no | byte-for-byte | accepted |
| empty | no | header still sent, empty | accepted |

Three consequences.

**Upstream accepts the config and then fails every flow, forever.**
`GRPCConfig.Build` passes `UserAgent` through untouched
(`Xray-core/infra/conf/grpc.go:19-40`), `WithUserAgent` never validates, and the
connection is established and cached in `globalDialerMap`. It is the *streams*
that die — one RST_STREAM per call, for as long as the config stands. There is
no working upstream behaviour to preserve.

**The two validators are the same predicate.** `http`'s is
`b >= 32 && b != 127 || b == b'\t'` (`http-1.5.0/src/header/value.rs:563-565`).
Go's `ValidHeaderFieldValue` is `!(isCTL(b) && !isLWS(b))`
(`golang.org/x/net@v0.53.0/http/httpguts/httplex.go:173-183,303-311`), which
expands to `b >= 32 && b != 127 || b == '\t'` — identical, since `isLWS`'s space
is already `b >= 32`. So the set of user agents a `HeaderValue` refuses *is* the
set a grpc-go peer refuses. Rejecting at config time narrows nothing; it moves
the same verdict from once-per-flow to once-at-startup.

**`\r\n` is not header injection.** HPACK is length-prefixed: the decoded field
on the wire was byte-identical to the configured string and no second header
appeared. The failure is field-value validation at the peer, not smuggling.

## Decision

Refuse, and refuse by type: `GrpcConfig::user_agent` becomes a `HeaderValue`,
resolved when the outbound is built, beside `authority`.

Not sanitised: stripping the offending bytes would put a user agent on the wire
that upstream never sends — a fingerprint divergence — and would silently not be
what the profile asked for.

Not in the parser: `xray-config` has no `http` dependency, so a check there
either adds one for a two-line predicate or restates the rule in a second place
where it can drift. Restating it is the thing to avoid — the argument for
refusing at all is that `HeaderValue`'s rule and grpc-go's are the same set, and
a hand-rolled third copy is exactly how that stops being true. The type is the
ceiling `h2` imposes, so the type is where the refusal belongs. The cost is that
the message cannot carry the `$.outbounds[N]` prefix the parser would have, which
is the cost `authority` already pays for the same reason.

## Design

### `crates/xray-transport/src/stream/grpc/config.rs`

- `GrpcConfig::user_agent: HeaderValue`.
- `resolve_user_agent(Option<&str>) -> Result<HeaderValue, InvalidHeaderValue>`.
  Only the verbatim arm can fail; the three masquerade arms and `golang` → `""`
  cannot, and a test pins that across the whole table rather than leaving it
  asserted in prose.
- `pub use http::HeaderValue;` beside the existing `pub use http::uri::Authority;`,
  under the same rationale: the crate that builds the config has no `http` of its
  own, and one re-export keeps exactly one `http` in the chain.

### `crates/xray-transport/src/stream/grpc/h2client.rs`

`.header("user-agent", config.user_agent.clone())`. The `.body(())` `map_err`
stays — the path is still the one part of the request a future caller could
supply — but its doc stops naming the user agent as a live cause.

### `crates/xray-core-rs`

- `CoreError::InvalidGrpcUserAgent(String)`, raised in `build_transport_layer`
  next to `grpc_authority`, naming `grpcSettings.user_agent`.
- The message interpolates with `{0:?}`, not `{0}`. The whole point of the
  variant is that the value can hold `\r\n`; interpolating it raw would let a
  config string forge log lines.

### Divergence to state in the docs

Against grpc-go, refusing costs nothing reachable: every value we refuse is a
value whose every stream a grpc-go peer resets. The residual gap is narrower
than the predicate. RFC 9113 §8.2.1 forbids only NUL, LF and CR in a field
value; Go additionally rejects DEL and the rest of C0. So a gRPC server that is
*not* grpc-go could accept `\x7f` where we refuse. An Xray gRPC inbound is
`grpc.NewServer` (`Xray-core/transport/internet/grpc/hub.go:93`), so that peer is
hypothetical, and it is the only one.

## Tests

- **`a_request_that_cannot_be_built_never_reaches_a_dial` is removed.** Its
  trigger is now unrepresentable. Its reasoning — that a per-dial build failure
  would retire healthy pooled connections and pay a handshake per flow to learn
  the same thing — moves into the `GrpcConfig::user_agent` doc, where it becomes
  the justification for the type rather than an assertion about a `String`.
- **New Go oracle artefact `user_agent_validity`**, a fifth `-wire` mode plus
  `tests/fixtures/grpc/user_agent_validity.json` and a fifth entry in
  `scripts/verify-oracle-fixtures.py`. It records, per case, the configured bytes
  in hex, whether the client put them on the wire verbatim, and whether the peer
  accepted the stream. Hex because a lone `0x80` is not representable in a JSON
  string. Unlike the four existing artefacts it cannot share one capture: each
  case needs its own dial.
- **New Rust test reading that fixture**, asserting `HeaderValue::from_bytes`
  agrees with the recorded peer verdict on every case. This is what keeps the
  central claim — same set — true rather than true-on-the-day-it-was-written.
- **New `outbound.rs` unit test** that an unsendable `user_agent` is refused when
  the outbound is built and that the error names the key, mirroring the two
  authority tests already there.

## Out of scope

`CoreError::InvalidGrpcAuthority` interpolates its value with `{0}` and has the
same log-forging exposure, since `grpcSettings.authority` is equally free-form.
Same family, different key; tracked separately rather than widening this change.
