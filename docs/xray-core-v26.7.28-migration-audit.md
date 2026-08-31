# Xray-core v26.7.28 migration audit

This is the tracked compatibility and test migration record for changing the
Xray-core reference from `v26.5.9` to `v26.7.28`. It records the upstream
delta, implemented adaptations, and executed verification. Compatibility
benchmark smoke and the publication-quality replacement campaign are complete.
The immutable [RC4 result group](benchmarks/results/2026-08-31-v26.7.28/README.md)
contains the exact comparator identities, 139 validated series, 695 embedded
results, reviewed omissions, and raw-archive digest.

## Fixed reference

| Reference | Tag | Full commit |
| --- | --- | --- |
| Previous | `v26.5.9` | `1bdb488c9ec09ea51e6899697d5b7437f3cf6eb2` |
| Target | `v26.7.28` | `5ca6f4b7d4dc20a881d4330e498892697627ec0c` |

The authoritative upstream range is the
[v26.5.9...v26.7.28 comparison](https://github.com/XTLS/Xray-core/compare/v26.5.9...v26.7.28).
It contains 107 commits. All new oracle reports and benchmark runs must record
the target's full commit, not only a mutable checkout path or a locally named
binary.

The published benchmark tables, charts, SVG metadata, and branch-local result
sections that say `v26.5.9` are historical evidence for that exact reference.
Keep them unchanged. Results collected against `v26.7.28` belong in new,
date-labelled result groups and sections.

## Implemented synchronization

- The REALITY authenticated ClientHello advertises `[26, 7, 28]` in
  `crates/xray-transport/src/reality_runtime.rs`. This is new enough for the
  target server's default `minClientVer` of `26.3.27`.
- `xray-utls` contains the target's explicit `hellochrome_133`,
  `hellofirefox_148`, and `hellosafari_26_3` names. Its random/modern pool is
  the target's eleven-profile pool; profiles removed from that pool remain
  available by explicit name.
- The standalone masquerade and gRPC oracle modules declare Xray-core pseudo
  version `v1.260327.1-0.20260728075948-5ca6f4b7d4dc`. The gRPC oracle also
  declares the target graph's gRPC `v1.82.1` and `x/net` `v0.57.0`.
- The benchmark SOCKS5 UDP client consumes the BND address and port returned by
  UDP ASSOCIATE instead of assuming that UDP shares the TCP listener port.
- The config parser accepts `streamSettings.method`, gives it precedence over
  `network`, and still validates the decode shape of both fields.
- XHTTP parsing uses `sessionIDPlacement`/`sessionIDKey`, applies upstream
  validation to `sessionIDTable`/`sessionIDLength`, and carries the normalized
  policy into target-compatible UUID/custom-table runtime generation.
- The Rust XHTTP model and scheduler use the target explicit-settings default
  `maxConnections=3` with zero implicit `maxConcurrency`, while preserving the
  all-zero XMUX policy produced when both settings pointers are absent/null.
- DNS parsing and the default managed cache preserve authoritative TTLs above
  300 seconds; 300 seconds remains only the no-metadata fallback.
- Local interop/process/live test harnesses assert the target's full revision.
  The benchmark builder additionally requires the exact source-clean target
  checkout and rebuilds a version-and-revision-scoped binary on every guarded
  auto-build.

## Verification completed on 2026-08-28

- `cargo test --workspace --locked`, `cargo fmt --all -- --check`, and
  `cargo clippy --workspace --all-targets --locked -- -D warnings` all passed.
- The oracle verifier checked 32 artifacts: 24 exact, eight expected
  browser-version drifts, and zero failures. The REALITY session-ID, gRPC
  fixture-consumer, user-agent, masquerade, and JSON fixture suites all passed.
- The exact target checkout passed the complete 20-case ignored local interop
  suite. A separate explicit run covered all eleven modern REALITY
  fingerprints, and the full 15-case XHTTP H1/H2/H3 matrix passed.
- Benchmark smoke passed every one of the 19 workloads supported by the
  Xray-core engine. Stream smoke covered six transports, five traffic drivers,
  all three XHTTP modes, the legacy XHTTP profile, and `reality-matrix` 7/7.
  A bounded run of all six `bench-xhttp-memory.sh` cases passed for both
  engines, followed by a second guarded auto-build smoke that rebuilt the
  pinned target and recorded clean source provenance.
- Smoke artifacts live only under ignored `target/benchmarks/v26728-smoke/`.
  No historical `v26.5.9` number or chart was relabelled.
- The fresh RC4 release campaign passed its fail-closed publication validator:
  139 summaries and 695 embedded five-run results against exact Xray-core
  v26.7.28 and stable sing-box v1.13.20. Results, tables, provenance, and the
  two runtime omissions are in the
  [dated evidence](benchmarks/results/2026-08-31-v26.7.28/README.md).

## High-impact changes on supported surfaces

### REALITY, VLESS, Vision, and uTLS

- [REALITY default minimum client version](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770)
  is now `26.3.27`. An old xray-rust version tuple such as `1.8.0` is rejected
  by a default target server.
- [The modern uTLS fingerprint registry changed](https://github.com/XTLS/Xray-core/commit/455f6bc2d5915be0465d66fe6d7d06974c2729d3).
  The target random pool is Firefox 120/148, Chrome 120/131/133, iOS 13/14,
  Edge 106, Safari 26.3, 360 11.0, and QQ 11.1. Tests must not retain the old
  nineteen-profile random expectation.
- Ignoring formatting-only changes, the range contains no semantic change to
  the VLESS wire format, Vision filtering, REALITY handshake/crypto, or the
  `transport/internet/xtls` implementation. The migration obligation here is
  the advertised version, fingerprint registry, regenerated oracle evidence,
  and live target-tag interop rather than a new wire algorithm.

Verified evidence:

- regenerated REALITY session-ID data and the complete fixture manifest pass;
- all eleven modern fingerprints interoperate with a target-tag server;
- VLESS + TLS + Vision, VLESS + REALITY + Vision, parallel-flow, and
  peer-speaks-first ignored interop cases pass.

### XHTTP

[XHTTP session fields were renamed](https://github.com/XTLS/Xray-core/commit/e10347bf01f28bca118002963ee29bbcf529cb25):

- `sessionPlacement` became `sessionIDPlacement`;
- `sessionKey` became `sessionIDKey`;
- `sessionIDTable` and `sessionIDLength` were added, including entropy
  validation.

The source and runtime adaptation is present: xray-rust accepts the target
`sessionID*` names and no longer models the old names. Xray's custom-table
ASCII, positive-length, and entropy checks apply even to an unselected block.
For a selected XHTTP transport, all nine predefined aliases and literal ASCII
tables feed the session generator, unequal lengths retain Xray's half-open
range, and an empty table retains the UUID v4 fallback. One fresh ID is created
per split-mode flow and placed with the configured target key; `stream-one`
continues to omit session metadata.

The net XMUX default changed from `maxConcurrency=1` to
`maxConnections=3`: it first changed to six in
[`18b85adb`](https://github.com/XTLS/Xray-core/commit/18b85adb4e288f49a7894351c6e0f2428c0beef6)
and then to three in
[`18e28390`](https://github.com/XTLS/Xray-core/commit/18e283909ca253d4220136eccca0a27006ea709f).
The Rust model, scheduler documentation, and default-flow coverage now use the
same three-client-slot default for an explicit settings block. Both settings
pointers absent/null still bypass `SplitHTTPConfig.Build` and retain an
all-zero XMUX policy, matching the target. Benchmarks that intend to study a
different topology must continue to set identical explicit XMUX values for
both engines.

Resource and behavior fixes make old XHTTP performance baselines
non-comparable:

- [packet-up usage accounting and H3 keepalive](https://github.com/XTLS/Xray-core/commit/4c3842711dd6abc8401f83678f30bb56e3f8819b);
- [active close of retired H3 QUIC/UDP resources](https://github.com/XTLS/Xray-core/commit/1e036ce1c5076f695d149a672ca578ebf907f882);
- [no forced trailing slash when neither identifier is in the path](https://github.com/XTLS/Xray-core/commit/1aabe7ea78eca88deedc234a3e668895fa9bc08c);
- [invalid hosts return an error instead of panicking](https://github.com/XTLS/Xray-core/commit/986c512e0f7bc40069e84de903ae2d5a32e324b4).

Parser and scheduler cases cover the target names/default, the full 15-case
H1/H2/H3 XHTTP interop matrix passes, and bounded concurrent/rollover smoke is
green. RC4 now supplies fresh five-run release RSS, setup, duration, CPU, and
throughput evidence for stream, packet-pressure, and the explicit
`maxConnections=16` legacy memory profile. The publication does not infer
network latency/loss or a complete FD-lifetime result from those loopback
summaries.

### TLS and transport security

[Deprecated TLS fields were removed](https://github.com/XTLS/Xray-core/commit/55956f8d70f0f92e861cea57957f62afffda31d4):
`allowInsecure: true` is now a configuration error, and
`verifyPeerCertInNames` and `echForceQuery` are gone. Target-tag oracle and
benchmark configs must use a real trust chain or `pinnedPeerCertSha256` and
must not depend on these fields. xray-rust now rejects canonical
`allowInsecure: true` at its exact JSON path. Legacy importer output carrying
that flag is rejected too; there is no implicit host-policy exception.

[A CA certificate pin now requires a valid server name](https://github.com/XTLS/Xray-core/commit/64fada32b5b9e6ae064a038fa0e4e2b766499bd5).
The supported `pinnedPeerCertSha256` slice hashes the whole DER certificate,
accepts an exact leaf pin before PKI/name checks, and otherwise trusts only the
first matching presented CA while preserving chain, time, and DNS/IP name
verification. Positive DNS/IP SAN and negative SNI/mismatch coverage exercises
that boundary. `verifyPeerCertByName` now follows the target grammar (split on
commas, trim whitespace, ignore empty entries) and ORs DNS/IP SAN names against
ordinary roots or the pinned CA without replacing handshake SNI. A leaf pin
still bypasses the list. Parser, runtime, cache-key, destination-fallback, and
DNS/VLESS propagation tests cover the boundary. `fromMitm`, ECH, custom trust
stores, and removed pin forms remain unsupported and fail closed.

[Plaintext VLESS and Trojan outbounds to public destinations are rejected](https://github.com/XTLS/Xray-core/commit/d7fa2076c3e5401173bf9b58f7b07f9aa5174443).
The target implementation invokes this validator only for simplified
top-level VLESS settings; its legacy `vnext` form leaves the checked `Address`
field nil and is accepted even for a public plaintext endpoint. xray-rust
supports `vnext` and deliberately closes that upstream gap: absent/empty/`none`
stream security rejects a public IPv4, IPv6, or domain server during parsing,
while TLS and REALITY stay valid. This is an intentional security-policy
divergence, not an exact parser-parity claim. The exemption uses Xray's exact
18 private/reserved/test CIDRs and its
private/test/domain-suffix plus dotless-host matcher, including lowercase and
single-trailing-dot normalization. Model boundary tests cover every CIDR class,
IPv4-mapped IPv6, domain suffixes, dotless syntax, and normalization; parser
tests cover rejection, bracket-then-whitespace address normalization, and both
protected security modes. Trojan remains out of scope because xray-rust does
not implement that outbound.

### SOCKS5 UDP and XUDP

[UDP ASSOCIATE now creates a listener per TCP control connection](https://github.com/XTLS/Xray-core/commit/e26f5e95487a9c0064dd9f9e34ebef53f0018460),
with follow-up source/domain fixes in
[`64127384`](https://github.com/XTLS/Xray-core/commit/641273848694934d6aec7992bb71162ec69f2a53).
The client must send to the returned BND address/port and keep the TCP control
connection open. The benchmark client follows that contract, and SOCKS UDP,
XUDP, REALITY/Vision-XUDP, idle-resource, and teardown smoke passed. Fresh
repeated resource measurements are still needed because the target's
allocation, FD, and lifetime model differs from the old oracle.

### DNS

[The unintended 300-second TTL cap was removed](https://github.com/XTLS/Xray-core/commit/ac04c445bd09541cc9c35a120ee01d8a177a4d83).
The minimum valid answer TTL is retained; 300 seconds is only the fallback
when no valid TTL exists. The Rust response parser, default cache, and active
compatibility text now preserve authoritative values above 300 seconds.
Source-level cases cover that behavior; oracle/runtime verification remains a
separate gate.

[DNS outbound `reject` became `return`](https://github.com/XTLS/Xray-core/commit/cb8cd048c12f902b673a0e4ed6e4c51017a85439),
with configurable `rCode` and JSON spelling `qType`. The target default for
non-A/AAAA queries is an empty `NOERROR`; legacy `nonIPQuery=reject` maps to
`REFUSED` (`RCODE=5`). xray-rust now accepts the canonical
`qType`/`Return`/`rCode` surface, returns empty `NOERROR` on the default
non-address path, and preserves lower-case `qtype` plus `Reject` only as warned,
unambiguous input aliases. Parser, policy, wire-response, and TUN UDP/TCP cases
cover configured response codes and the default. Also retain a negative case
for overlong names, which now return an error instead of panicking after
[`a2cec2e5`](https://github.com/XTLS/Xray-core/commit/a2cec2e580e8ea1900701b11b425e0351de2ec71).

### Routing, config, and server-side transports

- [`domain:` suffix matching is now case-insensitive](https://github.com/XTLS/Xray-core/commit/be8009c62509322682299bfbe969a62cee03f4d5),
  which the existing matcher already implements; mixed-case coverage now
  locks it in. Weakly held geodata matchers also change steady-state RSS;
  routed-geodata smoke passed and RC4 publishes fresh repeated RSS and setup
  numbers for the exact pinned geodata files.
- [`streamSettings.method` is the preferred spelling](https://github.com/XTLS/Xray-core/commit/fb548f54d22856446e883c6d13b32d60f0dda9bd),
  while `network` remains an alias and loses when both occur. The parser now
  implements that precedence, treats null pointers as absent, and validates
  malformed values on either spelling; verification remains part of the
  config test gate.
- [Root-level `env` was added](https://github.com/XTLS/Xray-core/commit/d5bc58dc6b7608e664515f970a9742e67e5f9623).
  It is outside the currently accepted top-level subset unless deliberately
  implemented; reject it clearly rather than silently ignoring it.
- XHTTP, WebSocket, HTTPUpgrade, and gRPC servers now require configured
  [`sockopt.trustedXForwardedFor`](https://github.com/XTLS/Xray-core/commit/711aea4e34b0a00073d2fea6577f28a5d7c9b5eb)
  before trusting `X-Forwarded-For`. This mostly affects the target server used
  by local tests because xray-rust does not implement those VLESS inbounds.
- HTTPUpgrade server handshakes now have a four-second/12 KiB read bound
  ([`c320e891`](https://github.com/XTLS/Xray-core/commit/c320e89108c73b3d83ace6c2f32db1da7a48e5d4));
  malformed QUIC sniffing was hardened against panic
  ([`8f15190c`](https://github.com/XTLS/Xray-core/commit/8f15190c230fe6975c9b18e31316c6bc494f3863)).

The public commander/proxyman/router protobuf API has no material semantic
change in this range. Stats registration race fixes, instance-scoped metrics,
and TUN traffic counters can change resource observations but do not create a
new xray-rust API compatibility target.

## Intentionally out of scope

Unless the supported-surface document is expanded separately, this migration
does not add parity for:

- WireGuard refactors or dynamic inbound peers;
- Hysteria server, `vlessRoute`, or `udpHop` features;
- FinalMask additions (`mkcp-legacy`, Realm, Salamander/Gecko, XICMP, XMC,
  fragment lengths/delays, and related masks);
- VMess, Trojan, Shadowsocks, or SS2022 protocol support;
- Xray-managed OS TUN creation, automatic routes, random `utunN` naming, or
  macOS process routing; xray-rust continues to expose the host-managed packet
  and file-descriptor boundary;
- Xray server-side VLESS transports, trusted-forwarder processing, metrics
  service parity, or internal stats-manager interfaces.

Out-of-scope features must remain rejected or documented as unsupported; they
must not be accepted and silently approximated.

## Remaining evidence limits

- [x] Five-run release process evidence against exact Xray-core v26.7.28 and
  stable sing-box v1.13.20 is published in a new immutable result group.
- [ ] Controlled RTT/loss and wide-area behavior remain unmeasured; loopback
  latency is not a substitute.
- [ ] Mobile-device RSS, energy, thermal, sleep/wake, and network-transition
  evidence still requires Instruments/Perfetto campaigns.
- [ ] Long-running fuzz, sanitizer, Miri, and independent security-audit work
  remains separate from this compatibility migration.

## Verification gates

Pin and build the exact local oracle before any live run:

```sh
export XRAY_CORE_CHECKOUT=/absolute/path/to/Xray-core
git -C "$XRAY_CORE_CHECKOUT" switch --detach v26.7.28
git -C "$XRAY_CORE_CHECKOUT" rev-parse HEAD
git -C "$XRAY_CORE_CHECKOUT" status --short
(
  cd "$XRAY_CORE_CHECKOUT"
  go build -o xray ./main
)
```

The printed revision must be
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. The oracle and benchmark guards
also reject tracked/staged changes and any untracked path other than the root
`xray`/`xray.exe` build product and `target/`. Go may still print a `-dirty`
VCS token for those allowlisted artifacts; record the token and executable
SHA-256 alongside the full source revision.

Run the deterministic and fixture gates from the xray-rust root:

```sh
go run ./tools/reality-oracle/session_id_vectors.go \
  --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go \
  --check tests/fixtures/reality/clienthello_chrome_auto.json
bash scripts/verify-oracle-fixtures.sh
cargo test --locked -p xray-transport reality
```

Then run the ignored local Xray-core suite and the complete XHTTP matrix:

```sh
XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests -- --ignored --nocapture

XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
XRAY_XHTTP_INTEROP_CASES=all \
cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests \
  rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases \
  -- --ignored --nocapture
```

Before publishing replacement benchmark numbers, run all existing release
workloads against the exact target checkout, with special attention to XHTTP
concurrency/rollover, SOCKS UDP/XUDP, REALITY/Vision, DNS TTL/response codes,
and routed geodata memory. Keep each new raw result group and its provenance;
pass `--xray-core-version v26.7.28` only for groups whose recorded Xray source
revision is the full target commit.

## Reproducing the upstream audit

```sh
git -C Xray-core fetch --tags origin
git -C Xray-core rev-parse v26.5.9 v26.7.28
git -C Xray-core log --reverse --oneline v26.5.9..v26.7.28
git -C Xray-core diff --stat v26.5.9..v26.7.28
git -C Xray-core diff --name-status v26.5.9..v26.7.28

# Separate real wire changes from formatting-only churn in the critical path.
git -C Xray-core diff --ignore-all-space v26.5.9..v26.7.28 -- \
  proxy/vless transport/internet/reality transport/internet/xtls

# Inspect the supported surfaces with full context.
git -C Xray-core diff v26.5.9..v26.7.28 -- \
  infra/conf proxy/dns proxy/socks app/router \
  transport/internet/tls transport/internet/splithttp \
  transport/internet/grpc transport/internet/websocket \
  transport/internet/httpupgrade
```

For a specific change, use `git -C Xray-core show <full-commit>`; the commit
links above are the corresponding primary-source GitHub views.
