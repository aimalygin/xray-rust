# shaped-rustls Brief: Real ECH In A Shaped ClientHello

## Goal

Accept `streamSettings.tlsSettings.echConfigList` the way Xray-core v26.10.21
does: the outer ClientHello keeps the uTLS fingerprint shape, carries the ECH
config's `public_name` as SNI and a real `encrypted_client_hello` extension in
the slot where the fingerprint has its GREASE ECH, and the server sees the real
`serverName` only inside the encrypted inner hello.

Subscriptions increasingly carry `ech=` / `echConfigList`, and xray-rust rejects
them today (`config-compatibility.md`, TLS section). This brief records what Go
does, why stock managed ECH in our rustls fork cannot be combined with the
shaped hello as it stands, and the fork changes that would make it correct.
Nothing here is implemented yet.

## What Xray-core Does

References are to Xray-core `1b1647cd` (v26.10.21) and the uTLS it pins,
`v1.8.3-0.20260301010127-aa6edf4b11af`.

### Configuration

- JSON: `echConfigList` (string), `echSockopt` (sockopt object, used only for
  the DNS query dial), and the server-side `echServerKeys` (base64)
  (`infra/conf/transport_security.go:316-318`, `:392-405`). There is no
  `echForceQuery` in this version; it does not exist anywhere in the tree.
- `echConfigList` without `://` is a standard-base64 `ECHConfigList`
  (`transport/internet/tls/ech.go:77-82`).
- `echConfigList` containing `://` is a DNS source for an `HTTPS` (type 65)
  record (`ech.go:60-76`, `:175-318`):
  - `udp://host[:port]` — classic DNS, port 53 by default, 5 s timeout, a
    single 512-byte read;
  - `https://…` — DoH POST over HTTP/2, dialed through `internet.DialSystem`
    with `echSockopt`, uTLS `HelloChrome_Auto`, EDNS0 padding of 100–300 bytes
    and an `X-Padding` header;
  - `h2c://…` — the same request, but the TLS is expected from the dialed
    outbound (`echSockopt.dialerProxy`), with the MITM server name in context;
  - `name+URL` overrides the queried name; otherwise the queried name is
    `serverName` and an IP `serverName` is an error.
  The first `ech` SvcParam of the first matching `HTTPS` answer is used. Results
  are cached per `server|name|sockopt` for the record TTL, served stale while a
  background refresh runs, and refreshed synchronously once more than four
  hours stale (`ech.go:142-171`).
- Every failure — bad base64, DNS error, no record — is only logged at config
  build time (`transport/internet/tls/config.go:476-481`), and a deliberately
  invalid list `{1,1,4,5,1,4}` is installed (`ech.go:52-58`), so the connection
  fails closed at handshake time instead.

### Handshake

- The ECH list goes into `tls.Config.EncryptedClientHelloConfigList` and is
  copied into the uTLS config (`transport/internet/tls/tls.go:184-194`). Every
  TLS dialer (raw, ws, httpupgrade, grpc, xhttp, masque, xdrive) uses
  `UClient` with the fingerprint unless `fingerprint` is `unsafe`, in which
  case Go `crypto/tls` performs ECH itself. Hysteria and XHTTP/3 use quic-go,
  i.e. unshaped `crypto/tls` ECH.
- uTLS builds the outer hello from the fingerprint, sets the outer SNI to the
  ECH `public_name` (`u_parrots.go:3098-3100`), and replaces the fingerprint's
  GREASE ECH extension **in place** with the real outer ECH extension
  (`u_conn.go:504-565`). A fingerprint without an ECH extension (Safari, iOS,
  Edge, the older Chrome/Firefox snapshots, …) fails the handshake with
  `extension satisfying EncryptedClientHelloExtension not present`
  (`u_conn.go:530`).
- The inner hello is a Go-`crypto/tls` hello built from the configuration, so
  it carries the configured `alpn`, not the fingerprint's
  (`u_conn.go:567-584`, `u_handshake_client.go:337-372`). Key shares,
  signature algorithms, session id and curves are copied from the outer hello,
  and the compressible extensions are referenced through
  `ech_outer_extensions` in outer order (`handshake_messages.go:181-345`); ALPN
  is never compressed for that reason (`handshake_messages.go:242-244`). Xray
  relies on this: the WebSocket path keeps the fingerprint ALPN outside and
  sends `http/1.1` only inside ECH (`tls.go:127-132`).
- ECH forces TLS 1.3 (`u_handshake_client.go:337-343`).
- On rejection uTLS verifies the certificate against `ServerName` rather than
  the public name (`handshake_client.go:1142-1175`, a uTLS deviation), sends
  `ech_required` and returns `ECHRejectionError{RetryConfigList}`
  (`handshake_client_tls13.go:170-173`). Xray never reads the retry configs:
  the dial simply fails. There is no automatic retry.
- REALITY has no ECH fields; ECH exists only under `tlsSettings`.

## Why Stock Managed ECH Does Not Compose With The Shaped Hello

shaped-rustls (`3a131bea`) already contains upstream rustls client ECH
(`EchMode::Enable`, HPKE via `crypto::aws_lc_rs::hpke`). On its own it
interoperates with the Go server: an experiment against a Go `crypto/tls`
server keyed with `xray tls ech` output reports `ECHAccepted=true
ServerName="inner.example"` and rustls reports `EchStatus::Accepted`.

The same connection with one plan entry that xray-rust always sets — an exact
`signature_algorithms` payload — fails: the Go server aborts with
`tls: second client hello encrypted client hello extension does not match`,
rustls receives `illegal_parameter` and reports `EchStatus::Rejected`. When the
verifier's typed signature-scheme list is made byte-identical to the exact
payload, the same plan is accepted again, which pins the failure on the
mismatch described in the first item below. The causes, in the fork:

1. **The inner hello is rebuilt from typed fields only.**
   `EchState::encode_inner_hello` copies the outer extensions with
   `clone_one` (`rustls/src/client/ech.rs:563-660`), which knows the typed
   slots but not `exact_extensions`, `raw_extensions` or
   `grease_extensions`. xray-rust carries `signature_algorithms`,
   the advertised `supported_versions`/`supported_groups`, ALPS, delegated
   credentials, record size limit and others as exact/raw payloads
   (`crates/xray-transport/src/utls_shaping.rs:461-553`; the advertised lists
go through `add_exact_extension_payload`, `client/hs.rs:620-656`). Several of those are
   ECH-compressible (`ExtensionType::ech_compress`), so the encoded inner hello
   points the server at the outer's exact bytes while the client's inner
   transcript hashes the typed bytes. The two sides disagree about the inner
   hello, and the handshake cannot succeed.
2. **The real ECH extension is forced last.** With managed ECH the extension
   is a "final" extension (`msgs/handshake.rs:1157-1172`), excluded from the
   custom order and appended after it (`msgs/handshake.rs:1204-1226`). uTLS
   puts it in the GREASE slot, which for Chrome is a shuffled middle position.
   The planned order also has to drop the exact GREASE ECH entry, because exact
   ECH and managed ECH are mutually exclusive (`client/hs.rs:658-694`,
   `:1248-1255`).
3. **Padding is finalized after sealing.** `finalize_padding_plan` runs after
   `ech_hello` has computed the AAD over the outer hello
   (`client/hs.rs:1260-1290`). Any profile whose padding length changes at that
   point changes the outer hello after it was authenticated.
4. **The inner ALPN cannot differ from the outer.** ALPN is compressed and the
   inner copies the shaped outer ALPN, whereas Go sends the configured `alpn`
   inside (see Handshake above).

None of these can be worked around from xray-rust without either dropping the
fingerprint shape (a new, distinctive hello) or reimplementing ECH outside
rustls. Both are worse than a fork change.

## Proposed Fork Changes

All behind the existing `ClientHelloPlan`; no change for connections without
ECH.

1. Let a custom extension order place managed ECH: treat
   `EncryptedClientHello` as orderable when the plan's order names it, so the
   real outer extension lands where the fingerprint's GREASE ECH was. Only
   `pre_shared_key` must stay last.
2. Build the inner hello from the effective outer encoding: carry the outer's
   exact/raw payloads into the inner for every extension the inner keeps, so a
   compressed reference and the client's own inner transcript describe the same
   bytes. Keep the rule that the inner omits TLS-1.2-only extensions and has no
   GREASE.
3. Add a plan field for the inner ALPN (`ClientHelloPlan::with_ech_inner_alpn`
   or similar) and stop compressing ALPN when it differs from the outer, the
   way uTLS does.
4. Run padding finalization on the outer hello before `ech_hello` seals it,
   with the placeholder ECH payload already in place so the length is right.
5. Tests in the fork: an ECH oracle comparing the outer extension order and the
   decoded inner hello against uTLS, and a round trip against the rustls
   server with exact and raw extensions present.

## xray-rust Work Once The Fork Lands

- Parser: accept a base64 `echConfigList`, decode it, and validate it with
  `EchConfig::new` at load time, failing with a JSON-path error instead of
  Go's handshake-time failure. Reject `echConfigList` with a fingerprint whose
  profile has no ECH extension, at load time, with the same message uTLS
  gives at handshake time. DNS forms (`udp://`, `https://`, `h2c://`,
  `name+URL`) and `echSockopt` stay rejected with a path-aware error until a
  DNS fetch path exists; `echServerKeys` stays rejected (no TLS server role).
- Dialer: `with_ech(EchMode::Enable)`, inner name from `serverName`, plan from
  the fingerprint with its GREASE ECH replaced by managed ECH; TLS 1.3 only.
  `fingerprint: "unsafe"` and Hysteria need no fork change and can use
  unshaped managed ECH directly.
- Rejection: fail the dial like Xray. Optionally log the retry configs; no
  automatic retry, since Go has none.
- Surface: `config-contract.json`, tooling cases, `config-compatibility.md`
  (replace the "does not implement ECH" sentence), `status.md`, CHANGELOG, and
  the trojan share-link importer (`ech=` → `echConfigList`).
- Interop: a `scripts/check-ech-interop.sh` that runs the pinned Xray binary as
  a VLESS+TLS server with `echServerKeys` and proves acceptance with the inner
  name, for `chrome` and `firefox`.
