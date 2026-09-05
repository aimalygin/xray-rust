# XHTTP independent download transport

Development increment for v0.6, 2026-09-05. Contract: Xray-core v26.7.28,
commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

## Configuration and wire contract

A populated effective `xhttpSettings.downloadSettings` is one independent
StreamConfig: an explicit non-empty `address`, nonzero `port`, `network: xhttp`
(or `splithttp`), and independently validated security, XHTTP settings, socket
options and QUIC parameters. Existing one-level `extra` replacement and alias
priority apply independently. No address, path, TLS identity or pool is inherited.
The two endpoints must reach the same server-side XHTTP session namespace; two
unrelated servers cannot join a session merely by using equal credentials.

Uploads support packet-up and stream-up. Auto is packet-up except REALITY,
where the presence of downloadSettings selects stream-up (upstream
`transport/internet/splithttp/dialer.go`). Stream-one with downloadSettings is
rejected, matching `infra/conf/transport_method.go:SplitHTTPConfig.Build`.
The download side always issues the bodyless stream request with the upload's
fresh session ID, using its own path, metadata placement, headers and padding.
Its configured mode does not turn the GET into a second upload or session.
H1, TLS H1/H2/H3 and REALITY H2 use the existing protected transport engines.

Nested effective downloadSettings are rejected before descending into another
stream configuration. Only one additional transport and pool may exist per
outbound. A protected upload cannot select a plaintext download. Without VLESS
encryption, plaintext download destinations follow the existing private/test
server exemption. Unsupported fields and insecure TLS remain fail closed.
Transport-layer chaining with split downloads is deferred and rejected for
both a chain's source and target, before resolution or sockets.

## Ownership and resource contract

Each outbound owns separate upload and download XMUX managers, with independent
request budgets, connection retirement and idle deadlines. A logical flow owns
both usage leases and one shared failure state. Download response establishment
is deferred so that server-first reads work without waiting for an upload body.
Cancellation during upload setup aborts the already-started download opener;
dropping a flow aborts its workers, releases both leases and stream reservations.
Packet upload rollover uses only the upload pool. Failure never falls back to
the upload endpoint or automatically replays application data.

Both destinations resolve through the managed resolver before opening the flow;
all TCP/QUIC sockets use the host's protector and existing Happy Eyeballs path.
No global resolver or hidden unprotected dial is introduced. Existing request,
record, header, packet worker, H3 stream and receive-window bounds remain in
force; split downloads add at most one additional existing pool per outbound.
Adaptive H3 windows and concurrent H3 requests remain conditional experiments.

## Verification

Shared configuration fixtures are checked against the pinned Go builder and
Rust parser. Transport tests cover independent request identity, session reuse,
server-first reads, cancellation, failure, usage accounting and rollover.
Full-process interop must exercise supported upload/download HTTP versions and
security with endpoints converging on the same Xray listener/session namespace.
Changes require the normal Rust checks and scoped security review. Physical
Apple/Android and clean-candidate performance evidence remain release gates;
local tests do not substitute for them. Canonical JSON is the initial mobile
entry point; no new share-link syntax is claimed by this increment.


## Development evidence (2026-09-05)

- Full Rust workspace, `--exclude xray-rust-fuzz --all-targets --locked`:
  2,167 passed, zero failures, 45 explicitly ignored. Dedicated oracle gates
  below run their prerequisite-dependent ignored cases separately.
- All-target/all-feature Clippy with warnings denied, rustdoc with warnings
  denied, Rust formatting, diff whitespace and JSON fixture safety passed.
- The existing guarded VLESS encryption oracle also passed after the carrier
  refactor, including its full-process carrier/Vision matrix. RC and scheduled
  interop script/workflow policy tests passed with the dedicated gate wiring.
- Shared configuration oracle: 33 cases, with independent Go build acceptance
  and Rust subset/error-path assertions, passed.
- Full-Xray matrix: 66 profiles and 264 application flows passed. TLS covers
  all nine H1/H2/H3 upload/download pairs; plaintext H1 and direct REALITY H2
  are also covered. Every pair runs packet-up and stream-up, with no VLESS
  encryption, authenticated 0-RTT encryption, and encryption plus Vision.
- Each profile exercises server-first TCP data, two simultaneous subsequent
  TCP flows and UDP/XUDP, and asserts both managed DNS queries and socket
  protection. The first encrypted flow creates a ticket; subsequent calls
  exercise the runtime's reuse path.
- Separate transport regressions passed for independent headers/authority and
  session placement (eight H1/H2 combinations), cancellation during upload
  setup, download rejection, upload request-budget rollover, and H3 drop/reset
  with both connections subsequently reused.
- The test frontend enables HTTP/1 full duplex and disables backend keepalive,
  following the pinned Xray client's H1 download limitation. Rust frontend
  connection pooling remains enabled and is exercised by the tests.

These are local development results, not clean-candidate device or performance
reports. No changes to cryptographic primitives, unsafe code or C ABI layouts
are introduced by this increment. The author checked recursive and programmatic
configuration rejection, downgrade checks, protected DNS/dial ownership,
separate pool identity and RAII cleanup; final independent sign-off still
applies to the final candidate delta.

## Example canonical JSON

The two CDN endpoints below must forward their respective paths into the same
XHTTP server/session namespace. Hosts, paths, credentials and padding must be
replaced with the operator's settings.

```json
{
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{
      "address": "upload.example.com", "port": 443,
      "users": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none"}]
    }]},
    "streamSettings": {
      "network": "xhttp", "security": "tls",
      "tlsSettings": {"serverName": "upload.example.com", "alpn": ["h2"]},
      "xhttpSettings": {
        "path": "/upload/", "mode": "packet-up",
        "downloadSettings": {
          "address": "download.example.com", "port": 443,
          "network": "xhttp", "security": "tls",
          "tlsSettings": {"serverName": "download.example.com", "alpn": ["h3"]},
          "xhttpSettings": {"path": "/download/"}
        }
      }
    }
  }]
}
```
