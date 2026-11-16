# shaped-rustls at ca91d48c with upstream rustls 0.23.45/0.23.46 security fixes

Source: the `rustls` crate of the ClientHello-shaping fork
[aimalygin/shaped-rustls](https://github.com/aimalygin/shaped-rustls), commit
`ca91d48c385f7d16ad3993ecaf26fa9b84882dbc` (branch `xray/rustls-0.23.40`, based
on rustls 0.23.40), which the workspace used as a git dependency until now.
Archive: `https://codeload.github.com/aimalygin/shaped-rustls/tar.gz/ca91d48c385f7d16ad3993ecaf26fa9b84882dbc`,
SHA-256 `797e1851f8511d2d6d9ddb17006b17c8fe5c1726bb4521437fcbf43d7dfb8467`.

The vendored crate is that archive's `rustls/Cargo.toml`, `rustls/build.rs`
and `rustls/src`, with the fork's `LICENSE`, `LICENSE-APACHE`, `LICENSE-ISC`
and `LICENSE-MIT` (the crate directory only links to them). `XRAY-PATCH.diff`
reconstructs it from those files with zero fuzz.
`scripts/check-vendored-sources.sh` verifies the archive and the exact
reconstruction, then runs the fork's library tests, in the fork's own
workspace and lockfile, against these sources.

## Why it is vendored

A git dependency cannot be patched in place, the fork is not ours to push to
from this repository, and `cargo audit` does not match advisories against a
git source. The fixes below change no ClientHello byte: they act on what the
server sends back, on when a value is stored, and on `Debug` output. The
shaping oracle tests (`utls_tls_shaping_tests`, `reality_rustls_tests`,
`chrome_parrot_tests`) pass unchanged. Configuring a bounded brotli
decompressor from xray-rust instead would leave every `ClientConfig` built
without it, the server side and the other three advisories as they were.

When the fork takes these commits, or is rebased onto rustls 0.23.46 or later,
point `[patch.crates-io] rustls` back at the fork's new revision, delete this
directory and its acknowledgements in `scripts/check-vendored-advisories.sh`.

## Changes

- `Cargo.toml`: the fork's `workspace = true` dependencies take the versions
  and features of the fork's workspace manifest. Dev-dependencies, tests,
  benches, the internal example and the `readme` field are removed: they refer
  to fork workspace files that are not vendored.
- RUSTSEC-2026-0348 (`src/compress.rs`): the brotli certificate decompressor
  uses `BrotliState::new_strict`, which refuses the large-window extension,
  so a five-byte header can no longer make it allocate up to 1 GiB before the
  certificate is authenticated. Chrome-shaped hellos offer brotli, so any
  server, or anyone answering in its place, could trigger it. The zlib and
  brotli decompressors also refuse trailing input. Upstream rustls `1aa987af`
  and `b10cdb0d`, with their tests.
- RUSTSEC-2026-0349 (`src/client/tls13.rs`): the key exchange group the
  server chose is remembered for the next ClientHello's key share only after
  the handshake has authenticated the server, not when the ServerHello
  arrives. Upstream `f04804fa`.
- RUSTSEC-2026-0285 (`src/conn.rs`, `src/msgs/deframer/handshake.rs`): a
  TLS 1.3 handshake message joined to a key-changing message in the same
  record is refused with `unexpected_message`, as RFC 8446 section 5.1
  requires. Upstream `f9d4ee92`; its four regression tests are in the fork's
  `rustls/tests/api.rs`, which is not vendored, and pass against these
  sources in the fork's workspace once the two `rustls-test` helpers from
  upstream `b480cc67` are added there.
- RUSTSEC-2026-0346 (`src/msgs/persist.rs`, `src/client/handy.rs`): `Debug`
  of TLS 1.2 and TLS 1.3 client session values and of `ServerSessionValue`
  no longer prints the master secret or resumption PSK. Upstream `dcdb9464`
  (its unrelated session-cache tests left out) and `6d0ba089`.

RUSTSEC-2026-0347 (application data after an ECH rejection) does not affect
0.23.40: the client checked the certificate against the inner name until
0.23.44, so the handshake failed before any data went out.

The fork's library suite passes against these sources with `ring` (490 tests)
and its `api` suite with the four new tests (432 without `brotli`/`zlib`, 438
with them). With `brotli` and `zlib` enabled, seven ClientHello shaping unit
tests of the fork fail at `ca91d48c` already, with and without these changes:
they expect a hello without `compress_certificate`. In xray-transport,
`chrome_refuses_a_large_window_brotli_certificate` has a server send a
stored-brotli certificate under a standard header, which completes, and under
the large-window header, which must be refused; it fails without the
`compress.rs` change.
