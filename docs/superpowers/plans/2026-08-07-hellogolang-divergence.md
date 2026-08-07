# `hellogolang` Divergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decide and record what `tlsSettings.fingerprint: "hellogolang"` should do here. Today it is rejected at parse time, and it is the one fingerprint name that parses on xray-core and fails on us.

**Architecture:** This is not a missing browser profile. In uTLS, `HelloGolang` means *emit Go's own `crypto/tls` ClientHello and apply no shaping*, which is the same intent our `unsafe` already serves through a different TLS stack. So the question is not "port a shape" but "which existing behavior should this name map to, if any".

**Tech Stack:** Rust 2021, the existing `xray-utls` crate.

**Origin:** raised while landing `190ebda` (`fix(config): reject uTLS fingerprints xray-core never mapped`), which tightened the accepted set to Xray's 58 names on the argument that a name parsing here and failing on xray-core is a break the user only discovers after moving the profile. `hellogolang` is that same break mirrored, and the commit did not address it.

---

### Task 1: Decide what `hellogolang` maps to

**Verified against Xray-core v26.5.9 and uTLS `v1.8.3-0.20260301010127-aa6edf4b11af`, both pinned in `Xray-core/` in this repo.**

What the name means in uTLS, at `u_common.go:589`:

```go
// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
// overwrite your changes to Hello(Config, Session are fine).
// You might want to call BuildHandshakeState() before applying any changes.
// UConn.Extensions will be completely ignored.
HelloGolang = ClientHelloID{helloGolang, helloAutoVers, nil, nil}
```

So it is the *absence* of shaping, spelled as a fingerprint name.

Where Xray accepts it:

- `transport/internet/tls/tls.go:242` puts `"hellogolang": &utls.HelloGolang` in `OtherFingerprints`, one of the three maps `GetFingerprint` consults.
- **Plain TLS accepts it.** `infra/conf/transport_internet.go:699-701` rejects only names `GetFingerprint` cannot resolve, letting `unsafe` through by an explicit `!=` guard. `hellogolang` resolves, so it is accepted.
- **REALITY rejects it,** and rejects it *together with* `unsafe`, at `infra/conf/transport_internet.go:924-926`:

  ```go
  if config.Fingerprint == "unsafe" || config.Fingerprint == "hellogolang" {
      return nil, errors.New(`invalid "fingerprint": `, config.Fingerprint)
  }
  ```

  That line is the only place in Xray's config builder where the two names appear together, and it is good evidence Xray itself treats them as one category: names that are not a real fingerprint.

Where we stand: `XRAY_UTLS_FINGERPRINTS` in `crates/xray-utls/src/lib.rs` excludes it, and `normalize_utls_fingerprint_rejects_names_xray_never_mapped` asserts the rejection. So a config carrying `tlsSettings.fingerprint: "hellogolang"` runs on xray-core and fails to parse here. The divergence is confined to plain TLS; on the REALITY path we and Xray agree.

**Files:**
- Modify: `crates/xray-utls/src/lib.rs`
- Modify: `docs/config-compatibility.md`
- Modify: `CHANGELOG.md`, if the decision changes what a config does
- Test: `crates/xray-utls/src/lib.rs` unit tests, `crates/xray-config/tests/parser_tests.rs`

**Three candidate answers. The implementer should pick one with reasoning rather than silently:**

1. **Accept it as an alias for `unsafe`.** One name mapping, plus documentation. The config becomes portable and the user's intent — an unshaped hello — is honored. The bytes differ from Xray's, because ours is rustls's native hello where Xray's is Go's, but that difference is inherent to not being a Go program and is already true of `unsafe`. Xray grouping the two names on a single rejection line supports reading them as equivalent.
2. **Port Go's `crypto/tls` ClientHello as a real profile.** Faithful to the byte, and it needs its own oracle and fixtures. The value is doubtful: the shape identifies the peer as a Go program, which is the opposite of what shaping is for, and nothing else about our stack backs up that claim.
3. **Keep rejecting, and leave this document as the record.** Defensible — the name asks for something we structurally cannot be — but it leaves a real config breaking on import with no migration note.

**Recommendation:** option 1. It closes a portability break for the cost of one mapping, and option 2 buys fidelity that no user benefits from. Whichever is chosen, `docs/config-compatibility.md` must say plainly which of the three shipped, because a user picking `hellogolang` deserves to know whether they got Go's hello, rustls's, or an error.

**Acceptance criteria:**
- The decision is stated in `docs/config-compatibility.md` in the file's existing voice, including what actually goes on the wire.
- If the name becomes accepted, `XRAY_UTLS_FINGERPRINTS` still matches Xray's accepted set exactly — the count in the doc and in the parity report moves together with it, and `normalize_utls_fingerprint_rejects_names_xray_never_mapped` is updated rather than deleted.
- The REALITY path is unchanged: `hellogolang` stays rejected there, matching `transport_internet.go:924-926`.
- If the name becomes accepted, `CHANGELOG.md` says so — it is a config that used to fail and now parses.

---

## Verification

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```
