# uTLS Fidelity Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three divergences from Xray-core that the plain-TLS shaping work left behind, and tell users what changed.

**Architecture:** Two of the three are the same defect in different places — we froze something Xray varies per install, so our whole user base shares one signature where Xray's spreads across many. The third is a changelog entry for behavior that is now on by default.

**Tech Stack:** Rust 2021, the existing `xray-utls` and `xray-transport` crates.

**Origin:** raised during execution of `docs/superpowers/plans/2026-08-06-plain-tls-utls-shaping.md` and deferred there rather than silently absorbed.

---

### Task 1: Make `random` and `randomized` actually random

**This is the highest-value item in this plan.** Someone who selects `fingerprint: "random"` is asking not to be identifiable. Today they get the opposite.

Xray-core, at `Xray-core/transport/internet/tls/tls.go:161`, seeds this per process:

```go
func init() {
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ModernFingerprints))))
	// ... picks one of ModernFingerprints as PresetFingerprints["random"]
	randomized := utls.HelloRandomizedALPN
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	// ... same for randomizednoalpn
}
```

So `random` resolves to a different real fingerprint on every Xray install, and `randomized`/`randomizednoalpn` generate a genuinely novel ClientHello shape from a fresh PRNG seed.

Ours, at `crates/xray-transport/src/utls_profiles.rs`, maps all of them to two frozen snapshots:

```
"random"               => PROFILE_8
"randomized"           => PROFILE_8
"hellorandomized"      => PROFILE_8
"randomizednoalpn"     => PROFILE_9
"hellorandomizednoalpn"=> PROFILE_9
```

Every xray-rust user who picks `random` therefore sends **the same** hello — a stable signature shared across our entire user base, and one distinguishable from the Xray population precisely because it does not vary.

**Files:**
- Modify: `crates/xray-transport/src/utls_profiles.rs` or a new sibling module
- Modify: `crates/xray-transport/src/utls_tls.rs` (`shaping_profile`)
- Test: `crates/xray-transport/tests/utls_tls_shaping_tests.rs`

**Scope note — this task is deliberately specified as an investigation plus a fix, because the right shape is not obvious.** `random` is straightforward: pick one of the profiles corresponding to Xray's `ModernFingerprints` set at process start, with a cryptographic RNG, and resolve the name to it for the process's lifetime. `randomized` is harder: uTLS generates a novel spec from a PRNG seed and a weight table, which we have no port of. Two candidate answers, and the implementer should recommend one with reasoning rather than pick silently:

1. Treat `randomized` as an alias for `random` — a real fingerprint drawn per process rather than a synthesized one. Honest, cheap, and strictly better than today. Diverges from Xray in kind, not just in value.
2. Port uTLS's randomized-spec generator. Faithful, and a substantial piece of work with its own oracle requirement.

Whichever is chosen must be documented in `docs/config-compatibility.md` — a user picking `randomized` deserves to know which of the two they are getting.

**Acceptance criteria:**
- Two processes started separately resolve `random` to different profiles, with high probability. Test this by exposing the selection function and calling it many times with fresh state, not by spawning processes.
- Within one process the selection is stable: two connections must not disagree, since a client whose fingerprint changes between connections is more distinguishable than one that never changes.
- Every named non-random fingerprint still resolves exactly as before. Verify by dumping the emitted shape for all 61 names before and after and diffing — the method used throughout the shaping plan.
- The REALITY path is unaffected. `normalize_reality_supported_fingerprint` already gates which names REALITY accepts; confirm the random names' behavior there is unchanged.

---

### Task 2: Draw the browser version per install

Xray derives the Chrome major version from the date **minus a random offset seeded from the host CPU's identity** (`Xray-core/common/utils/browser.go`, `ChromeVersion()`). Measured on 2026-08-07 across 25 600 synthetic CPU identities: 148 for 55% of machines, 147 for 25%, 146 for 19%, 145 for 1%.

Our port (`crates/xray-transport/src/stream/masquerade.rs`, added by the ws/httpupgrade work) reproduces Xray's date formulas exactly but pins the random term to **zero** — the single most likely draw, never older than an Xray client and at most three versions newer, and it moves with the calendar so nothing freezes.

That was a sound call for a first cut, and it leaves one thing open: every xray-rust install reports the same version where Xray installs spread across four. In aggregate that is distinguishable. The implementer of that task noted the fix is one function.

**Files:**
- Modify: `crates/xray-transport/src/stream/masquerade.rs` (`BrowserVersions::at`)
- Test: `crates/xray-transport/tests/stream_http_headers_tests.rs`

**Acceptance criteria:**
- The version is drawn once per process, from a cryptographic RNG, over the same distribution Xray's formula produces — not necessarily by porting Go's `math/rand`, which would buy nothing, but matching the shape of the distribution.
- It is **stable within a process**. A UA that changes between connections from one client is worse than a fixed one.
- The existing oracle tests keep passing. They already replay a recorded version through `apply_masquerade_with_versions`, so they are insulated from the default — confirm that rather than assume it.
- Firefox and Safari get the same treatment; their versions are derived the same way.

---

### Task 3: Write the changelog entry

`CHANGELOG.md` has an empty `## Unreleased` section and no commit on this branch has touched it. Three changes from the shaping work are user-visible and none is currently announced.

**Files:**
- Modify: `CHANGELOG.md`

**What must be said, in the file's existing voice:**

- **TLS connections are now shaped by default.** `tlsSettings.fingerprint` selects a uTLS ClientHello shape and an absent value means `chrome`, matching Xray. `unsafe` disables shaping.
- **Shaped connections use a different crypto backend and offer a post-quantum key share.** aws-lc-rs rather than ring, with an X25519MLKEM768 key share, because that is what matching Chrome requires. `fingerprint: "unsafe"` keeps the previous ring path.
- **Session resumption is disabled on shaped connections.** A resumed handshake would emit a second ClientHello carrying `pre_shared_key`, an extension the fingerprint never described. Every reconnect is now a full handshake where it previously resumed — a real cost, stated plainly rather than buried.

Also worth a line: fourteen of the sixty-one fingerprint names are shaped but **not** byte-exact, because rustls emits a `supported_versions` extension uTLS does not and nothing in the shaping API can suppress it. `docs/config-compatibility.md` already carries the detail; the changelog should point at it rather than repeat it.

---

## Verification

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```
