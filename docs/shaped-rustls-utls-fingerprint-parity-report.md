# shaped-rustls uTLS Fingerprint Parity Report

This report compares every fingerprint in `xray_utls::XRAY_UTLS_FINGERPRINTS` against the Go uTLS oracle used by xray-core-compatible REALITY tests.

## What a `match` here does and does not mean

Every row below compares normalised shape JSON, in which an extension is a type and a length. Anything wrong *inside* a body of the right length is a `match` here. ECH is the worked example: this report recorded `encrypted_client_hello_length: 186` and called it parity while the body underneath declared a zero-length `enc`, carried no X25519 key, and padded the remaining 176 bytes with zeroes -- a structure no ECH parser accepts and a DPI can pick out deterministically. It shipped that way from before v0.1.1.

Byte-level agreement is a separate guard, and the one to reach for when a body's contents matter: `rustls_reality_provider_raw_clienthello_matches_utls_oracle_for_risky_fingerprints` compares whole ClientHellos against committed oracle output, masking only what uTLS redraws per connection, and runs in the ordinary `cargo test --workspace` CI job.

## Reproduce

```sh
XRAY_UTLS_REPORT_MD=docs/shaped-rustls-utls-fingerprint-parity-report.md cargo test -p xray-transport --test reality_rustls_tests rustls_reality_provider_reports_utls_xray_fingerprint_parity -- --ignored --nocapture
```

## Summary

- Total fingerprints: `58`
- Matches: `42`
- Mismatches: `0`
- Not REALITY-capable fingerprints: `14`
- Drawn per process (no fixed shape to compare): `2`
- Go uTLS oracle errors: `0`
- Rust generation errors: `0`

## Agent Task

- Work in the shaped-rustls fork, currently expected at `aimalygin/shaped-rustls` branch `xray/rustls-0.23.40`.
- Use this report as the current wire-parity oracle after applying xray-rust's deliberate provider-capability cipher filter to the uTLS expectation. Every other tracked field remains the shaped-rustls byte-shape oracle: advertised versions/groups, real key shares, exact extension payloads, duplicate signature algorithms, ALPS, ECH, and GREASE.
- Treat this as the regression oracle for shaped-rustls ClientHello shaping. All REALITY-capable rows should remain `match`; the TLS1.2-only rows should remain `not-reality-capable` in xray-rust.
- This is a byte-shape oracle only. It does not prove key-share cryptographic validity or REALITY prepare/complete ClientHello reproducibility; those must stay covered by dedicated runtime invariants.
- Acceptance criterion: rerun the reproduce command from this report and get all REALITY-capable provider-filtered fingerprints as `match`, `0` mismatches, `0` Go uTLS oracle errors, `0` Rust generation errors, and keep the known TLS1.2-only rows as `not-reality-capable`.

## Current Findings

- shaped-rustls now represents GREASE extension positions relative to the final non-GREASE extension order, including slots before padding and after the final real extension. xray-rust passes those positions through without the old workaround that compensated for previously inserted GREASE entries.
- All REALITY-capable xray-core/uTLS fingerprints currently match the provider-filtered Go uTLS byte-shape fields tracked by this report.
- xray-rust uses real rustls key shares for X25519, P-256, P-384, final `X25519MLKEM768`, and draft `X25519Kyber768Draft00`. `FixedX25519KeyShare` keeps REALITY's X25519 public key stable inside X25519 and both hybrid shares.
- Runtime REALITY completion uses shaped-rustls' ClientHello finalizer to seal the actual generated ClientHello before transcript/write. Dedicated tests assert nonzero final `X25519MLKEM768` ML-KEM material and finalizer-derived auth/session state; this report remains the byte-shape oracle.
- The `not-reality-capable` rows are TLS1.2-only uTLS fingerprints with no X25519-compatible key_share extension. That is not a shaped-rustls primitive gap: REALITY cannot derive the server-side shared secret without a ClientHello X25519 public key. xray-rust intentionally rejects these before ClientHello generation.
- If xray-rust decides to expose non-REALITY uTLS shaping later, those TLS1.2-only profiles should be tested outside the REALITY provider path.

## Per-Fingerprint Results

| # | fingerprint | uTLS ID | status | first actionable difference |
|---:|---|---|---|---|
| 1 | `chrome` | `Chrome-133` | `match` | `none` |
| 2 | `firefox` | `Firefox-148` | `match` | `none` |
| 3 | `safari` | `Safari-26.3` | `match` | `none` |
| 4 | `ios` | `iOS-14` | `match` | `none` |
| 5 | `android` | `Android-11` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 6 | `edge` | `Edge-85` | `match` | `none` |
| 7 | `360` | `360Browser-7.5` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 8 | `qq` | `QQBrowser-11.1` | `match` | `none` |
| 9 | `random` | `Randomized-0` | `drawn-per-process` | `skipped: resolved from a per-process draw over Xray's ModernFingerprints, so it has no fixed shape to compare` |
| 10 | `randomized` | `Randomized-0` | `drawn-per-process` | `skipped: resolved from a per-process draw over Xray's ModernFingerprints, so it has no fixed shape to compare` |
| 11 | `randomizednoalpn` | `Randomized-NoALPN-0` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 12 | `hellofirefox_120` | `Firefox-120` | `match` | `none` |
| 13 | `hellochrome_120` | `Chrome-120` | `match` | `none` |
| 14 | `hellochrome_131` | `Chrome-131` | `match` | `none` |
| 15 | `helloios_13` | `iOS-13` | `match` | `none` |
| 16 | `helloios_14` | `iOS-14` | `match` | `none` |
| 17 | `helloedge_106` | `Edge-106` | `match` | `none` |
| 18 | `hello360_11_0` | `360Browser-11.0` | `match` | `none` |
| 19 | `helloqq_11_1` | `QQBrowser-11.1` | `match` | `none` |
| 20 | `hellorandomized` | `Randomized-0` | `match` | `none` |
| 21 | `hellorandomizedalpn` | `Randomized-ALPN-0` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 22 | `hellorandomizednoalpn` | `Randomized-NoALPN-0` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 23 | `hellofirefox_auto` | `Firefox-148` | `match` | `none` |
| 24 | `hellofirefox_55` | `Firefox-55` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 25 | `hellofirefox_56` | `Firefox-56` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 26 | `hellofirefox_63` | `Firefox-63` | `match` | `none` |
| 27 | `hellofirefox_65` | `Firefox-65` | `match` | `none` |
| 28 | `hellofirefox_99` | `Firefox-99` | `match` | `none` |
| 29 | `hellofirefox_102` | `Firefox-102` | `match` | `none` |
| 30 | `hellofirefox_105` | `Firefox-105` | `match` | `none` |
| 31 | `hellochrome_auto` | `Chrome-133` | `match` | `none` |
| 32 | `hellochrome_58` | `Chrome-58` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 33 | `hellochrome_62` | `Chrome-62` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 34 | `hellochrome_70` | `Chrome-70` | `match` | `none` |
| 35 | `hellochrome_72` | `Chrome-72` | `match` | `none` |
| 36 | `hellochrome_83` | `Chrome-83` | `match` | `none` |
| 37 | `hellochrome_87` | `Chrome-87` | `match` | `none` |
| 38 | `hellochrome_96` | `Chrome-96` | `match` | `none` |
| 39 | `hellochrome_100` | `Chrome-100` | `match` | `none` |
| 40 | `hellochrome_102` | `Chrome-102` | `match` | `none` |
| 41 | `hellochrome_106_shuffle` | `Chrome-106` | `match` | `none` |
| 42 | `helloios_auto` | `iOS-14` | `match` | `none` |
| 43 | `helloios_11_1` | `iOS-111` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 44 | `helloios_12_1` | `iOS-12.1` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 45 | `helloandroid_11_okhttp` | `Android-11` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 46 | `helloedge_85` | `Edge-85` | `match` | `none` |
| 47 | `helloedge_auto` | `Edge-85` | `match` | `none` |
| 48 | `hellosafari_16_0` | `Safari-16.0` | `match` | `none` |
| 49 | `hellosafari_auto` | `Safari-26.3` | `match` | `none` |
| 50 | `hello360_auto` | `360Browser-7.5` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 51 | `hello360_7_5` | `360Browser-7.5` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 52 | `helloqq_auto` | `QQBrowser-11.1` | `match` | `none` |
| 53 | `hellochrome_100_psk` | `Chrome-100_PSK` | `match` | `none` |
| 54 | `hellochrome_112_psk_shuf` | `Chrome-112_PSK` | `match` | `none` |
| 55 | `hellochrome_114_padding_psk_shuf` | `Chrome-114_PSK` | `match` | `none` |
| 56 | `hellochrome_115_pq` | `Chrome-115_PQ` | `match` | `none` |
| 57 | `hellochrome_115_pq_psk` | `Chrome-115_PQ_PSK` | `match` | `none` |
| 58 | `hellochrome_120_pq` | `Chrome-120_PQ` | `match` | `none` |

## Detailed Non-Match Rows

### 1. `android`

- Status: `not-reality-capable`
- uTLS ID: `Android-11`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 2. `360`

- Status: `not-reality-capable`
- uTLS ID: `360Browser-7.5`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 3. `random`

- Status: `drawn-per-process`
- uTLS ID: `Randomized-0`
- First actionable difference: `skipped: resolved from a per-process draw over Xray's ModernFingerprints, so it has no fixed shape to compare`

Per-process draw skip:

```text
skipped: resolved from a per-process draw over Xray's ModernFingerprints, so it has no fixed shape to compare
```

### 4. `randomized`

- Status: `drawn-per-process`
- uTLS ID: `Randomized-0`
- First actionable difference: `skipped: resolved from a per-process draw over Xray's ModernFingerprints, so it has no fixed shape to compare`

Per-process draw skip:

```text
skipped: resolved from a per-process draw over Xray's ModernFingerprints, so it has no fixed shape to compare
```

### 5. `randomizednoalpn`

- Status: `not-reality-capable`
- uTLS ID: `Randomized-NoALPN-0`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 6. `hellorandomizedalpn`

- Status: `not-reality-capable`
- uTLS ID: `Randomized-ALPN-0`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 7. `hellorandomizednoalpn`

- Status: `not-reality-capable`
- uTLS ID: `Randomized-NoALPN-0`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 8. `hellofirefox_55`

- Status: `not-reality-capable`
- uTLS ID: `Firefox-55`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 9. `hellofirefox_56`

- Status: `not-reality-capable`
- uTLS ID: `Firefox-56`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 10. `hellochrome_58`

- Status: `not-reality-capable`
- uTLS ID: `Chrome-58`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 11. `hellochrome_62`

- Status: `not-reality-capable`
- uTLS ID: `Chrome-62`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 12. `helloios_11_1`

- Status: `not-reality-capable`
- uTLS ID: `iOS-111`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 13. `helloios_12_1`

- Status: `not-reality-capable`
- uTLS ID: `iOS-12.1`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 14. `helloandroid_11_okhttp`

- Status: `not-reality-capable`
- uTLS ID: `Android-11`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 15. `hello360_auto`

- Status: `not-reality-capable`
- uTLS ID: `360Browser-7.5`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 16. `hello360_7_5`

- Status: `not-reality-capable`
- uTLS ID: `360Browser-7.5`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```
