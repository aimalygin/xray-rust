# shaped-rustls uTLS Fingerprint Parity Report

This report compares every fingerprint in `xray_utls::XRAY_REALITY_FINGERPRINTS` against the Go uTLS oracle used by xray-core-compatible REALITY tests.

## Reproduce

```sh
XRAY_UTLS_REPORT_MD=docs/shaped-rustls-utls-fingerprint-parity-report.md cargo test -p xray-transport --test reality_rustls_tests rustls_reality_provider_reports_utls_xray_fingerprint_parity -- --ignored --nocapture
```

## Summary

- Total fingerprints: `61`
- Matches: `47`
- Mismatches: `0`
- Not REALITY-capable fingerprints: `14`
- Go uTLS oracle errors: `0`
- Rust generation errors: `0`

## Agent Task

- Work in the shaped-rustls fork, currently expected at `aimalygin/shaped-rustls` branch `xray/rustls-0.23.40`.
- Use this report as the current wire-parity oracle after xray-rust adopted the shaped-rustls primitives for advertised cipher suites, advertised versions/groups, raw key shares, exact extension payloads, duplicate signature algorithms, ALPS, ECH, and GREASE.
- Treat this as the regression oracle for shaped-rustls ClientHello shaping. All REALITY-capable rows should remain `match`; the TLS1.2-only rows should remain `not-reality-capable` in xray-rust.
- Acceptance criterion: rerun the reproduce command from this report and get all REALITY-capable fingerprints as `match`, `0` mismatches, `0` Go uTLS oracle errors, `0` Rust generation errors, and keep the known TLS1.2-only rows as `not-reality-capable`.

## Current Findings

- shaped-rustls now represents GREASE extension positions relative to the final non-GREASE extension order, including slots before padding and after the final real extension. xray-rust passes those positions through without the old workaround that compensated for previously inserted GREASE entries.
- All REALITY-capable xray-core/uTLS fingerprints currently match the Go uTLS oracle byte-shape fields tracked by this report.
- xray-rust now works around multi-share fixed-X25519 limitations by keeping only X25519 as a real rustls key share and advertising P-256/P-384/hybrid shares as raw wire-shape entries. That keeps REALITY's X25519 public key stable while preserving ClientHello shape.
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
| 9 | `random` | `Randomized-0` | `match` | `none` |
| 10 | `randomized` | `Randomized-0` | `match` | `none` |
| 11 | `randomizednoalpn` | `Randomized-NoALPN-0` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 12 | `hellofirefox_120` | `Firefox-120` | `match` | `none` |
| 13 | `hellofirefox_148` | `Firefox-148` | `match` | `none` |
| 14 | `hellochrome_120` | `Chrome-120` | `match` | `none` |
| 15 | `hellochrome_131` | `Chrome-131` | `match` | `none` |
| 16 | `hellochrome_133` | `Chrome-133` | `match` | `none` |
| 17 | `helloios_13` | `iOS-13` | `match` | `none` |
| 18 | `helloios_14` | `iOS-14` | `match` | `none` |
| 19 | `helloedge_106` | `Edge-106` | `match` | `none` |
| 20 | `hellosafari_26_3` | `Safari-26.3` | `match` | `none` |
| 21 | `hello360_11_0` | `360Browser-11.0` | `match` | `none` |
| 22 | `helloqq_11_1` | `QQBrowser-11.1` | `match` | `none` |
| 23 | `hellorandomized` | `Randomized-0` | `match` | `none` |
| 24 | `hellorandomizedalpn` | `Randomized-ALPN-0` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 25 | `hellorandomizednoalpn` | `Randomized-NoALPN-0` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 26 | `hellofirefox_auto` | `Firefox-148` | `match` | `none` |
| 27 | `hellofirefox_55` | `Firefox-55` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 28 | `hellofirefox_56` | `Firefox-56` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 29 | `hellofirefox_63` | `Firefox-63` | `match` | `none` |
| 30 | `hellofirefox_65` | `Firefox-65` | `match` | `none` |
| 31 | `hellofirefox_99` | `Firefox-99` | `match` | `none` |
| 32 | `hellofirefox_102` | `Firefox-102` | `match` | `none` |
| 33 | `hellofirefox_105` | `Firefox-105` | `match` | `none` |
| 34 | `hellochrome_auto` | `Chrome-133` | `match` | `none` |
| 35 | `hellochrome_58` | `Chrome-58` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 36 | `hellochrome_62` | `Chrome-62` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 37 | `hellochrome_70` | `Chrome-70` | `match` | `none` |
| 38 | `hellochrome_72` | `Chrome-72` | `match` | `none` |
| 39 | `hellochrome_83` | `Chrome-83` | `match` | `none` |
| 40 | `hellochrome_87` | `Chrome-87` | `match` | `none` |
| 41 | `hellochrome_96` | `Chrome-96` | `match` | `none` |
| 42 | `hellochrome_100` | `Chrome-100` | `match` | `none` |
| 43 | `hellochrome_102` | `Chrome-102` | `match` | `none` |
| 44 | `hellochrome_106_shuffle` | `Chrome-106` | `match` | `none` |
| 45 | `helloios_auto` | `iOS-14` | `match` | `none` |
| 46 | `helloios_11_1` | `iOS-111` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 47 | `helloios_12_1` | `iOS-12.1` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 48 | `helloandroid_11_okhttp` | `Android-11` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 49 | `helloedge_85` | `Edge-85` | `match` | `none` |
| 50 | `helloedge_auto` | `Edge-85` | `match` | `none` |
| 51 | `hellosafari_16_0` | `Safari-16.0` | `match` | `none` |
| 52 | `hellosafari_auto` | `Safari-26.3` | `match` | `none` |
| 53 | `hello360_auto` | `360Browser-7.5` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 54 | `hello360_7_5` | `360Browser-7.5` | `not-reality-capable` | `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share` |
| 55 | `helloqq_auto` | `QQBrowser-11.1` | `match` | `none` |
| 56 | `hellochrome_100_psk` | `Chrome-100_PSK` | `match` | `none` |
| 57 | `hellochrome_112_psk_shuf` | `Chrome-112_PSK` | `match` | `none` |
| 58 | `hellochrome_114_padding_psk_shuf` | `Chrome-114_PSK` | `match` | `none` |
| 59 | `hellochrome_115_pq` | `Chrome-115_PQ` | `match` | `none` |
| 60 | `hellochrome_115_pq_psk` | `Chrome-115_PQ_PSK` | `match` | `none` |
| 61 | `hellochrome_120_pq` | `Chrome-120_PQ` | `match` | `none` |

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

### 3. `randomizednoalpn`

- Status: `not-reality-capable`
- uTLS ID: `Randomized-NoALPN-0`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 4. `hellorandomizedalpn`

- Status: `not-reality-capable`
- uTLS ID: `Randomized-ALPN-0`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 5. `hellorandomizednoalpn`

- Status: `not-reality-capable`
- uTLS ID: `Randomized-NoALPN-0`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 6. `hellofirefox_55`

- Status: `not-reality-capable`
- uTLS ID: `Firefox-55`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 7. `hellofirefox_56`

- Status: `not-reality-capable`
- uTLS ID: `Firefox-56`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 8. `hellochrome_58`

- Status: `not-reality-capable`
- uTLS ID: `Chrome-58`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 9. `hellochrome_62`

- Status: `not-reality-capable`
- uTLS ID: `Chrome-62`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 10. `helloios_11_1`

- Status: `not-reality-capable`
- uTLS ID: `iOS-111`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 11. `helloios_12_1`

- Status: `not-reality-capable`
- uTLS ID: `iOS-12.1`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 12. `helloandroid_11_okhttp`

- Status: `not-reality-capable`
- uTLS ID: `Android-11`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 13. `hello360_auto`

- Status: `not-reality-capable`
- uTLS ID: `360Browser-7.5`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```

### 14. `hello360_7_5`

- Status: `not-reality-capable`
- uTLS ID: `360Browser-7.5`
- First actionable difference: `skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share`

REALITY capability skip:

```text
skipped: fingerprint is known in xray-core/uTLS but is not REALITY-capable because its ClientHello has no X25519-compatible key_share
```
