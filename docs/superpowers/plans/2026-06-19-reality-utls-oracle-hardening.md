# REALITY uTLS Oracle Hardening Plan

## Goal

Strengthen the xray-rust Go/uTLS oracle tests so byte-level ClientHello drift is caught, not only high-level shape drift. Keep `hello360_11_0` explicitly covered because it is a known suspicious fingerprint.

## Scope

- Add a Go oracle output mode that returns deterministic raw uTLS ClientHello bytes without changing the existing shape fixture behavior.
- Add Rust test helpers that parse raw ClientHello boundaries and mask only expected dynamic regions:
  - ClientHello random
  - legacy session id
  - key share public key bytes
  - ECH GREASE payload bytes
  - padding bytes when payload content is intentionally synthetic
- Add ignored Go/uTLS oracle tests that compare masked raw bytes for representative risky fingerprints, including `chrome`, `helloios_13`, `hellochrome_120_pq`, and `hello360_11_0`.
- Add a second ignored comparison that seals the Rust REALITY ClientHello with `prepare_reality_handshake` and verifies the final wire bytes still match uTLS after masking only legitimate dynamic fields.
- Keep full-fingerprint shape parity report as the broad coverage layer, and use raw-byte tests as the deeper regression layer.
- Extend the existing ignored local Xray-core interop harness so it can run a real VLESS + REALITY + Vision path for selected fingerprints, including `hello360_11_0`.

## Verification

- First run the new focused test before implementing the Go raw oracle and observe failure.
- Run:
  - `cargo test -p xray-transport --test reality_rustls_tests rustls_reality_provider_raw_clienthello_matches_utls_oracle_for_risky_fingerprints -- --ignored --nocapture`
  - `cargo test -p xray-transport --test reality_rustls_tests rustls_reality_provider_final_reality_clienthello_matches_utls_oracle_for_risky_fingerprints -- --ignored --nocapture`
  - `cargo test -p xray-transport --test reality_rustls_tests -- --ignored --nocapture`
  - `cargo test -p xray-transport`
- Compile-check the live interop harness with `cargo test -p xray-core-rs --test local_xray_interop_tests`.
- When a local Xray-core checkout is available, run:
  - `XRAY_CORE_CHECKOUT=/path/to/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision_selected_fingerprints -- --ignored --nocapture`
