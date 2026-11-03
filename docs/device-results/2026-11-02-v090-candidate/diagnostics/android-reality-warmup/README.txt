Diagnosis of the legacy-v09 vless-reality first-case failure (2026-11-02).
Symptom: first HTTP probe (ipv4) times out at 5 s; fixture log shows the first
REALITY flows arrive 4-5 s after the probe starts. UDP passes.
- diag-reality-1..3: candidate .v09, fresh fixture, no wait: 3/3 fail.
- diag-reality-v081-1..2: 0.8.1 harness .v081, same fixture type: 1 pass, 1 fail.
- diag-reality-probeonly-1..3: candidate, probe-only VPN (no background apps): 3/3 fail.
- Mac -> www.google.com fast over IPv4/IPv6; Go pure resolver/dial fast (ruled out).
- diag-reality-warm-1..3: candidate, 10 s wait after fixture ready: 3/3 pass.
Cause: REALITY fixture warm-up (first decoy handshake), which the host preflight
already waits 8 s for. Runner change: WARMUP_SECONDS=10 before the matrix.
