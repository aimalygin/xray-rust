Attempt 1 of the v0.9 protocol performance collector (2026-11-02 23:09 UTC).

Stopped on the first reference run: `reference configuration preparation failed`.
Cause: collector defect. `tools/collect_protocols_v09.py` wrote the launcher
spec `xray-client.json` without `"suite": "v09"`, so
`scripts/v08-reference-client.py` defaulted to the v08 suite and rejected the
SOCKS outbound as an unsupported comparison protocol. The candidate run before it
(socks-auth full-duplex, repeat 1) exited 0. Fixed by adding the suite field;
the full collection was rerun from scratch.
