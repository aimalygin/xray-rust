#!/usr/bin/env python3
"""One line per iOS WAN transitions result.json: start time, stage recoveries (seconds, retries), lock interval,
whether the cellular leg offered IPv4 (system-path supportsIPv4 during the cellular stage), outcome."""
import json, sys
for path in sys.argv[1:]:
    rows = json.load(open(path))
    stage = "wifi-baseline"; v4cell = set(); parts = []
    for r in rows:
        e = r.get("event")
        if e == "action-required": stage = r.get("action")
        if e == "system-path" and stage == "cellular": v4cell.add(r.get("supportsIPv4"))
        if e == "transition-recovered": parts.append(f"{r.get('stage')} {r.get('activeRecoverySeconds', 0):.2f}s r{r.get('retries')}")
        if e == "recovery-retry": parts.append(f"retry@{r.get('stage')}#{r.get('attempt')}")
        if e == "transition-failed": parts.append(f"FAILED@{r.get('stage')}")
        if e == "lock-interval": parts.append(f"lock {r.get('seconds', 0):.1f}s")
    out = next((r.get("result") for r in rows if r.get("event") == "complete"), None)
    print(f"{path}: start {rows[0]['time']} cellular-IPv4={sorted(v4cell, key=str)} | {'; '.join(parts)} | {out}")
