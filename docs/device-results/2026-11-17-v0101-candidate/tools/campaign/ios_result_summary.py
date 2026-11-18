#!/usr/bin/env python3
"""Prints a short summary of an iOS probe result.json: events per protocol, failures, outcome."""
import collections, json, sys
rows = json.load(open(sys.argv[1]))
by = collections.defaultdict(collections.Counter)
fails = []
for r in rows:
    by[r.get("protocol", "?")][r.get("event")] += 1
    if r.get("event") in ("failure", "transition-failed", "case-fail") or r.get("result") == "failed":
        fails.append({k: v for k, v in r.items() if k != "time"})
for p, c in by.items():
    print(p, dict(c))
print("last:", {k: v for k, v in rows[-1].items() if k != "time"})
for f in fails[:10]:
    print("FAIL:", f)
