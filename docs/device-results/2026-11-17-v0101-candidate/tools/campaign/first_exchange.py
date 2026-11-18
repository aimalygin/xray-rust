#!/usr/bin/env python3
"""Counts, in iOS probe result.json files, tunnel starts and their first exchange: for every
`connected` event, the next tcp/udp/dns-anchor/failure event of the same protocol. "Slow" = 2 s or
more after the connect (timestamps have one-second resolution). The coordinator's measure, 2026-11-15.
usage: first_exchange.py <result.json>...
"""
import datetime, json, sys

def t(row):
    return datetime.datetime.fromisoformat(row["time"].replace("Z", "+00:00")).timestamp()

for path in sys.argv[1:]:
    rows = json.load(open(path))
    starts = failed = slow = 0
    for i, row in enumerate(rows):
        if row.get("event") != "connected":
            continue
        starts += 1
        for nxt in rows[i + 1:]:
            if nxt.get("protocol") == row.get("protocol") and nxt.get("event") in ("tcp", "udp", "dns-anchor", "failure"):
                if nxt["event"] == "failure" or nxt.get("result") == "failed":
                    failed += 1
                elif t(nxt) - t(row) >= 2:
                    slow += 1
                break
    print(f"{path}: starts={starts} first-failed={failed} first-slow={slow}")
