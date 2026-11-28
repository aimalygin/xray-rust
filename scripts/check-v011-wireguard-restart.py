#!/usr/bin/env python3
"""Did the WireGuard idle case's device close and start again?

Reads the relay log the fixture keeps for ``--protocol wireguard-idle``
(``wireguard-sources.jsonl``: a time, an event and a client source address
per line, never a payload). A WireGuard device that was closed and started
again sends from a new socket, so the restart shows as a handshake
initiation, after the idle time began, from a source address the relay had
not seen before it. A device kept open keeps its source; a handshake from it
proves nothing about the idle close.

    check-v011-wireguard-restart.py <wireguard-sources.jsonl> <since>

``since`` is when the idle time began, as Unix seconds or an ISO 8601 time
(the Apple probe's ``idle-start`` row). Exit status 0 means a fresh device.
"""
from datetime import datetime
import json
from pathlib import Path
import sys

MAX_LOG_BYTES = 16 * 1024 * 1024


def read(path):
    path = Path(path)
    if path.stat().st_size > MAX_LOG_BYTES:
        raise ValueError("the relay log exceeds 16 MiB")
    rows = []
    for line in path.read_text().splitlines():
        row = json.loads(line)
        if not (isinstance(row, dict) and isinstance(row.get("time"), (int, float))
                and row.get("event") in ("new-source", "handshake-initiation")
                and isinstance(row.get("source"), str)):
            raise ValueError("a relay log row is malformed")
        rows.append(row)
    return rows


def since_seconds(value):
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def fresh_handshake(rows, since):
    before = {row["source"] for row in rows if row["time"] < since}
    after = [row for row in rows if row["time"] >= since and row["event"] == "handshake-initiation"]
    fresh = sorted({row["source"] for row in after} - before)
    return {"fresh": bool(fresh), "sourcesBefore": len(before), "handshakesAfter": len(after),
            "newSources": len(fresh)}


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print(f"usage: {sys.argv[0]} <wireguard-sources.jsonl> <since>", file=sys.stderr)
        return 2
    try:
        verdict = fresh_handshake(read(sys.argv[1]), since_seconds(sys.argv[2]))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(verdict))
    return 0 if verdict["fresh"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
