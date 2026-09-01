#!/usr/bin/env python3
"""Append a non-secret physical action marker to an active Apple campaign."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re


SCENARIO_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=pathlib.Path)
    parser.add_argument("scenario_id")
    parser.add_argument("--phase", choices=("begin", "passed", "failed", "note"), required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--notes", required=True)
    args = parser.parse_args()

    if not SCENARIO_ID.fullmatch(args.scenario_id):
        parser.error("scenario_id has invalid characters")
    if args.attempt < 1:
        parser.error("--attempt must be positive")
    if (
        not args.notes
        or len(args.notes) > 512
        or any(ord(character) < 0x20 for character in args.notes)
    ):
        parser.error("--notes must be 1..512 printable characters")

    state_path = args.campaign_dir / ".apple-campaign-state.json"
    timeline_path = args.campaign_dir / "transition-timeline.jsonl"
    if state_path.is_symlink() or not state_path.is_file():
        parser.error("campaign is not active")
    if timeline_path.is_symlink() or not timeline_path.is_file():
        parser.error("transition timeline is unavailable")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    started_at = dt.datetime.fromisoformat(state["startedAt"].replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    event = {
        "at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "attempt": args.attempt,
        "elapsedSeconds": max(0, int((now - started_at).total_seconds())),
        "event": "scenario",
        "notes": args.notes,
        "phase": args.phase,
        "scenarioId": args.scenario_id,
    }
    descriptor = os.open(
        timeline_path,
        os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        payload = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(
        f"marked {args.scenario_id} attempt={args.attempt} phase={args.phase} "
        f"elapsed={event['elapsedSeconds']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
