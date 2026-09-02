#!/usr/bin/env python3
"""Append a non-secret physical action marker to an active Apple campaign."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import runpy


SCENARIO_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")


def load_policy(root: pathlib.Path) -> tuple[set[str], set[str], set[str]]:
    policy = runpy.run_path(str(root / "scripts/check-mobile-device-evidence.py"))
    required = policy.get("REQUIRED_SCENARIOS")
    probe_oracles = policy.get("APPLE_PROBE_ORACLE_SCENARIOS")
    outage_oracles = policy.get("APPLE_DUAL_PROBE_OUTAGE_SCENARIOS")
    if (
        not isinstance(required, dict)
        or not isinstance(probe_oracles, set)
        or not isinstance(outage_oracles, set)
        or not outage_oracles.issubset(probe_oracles)
    ):
        raise ValueError("mobile evidence scenario policy is invalid")
    return set(required), probe_oracles, outage_oracles


def load_timeline(path: pathlib.Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"timeline line {line_number} is invalid") from error
            if not isinstance(event, dict):
                raise ValueError(f"timeline line {line_number} is not an object")
            events.append(event)
    return events


def attempt_state(
    events: list[dict[str, object]], scenario_id: str, attempt: int
) -> tuple[str | None, int, dict[str, int], dict[str, int]]:
    state: str | None = None
    begin_index = -1
    latest_passed_probe_indices: dict[str, int] = {}
    latest_failed_probe_indices: dict[str, int] = {}
    for index, event in enumerate(events):
        if (
            event.get("event") == "probe"
            and event.get("kind") in {"http", "udp"}
        ):
            kind = str(event["kind"])
            if event.get("result") == "passed":
                latest_passed_probe_indices[kind] = index
            elif event.get("result") == "failed":
                latest_failed_probe_indices[kind] = index
        if (
            event.get("event") != "scenario"
            or event.get("scenarioId") != scenario_id
            or event.get("attempt") != attempt
        ):
            continue
        phase = event.get("phase")
        if phase == "begin" and state is None:
            state = "running"
            begin_index = index
        elif phase == "note" and state == "running":
            continue
        elif phase in {"passed", "failed"} and state == "running":
            state = str(phase)
        else:
            raise ValueError(f"timeline has an invalid state for attempt {attempt}")
    return (
        state,
        begin_index,
        latest_passed_probe_indices,
        latest_failed_probe_indices,
    )


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
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        (
            required_scenarios,
            probe_oracle_scenarios,
            outage_oracle_scenarios,
        ) = load_policy(root)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.scenario_id not in required_scenarios:
        parser.error("scenario_id is not a required release scenario")
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
    try:
        events = load_timeline(timeline_path)
        (
            current_state,
            begin_index,
            latest_passed_probe_indices,
            latest_failed_probe_indices,
        ) = attempt_state(events, args.scenario_id, args.attempt)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        parser.error(str(error))
    if args.phase == "begin":
        if current_state is not None:
            parser.error("scenario attempt has already started")
    elif current_state != "running":
        parser.error("scenario attempt is not running")
    if args.phase == "passed" and args.scenario_id in probe_oracle_scenarios:
        missing = sorted(
            kind
            for kind in ("http", "udp")
            if latest_passed_probe_indices.get(kind, -1) <= begin_index
        )
        if missing:
            parser.error(
                "passing this scenario requires post-begin "
                + "/".join(missing)
                + " probe evidence"
            )
        if args.scenario_id in outage_oracle_scenarios:
            missing_outage = sorted(
                kind
                for kind in ("http", "udp")
                if latest_failed_probe_indices.get(kind, -1) <= begin_index
            )
            if missing_outage:
                parser.error(
                    "passing this scenario requires post-begin "
                    + "/".join(missing_outage)
                    + " failed probe evidence"
                )
            missing_recovery = sorted(
                kind
                for kind in ("http", "udp")
                if latest_passed_probe_indices.get(kind, -1)
                <= latest_failed_probe_indices.get(kind, -1)
            )
            if missing_recovery:
                parser.error(
                    "passing this scenario requires post-failure "
                    + "/".join(missing_recovery)
                    + " recovery probe evidence"
                )
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("phase") != "running" or "startedAt" not in state:
        parser.error("campaign is building; wait for the first device sample")
    try:
        started_at = dt.datetime.fromisoformat(
            state["startedAt"].replace("Z", "+00:00")
        )
    except (AttributeError, TypeError, ValueError):
        parser.error("campaign state has an invalid start timestamp")
    if started_at.utcoffset() != dt.timedelta(0):
        parser.error("campaign start timestamp is not UTC")
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
            written = os.write(descriptor, payload[offset:])
            if written == 0:
                raise OSError("short write while recording transition marker")
            offset += written
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
