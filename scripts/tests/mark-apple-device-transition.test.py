#!/usr/bin/env python3
"""Contract checks for live Apple transition marker oracle enforcement."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import subprocess
import sys
import tempfile


def timestamp(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def run(
    marker: pathlib.Path, campaign: pathlib.Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(marker), str(campaign), *arguments],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def append_event(path: pathlib.Path, event: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, sort_keys=True) + "\n")


def expect_failure(
    result: subprocess.CompletedProcess[str], expected: str
) -> None:
    if result.returncode == 0 or expected not in result.stderr:
        raise AssertionError(f"expected {expected!r}, got: {result.stderr}")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    marker = root / "scripts/mark-apple-device-transition.py"
    with tempfile.TemporaryDirectory(prefix="xray-apple-transition-marker-") as raw:
        campaign = pathlib.Path(raw)
        started = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=10)
        started_at = timestamp(started)
        (campaign / ".apple-campaign-state.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "campaignId": "marker-contract",
                    "phase": "running",
                    "startedAt": started_at,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        timeline = campaign / "transition-timeline.jsonl"
        timeline.write_text(
            json.dumps({"event": "campaign-start", "at": started_at}) + "\n",
            encoding="utf-8",
        )

        unknown = run(
            marker,
            campaign,
            "not-a-release-gate",
            "--attempt",
            "1",
            "--phase",
            "begin",
            "--notes",
            "unknown",
        )
        expect_failure(unknown, "not a required release scenario")

        begin = run(
            marker,
            campaign,
            "airplane-mode",
            "--attempt",
            "1",
            "--phase",
            "begin",
            "--notes",
            "radios disabled",
        )
        if begin.returncode != 0:
            raise AssertionError(begin.stderr)

        premature = run(
            marker,
            campaign,
            "airplane-mode",
            "--attempt",
            "1",
            "--phase",
            "passed",
            "--notes",
            "premature recovery claim",
        )
        expect_failure(premature, "post-begin http/udp probe evidence")

        now = dt.datetime.now(dt.timezone.utc)
        elapsed = max(0, int((now - started).total_seconds()))
        append_event(
            timeline,
            {
                "event": "probe",
                "at": timestamp(now),
                "elapsedSeconds": elapsed,
                "kind": "http",
                "result": "passed",
                "sequence": 1,
            },
        )
        http_only = run(
            marker,
            campaign,
            "airplane-mode",
            "--attempt",
            "1",
            "--phase",
            "passed",
            "--notes",
            "only HTTPS recovered",
        )
        expect_failure(http_only, "post-begin udp probe evidence")

        append_event(
            timeline,
            {
                "event": "probe",
                "at": timestamp(now),
                "elapsedSeconds": elapsed,
                "kind": "udp",
                "result": "passed",
                "sequence": 1,
            },
        )
        passed = run(
            marker,
            campaign,
            "airplane-mode",
            "--attempt",
            "1",
            "--phase",
            "passed",
            "--notes",
            "both probes recovered",
        )
        if passed.returncode != 0:
            raise AssertionError(passed.stderr)

        duplicate = run(
            marker,
            campaign,
            "airplane-mode",
            "--attempt",
            "1",
            "--phase",
            "passed",
            "--notes",
            "duplicate terminal",
        )
        expect_failure(duplicate, "scenario attempt is not running")

        for phase in ("begin", "passed"):
            redaction = run(
                marker,
                campaign,
                "credential-redaction",
                "--attempt",
                "1",
                "--phase",
                phase,
                "--notes",
                "sanitized log inspected",
            )
            if redaction.returncode != 0:
                raise AssertionError(redaction.stderr)

    print("Apple transition marker oracle contract test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
