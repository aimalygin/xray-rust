#!/usr/bin/env python3
"""Build one fail-closed Apple report from a completed device campaign."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import runpy
import sys
from typing import Any


MAX_JSON_BYTES = 16 * 1024 * 1024
SCENARIO_FIELDS = {
    "at",
    "attempt",
    "elapsedSeconds",
    "event",
    "notes",
    "phase",
    "scenarioId",
}
PASSED_PROBE_FIELDS = {
    "at",
    "elapsedSeconds",
    "event",
    "kind",
    "result",
    "sequence",
}
FAILED_PROBE_FIELDS = {
    "at",
    "elapsedSeconds",
    "errorCode",
    "event",
    "kind",
    "result",
}
PROBE_ERROR_CODE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ReportError(Exception):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ReportError(f"non-standard JSON constant: {value}")


def load_json(path: pathlib.Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ReportError(f"missing regular file: {path.name}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ReportError(f"JSON file is too large: {path.name}")
    try:
        with path.open("r", encoding="utf-8") as source:
            return json.load(
                source,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_constant,
            )
    except UnicodeDecodeError as error:
        raise ReportError(f"JSON is not valid UTF-8: {path.name}") from error
    except json.JSONDecodeError as error:
        raise ReportError(f"invalid JSON in {path.name}: {error.msg}") from error


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportError(f"{label} must be an object")
    return value


def require_int(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ReportError(f"{label} must be an integer >= {minimum}")
    return value


def require_string(value: Any, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReportError(f"{label} must be a nonempty bounded string")
    if not value.isprintable():
        raise ReportError(f"{label} must contain only printable characters")
    return value


def parse_UTC(value: Any, label: str) -> dt.datetime:
    raw = require_string(value, label, 64)
    if not raw.endswith("Z"):
        raise ReportError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise ReportError(f"{label} is not a valid timestamp") from error
    if parsed.utcoffset() != dt.timedelta(0):
        raise ReportError(f"{label} must use UTC")
    return parsed


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_policy(
    root: pathlib.Path,
) -> tuple[int, dict[str, int], set[str], set[str]]:
    policy = runpy.run_path(str(root / "scripts/check-mobile-device-evidence.py"))
    minimum_duration = policy.get("MIN_SOAK_SECONDS")
    required_scenarios = policy.get("REQUIRED_SCENARIOS")
    probe_oracle_scenarios = policy.get("APPLE_PROBE_ORACLE_SCENARIOS")
    outage_oracle_scenarios = policy.get("APPLE_DUAL_PROBE_OUTAGE_SCENARIOS")
    if (
        not isinstance(minimum_duration, int)
        or not isinstance(required_scenarios, dict)
        or not isinstance(probe_oracle_scenarios, set)
        or not isinstance(outage_oracle_scenarios, set)
    ):
        raise ReportError("mobile evidence policy could not be loaded")
    if any(
        not isinstance(key, str)
        or isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        for key, value in required_scenarios.items()
    ):
        raise ReportError("mobile evidence scenario policy is invalid")
    if not probe_oracle_scenarios.issubset(required_scenarios):
        raise ReportError("Apple probe-oracle scenario policy is invalid")
    if not outage_oracle_scenarios.issubset(probe_oracle_scenarios):
        raise ReportError("Apple outage-oracle scenario policy is invalid")
    return (
        minimum_duration,
        required_scenarios,
        probe_oracle_scenarios,
        outage_oracle_scenarios,
    )


def load_timeline(path: pathlib.Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ReportError("transition timeline is missing")
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.endswith("\n") or len(line.encode("utf-8")) > 4096:
                    raise ReportError(f"timeline line {line_number} is malformed")
                try:
                    event = json.loads(
                        line,
                        object_pairs_hook=reject_duplicate_keys,
                        parse_constant=reject_constant,
                    )
                except json.JSONDecodeError as error:
                    raise ReportError(
                        f"timeline line {line_number} is invalid JSON: {error.msg}"
                    ) from error
                events.append(require_object(event, f"timeline line {line_number}"))
    except UnicodeDecodeError as error:
        raise ReportError("transition timeline is not valid UTF-8") from error
    return events


def build_scenarios(
    events: list[dict[str, Any]],
    required: dict[str, int],
    probe_oracle_scenarios: set[str],
    outage_oracle_scenarios: set[str],
    started_at: str,
    ended_at: str,
    duration: int,
) -> list[dict[str, Any]]:
    build_starts = 0
    campaign_starts = 0
    campaign_ends = 0
    attempt_states: dict[tuple[str, int], str] = {}
    passed: dict[str, int] = {scenario_id: 0 for scenario_id in required}
    failed: dict[str, int] = {scenario_id: 0 for scenario_id in required}
    attempt_begin_indices: dict[tuple[str, int], int] = {}
    latest_passed_probe_indices: dict[str, int] = {}
    latest_failed_probe_indices: dict[str, int] = {}
    probe_sequences: dict[str, int] = {}
    previous_elapsed = -1
    previous_at: dt.datetime | None = None
    campaign_is_running = False
    campaign_has_ended = False

    for index, event in enumerate(events):
        event_name = event.get("event")
        if event_name == "campaign-build-start":
            if set(event) != {"event", "at"}:
                raise ReportError("campaign-build-start has an invalid field set")
            event_at = parse_UTC(event["at"], f"timeline[{index}].at")
            if campaign_is_running or campaign_has_ended:
                raise ReportError("campaign-build-start is out of order")
            build_starts += 1
        elif event_name == "campaign-start":
            if set(event) != {"event", "at"} or event.get("at") != started_at:
                raise ReportError("campaign-start does not match Apple run metadata")
            if build_starts != 1 or campaign_is_running or campaign_has_ended:
                raise ReportError("campaign-start is out of order")
            event_at = parse_UTC(event["at"], f"timeline[{index}].at")
            campaign_starts += 1
            campaign_is_running = True
        elif event_name == "campaign-end":
            expected = {"event", "at", "elapsedSeconds", "result"}
            if set(event) != expected or event.get("result") != "passed":
                raise ReportError("campaign-end is not a passing terminal marker")
            if event.get("at") != ended_at or event.get("elapsedSeconds") != duration:
                raise ReportError("campaign-end does not match Apple run metadata")
            if not campaign_is_running or campaign_has_ended:
                raise ReportError("campaign-end is out of order")
            event_at = parse_UTC(event["at"], f"timeline[{index}].at")
            campaign_ends += 1
            campaign_has_ended = True
        elif event_name == "probe" and frozenset(event) in {
            frozenset(PASSED_PROBE_FIELDS),
            frozenset(FAILED_PROBE_FIELDS),
        }:
            if not campaign_is_running or campaign_has_ended:
                raise ReportError("probe event is outside the running campaign")
            kind = event.get("kind")
            result = event.get("result")
            if kind not in {"http", "udp"} or result not in {"passed", "failed"}:
                raise ReportError("timeline has an invalid probe result")
            if result == "passed":
                if set(event) != PASSED_PROBE_FIELDS:
                    raise ReportError("passing probe has an invalid field set")
                sequence = require_int(event.get("sequence"), "probe sequence", 1)
                if sequence <= probe_sequences.get(kind, 0):
                    raise ReportError(f"timeline {kind} probe sequence is not increasing")
                probe_sequences[kind] = sequence
                latest_passed_probe_indices[kind] = index
            else:
                if set(event) != FAILED_PROBE_FIELDS:
                    raise ReportError("failed probe has an invalid field set")
                error_code = event.get("errorCode")
                if not isinstance(error_code, str) or not PROBE_ERROR_CODE.fullmatch(
                    error_code
                ):
                    raise ReportError("failed probe has an invalid errorCode")
                latest_failed_probe_indices[kind] = index
            elapsed = require_int(event.get("elapsedSeconds"), "probe elapsedSeconds")
            if elapsed < previous_elapsed or elapsed > duration:
                raise ReportError("probe events are outside monotonic campaign time")
            previous_elapsed = elapsed
            event_at = parse_UTC(event["at"], f"timeline[{index}].at")
            expected_at = parse_UTC(started_at, "startedAt") + dt.timedelta(
                seconds=elapsed
            )
            if abs((event_at - expected_at).total_seconds()) > 2:
                raise ReportError("probe timestamp does not match elapsedSeconds")
        elif event_name == "scenario" and set(event) == SCENARIO_FIELDS:
            if not campaign_is_running or campaign_has_ended:
                raise ReportError("scenario marker is outside the running campaign")
            scenario_id = require_string(event["scenarioId"], "scenarioId", 128)
            if scenario_id not in required:
                raise ReportError(f"timeline has unknown release scenario: {scenario_id}")
            attempt = require_int(event["attempt"], "scenario attempt", 1)
            elapsed = require_int(event["elapsedSeconds"], "scenario elapsedSeconds")
            if elapsed < previous_elapsed or elapsed > duration:
                raise ReportError("scenario markers are outside monotonic campaign time")
            previous_elapsed = elapsed
            event_at = parse_UTC(event["at"], f"timeline[{index}].at")
            expected_at = parse_UTC(started_at, "startedAt") + dt.timedelta(seconds=elapsed)
            if abs((event_at - expected_at).total_seconds()) > 2:
                raise ReportError("scenario timestamp does not match elapsedSeconds")
            require_string(event["notes"], "scenario notes", 512)
            phase = event["phase"]
            key = (scenario_id, attempt)
            state = attempt_states.get(key)
            if phase == "begin":
                if state is not None:
                    raise ReportError(f"duplicate begin for {scenario_id} attempt {attempt}")
                attempt_states[key] = "running"
                attempt_begin_indices[key] = index
            elif phase == "note":
                if state != "running":
                    raise ReportError(f"note without active {scenario_id} attempt {attempt}")
            elif phase in {"passed", "failed"}:
                if state != "running":
                    raise ReportError(
                        f"terminal marker without active {scenario_id} attempt {attempt}"
                    )
                if phase == "passed":
                    if scenario_id in probe_oracle_scenarios:
                        begin_index = attempt_begin_indices[key]
                        missing = sorted(
                            kind
                            for kind in ("http", "udp")
                            if latest_passed_probe_indices.get(kind, -1) <= begin_index
                        )
                        if missing:
                            raise ReportError(
                                f"scenario {scenario_id} attempt {attempt} has no "
                                f"post-begin {'/'.join(missing)} probe"
                            )
                    if scenario_id in outage_oracle_scenarios:
                        missing_outage = sorted(
                            kind
                            for kind in ("http", "udp")
                            if latest_failed_probe_indices.get(kind, -1)
                            <= begin_index
                        )
                        if missing_outage:
                            raise ReportError(
                                f"scenario {scenario_id} attempt {attempt} has no "
                                f"post-begin {'/'.join(missing_outage)} failed probe"
                            )
                        missing_recovery = sorted(
                            kind
                            for kind in ("http", "udp")
                            if latest_passed_probe_indices.get(kind, -1)
                            <= latest_failed_probe_indices.get(kind, -1)
                        )
                        if missing_recovery:
                            raise ReportError(
                                f"scenario {scenario_id} attempt {attempt} has no "
                                f"post-failure {'/'.join(missing_recovery)} recovery probe"
                            )
                    passed[scenario_id] += 1
                else:
                    failed[scenario_id] += 1
                attempt_states[key] = phase
            else:
                raise ReportError(f"invalid phase for {scenario_id} attempt {attempt}")
        else:
            raise ReportError(f"timeline[{index}] has an unsupported event")

        if previous_at is not None and event_at < previous_at:
            raise ReportError("timeline timestamps are not monotonic")
        previous_at = event_at

    if build_starts != 1 or campaign_starts != 1 or campaign_ends != 1:
        raise ReportError("timeline must contain one build/start/end marker")
    incomplete = sorted(key for key, state in attempt_states.items() if state == "running")
    if incomplete:
        raise ReportError(f"timeline has incomplete scenario attempt: {incomplete[0]}")

    reports: list[dict[str, Any]] = []
    for scenario_id, minimum_attempts in required.items():
        if passed[scenario_id] < minimum_attempts:
            raise ReportError(
                f"scenario {scenario_id} has {passed[scenario_id]} passing attempt(s); "
                f"{minimum_attempts} required"
            )
        reports.append(
            {
                "id": scenario_id,
                "status": "passed",
                "attempts": passed[scenario_id],
                "notes": (
                    f"{passed[scenario_id]} passed and {failed[scenario_id]} failed "
                    "attempt(s); see the checksum-verified transition timeline."
                ),
            }
        )
    return reports


def artifact_prefix(value: str) -> pathlib.PurePosixPath:
    prefix = pathlib.PurePosixPath(value)
    if prefix.is_absolute() or not prefix.parts or ".." in prefix.parts or "." in prefix.parts:
        raise ReportError("--artifact-prefix must be a normalized relative path")
    if any(not PATH_COMPONENT.fullmatch(component) for component in prefix.parts):
        raise ReportError("--artifact-prefix contains an invalid path component")
    return prefix


def build_report(
    root: pathlib.Path,
    campaign_dir: pathlib.Path,
    prefix: pathlib.PurePosixPath,
) -> dict[str, Any]:
    metadata = require_object(load_json(campaign_dir / "apple-run.json"), "apple-run")
    if metadata.get("schemaVersion") != 1 or metadata.get("rehearsal") is not False:
        raise ReportError("only a formal schema-v1 Apple run can produce release evidence")
    candidate = require_object(metadata.get("candidate"), "candidate")
    if candidate.get("dirty") is not False:
        raise ReportError("Apple release evidence must come from a clean candidate")

    (
        minimum_duration,
        required_scenarios,
        probe_oracle_scenarios,
        outage_oracle_scenarios,
    ) = load_policy(root)
    duration = require_int(metadata.get("observedDurationSeconds"), "duration", 1)
    if duration < minimum_duration:
        raise ReportError(f"Apple run is shorter than {minimum_duration} seconds")
    started_at = require_string(metadata.get("startedAt"), "startedAt", 64)
    ended_at = require_string(metadata.get("endedAt"), "endedAt", 64)
    started = parse_UTC(started_at, "startedAt")
    ended = parse_UTC(ended_at, "endedAt")
    if ended - started != dt.timedelta(seconds=duration):
        raise ReportError("Apple run timestamps do not match observed duration")

    samples = load_json(campaign_dir / "apple-device-samples.json")
    if not isinstance(samples, list) or not samples:
        raise ReportError("Apple samples must be a nonempty array")
    final_sample = require_object(samples[-1], "final Apple sample")
    if final_sample.get("elapsedSeconds") != duration:
        raise ReportError("Apple samples do not cover the reported duration")
    scenarios = build_scenarios(
        load_timeline(campaign_dir / "transition-timeline.jsonl"),
        required_scenarios,
        probe_oracle_scenarios,
        outage_oracle_scenarios,
        started_at,
        ended_at,
        duration,
    )

    artifacts = []
    for kind, name in (
        ("resource-profile", "resource-profile.trace.zip"),
        ("sanitized-log", "sanitized-log.txt"),
        ("transition-timeline", "transition-timeline.jsonl"),
    ):
        path = campaign_dir / name
        if path.is_symlink() or not path.is_file():
            raise ReportError(f"required artifact is missing: {name}")
        artifacts.append(
            {
                "kind": kind,
                "path": str(prefix / name),
                "sha256": sha256_file(path),
            }
        )

    return {
        "platform": "apple",
        "device": require_object(metadata.get("device"), "device"),
        "app": require_object(metadata.get("app"), "app"),
        "startedAt": started_at,
        "endedAt": ended_at,
        "durationSeconds": duration,
        "sampleIntervalSeconds": require_int(
            metadata.get("sampleIntervalSeconds"), "sampleIntervalSeconds", 1
        ),
        "samples": samples,
        "scenarios": scenarios,
        "artifacts": artifacts,
        "result": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=pathlib.Path)
    parser.add_argument("--artifact-prefix")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    campaign_dir = args.campaign_dir.resolve()
    prefix = artifact_prefix(args.artifact_prefix or campaign_dir.name)
    report = build_report(root, campaign_dir, prefix)
    output = campaign_dir / "apple-report.json"
    if output.is_symlink():
        raise ReportError("refusing to replace a symlinked Apple report")
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"built Apple device report: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReportError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
