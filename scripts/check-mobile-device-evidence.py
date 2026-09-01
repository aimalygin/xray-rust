#!/usr/bin/env python3
"""Fail-closed validation for the v0.5 physical mobile-device release gate."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import pathlib
import re
import statistics
import sys
from typing import Any


SCHEMA_VERSION = 1
MIN_SOAK_SECONDS = 6 * 60 * 60
MAX_SAMPLE_INTERVAL_SECONDS = 60
MAX_SAMPLE_GAP_MULTIPLIER = 2
MIN_SAMPLE_COVERAGE = 0.90
MAX_ABSOLUTE_RSS_GROWTH_BYTES = 8 * 1024 * 1024
MAX_RELATIVE_RSS_GROWTH_DIVISOR = 4
MAX_THREAD_GROWTH = 4
MAX_JSON_BYTES = 16 * 1024 * 1024

LOWER_SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

TOP_FIELDS = {"schemaVersion", "campaignId", "candidate", "reports"}
CANDIDATE_FIELDS = {"revision", "dirty"}
REPORT_FIELDS = {
    "platform",
    "device",
    "app",
    "startedAt",
    "endedAt",
    "durationSeconds",
    "sampleIntervalSeconds",
    "samples",
    "scenarios",
    "artifacts",
    "result",
}
DEVICE_FIELDS = {
    "physical",
    "model",
    "osVersion",
    "architecture",
    "identifierHash",
}
APP_FIELDS = {"bundleIdentifier", "version", "build"}
SAMPLE_FIELDS = {
    "elapsedSeconds",
    "runtimeGeneration",
    "residentMemoryBytes",
    "threadCount",
    "activeConnections",
    "tunInboundPackets",
    "tunOutboundPackets",
    "fatalTunErrors",
    "unrecoveredTransitions",
}
SCENARIO_FIELDS = {"id", "status", "attempts", "notes"}
ARTIFACT_FIELDS = {"kind", "path", "sha256"}

REQUIRED_SCENARIOS = {
    "repeated-connect": 20,
    "rapid-stop-during-start": 10,
    "ipv4-traffic": 1,
    "ipv6-traffic": 1,
    "happy-eyeballs-failed-preferred": 5,
    "happy-eyeballs-cancellation": 5,
    "tcp-freedom": 1,
    "tcp-vless-reality": 1,
    "udp-freedom": 1,
    "udp-vless-xudp": 1,
    "dns-failover": 5,
    "captive-network": 1,
    "airplane-mode": 3,
    "wifi-cellular": 10,
    "sleep-wake": 5,
    "memory-pressure": 3,
    "provider-service-restart": 5,
    "dns64-nat64": 1,
    "packet-loss": 1,
    "long-xhttp-h2": 1,
    "long-xhttp-h3": 1,
    "secure-profile-persistence": 1,
    "credential-redaction": 1,
    "platform-lifecycle": 1,
}
REQUIRED_ARTIFACT_KINDS = {
    "resource-profile",
    "sanitized-log",
    "transition-timeline",
}


class ValidationError(Exception):
    """The supplied campaign is not valid release evidence."""


def fail(message: str) -> None:
    raise ValidationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact_fields(value: dict[str, Any], fields: set[str], label: str) -> None:
    missing = sorted(fields - value.keys())
    extra = sorted(value.keys() - fields)
    if missing:
        fail(f"{label} is missing field(s): {', '.join(missing)}")
    if extra:
        fail(f"{label} has unsupported field(s): {', '.join(extra)}")


def require_int(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def require_string(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        fail(f"{label} must be a nonempty string of at most {maximum} characters")
    if any(ord(character) < 0x20 for character in value):
        fail(f"{label} must not contain control characters")
    return value


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    timestamp = require_string(value, label, maximum=64)
    if not UTC_TIMESTAMP.fullmatch(timestamp):
        fail(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} is not a valid RFC 3339 timestamp")
    if parsed.utcoffset() != dt.timedelta(0):
        fail(f"{label} must use UTC")
    return parsed


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_artifact_path(root: pathlib.Path, raw_path: Any, label: str) -> pathlib.Path:
    relative = pathlib.PurePosixPath(require_string(raw_path, f"{label}.path", maximum=512))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        fail(f"{label}.path must be a normalized relative path")
    path = root.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        fail(f"{label}.path must name an existing regular non-symlink file")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        fail(f"{label}.path escapes the evidence directory")
    return path


def validate_samples(report: dict[str, Any], label: str) -> None:
    duration = require_int(report["durationSeconds"], f"{label}.durationSeconds", 1)
    interval = require_int(
        report["sampleIntervalSeconds"], f"{label}.sampleIntervalSeconds", 1
    )
    if duration < MIN_SOAK_SECONDS:
        fail(f"{label} duration is below the {MIN_SOAK_SECONDS}-second soak minimum")
    if interval > MAX_SAMPLE_INTERVAL_SECONDS:
        fail(
            f"{label} sample interval exceeds {MAX_SAMPLE_INTERVAL_SECONDS} seconds"
        )
    samples = report["samples"]
    if not isinstance(samples, list):
        fail(f"{label}.samples must be an array")
    minimum_samples = math.floor(duration / interval * MIN_SAMPLE_COVERAGE) + 1
    if len(samples) < minimum_samples:
        fail(
            f"{label}.samples has {len(samples)} entries; at least {minimum_samples} are required"
        )

    checked: list[dict[str, int]] = []
    previous_elapsed = -1
    previous_generation = 0
    previous_inbound = 0
    previous_outbound = 0
    for index, raw_sample in enumerate(samples):
        sample_label = f"{label}.samples[{index}]"
        sample = require_object(raw_sample, sample_label)
        require_exact_fields(sample, SAMPLE_FIELDS, sample_label)
        checked_sample = {
            field: require_int(sample[field], f"{sample_label}.{field}")
            for field in SAMPLE_FIELDS
        }
        if checked_sample["residentMemoryBytes"] == 0:
            fail(f"{sample_label}.residentMemoryBytes must be positive")
        if checked_sample["threadCount"] == 0:
            fail(f"{sample_label}.threadCount must be positive")
        elapsed = checked_sample["elapsedSeconds"]
        generation = checked_sample["runtimeGeneration"]
        if generation == 0:
            fail(f"{sample_label}.runtimeGeneration must be positive")
        if elapsed <= previous_elapsed:
            fail(f"{sample_label}.elapsedSeconds must be strictly increasing")
        if index > 0 and elapsed - previous_elapsed > interval * MAX_SAMPLE_GAP_MULTIPLIER:
            fail(f"{sample_label} follows a sampling gap larger than the allowed bound")
        if generation < previous_generation or generation > previous_generation + 1:
            fail(f"{sample_label}.runtimeGeneration must advance one generation at a time")
        if generation == previous_generation:
            if checked_sample["tunInboundPackets"] < previous_inbound:
                fail(f"{sample_label}.tunInboundPackets regressed within one runtime")
            if checked_sample["tunOutboundPackets"] < previous_outbound:
                fail(f"{sample_label}.tunOutboundPackets regressed within one runtime")
        if checked_sample["fatalTunErrors"] != 0:
            fail(f"{sample_label} reports a fatal TUN error")
        if checked_sample["unrecoveredTransitions"] != 0:
            fail(f"{sample_label} reports an unrecovered network transition")
        previous_elapsed = elapsed
        previous_generation = generation
        previous_inbound = checked_sample["tunInboundPackets"]
        previous_outbound = checked_sample["tunOutboundPackets"]
        checked.append(checked_sample)

    if checked[0]["elapsedSeconds"] > interval:
        fail(f"{label}.samples begins after the first sampling interval")
    if checked[-1]["elapsedSeconds"] < duration - interval:
        fail(f"{label}.samples does not cover the end of the soak")
    if checked[-1]["activeConnections"] != 0:
        fail(f"{label} ends with active connections after teardown")
    if not any(
        sample["tunInboundPackets"] > 0 and sample["tunOutboundPackets"] > 0
        for sample in checked
    ):
        fail(f"{label}.samples never demonstrate bidirectional TUN traffic")

    window = min(5, len(checked))
    first_rss = statistics.median(
        sample["residentMemoryBytes"] for sample in checked[:window]
    )
    last_rss = statistics.median(
        sample["residentMemoryBytes"] for sample in checked[-window:]
    )
    allowed_rss_growth = max(
        MAX_ABSOLUTE_RSS_GROWTH_BYTES,
        first_rss / MAX_RELATIVE_RSS_GROWTH_DIVISOR,
    )
    if last_rss - first_rss > allowed_rss_growth:
        fail(f"{label} reports unexplained steady-state resident-memory growth")
    first_threads = statistics.median(
        sample["threadCount"] for sample in checked[:window]
    )
    last_threads = statistics.median(
        sample["threadCount"] for sample in checked[-window:]
    )
    if last_threads - first_threads > MAX_THREAD_GROWTH:
        fail(f"{label} reports unexplained steady-state thread growth")


def validate_scenarios(report: dict[str, Any], label: str) -> None:
    scenarios = report["scenarios"]
    if not isinstance(scenarios, list):
        fail(f"{label}.scenarios must be an array")
    observed: dict[str, int] = {}
    for index, raw_scenario in enumerate(scenarios):
        scenario_label = f"{label}.scenarios[{index}]"
        scenario = require_object(raw_scenario, scenario_label)
        require_exact_fields(scenario, SCENARIO_FIELDS, scenario_label)
        scenario_id = require_string(scenario["id"], f"{scenario_label}.id", maximum=128)
        if scenario_id in observed:
            fail(f"{label}.scenarios contains duplicate id {scenario_id}")
        if scenario["status"] != "passed":
            fail(f"{scenario_label}.status must be passed")
        attempts = require_int(scenario["attempts"], f"{scenario_label}.attempts", 1)
        require_string(scenario["notes"], f"{scenario_label}.notes")
        observed[scenario_id] = attempts

    missing = sorted(REQUIRED_SCENARIOS.keys() - observed.keys())
    extra = sorted(observed.keys() - REQUIRED_SCENARIOS.keys())
    if missing:
        fail(f"{label}.scenarios is missing release gate(s): {', '.join(missing)}")
    if extra:
        fail(f"{label}.scenarios has unknown release gate(s): {', '.join(extra)}")
    for scenario_id, minimum_attempts in REQUIRED_SCENARIOS.items():
        if observed[scenario_id] < minimum_attempts:
            fail(
                f"{label} scenario {scenario_id} requires at least {minimum_attempts} attempt(s)"
            )


def validate_artifacts(report: dict[str, Any], root: pathlib.Path, label: str) -> None:
    artifacts = report["artifacts"]
    if not isinstance(artifacts, list):
        fail(f"{label}.artifacts must be an array")
    kinds: set[str] = set()
    paths: set[str] = set()
    for index, raw_artifact in enumerate(artifacts):
        artifact_label = f"{label}.artifacts[{index}]"
        artifact = require_object(raw_artifact, artifact_label)
        require_exact_fields(artifact, ARTIFACT_FIELDS, artifact_label)
        kind = require_string(artifact["kind"], f"{artifact_label}.kind", maximum=64)
        if kind not in REQUIRED_ARTIFACT_KINDS:
            fail(f"{artifact_label}.kind is not a supported release artifact kind")
        if kind in kinds:
            fail(f"{label}.artifacts contains duplicate kind {kind}")
        path_text = require_string(artifact["path"], f"{artifact_label}.path", maximum=512)
        if path_text in paths:
            fail(f"{label}.artifacts contains duplicate path {path_text}")
        paths.add(path_text)
        kinds.add(kind)
        expected_hash = require_string(
            artifact["sha256"], f"{artifact_label}.sha256", maximum=64
        )
        if not LOWER_SHA256.fullmatch(expected_hash):
            fail(f"{artifact_label}.sha256 must be a lowercase SHA-256 digest")
        path = validate_artifact_path(root, artifact["path"], artifact_label)
        if sha256_file(path) != expected_hash:
            fail(f"{artifact_label}.sha256 does not match {path_text}")
    missing_kinds = sorted(REQUIRED_ARTIFACT_KINDS - kinds)
    if missing_kinds:
        fail(f"{label}.artifacts is missing kind(s): {', '.join(missing_kinds)}")


def validate_report(report: dict[str, Any], root: pathlib.Path, index: int) -> str:
    label = f"reports[{index}]"
    require_exact_fields(report, REPORT_FIELDS, label)
    platform = report["platform"]
    if platform not in {"apple", "android"}:
        fail(f"{label}.platform must be apple or android")
    if report["result"] != "passed":
        fail(f"{label}.result must be passed")

    device = require_object(report["device"], f"{label}.device")
    require_exact_fields(device, DEVICE_FIELDS, f"{label}.device")
    if device["physical"] is not True:
        fail(f"{label}.device.physical must be true")
    require_string(device["model"], f"{label}.device.model", maximum=128)
    require_string(device["osVersion"], f"{label}.device.osVersion", maximum=64)
    architecture = require_string(
        device["architecture"], f"{label}.device.architecture", maximum=32
    )
    allowed_architectures = (
        {"arm64"}
        if platform == "apple"
        else {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
    )
    if architecture not in allowed_architectures:
        fail(f"{label}.device.architecture is not a supported physical architecture")
    identifier_hash = require_string(
        device["identifierHash"], f"{label}.device.identifierHash", maximum=64
    )
    if not LOWER_SHA256.fullmatch(identifier_hash):
        fail(f"{label}.device.identifierHash must be a lowercase SHA-256 digest")

    app = require_object(report["app"], f"{label}.app")
    require_exact_fields(app, APP_FIELDS, f"{label}.app")
    bundle_id = require_string(
        app["bundleIdentifier"], f"{label}.app.bundleIdentifier", maximum=256
    )
    if not IDENTIFIER.fullmatch(bundle_id):
        fail(f"{label}.app.bundleIdentifier has invalid characters")
    require_string(app["version"], f"{label}.app.version", maximum=64)
    require_string(app["build"], f"{label}.app.build", maximum=64)

    started_at = parse_timestamp(report["startedAt"], f"{label}.startedAt")
    ended_at = parse_timestamp(report["endedAt"], f"{label}.endedAt")
    duration = require_int(report["durationSeconds"], f"{label}.durationSeconds", 1)
    if ended_at - started_at != dt.timedelta(seconds=duration):
        fail(f"{label}.durationSeconds does not match startedAt/endedAt")

    validate_samples(report, label)
    validate_scenarios(report, label)
    validate_artifacts(report, root, label)
    return platform


def load_json(path: pathlib.Path) -> Any:
    if path.is_symlink() or not path.is_file():
        fail("campaign path must be an existing regular non-symlink file")
    if path.stat().st_size > MAX_JSON_BYTES:
        fail(f"campaign JSON exceeds {MAX_JSON_BYTES} bytes")
    try:
        with path.open("r", encoding="utf-8") as source:
            return json.load(
                source,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=lambda value: fail(
                    f"non-standard JSON constant is not allowed: {value}"
                ),
            )
    except UnicodeDecodeError:
        fail("campaign JSON is not valid UTF-8")
    except RecursionError:
        fail("campaign JSON nesting exceeds the parser limit")
    except json.JSONDecodeError as error:
        fail(f"campaign JSON is invalid: {error.msg}")


def validate_campaign(path: pathlib.Path, expected_candidate: str | None) -> None:
    root = path.parent
    campaign = require_object(load_json(path), "campaign")
    require_exact_fields(campaign, TOP_FIELDS, "campaign")
    if campaign["schemaVersion"] != SCHEMA_VERSION:
        fail(f"campaign.schemaVersion must be {SCHEMA_VERSION}")
    campaign_id = require_string(campaign["campaignId"], "campaign.campaignId", maximum=128)
    if not CAMPAIGN_ID.fullmatch(campaign_id):
        fail("campaign.campaignId has invalid characters")

    candidate = require_object(campaign["candidate"], "campaign.candidate")
    require_exact_fields(candidate, CANDIDATE_FIELDS, "campaign.candidate")
    revision = require_string(candidate["revision"], "campaign.candidate.revision", maximum=40)
    if not LOWER_SHA40.fullmatch(revision):
        fail("campaign.candidate.revision must be a full lowercase Git revision")
    if candidate["dirty"] is not False:
        fail("campaign.candidate.dirty must be false")
    if expected_candidate is not None and revision != expected_candidate:
        fail("campaign candidate does not match --candidate")

    reports = campaign["reports"]
    if not isinstance(reports, list) or len(reports) != 2:
        fail("campaign.reports must contain exactly one Apple and one Android report")
    platforms = {
        validate_report(require_object(report, f"reports[{index}]"), root, index)
        for index, report in enumerate(reports)
    }
    if platforms != {"apple", "android"}:
        fail("campaign.reports must contain exactly one Apple and one Android report")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="validate physical Apple/Android transition and soak evidence"
    )
    parser.add_argument("campaign", type=pathlib.Path)
    parser.add_argument(
        "--candidate",
        help="require the evidence to name this full lowercase Git revision",
    )
    args = parser.parse_args()
    if args.candidate is not None and not LOWER_SHA40.fullmatch(args.candidate):
        print("error: --candidate must be a full lowercase Git revision", file=sys.stderr)
        return 2
    try:
        validate_campaign(args.campaign, args.candidate)
    except (OSError, ValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"verified physical mobile-device evidence: {args.campaign}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
