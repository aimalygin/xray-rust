#!/usr/bin/env python3
"""Validate exact-candidate v0.6 physical-device and performance evidence."""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import re
import stat
import statistics
import sys
import zipfile
from typing import Any


SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
REQUIRED_PLATFORMS = {"apple", "android"}
REQUIRED_SCENARIOS = {
    "vless-encryption",
    "ip-on-demand",
    "xhttp-download-session",
    "cancellation",
    "host-adapter-projection",
}
REQUIRED_DEVICE_ARTIFACTS = {
    "resource-profile",
    "sanitized-log",
    "transition-timeline",
}
MEASUREMENT_COMPARISONS = {
    "process-throughput": "at-least",
    "vless-encryption-throughput": "at-least",
    "ip-on-demand-latency": "at-most",
    "xhttp-memory": "at-most",
}
REQUIRED_PERFORMANCE_ARTIFACTS = {"benchmark-raw", "build-manifest"}


class ValidationError(Exception):
    pass


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


def require_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(
            f"{label} fields differ: missing={sorted(expected - set(value))!r} "
            f"unexpected={sorted(set(value) - expected)!r}"
        )


def require_string(value: Any, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        fail(f"{label} must be a nonempty string of at most {maximum} characters")
    if any(ord(character) < 0x20 for character in value):
        fail(f"{label} contains a control character")
    return value


def require_int(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def require_number(value: Any, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result < 0 or (positive and result <= 0):
        fail(f"{label} is outside its allowed numeric range")
    return result


def require_pass(value: Any, label: str) -> None:
    if value != "pass":
        fail(f"{label} must be 'pass'")


def validate_relative_path(value: Any, label: str) -> str:
    raw = require_string(value, label)
    path = pathlib.PurePosixPath(raw)
    if "\\" in raw or path.is_absolute() or raw.endswith("/") or any(
        part in {"", ".", ".."} for part in raw.split("/")
    ):
        fail(f"{label} must be a normalized relative file path")
    return raw


def validate_artifacts(
    raw: Any,
    required_kinds: set[str],
    label: str,
    expected_files: dict[str, str],
) -> None:
    if not isinstance(raw, list):
        fail(f"{label} must be an array")
    kinds: list[str] = []
    for index, raw_artifact in enumerate(raw):
        artifact_label = f"{label}[{index}]"
        artifact = require_object(raw_artifact, artifact_label)
        require_fields(artifact, {"kind", "path", "sha256"}, artifact_label)
        kind = require_string(artifact["kind"], f"{artifact_label}.kind", 64)
        path = validate_relative_path(artifact["path"], f"{artifact_label}.path")
        digest = require_string(artifact["sha256"], f"{artifact_label}.sha256", 64)
        if not SHA256.fullmatch(digest):
            fail(f"{artifact_label}.sha256 must be lowercase SHA-256")
        if path in expected_files:
            fail(f"artifact path is repeated: {path}")
        kinds.append(kind)
        expected_files[path] = digest
    if len(kinds) != len(set(kinds)) or set(kinds) != required_kinds:
        fail(f"{label} kinds must be exactly {sorted(required_kinds)!r}")


def validate_device(
    raw: Any,
    label: str,
    expected_files: dict[str, str],
) -> str:
    device = require_object(raw, label)
    require_fields(
        device,
        {
            "platform",
            "physical",
            "model",
            "osVersion",
            "architecture",
            "durationSeconds",
            "scenarios",
            "limits",
            "observed",
            "artifacts",
            "result",
        },
        label,
    )
    platform = require_string(device["platform"], f"{label}.platform", 16)
    if platform not in REQUIRED_PLATFORMS:
        fail(f"{label}.platform is unsupported")
    if device["physical"] is not True:
        fail(f"{label}.physical must be true")
    for field in ("model", "osVersion", "architecture"):
        require_string(device[field], f"{label}.{field}", 128)
    require_int(device["durationSeconds"], f"{label}.durationSeconds", 1)
    require_pass(device["result"], f"{label}.result")

    scenarios = device["scenarios"]
    if not isinstance(scenarios, list):
        fail(f"{label}.scenarios must be an array")
    scenario_ids: list[str] = []
    for index, raw_scenario in enumerate(scenarios):
        scenario_label = f"{label}.scenarios[{index}]"
        scenario = require_object(raw_scenario, scenario_label)
        require_fields(
            scenario,
            {"id", "durationSeconds", "transitions", "trafficResult", "result"},
            scenario_label,
        )
        scenario_ids.append(require_string(scenario["id"], f"{scenario_label}.id", 64))
        require_int(scenario["durationSeconds"], f"{scenario_label}.durationSeconds", 1)
        transitions = scenario["transitions"]
        if not isinstance(transitions, list) or not transitions:
            fail(f"{scenario_label}.transitions must be a nonempty array")
        for transition_index, transition in enumerate(transitions):
            require_string(
                transition,
                f"{scenario_label}.transitions[{transition_index}]",
                128,
            )
        require_pass(scenario["trafficResult"], f"{scenario_label}.trafficResult")
        require_pass(scenario["result"], f"{scenario_label}.result")
    if len(scenario_ids) != len(set(scenario_ids)) or set(scenario_ids) != REQUIRED_SCENARIOS:
        fail(f"{label}.scenarios must be exactly {sorted(REQUIRED_SCENARIOS)!r}")

    limit_fields = {
        "residentMemoryGrowthBytes",
        "threadGrowth",
        "fatalErrors",
        "unrecoveredTransitions",
    }
    limits = require_object(device["limits"], f"{label}.limits")
    observed = require_object(device["observed"], f"{label}.observed")
    require_fields(limits, limit_fields, f"{label}.limits")
    require_fields(observed, limit_fields, f"{label}.observed")
    for field in limit_fields:
        minimum = 1 if field == "residentMemoryGrowthBytes" else 0
        maximum = require_int(limits[field], f"{label}.limits.{field}", minimum)
        actual = require_int(observed[field], f"{label}.observed.{field}")
        if actual > maximum:
            fail(f"{label}.observed.{field} exceeds its explicit limit")
    if limits["fatalErrors"] != 0 or limits["unrecoveredTransitions"] != 0:
        fail(f"{label} must set zero tolerance for fatal or unrecovered errors")

    validate_artifacts(
        device["artifacts"],
        REQUIRED_DEVICE_ARTIFACTS,
        f"{label}.artifacts",
        expected_files,
    )
    return platform


def validate_manifest(
    data: bytes,
    expected_revision: str,
    expected_tree: str,
) -> dict[str, str]:
    if len(data) > MAX_MANIFEST_BYTES:
        fail("manifest.json exceeds 1 MiB")
    try:
        manifest = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid manifest.json: {error}")
    manifest = require_object(manifest, "manifest")
    require_fields(
        manifest,
        {"schemaVersion", "candidate", "devices", "performance", "result"},
        "manifest",
    )
    if manifest["schemaVersion"] != 1:
        fail("manifest.schemaVersion must be 1")
    require_pass(manifest["result"], "manifest.result")

    candidate = require_object(manifest["candidate"], "manifest.candidate")
    require_fields(candidate, {"revision", "tree", "dirty"}, "manifest.candidate")
    if candidate["revision"] != expected_revision or not SHA40.fullmatch(expected_revision):
        fail("candidate revision does not match the release commit")
    if candidate["tree"] != expected_tree or not SHA40.fullmatch(expected_tree):
        fail("candidate tree does not match the release tree")
    if candidate["dirty"] is not False:
        fail("candidate.dirty must be false")

    expected_files: dict[str, str] = {}
    devices = manifest["devices"]
    if not isinstance(devices, list):
        fail("manifest.devices must be an array")
    platforms = [
        validate_device(device, f"manifest.devices[{index}]", expected_files)
        for index, device in enumerate(devices)
    ]
    if len(platforms) != 2 or set(platforms) != REQUIRED_PLATFORMS:
        fail("manifest.devices must contain one physical Apple and one physical Android report")

    performance = require_object(manifest["performance"], "manifest.performance")
    require_fields(
        performance,
        {"profile", "clean", "measurements", "artifacts", "result"},
        "manifest.performance",
    )
    if performance["profile"] != "release" or performance["clean"] is not True:
        fail("performance evidence must be a clean release-profile build")
    require_pass(performance["result"], "manifest.performance.result")
    measurements = performance["measurements"]
    if not isinstance(measurements, list):
        fail("manifest.performance.measurements must be an array")
    measurement_ids: list[str] = []
    for index, raw_measurement in enumerate(measurements):
        label = f"manifest.performance.measurements[{index}]"
        measurement = require_object(raw_measurement, label)
        require_fields(
            measurement,
            {"id", "unit", "samples", "comparison", "threshold"},
            label,
        )
        measurement_id = require_string(measurement["id"], f"{label}.id", 64)
        measurement_ids.append(measurement_id)
        require_string(measurement["unit"], f"{label}.unit", 32)
        comparison = require_string(
            measurement["comparison"], f"{label}.comparison", 16
        )
        expected_comparison = MEASUREMENT_COMPARISONS.get(measurement_id)
        if comparison != expected_comparison:
            fail(
                f"{label}.comparison must be {expected_comparison!r} "
                f"for {measurement_id!r}"
            )
        threshold = require_number(
            measurement["threshold"], f"{label}.threshold", positive=True
        )
        samples = measurement["samples"]
        if not isinstance(samples, list) or len(samples) < 5:
            fail(f"{label}.samples must contain at least five clean runs")
        checked = [
            require_number(sample, f"{label}.samples[{sample_index}]", positive=True)
            for sample_index, sample in enumerate(samples)
        ]
        median = statistics.median(checked)
        if comparison == "at-most" and median > threshold:
            fail(f"{label} median exceeds its explicit maximum")
        if comparison == "at-least" and median < threshold:
            fail(f"{label} median is below its explicit minimum")
    required_measurements = set(MEASUREMENT_COMPARISONS)
    if (
        len(measurement_ids) != len(set(measurement_ids))
        or set(measurement_ids) != required_measurements
    ):
        fail(
            f"performance measurements must be exactly "
            f"{sorted(required_measurements)!r}"
        )
    validate_artifacts(
        performance["artifacts"],
        REQUIRED_PERFORMANCE_ARTIFACTS,
        "manifest.performance.artifacts",
        expected_files,
    )
    return expected_files


def validate_archive(path: pathlib.Path, revision: str, tree: str) -> None:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        fail("evidence ZIP exceeds 256 MiB")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            fail("evidence ZIP contains duplicate entries")
        total_size = 0
        for info in infos:
            raw = info.filename
            validate_relative_path(raw.removesuffix("/"), f"ZIP entry {raw!r}")
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                fail(f"evidence ZIP contains a symbolic link: {raw}")
            if info.flag_bits & 0x1:
                fail(f"evidence ZIP contains an encrypted entry: {raw}")
            total_size += info.file_size
            if total_size > MAX_ARCHIVE_BYTES:
                fail("evidence ZIP expands beyond 256 MiB")
            if info.file_size > 1024 * 1024 and info.compress_size * 200 < info.file_size:
                fail(f"evidence ZIP entry has an unsafe compression ratio: {raw}")

        try:
            manifest_data = archive.read("manifest.json")
        except KeyError:
            fail("evidence ZIP is missing manifest.json")
        expected_files = validate_manifest(manifest_data, revision, tree)
        files = {name for name in names if not name.endswith("/")}
        expected_names = {"manifest.json", *expected_files}
        if files != expected_names:
            fail(
                f"evidence ZIP file set differs: missing={sorted(expected_names - files)!r} "
                f"unexpected={sorted(files - expected_names)!r}"
            )
        expected_dirs = {
            f"{parent}/"
            for name in expected_names
            for parent in list(pathlib.PurePosixPath(name).parents)[:-1]
        }
        directories = {name for name in names if name.endswith("/")}
        if not directories <= expected_dirs:
            fail(f"evidence ZIP has unexpected directories: {sorted(directories - expected_dirs)!r}")
        for artifact_path, expected_digest in expected_files.items():
            actual = hashlib.sha256(archive.read(artifact_path)).hexdigest()
            if actual != expected_digest:
                fail(f"artifact checksum differs: {artifact_path}")


def main() -> int:
    if len(sys.argv) != 4:
        print(
            f"usage: {sys.argv[0]} <evidence.zip> <expected-revision> <expected-tree>",
            file=sys.stderr,
        )
        return 2
    try:
        validate_archive(pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    except (OSError, ValidationError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"v0.6 release evidence passed for {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
