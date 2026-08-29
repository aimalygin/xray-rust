#!/usr/bin/env python3
"""Fail-closed validation for a committed benchmark publication."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import sys
from typing import Any


XRAY_CORE_VERSION = "v26.7.28"
XRAY_CORE_REVISION = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
SING_BOX_BUILD_TAGS = (
    "with_gvisor,with_utls,badlinkname,tfogo_checklinkname0"
)
SING_BOX_SOURCE_URL = "https://github.com/SagerNet/sing-box"
SEMVER_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
LOWER_SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")

MANIFEST_FIELDS = {
    "schemaVersion",
    "publicationId",
    "measuredAt",
    "candidate",
    "environment",
    "comparators",
    "rawArchive",
    "series",
}
ENVIRONMENT_FIELDS = {"hardware", "os", "rustc", "cargo", "go"}
PARAMETER_FIELDS = (
    "connections",
    "iterations",
    "payload_size",
    "stream_transport",
    "stream_traffic",
    "xhttp_mode",
    "xhttp_profile",
    "xhttp_max_post_bytes",
    "settle_ms",
    "dns_transport",
    "dns_upstream_transport",
)


class ValidationError(Exception):
    """A publication violates the committed evidence policy."""


def fail(message: str) -> None:
    raise ValidationError(message)


def reject_json_constant(value: str) -> None:
    fail(f"non-standard JSON constant is not allowed: {value}")


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def read_json(path: pathlib.Path, label: str) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read {label}: {error}")
    try:
        return json.loads(
            text,
            parse_constant=reject_json_constant,
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as error:
        fail(f"invalid JSON in {label}: {error}")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact_fields(
    value: dict[str, Any], expected: set[str], label: str
) -> None:
    missing = sorted(expected - value.keys())
    unexpected = sorted(value.keys() - expected)
    if missing:
        fail(f"{label} is missing field: {missing[0]}")
    if unexpected:
        fail(f"{label} has unexpected field: {unexpected[0]}")


def require_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - value.keys())
    if missing:
        fail(f"{label} is missing field: {missing[0]}")


def require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be non-empty")
    return value


def require_sha40(value: Any, label: str) -> str:
    if not isinstance(value, str) or LOWER_SHA40.fullmatch(value) is None:
        fail(f"{label} must be 40 lowercase hexadecimal characters")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or LOWER_SHA256.fullmatch(value) is None:
        fail(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def require_integer(value: Any, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        fail(f"{label} must be {expected}")


def require_positive_integer(value: Any, label: str) -> None:
    if type(value) is not int or value <= 0:
        fail(f"{label} must be a positive integer")


def require_nonnegative_integer(value: Any, label: str) -> None:
    if type(value) is not int or value < 0:
        fail(f"{label} must be a non-negative integer")


def require_optional_nonempty_string(value: Any, label: str) -> None:
    if value is not None:
        require_nonempty_string(value, label)


def json_equal_strict(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            json_equal_strict(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            json_equal_strict(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def expected_matrix() -> dict[tuple[str, str], dict[str, Any]]:
    matrix: dict[tuple[str, str], dict[str, Any]] = {}
    all_engines = ("xray-rust", "xray-core", "sing-box")

    def add(
        scenario: str, engines: tuple[str, ...], **fields: Any
    ) -> None:
        for engine in engines:
            matrix[(scenario, engine)] = fields.copy()

    base = {
        "idle": ("idle", 1),
        "many-idle-flows-100": ("many-idle-flows", 100),
        "many-idle-flows-1000": ("many-idle-flows", 1000),
        "tcp-freedom": ("tcp-freedom", 1),
        "udp-freedom": ("udp-freedom", 1),
        "reconnect-burst": ("reconnect-burst", 16),
        "reality-vision-xudp": ("reality-vision-xudp", 1),
        "tcp-bulk-throughput": ("tcp-bulk-throughput", 1),
        "reality-vision-bulk-throughput": (
            "reality-vision-bulk-throughput",
            1,
        ),
    }
    for scenario, (workload, connections) in base.items():
        add(
            scenario,
            all_engines,
            workload=workload,
            connections=connections,
        )
    add(
        "routed-tcp-freedom",
        ("xray-rust", "xray-core"),
        workload="routed-tcp-freedom",
        connections=8,
    )

    for transport in ("ws", "httpupgrade", "grpc"):
        for traffic in ("upload", "download", "full-duplex"):
            for flows in (1, 32):
                add(
                    f"stream-{transport}-{traffic}-{flows}",
                    all_engines,
                    workload="stream-transport",
                    connections=flows,
                    stream_transport=transport,
                    stream_traffic=traffic,
                    xhttp_mode=None,
                    xhttp_profile=None,
                    xhttp_max_post_bytes=None,
                )

    for transport in ("xhttp-h1", "xhttp-h2", "xhttp-h3"):
        for traffic in ("upload", "download", "full-duplex"):
            for flows in (1, 32):
                add(
                    f"stream-{transport}-{traffic}-{flows}",
                    ("xray-rust", "xray-core"),
                    workload="stream-transport",
                    connections=flows,
                    stream_transport=transport,
                    stream_traffic=traffic,
                    xhttp_mode="stream-up",
                    xhttp_profile=None,
                    xhttp_max_post_bytes=65_536,
                )

    for transport in ("xhttp-h1", "xhttp-h2", "xhttp-h3"):
        for flows in (1, 32):
            add(
                f"xhttp-pressure-{transport}-{flows}",
                ("xray-rust", "xray-core"),
                workload="stream-transport",
                connections=flows,
                stream_transport=transport,
                stream_traffic="packet-up",
                xhttp_mode="packet-up",
                xhttp_profile=None,
                xhttp_max_post_bytes=16_384,
            )

    for flows in (1, 16, 32):
        add(
            f"xhttp-memory-held-open-{flows}-max-500000",
            ("xray-rust", "xray-core"),
            workload="stream-transport",
            connections=flows,
            stream_transport="xhttp-h1",
            stream_traffic="held-open",
            xhttp_mode="packet-up",
            xhttp_profile="legacy-extra-h1-packet-up",
            xhttp_max_post_bytes=500_000,
        )
    add(
        "xhttp-memory-held-open-16-control-16384",
        ("xray-rust", "xray-core"),
        workload="stream-transport",
        connections=16,
        stream_transport="xhttp-h1",
        stream_traffic="held-open",
        xhttp_mode="packet-up",
        xhttp_profile="legacy-extra-h1-packet-up",
        xhttp_max_post_bytes=16_384,
    )
    for flows in (1, 16):
        add(
            f"xhttp-memory-packet-up-{flows}-max-500000",
            ("xray-rust", "xray-core"),
            workload="stream-transport",
            connections=flows,
            stream_transport="xhttp-h1",
            stream_traffic="packet-up",
            xhttp_mode="packet-up",
            xhttp_profile="legacy-extra-h1-packet-up",
            xhttp_max_post_bytes=500_000,
        )
    return matrix


def validate_manifest_shape(manifest: Any) -> dict[str, Any]:
    manifest = require_object(manifest, "manifest")
    require_exact_fields(manifest, MANIFEST_FIELDS, "manifest")
    require_integer(manifest["schemaVersion"], 1, "schemaVersion")

    publication_id = require_nonempty_string(
        manifest["publicationId"], "publicationId"
    )
    measured_at = require_nonempty_string(manifest["measuredAt"], "measuredAt")
    try:
        dt.date.fromisoformat(measured_at)
    except ValueError:
        fail("measuredAt must be a valid YYYY-MM-DD date")
    if publication_id != f"{measured_at}-{XRAY_CORE_VERSION}":
        fail(
            "publicationId must combine measuredAt with the pinned Xray-core "
            f"version ({measured_at}-{XRAY_CORE_VERSION})"
        )

    candidate = require_object(manifest["candidate"], "candidate")
    require_exact_fields(candidate, {"revision", "dirty"}, "candidate")
    require_sha40(candidate["revision"], "candidate.revision")
    if candidate["dirty"] is not False:
        fail("candidate.dirty must be false")

    environment = require_object(manifest["environment"], "environment")
    require_exact_fields(environment, ENVIRONMENT_FIELDS, "environment")
    for field in sorted(ENVIRONMENT_FIELDS):
        require_nonempty_string(environment[field], f"environment.{field}")

    comparators = require_object(manifest["comparators"], "comparators")
    require_exact_fields(comparators, {"xray-core", "sing-box"}, "comparators")

    xray = require_object(comparators["xray-core"], "comparators.xray-core")
    require_exact_fields(
        xray,
        {"version", "revision", "binarySha256", "buildCommand"},
        "comparators.xray-core",
    )
    if xray["version"] != XRAY_CORE_VERSION:
        fail(f"xray-core version must be {XRAY_CORE_VERSION}")
    if xray["revision"] != XRAY_CORE_REVISION:
        fail(f"xray-core revision must be {XRAY_CORE_REVISION}")
    require_sha256(
        xray["binarySha256"], "comparators.xray-core.binarySha256"
    )
    if xray["buildCommand"] != "go build ./main":
        fail("comparators.xray-core.buildCommand must be go build ./main")

    sing = require_object(comparators["sing-box"], "comparators.sing-box")
    require_exact_fields(
        sing,
        {
            "version",
            "revision",
            "binarySha256",
            "buildTags",
            "sourceUrl",
        },
        "comparators.sing-box",
    )
    if (
        not isinstance(sing["version"], str)
        or SEMVER_TAG.fullmatch(sing["version"]) is None
    ):
        fail("comparators.sing-box.version must be a stable vMAJOR.MINOR.PATCH tag")
    require_sha40(sing["revision"], "comparators.sing-box.revision")
    require_sha256(
        sing["binarySha256"], "comparators.sing-box.binarySha256"
    )
    if sing["buildTags"] != SING_BOX_BUILD_TAGS:
        fail("comparators.sing-box.buildTags does not match the pinned build")
    if sing["sourceUrl"] != SING_BOX_SOURCE_URL:
        fail("comparators.sing-box.sourceUrl does not match the pinned source")

    archive = require_object(manifest["rawArchive"], "rawArchive")
    require_exact_fields(archive, {"location", "sha256"}, "rawArchive")
    require_nonempty_string(archive["location"], "rawArchive.location")
    require_sha256(archive["sha256"], "rawArchive.sha256")

    if not isinstance(manifest["series"], list):
        fail("series must be an array")
    return manifest


def safe_summary_path(root: pathlib.Path, relative: Any) -> pathlib.Path:
    relative = require_nonempty_string(relative, "series summary")
    try:
        relative_path = pathlib.Path(relative)
        if relative_path.is_absolute():
            fail("summary path escapes publication root")
        resolved = (root / relative_path).resolve()
    except (OSError, RuntimeError, ValueError) as error:
        fail(f"invalid summary path: {error}")
    try:
        resolved.relative_to(root)
    except ValueError:
        fail("summary path escapes publication root")
    if not resolved.is_file():
        fail(f"summary file does not exist: {relative}")
    return resolved


def validate_git_state(
    value: Any,
    label: str,
    expected_revision: str | None,
) -> None:
    state = require_object(value, label)
    revision = require_sha40(state.get("revision"), f"{label}.revision")
    if expected_revision is not None and revision != expected_revision:
        fail(f"{label}.revision does not match publication provenance")
    if state.get("dirty") is not False:
        if label == "workspace_git":
            fail("workspace provenance must be clean")
        fail("engine source provenance must be clean")


def validate_provenance(
    provenance_value: Any,
    engine: str,
    manifest: dict[str, Any],
) -> tuple[str, str]:
    provenance = require_object(provenance_value, "summary provenance")
    if provenance.get("harness_profile") != "release":
        fail("harness profile must be release")

    validate_git_state(
        provenance.get("workspace_git"),
        "workspace_git",
        manifest["candidate"]["revision"],
    )

    engine_revision = {
        "xray-rust": manifest["candidate"]["revision"],
        "xray-core": manifest["comparators"]["xray-core"]["revision"],
        "sing-box": manifest["comparators"]["sing-box"]["revision"],
    }[engine]
    engine_source = provenance.get("engine_source_git")
    if engine_source is None:
        if engine != "xray-core":
            fail(f"{engine} engine source provenance is required")
    else:
        validate_git_state(engine_source, "engine_source_git", engine_revision)

    require_nonempty_string(
        provenance.get("harness_binary_path"), "harness binary path"
    )
    require_nonempty_string(
        provenance.get("engine_binary_path"), "engine binary path"
    )
    if "harness_binary_sha256" not in provenance:
        fail("harness binary SHA-256 is required")
    harness_hash = require_sha256(
        provenance["harness_binary_sha256"], "harness binary SHA-256"
    )
    if "engine_binary_sha256" not in provenance:
        fail("engine binary SHA-256 is required")
    engine_hash = require_sha256(
        provenance["engine_binary_sha256"], "engine binary SHA-256"
    )

    expected_external_hash = {
        "xray-core": manifest["comparators"]["xray-core"]["binarySha256"],
        "sing-box": manifest["comparators"]["sing-box"]["binarySha256"],
    }.get(engine)
    if expected_external_hash is not None and engine_hash != expected_external_hash:
        fail(f"{engine} engine binary SHA-256 does not match manifest comparator")

    require_nonempty_string(
        provenance.get("working_directory"), "provenance working_directory"
    )
    invocation = provenance.get("invocation_args")
    if (
        not isinstance(invocation, list)
        or not invocation
        or any(not isinstance(item, str) or not item for item in invocation)
    ):
        fail("provenance invocation_args must be a non-empty string array")
    return harness_hash, engine_hash


def validate_summary(
    summary: Any,
    scenario: str,
    engine: str,
    expected: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[str, str]:
    summary = require_object(summary, f"summary for {scenario}/{engine}")
    run_id = require_nonempty_string(summary.get("run_id"), "summary run_id")
    if summary.get("engine") != engine:
        fail("summary engine does not match manifest")
    if summary.get("workload") != expected["workload"]:
        fail("summary workload does not match scenario")
    if summary.get("status") != "ok":
        fail("summary status must be ok")
    require_integer(summary.get("runs"), 5, "summary runs")
    require_positive_integer(summary.get("connections"), "summary connections")
    require_positive_integer(summary.get("iterations"), "summary iterations")
    require_positive_integer(summary.get("payload_size"), "summary payload_size")
    require_nonnegative_integer(summary.get("settle_ms"), "summary settle_ms")
    for field in (
        "stream_transport",
        "stream_traffic",
        "xhttp_mode",
        "xhttp_profile",
        "dns_transport",
        "dns_upstream_transport",
    ):
        require_optional_nonempty_string(summary.get(field), f"summary {field}")
    max_post_bytes = summary.get("xhttp_max_post_bytes")
    if max_post_bytes is not None:
        require_positive_integer(max_post_bytes, "summary xhttp_max_post_bytes")

    for field, expected_value in expected.items():
        if field == "workload":
            continue
        if not json_equal_strict(summary.get(field), expected_value):
            fail(
                f"summary {field} does not match scenario {scenario}: "
                f"expected {expected_value!r}"
            )

    hashes = validate_provenance(summary.get("provenance"), engine, manifest)
    results = summary.get("results")
    if not isinstance(results, list) or len(results) != 5:
        fail("summary must embed exactly 5 results")
    for index, result_value in enumerate(results, start=1):
        result = require_object(
            result_value, f"embedded result {index} for {scenario}/{engine}"
        )
        if result.get("status") != "ok":
            fail(f"embedded result {index} status must be ok")
        if (
            result.get("run_id") != run_id
            or result.get("engine") != summary.get("engine")
            or result.get("workload") != summary.get("workload")
            or any(
                not json_equal_strict(result.get(field), summary.get(field))
                for field in PARAMETER_FIELDS
            )
        ):
            fail(f"embedded result {index} parameters do not match summary")
        if not json_equal_strict(
            result.get("provenance"), summary.get("provenance")
        ):
            fail(f"embedded result {index} provenance does not match summary")
    return hashes


def validate_publication(publication_root: pathlib.Path) -> int:
    try:
        root = publication_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        fail(f"publication root does not exist: {error}")
    if not root.is_dir():
        fail("publication root must be a directory")

    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        fail("publication manifest.json does not exist")
    manifest = validate_manifest_shape(read_json(manifest_path, "manifest.json"))
    expected = expected_matrix()
    actual: dict[tuple[str, str], pathlib.Path] = {}

    for index, entry_value in enumerate(manifest["series"], start=1):
        entry = require_object(entry_value, f"series entry {index}")
        require_fields(entry, {"scenario", "engine", "summary"}, f"series entry {index}")
        scenario = require_nonempty_string(
            entry["scenario"], f"series entry {index} scenario"
        )
        engine = require_nonempty_string(
            entry["engine"], f"series entry {index} engine"
        )
        key = (scenario, engine)
        if key in actual:
            fail(f"duplicate series: {scenario}/{engine}")
        if key not in expected:
            fail(f"unexpected series combination: {scenario}/{engine}")
        actual[key] = safe_summary_path(root, entry["summary"])

    missing = sorted(expected.keys() - actual.keys())
    if missing:
        scenario, engine = missing[0]
        fail(f"missing required combination: {scenario}/{engine}")

    harness_hash: str | None = None
    engine_hashes: dict[str, str] = {}
    for scenario, engine in sorted(actual):
        summary_path = actual[(scenario, engine)]
        summary = read_json(
            summary_path,
            f"summary {summary_path.relative_to(root)}",
        )
        current_harness_hash, current_engine_hash = validate_summary(
            summary,
            scenario,
            engine,
            expected[(scenario, engine)],
            manifest,
        )
        if harness_hash is None:
            harness_hash = current_harness_hash
        elif harness_hash != current_harness_hash:
            fail("harness binary SHA-256 is inconsistent across summaries")
        prior_engine_hash = engine_hashes.setdefault(engine, current_engine_hash)
        if prior_engine_hash != current_engine_hash:
            fail(f"{engine} binary SHA-256 is inconsistent across summaries")

    return len(actual)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: check-benchmark-publication.py PUBLICATION_DIRECTORY",
            file=sys.stderr,
        )
        return 2
    try:
        count = validate_publication(pathlib.Path(argv[1]))
    except ValidationError as error:
        print(f"benchmark publication validation failed: {error}", file=sys.stderr)
        return 1
    print(f"validated benchmark publication: {count} series")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
