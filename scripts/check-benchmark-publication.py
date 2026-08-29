#!/usr/bin/env python3
"""Fail-closed validation for a committed benchmark publication."""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any, Iterable


XRAY_CORE_VERSION = "v26.7.28"
XRAY_CORE_REVISION = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
SING_BOX_BUILD_TAGS = "with_gvisor,with_utls,badlinkname,tfogo_checklinkname0"
SING_BOX_SOURCE_URL = "https://github.com/SagerNet/sing-box"
SEMVER_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
CANONICAL_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
LOWER_SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")

MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1

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

PROVENANCE_REQUIRED_FIELDS = {"harness_profile", "invocation_args"}
PROVENANCE_OPTIONAL_FIELDS = {
    "workspace_git",
    "engine_source_git",
    "harness_binary_path",
    "harness_binary_sha256",
    "engine_binary_path",
    "engine_binary_sha256",
    "working_directory",
}
GIT_REQUIRED_FIELDS = {"revision"}
GIT_OPTIONAL_FIELDS = {"dirty"}

SUMMARY_REQUIRED_FIELDS = {
    "run_id",
    "provenance",
    "engine",
    "workload",
    "status",
    "runs",
    "duration_ms",
    "transfer_duration_ms",
    "peak_rss_kib",
    "cpu_millis",
    "cpu_millis_per_gib",
    "throughput_mbps",
    "connections",
    "iterations",
    "payload_size",
    "settle_ms",
    "latency_us",
    "setup_us",
    "bytes_sent",
    "bytes_received",
    "results",
}
SUMMARY_OPTIONAL_FIELDS = {
    "stream_transport",
    "stream_traffic",
    "xhttp_mode",
    "xhttp_profile",
    "xhttp_max_post_bytes",
    "uplink_write_ops",
    "uplink_write_ops_per_second",
    "dns_transport",
    "dns_upstream_transport",
}

RESULT_REQUIRED_FIELDS = {
    "run_id",
    "run_index",
    "provenance",
    "engine",
    "workload",
    "status",
    "duration_ms",
    "transfer_duration_ms",
    "bytes_sent",
    "bytes_received",
    "peak_rss_kib",
    "cpu_millis",
    "cpu_millis_per_gib",
    "throughput_mbps",
    "connections",
    "iterations",
    "payload_size",
    "settle_ms",
    "latency_us",
    "setup_us",
    "samples",
}
RESULT_OPTIONAL_FIELDS = {
    "stream_transport",
    "stream_traffic",
    "xhttp_mode",
    "xhttp_profile",
    "xhttp_max_post_bytes",
    "memory_phases",
    "uplink_write_ops",
    "uplink_write_ops_per_second",
    "dns_transport",
    "dns_upstream_transport",
    "blackhole_connections_accepted",
    "blackhole_connections_active",
}

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
METRIC_FIELDS = {"min", "median", "p95"}
LATENCY_FIELDS = {"min", "median", "p95", "p99"}
SETUP_FIELDS = {
    "tcp_connect_us",
    "socks_method_us",
    "socks_connect_us",
    "socks_setup_us",
    "total_us",
}
MEMORY_PHASE_FIELDS = {
    "phase",
    "samples",
    "first_rss_kib",
    "median_rss_kib",
    "peak_rss_kib",
    "last_rss_kib",
}
MEMORY_PHASE_ORDER = {
    phase: index
    for index, phase in enumerate(
        ("startup", "workload", "opening", "traffic", "held-open", "settle", "complete")
    )
}

VALUE_FLAGS = {
    "--engine",
    "--workload",
    "--duration-ms",
    "--sample-interval-ms",
    "--run-timeout-ms",
    "--connections",
    "--iterations",
    "--payload-size",
    "--stream-transport",
    "--traffic",
    "--xhttp-mode",
    "--xhttp-profile",
    "--xhttp-max-post-bytes",
    "--settle-ms",
    "--transport",
    "--dns-upstream-transport",
    "--runs",
    "--out-dir",
    "--xray-rust-bin",
    "--xray-core-bin",
    "--sing-box-bin",
    "--xray-core-dir",
    "--sing-box-dir",
    "--geodata-dir",
}
BOOLEAN_FLAGS = {"--no-auto-build"}


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


def validate_json_limits(value: Any, label: str) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            fail(f"{label} exceeds validation node limit")
        if isinstance(current, (dict, list)):
            if depth > MAX_JSON_DEPTH:
                fail("JSON nesting exceeds validation limit")
            children: Iterable[Any]
            children = current.values() if isinstance(current, dict) else current
            stack.extend((child, depth + 1) for child in children)


def read_json(path: pathlib.Path, label: str) -> Any:
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"cannot read {label}: path is not a regular file")
        if metadata.st_size > MAX_JSON_BYTES:
            fail(f"{label} exceeds validation size limit")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = handle.read(MAX_JSON_BYTES + 1)
        if len(data) > MAX_JSON_BYTES:
            fail(f"{label} exceeds validation size limit")
        text = data.decode("utf-8")
    except ValidationError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        fail(f"cannot read {label}: {error}")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        value = json.loads(
            text,
            parse_constant=reject_json_constant,
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as error:
        fail(f"invalid JSON in {label}: {error}")
    validate_json_limits(value, label)
    return value


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
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


def require_serialized_fields(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    label: str,
) -> None:
    missing = sorted(required - value.keys())
    unexpected = sorted(value.keys() - required - optional)
    if missing:
        fail(f"{label}.{missing[0]} is required")
    if unexpected:
        fail(f"{label} has unexpected field: {unexpected[0]}")
    for field in sorted(optional & value.keys()):
        if value[field] is None:
            fail(f"{label}.{field} must be omitted rather than null")
        if field == "memory_phases" and value[field] == []:
            fail(f"{label}.memory_phases must be omitted rather than empty")


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


def require_bounded_integer(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        fail(f"{label} must be a non-negative integer")
    return value


def require_u64(value: Any, label: str) -> int:
    return require_bounded_integer(value, U64_MAX, label)


def require_u128(value: Any, label: str) -> int:
    return require_bounded_integer(value, U128_MAX, label)


def require_positive_u64(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0 or value > U64_MAX:
        fail(f"{label} must be a positive integer")
    return value


def require_optional_u64(value: Any, label: str) -> int | None:
    return None if value is None else require_u64(value, label)


def require_optional_u128(value: Any, label: str) -> int | None:
    return None if value is None else require_u128(value, label)


def json_equal_strict(left: Any, right: Any) -> bool:
    stack = [(left, right)]
    while stack:
        left_value, right_value = stack.pop()
        if type(left_value) is not type(right_value):
            return False
        if isinstance(left_value, dict):
            if left_value.keys() != right_value.keys():
                return False
            stack.extend((left_value[key], right_value[key]) for key in left_value)
        elif isinstance(left_value, list):
            if len(left_value) != len(right_value):
                return False
            stack.extend(zip(left_value, right_value))
        elif left_value != right_value:
            return False
    return True


def expected_matrix() -> dict[tuple[str, str], dict[str, Any]]:
    matrix: dict[tuple[str, str], dict[str, Any]] = {}
    all_engines = ("xray-rust", "xray-core", "sing-box")

    def add(
        scenario: str,
        engines: tuple[str, ...],
        *,
        workload: str,
        connections: int,
        iterations: int,
        payload_size: int,
        duration_ms: int,
        run_timeout_ms: int,
        output_name: str,
        stream_transport: str | None = None,
        stream_traffic: str | None = None,
        xhttp_mode: str | None = None,
        xhttp_profile: str | None = None,
        xhttp_max_post_bytes: int | None = None,
        explicit_xhttp_max_post_bytes: int | None = None,
        settle_ms: int = 0,
        supports_sing_box: bool = True,
        geodata: bool = False,
    ) -> None:
        fields = {
            "workload": workload,
            "connections": connections,
            "iterations": iterations,
            "payload_size": payload_size,
            "stream_transport": stream_transport,
            "stream_traffic": stream_traffic,
            "xhttp_mode": xhttp_mode,
            "xhttp_profile": xhttp_profile,
            "xhttp_max_post_bytes": xhttp_max_post_bytes,
            "settle_ms": settle_ms,
            "dns_transport": None,
            "dns_upstream_transport": None,
            "duration_ms_option": duration_ms,
            "sample_interval_ms": 100,
            "run_timeout_ms": run_timeout_ms,
            "explicit_xhttp_max_post_bytes": explicit_xhttp_max_post_bytes,
            "output_name": output_name,
            "supports_sing_box": supports_sing_box,
            "geodata": geodata,
        }
        for engine in engines:
            key = (scenario, engine)
            if key in matrix:
                raise AssertionError(f"duplicate required benchmark series: {key}")
            matrix[key] = fields.copy()

    base = {
        "idle": ("idle", 1, 1, 1_024, 5_000, 30_000, "base-idle"),
        "many-idle-flows-100": (
            "many-idle-flows",
            100,
            1,
            1_024,
            5_000,
            30_000,
            "base-flows-100",
        ),
        "many-idle-flows-1000": (
            "many-idle-flows",
            1_000,
            1,
            1_024,
            5_000,
            30_000,
            "base-flows-1000",
        ),
        "tcp-freedom": ("tcp-freedom", 1, 1_000, 1_024, 2_000, 30_000, "base-tcp"),
        "udp-freedom": ("udp-freedom", 1, 1_000, 512, 2_000, 30_000, "base-udp"),
        "reconnect-burst": (
            "reconnect-burst",
            16,
            25,
            1_024,
            2_000,
            30_000,
            "base-reconnect",
        ),
        "reality-vision-xudp": (
            "reality-vision-xudp",
            1,
            1_000,
            512,
            2_000,
            30_000,
            "base-reality-xudp",
        ),
        "tcp-bulk-throughput": (
            "tcp-bulk-throughput",
            1,
            2_048,
            4_194_304,
            2_000,
            300_000,
            "base-tcp-bulk",
        ),
        "reality-vision-bulk-throughput": (
            "reality-vision-bulk-throughput",
            1,
            256,
            4_194_304,
            2_000,
            120_000,
            "base-reality-bulk",
        ),
    }
    for scenario, values in base.items():
        add(
            scenario,
            all_engines,
            workload=values[0],
            connections=values[1],
            iterations=values[2],
            payload_size=values[3],
            duration_ms=values[4],
            run_timeout_ms=values[5],
            output_name=values[6],
        )

    add(
        "routed-tcp-freedom",
        ("xray-rust", "xray-core"),
        workload="routed-tcp-freedom",
        connections=8,
        iterations=100,
        payload_size=1_024,
        duration_ms=2_000,
        run_timeout_ms=120_000,
        output_name="base-geodata",
        supports_sing_box=False,
        geodata=True,
    )

    for transport in ("ws", "httpupgrade", "grpc"):
        for traffic in ("upload", "download", "full-duplex"):
            for flows in (1, 32):
                add(
                    f"stream-{transport}-{traffic}-{flows}",
                    all_engines,
                    workload="stream-transport",
                    connections=flows,
                    iterations=4_096,
                    payload_size=65_536,
                    duration_ms=2_000,
                    run_timeout_ms=300_000,
                    output_name=f"stream-{transport}-{traffic}-{flows}",
                    stream_transport=transport,
                    stream_traffic=traffic,
                )

    for transport in ("xhttp-h1", "xhttp-h2", "xhttp-h3"):
        for traffic in ("upload", "download", "full-duplex"):
            for flows in (1, 32):
                add(
                    f"stream-{transport}-{traffic}-{flows}",
                    ("xray-rust", "xray-core"),
                    workload="stream-transport",
                    connections=flows,
                    iterations=4_096,
                    payload_size=65_536,
                    duration_ms=2_000,
                    run_timeout_ms=300_000,
                    output_name=f"stream-{transport}-{traffic}-{flows}",
                    stream_transport=transport,
                    stream_traffic=traffic,
                    xhttp_mode="stream-up",
                    xhttp_max_post_bytes=65_536,
                    supports_sing_box=False,
                )

    for transport in ("xhttp-h1", "xhttp-h2", "xhttp-h3"):
        for flows in (1, 32):
            add(
                f"xhttp-pressure-{transport}-{flows}",
                ("xray-rust", "xray-core"),
                workload="stream-transport",
                connections=flows,
                iterations=4_096,
                payload_size=16_384,
                duration_ms=2_000,
                run_timeout_ms=300_000,
                output_name=f"xhttp-pressure-{transport}-{flows}",
                stream_transport=transport,
                stream_traffic="packet-up",
                xhttp_mode="packet-up",
                xhttp_max_post_bytes=16_384,
                supports_sing_box=False,
            )

    for flows in (1, 16, 32):
        add(
            f"xhttp-memory-held-open-{flows}-max-500000",
            ("xray-rust", "xray-core"),
            workload="stream-transport",
            connections=flows,
            iterations=1,
            payload_size=16_384,
            duration_ms=30_000,
            run_timeout_ms=155_000,
            output_name="xhttp-memory",
            stream_transport="xhttp-h1",
            stream_traffic="held-open",
            xhttp_mode="packet-up",
            xhttp_profile="legacy-extra-h1-packet-up",
            xhttp_max_post_bytes=500_000,
            explicit_xhttp_max_post_bytes=500_000,
            settle_ms=5_000,
            supports_sing_box=False,
        )
    add(
        "xhttp-memory-held-open-16-control-16384",
        ("xray-rust", "xray-core"),
        workload="stream-transport",
        connections=16,
        iterations=1,
        payload_size=16_384,
        duration_ms=30_000,
        run_timeout_ms=155_000,
        output_name="xhttp-memory",
        stream_transport="xhttp-h1",
        stream_traffic="held-open",
        xhttp_mode="packet-up",
        xhttp_profile="legacy-extra-h1-packet-up",
        xhttp_max_post_bytes=16_384,
        explicit_xhttp_max_post_bytes=16_384,
        settle_ms=5_000,
        supports_sing_box=False,
    )
    for flows in (1, 16):
        add(
            f"xhttp-memory-packet-up-{flows}-max-500000",
            ("xray-rust", "xray-core"),
            workload="stream-transport",
            connections=flows,
            iterations=1_000,
            payload_size=16_384,
            duration_ms=0,
            run_timeout_ms=300_000,
            output_name="xhttp-memory",
            stream_transport="xhttp-h1",
            stream_traffic="packet-up",
            xhttp_mode="packet-up",
            xhttp_profile="legacy-extra-h1-packet-up",
            xhttp_max_post_bytes=500_000,
            explicit_xhttp_max_post_bytes=500_000,
            settle_ms=5_000,
            supports_sing_box=False,
        )

    if len(matrix) != 143:
        raise AssertionError(f"benchmark publication matrix has {len(matrix)} entries")
    return matrix


def validate_manifest_shape(manifest: Any) -> dict[str, Any]:
    manifest = require_object(manifest, "manifest")
    require_exact_fields(manifest, MANIFEST_FIELDS, "manifest")
    require_integer(manifest["schemaVersion"], 1, "schemaVersion")

    publication_id = require_nonempty_string(manifest["publicationId"], "publicationId")
    measured_at = require_nonempty_string(manifest["measuredAt"], "measuredAt")
    if CANONICAL_DATE.fullmatch(measured_at) is None:
        fail("measuredAt must use canonical YYYY-MM-DD format")
    try:
        parsed_date = dt.date.fromisoformat(measured_at)
    except ValueError:
        fail("measuredAt must be a valid YYYY-MM-DD date")
    if parsed_date.isoformat() != measured_at:
        fail("measuredAt must use canonical YYYY-MM-DD format")
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
    require_sha256(xray["binarySha256"], "comparators.xray-core.binarySha256")
    if xray["buildCommand"] != "go build ./main":
        fail("comparators.xray-core.buildCommand must be go build ./main")

    sing = require_object(comparators["sing-box"], "comparators.sing-box")
    require_exact_fields(
        sing,
        {"version", "revision", "binarySha256", "buildTags", "sourceUrl"},
        "comparators.sing-box",
    )
    if not isinstance(sing["version"], str) or SEMVER_TAG.fullmatch(sing["version"]) is None:
        fail("comparators.sing-box.version must be a stable vMAJOR.MINOR.PATCH tag")
    require_sha40(sing["revision"], "comparators.sing-box.revision")
    require_sha256(sing["binarySha256"], "comparators.sing-box.binarySha256")
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


def resolve_manifest_path(root: pathlib.Path) -> pathlib.Path:
    candidate = root / "manifest.json"
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        fail("publication manifest.json does not exist")
    except (OSError, ValueError) as error:
        fail(f"cannot inspect manifest.json: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("manifest.json must be an in-root regular non-symlink file")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        fail("manifest.json must be an in-root regular non-symlink file")
    return resolved


def safe_summary_path(root: pathlib.Path, relative: Any) -> pathlib.Path:
    relative = require_nonempty_string(relative, "series summary")
    try:
        relative_path = pathlib.Path(relative)
        if relative_path.is_absolute():
            fail("summary path escapes publication root")
        candidate = root / relative_path
        lexical = candidate.resolve(strict=False)
        lexical.relative_to(root)
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except ValidationError:
        raise
    except FileNotFoundError:
        fail(f"summary file does not exist: {relative}")
    except ValueError as error:
        if "embedded null byte" in str(error).lower():
            fail(f"invalid summary path: {error}")
        fail("summary path escapes publication root")
    except (OSError, RuntimeError) as error:
        fail(f"invalid summary path: {error}")
    if stat.S_ISLNK(metadata.st_mode):
        fail(f"summary file does not exist: {relative}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"summary file does not exist: {relative}")
    return resolved


def validate_git_state(value: Any, label: str, expected_revision: str) -> None:
    state = require_object(value, label)
    require_serialized_fields(state, GIT_REQUIRED_FIELDS, GIT_OPTIONAL_FIELDS, label)
    revision = require_sha40(state["revision"], f"{label}.revision")
    if revision != expected_revision:
        fail(f"{label}.revision does not match publication provenance")
    if state.get("dirty") is not False:
        if label == "workspace_git":
            fail("workspace provenance must be clean")
        fail("engine source provenance must be clean")


def require_absolute_path(value: Any, label: str) -> pathlib.Path:
    path_text = require_nonempty_string(value, label)
    try:
        path = pathlib.Path(path_text)
    except (OSError, ValueError) as error:
        fail(f"{label} is invalid: {error}")
    if not path.is_absolute() or ".." in path.parts:
        fail(f"{label} must be a canonical absolute path")
    return path


def expected_paths(
    working_directory: pathlib.Path,
    manifest: dict[str, Any],
) -> dict[str, pathlib.Path]:
    raw_root = (
        working_directory
        / "target"
        / "benchmarks"
        / manifest["publicationId"]
    )
    return {
        "raw_root": raw_root,
        "harness": working_directory / "target" / "release" / "xray-bench",
        "xray-rust": working_directory / "target" / "release" / "xray-rust",
        "xray-core": (
            working_directory
            / "target"
            / "bench-bin"
            / f"xray-core-{XRAY_CORE_VERSION}"
        ),
        "sing-box": (
            raw_root
            / "comparators"
            / "bin"
            / f"sing-box-{manifest['comparators']['sing-box']['version']}"
        ),
        "xray-core-dir": working_directory / "Xray-core",
        "sing-box-dir": raw_root / "comparators" / "sing-box",
        "geodata-dir": raw_root / "comparators" / "geodata",
    }


def validate_provenance(
    provenance_value: Any,
    engine: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    provenance = require_object(provenance_value, "summary provenance")
    require_serialized_fields(
        provenance,
        PROVENANCE_REQUIRED_FIELDS,
        PROVENANCE_OPTIONAL_FIELDS,
        "summary provenance",
    )
    if provenance["harness_profile"] != "release":
        fail("harness profile must be release")

    if "workspace_git" not in provenance:
        fail("workspace_git provenance is required")
    validate_git_state(
        provenance["workspace_git"],
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
        fail(f"{engine} engine source provenance is required")
    validate_git_state(engine_source, "engine_source_git", engine_revision)

    for field, message in (
        ("harness_binary_path", "harness binary path is required"),
        ("engine_binary_path", "engine binary path is required"),
        ("working_directory", "provenance working_directory is required"),
    ):
        if field not in provenance:
            fail(message)
    for field, message in (
        ("harness_binary_sha256", "harness binary SHA-256 is required"),
        ("engine_binary_sha256", "engine binary SHA-256 is required"),
    ):
        if field not in provenance:
            fail(message)

    working_directory = require_absolute_path(
        provenance["working_directory"], "provenance working_directory"
    )
    paths = expected_paths(working_directory, manifest)
    harness_path = require_absolute_path(
        provenance["harness_binary_path"], "harness binary path"
    )
    engine_path = require_absolute_path(
        provenance["engine_binary_path"], "engine binary path"
    )
    if harness_path != paths["harness"]:
        fail("harness binary path does not match the release harness")
    if engine_path != paths[engine]:
        fail(
            "engine binary path does not match the recorded benchmark binary: "
            f"expected {paths[engine]}, found {engine_path}"
        )

    harness_hash = require_sha256(
        provenance["harness_binary_sha256"], "harness binary SHA-256"
    )
    engine_hash = require_sha256(
        provenance["engine_binary_sha256"], "engine binary SHA-256"
    )
    expected_external_hash = {
        "xray-core": manifest["comparators"]["xray-core"]["binarySha256"],
        "sing-box": manifest["comparators"]["sing-box"]["binarySha256"],
    }.get(engine)
    if expected_external_hash is not None and engine_hash != expected_external_hash:
        fail(f"{engine} engine binary SHA-256 does not match manifest comparator")

    invocation = provenance["invocation_args"]
    if (
        not isinstance(invocation, list)
        or not invocation
        or any(not isinstance(item, str) or not item for item in invocation)
    ):
        fail("provenance invocation_args must be a non-empty string array")

    return {
        "working_directory": str(working_directory),
        "harness_path": str(harness_path),
        "harness_hash": harness_hash,
        "engine_path": str(engine_path),
        "engine_hash": engine_hash,
        "paths": paths,
        "invocation": invocation,
    }


def expected_invocation_flags(expected: dict[str, Any]) -> list[str]:
    flags = [
        "--engine",
        "--workload",
        "--duration-ms",
        "--sample-interval-ms",
        "--run-timeout-ms",
        "--connections",
        "--iterations",
        "--payload-size",
    ]
    if expected["workload"] == "stream-transport":
        flags.extend(("--stream-transport", "--traffic"))
        if expected["xhttp_mode"] is not None:
            flags.append("--xhttp-mode")
        if expected["xhttp_profile"] is not None:
            flags.append("--xhttp-profile")
        if expected["explicit_xhttp_max_post_bytes"] is not None:
            flags.append("--xhttp-max-post-bytes")
        flags.append("--settle-ms")
    flags.extend(
        (
            "--transport",
            "--dns-upstream-transport",
            "--runs",
            "--out-dir",
            "--xray-rust-bin",
            "--xray-core-bin",
        )
    )
    if expected["supports_sing_box"]:
        flags.append("--sing-box-bin")
    flags.append("--xray-core-dir")
    if expected["supports_sing_box"]:
        flags.append("--sing-box-dir")
    flags.append("--no-auto-build")
    if expected["geodata"]:
        flags.append("--geodata-dir")
    return flags


def parse_invocation(invocation: list[str], expected: dict[str, Any]) -> dict[str, str | bool]:
    if invocation[0] != "run":
        fail("invocation_args must begin with run")
    values: dict[str, str | bool] = {}
    order: list[str] = []
    index = 1
    while index < len(invocation):
        flag = invocation[index]
        if flag not in VALUE_FLAGS and flag not in BOOLEAN_FLAGS:
            fail(f"invocation_args contains unexpected flag: {flag}")
        if flag in values:
            fail(f"invocation_args contains duplicate flag: {flag}")
        order.append(flag)
        if flag in BOOLEAN_FLAGS:
            values[flag] = True
            index += 1
            continue
        if index + 1 >= len(invocation) or invocation[index + 1].startswith("--"):
            fail("invocation_args flags do not match canonical harness order")
        values[flag] = invocation[index + 1]
        index += 2
    if order != expected_invocation_flags(expected):
        fail("invocation_args flags do not match canonical harness order")
    return values


def validate_invocation(
    scenario: str,
    engine: str,
    expected: dict[str, Any],
    manifest: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, str]:
    values = parse_invocation(provenance["invocation"], expected)

    fixed_values = {
        "--engine": engine,
        "--workload": expected["workload"],
        "--duration-ms": str(expected["duration_ms_option"]),
        "--sample-interval-ms": str(expected["sample_interval_ms"]),
        "--run-timeout-ms": str(expected["run_timeout_ms"]),
        "--connections": str(expected["connections"]),
        "--iterations": str(expected["iterations"]),
        "--payload-size": str(expected["payload_size"]),
        "--transport": "both",
        "--dns-upstream-transport": "classic",
        "--runs": "5",
    }
    if expected["workload"] == "stream-transport":
        fixed_values.update(
            {
                "--stream-transport": expected["stream_transport"],
                "--traffic": expected["stream_traffic"],
                "--settle-ms": str(expected["settle_ms"]),
            }
        )
        if expected["xhttp_mode"] is not None:
            fixed_values["--xhttp-mode"] = expected["xhttp_mode"]
        if expected["xhttp_profile"] is not None:
            fixed_values["--xhttp-profile"] = expected["xhttp_profile"]
        if expected["explicit_xhttp_max_post_bytes"] is not None:
            fixed_values["--xhttp-max-post-bytes"] = str(
                expected["explicit_xhttp_max_post_bytes"]
            )
    for flag, expected_value in fixed_values.items():
        if values[flag] != expected_value:
            fail(f"invocation {flag} does not match scenario {scenario}")

    paths: dict[str, pathlib.Path] = provenance["paths"]
    binary_values = {
        "xray-rust": require_absolute_path(values["--xray-rust-bin"], "xray-rust binary path"),
        "xray-core": require_absolute_path(values["--xray-core-bin"], "xray-core binary path"),
    }
    if expected["supports_sing_box"]:
        binary_values["sing-box"] = require_absolute_path(
            values["--sing-box-bin"], "sing-box binary path"
        )
    for binary_engine, binary_path in binary_values.items():
        if binary_path != paths[binary_engine]:
            fail("invocation binary path does not match provenance")
    if str(binary_values[engine]) != provenance["engine_path"]:
        fail("invocation binary path does not match provenance")

    xray_core_dir = require_absolute_path(values["--xray-core-dir"], "xray-core source path")
    if xray_core_dir != paths["xray-core-dir"]:
        fail("xray-core source path must end in Xray-core")
    if expected["supports_sing_box"]:
        sing_box_dir = require_absolute_path(values["--sing-box-dir"], "sing-box source path")
        if sing_box_dir != paths["sing-box-dir"]:
            fail("sing-box source path does not match the dated comparator checkout")

    output_path = require_absolute_path(values["--out-dir"], "invocation output path")
    expected_output = paths["raw_root"] / expected["output_name"]
    if output_path != expected_output:
        fail("invocation output path does not match scenario")

    if expected["geodata"]:
        geodata_path = require_absolute_path(values["--geodata-dir"], "geodata path")
        if geodata_path != paths["geodata-dir"]:
            fail("invocation geodata path does not match the dated comparator data")

    return {
        "xray_rust_binary": str(binary_values["xray-rust"]),
        "xray_core_binary": str(binary_values["xray-core"]),
        "xray_core_dir": str(xray_core_dir),
        **(
            {
                "sing_box_binary": str(binary_values["sing-box"]),
                "sing_box_dir": str(paths["sing-box-dir"]),
            }
            if expected["supports_sing_box"]
            else {}
        ),
        **({"geodata_dir": str(paths["geodata-dir"])} if expected["geodata"] else {}),
    }


def validate_metric(value: Any, label: str) -> dict[str, int]:
    metric = require_object(value, label)
    if set(metric) != METRIC_FIELDS:
        fail(f"{label} must contain exactly min, median, and p95")
    result = {field: require_u128(metric[field], f"{label}.{field}") for field in METRIC_FIELDS}
    if not result["min"] <= result["median"] <= result["p95"]:
        fail(f"{label} must satisfy min <= median <= p95")
    return result


def validate_optional_metric(value: Any, label: str) -> dict[str, int] | None:
    return None if value is None else validate_metric(value, label)


def validate_latency(value: Any, label: str) -> dict[str, int]:
    latency = require_object(value, label)
    require_exact_fields(latency, LATENCY_FIELDS, label)
    result = {
        field: require_u128(latency[field], f"{label}.{field}")
        for field in LATENCY_FIELDS
    }
    if not result["min"] <= result["median"] <= result["p95"] <= result["p99"]:
        fail(f"{label} must satisfy min <= median <= p95 <= p99")
    return result


def validate_latency_aggregate(value: Any, label: str) -> dict[str, dict[str, int]]:
    aggregate = require_object(value, label)
    require_exact_fields(aggregate, LATENCY_FIELDS, label)
    return {
        field: validate_metric(aggregate[field], f"{label}.{field}")
        for field in LATENCY_FIELDS
    }


def validate_setup(value: Any, label: str) -> dict[str, dict[str, int]]:
    setup = require_object(value, label)
    require_exact_fields(setup, SETUP_FIELDS, label)
    return {
        field: validate_latency(setup[field], f"{label}.{field}")
        for field in SETUP_FIELDS
    }


def validate_setup_aggregate(
    value: Any, label: str
) -> dict[str, dict[str, dict[str, int]]]:
    setup = require_object(value, label)
    require_exact_fields(setup, SETUP_FIELDS, label)
    return {
        field: validate_latency_aggregate(setup[field], f"{label}.{field}")
        for field in SETUP_FIELDS
    }


def expected_memory_phases(expected: dict[str, Any]) -> tuple[set[str], set[str]]:
    allowed = {"startup", "workload", "complete"}
    required = {"startup", "complete"}
    workload = expected["workload"]
    if workload in {"idle", "many-idle-flows"}:
        required.add("workload")
    if workload == "stream-transport":
        allowed.add("opening")
        if expected["stream_traffic"] == "held-open":
            allowed.add("held-open")
            required.add("held-open")
        else:
            allowed.add("traffic")
        if expected["settle_ms"] > 0:
            allowed.add("settle")
            required.add("settle")
    return allowed, required


def validate_memory_phases(
    value: Any,
    result_samples: int,
    result_peak_rss_kib: int,
    expected: dict[str, Any],
    label: str,
) -> None:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be a non-empty array")
    prior_order = -1
    sample_total = 0
    peak_rss_kib_values: list[int] = []
    phase_names: list[str] = []
    allowed_phases, required_phases = expected_memory_phases(expected)
    for index, phase_value in enumerate(value, start=1):
        phase_label = f"{label}[{index}]"
        phase = require_object(phase_value, phase_label)
        require_exact_fields(phase, MEMORY_PHASE_FIELDS, phase_label)
        phase_name = phase["phase"]
        if not isinstance(phase_name, str) or phase_name not in MEMORY_PHASE_ORDER:
            fail(f"{phase_label}.phase is not a serialized BenchmarkPhase")
        if phase_name not in allowed_phases:
            fail(f"{phase_label}.phase is not available for this workload")
        phase_order = MEMORY_PHASE_ORDER[phase_name]
        if phase_order <= prior_order:
            fail(f"{label} phases must be unique and in harness order")
        prior_order = phase_order
        phase_names.append(phase_name)
        samples = require_positive_u64(phase["samples"], f"{phase_label}.samples")
        sample_total += samples
        first = require_u64(phase["first_rss_kib"], f"{phase_label}.first_rss_kib")
        median = require_u64(phase["median_rss_kib"], f"{phase_label}.median_rss_kib")
        peak = require_u64(phase["peak_rss_kib"], f"{phase_label}.peak_rss_kib")
        peak_rss_kib_values.append(peak)
        last = require_u64(phase["last_rss_kib"], f"{phase_label}.last_rss_kib")
        if max(first, median, last) > peak:
            fail(f"{phase_label} RSS values exceed its peak")
        if peak > result_peak_rss_kib:
            fail(f"{phase_label}.peak_rss_kib exceeds result peak_rss_kib")
    if phase_names[0] != "startup" or phase_names[-1] != "complete":
        fail(f"{label} must begin at startup and end at complete")
    missing_phases = required_phases - set(phase_names)
    if missing_phases:
        missing_phase = min(missing_phases, key=MEMORY_PHASE_ORDER.__getitem__)
        fail(f"{label} is missing required {missing_phase} phase")
    if sample_total != result_samples:
        fail(f"{label} sample counts do not match result samples")
    if max(peak_rss_kib_values) != result_peak_rss_kib:
        fail(f"{label} peak does not match result peak_rss_kib")


def ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def expected_workload_bytes(expected: dict[str, Any]) -> tuple[int, int]:
    total = (
        expected["connections"]
        * expected["iterations"]
        * expected["payload_size"]
    )
    if expected["workload"] == "stream-transport":
        traffic = expected["stream_traffic"]
        if traffic == "held-open":
            return 0, 0
        return (
            total if traffic in {"upload", "full-duplex", "packet-up"} else 0,
            total if traffic in {"download", "full-duplex"} else 0,
        )
    if expected["workload"] in {"idle", "many-idle-flows", "reconnect-burst"}:
        return 0, 0
    if expected["workload"] in {
        "tcp-bulk-throughput",
        "reality-vision-bulk-throughput",
    }:
        return 0, total
    return total, total


def expected_metric_availability(expected: dict[str, Any]) -> dict[str, bool]:
    workload = expected["workload"]
    transfer = workload in {
        "tcp-bulk-throughput",
        "reality-vision-bulk-throughput",
    } or (
        workload == "stream-transport"
        and expected["stream_traffic"] != "held-open"
    )
    latency = workload in {
        "tcp-freedom",
        "udp-freedom",
        "many-idle-flows",
        "reconnect-burst",
        "reality-vision-xudp",
        "routed-tcp-freedom",
    }
    setup = workload == "stream-transport" or workload in {
        "many-idle-flows",
        "reconnect-burst",
        "routed-tcp-freedom",
    }
    return {"transfer_duration_ms": transfer, "latency_us": latency, "setup_us": setup}


def minimum_result_duration_ms(expected: dict[str, Any]) -> int:
    workload = expected["workload"]
    if workload in {"idle", "many-idle-flows"}:
        return expected["duration_ms_option"]
    if workload == "stream-transport":
        # The harness samples both the initial cleanup window and a second
        # stable post-cleanup window, each lasting the configured settle time.
        minimum = expected["settle_ms"] * 2
        if expected["stream_traffic"] == "held-open":
            minimum += expected["duration_ms_option"]
        return minimum
    return 0


def summarize_metric(values: Iterable[int]) -> dict[str, int]:
    ordered = sorted(values)
    if not ordered:
        raise AssertionError("cannot aggregate an empty required metric")
    length = len(ordered)
    if length % 2:
        median = ordered[length // 2]
    else:
        median = (ordered[length // 2 - 1] + ordered[length // 2]) // 2
    rank = ceil_div(length * 95, 100)
    return {"min": ordered[0], "median": median, "p95": ordered[rank - 1]}


def summarize_optional_metric(values: Iterable[int | None]) -> dict[str, int] | None:
    present = [value for value in values if value is not None]
    return summarize_metric(present) if present else None


def summarize_latency_aggregate(
    values: Iterable[dict[str, int] | None],
) -> dict[str, dict[str, int]] | None:
    present = [value for value in values if value is not None]
    if not present:
        return None
    return {
        field: summarize_metric(value[field] for value in present)
        for field in LATENCY_FIELDS
    }


def summarize_setup_aggregate(
    values: Iterable[dict[str, dict[str, int]] | None],
) -> dict[str, dict[str, dict[str, int]]] | None:
    present = [value for value in values if value is not None]
    if not present:
        return None
    return {
        field: summarize_latency_aggregate(value[field] for value in present)
        for field in SETUP_FIELDS
    }


def validate_result_metrics(
    result: dict[str, Any],
    index: int,
    expected: dict[str, Any],
) -> dict[str, Any]:
    label = f"embedded result {index}"
    duration_ms = require_u128(result["duration_ms"], f"{label}.duration_ms")
    if duration_ms < minimum_result_duration_ms(expected):
        fail(f"{label}.duration_ms is shorter than the canonical workload minimum")
    transfer_duration_ms = require_optional_u128(
        result["transfer_duration_ms"], f"{label}.transfer_duration_ms"
    )
    availability = expected_metric_availability(expected)
    if (transfer_duration_ms is not None) != availability["transfer_duration_ms"]:
        fail(f"{label}.transfer_duration_ms availability does not match workload")
    if transfer_duration_ms is not None and transfer_duration_ms > duration_ms:
        fail(f"{label}.transfer_duration_ms exceeds duration_ms")
    bytes_sent = require_u64(result["bytes_sent"], f"{label}.bytes_sent")
    bytes_received = require_u64(result["bytes_received"], f"{label}.bytes_received")
    if (bytes_sent, bytes_received) != expected_workload_bytes(expected):
        fail(f"{label} bytes do not match workload parameters")
    peak_rss_kib = require_u64(result["peak_rss_kib"], f"{label}.peak_rss_kib")
    cpu_millis = require_u64(result["cpu_millis"], f"{label}.cpu_millis")
    cpu_millis_per_gib = require_optional_u128(
        result["cpu_millis_per_gib"], f"{label}.cpu_millis_per_gib"
    )
    throughput_mbps = require_optional_u128(
        result["throughput_mbps"], f"{label}.throughput_mbps"
    )
    require_u128(result["settle_ms"], f"{label}.settle_ms")
    samples = require_u64(result["samples"], f"{label}.samples")
    if samples < 2:
        fail(f"{label}.samples must include startup and completion samples")

    total_bytes = bytes_sent + bytes_received
    expected_cpu_per_gib = (
        ceil_div(cpu_millis * 1024 * 1024 * 1024, total_bytes)
        if total_bytes
        else None
    )
    if cpu_millis_per_gib != expected_cpu_per_gib:
        fail(f"{label}.cpu_millis_per_gib does not match bytes and CPU")
    throughput_duration = (
        transfer_duration_ms if transfer_duration_ms is not None else duration_ms
    )
    expected_throughput = (
        ceil_div(total_bytes * 8, throughput_duration * 1_000)
        if total_bytes and throughput_duration
        else None
    )
    if throughput_mbps != expected_throughput:
        fail(f"{label}.throughput_mbps does not match bytes and duration")

    latency = (
        None
        if result["latency_us"] is None
        else validate_latency(result["latency_us"], f"{label}.latency_us")
    )
    setup = (
        None
        if result["setup_us"] is None
        else validate_setup(result["setup_us"], f"{label}.setup_us")
    )
    if (latency is not None) != availability["latency_us"]:
        fail(f"{label}.latency_us availability does not match workload")
    if (setup is not None) != availability["setup_us"]:
        fail(f"{label}.setup_us availability does not match workload")
    if "memory_phases" not in result:
        fail(f"{label}.memory_phases is required for a successful harness run")
    validate_memory_phases(
        result["memory_phases"],
        samples,
        peak_rss_kib,
        expected,
        f"{label}.memory_phases",
    )

    uplink_write_ops = require_optional_u64(
        result.get("uplink_write_ops"), f"{label}.uplink_write_ops"
    )
    uplink_rate = require_optional_u128(
        result.get("uplink_write_ops_per_second"),
        f"{label}.uplink_write_ops_per_second",
    )
    if result.get("stream_traffic") == "packet-up":
        expected_ops = result["connections"] * result["iterations"]
        if uplink_write_ops != expected_ops:
            fail(f"{label}.uplink_write_ops does not match packet-up operations")
        if uplink_rate is None or uplink_rate == 0:
            fail(f"{label}.uplink_write_ops_per_second must be positive")
        if transfer_duration_ms is None:
            fail(f"{label}.uplink_write_ops_per_second requires a transfer duration")
        rate_numerator = uplink_write_ops * 1_000_000_000
        minimum_duration_ns = max(1, transfer_duration_ms * 1_000_000)
        maximum_duration_ns = (transfer_duration_ms + 1) * 1_000_000 - 1
        minimum_rate = ceil_div(rate_numerator, maximum_duration_ns)
        maximum_rate = ceil_div(rate_numerator, minimum_duration_ns)
        if not minimum_rate <= uplink_rate <= maximum_rate:
            fail(
                f"{label}.uplink_write_ops_per_second is outside "
                "transfer-duration bounds"
            )
    elif uplink_write_ops is not None or uplink_rate is not None:
        fail(f"{label} has packet-up metrics for a non-packet-up scenario")

    for field in ("blackhole_connections_accepted", "blackhole_connections_active"):
        if field in result:
            require_u64(result[field], f"{label}.{field}")
            fail(f"{label}.{field} is not part of the publication matrix")

    return {
        "duration_ms": duration_ms,
        "transfer_duration_ms": transfer_duration_ms,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "peak_rss_kib": peak_rss_kib,
        "cpu_millis": cpu_millis,
        "cpu_millis_per_gib": cpu_millis_per_gib,
        "throughput_mbps": throughput_mbps,
        "uplink_write_ops": uplink_write_ops,
        "uplink_write_ops_per_second": uplink_rate,
        "latency_us": latency,
        "setup_us": setup,
    }


def validate_aggregate(
    actual: Any,
    expected: Any,
    label: str,
) -> None:
    if not json_equal_strict(actual, expected):
        fail(f"{label} does not match embedded results")


def validate_summary(
    summary_value: Any,
    scenario: str,
    engine: str,
    expected: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    summary = require_object(summary_value, f"summary for {scenario}/{engine}")
    if "run_id" not in summary:
        fail("summary run_id must be non-empty")
    require_serialized_fields(
        summary,
        SUMMARY_REQUIRED_FIELDS,
        SUMMARY_OPTIONAL_FIELDS,
        "summary",
    )
    run_id = require_nonempty_string(summary["run_id"], "summary run_id")
    if summary["engine"] != engine:
        fail("summary engine does not match manifest")
    if summary["workload"] != expected["workload"]:
        fail("summary workload does not match scenario")
    if summary["status"] != "ok":
        fail("summary status must be ok")
    require_integer(summary["runs"], 5, "summary runs")

    for field in ("connections", "iterations", "payload_size"):
        require_positive_u64(summary[field], f"summary {field}")
        if not json_equal_strict(summary[field], expected[field]):
            fail(f"summary {field} does not match scenario {scenario}")
    require_u128(summary["settle_ms"], "summary settle_ms")
    if not json_equal_strict(summary["settle_ms"], expected["settle_ms"]):
        fail(f"summary settle_ms does not match scenario {scenario}")

    for field in (
        "stream_transport",
        "stream_traffic",
        "xhttp_mode",
        "xhttp_profile",
        "dns_transport",
        "dns_upstream_transport",
    ):
        actual = summary.get(field)
        if actual is not None:
            require_nonempty_string(actual, f"summary {field}")
        if not json_equal_strict(actual, expected[field]):
            fail(f"summary {field} does not match scenario {scenario}")
    max_post_bytes = summary.get("xhttp_max_post_bytes")
    if max_post_bytes is not None:
        require_positive_u64(max_post_bytes, "summary xhttp_max_post_bytes")
    if not json_equal_strict(max_post_bytes, expected["xhttp_max_post_bytes"]):
        fail(f"summary xhttp_max_post_bytes does not match scenario {scenario}")

    results_value = summary["results"]
    if not isinstance(results_value, list) or len(results_value) != 5:
        fail("summary must embed exactly 5 results")

    provenance = validate_provenance(summary["provenance"], engine, manifest)
    invocation_paths = validate_invocation(
        scenario, engine, expected, manifest, provenance
    )

    summary_metrics = {
        "duration_ms": validate_metric(summary["duration_ms"], "summary.duration_ms"),
        "transfer_duration_ms": validate_optional_metric(
            summary["transfer_duration_ms"], "summary.transfer_duration_ms"
        ),
        "peak_rss_kib": validate_metric(summary["peak_rss_kib"], "summary.peak_rss_kib"),
        "cpu_millis": validate_metric(summary["cpu_millis"], "summary.cpu_millis"),
        "cpu_millis_per_gib": validate_optional_metric(
            summary["cpu_millis_per_gib"], "summary.cpu_millis_per_gib"
        ),
        "throughput_mbps": validate_optional_metric(
            summary["throughput_mbps"], "summary.throughput_mbps"
        ),
        "bytes_sent": validate_metric(summary["bytes_sent"], "summary.bytes_sent"),
        "bytes_received": validate_metric(
            summary["bytes_received"], "summary.bytes_received"
        ),
        "uplink_write_ops": validate_optional_metric(
            summary.get("uplink_write_ops"), "summary.uplink_write_ops"
        ),
        "uplink_write_ops_per_second": validate_optional_metric(
            summary.get("uplink_write_ops_per_second"),
            "summary.uplink_write_ops_per_second",
        ),
    }
    summary_latency = (
        None
        if summary["latency_us"] is None
        else validate_latency_aggregate(summary["latency_us"], "summary.latency_us")
    )
    summary_setup = (
        None
        if summary["setup_us"] is None
        else validate_setup_aggregate(summary["setup_us"], "summary.setup_us")
    )
    availability = expected_metric_availability(expected)
    for field, value in (
        ("transfer_duration_ms", summary_metrics["transfer_duration_ms"]),
        ("latency_us", summary_latency),
        ("setup_us", summary_setup),
    ):
        if (value is not None) != availability[field]:
            fail(f"summary.{field} availability does not match workload")

    result_metrics: list[dict[str, Any]] = []
    for index, result_value in enumerate(results_value, start=1):
        result = require_object(
            result_value, f"embedded result {index} for {scenario}/{engine}"
        )
        require_serialized_fields(
            result,
            RESULT_REQUIRED_FIELDS,
            RESULT_OPTIONAL_FIELDS,
            f"embedded result {index}",
        )
        run_index = require_positive_u64(
            result["run_index"], f"embedded result {index}.run_index"
        )
        if run_index != index:
            fail("embedded result run_index values must be exactly 1..5")
        if result["status"] != "ok":
            fail(f"embedded result {index} status must be ok")
        if (
            result["run_id"] != run_id
            or result["engine"] != summary["engine"]
            or result["workload"] != summary["workload"]
            or any(
                not json_equal_strict(result.get(field), summary.get(field))
                for field in PARAMETER_FIELDS
            )
        ):
            fail(f"embedded result {index} parameters do not match summary")
        if not json_equal_strict(result["provenance"], summary["provenance"]):
            fail(f"embedded result {index} provenance does not match summary")
        result_metrics.append(validate_result_metrics(result, index, expected))

    aggregate_inputs = {
        "duration_ms": summarize_metric(item["duration_ms"] for item in result_metrics),
        "transfer_duration_ms": summarize_optional_metric(
            item["transfer_duration_ms"] for item in result_metrics
        ),
        "peak_rss_kib": summarize_metric(item["peak_rss_kib"] for item in result_metrics),
        "cpu_millis": summarize_metric(item["cpu_millis"] for item in result_metrics),
        "cpu_millis_per_gib": summarize_optional_metric(
            item["cpu_millis_per_gib"] for item in result_metrics
        ),
        "throughput_mbps": summarize_optional_metric(
            item["throughput_mbps"] for item in result_metrics
        ),
        "bytes_sent": summarize_metric(item["bytes_sent"] for item in result_metrics),
        "bytes_received": summarize_metric(item["bytes_received"] for item in result_metrics),
        "uplink_write_ops": summarize_optional_metric(
            item["uplink_write_ops"] for item in result_metrics
        ),
        "uplink_write_ops_per_second": summarize_optional_metric(
            item["uplink_write_ops_per_second"] for item in result_metrics
        ),
    }
    for field, expected_aggregate in aggregate_inputs.items():
        validate_aggregate(summary_metrics[field], expected_aggregate, f"summary.{field}")
    validate_aggregate(
        summary_latency,
        summarize_latency_aggregate(item["latency_us"] for item in result_metrics),
        "summary.latency_us",
    )
    validate_aggregate(
        summary_setup,
        summarize_setup_aggregate(item["setup_us"] for item in result_metrics),
        "summary.setup_us",
    )

    return {"run_id": run_id, **provenance, **invocation_paths}


def require_consistent(
    consistency: dict[str, str],
    key: str,
    value: str,
    message: str,
) -> None:
    prior = consistency.setdefault(key, value)
    if prior != value:
        fail(message)


def validate_publication(publication_root: pathlib.Path) -> int:
    try:
        root = publication_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        fail(f"publication root does not exist: {error}")
    if not root.is_dir():
        fail("publication root must be a directory")

    manifest_path = resolve_manifest_path(root)
    manifest = validate_manifest_shape(read_json(manifest_path, "manifest.json"))
    if root.name != manifest["publicationId"]:
        fail("publication root basename must match publicationId")

    expected = expected_matrix()
    actual: dict[tuple[str, str], pathlib.Path] = {}
    for index, entry_value in enumerate(manifest["series"], start=1):
        entry = require_object(entry_value, f"series entry {index}")
        require_fields(entry, {"scenario", "engine", "summary"}, f"series entry {index}")
        scenario = require_nonempty_string(
            entry["scenario"], f"series entry {index} scenario"
        )
        engine = require_nonempty_string(entry["engine"], f"series entry {index} engine")
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

    consistency: dict[str, str] = {}
    scenario_run_ids: dict[str, str] = {}
    run_id_scenarios: dict[str, str] = {}
    for scenario, engine in sorted(actual):
        summary_path = actual[(scenario, engine)]
        summary = read_json(summary_path, f"summary {summary_path.relative_to(root)}")
        info = validate_summary(
            summary,
            scenario,
            engine,
            expected[(scenario, engine)],
            manifest,
        )
        prior_run_id = scenario_run_ids.setdefault(scenario, info["run_id"])
        if prior_run_id != info["run_id"]:
            fail("scenario run_id is inconsistent across engines")
        prior_scenario = run_id_scenarios.setdefault(info["run_id"], scenario)
        if prior_scenario != scenario:
            fail("run_id must be distinct across benchmark scenarios")
        require_consistent(
            consistency,
            "working_directory",
            info["working_directory"],
            "provenance working_directory is inconsistent across summaries",
        )
        require_consistent(
            consistency,
            "harness_path",
            info["harness_path"],
            "harness binary path is inconsistent across summaries",
        )
        require_consistent(
            consistency,
            "harness_hash",
            info["harness_hash"],
            "harness binary SHA-256 is inconsistent across summaries",
        )
        require_consistent(
            consistency,
            f"{engine}_path",
            info["engine_path"],
            f"{engine} binary path is inconsistent across summaries",
        )
        require_consistent(
            consistency,
            f"{engine}_hash",
            info["engine_hash"],
            f"{engine} binary SHA-256 is inconsistent across summaries",
        )
        for key in (
            "xray_rust_binary",
            "xray_core_binary",
            "xray_core_dir",
            "sing_box_binary",
            "sing_box_dir",
            "geodata_dir",
        ):
            if key in info:
                require_consistent(
                    consistency,
                    key,
                    info[key],
                    f"{key.replace('_', ' ')} is inconsistent across summaries",
                )

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
    except RecursionError:
        print(
            "benchmark publication validation failed: JSON nesting exceeds validation limit",
            file=sys.stderr,
        )
        return 1
    print(f"validated benchmark publication: {count} series")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
