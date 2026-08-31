#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
validator="$repo_root/scripts/check-benchmark-publication.py"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

make_fixture() {
  local publication_root="$1"
  local mutation="${2:-valid}"

  python3 - "$publication_root" "$mutation" <<'PY'
import copy
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]
root.mkdir(parents=True)

candidate_revision = "0123456789abcdef0123456789abcdef01234567"
xray_revision = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
sing_revision = "56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778"

manifest = {
    "schemaVersion": 1,
    "publicationId": "2026-08-29-v26.7.28",
    "measuredAt": "2026-08-29",
    "candidate": {"revision": candidate_revision, "dirty": False},
    "environment": {
        "hardware": "test hardware",
        "os": "test os",
        "rustc": "rustc test",
        "cargo": "cargo test",
        "go": "go test",
    },
    "comparators": {
        "xray-core": {
            "version": "v26.7.28",
            "revision": xray_revision,
            "binarySha256": "a" * 64,
            "buildCommand": "go build ./main",
        },
        "sing-box": {
            "version": "v1.13.20",
            "revision": sing_revision,
            "binarySha256": "b" * 64,
            "buildTags": "with_gvisor,with_utls,badlinkname,tfogo_checklinkname0",
            "sourceUrl": "https://github.com/SagerNet/sing-box",
        },
    },
    "rawArchive": {
        "location": "checksum-addressed maintainer archive",
        "sha256": "c" * 64,
    },
    "omissions": [
        {
            "scenario": "stream-grpc-full-duplex-32",
            "engine": "sing-box",
            "reasonCode": "nondeterministic-timeout",
            "failedCampaigns": 2,
            "completedRunsBeforeTimeout": 7,
            "timedOutRuns": 2,
            "timeoutMs": 300_000,
        },
        {
            "scenario": "xhttp-pressure-xhttp-h3-32",
            "engine": "xray-core",
            "reasonCode": "upstream-reset-and-timeout",
            "failedCampaigns": 1,
            "completedRunsBeforeTimeout": 0,
            "timedOutRuns": 1,
            "timeoutMs": 300_000,
        }
    ],
    "series": [],
}

engines = ("xray-rust", "xray-core", "sing-box")
series = []


def add(scenario, selected_engines, **fields):
    for engine in selected_engines:
        series.append((scenario, engine, fields.copy()))


base = {
    "idle": ("idle", 1, 1, 1_024),
    "many-idle-flows-100": ("many-idle-flows", 100, 1, 1_024),
    "many-idle-flows-1000": ("many-idle-flows", 1000, 1, 1_024),
    "tcp-freedom": ("tcp-freedom", 1, 1_000, 1_024),
    "udp-freedom": ("udp-freedom", 1, 1_000, 512),
    "reconnect-burst": ("reconnect-burst", 16, 25, 1_024),
    "reality-vision-xudp": ("reality-vision-xudp", 1, 1_000, 512),
    "tcp-bulk-throughput": ("tcp-bulk-throughput", 1, 2_048, 4_194_304),
    "reality-vision-bulk-throughput": (
        "reality-vision-bulk-throughput",
        1,
        256,
        4_194_304,
    ),
}
for scenario, (workload, connections, iterations, payload_size) in base.items():
    selected_engines = (
        ("xray-rust", "xray-core")
        if scenario
        in {"reality-vision-xudp", "reality-vision-bulk-throughput"}
        else engines
    )
    add(
        scenario,
        selected_engines,
        workload=workload,
        connections=connections,
        iterations=iterations,
        payload_size=payload_size,
    )
add(
    "routed-tcp-freedom",
    ("xray-rust", "xray-core"),
    workload="routed-tcp-freedom",
    connections=8,
    iterations=100,
    payload_size=1_024,
)

for transport in ("ws", "httpupgrade", "grpc"):
    for traffic in ("upload", "download", "full-duplex"):
        for flows in (1, 32):
            scenario = f"stream-{transport}-{traffic}-{flows}"
            add(
                scenario,
                (
                    ("xray-rust", "xray-core")
                    if scenario == "stream-grpc-full-duplex-32"
                    else engines
                ),
                workload="stream-transport",
                connections=flows,
                iterations=4_096,
                payload_size=65_536,
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
                iterations=4_096,
                payload_size=65_536,
                stream_transport=transport,
                stream_traffic=traffic,
                xhttp_mode="stream-up",
                xhttp_profile=None,
                xhttp_max_post_bytes=65_536,
            )

for transport in ("xhttp-h1", "xhttp-h2", "xhttp-h3"):
    for flows in (1, 32):
        scenario = f"xhttp-pressure-{transport}-{flows}"
        add(
            scenario,
            (
                ("xray-rust",)
                if scenario == "xhttp-pressure-xhttp-h3-32"
                else ("xray-rust", "xray-core")
            ),
            workload="stream-transport",
            connections=flows,
            iterations=4_096,
            payload_size=16_384,
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
        iterations=1,
        payload_size=16_384,
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
    iterations=1,
    payload_size=16_384,
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
        iterations=1_000,
        payload_size=16_384,
        stream_transport="xhttp-h1",
        stream_traffic="packet-up",
        xhttp_mode="packet-up",
        xhttp_profile="legacy-extra-h1-packet-up",
        xhttp_max_post_bytes=500_000,
    )

engine_revisions = {
    "xray-rust": candidate_revision,
    "xray-core": xray_revision,
    "sing-box": sing_revision,
}
engine_hashes = {
    "xray-rust": "e" * 64,
    "xray-core": "a" * 64,
    "sing-box": "b" * 64,
}
workspace = pathlib.Path("/tmp/xray-rust-benchmark-workspace")
engine_paths = {
    "xray-rust": workspace / "target/release/xray-rust",
    "xray-core": workspace / "target/bench-bin/xray-core-v26.7.28",
    "sing-box": workspace
    / "target/benchmarks/2026-08-29-v26.7.28/comparators/bin/sing-box-v1.13.20",
}
xray_core_dir = workspace / "Xray-core"
raw_root = workspace / "target/benchmarks/2026-08-29-v26.7.28"
sing_box_dir = raw_root / "comparators/sing-box"
geodata_dir = raw_root / "comparators/geodata"


def scenario_config(scenario, fields):
    base = {
        "idle": (5_000, 30_000, "base-idle"),
        "many-idle-flows-100": (5_000, 30_000, "base-flows-100"),
        "many-idle-flows-1000": (5_000, 30_000, "base-flows-1000"),
        "tcp-freedom": (2_000, 30_000, "base-tcp"),
        "udp-freedom": (2_000, 30_000, "base-udp"),
        "reconnect-burst": (2_000, 30_000, "base-reconnect"),
        "reality-vision-xudp": (2_000, 30_000, "base-reality-xudp"),
        "tcp-bulk-throughput": (2_000, 300_000, "base-tcp-bulk"),
        "reality-vision-bulk-throughput": (
            2_000,
            120_000,
            "base-reality-bulk",
        ),
        "routed-tcp-freedom": (2_000, 120_000, "base-geodata"),
    }
    if scenario in base:
        duration_ms, timeout_ms, output_name = base[scenario]
        return {
            "duration_ms": duration_ms,
            "sample_interval_ms": 100,
            "run_timeout_ms": timeout_ms,
            "settle_ms": 0,
            "explicit_max_post_bytes": None,
            "output_name": output_name,
            "supports_sing_box": scenario
            not in {
                "routed-tcp-freedom",
                "reality-vision-xudp",
                "reality-vision-bulk-throughput",
            },
            "skip_sing_box": scenario
            in {"reality-vision-xudp", "reality-vision-bulk-throughput"},
            "geodata": scenario == "routed-tcp-freedom",
        }
    if scenario.startswith("stream-"):
        omit_sing_box = scenario == "stream-grpc-full-duplex-32"
        return {
            "duration_ms": 2_000,
            "sample_interval_ms": 100,
            "run_timeout_ms": 300_000,
            "settle_ms": 0,
            "explicit_max_post_bytes": None,
            "output_name": scenario,
            "supports_sing_box": not fields["stream_transport"].startswith("xhttp-")
            and not omit_sing_box,
            "skip_sing_box": omit_sing_box,
            "geodata": False,
        }
    if scenario.startswith("xhttp-pressure-"):
        return {
            "duration_ms": 2_000,
            "sample_interval_ms": 100,
            "run_timeout_ms": 300_000,
            "settle_ms": 0,
            "explicit_max_post_bytes": None,
            "output_name": scenario,
            "supports_sing_box": False,
            "skip_sing_box": False,
            "geodata": False,
        }
    held_open = "-held-open-" in scenario
    return {
        "duration_ms": 30_000 if held_open else 0,
        "sample_interval_ms": 100,
        "run_timeout_ms": 155_000 if held_open else 300_000,
        "settle_ms": 5_000,
        "explicit_max_post_bytes": fields["xhttp_max_post_bytes"],
        "output_name": "xhttp-memory",
        "supports_sing_box": False,
        "skip_sing_box": False,
        "geodata": False,
    }


def canonical_invocation(scenario, engine, fields, config):
    args = [
        "run",
        "--engine",
        engine,
        "--workload",
        fields["workload"],
        "--duration-ms",
        str(config["duration_ms"]),
        "--sample-interval-ms",
        str(config["sample_interval_ms"]),
        "--run-timeout-ms",
        str(config["run_timeout_ms"]),
        "--connections",
        str(fields["connections"]),
        "--iterations",
        str(fields["iterations"]),
        "--payload-size",
        str(fields["payload_size"]),
    ]
    if fields["workload"] == "stream-transport":
        args += [
            "--stream-transport",
            fields["stream_transport"],
            "--traffic",
            fields["stream_traffic"],
        ]
        if fields.get("xhttp_mode") is not None:
            args += ["--xhttp-mode", fields["xhttp_mode"]]
        if fields.get("xhttp_profile") is not None:
            args += ["--xhttp-profile", fields["xhttp_profile"]]
        if config["explicit_max_post_bytes"] is not None:
            args += [
                "--xhttp-max-post-bytes",
                str(config["explicit_max_post_bytes"]),
            ]
        args += ["--settle-ms", str(config["settle_ms"])]
    args += [
        "--transport",
        "both",
        "--dns-upstream-transport",
        "classic",
        "--runs",
        "5",
        "--out-dir",
        str(raw_root / config["output_name"]),
        "--xray-rust-bin",
        str(engine_paths["xray-rust"]),
        "--xray-core-bin",
        str(engine_paths["xray-core"]),
    ]
    if config["supports_sing_box"]:
        args += ["--sing-box-bin", str(engine_paths["sing-box"])]
    args += ["--xray-core-dir", str(xray_core_dir)]
    if config["supports_sing_box"]:
        args += ["--sing-box-dir", str(sing_box_dir)]
    if config["skip_sing_box"]:
        args.append("--skip-sing-box")
    args.append("--no-auto-build")
    if config["geodata"]:
        args += ["--geodata-dir", str(geodata_dir)]
    return args


def ceil_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def metric(values):
    ordered = sorted(values)
    middle = len(ordered) // 2
    median = (
        ordered[middle]
        if len(ordered) % 2
        else (ordered[middle - 1] + ordered[middle]) // 2
    )
    return {
        "min": ordered[0],
        "median": median,
        "p95": ordered[ceil_div(len(ordered) * 95, 100) - 1],
    }


def optional_metric(values):
    present = [value for value in values if value is not None]
    return metric(present) if present else None


def latency(seed):
    return {"min": seed, "median": seed + 2, "p95": seed + 4, "p99": seed + 5}


def latency_aggregate(values):
    present = [value for value in values if value is not None]
    if not present:
        return None
    return {
        field: metric([value[field] for value in present])
        for field in ("min", "median", "p95", "p99")
    }


def setup(seed):
    return {
        field: latency(seed + offset * 10)
        for offset, field in enumerate(
            (
                "tcp_connect_us",
                "socks_method_us",
                "socks_connect_us",
                "socks_setup_us",
                "total_us",
            )
        )
    }


def setup_aggregate(values):
    present = [value for value in values if value is not None]
    if not present:
        return None
    return {
        field: latency_aggregate([value[field] for value in present])
        for field in (
            "tcp_connect_us",
            "socks_method_us",
            "socks_connect_us",
            "socks_setup_us",
            "total_us",
        )
    }


def workload_bytes(fields):
    total = fields["connections"] * fields["iterations"] * fields["payload_size"]
    if fields["workload"] == "stream-transport":
        traffic = fields["stream_traffic"]
        if traffic == "held-open":
            return 0, 0
        return (
            total if traffic in {"upload", "full-duplex", "packet-up"} else 0,
            total if traffic in {"download", "full-duplex"} else 0,
        )
    if fields["workload"] in {"idle", "many-idle-flows", "reconnect-burst"}:
        return 0, 0
    if fields["workload"] in {
        "tcp-bulk-throughput",
        "reality-vision-bulk-throughput",
    }:
        return 0, total
    return total, total


summaries = {}
for scenario, engine, fields in series:
    summary_path = f"chart-inputs/{scenario}/{engine}/summary.json"
    config = scenario_config(scenario, fields)
    provenance = {
        "harness_profile": "release",
        "workspace_git": {"revision": candidate_revision, "dirty": False},
        "harness_binary_path": str(workspace / "target/release/xray-bench"),
        "harness_binary_sha256": "d" * 64,
        "engine_binary_path": str(engine_paths[engine]),
        "engine_binary_sha256": engine_hashes[engine],
        "working_directory": str(workspace),
        "invocation_args": canonical_invocation(scenario, engine, fields, config),
    }
    provenance["engine_source_git"] = {
        "revision": engine_revisions[engine],
        "dirty": False,
    }
    bytes_sent, bytes_received = workload_bytes(fields)
    total_bytes = bytes_sent + bytes_received
    run_id = f"publication-run-{scenario}"
    has_transfer = fields["workload"] in {
        "tcp-bulk-throughput",
        "reality-vision-bulk-throughput",
    } or (
        fields["workload"] == "stream-transport"
        and fields.get("stream_traffic") != "held-open"
    )
    has_latency = fields["workload"] in {
        "tcp-freedom",
        "udp-freedom",
        "many-idle-flows",
        "reconnect-burst",
        "reality-vision-xudp",
        "routed-tcp-freedom",
    }
    has_setup = fields["workload"] == "stream-transport" or fields["workload"] in {
        "many-idle-flows",
        "reconnect-burst",
        "routed-tcp-freedom",
    }
    results = []
    for run in range(5):
        duration_floor_ms = 0
        if fields["workload"] in {"idle", "many-idle-flows"}:
            duration_floor_ms = config["duration_ms"]
        elif fields["workload"] == "stream-transport":
            duration_floor_ms = config["settle_ms"]
            if fields.get("stream_traffic") == "held-open":
                duration_floor_ms += config["duration_ms"]
        duration_ms = duration_floor_ms + 100 + run
        transfer_duration_ms = 50 + run if has_transfer else None
        cpu_millis = 20 + run
        cpu_per_gib = (
            ceil_div(cpu_millis * 1024 * 1024 * 1024, total_bytes)
            if total_bytes > 0
            else None
        )
        throughput_duration = transfer_duration_ms or duration_ms
        throughput = (
            ceil_div(total_bytes * 8, throughput_duration * 1_000)
            if total_bytes > 0 and throughput_duration > 0
            else None
        )
        uplink_ops = (
            fields["connections"] * fields["iterations"]
            if fields.get("stream_traffic") == "packet-up"
            else None
        )
        phase_names = ["startup"]
        if fields["workload"] == "stream-transport":
            phase_names += [
                "held-open"
                if fields.get("stream_traffic") == "held-open"
                else "traffic"
            ]
            if config["settle_ms"] > 0:
                phase_names.append("settle")
        else:
            phase_names.append("workload")
        phase_names.append("complete")
        memory_phases = []
        for phase_index, phase_name in enumerate(phase_names):
            is_peak_phase = phase_index == len(phase_names) - 2
            phase_rss = 1_000 + run if is_peak_phase else 900 + run + phase_index
            memory_phases.append(
                {
                    "phase": phase_name,
                    "samples": 8 + run if is_peak_phase else 1,
                    "first_rss_kib": phase_rss,
                    "median_rss_kib": phase_rss,
                    "peak_rss_kib": phase_rss,
                    "last_rss_kib": phase_rss,
                }
            )
        result = {
            "run_id": run_id,
            "run_index": run + 1,
            "provenance": copy.deepcopy(provenance),
            "engine": engine,
            "workload": fields["workload"],
            "status": "ok",
            "duration_ms": duration_ms,
            "transfer_duration_ms": transfer_duration_ms,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "peak_rss_kib": 1_000 + run,
            "cpu_millis": cpu_millis,
            "cpu_millis_per_gib": cpu_per_gib,
            "throughput_mbps": throughput,
            "connections": fields["connections"],
            "iterations": fields["iterations"],
            "payload_size": fields["payload_size"],
            "settle_ms": config["settle_ms"],
            "memory_phases": memory_phases,
            "latency_us": latency(10 + run) if has_latency else None,
            "setup_us": setup(20 + run) if has_setup else None,
            "samples": sum(phase["samples"] for phase in memory_phases),
        }
        for field in (
            "stream_transport",
            "stream_traffic",
            "xhttp_mode",
            "xhttp_profile",
            "xhttp_max_post_bytes",
        ):
            if fields.get(field) is not None:
                result[field] = fields[field]
        if uplink_ops is not None:
            result["uplink_write_ops"] = uplink_ops
            result["uplink_write_ops_per_second"] = ceil_div(
                uplink_ops * 1_000, transfer_duration_ms
            )
        results.append(result)
    summary = {
        "run_id": run_id,
        "provenance": provenance,
        "engine": engine,
        "workload": fields["workload"],
        "status": "ok",
        "runs": 5,
        "duration_ms": metric([result["duration_ms"] for result in results]),
        "transfer_duration_ms": optional_metric(
            [result["transfer_duration_ms"] for result in results]
        ),
        "peak_rss_kib": metric([result["peak_rss_kib"] for result in results]),
        "cpu_millis": metric([result["cpu_millis"] for result in results]),
        "cpu_millis_per_gib": optional_metric(
            [result["cpu_millis_per_gib"] for result in results]
        ),
        "throughput_mbps": optional_metric(
            [result["throughput_mbps"] for result in results]
        ),
        "connections": fields["connections"],
        "iterations": fields["iterations"],
        "payload_size": fields["payload_size"],
        "settle_ms": config["settle_ms"],
        "latency_us": latency_aggregate(
            [result["latency_us"] for result in results]
        ),
        "setup_us": setup_aggregate([result["setup_us"] for result in results]),
        "bytes_sent": metric([result["bytes_sent"] for result in results]),
        "bytes_received": metric(
            [result["bytes_received"] for result in results]
        ),
        "results": results,
    }
    for field in (
        "stream_transport",
        "stream_traffic",
        "xhttp_mode",
        "xhttp_profile",
        "xhttp_max_post_bytes",
    ):
        if fields.get(field) is not None:
            summary[field] = fields[field]
    if any("uplink_write_ops" in result for result in results):
        summary["uplink_write_ops"] = optional_metric(
            [result.get("uplink_write_ops") for result in results]
        )
        summary["uplink_write_ops_per_second"] = optional_metric(
            [result.get("uplink_write_ops_per_second") for result in results]
        )
    summaries[summary_path] = summary
    manifest["series"].append(
        {"scenario": scenario, "engine": engine, "summary": summary_path}
    )

target_path = manifest["series"][0]["summary"]
target = summaries[target_path]


def mutate_invocation(summary, callback):
    callback(summary["provenance"]["invocation_args"])
    for result in summary["results"]:
        callback(result["provenance"]["invocation_args"])


def remove_flag(args, flag):
    index = args.index(flag)
    del args[index : index + 2]


def replace_flag(args, flag, value):
    args[args.index(flag) + 1] = value


def set_summary_duration(summary, duration_ms):
    for result in summary["results"]:
        result["duration_ms"] = duration_ms
    summary["duration_ms"] = metric(
        [result["duration_ms"] for result in summary["results"]]
    )


if mutation == "wrong_xray_revision":
    manifest["comparators"]["xray-core"]["revision"] = "0" * 40
elif mutation == "wrong_xray_version":
    manifest["comparators"]["xray-core"]["version"] = "v0.0.0"
elif mutation == "compact_date":
    manifest["measuredAt"] = "20260829"
    manifest["publicationId"] = "20260829-v26.7.28"
elif mutation == "week_date":
    manifest["measuredAt"] = "2026-W35-6"
    manifest["publicationId"] = "2026-W35-6-v26.7.28"
elif mutation == "invalid_calendar_date":
    manifest["measuredAt"] = "2026-02-30"
    manifest["publicationId"] = "2026-02-30-v26.7.28"
elif mutation == "root_basename_mismatch":
    manifest["measuredAt"] = "2026-08-30"
    manifest["publicationId"] = "2026-08-30-v26.7.28"
elif mutation == "malformed_candidate_digest":
    manifest["candidate"]["revision"] = "not-a-revision"
elif mutation == "candidate_dirty":
    manifest["candidate"]["dirty"] = True
elif mutation == "malformed_xray_digest":
    manifest["comparators"]["xray-core"]["binarySha256"] = "A" * 64
elif mutation == "malformed_sing_digest":
    manifest["comparators"]["sing-box"]["binarySha256"] = "b" * 63
elif mutation == "malformed_sing_version":
    manifest["comparators"]["sing-box"]["version"] = "main"
elif mutation == "wrong_sing_version":
    manifest["comparators"]["sing-box"]["version"] = "v1.13.15"
elif mutation == "malformed_sing_revision":
    manifest["comparators"]["sing-box"]["revision"] = "R" * 40
elif mutation == "wrong_sing_revision":
    manifest["comparators"]["sing-box"]["revision"] = "f" * 40
elif mutation == "malformed_archive_digest":
    manifest["rawArchive"]["sha256"] = "sha256:bad"
elif mutation == "empty_environment":
    manifest["environment"]["hardware"] = ""
elif mutation == "empty_raw_location":
    manifest["rawArchive"]["location"] = ""
elif mutation == "missing_omission":
    manifest["omissions"] = []
elif mutation == "wrong_omission_reason":
    manifest["omissions"][0]["reasonCode"] = "unsupported"
elif mutation == "wrong_omission_evidence":
    manifest["omissions"][0]["timedOutRuns"] = 1
elif mutation == "wrong_h3_pressure_omission_reason":
    manifest["omissions"][1]["reasonCode"] = "unsupported"
elif mutation == "wrong_h3_pressure_omission_evidence":
    manifest["omissions"][1]["timedOutRuns"] = 2
elif mutation == "extra_omission":
    manifest["omissions"].append(copy.deepcopy(manifest["omissions"][0]))
elif mutation == "duplicate_series":
    manifest["series"].append(copy.deepcopy(manifest["series"][0]))
elif mutation == "reused_summary_path":
    manifest["series"][1]["summary"] = manifest["series"][0]["summary"]
elif mutation == "escaping_path":
    manifest["series"][0]["summary"] = "../outside.json"
elif mutation == "absolute_path":
    manifest["series"][0]["summary"] = str(root.parent / "absolute.json")
elif mutation == "malformed_path":
    manifest["series"][0]["summary"] = "bad\0path.json"
elif mutation == "prefix_sibling_escape":
    sibling = root.parent / f"{root.name}-sibling"
    sibling.mkdir()
    (sibling / "summary.json").write_text("{}\n", encoding="utf-8")
    manifest["series"][0]["summary"] = f"../{sibling.name}/summary.json"
elif mutation == "symlink_escape":
    outside = root.parent / f"{root.name}-outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (root / "linked-summary.json").symlink_to(outside)
    manifest["series"][0]["summary"] = "linked-summary.json"
elif mutation == "summary_directory":
    manifest["series"][0]["summary"] = "summaries"
elif mutation == "missing_summary":
    summaries.pop(target_path)
elif mutation == "fewer_results":
    target["results"].pop()
elif mutation == "summary_status":
    target["status"] = "failed"
elif mutation == "wrong_runs":
    target["runs"] = 4
elif mutation == "harness_profile":
    target["provenance"]["harness_profile"] = "debug"
elif mutation == "workspace_dirty":
    target["provenance"]["workspace_git"]["dirty"] = True
elif mutation == "workspace_revision_mismatch":
    target["provenance"]["workspace_git"]["revision"] = "1" * 40
elif mutation == "engine_dirty":
    target["provenance"]["engine_source_git"]["dirty"] = True
elif mutation == "engine_revision_mismatch":
    target["provenance"]["engine_source_git"]["revision"] = "1" * 40
elif mutation == "missing_harness_hash":
    target["provenance"].pop("harness_binary_sha256")
elif mutation == "malformed_harness_hash":
    target["provenance"]["harness_binary_sha256"] = "d" * 63
elif mutation == "missing_engine_hash":
    target["provenance"].pop("engine_binary_sha256")
elif mutation == "malformed_engine_hash":
    target["provenance"]["engine_binary_sha256"] = "E" * 64
elif mutation == "external_engine_hash_mismatch":
    xray_entry = next(
        entry for entry in manifest["series"] if entry["engine"] == "xray-core"
    )
    summaries[xray_entry["summary"]]["provenance"]["engine_binary_sha256"] = "f" * 64
elif mutation == "inconsistent_harness_hash":
    target["provenance"]["harness_binary_sha256"] = "f" * 64
    for result in target["results"]:
        result["provenance"]["harness_binary_sha256"] = "f" * 64
elif mutation == "inconsistent_xray_rust_hash":
    target["provenance"]["engine_binary_sha256"] = "f" * 64
    for result in target["results"]:
        result["provenance"]["engine_binary_sha256"] = "f" * 64
elif mutation == "summary_workload":
    target["workload"] = "tcp-freedom"
elif mutation == "summary_engine":
    target["engine"] = "xray-core"
elif mutation == "missing_summary_run_id":
    target.pop("run_id")
elif mutation == "summary_connections_boolean":
    target["connections"] = True
elif mutation == "summary_iterations_boolean":
    target["iterations"] = True
elif mutation == "missing_summary_metric":
    target.pop("duration_ms")
elif mutation == "missing_result_metric":
    target["results"][0].pop("duration_ms")
elif mutation == "metric_boolean":
    target["results"][0]["bytes_sent"] = True
elif mutation == "metric_negative":
    target["results"][0]["cpu_millis"] = -1
elif mutation == "workload_byte_direction":
    bulk_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "tcp-bulk-throughput"
        and entry["engine"] == "xray-rust"
    )
    bulk_summary = summaries[bulk_entry["summary"]]
    bulk_summary["results"][0]["bytes_sent"] = bulk_summary["results"][0][
        "bytes_received"
    ]
elif mutation == "metric_shape":
    target["duration_ms"].pop("p95")
elif mutation == "optional_metric_shape":
    data_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "tcp-freedom" and entry["engine"] == "xray-rust"
    )
    summaries[data_entry["summary"]]["throughput_mbps"].pop("p95")
elif mutation == "metric_order":
    target["duration_ms"]["min"] = target["duration_ms"]["median"] + 1
elif mutation == "aggregate_tamper":
    target["duration_ms"]["median"] += 1
elif mutation == "derived_metric_tamper":
    data_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "tcp-freedom" and entry["engine"] == "xray-rust"
    )
    summaries[data_entry["summary"]]["results"][0]["cpu_millis_per_gib"] += 1
elif mutation == "uplink_rate_below_bound":
    packet_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "xhttp-pressure-xhttp-h1-1"
        and entry["engine"] == "xray-rust"
    )
    summaries[packet_entry["summary"]]["results"][0][
        "uplink_write_ops_per_second"
    ] = 1
elif mutation == "uplink_rate_above_bound":
    packet_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "xhttp-pressure-xhttp-h1-1"
        and entry["engine"] == "xray-rust"
    )
    packet_result = summaries[packet_entry["summary"]]["results"][0]
    packet_result["uplink_write_ops_per_second"] = (
        packet_result["uplink_write_ops"] * 1_000_000_000 + 1
    )
elif mutation == "missing_memory_phases":
    target["results"][0].pop("memory_phases")
elif mutation == "memory_peak_mismatch":
    peak_phase = target["results"][0]["memory_phases"][1]
    for field in (
        "first_rss_kib",
        "median_rss_kib",
        "peak_rss_kib",
        "last_rss_kib",
    ):
        peak_phase[field] -= 1
elif mutation == "memory_phase_boundaries":
    phases = target["results"][0]["memory_phases"]
    phases[1]["samples"] += phases[0]["samples"]
    phases.pop(0)
elif mutation == "memory_phase_unhashable":
    target["results"][0]["memory_phases"][0]["phase"] = []
elif mutation == "memory_phase_impossible_for_workload":
    target["results"][0]["memory_phases"][1]["phase"] = "traffic"
elif mutation == "memory_phase_missing_settle":
    packet_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "xhttp-memory-packet-up-1-max-500000"
        and entry["engine"] == "xray-rust"
    )
    packet_result = summaries[packet_entry["summary"]]["results"][0]
    traffic_phase = packet_result["memory_phases"][-3]
    settle_phase = packet_result["memory_phases"].pop(-2)
    traffic_phase["samples"] += settle_phase["samples"]
    traffic_phase["peak_rss_kib"] = max(
        traffic_phase["peak_rss_kib"], settle_phase["peak_rss_kib"]
    )
elif mutation == "idle_duration_below_floor":
    target["results"][0]["duration_ms"] = 1
elif mutation == "held_open_duration_below_floor":
    held_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "xhttp-memory-held-open-1-max-500000"
        and entry["engine"] == "xray-rust"
    )
    summaries[held_entry["summary"]]["results"][0]["duration_ms"] = 34_999
elif mutation == "settled_stream_duration_below_floor":
    packet_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "xhttp-memory-packet-up-1-max-500000"
        and entry["engine"] == "xray-rust"
    )
    summaries[packet_entry["summary"]]["results"][0]["duration_ms"] = 4_999
elif mutation == "parameter_collapse_1_1_0":
    stream_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "stream-ws-upload-32"
        and entry["engine"] == "xray-rust"
    )
    collapsed = summaries[stream_entry["summary"]]
    for field, value in (("connections", 1), ("iterations", 1), ("payload_size", 0)):
        collapsed[field] = value
        for result in collapsed["results"]:
            result[field] = value
        mutate_invocation(
            collapsed,
            lambda args, flag=f"--{field.replace('_', '-')}", replacement=value: replace_flag(
                args, flag, str(replacement)
            ),
        )
elif mutation == "invocation_wrong_subcommand":
    mutate_invocation(target, lambda args: args.__setitem__(0, "compare"))
elif mutation == "invocation_unrelated_flag":
    mutate_invocation(target, lambda args: args.extend(["--unrelated", "value"]))
elif mutation == "invocation_missing_flag":
    mutate_invocation(target, lambda args: remove_flag(args, "--runs"))
elif mutation == "invocation_duplicate_flag":
    mutate_invocation(target, lambda args: args.extend(["--runs", "5"]))
elif mutation == "invocation_missing_no_auto_build":
    mutate_invocation(target, lambda args: args.remove("--no-auto-build"))
elif mutation == "invocation_effective_config_mismatch":
    mutate_invocation(
        target,
        lambda args: replace_flag(args, "--duration-ms", "999"),
    )
elif mutation == "invocation_runs_mismatch":
    mutate_invocation(target, lambda args: replace_flag(args, "--runs", "4"))
elif mutation == "invocation_binary_path_mismatch":
    mutate_invocation(
        target,
        lambda args: replace_flag(args, "--xray-rust-bin", "/tmp/wrong-xray-rust"),
    )
elif mutation == "invocation_missing_binary":
    mutate_invocation(target, lambda args: remove_flag(args, "--xray-rust-bin"))
elif mutation == "missing_reality_skip_sing_box":
    reality_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "reality-vision-xudp"
        and entry["engine"] == "xray-rust"
    )
    mutate_invocation(
        summaries[reality_entry["summary"]],
        lambda args: args.remove("--skip-sing-box"),
    )
elif mutation == "missing_grpc_omission_skip_sing_box":
    grpc_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "stream-grpc-full-duplex-32"
        and entry["engine"] == "xray-rust"
    )
    mutate_invocation(
        summaries[grpc_entry["summary"]],
        lambda args: args.remove("--skip-sing-box"),
    )
elif mutation == "extra_skip_sing_box_on_unsupported":
    routed_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "routed-tcp-freedom"
        and entry["engine"] == "xray-rust"
    )
    mutate_invocation(
        summaries[routed_entry["summary"]],
        lambda args: args.insert(args.index("--no-auto-build"), "--skip-sing-box"),
    )
elif mutation == "reality_invocation_with_sing_box":
    reality_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "reality-vision-xudp"
        and entry["engine"] == "xray-rust"
    )
    reality_summary = summaries[reality_entry["summary"]]

    def add_sing_box_binary(args):
        index = args.index("--xray-core-dir")
        args[index:index] = ["--sing-box-bin", str(engine_paths["sing-box"])]

    mutate_invocation(reality_summary, add_sing_box_binary)
elif mutation == "invocation_source_path_mismatch":
    mutate_invocation(
        target,
        lambda args: replace_flag(args, "--xray-core-dir", "/tmp/not-the-core"),
    )
elif mutation == "invocation_output_mismatch":
    mutate_invocation(
        target,
        lambda args: replace_flag(args, "--out-dir", "/tmp/unrelated-output"),
    )
elif mutation == "result_status":
    target["results"][0]["status"] = "failed"
elif mutation == "result_parameters":
    target["results"][0]["connections"] += 1
elif mutation == "result_connections_boolean":
    target["results"][0]["connections"] = True
elif mutation == "result_provenance":
    target["results"][0]["provenance"]["workspace_git"]["dirty"] = True
elif mutation == "result_run_id":
    target["results"][0]["run_id"] = "different-run"
elif mutation == "missing_run_index":
    target["results"][0].pop("run_index")
elif mutation == "run_index_boolean":
    target["results"][0]["run_index"] = True
elif mutation == "copied_result_repeat":
    target["results"][1] = copy.deepcopy(target["results"][0])
elif mutation == "run_index_gap":
    target["results"][-1]["run_index"] = 6
elif mutation == "scenario_engine_run_id_mismatch":
    mismatched_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "idle" and entry["engine"] == "xray-core"
    )
    mismatched = summaries[mismatched_entry["summary"]]
    mismatched["run_id"] = "publication-run-idle-other-engine"
    for result in mismatched["results"]:
        result["run_id"] = mismatched["run_id"]
elif mutation == "scenario_run_id_reuse":
    reused_run_id = "publication-run-idle"
    for entry in manifest["series"]:
        if entry["scenario"] != "many-idle-flows-100":
            continue
        reused = summaries[entry["summary"]]
        reused["run_id"] = reused_run_id
        for result in reused["results"]:
            result["run_id"] = reused_run_id
elif mutation == "missing_combination":
    manifest["series"].pop()
elif mutation == "extra_combination":
    extra = copy.deepcopy(manifest["series"][0])
    extra["scenario"] = "unreviewed-scenario"
    manifest["series"].append(extra)
elif mutation == "extra_sing_reality_series":
    xray_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "reality-vision-xudp"
        and entry["engine"] == "xray-rust"
    )
    extra = copy.deepcopy(xray_entry)
    extra["engine"] = "sing-box"
    manifest["series"].append(extra)
elif mutation == "extra_sing_grpc_omission_series":
    xray_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "stream-grpc-full-duplex-32"
        and entry["engine"] == "xray-rust"
    )
    extra = copy.deepcopy(xray_entry)
    extra["engine"] = "sing-box"
    manifest["series"].append(extra)
elif mutation == "extra_xray_core_h3_pressure_series":
    xray_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "xhttp-pressure-xhttp-h3-32"
        and entry["engine"] == "xray-rust"
    )
    extra = copy.deepcopy(xray_entry)
    extra["engine"] = "xray-core"
    manifest["series"].append(extra)
elif mutation == "unreferenced_chart_input_summary":
    summaries[
        "chart-inputs/reality-vision-xudp/sing-box/summary.json"
    ] = copy.deepcopy(target)
elif mutation == "unrelated_document_summary":
    summaries["docs/example/summary.json"] = copy.deepcopy(target)
elif mutation == "unknown_top_level":
    manifest["unexpected"] = True
elif mutation == "additive_series_metadata":
    manifest["series"][0]["runCount"] = 5
    manifest["series"][0]["unavailableMetrics"] = ["packet-loss"]
elif mutation == "alternate_sing_pin":
    alternate_revision = "f" * 40
    manifest["comparators"]["sing-box"]["version"] = "v9.8.7"
    manifest["comparators"]["sing-box"]["revision"] = alternate_revision
    alternate_binary = raw_root / "comparators/bin/sing-box-v9.8.7"
    for entry in manifest["series"]:
        summary = summaries[entry["summary"]]
        if "--sing-box-bin" in summary["provenance"]["invocation_args"]:
            mutate_invocation(
                summary,
                lambda args: replace_flag(
                    args, "--sing-box-bin", str(alternate_binary)
                ),
            )
        if entry["engine"] != "sing-box":
            continue
        summary["provenance"]["engine_binary_path"] = str(alternate_binary)
        summary["provenance"]["engine_source_git"]["revision"] = alternate_revision
        for result in summary["results"]:
            result["provenance"]["engine_binary_path"] = str(alternate_binary)
            result["provenance"]["engine_source_git"]["revision"] = alternate_revision
elif mutation == "xray_core_without_source":
    for entry in manifest["series"]:
        if entry["engine"] != "xray-core":
            continue
        summary = summaries[entry["summary"]]
        summary["provenance"].pop("engine_source_git", None)
        for result in summary["results"]:
            result["provenance"].pop("engine_source_git", None)
elif mutation == "xray_core_source_revision_mismatch":
    xray_entry = next(
        entry for entry in manifest["series"] if entry["engine"] == "xray-core"
    )
    xray_summary = summaries[xray_entry["summary"]]
    xray_summary["provenance"]["engine_source_git"]["revision"] = "1" * 40
    for result in xray_summary["results"]:
        result["provenance"]["engine_source_git"]["revision"] = "1" * 40
elif mutation == "missing_sing_source":
    sing_entry = next(
        entry for entry in manifest["series"] if entry["engine"] == "sing-box"
    )
    summaries[sing_entry["summary"]]["provenance"].pop("engine_source_git")
elif mutation == "deep_provenance":
    nested = {"leaf": True}
    for _ in range(96):
        nested = {"nested": nested}
    target["provenance"]["unexpected_deep_data"] = nested
    for result in target["results"]:
        result["provenance"]["unexpected_deep_data"] = copy.deepcopy(nested)
elif mutation == "omitted_optional_serde_fields":
    # The base fixture already omits every Serde skip field whose effective
    # value is None: stream/DNS/blackhole axes. Source provenance is required
    # for every publication engine, including an explicitly supplied Xray binary.
    assert all(
        "engine_source_git" in summary["provenance"]
        for summary in summaries.values()
    )
elif mutation == "held_open_duration_boundary":
    for entry in manifest["series"]:
        if entry["scenario"].startswith("xhttp-memory-held-open-"):
            set_summary_duration(summaries[entry["summary"]], 35_000)
elif mutation == "settled_stream_duration_boundary":
    for entry in manifest["series"]:
        if entry["scenario"].startswith("xhttp-memory-packet-up-"):
            set_summary_duration(summaries[entry["summary"]], 5_000)
elif mutation == "mixed_optional_metric_runs":
    data_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "tcp-freedom" and entry["engine"] == "xray-rust"
    )
    mixed_summary = summaries[data_entry["summary"]]
    mixed_summary["results"][-1]["latency_us"] = None
    mixed_summary["latency_us"] = latency_aggregate(
        [result["latency_us"] for result in mixed_summary["results"]]
    )
elif mutation == "impossible_transfer_metric":
    data_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "tcp-freedom" and entry["engine"] == "xray-rust"
    )
    summaries[data_entry["summary"]]["results"][0]["transfer_duration_ms"] = 1
elif mutation == "impossible_setup_metric":
    data_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "tcp-freedom" and entry["engine"] == "xray-rust"
    )
    summaries[data_entry["summary"]]["results"][0]["setup_us"] = setup(99)
elif mutation == "missing_required_setup_metric":
    stream_entry = next(
        entry
        for entry in manifest["series"]
        if entry["scenario"] == "stream-ws-upload-1"
        and entry["engine"] == "xray-rust"
    )
    stream_summary = summaries[stream_entry["summary"]]
    stream_summary["results"][-1]["setup_us"] = None
    stream_summary["setup_us"] = setup_aggregate(
        [result["setup_us"] for result in stream_summary["results"]]
    )
elif mutation not in {
    "valid",
    "missing_manifest",
    "malformed_manifest_json",
    "malformed_summary_json",
    "manifest_wrong_root",
    "summary_wrong_root",
    "manifest_symlink_outside",
    "manifest_symlink_inside",
    "manifest_directory",
    "manifest_broken_symlink",
    "unreadable_summary",
    "deep_parser_json",
}:
    raise SystemExit(f"unknown mutation: {mutation}")

(root / "manifest.json").write_text(
    json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
)
for relative_path, summary in summaries.items():
    destination = root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(summary, separators=(",", ":")) + "\n", encoding="utf-8"
    )
if mutation == "missing_manifest":
    (root / "manifest.json").unlink()
elif mutation == "malformed_manifest_json":
    (root / "manifest.json").write_text("{not json\n", encoding="utf-8")
elif mutation == "malformed_summary_json":
    (root / target_path).write_text("[not json\n", encoding="utf-8")
elif mutation == "manifest_wrong_root":
    (root / "manifest.json").write_text("[]\n", encoding="utf-8")
elif mutation == "summary_wrong_root":
    (root / target_path).write_text("[]\n", encoding="utf-8")
elif mutation == "manifest_symlink_outside":
    outside_manifest = root.parent / "outside-manifest.json"
    (root / "manifest.json").replace(outside_manifest)
    (root / "manifest.json").symlink_to(outside_manifest)
elif mutation == "manifest_symlink_inside":
    real_manifest = root / "real-manifest.json"
    (root / "manifest.json").replace(real_manifest)
    (root / "manifest.json").symlink_to(real_manifest)
elif mutation == "manifest_directory":
    (root / "manifest.json").unlink()
    (root / "manifest.json").mkdir()
elif mutation == "manifest_broken_symlink":
    (root / "manifest.json").unlink()
    (root / "manifest.json").symlink_to(root / "missing-manifest.json")
elif mutation == "unreadable_summary":
    # Invalid UTF-8 gives a portable, controlled read failure even for root.
    (root / target_path).write_bytes(b"\xff\xfe\xfd")
elif mutation == "deep_parser_json":
    (root / target_path).write_text(
        "[" * 2_000 + "0" + "]" * 2_000,
        encoding="utf-8",
    )
PY
}

expect_rejected() {
  local mutation="$1"
  local expected_reason="$2"
  local fixture="$tmp_dir/$mutation/2026-08-29-v26.7.28"
  local output

  make_fixture "$fixture" "$mutation"
  if output="$(python3 "$validator" "$fixture" 2>&1)"; then
    fail "$mutation was accepted"
  fi
  if ! grep -Fq "$expected_reason" <<<"$output"; then
    fail "$mutation did not report '$expected_reason': $output"
  fi
  if grep -Fq "Traceback (most recent call last)" <<<"$output"; then
    fail "$mutation emitted an uncontrolled Python traceback: $output"
  fi
}

valid_fixture="$tmp_dir/valid/2026-08-29-v26.7.28"
make_fixture "$valid_fixture"
valid_output="$(python3 "$validator" "$valid_fixture")"
grep -Fq "validated benchmark publication: 139 series" <<<"$valid_output" \
  || fail "valid publication did not report the complete matrix: $valid_output"

for valid_variant in \
  additive_series_metadata \
  held_open_duration_boundary \
  settled_stream_duration_boundary \
  unrelated_document_summary \
  omitted_optional_serde_fields; do
  variant_fixture="$tmp_dir/$valid_variant/2026-08-29-v26.7.28"
  make_fixture "$variant_fixture" "$valid_variant"
  variant_output="$(python3 "$validator" "$variant_fixture")"
  grep -Fq "validated benchmark publication: 139 series" <<<"$variant_output" \
    || fail "$valid_variant did not validate: $variant_output"
done

expect_rejected wrong_xray_revision "xray-core revision must be"
expect_rejected wrong_xray_version "xray-core version must be v26.7.28"
expect_rejected compact_date "measuredAt must use canonical YYYY-MM-DD format"
expect_rejected week_date "measuredAt must use canonical YYYY-MM-DD format"
expect_rejected invalid_calendar_date "measuredAt must be a valid YYYY-MM-DD date"
expect_rejected root_basename_mismatch "publication root basename must match publicationId"
expect_rejected malformed_candidate_digest "candidate.revision must be 40 lowercase hexadecimal characters"
expect_rejected candidate_dirty "candidate.dirty must be false"
expect_rejected malformed_xray_digest "comparators.xray-core.binarySha256 must be 64 lowercase hexadecimal characters"
expect_rejected malformed_sing_digest "comparators.sing-box.binarySha256 must be 64 lowercase hexadecimal characters"
expect_rejected malformed_sing_version "comparators.sing-box.version must be v1.13.20"
expect_rejected wrong_sing_version "comparators.sing-box.version must be v1.13.20"
expect_rejected alternate_sing_pin "comparators.sing-box.version must be v1.13.20"
expect_rejected malformed_sing_revision "comparators.sing-box.revision must be 40 lowercase hexadecimal characters"
expect_rejected wrong_sing_revision "comparators.sing-box.revision must be 56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778"
expect_rejected malformed_archive_digest "rawArchive.sha256 must be 64 lowercase hexadecimal characters"
expect_rejected empty_environment "environment.hardware must be non-empty"
expect_rejected empty_raw_location "rawArchive.location must be non-empty"
expect_rejected missing_omission "manifest omissions must contain exactly two entries"
expect_rejected wrong_omission_reason "manifest omissions do not match the reviewed RC4 exceptions"
expect_rejected wrong_omission_evidence "manifest omissions do not match the reviewed RC4 exceptions"
expect_rejected wrong_h3_pressure_omission_reason "manifest omissions do not match the reviewed RC4 exceptions"
expect_rejected wrong_h3_pressure_omission_evidence "manifest omissions do not match the reviewed RC4 exceptions"
expect_rejected extra_omission "manifest omissions must contain exactly two entries"
expect_rejected duplicate_series "duplicate series"
expect_rejected reused_summary_path "summary engine does not match manifest"
expect_rejected escaping_path "summary path escapes publication root"
expect_rejected absolute_path "summary path escapes publication root"
expect_rejected malformed_path "invalid summary path"
expect_rejected prefix_sibling_escape "summary path escapes publication root"
expect_rejected symlink_escape "summary path escapes publication root"
expect_rejected missing_summary "summary file does not exist"
expect_rejected summary_directory "summary file does not exist"
expect_rejected missing_manifest "publication manifest.json does not exist"
expect_rejected manifest_symlink_outside "manifest.json must be an in-root regular non-symlink file"
expect_rejected manifest_symlink_inside "manifest.json must be an in-root regular non-symlink file"
expect_rejected manifest_directory "manifest.json must be an in-root regular non-symlink file"
expect_rejected manifest_broken_symlink "manifest.json must be an in-root regular non-symlink file"
expect_rejected malformed_manifest_json "invalid JSON in manifest.json"
expect_rejected malformed_summary_json "invalid JSON in summary"
expect_rejected unreadable_summary "cannot read summary"
expect_rejected deep_parser_json "invalid JSON in summary"
expect_rejected deep_provenance "JSON nesting exceeds validation limit"
expect_rejected manifest_wrong_root "manifest must be an object"
expect_rejected summary_wrong_root "must be an object"
expect_rejected fewer_results "must embed exactly 5 results"
expect_rejected summary_status "summary status must be ok"
expect_rejected wrong_runs "summary runs must be 5"
expect_rejected harness_profile "harness profile must be release"
expect_rejected workspace_dirty "workspace provenance must be clean"
expect_rejected workspace_revision_mismatch "workspace_git.revision does not match publication provenance"
expect_rejected engine_dirty "engine source provenance must be clean"
expect_rejected engine_revision_mismatch "engine_source_git.revision does not match publication provenance"
expect_rejected missing_harness_hash "harness binary SHA-256 is required"
expect_rejected malformed_harness_hash "harness binary SHA-256 must be 64 lowercase hexadecimal characters"
expect_rejected missing_engine_hash "engine binary SHA-256 is required"
expect_rejected malformed_engine_hash "engine binary SHA-256 must be 64 lowercase hexadecimal characters"
expect_rejected external_engine_hash_mismatch "xray-core engine binary SHA-256 does not match manifest comparator"
expect_rejected inconsistent_harness_hash "harness binary SHA-256 is inconsistent across summaries"
expect_rejected inconsistent_xray_rust_hash "xray-rust binary SHA-256 is inconsistent across summaries"
expect_rejected summary_workload "summary workload does not match scenario"
expect_rejected summary_engine "summary engine does not match manifest"
expect_rejected missing_summary_run_id "summary run_id must be non-empty"
expect_rejected summary_connections_boolean "summary connections must be a positive integer"
expect_rejected summary_iterations_boolean "summary iterations must be a positive integer"
expect_rejected missing_summary_metric "summary.duration_ms is required"
expect_rejected missing_result_metric "embedded result 1.duration_ms is required"
expect_rejected metric_boolean "embedded result 1.bytes_sent must be a non-negative integer"
expect_rejected metric_negative "embedded result 1.cpu_millis must be a non-negative integer"
expect_rejected workload_byte_direction "embedded result 1 bytes do not match workload parameters"
expect_rejected metric_shape "summary.duration_ms must contain exactly min, median, and p95"
expect_rejected optional_metric_shape "summary.throughput_mbps must contain exactly min, median, and p95"
expect_rejected metric_order "summary.duration_ms must satisfy min <= median <= p95"
expect_rejected aggregate_tamper "summary.duration_ms does not match embedded results"
expect_rejected derived_metric_tamper "embedded result 1.cpu_millis_per_gib does not match bytes and CPU"
expect_rejected uplink_rate_below_bound "embedded result 1.uplink_write_ops_per_second is outside transfer-duration bounds"
expect_rejected uplink_rate_above_bound "embedded result 1.uplink_write_ops_per_second is outside transfer-duration bounds"
expect_rejected missing_memory_phases "embedded result 1.memory_phases is required for a successful harness run"
expect_rejected memory_peak_mismatch "embedded result 1.memory_phases peak does not match result peak_rss_kib"
expect_rejected memory_phase_boundaries "embedded result 1.memory_phases must begin at startup and end at complete"
expect_rejected memory_phase_unhashable "embedded result 1.memory_phases[1].phase is not a serialized BenchmarkPhase"
expect_rejected memory_phase_impossible_for_workload "embedded result 1.memory_phases[2].phase is not available for this workload"
expect_rejected memory_phase_missing_settle "embedded result 1.memory_phases is missing required settle phase"
expect_rejected idle_duration_below_floor "embedded result 1.duration_ms is shorter than the canonical workload minimum"
expect_rejected held_open_duration_below_floor "embedded result 1.duration_ms is shorter than the canonical workload minimum"
expect_rejected settled_stream_duration_below_floor "embedded result 1.duration_ms is shorter than the canonical workload minimum"
expect_rejected parameter_collapse_1_1_0 "summary connections does not match scenario"
expect_rejected invocation_wrong_subcommand "invocation_args must begin with run"
expect_rejected invocation_unrelated_flag "invocation_args contains unexpected flag"
expect_rejected invocation_missing_flag "invocation_args flags do not match canonical harness order"
expect_rejected invocation_duplicate_flag "invocation_args contains duplicate flag"
expect_rejected invocation_missing_no_auto_build "invocation_args flags do not match canonical harness order"
expect_rejected invocation_effective_config_mismatch "invocation --duration-ms does not match scenario"
expect_rejected invocation_runs_mismatch "invocation --runs does not match scenario"
expect_rejected invocation_binary_path_mismatch "invocation binary path does not match provenance"
expect_rejected invocation_missing_binary "invocation_args flags do not match canonical harness order"
expect_rejected missing_reality_skip_sing_box "invocation_args flags do not match canonical harness order"
expect_rejected missing_grpc_omission_skip_sing_box "invocation_args flags do not match canonical harness order"
expect_rejected extra_skip_sing_box_on_unsupported "invocation_args flags do not match canonical harness order"
expect_rejected reality_invocation_with_sing_box "invocation_args flags do not match canonical harness order"
expect_rejected invocation_source_path_mismatch "xray-core source path must end in Xray-core"
expect_rejected invocation_output_mismatch "invocation output path does not match scenario"
expect_rejected result_status "embedded result 1 status must be ok"
expect_rejected result_parameters "embedded result 1 parameters do not match summary"
expect_rejected result_connections_boolean "embedded result 1 parameters do not match summary"
expect_rejected result_provenance "embedded result 1 provenance does not match summary"
expect_rejected result_run_id "embedded result 1 parameters do not match summary"
expect_rejected missing_run_index "embedded result 1.run_index is required"
expect_rejected run_index_boolean "embedded result 1.run_index must be a positive integer"
expect_rejected copied_result_repeat "embedded result run_index values must be exactly 1..5"
expect_rejected run_index_gap "embedded result run_index values must be exactly 1..5"
expect_rejected scenario_engine_run_id_mismatch "scenario run_id is inconsistent across engines"
expect_rejected scenario_run_id_reuse "run_id must be distinct across benchmark scenarios"
expect_rejected xray_core_without_source "xray-core engine source provenance is required"
expect_rejected xray_core_source_revision_mismatch "engine_source_git.revision does not match publication provenance"
expect_rejected missing_sing_source "sing-box engine source provenance is required"
expect_rejected mixed_optional_metric_runs "embedded result 5.latency_us availability does not match workload"
expect_rejected impossible_transfer_metric "embedded result 1.transfer_duration_ms availability does not match workload"
expect_rejected impossible_setup_metric "embedded result 1.setup_us availability does not match workload"
expect_rejected missing_required_setup_metric "embedded result 5.setup_us availability does not match workload"
expect_rejected missing_combination "missing required combination"
expect_rejected extra_combination "unexpected series combination"
expect_rejected extra_sing_reality_series "unexpected series combination: reality-vision-xudp/sing-box"
expect_rejected extra_sing_grpc_omission_series "unexpected series combination: stream-grpc-full-duplex-32/sing-box"
expect_rejected extra_xray_core_h3_pressure_series "unexpected series combination: xhttp-pressure-xhttp-h3-32/xray-core"
expect_rejected unreferenced_chart_input_summary "unreferenced chart-input summary"
expect_rejected unknown_top_level "manifest has unexpected field"

echo "benchmark publication policy tests passed"
