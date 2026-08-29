#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
sing_revision = "3708fa18766cda1f11b77f6ed9c7bd61688f17df"

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
            "version": "v1.13.15",
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
    add(
        scenario,
        engines,
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
            add(
                f"stream-{transport}-{traffic}-{flows}",
                engines,
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
        add(
            f"xhttp-pressure-{transport}-{flows}",
            ("xray-rust", "xray-core"),
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
summaries = {}
for index, (scenario, engine, fields) in enumerate(series):
    summary_path = f"summaries/{index:03d}-{scenario}-{engine}.json"
    provenance = {
        "harness_profile": "release",
        "workspace_git": {"revision": candidate_revision, "dirty": False},
        "engine_source_git": {
            "revision": engine_revisions[engine],
            "dirty": False,
        },
        "harness_binary_path": "/tmp/xray-bench",
        "harness_binary_sha256": "d" * 64,
        "engine_binary_path": f"/tmp/{engine}",
        "engine_binary_sha256": engine_hashes[engine],
        "working_directory": "/tmp/xray-rust",
        "invocation_args": ["compare", "--engine", engine],
    }
    summary = {
        "run_id": "publication-run",
        "engine": engine,
        "workload": fields["workload"],
        "status": "ok",
        "runs": 5,
        "connections": fields["connections"],
        "iterations": fields["iterations"],
        "payload_size": fields["payload_size"],
        "stream_transport": fields.get("stream_transport"),
        "stream_traffic": fields.get("stream_traffic"),
        "xhttp_mode": fields.get("xhttp_mode"),
        "xhttp_profile": fields.get("xhttp_profile"),
        "xhttp_max_post_bytes": fields.get("xhttp_max_post_bytes"),
        "settle_ms": 5_000 if scenario.startswith("xhttp-memory-") else 0,
        "dns_transport": None,
        "dns_upstream_transport": None,
        "provenance": provenance,
    }
    result_template = {
        "engine": summary["engine"],
        "workload": summary["workload"],
        "status": summary["status"],
        "connections": summary["connections"],
        "iterations": summary["iterations"],
        "payload_size": summary["payload_size"],
        "stream_transport": summary["stream_transport"],
        "stream_traffic": summary["stream_traffic"],
        "xhttp_mode": summary["xhttp_mode"],
        "xhttp_profile": summary["xhttp_profile"],
        "xhttp_max_post_bytes": summary["xhttp_max_post_bytes"],
        "settle_ms": summary["settle_ms"],
        "dns_transport": summary["dns_transport"],
        "dns_upstream_transport": summary["dns_upstream_transport"],
        "provenance": copy.deepcopy(provenance),
    }
    summary["results"] = []
    for _ in range(5):
        result = copy.deepcopy(result_template)
        result["run_id"] = "publication-run"
        summary["results"].append(result)
    summaries[summary_path] = summary
    manifest["series"].append(
        {"scenario": scenario, "engine": engine, "summary": summary_path}
    )

target_path = manifest["series"][0]["summary"]
target = summaries[target_path]
if mutation == "wrong_xray_revision":
    manifest["comparators"]["xray-core"]["revision"] = "0" * 40
elif mutation == "wrong_xray_version":
    manifest["comparators"]["xray-core"]["version"] = "v0.0.0"
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
elif mutation == "malformed_sing_revision":
    manifest["comparators"]["sing-box"]["revision"] = "R" * 40
elif mutation == "malformed_archive_digest":
    manifest["rawArchive"]["sha256"] = "sha256:bad"
elif mutation == "empty_environment":
    manifest["environment"]["hardware"] = ""
elif mutation == "empty_raw_location":
    manifest["rawArchive"]["location"] = ""
elif mutation == "duplicate_series":
    manifest["series"].append(copy.deepcopy(manifest["series"][0]))
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
elif mutation == "missing_combination":
    manifest["series"].pop()
elif mutation == "extra_combination":
    extra = copy.deepcopy(manifest["series"][0])
    extra["scenario"] = "unreviewed-scenario"
    manifest["series"].append(extra)
elif mutation == "unknown_top_level":
    manifest["unexpected"] = True
elif mutation == "additive_series_metadata":
    manifest["series"][0]["runCount"] = 5
    manifest["series"][0]["unavailableMetrics"] = ["packet-loss"]
elif mutation == "alternate_sing_pin":
    alternate_revision = "f" * 40
    manifest["comparators"]["sing-box"]["version"] = "v9.8.7"
    manifest["comparators"]["sing-box"]["revision"] = alternate_revision
    for entry in manifest["series"]:
        if entry["engine"] != "sing-box":
            continue
        summary = summaries[entry["summary"]]
        summary["provenance"]["engine_source_git"]["revision"] = alternate_revision
        for result in summary["results"]:
            result["provenance"]["engine_source_git"]["revision"] = alternate_revision
elif mutation == "xray_core_without_source":
    for entry in manifest["series"]:
        if entry["engine"] != "xray-core":
            continue
        summary = summaries[entry["summary"]]
        summary["provenance"].pop("engine_source_git")
        for result in summary["results"]:
            result["provenance"].pop("engine_source_git")
elif mutation == "missing_sing_source":
    sing_entry = next(
        entry for entry in manifest["series"] if entry["engine"] == "sing-box"
    )
    summaries[sing_entry["summary"]]["provenance"].pop("engine_source_git")
elif mutation not in {
    "valid",
    "missing_manifest",
    "malformed_manifest_json",
    "malformed_summary_json",
    "manifest_wrong_root",
    "summary_wrong_root",
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
PY
}

expect_rejected() {
  local mutation="$1"
  local expected_reason="$2"
  local fixture="$tmp_dir/$mutation"
  local output

  make_fixture "$fixture" "$mutation"
  if output="$(python3 "$validator" "$fixture" 2>&1)"; then
    fail "$mutation was accepted"
  fi
  if ! grep -Fq "$expected_reason" <<<"$output"; then
    fail "$mutation did not report '$expected_reason': $output"
  fi
}

valid_fixture="$tmp_dir/valid"
make_fixture "$valid_fixture"
valid_output="$(python3 "$validator" "$valid_fixture")"
grep -Fq "validated benchmark publication: 143 series" <<<"$valid_output" \
  || fail "valid publication did not report the complete matrix: $valid_output"

for valid_variant in \
  additive_series_metadata \
  alternate_sing_pin \
  xray_core_without_source; do
  variant_fixture="$tmp_dir/$valid_variant"
  make_fixture "$variant_fixture" "$valid_variant"
  variant_output="$(python3 "$validator" "$variant_fixture")"
  grep -Fq "validated benchmark publication: 143 series" <<<"$variant_output" \
    || fail "$valid_variant did not validate: $variant_output"
done

expect_rejected wrong_xray_revision "xray-core revision must be"
expect_rejected wrong_xray_version "xray-core version must be v26.7.28"
expect_rejected malformed_candidate_digest "candidate.revision must be 40 lowercase hexadecimal characters"
expect_rejected candidate_dirty "candidate.dirty must be false"
expect_rejected malformed_xray_digest "comparators.xray-core.binarySha256 must be 64 lowercase hexadecimal characters"
expect_rejected malformed_sing_digest "comparators.sing-box.binarySha256 must be 64 lowercase hexadecimal characters"
expect_rejected malformed_sing_version "comparators.sing-box.version must be a stable vMAJOR.MINOR.PATCH tag"
expect_rejected malformed_sing_revision "comparators.sing-box.revision must be 40 lowercase hexadecimal characters"
expect_rejected malformed_archive_digest "rawArchive.sha256 must be 64 lowercase hexadecimal characters"
expect_rejected empty_environment "environment.hardware must be non-empty"
expect_rejected empty_raw_location "rawArchive.location must be non-empty"
expect_rejected duplicate_series "duplicate series"
expect_rejected escaping_path "summary path escapes publication root"
expect_rejected absolute_path "summary path escapes publication root"
expect_rejected malformed_path "invalid summary path"
expect_rejected prefix_sibling_escape "summary path escapes publication root"
expect_rejected symlink_escape "summary path escapes publication root"
expect_rejected missing_summary "summary file does not exist"
expect_rejected summary_directory "summary file does not exist"
expect_rejected missing_manifest "publication manifest.json does not exist"
expect_rejected malformed_manifest_json "invalid JSON in manifest.json"
expect_rejected malformed_summary_json "invalid JSON in summary"
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
expect_rejected result_status "embedded result 1 status must be ok"
expect_rejected result_parameters "embedded result 1 parameters do not match summary"
expect_rejected result_connections_boolean "embedded result 1 parameters do not match summary"
expect_rejected result_provenance "embedded result 1 provenance does not match summary"
expect_rejected result_run_id "embedded result 1 parameters do not match summary"
expect_rejected missing_sing_source "sing-box engine source provenance is required"
expect_rejected missing_combination "missing required combination"
expect_rejected extra_combination "unexpected series combination"
expect_rejected unknown_top_level "manifest has unexpected field"

echo "benchmark publication policy tests passed"
