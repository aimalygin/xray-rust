#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CHECKER="$WORKSPACE_ROOT/scripts/check-v05-performance.py"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
HEAD_REVISION="$(git -C "$WORKSPACE_ROOT" rev-parse --verify HEAD)"

python3 - "$TEST_ROOT" "$HEAD_REVISION" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
revision = sys.argv[2]

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")

for index in range(5):
    write(root / f"route-{index}" / "result.json", {
        "iterations": 10_000_000,
        "rules": 64,
        "outbounds": 8,
        "selected": 10_000_000,
        "avg_ns": 360,
    })
    write(root / f"dns-{index}" / "result.json", {
        "iterations": 100_000,
        "servers": 4,
        "matchers": 4_096,
        "outbound_selector_prefilter": [{
            "rules": 4_096,
            "last_hit_selected_dns": True,
            "semantic_miss_preserved_regular_path": True,
            "last_hit_avg_ns": 26_000,
            "semantic_miss_avg_ns": 26_000,
        }],
    })
    metric = {"avg_ns": 40}
    phase2 = {
        "iterations": 10_000,
        "members": 64,
        "connections": 64,
        "chain_depth": 8,
        "build_profile": "release",
        "source_revision": revision,
        "source_dirty": False,
        "peak_rss_kib": 8_000,
        "dns_upstream_calls": 1,
    }
    for field in (
        "round_robin_selection", "chain_selection", "override_switch",
        "selection_snapshot", "health_snapshot", "dns_cache_hit",
        "connection_snapshot", "accounting_snapshot", "connection_close",
        "diagnostic_queue_round_trip", "tun_stats_snapshot",
    ):
        phase2[field] = metric
    write(root / f"phase2-{index}" / "result.json", phase2)

def summary(workload, connections, rss, latency=40):
    arguments = ["run", "--connections", str(connections)]
    clean_git = {"revision": revision, "dirty": False}
    return {
        "workload": workload,
        "runs": 5,
        "status": "ok",
        "results": [{"status": "ok"} for _ in range(5)],
        "peak_rss_kib": {"median": rss},
        "latency_us": {"median": {"median": latency}},
        "provenance": {
            "harness_profile": "release",
            "workspace_git": clean_git,
            "engine_source_git": clean_git,
            "invocation_args": arguments,
        },
    }

write(root / "process-idle" / "summary.json", summary("idle", 1, 4_300))
write(root / "process-100" / "summary.json", summary("many-idle-flows", 100, 6_800))
write(root / "process-1000" / "summary.json", summary("many-idle-flows", 1000, 23_600))
write(root / "process-tcp" / "summary.json", summary("tcp-freedom", 1, 4_700, 41))
write(root / "process-tun" / "summary.json", summary("tun-tcp-freedom", 16, 5_600, 2_500))
PY

python3 "$CHECKER" "$TEST_ROOT" >/dev/null

expect_failure() {
  local expected="$1"
  set +e
  python3 "$CHECKER" "$TEST_ROOT" >"$TEST_ROOT/failure.log" 2>&1
  local status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "v0.5 performance checker accepted invalid evidence: $expected" >&2
    exit 1
  fi
  grep -Fq "$expected" "$TEST_ROOT/failure.log"
}

python3 - "$TEST_ROOT" <<'PY'
import json
import pathlib
import sys

for path in pathlib.Path(sys.argv[1]).glob("phase2-*/result.json"):
    value = json.loads(path.read_text(encoding="utf-8"))
    value["source_dirty"] = True
    path.write_text(json.dumps(value), encoding="utf-8")
PY
expect_failure 'Phase 2 dirty flag'

python3 - "$TEST_ROOT" <<'PY'
import json
import pathlib
import sys

for path in pathlib.Path(sys.argv[1]).glob("phase2-*/result.json"):
    value = json.loads(path.read_text(encoding="utf-8"))
    value["source_dirty"] = False
    path.write_text(json.dumps(value), encoding="utf-8")
path = pathlib.Path(sys.argv[1]) / "process-idle" / "summary.json"
value = json.loads(path.read_text(encoding="utf-8"))
value["provenance"]["engine_source_git"]["revision"] = "mixed-revision"
path.write_text(json.dumps(value), encoding="utf-8")
PY
expect_failure 'process engine_source_git revision'

python3 - "$TEST_ROOT" "$HEAD_REVISION" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1]) / "process-idle" / "summary.json"
value = json.loads(path.read_text(encoding="utf-8"))
value["provenance"]["engine_source_git"]["revision"] = sys.argv[2]
path.write_text(json.dumps(value), encoding="utf-8")
PY

python3 - "$TEST_ROOT" <<'PY'
import json
import pathlib
import sys

for path in pathlib.Path(sys.argv[1]).glob("route-*/result.json"):
    value = json.loads(path.read_text(encoding="utf-8"))
    value["avg_ns"] = 501
    path.write_text(json.dumps(value), encoding="utf-8")
PY
expect_failure 'route-probe avg ns exceeds its performance budget'

echo 'v0.5 performance checker validates provenance and rejects a shared-path regression'
