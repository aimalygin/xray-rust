#!/usr/bin/env python3
"""Validate the clean five-run v0.5 pre-device performance evidence."""

from __future__ import annotations

import json
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REPEATS = 5


def fail(message: str) -> None:
    raise SystemExit(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"cannot read benchmark JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"benchmark JSON must be an object: {path}")
    return value


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label}: expected {expected!r}, found {actual!r}")


def median(values: list[int], label: str) -> int:
    if len(values) != EXPECTED_REPEATS:
        fail(f"{label}: expected {EXPECTED_REPEATS} results, found {len(values)}")
    return int(statistics.median(values))


def require_budget(label: str, actual: int, maximum: int, baseline: int | None = None) -> None:
    relation = f"; v0.4.0 baseline={baseline}" if baseline is not None else ""
    print(f"{label}: median={actual}, budget<={maximum}{relation}")
    if actual > maximum:
        fail(f"{label} exceeds its performance budget: {actual} > {maximum}")


def invocation_value(summary: dict[str, Any], flag: str) -> str | None:
    arguments = summary.get("provenance", {}).get("invocation_args", [])
    if not isinstance(arguments, list):
        return None
    try:
        index = arguments.index(flag)
    except ValueError:
        return None
    return str(arguments[index + 1]) if index + 1 < len(arguments) else None


def validate_process_summary(summary: dict[str, Any], head: str) -> None:
    require_equal(summary.get("runs"), EXPECTED_REPEATS, "process summary runs")
    require_equal(summary.get("status"), "ok", "process summary status")
    require_equal(len(summary.get("results", [])), EXPECTED_REPEATS, "process result count")
    provenance = summary.get("provenance", {})
    require_equal(provenance.get("harness_profile"), "release", "process harness profile")
    for source in ("workspace_git", "engine_source_git"):
        git = provenance.get(source, {})
        require_equal(git.get("revision"), head, f"process {source} revision")
        require_equal(git.get("dirty"), False, f"process {source} dirty flag")
    for result in summary.get("results", []):
        require_equal(result.get("status"), "ok", "embedded process result status")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check-v05-performance.py <benchmark-output-root>")
    root = Path(sys.argv[1]).expanduser().resolve()
    if not root.is_dir():
        fail(f"benchmark output root does not exist: {root}")

    head = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "--verify", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    routes: list[dict[str, Any]] = []
    dns: list[dict[str, Any]] = []
    phase2: list[dict[str, Any]] = []
    for path in root.rglob("result.json"):
        document = load_json(path)
        if "round_robin_selection" in document:
            phase2.append(document)
        elif "outbound_selector_prefilter" in document:
            dns.append(document)
        elif {"rules", "outbounds", "avg_ns"}.issubset(document):
            routes.append(document)

    for route in routes:
        require_equal(route.get("iterations"), 10_000_000, "route iterations")
        require_equal(route.get("rules"), 64, "route rules")
        require_equal(route.get("outbounds"), 8, "route outbounds")
        require_equal(route.get("selected"), 10_000_000, "route selected count")
    require_budget(
        "route-probe avg ns",
        median([int(result["avg_ns"]) for result in routes], "route-probe"),
        500,
        384,
    )

    dns_last: list[int] = []
    dns_semantic_miss: list[int] = []
    for result in dns:
        require_equal(result.get("iterations"), 100_000, "DNS iterations")
        require_equal(result.get("servers"), 4, "DNS servers")
        require_equal(result.get("matchers"), 4_096, "DNS matchers")
        selector = next(
            (item for item in result["outbound_selector_prefilter"] if item.get("rules") == 4_096),
            None,
        )
        if selector is None:
            fail("DNS result omitted the 4096-rule selector slice")
        require_equal(selector.get("last_hit_selected_dns"), True, "DNS selector last hit")
        require_equal(
            selector.get("semantic_miss_preserved_regular_path"),
            True,
            "DNS selector semantic miss",
        )
        dns_last.append(int(selector["last_hit_avg_ns"]))
        dns_semantic_miss.append(int(selector["semantic_miss_avg_ns"]))
    require_budget("DNS selector last-hit ns", median(dns_last, "DNS selector"), 30_000, 21_896)
    require_budget(
        "DNS selector semantic-miss ns",
        median(dns_semantic_miss, "DNS semantic miss"),
        30_000,
        21_980,
    )

    phase2_metrics = {
        "round-robin selection ns": ("round_robin_selection", 200),
        "chain selection ns": ("chain_selection", 600),
        "override switch ns": ("override_switch", 250),
        "selection snapshot ns": ("selection_snapshot", 3_000),
        "health snapshot ns": ("health_snapshot", 3_500),
        "DNS cache-hit ns": ("dns_cache_hit", 300),
        "connection snapshot ns": ("connection_snapshot", 5_000),
        "accounting snapshot ns": ("accounting_snapshot", 100),
        "connection close ns": ("connection_close", 4_000),
        "diagnostic queue round-trip ns": ("diagnostic_queue_round_trip", 150),
        "TUN stats snapshot ns": ("tun_stats_snapshot", 50),
    }
    phase2_revisions: set[str] = set()
    for result in phase2:
        require_equal(result.get("iterations"), 10_000, "Phase 2 iterations")
        require_equal(result.get("members"), 64, "Phase 2 members")
        require_equal(result.get("connections"), 64, "Phase 2 connections")
        require_equal(result.get("chain_depth"), 8, "Phase 2 chain depth")
        require_equal(result.get("build_profile"), "release", "Phase 2 build profile")
        require_equal(result.get("source_dirty"), False, "Phase 2 dirty flag")
        require_equal(result.get("dns_upstream_calls"), 1, "Phase 2 DNS upstream calls")
        phase2_revisions.add(str(result.get("source_revision")))
    require_equal(phase2_revisions, {head}, "Phase 2 source revisions")
    require_budget(
        "Phase 2 peak RSS KiB",
        median([int(result["peak_rss_kib"]) for result in phase2], "Phase 2 RSS"),
        10_240,
    )
    for label, (field, maximum) in phase2_metrics.items():
        require_budget(
            label,
            median([int(result[field]["avg_ns"]) for result in phase2], label),
            maximum,
        )

    summaries = [load_json(path) for path in root.rglob("summary.json")]
    if len(summaries) != 5:
        fail(f"expected five process summaries, found {len(summaries)}")
    for summary in summaries:
        validate_process_summary(summary, head)

    def one_summary(workload: str, connections: str | None = None) -> dict[str, Any]:
        matches = [
            summary
            for summary in summaries
            if summary.get("workload") == workload
            and (connections is None or invocation_value(summary, "--connections") == connections)
        ]
        if len(matches) != 1:
            fail(f"expected one {workload}/{connections or '-'} summary, found {len(matches)}")
        return matches[0]

    idle = one_summary("idle")
    flows_100 = one_summary("many-idle-flows", "100")
    flows_1000 = one_summary("many-idle-flows", "1000")
    tcp = one_summary("tcp-freedom", "1")
    tun = one_summary("tun-tcp-freedom", "16")
    require_budget("idle RSS KiB", int(idle["peak_rss_kib"]["median"]), 5_120, 3_932)
    require_budget(
        "100-flow RSS KiB", int(flows_100["peak_rss_kib"]["median"]), 7_500, 5_632
    )
    require_budget(
        "1000-flow RSS KiB", int(flows_1000["peak_rss_kib"]["median"]), 25_000, 18_708
    )
    require_budget(
        "TCP median latency us", int(tcp["latency_us"]["median"]["median"]), 55, 39
    )
    require_budget("fd-backed TUN RSS KiB", int(tun["peak_rss_kib"]["median"]), 8_192)
    print(f"v0.5 pre-device performance evidence passed at {head}")


if __name__ == "__main__":
    main()
