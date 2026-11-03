#!/usr/bin/env python3
"""v0.9 copy of docs/device-results/2026-10-18-v081-candidate/summarize-performance.py.

Paired candidate/Xray only: 0.8.1 has none of the v0.9 outbounds, so there is
no previous-release baseline. Each schema-4 sample is the worst profile of its
group in that repeat (lowest throughput ratio, highest latency ratio, highest
candidate RSS), as in 0.8.1. Usage: summarize_protocols_v09.py <collection-dir>"""
import json, pathlib, statistics, sys

d = pathlib.Path(sys.argv[1])
m = json.loads((d / "manifest.json").read_text())
groups = m["measurementGroups"]
raw, by = [], {}
for run in m["runs"]:
    name = f"{run['case']}-{run['version']}-{run['repeat']}"
    result = json.loads((d / name / "result.json").read_text())
    assert result["status"] == "pass" and run["returncode"] == 0 and not run["surviving_process_group"], name
    raw.append({"case": run["case"], "version": run["version"], "repeat": run["repeat"], "order": run["order"],
                "ambient": run["ambient_cpu"], "processGroupEmpty": run["process_group_empty_after_run"],
                "result": result})
    by[(run["case"], run["version"], run["repeat"])] = result
versions = ["candidate", "xray"]
comparisons = []
for profile in [p for selected in groups.values() for p in selected]:
    case = lambda work: f"{profile}-socks-{work}-1"
    throughput = {v: [by[(case("full-duplex"), v, k)]["throughput_mib_s"] for k in range(1, 6)] for v in versions}
    latency = {v: [by[(case("tcp-latency"), v, k)]["latency_us"]["p95"] for k in range(1, 6)] for v in versions}
    memory = {v: [max(by[(case(work), v, k)]["peak_rss_kib"] for work in ("full-duplex", "tcp-latency")) / 1024
                  for k in range(1, 6)] for v in versions}
    ratios = {metric: [x / y for x, y in zip(values["candidate"], values["xray"])]
              for metric, values in [("throughput", throughput), ("latency", latency), ("memory", memory)]}
    checks = {"throughputVsXray": statistics.median(ratios["throughput"]) >= .5,
              "latencyVsXray": statistics.median(ratios["latency"]) <= 2,
              "memoryWithin64MiB": statistics.median(memory["candidate"]) <= 64}
    comparisons.append({"profile": profile, "throughputMiBs": throughput, "p95LatencyUs": latency,
                        "sampledPeakRSSMiB": memory, "pairedRatiosVsXray": ratios, "checks": checks})
measurements = []
for protocol, selected in groups.items():
    rows = [c for c in comparisons if c["profile"] in selected]
    assert len(rows) == len(selected), protocol
    for metric, unit, comparison, threshold in [
            ("throughput", "% of paired Xray throughput", "at-least", 50),
            ("latency", "% of paired Xray p95 latency", "at-most", 200),
            ("memory", "MiB sampled peak RSS", "at-most", 64)]:
        samples = []
        for k in range(5):
            values = [r["sampledPeakRSSMiB"]["candidate"][k] if metric == "memory"
                      else 100 * r["pairedRatiosVsXray"][metric][k] for r in rows]
            samples.append(min(values) if metric == "throughput" else max(values))
        measurements.append({"id": f"{protocol}-{metric}", "unit": unit, "samples": samples,
                             "comparison": comparison, "threshold": threshold})
expected = sum(len(s) for s in groups.values()) * 2 * 5 * len(versions)
out = {"complete": m.get("status") == "pass" and len(raw) == expected, "trialCount": len(raw),
       "profiles": comparisons, "schema4Measurements": measurements,
       "allProfilesPassed": all(v for c in comparisons for v in c["checks"].values()),
       "scope": "Single-flow loopback SOCKS ingress, five rotating-order paired repetitions against pinned "
                "Xray-core v26.10.21 over a common Xray-core server; native release profile. "
                "No previous-release baseline: 0.8.1 has none of these outbounds. Original outliers retained."}
(d / "benchmark-raw.json").write_text(json.dumps(raw, indent=2) + "\n")
(d / "protocol-comparisons.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps({"complete": out["complete"], "trials": len(raw), "allProfilesPassed": out["allProfilesPassed"],
                  "measurements": [{"id": x["id"], "median": round(statistics.median(x["samples"]), 2),
                                    "comparison": x["comparison"], "threshold": x["threshold"]} for x in measurements],
                  "profiles": [{"profile": c["profile"], "checks": c["checks"],
                                "medians": {k: round(statistics.median(v), 3) for k, v in c["pairedRatiosVsXray"].items()}}
                               for c in comparisons]}, indent=2))
