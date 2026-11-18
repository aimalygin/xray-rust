#!/usr/bin/env python3
"""v0.10 copy of docs/device-results/2026-11-02-v090-candidate/tools/summarize_protocols_v09.py.

Turns the `v010` suite of run-v08-protocol-comparison.py into the gate's six measurements,
`mkcp-` and `masque-` `throughput`, `latency` and `memory`, the way 0.9.0 computed its
protocol rows (docs/v010-release-evidence.md "mKCP and MASQUE against Xray-core"): paired
candidate/Xray-core client over a common Xray-core server, five rotating-order repeats; each
sample is the worst profile of its group in that repeat (one profile per group here), with
0.9.0's thresholds (throughput at least 50% of paired Xray-core, p95 latency at most 200%,
sampled peak RSS at most 64 MiB). Changes from v0.9: the collection's own `client_order`
field, the v010 groups (mkcp: mkcp-vless, masque: masque-h3, ten cases each), the reference
Xray-core v26.11.9, and an output directory apart from the measured one.
Usage: summarize_protocols_v010.py <collection-dir> <output-dir>"""
import json, pathlib, statistics, sys

d, out_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
out_dir.mkdir(parents=True, exist_ok=True)
m = json.loads((d / "manifest.json").read_text())
groups = m["measurement_groups"]
raw, by = [], {}
for run in m["runs"]:
    name = run["output_relative"]
    result = json.loads((d / name / "result.json").read_text())
    assert result["status"] == "pass" and run["returncode"] == 0 and not run["surviving_process_group"], name
    raw.append({"case": run["case"], "version": run["version"], "repeat": run["repeat"],
                "clientOrder": run["client_order"], "ambient": run["ambient_cpu"],
                "processGroupEmpty": run["process_group_empty_after_run"], "result": result})
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
cases_per_profile = len({run["case"] for run in m["runs"]}) // sum(len(s) for s in groups.values())
expected = sum(len(s) for s in groups.values()) * cases_per_profile * 5 * len(versions)
out = {"complete": m.get("status") == "pass" and len(raw) == expected, "trialCount": len(raw),
       "profiles": comparisons, "schema5Measurements": measurements,
       "allProfilesPassed": all(v for c in comparisons for v in c["checks"].values()),
       "scope": "Single-flow loopback SOCKS ingress, five rotating-order paired repetitions against pinned "
                "Xray-core v26.11.9 over a common Xray-core server; native release profile; sing-box implements "
                "neither carrier. The suite's eight-flow and upload/download/UDP cases stay in benchmark-raw.json "
                "and are not gate rows. Original outliers retained."}
(out_dir / "benchmark-raw.json").write_text(json.dumps(raw, indent=2) + "\n")
(out_dir / "protocol-comparisons.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps({"complete": out["complete"], "trials": len(raw), "allProfilesPassed": out["allProfilesPassed"],
                  "measurements": [{"id": x["id"], "median": round(statistics.median(x["samples"]), 2),
                                    "samples": [round(s, 2) for s in x["samples"]],
                                    "comparison": x["comparison"], "threshold": x["threshold"]} for x in measurements]},
                 indent=2))
