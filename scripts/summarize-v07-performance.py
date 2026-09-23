#!/usr/bin/env python3
"""Verify a completed v0.7 performance collection and aggregate every repetition.

Threshold crossings mean investigation is required, not an automatically proven
regression. Incomplete/failed groups never receive a passing median.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import statistics


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def summarize(root):
    quality=root/"quality.json"
    if quality.exists() and not json.loads(quality.read_text()).get("usable_for_performance",True):
        raise ValueError("evidence invalidated: "+json.loads(quality.read_text())["reason"])
    manifest=json.loads((root/"manifest.json").read_text())
    expected={(c["id"],v,i) for c in manifest["cases"] for v in manifest["versions"] for i in range(1,manifest["repeats"]+1)}
    actual=[(r["case"],r["version"],r["repeat"]) for r in manifest["runs"]]
    if len(actual)!=len(set(actual)) or set(actual)!=expected:
        raise ValueError("missing or duplicate scheduled runs")
    cases={c["id"]:c for c in manifest["cases"]}
    groups={}
    failures=[]
    artifact_hashes={}
    for run in manifest["runs"]:
        key=(run["case"],run["version"])
        group=groups.setdefault(key,[])
        directory=root/run["output_relative"] if "output_relative" in run else Path(run["output"])
        paths=list(directory.rglob("result.json"))
        for path in paths:
            artifact_hashes[str(path.relative_to(root))]=sha(path)
        if run["returncode"]:
            error = run.get("error")
            if len(paths)==1:
                error=json.loads(paths[0].read_text()).get("error",error)
            failures.append({"case":key[0],"version":key[1],"repeat":run["repeat"],"returncode":run["returncode"],"error":error})
            continue
        if len(paths)!=1:
            raise ValueError(f"expected one raw result: {directory}")
        result=json.loads(paths[0].read_text())
        artifact_hashes[str(paths[0].relative_to(root))]=sha(paths[0])
        if result.get("status") not in ["pass","ok"]:
            raise ValueError("successful command contains failed measurement")
        case=cases[run["case"]]
        if manifest["suite"]!="legacy":
            for k in ["connections","iterations","payload_size","traffic","path"]:
                if result[k]!=case[k]: raise ValueError(f"result axis mismatch: {k}")
            n=case["connections"]*case["iterations"]*case["payload_size"]
            sent=0 if case["traffic"]=="download" else n
            received=0 if case["traffic"]=="upload" else n
            if (result["bytes_sent"],result["bytes_received"])!=(sent,received):
                raise ValueError("validated byte counts differ from scheduled work")
            if len(result["samples"])<2:raise ValueError("missing process resource samples")
            throughput=result["throughput_mib_s"]
        else:
            arguments=case["args"]
            values={arguments[i]:arguments[i+1] for i in range(0,len(arguments),2)}
            for field in ["connections","iterations","payload_size"]:
                if result[field]!=int(values["--"+field.replace("_","-")]):
                    raise ValueError(f"legacy result axis mismatch: {field}")
            if result["workload"]!=values["--workload"]:
                raise ValueError("legacy workload mismatch")
            traffic=values.get("--traffic","download")
            n=result["connections"]*result["iterations"]*result["payload_size"]
            expected=(0 if traffic=="download" else n,0 if traffic=="upload" else n)
            if (result["bytes_sent"],result["bytes_received"])!=expected:
                raise ValueError("legacy validated byte counts differ from scheduled work")
            # Retain the original harness's integer Mbps metric and unit conversion.
            mbps=result.get("throughput_mbps")
            throughput=None if mbps is None else mbps/8/1.048576
            if result["provenance"]["engine_binary_sha256"]!=manifest["versions"][run["version"]]["engine_sha256"]:
                raise ValueError("legacy result engine hash mismatch")
        latency=(result.get("latency_us") or {}) if manifest["suite"]=="legacy" or case["traffic"] in ("tcp-latency","udp") else {}
        group.append({"throughput_mib_s":throughput,"rss_mib":result["peak_rss_kib"]/1024,
            "cpu_ms":result["cpu_millis"],"latency_us":latency.get("median"),
            "cpu_ms_per_mib":result["cpu_millis"]*1048576/(result["bytes_sent"]+result["bytes_received"])})
    rows=[]
    for case in manifest["cases"]:
        row={"case":case["id"],"versions":{},"review":[]}
        for version in manifest["versions"]:
            group=groups.get((case["id"],version),[])
            complete=len(group)==manifest["repeats"]
            metrics={}
            if complete:
                for metric in ["throughput_mib_s","rss_mib","cpu_ms","cpu_ms_per_mib","latency_us"]:
                    values=[r[metric] for r in group if r[metric] is not None]
                    if len(values)==len(group):metrics[metric]={"median":statistics.median(values),"min":min(values),"max":max(values),"samples":values}
            row["versions"][version]={"complete":complete,"passed_repeats":len(group),"metrics":metrics}
        if all(v["complete"] for v in row["versions"].values()) and "baseline" in row["versions"]:
            baseline=row["versions"]["baseline"]["metrics"]
            candidate=row["versions"]["candidate"]["metrics"]
            row["ratios"]={}
            for metric in baseline.keys() & candidate.keys():
                b=baseline[metric]["median"]
                if b==0:continue
                ratio=candidate[metric]["median"]/b
                row["ratios"][metric]=ratio
                lower=metric=="throughput_mib_s"
                if (lower and ratio<0.85) or (not lower and ratio>1.15):row["review"].append(metric)
        rows.append(row)
    return {"manifest_sha256":sha(root/"manifest.json"),"smoke":manifest["smoke"],
        "suite":manifest["suite"],"failures":failures,"rows":rows,"artifact_sha256":artifact_hashes}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root",type=Path)
    args=parser.parse_args()
    result=summarize(args.root.resolve())
    (args.root/"summary.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"rows":len(result["rows"]),"failures":len(result["failures"]),
        "review_cases":[r["case"] for r in result["rows"] if r["review"]]},indent=2))


if __name__=="__main__":main()
