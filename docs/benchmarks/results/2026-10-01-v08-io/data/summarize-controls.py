#!/usr/bin/env python3
"""Recompute control medians/ranges from the verified numeric archive."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import statistics
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    index = json.loads((args.report / "evidence-index.json").read_text())
    archive = args.report / index["archive"]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == index["archive_sha256"]
    with tarfile.open(archive) as tar:
        assert {m.name for m in tar.getmembers()} == set(index["file_sha256"])
        files = {}
        for name, digest in index["file_sha256"].items():
            data = tar.extractfile(name).read()
            assert hashlib.sha256(data).hexdigest() == digest, name
            files[name] = data
    def read(name):
        return json.loads(files[name])
    def stats(samples):
        return {"median": statistics.median(samples), "min": min(samples),
                "max": max(samples), "samples": samples}
    output = {"archive_sha256": index["archive_sha256"], "groups": {}}
    counts = {"decouple-controls": 48, "read-controls": 48,
              "erasure-controls": 72, "final-controls": 144, "duplex-confirmation": 10}
    for group, count in counts.items():
        manifest = read(group + "/manifest.json")
        assert len(manifest["runs"]) == count
        assert manifest["status"] == "pass"
        records = collections.defaultdict(lambda: collections.defaultdict(list))
        excluded = []
        for run in manifest["runs"]:
            assert run["returncode"] == 0 and run["process_group_empty_after_run"]
            assert not run["remaining_engine_processes"] and not run["surviving_process_group"]
            assert not run["ambient_cpu"]["compiler_load_detected"]
            assert not run["ambient_cpu"]["observer_errors"]
            result = read(group + "/" + run["output_relative"] + "/result.json")
            assert result["engine_sha256"] == manifest["file_hashes"][result["engine_binary"]]
            metrics = {"cpu_ms": result["cpu_millis"],
                       "throughput_mib_s": result["throughput_mib_s"],
                       "rss_mib": result["peak_rss_kib"] / 1024}
            for metric, value in metrics.items():
                records[(run["case"], run["version"])][metric].append(value)
        rows = []
        for (case, version), metrics in sorted(records.items()):
            assert all(len(samples) == manifest["repeats"] for samples in metrics.values())
            rows.append({"case": case, "version": version,
                         "metrics": {m: stats(s) for m, s in metrics.items()}})
        output["groups"][group] = {"repeats": manifest["repeats"], "rows": rows, "excluded_runs": excluded}
    memory = read("held-memory/manifest.json")
    assert memory["status"] == "pass" and len(memory["runs"]) == 24
    records = collections.defaultdict(list)
    for run in memory["runs"]:
        result = read("held-memory/" + run["output_relative"] + "/result.json")
        assert result["status"] == "pass" and not result["remaining_engine_processes"]
        assert result["engine_sha256"] == memory["file_hashes"][result["binary"]]
        assert result["checked_bytes_each_direction"] == 512 * 8192
        assert [p["connections"] for p in result["points"]] == [0, 32, 128, 512]
        for point in result["points"]:
            samples = [p["rss_kib"] for p in point["samples"]]
            assert len(samples) == 5 and statistics.median(samples) == point["rss_kib_median"]
            records[(run["profile"], run["version"], point["connections"])].append(point["rss_kib_median"] / 1024)
    output["held_memory"] = []
    for (profile, version, connections), samples in sorted(records.items()):
        assert len(samples) == 3
        output["held_memory"].append({"profile": profile, "version": version,
                                      "connections": connections, "rss_mib": stats(samples)})
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(f"Verified {len(files)} archived files; controls have their declared clean repeat counts.")


if __name__ == "__main__":
    main()
