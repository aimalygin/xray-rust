#!/usr/bin/env python3
"""Measure every protocol 0.9.0 shipped on a build of the published v0.9.0 tag
and on the candidate, in one run, and write the "release-comparison" artifact.

Both clients and the driver are builds made by build-isolated-release.py in
one campaign directory: bin/baseline (the v0.9.0 tag), bin/candidate and
bin/harness (the candidate's xray-bench), each with its build/NAME.json.

Each repeat starts a fresh pinned Xray-core server with fresh keys, the
device fixture's twelve legacy-regression cases, and runs both builds on one
SOCKS flow per protocol, full-duplex bulk and TCP latency, in alternating
order. Throughput is the bulk run's MiB/s, latency the latency run's p95,
memory the larger sampled peak RSS of the two runs.

The verdicts, and the budgets behind them, are the checker's
(check-v010-release-evidence.py): this script holds no threshold of its own.
The artifact is written only by a complete run: every protocol, at least
five repeats, the full work size. Anything less writes a diagnostic document
of the same shape under another name. REALITY's decoy handshake needs
www.google.com:443 reachable from this host, as in the device fixture.
"""
import argparse
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


comparison = module("comparison", "run-v08-protocol-comparison.py")
acceptance = module("acceptance", "run-v08-apple-acceptance-fixture.py")
policy = module("policy", "check-v010-release-evidence.py")
bench, followup = comparison.bench, comparison.followup

VERSIONS = ("baseline", "candidate")
BUILDS = (*VERSIONS, "harness")
# metric -> the workload that yields it; memory is read from both.
WORKLOADS = {"throughput": "full-duplex", "latency": "tcp-latency"}
UNITS = {"throughput": "MiB/s", "latency": "microseconds, p95", "memory": "MiB sampled peak RSS"}
ARTIFACT, DIAGNOSTIC = "release-comparison.json", "diagnostic-comparison.json"
# REALITY's first decoy handshake, as in run-v07-performance.py.
WARMUP_SECONDS = 8


def build(campaign, name):
    """One build-isolated-release.py record, with its binary still as recorded."""
    record = json.loads((campaign / "build" / (name + ".json")).read_text())
    binary = campaign / "bin" / name
    if record.get("isolated_target") is not True or record.get("incremental") is not False or record.get("rustflags"):
        raise ValueError(f"{name} is not a clean isolated build")
    if bench.sha(binary) != record["sha256"]:
        raise ValueError(f"{name} differs from its recorded build")
    return {**record, "path": str(binary.resolve())}


def builds(campaign):
    """The three builds; the baseline is the tag the checker names."""
    found = {name: build(campaign, name) for name in BUILDS}
    baseline = {"version": policy.BASELINE["version"], "revision": found["baseline"]["commit"],
                "tree": found["baseline"]["tree"]}
    if baseline != policy.BASELINE:
        raise ValueError("the baseline is not the published v" + policy.BASELINE["version"] + " revision and tree")
    if found["harness"]["commit"] != found["candidate"]["commit"]:
        raise ValueError("the driver must be built from the candidate's commit")
    return found


def cases(protocols, smoke=False):
    return [{"id": f"{protocol}-{traffic}", "protocol": protocol, "path": "socks", "traffic": traffic,
             "connections": 1, "payload_size": 1024 if traffic == "tcp-latency" else 65536,
             "iterations": (10 if smoke else 1000) if traffic == "tcp-latency" else (4 if smoke else 4096)}
            for protocol in protocols for traffic in WORKLOADS.values()]


def client_configs(envelope):
    """Each legacy case's outbound alone: the driver adds its own SOCKS inbound."""
    configs = {}
    for case in envelope["cases"]:
        config = json.loads(case["configJSON"])
        for section in ("inbounds", "dns", "routing"):
            config.pop(section, None)
        if case["format"] == "wireguard":
            # The driver's origin is this host's own address, not the fixture's.
            config["outbounds"][0]["settings"]["peers"][0]["allowedIPs"] = ["0.0.0.0/0"]
        configs[case["label"]] = config
    if set(configs) != policy.LEGACY_PROTOCOLS:
        raise RuntimeError(f"the legacy fixture does not cover the comparison: {sorted(configs)}")
    return configs


@contextlib.contextmanager
def fixture(reference, directory):
    """A pinned Xray-core server carrying all twelve protocols, with fresh keys."""
    directory.mkdir(parents=True, mode=0o700)
    acceptance.write_legacy_v010(directory, "127.0.0.1", 1, 2, 3)
    server = json.loads((directory / "server.json").read_text())
    # The driver's origin is this host's own address; nothing leaves the host.
    server.pop("routing", None)
    server["outbounds"] = [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
    bench.save(directory / "server.json", server)
    configs = client_configs(json.loads((directory / "v07-probe.json").read_text()))
    with (directory / "server.log").open("w") as log:
        child = subprocess.Popen([str(reference), "run", "-config", str(directory / "server.json")],
                                 stdout=log, stderr=log, env=bench.env())
        try:
            time.sleep(WARMUP_SECONDS)
            if child.poll() is not None:
                raise RuntimeError("the reference server failed to start; see " + str(directory / "server.log"))
            yield configs, child
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def order(index, repeat):
    """Which build goes first alternates by protocol and by repeat."""
    return list(VERSIONS) if (index + repeat) % 2 else list(reversed(VERSIONS))


def samples(results, protocols, repeats):
    """results[(case id, version, repeat)] -> samples[protocol][metric][version]."""
    out = {}
    for protocol in protocols:
        read = lambda traffic, version, repeat: results[(f"{protocol}-{traffic}", version, repeat)]
        out[protocol] = {
            "throughput": {v: [read("full-duplex", v, k)["throughput_mib_s"] for k in repeats] for v in VERSIONS},
            "latency": {v: [read("tcp-latency", v, k)["latency_us"]["p95"] for k in repeats] for v in VERSIONS},
            "memory": {v: [max(read(traffic, v, k)["peak_rss_kib"] for traffic in WORKLOADS.values()) / 1024
                           for k in repeats] for v in VERSIONS}}
    return out


def release_comparison(measured, revision, tree):
    """The artifact: one row per protocol and metric, judged the checker's way."""
    rows = []
    for protocol in sorted(measured):
        for metric in policy.COMPARISON_BUDGETS:
            sides = measured[protocol][metric]
            rows.append({"id": f"{protocol}-{metric}", "unit": UNITS[metric],
                         "baseline": sides["baseline"], "candidate": sides["candidate"],
                         "verdict": policy.comparison_verdict(metric, sides["baseline"], sides["candidate"])})
    return {"schemaVersion": 1, "baseline": dict(policy.BASELINE),
            "candidate": {"revision": revision, "tree": tree}, "measurements": rows}


def regressions(document):
    return [row["id"] for row in document["measurements"] if row["verdict"] == "regression"]


def complete(manifest):
    """Whether this run may write the artifact rather than a diagnostic."""
    return (not manifest["smoke"] and manifest["repeats"] >= 5
            and set(manifest["protocols"]) == policy.LEGACY_PROTOCOLS)


def summary(document):
    lines = []
    for row in document["measurements"]:
        baseline, candidate = statistics.median(row["baseline"]), statistics.median(row["candidate"])
        lines.append(f"{row['id']:28} {baseline:12.2f} {candidate:12.2f} {candidate * 100 / baseline:7.1f}%  {row['verdict']}")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--campaign", type=Path, required=True, help="bin/ and build/ of the three isolated builds")
    p.add_argument("--reference", type=Path, required=True, help="the pinned Xray-core binary")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--protocol", choices=sorted(policy.LEGACY_PROTOCOLS), action="append",
                   help="diagnostic: measure only these; writes no artifact")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--smoke", action="store_true", help="diagnostic: a tiny work size; writes no artifact")
    a = p.parse_args()
    if not 1 <= a.repeats <= 20 or (a.protocol and len(set(a.protocol)) != len(a.protocol)):
        raise ValueError("1..20 repetitions and unique protocols required")
    if set(UNITS) != set(policy.COMPARISON_BUDGETS):
        raise RuntimeError("the checker's metrics changed; this collector does not measure them all")
    for variable in ("GOMAXPROCS", "TOKIO_WORKER_THREADS", "GOMEMLIMIT", "GOGC"):
        os.environ.pop(variable, None)
    os.umask(0o077)
    campaign, reference = a.campaign.resolve(strict=True), a.reference.resolve(strict=True)
    identities = builds(campaign)
    comparison.device.verify_reference(reference)
    engines = [Path(identities[name]["path"]) for name in BUILDS] + [reference]
    if followup.inventory(engines) or comparison.ambient()["compiler_load_detected"]:
        raise RuntimeError("benchmark/compiler already running")
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    protocols = a.protocol or sorted(policy.LEGACY_PROTOCOLS)
    files = [*engines, Path(__file__).resolve(), Path(comparison.__file__), Path(acceptance.__file__),
             Path(policy.__file__), Path(bench.__file__), Path(comparison.device.__file__)]
    hashes = {str(f): bench.sha(f) for f in files}
    manifest = {"schema_version": 1, "smoke": a.smoke, "repeats": a.repeats, "protocols": protocols,
                "cases": cases(protocols, a.smoke), "builds": identities, "baseline": dict(policy.BASELINE),
                "budgets": {metric: list(budget) for metric, budget in policy.COMPARISON_BUDGETS.items()},
                "reference_commit": bench.REFERENCE, "reference_sha256": bench.sha(reference),
                "file_hashes": hashes, "platform": platform.platform(),
                "fixture_policy": "one fresh pinned Xray-core server and key set per repeat, shared by both builds",
                "process_accounting": "real full client launched directly; verified TCP warmup",
                "scope": "single-flow loopback SOCKS ingress; published v0.9.0 against the candidate; "
                         "no TUN comparison and no physical-device claim",
                "started_unix": time.time(), "runs": []}
    bench.save(out / "manifest.json", manifest)
    results = {}
    for repeat in range(1, a.repeats + 1):
        if comparison.ambient()["compiler_load_detected"]:
            raise RuntimeError("compiler started during measurement; results retained")
        with fixture(reference, out / f"server-{repeat}") as (configs, server):
            for index, case in enumerate(manifest["cases"]):
                for version in order(index // len(WORKLOADS), repeat):
                    if server.poll() is not None:
                        raise RuntimeError("the reference server exited; results retained")
                    name = f"{case['id']}-{version}-{repeat}"
                    request = {k: case[k] for k in ("path", "traffic", "connections", "iterations", "payload_size")}
                    request.update(binary=identities[version]["path"], config=copy.deepcopy(configs[case["protocol"]]),
                                   output=str(out / name), warmup=True,
                                   client_preface=case["traffic"] != "tcp-latency")
                    bench.save(out / (name + ".json"), request)
                    run = comparison.measured_execute(
                        [identities["harness"]["path"], "protocol-run", str(out / (name + ".json"))],
                        out / (name + ".log"))
                    remaining = [s for s in followup.inventory(engines) if int(s.split(None, 1)[0]) != server.pid]
                    run.update(case=case["id"], version=version, repeat=repeat, output_relative=name,
                               remaining_engine_processes=remaining)
                    manifest["runs"].append(run)
                    bench.save(out / "manifest.json", manifest)
                    print(name, run["returncode"], round(run["seconds"], 2), flush=True)
                    if (run["returncode"] or remaining or run["surviving_process_group"]
                            or run["ambient_cpu"]["compiler_load_detected"]):
                        manifest.update(status="fail", finished_unix=time.time())
                        bench.save(out / "manifest.json", manifest)
                        raise RuntimeError("failed run, leaked process or compiler activity; results retained")
                    results[(case["id"], version, repeat)] = json.loads((out / name / "result.json").read_text())
        if followup.inventory(engines):
            raise RuntimeError("server/engine survived fixture cleanup")
    if any(bench.sha(path) != expected for path, expected in hashes.items()):
        raise RuntimeError("input changed during measurement")
    candidate = identities["candidate"]
    document = release_comparison(samples(results, protocols, range(1, a.repeats + 1)),
                                  candidate["commit"], candidate["tree"])
    name = ARTIFACT if complete(manifest) else DIAGNOSTIC
    data = (json.dumps(document, indent=2) + "\n").encode()
    if name == ARTIFACT:
        # The gate reads this file: refuse to leave one it would reject. Each
        # regression must still be named in the release's known limitations.
        policy.validate_release_comparison(data, candidate["commit"], candidate["tree"],
                                           "\n".join(regressions(document)).encode())
    (out / name).write_bytes(data)
    manifest.update(status="pass", finished_unix=time.time(), document=name, regressions=regressions(document))
    bench.save(out / "manifest.json", manifest)
    print(summary(document))
    print(out / name)
    if name == DIAGNOSTIC:
        print("diagnostic run: not the release artifact, and its verdicts are not the release's")
    elif regressions(document):
        print("regressions to name in known-limitations: " + ", ".join(regressions(document)))


if __name__ == "__main__":
    main()
