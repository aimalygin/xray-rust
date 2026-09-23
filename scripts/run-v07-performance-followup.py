#!/usr/bin/env python3
"""Compare explicitly supplied engine builds using the frozen protocol driver.

Retains failures, source patch, binary hashes and per-run cleanup evidence.
Run builds/tests before starting this collector, never beside measurements.
"""
import argparse
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import platform
import time

SPEC = importlib.util.spec_from_file_location("performance", Path(__file__).with_name("run-v07-performance.py"))
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


def inventory(binaries):
    prefixes = tuple(str(p) + " " for p in binaries)
    return [line.strip() for line in bench.command(["ps", "-axo", "pid=,command="]).splitlines()
            if len(line.strip().split(None, 1)) == 2
            and line.strip().split(None, 1)[1].startswith(prefixes)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", action="append", required=True, help="label=/absolute/binary")
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--suite", choices=["new", "tun", "reality", "legacy"], required=True)
    parser.add_argument("--case", action="append")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--iterations", type=int)
    parser.add_argument("--connections", type=int, action="append", help="generic flow counts (1..16); defaults to 1 and 8")
    args = parser.parse_args()
    engines = dict(item.split("=", 1) for item in args.engine)
    if len(engines) != len(args.engine) or not 1 <= args.repeats <= 20:
        raise ValueError("unique labels and 1..20 repeats required")
    binaries = [Path(p).resolve(strict=True) for p in [*engines.values(), args.harness, args.reference]]
    if inventory(binaries):
        raise RuntimeError("benchmark processes already running")
    cases = bench.legacy_cases(False) if args.suite == "legacy" else bench.protocol_cases(args.suite, False)
    if args.connections:
        if args.suite == "legacy" or len(set(args.connections)) != len(args.connections) or not all(1 <= n <= 16 for n in args.connections):
            raise ValueError("connections requires a generic suite and unique counts in 1..16")
        templates = [c for c in cases if c["connections"] == 1]
        cases = []
        for template in templates:
            for count in args.connections:
                case = copy.deepcopy(template)
                case.update(connections=count, id=template["id"].rsplit("-", 1)[0] + f"-{count}")
                cases.append(case)
    if args.case:
        cases = [c for c in cases if c["id"] in args.case]
        if {c["id"] for c in cases} != set(args.case):
            raise ValueError("unknown case")
    if args.iterations is not None:
        if args.suite == "legacy" or not 1 <= args.iterations <= 16384:
            raise ValueError("iterations requires a generic suite and 1..16384")
        for case in cases:
            case["iterations"] = args.iterations
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    patch = bench.command(["git", "diff", "--binary", "HEAD"], source)
    (output / "source.patch").write_text(patch + "\n")
    scripts = [Path(__file__), Path(bench.__file__), source / "scripts/run-v07-apple-protocol-fixture.py"]
    hashes = {str(p): bench.sha(p) for p in [*binaries, *scripts]}
    manifest = {"schema_version": 1, "suite": args.suite, "diagnostic": True, "smoke": False,
        "repeats": args.repeats, "cases": cases, "started_unix": time.time(),
        "platform": platform.platform(), "source_commit": bench.command(["git", "rev-parse", "HEAD"], source),
        "source_patch_sha256": bench.sha(output / "source.patch"), "file_hashes": hashes,
        "reference_commit": bench.REFERENCE, "harness_sha256": bench.sha(args.harness),
        "versions": {label: {"binary": str(Path(path).resolve()), "engine_sha256": bench.sha(path)}
                     for label, path in engines.items()}, "runs": [],
        "review_thresholds": {"throughput_ratio_min": .85, "latency_cpu_rss_ratio_max": 1.15}}
    bench.save(output / "manifest.json", manifest)
    with contextlib.ExitStack() as stack:
        shared = stack.enter_context(bench.fixture(args.reference, output, True)) if args.suite == "reality" else None
        for case in cases:
            for repeat in range(args.repeats):
                order = list(engines) if repeat % 2 == 0 else list(reversed(engines))
                for version in order:
                    identifier = f"{case['id']}-{version}-{repeat+1}"
                    print(identifier, flush=True)
                    context = (contextlib.nullcontext(shared) if shared is not None else
                               contextlib.nullcontext({}) if args.suite == "legacy" else
                               bench.fixture(args.reference, output / f"{identifier}-server"))
                    with context as configs:
                        if args.suite == "legacy":
                            invocation = [str(args.harness), "run", "--engine", "xray-rust",
                                "--xray-rust-bin", str(Path(engines[version]).resolve()),
                                "--xray-core-bin", str(args.reference), "--no-auto-build", "--runs", "1",
                                "--run-timeout-ms", "150000", "--out-dir", str(output / identifier), *case["args"]]
                        else:
                            request = {k: case[k] for k in ["path", "traffic", "connections", "iterations", "payload_size"]}
                            request.update(binary=str(Path(engines[version]).resolve()), config=configs[case["protocol"]], output=str(output / identifier))
                            request_path = output / f"{identifier}.json"
                            bench.save(request_path, request)
                            invocation = [str(args.harness), "protocol-run", str(request_path)]
                        result = bench.execute(invocation, output / f"{identifier}.log", source)
                    result.update(case=case["id"], version=version, repeat=repeat+1,
                                  output=str(output / identifier), output_relative=identifier,
                                  remaining_engine_processes=inventory(binaries[:-2]))
                    manifest["runs"].append(result)
                    bench.save(output / "manifest.json", manifest)
                    print(f"  rc={result['returncode']} elapsed={result['seconds']:.1f}s", flush=True)
                    if result["surviving_process_group"] or result["remaining_engine_processes"]:
                        raise RuntimeError("stopping after leaked benchmark process")
    for path, digest in hashes.items():
        if bench.sha(path) != digest:
            raise RuntimeError(f"input changed during measurement: {path}")
    manifest.update(finished_unix=time.time(), status="pass" if all(r["returncode"] == 0 for r in manifest["runs"]) else "fail")
    bench.save(output / "manifest.json", manifest)
    if manifest["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
