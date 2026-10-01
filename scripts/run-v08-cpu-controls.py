#!/usr/bin/env python3
"""Paired CPU/RSS controls for frozen Rust clients using the v0.8 workload.

Example: --binary baseline=/path/old --binary candidate=/path/new --output DIR.
The three-client comparison remains run-v08-protocol-comparison.py.
--worker NAME=COUNT is an architectural diagnostic, never a stock result.
"""
import argparse
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("comparison", ROOT / "scripts/run-v08-protocol-comparison.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", action="append", required=True, help="NAME=PATH; repeat for paired clients")
    p.add_argument("--reference", type=Path, required=True)
    p.add_argument("--harness", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--profile", choices=list(c.PROFILES), action="append")
    p.add_argument("--traffic", choices=["upload", "download", "full-duplex", "tcp-latency", "udp"], action="append")
    p.add_argument("--flows", type=int, choices=[1, 8], action="append")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--idle", type=int, default=0)
    p.add_argument("--worker", action="append", default=[], help="NAME=COUNT; explicit non-stock experiment")
    a = p.parse_args()
    for variable in ("GOMAXPROCS", "TOKIO_WORKER_THREADS", "GOMEMLIMIT", "GOGC"):
        os.environ.pop(variable, None)
    os.umask(0o077)
    binaries = {name: Path(path).resolve(strict=True) for name, path in (b.split("=", 1) for b in a.binary)}
    workers = {name: int(count) for name, count in (w.split("=", 1) for w in a.worker)}
    if (len(binaries) != len(a.binary) or not 1 <= a.repeats <= 20
            or not set(workers) <= set(binaries) or not all(1 <= n <= 64 for n in workers.values())
            or any(not name.replace("-", "").isalnum() for name in binaries)):
        raise ValueError("invalid binaries/repeats/workers")
    reference, harness = a.reference.resolve(strict=True), a.harness.resolve(strict=True)
    c.device.verify_reference(reference)
    paths = list(binaries.values()) + [reference, harness]
    if c.ambient()["compiler_load_detected"] or c.followup.inventory(paths):
        raise RuntimeError("benchmark/compiler already running")
    selected = [case for case in c.cases(a.profile or ["ss2022-aes128", "ss2022-chacha20", "vmess-aes128", "vmess-chacha20"])
                if case["connections"] in (a.flows or [1, 8])
                and case["traffic"] in (a.traffic or ["upload", "download", "full-duplex"])]
    if (not selected or not 0 <= a.idle <= 15
            or any(case["connections"] + a.idle > 16 or case["traffic"] == "udp" and a.idle for case in selected)):
        raise ValueError("invalid case or idle connection selection")
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    files = [*paths, Path(__file__).resolve(), Path(c.__file__), Path(c.bench.__file__), Path(c.followup.__file__)]
    hashes = {str(path): c.bench.sha(path) for path in files}
    manifest = {"started_unix": time.time(), "repeats": a.repeats, "cases": selected,
                "file_hashes": hashes, "runs": [], "source_commit": c.bench.command(["git", "rev-parse", "HEAD"], ROOT),
                "idle_connections": a.idle, "workers": workers,
                "purpose": "paired controls; identical harness, reference fixture and payload; rotating order"}
    (out / "source.patch").write_text(c.bench.command(["git", "diff", "--binary", "HEAD"], ROOT))
    # Retain experimental untracked source as well as the tracked patch.
    for source in (ROOT / "crates/xray-proxy/src/aead.rs", ROOT / "crates/xray-proxy/benches/aead_backends.rs"):
        if source.exists():
            shutil.copyfile(source, out / source.name)
    try:
        for index, case in enumerate(selected):
            for repeat in range(1, a.repeats + 1):
                order = list(binaries)
                offset = (index + repeat - 1) % len(order)
                order = order[offset:] + order[:offset]
                if repeat % 2 == 0:
                    order.reverse()
                if c.ambient()["compiler_load_detected"]:
                    raise RuntimeError("compiler started during measurement")
                server_dir = out / f"{case['id']}-server-{repeat}"
                with c.fixture(reference, server_dir, case["profile"]) as (config, pid):
                    for name in order:
                        run_name = f"{case['id']}-{name}-{repeat}"
                        request = {k: case[k] for k in ("path", "traffic", "connections", "iterations", "payload_size")}
                        request.update(binary=str(binaries[name]), config=copy.deepcopy(config), output=str(out / run_name),
                                       warmup=True, client_preface=case["traffic"] not in ("tcp-latency", "udp"), idle_connections=a.idle)
                        if name in workers:
                            request["client_env"] = {"TOKIO_WORKER_THREADS": str(workers[name])}
                        request_path = out / (run_name + ".json")
                        c.bench.save(request_path, request)
                        result = c.measured_execute([str(harness), "protocol-run", str(request_path)], out / (run_name + ".log"))
                        remaining = [s for s in c.followup.inventory(paths) if int(s.split(None, 1)[0]) != pid]
                        result.update(case=case["id"], version=name, repeat=repeat, output_relative=run_name,
                                      remaining_engine_processes=remaining, client_order=order)
                        manifest["runs"].append(result)
                        c.bench.save(out / "manifest.json", manifest)
                        print(run_name, result["returncode"], round(result["seconds"], 2), flush=True)
                        if (result["returncode"] or remaining or result["surviving_process_group"]
                                or result["ambient_cpu"]["compiler_load_detected"]):
                            raise RuntimeError("failed or contaminated control; evidence retained")
                if c.followup.inventory(paths):
                    raise RuntimeError("server/engine survived fixture cleanup")
        if any(c.bench.sha(Path(path)) != sha for path, sha in hashes.items()):
            raise RuntimeError("input changed during measurement")
        manifest["status"] = "pass"
    except BaseException:
        manifest["status"] = "fail"
        raise
    finally:
        manifest["finished_unix"] = time.time()
        c.bench.save(out / "manifest.json", manifest)


if __name__ == "__main__":
    main()
