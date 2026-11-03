#!/usr/bin/env python3
"""v0.9 copy of docs/device-results/2026-10-18-v081-candidate/collect-protocols.py.

Single-flow loopback SOCKS ingress, full-duplex and TCP latency, five
rotating-order repeats of every v0.9 profile against the pinned Xray-core
client over a common Xray-core server. No previous-release baseline: 0.8.1 has
none of these outbounds. Runs from the clean candidate worktree."""
import copy, json, os, pathlib, shutil, sys, time
import importlib.util
ROOT = pathlib.Path(os.environ["CANDIDATE_ROOT"])
spec = importlib.util.spec_from_file_location("comparison", ROOT / "scripts/run-v08-protocol-comparison.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
b = c.bench
os.umask(0o077)
for key in ("GOMAXPROCS", "TOKIO_WORKER_THREADS", "GOMEMLIMIT", "GOGC"):
    os.environ.pop(key, None)
out = pathlib.Path(sys.argv[1]); out.mkdir(exist_ok=False)
R = pathlib.Path("<repo>/target/release-090")
paths = {"candidate": R / "host/cargo/release/xray-rust", "harness": R / "host/cargo/release/xray-bench",
         "xray": R / "xray-core/xray"}
c.device.verify_reference(paths["xray"])
assert not b.command(["git", "status", "--porcelain"], ROOT)
assert not c.ambient()["compiler_load_detected"], "wait until builds finish"
manifest = {"candidate": {"revision": b.command(["git", "rev-parse", "HEAD"], ROOT),
                          "tree": b.command(["git", "rev-parse", "HEAD^{tree}"], ROOT), "dirty": False},
            "profile": "release", "clean": True, "repeats": 5,
            "binarySha256": {k: b.sha(v) for k, v in paths.items()},
            "referenceCommit": b.REFERENCE, "collectorSha256": b.sha(pathlib.Path(__file__)),
            "scope": "single-flow loopback SOCKS ingress; v0.9 profiles; paired pinned Xray-core comparison",
            "measurementGroups": c.MEASUREMENT_GROUPS["v09"], "started": time.time(), "runs": []}
b.save(out / "manifest.json", manifest)
launcher = out / "xray-client"
shutil.copyfile(ROOT / "scripts/v08-reference-client.py", launcher); launcher.chmod(0o700)
b.save(pathlib.Path(str(launcher) + ".json"), {"mode": "xray", "suite": "v09", "binaries": {"xray": str(paths["xray"])}})
cases = [x for x in c.cases(c.V09_PROFILES) if x["connections"] == 1 and x["traffic"] in ("full-duplex", "tcp-latency")]
for index, case in enumerate(cases):
    for repeat in range(1, 6):
        assert not c.ambient()["compiler_load_detected"], "compiler activity"
        order = ["candidate", "xray"] if (index + repeat) % 2 else ["xray", "candidate"]
        with c.fixture(paths["xray"], out / f"{case['id']}-server-{repeat}", case["profile"]) as (config, pid):
            os.environ["BENCH_REFERENCE_CERT"] = str(out / f"{case['id']}-server-{repeat}/tls.crt")
            for version in order:
                name = f"{case['id']}-{version}-{repeat}"
                request = {k: case[k] for k in ("path", "traffic", "connections", "iterations", "payload_size")}
                request.update(binary=str(launcher if version == "xray" else paths[version]), config=copy.deepcopy(config),
                               output=str(out / name), warmup=True, prepare_client=version == "xray",
                               client_preface=case["traffic"] != "tcp-latency")
                b.save(out / (name + ".json"), request)
                run = c.measured_execute([str(paths["harness"]), "protocol-run", str(out / (name + ".json"))], out / (name + ".log"))
                run.update(case=case["id"], version=version, repeat=repeat, order=order)
                manifest["runs"].append(run); b.save(out / "manifest.json", manifest)
                print(name, run["returncode"], round(run["seconds"], 2), flush=True)
                assert run["returncode"] == 0 and not run["surviving_process_group"]
                assert not run["ambient_cpu"]["compiler_load_detected"]
manifest.update(finished=time.time(), status="pass")
b.save(out / "manifest.json", manifest)
