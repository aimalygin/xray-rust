#!/usr/bin/env python3
"""Compare three frozen full clients on seven v0.8 protocol/cipher profiles.

Common SOCKS ingress and Xray server; no TUN route changes. Compile beforehand.
Fresh clients, a fresh common server/key set per case/repeat, rotating order.
All failures, raw byte checks, startup CPU and cleanup results are retained.
"""
import argparse
import base64
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


bench = module("bench", "run-v07-performance.py")
followup = module("followup", "run-v07-performance-followup.py")
device = module("device", "run-v07-apple-protocol-fixture.py")
PROFILES = {"trojan-tls": ("trojan", None),
            "ss2022-aes128": ("shadowsocks", "2022-blake3-aes-128-gcm"),
            "ss2022-aes256": ("shadowsocks", "2022-blake3-aes-256-gcm"),
            "ss2022-chacha20": ("shadowsocks", "2022-blake3-chacha20-poly1305"),
            "vmess-aes128": ("vmess", "aes-128-gcm"),
            "vmess-chacha20": ("vmess", "chacha20-poly1305"),
            "vmess-auto": ("vmess", "auto")}


def cases(profiles, smoke=False):
    return [{"id": f"{name}-socks-{traffic}-{count}", "profile": name, "path": "socks",
             "traffic": traffic, "connections": count,
             "payload_size": 1200 if traffic == "udp" else 1024 if traffic == "tcp-latency" else 65536,
             "iterations": (10 if smoke else 1000) if traffic in ("tcp-latency", "udp") else (4 if smoke else 512)}
            for name in profiles for count in (1, 8)
            for traffic in ("upload", "download", "full-duplex", "tcp-latency", "udp")]


def configs(profile, directory, port):
    protocol, method = PROFILES[profile]
    settings = {"address": "127.0.0.1", "port": port}
    stream = {"network": "raw"}
    server_stream = {"network": "raw"}
    if protocol == "trojan":
        password = secrets.token_urlsafe(32)
        settings["password"] = password
        server_settings = {"clients": [{"password": password}]}
        cert, key = directory / "tls.crt", directory / "tls.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=v08-benchmark.test", "-keyout", str(key),
                        "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
        import hashlib
        stream.update(security="tls", tlsSettings={"serverName": "v08-benchmark.test",
            "fingerprint": "chrome", "alpn": ["http/1.1"], "pinnedPeerCertSha256": hashlib.sha256(der).hexdigest()})
        server_stream.update(security="tls", tlsSettings={"alpn": ["http/1.1"],
            "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]})
    elif protocol == "shadowsocks":
        password = base64.b64encode(secrets.token_bytes(16 if method.endswith("aes-128-gcm") else 32)).decode()
        settings.update(method=method, password=password)
        server_settings = {"method": method, "password": password, "network": "tcp,udp"}
    else:
        user = str(uuid.uuid4())
        settings.update(id=user, security=method, alterId=0)
        server_settings = {"clients": [{"id": user}]}
    client = {"log": {"loglevel": "error"}, "outbounds": [{
        "protocol": protocol, "settings": settings, "streamSettings": stream}]}
    server = {"log": {"loglevel": "error"}, "inbounds": [{"protocol": protocol,
        "listen": "127.0.0.1", "port": port, "settings": server_settings, "streamSettings": server_stream}],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
    return client, server


@contextlib.contextmanager
def fixture(reference, directory, profile):
    directory.mkdir(parents=True, mode=0o700)
    client, server = configs(profile, directory, bench.port())
    bench.save(directory / "server.json", server)
    with (directory / "server.log").open("w") as log:
        child = subprocess.Popen([str(reference), "run", "-config", str(directory / "server.json")],
                                 stdout=log, stderr=log, env=bench.env())
        try:
            time.sleep(1)
            if child.poll() is not None:
                raise RuntimeError("common server failed to start")
            yield client, child.pid
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def ambient():
    lines = bench.command(["ps", "-axo", "pid=,pcpu=,comm="]).splitlines()
    busy = []
    for line in lines:
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        name = Path(fields[2]).name
        if name in {"rustc", "cargo", "clang", "clang++", "go", "compile", "link", "xcodebuild", "swift-frontend"}:
            busy.append({"pid": int(fields[0]), "cpu": float(fields[1]), "name": name})
    return {"compiler_load_detected": busy}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inputs", type=Path, required=True, help="verified source/build identities and frozen paths")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--profile", choices=list(PROFILES), action="append")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--smoke", action="store_true")
    a = p.parse_args()
    if not 3 <= a.repeats <= 20 or (a.profile and len(set(a.profile)) != len(a.profile)):
        raise ValueError("3..20 repetitions and unique profiles required")
    for variable in ("GOMAXPROCS", "TOKIO_WORKER_THREADS", "GOMEMLIMIT", "GOGC"):
        os.environ.pop(variable, None)
    os.umask(0o077)
    inputs = json.loads(a.inputs.read_text())
    paths = {k: Path(inputs[k]["path"]).resolve(strict=True) for k in ("candidate", "xray", "singbox", "harness")}
    for name, path in paths.items():
        if bench.sha(path) != inputs[name]["sha256"]:
            raise ValueError("binary changed: " + name)
    if inputs["xray"]["commit"] != bench.REFERENCE or inputs["singbox"]["commit"] != "56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778":
        raise ValueError("reference source pin changed")
    device.verify_reference(paths["xray"])
    if followup.inventory(paths.values()) or ambient()["compiler_load_detected"]:
        raise RuntimeError("benchmark/compiler already running")
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    launcher = ROOT / "scripts/v08-reference-client.py"
    launchers = {}
    for mode in ("xray", "singbox"):
        target = out / (mode + "-client")
        shutil.copyfile(launcher, target)
        target.chmod(0o700)
        bench.save(Path(str(target) + ".json"), {"mode": mode,
                   "binaries": {k: str(paths[k]) for k in ("xray", "singbox")}})
        launchers[mode] = target
    files = [*paths.values(), a.inputs.resolve(), Path(__file__).resolve(), launcher,
             Path(bench.__file__), Path(followup.__file__), Path(device.__file__)]
    hashes = {str(f): bench.sha(f) for f in files}
    patch = bench.command(["git", "diff", "--binary", "HEAD"], ROOT)
    (out / "source.patch").write_text(patch + "\n")
    selected = cases(a.profile or PROFILES, a.smoke)
    manifest = {"schema_version": 1, "suite": "v08", "smoke": a.smoke, "diagnostic": False,
        "repeats": 1 if a.smoke else a.repeats, "cases": selected, "warmup": True,
        "versions": {k: {"binary": str(paths[k]), "engine_sha256": inputs[k]["sha256"]} for k in ("candidate", "xray", "singbox")},
        "binary_builds": inputs, "file_hashes": hashes, "reference_commit": bench.REFERENCE,
        "source_commit": bench.command(["git", "rev-parse", "HEAD"], ROOT),
        "source_patch_sha256": bench.sha(out / "source.patch"), "platform": platform.platform(),
        "process_accounting": "real full client launched directly; verified TCP warmup; startup/lifetime CPU retained separately",
        "fixture_policy": "fresh common Xray server and keys per case/repeat; fresh clients in rotating order",
        "worker_policy": "stock defaults; inherited Go/Tokio worker and GC overrides cleared",
        "scope": "SOCKS TCP/UDP; no TUN comparison, transport extensions, Mux, AEAD-2017 or physical-device claims",
        "started_unix": time.time(), "runs": []}
    bench.save(out / "manifest.json", manifest)
    for index, case in enumerate(selected):
        for repeat in range(1, manifest["repeats"] + 1):
            order = ["candidate", "xray", "singbox"]
            offset = (index + repeat - 1) % len(order)
            order = order[offset:] + order[:offset]
            if repeat % 2 == 0:
                order.reverse()
            server_dir = out / f"{case['id']}-server-{repeat}"
            load = ambient()
            if load["compiler_load_detected"]:
                bench.save(out / "measurement-quality.json", load)
                raise RuntimeError("compiler started during measurement")
            with fixture(paths["xray"], server_dir, case["profile"]) as (config, server_pid):
                os.environ["BENCH_REFERENCE_CERT"] = str(server_dir / "tls.crt")
                for version in order:
                    name = f"{case['id']}-{version}-{repeat}"
                    request = {k: case[k] for k in ("path", "traffic", "connections", "iterations", "payload_size")}
                    request.update(binary=str(launchers.get(version, paths[version])), config=copy.deepcopy(config),
                                   output=str(out / name), warmup=True, prepare_client=version != "candidate")
                    request_path = out / (name + ".json")
                    bench.save(request_path, request)
                    result = bench.execute([str(paths["harness"]), "protocol-run", str(request_path)], out / (name + ".log"), ROOT)
                    remaining = [s for s in followup.inventory(paths.values()) if int(s.split(None, 1)[0]) != server_pid]
                    result.update(case=case["id"], version=version, repeat=repeat, output_relative=name,
                                  remaining_engine_processes=remaining, ambient_cpu=load, client_order=order)
                    manifest["runs"].append(result)
                    bench.save(out / "manifest.json", manifest)
                    print(name, result["returncode"], round(result["seconds"], 2), flush=True)
                    if remaining or result["surviving_process_group"] or (a.smoke and result["returncode"]):
                        manifest.update(status="fail", finished_unix=time.time())
                        bench.save(out / "manifest.json", manifest)
                        raise RuntimeError("failed smoke or leaked process; results retained")
            if followup.inventory(paths.values()):
                raise RuntimeError("server/engine survived fixture cleanup")
    if any(bench.sha(path) != expected for path, expected in hashes.items()):
        raise RuntimeError("input changed during measurement")
    manifest.update(finished_unix=time.time(), status="pass" if all(r["returncode"] == 0 for r in manifest["runs"]) else "fail")
    bench.save(out / "manifest.json", manifest)
    if manifest["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
