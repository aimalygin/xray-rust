#!/usr/bin/env python3
"""Collect clean-candidate, five-run v0.6 process performance evidence.

All traffic stays on loopback. Run the calibrated v0.5 regression gate as well.
This report is a performance input to the release archive, not device evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import socket
import socketserver
import statistics
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
REPEATS = 5
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
BLOCK = bytes(range(256)) * 256
MIB = 1024 * 1024


def command(*args: str, cwd: Path = ROOT, timeout: int = 900) -> str:
    return subprocess.run(args, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE, timeout=timeout, env=environment()).stdout.strip()


def environment() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("XRAY_", "xray.", "CARGO_PROFILE_"))
           and k not in {"GOFLAGS", "GOEXPERIMENT", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}}
    env.update(GOENV="off", GOWORK="off", CGO_ENABLED="0")
    return env


def candidate() -> dict:
    if command("git", "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("performance evidence requires a clean candidate")
    return {"commit": command("git", "rev-parse", "HEAD"),
            "tree": command("git", "rev-parse", "HEAD^{tree}"), "dirty": False}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def receive(stream: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise RuntimeError("truncated benchmark response")
        result.extend(chunk)
    return bytes(result)


def socks(proxy: int, destination: int, domain: bool = False) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", proxy), timeout=10)
    try:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream.sendall(b"\x05\x01\x00")
        if receive(stream, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication failed")
        address = b"\x03\x0abench.test" if domain else b"\x01\x7f\x00\x00\x01"
        stream.sendall(b"\x05\x01\x00" + address + struct.pack("!H", destination))
        header = receive(stream, 4)
        if header[:3] != b"\x05\x00\x00":
            raise RuntimeError("SOCKS connection failed")
        if header[3] == 1:
            length = 4
        elif header[3] == 4:
            length = 16
        elif header[3] == 3:
            length = receive(stream, 1)[0]
        else:
            raise RuntimeError("invalid SOCKS reply")
        receive(stream, length + 2)
        return stream
    except BaseException:
        stream.close()
        raise


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.request.settimeout(120)
        try:
            while data := self.request.recv(len(BLOCK)):
                self.request.sendall(data)
        except (ConnectionError, TimeoutError):
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


@contextlib.contextmanager
def process(args: list[str], scratch: Path, name: str):
    with (scratch / f"{name}.log").open("w+") as log:
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=log, env=environment())
        try:
            yield child
            if child.poll() is not None:
                raise RuntimeError(f"{name} exited unexpectedly ({child.returncode})")
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            if child.stdout:
                child.stdout.close()


def ready(child: subprocess.Popen, listen: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("benchmark process failed during startup")
        try:
            with socket.create_connection(("127.0.0.1", listen), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("benchmark process startup timed out")


@contextlib.contextmanager
def core(binary: Path, outbound: dict, scratch: Path, name: str, routing: bool = False):
    listen = port()
    config = {"inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": listen,
                            "settings": {"auth": "noauth", "udp": False}}],
              "outbounds": [outbound],
              "dns": {"hosts": {"bench.test": "127.0.0.1"}, "queryStrategy": "UseIPv4"}}
    if routing:
        # Failure to select the IP rule reaches a closed VLESS listener, so
        # successful traffic proves the lazy DNS/routing path was exercised.
        config["outbounds"] = [vless(port()), {"tag": "ip", "protocol": "freedom"}]
        config["routing"] = {"domainStrategy": "IPOnDemand", "rules": [
            {"type": "field", "ip": ["127.0.0.1/32"], "outboundTag": "ip"}]}
    path = scratch / f"{name}.json"
    write_json(path, config)
    with process([str(binary), "run", "-config", str(path)], scratch, name) as child:
        ready(child, listen)
        yield child, listen


def vless(server: int, encryption: str = "none", stream: dict | None = None) -> dict:
    return {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1",
            "port": server, "users": [{"id": UUID, "encryption": encryption}]}]},
            "streamSettings": stream or {"network": "raw", "security": "none"}}


def bulk(proxy: int, origin: int) -> float:
    with socks(proxy, origin) as stream:
        stream.sendall(BLOCK)
        if receive(stream, len(BLOCK)) != BLOCK:
            raise RuntimeError("warm-up payload mismatch")
        start = time.perf_counter()
        # 32 MiB of verified upload and echo; throughput counts payload once.
        for _ in range(512):
            stream.sendall(BLOCK)
            if receive(stream, len(BLOCK)) != BLOCK:
                raise RuntimeError("bulk payload mismatch")
        return 32 / (time.perf_counter() - start)


def latency(proxy: int, origin: int) -> float:
    samples = []
    for index in range(110):
        start = time.perf_counter()
        with socks(proxy, origin, domain=True) as stream:
            stream.sendall(b"P")
            if receive(stream, 1) != b"P":
                raise RuntimeError("routing payload mismatch")
        if index >= 10:
            samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def rss(pid: int) -> int:
    value = int(command("ps", "-o", "rss=", "-p", str(pid)))
    if value <= 0:
        raise RuntimeError("RSS sample unavailable")
    return value


def memory(child: subprocess.Popen, proxy: int, origin: int) -> dict:
    baseline = rss(child.pid)
    with contextlib.ExitStack() as stack:
        flows = [stack.enter_context(socks(proxy, origin)) for _ in range(32)]
        for stream in flows:
            stream.sendall(BLOCK)
            if receive(stream, len(BLOCK)) != BLOCK:
                raise RuntimeError("XHTTP payload mismatch")
        samples = []
        # Keep 32 active split sessions alive for 30 seconds per repetition.
        for _ in range(30):
            for stream in flows:
                stream.sendall(b"P")
                if receive(stream, 1) != b"P":
                    raise RuntimeError("XHTTP held-open flow failed")
            samples.append(rss(child.pid))
            time.sleep(1)
    time.sleep(2)
    return {"baselineKiB": baseline, "heldKiB": samples,
            "afterCloseKiB": rss(child.pid), "peakMiB": max(samples) / 1024}


def measure(identifier: str, unit: str, samples: list[float], comparison: str, threshold: float) -> dict:
    median = statistics.median(samples)
    passed = median >= threshold if comparison == "at-least" else median <= threshold
    print(f"{identifier}: median={median:.3f} {unit}, {comparison} {threshold:.3f}: {'PASS' if passed else 'FAIL'}", flush=True)
    return {"id": identifier, "unit": unit, "samples": samples,
            "comparison": comparison, "threshold": threshold}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    if platform.system() != "Darwin":
        raise RuntimeError("v0.6 local performance budgets target the macOS publication host")
    source = candidate()
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    checkout = ROOT / "Xray-core"
    spec = importlib.util.spec_from_file_location("oracle_verification", ROOT / "scripts/verify-oracle-fixtures.py")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.verify_xray_core_checkout(checkout)
    command("cargo", "build", "--locked", "--release", "-p", "xray-cli", "--bin", "xray-rust")
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    binary = (ROOT / target / "release/xray-rust").resolve()
    if candidate() != source:
        raise RuntimeError("candidate changed during build")
    values = {key: [] for key in ("process", "plainVless", "encryption", "directLatency", "routing", "memory")}
    with tempfile.TemporaryDirectory(prefix="xray-v06-perf-") as temp:
        scratch = Path(temp)
        go = scratch / "xray"
        oracle = scratch / "keys"
        bridge = scratch / "bridge"
        command("go", "build", "-mod=readonly", "-o", str(go), "./main", cwd=checkout)
        command("go", "build", "-mod=readonly", "-o", str(oracle), str(ROOT / "tools/vless-encryption-oracle/main.go"), cwd=checkout)
        command("go", "build", "-mod=readonly", "-o", str(bridge),
                str(ROOT / "tools/xhttp-download-oracle/main.go"),
                str(ROOT / "tools/xhttp-download-oracle/bridge.go"), cwd=checkout)
        build = {"candidate": source, "profile": "release", "clean": True,
                 "platform": platform.platform(), "machine": platform.machine(),
                 "rustc": command("rustc", "-vV"), "go": command("go", "version"),
                 "oracleCommit": command("git", "rev-parse", "HEAD", cwd=checkout),
                 "binarySha256": {"xray-rust": sha256(binary), "xray-core": sha256(go),
                                  "bridge": sha256(bridge), "keys": sha256(oracle)},
                 "harnessSha256": sha256(Path(__file__)), "cargoLockSha256": sha256(ROOT / "Cargo.lock")}
        write_json(output / "build-manifest.json", build)
        keys = json.loads(command(str(oracle), "keypair", "x25519"))
        encryption = f"mlkem768x25519plus.random.0rtt.{keys['public']}"
        ports = [port() for _ in range(3)]
        inbound = lambda p, decrypt, stream: {
            "protocol": "vless", "listen": "127.0.0.1", "port": p,
            "settings": {"clients": [{"id": UUID}], "decryption": decrypt}, "streamSettings": stream}
        config = {"log": {"loglevel": "error"}, "inbounds": [
            inbound(ports[0], "none", {"network": "raw"}),
            inbound(ports[1], f"mlkem768x25519plus.random.600s.{keys['private']}", {"network": "raw"}),
            inbound(ports[2], "none", {"network": "xhttp", "xhttpSettings": {"path": "/split/", "mode": "auto"}})],
            "outbounds": [{"protocol": "freedom"}]}
        write_json(scratch / "server.json", config)
        with EchoServer(("127.0.0.1", 0), Echo) as echo, contextlib.ExitStack() as stack:
            thread = threading.Thread(target=echo.serve_forever, daemon=True)
            thread.start()
            stack.callback(echo.shutdown)
            origin = echo.server_address[1]
            server = stack.enter_context(process([str(go), "run", "-config", str(scratch / "server.json")], scratch, "server"))
            for listen in ports:
                ready(server, listen)
            frontend = stack.enter_context(process([str(bridge), "bridge", f"127.0.0.1:{ports[2]}"], scratch, "bridge"))
            if not select.select([frontend.stdout], [], [], 20)[0]:
                raise RuntimeError("bridge startup timed out")
            tls = json.loads(frontend.stdout.readline())
            tls_port = int(tls["tcp"].rsplit(":", 1)[1])
            def stream(down: bool) -> dict:
                return {"network": "xhttp", "security": "tls", "tlsSettings": {
                    "serverName": "download-oracle.test", "alpn": ["h2" if down else "http/1.1"],
                    "pinnedPeerCertSha256": tls["pin"]}, "xhttpSettings": {
                    "path": "/download/" if down else "/upload/", "mode": "packet-up",
                    "xmux": {"maxConnections": 1}, "scMinPostsIntervalMs": 1}}
            upload, download = stream(False), stream(True)
            download.update(address="127.0.0.1", port=tls_port)
            upload["xhttpSettings"]["downloadSettings"] = download
            for repeat in range(REPEATS):
                print(f"v0.6 performance repetition {repeat + 1}/{REPEATS}", flush=True)
                for name, outbound in [("process", {"protocol": "freedom"}),
                                       ("plainVless", vless(ports[0])),
                                       ("encryption", vless(ports[1], encryption))]:
                    with core(binary, outbound, scratch, name) as (_, proxy):
                        values[name].append(bulk(proxy, origin))
                for name, routing in [("directLatency", False), ("routing", True)]:
                    with core(binary, {"protocol": "freedom"}, scratch, name, routing) as (_, proxy):
                        values[name].append(latency(proxy, origin))
                with core(binary, vless(tls_port, stream=upload), scratch, "memory") as (child, proxy):
                    values["memory"].append(memory(child, proxy, origin))
                write_json(output / "benchmark-raw.json", values)
    if candidate() != source:
        raise RuntimeError("candidate changed during measurement")
    measurements = [
        measure("process-throughput", "MiB/s", values["process"], "at-least", 10),
        measure("vless-encryption-throughput", "MiB/s", values["encryption"], "at-least",
                0.5 * statistics.median(values["plainVless"])),
        measure("ip-on-demand-latency", "ms", values["routing"], "at-most",
                statistics.median(values["directLatency"]) + 1),
        measure("xhttp-memory", "MiB", [v["peakMiB"] for v in values["memory"]], "at-most", 64)]
    passed = all(statistics.median(m["samples"]) >= m["threshold"] if m["comparison"] == "at-least"
                 else statistics.median(m["samples"]) <= m["threshold"] for m in measurements)
    report = {"profile": "release", "clean": True, "measurements": measurements,
              "artifacts": [{"kind": kind, "path": name, "sha256": sha256(output / name)}
                            for kind, name in [("benchmark-raw", "benchmark-raw.json"),
                                               ("build-manifest", "build-manifest.json")]],
              "result": "pass" if passed else "fail"}
    write_json(output / "performance.json", report)
    if not passed:
        raise RuntimeError("v0.6 feature performance budget exceeded")


if __name__ == "__main__":
    main()
