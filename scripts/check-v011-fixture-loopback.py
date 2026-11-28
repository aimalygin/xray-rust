#!/usr/bin/env python3
"""Host-only preflight of the v0.11 device fixtures before a phone is involved.

The checks of check-v09-fixture-loopback.py, for the v0.11 suites, with the
candidate CLI behind a local SOCKS ingress instead of TUN:

- ``sniff-v011``: each case's sniffing moves from its TUN inbound to the SOCKS
  ingress, and each of its probes connects to its address, sends its first
  bytes and must be echoed or refused as the case says. The CLI does not run
  the SDK's start path, so ``sniff:imported`` keeps the importers' sniffing
  without ``routeOnly`` here: its decoy must be refused. That shows the probe
  tells a migrated profile from one that was not.
- ``import-v011``, ``wireguard-idle`` and ``reality-v011``: the traffic checks
  of every suite. With ``--idle-restart`` the WireGuard idle case also waits
  out its idle time, passes TCP again, and must show a handshake from a new
  client source in the relay's log: the device was closed and started again.

This is not device evidence and never changes host routes.
"""
import base64
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


loopback = load("fixture_loopback", "check-v09-fixture-loopback.py")
restart = load("wireguard_restart", "check-v011-wireguard-restart.py")

loopback.SUITES = {
    # suite: (fixture script, extra fixture arguments)
    "sniff-v011": ("run-v07-apple-protocol-fixture.py", ["--protocol", "sniff-v011"]),
    "import-v011": ("run-v07-apple-protocol-fixture.py", ["--protocol", "import-v011"]),
    "wireguard-idle": ("run-v07-apple-protocol-fixture.py", ["--protocol", "wireguard-idle"]),
    "reality-v011": ("run-v08-apple-acceptance-fixture.py", ["--suite", "reality-v011"]),
}
# REALITY's first decoy handshake, as in run-v07-performance.py.
loopback.WARMUP_SUITES = ("reality-v011",)
loopback.KEPT = {"server.log", "wireguard-sources.jsonl"}
# The datagrams the Apple probe sends.
loopback.UDP_PAYLOADS = (1392, 1372)
# What the CLI, which has no SDK start path, must do with each sniffing probe.
CLI_EXPECTATIONS = {"saved-profile-migration": "refused"}
IDLE_RESTART = False
original_check_case = loopback.check_case


def sniff_config(case, ingress):
    """The case on a SOCKS ingress that sniffs as its TUN inbound does."""
    config = json.loads(case["configJSON"])
    sniffing = config["inbounds"][0]["sniffing"]
    config["log"] = {"loglevel": "warning"}
    config["inbounds"] = [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": ingress,
                           "settings": {"udp": False}, "sniffing": sniffing}]
    return config


def exchange(ingress, host, port, payload, timeout=5):
    """``echo`` when every byte came back, ``refused`` when the flow closed
    or timed out with none, and a failure when only some did."""
    with socket.create_connection(("127.0.0.1", ingress), timeout=10) as sock:
        loopback.socks_request(sock, 1, host, port)
        sock.settimeout(timeout)
        sock.sendall(payload)
        received = b""
        try:
            while len(received) < len(payload):
                chunk = sock.recv(len(payload) - len(received))
                if not chunk:
                    break
                received += chunk
        except (TimeoutError, ConnectionError):
            pass
    if received == payload:
        return "echo"
    if not received:
        return "refused"
    raise loopback.CheckFailure(f"{len(received)} of {len(payload)} bytes came back")


def check_sniff_case(case, envelope, client_binary, work):
    label = case["label"]
    ingress = loopback.free_port()
    path = work / f"client-{label.replace(':', '-')}.json"
    path.write_text(json.dumps(sniff_config(case, ingress), indent=2) + "\n")
    rows = []
    with (work / f"client-{label.replace(':', '-')}.log").open("wb") as log:
        child = subprocess.Popen([str(client_binary), "run", "-config", str(path)], stdout=log, stderr=log)
        try:
            loopback.wait_listening(ingress, child)
            for probe in case["sniffProbes"]:
                expected = CLI_EXPECTATIONS.get(probe["transition"], probe["expect"])
                got = exchange(ingress, probe["host"], envelope["tcpPort"], base64.b64decode(probe["payload"]))
                if got != expected:
                    raise loopback.CheckFailure(f"{probe['transition']}: expected {expected}, got {got}")
                rows.append(f"{probe['transition']}:{got}")
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    path.unlink()
    return {"case": label, "format": case["format"], "checks": rows, "result": "passed"}


def check_idle_restart(case, envelope, client_binary, work):
    """The traffic checks, then the idle time with no flow, then TCP again
    over a device the relay saw start from a new source."""
    label = case["label"]
    ingress = loopback.free_port()
    path = work / f"client-{label.replace(':', '-')}-idle.json"
    path.write_text(json.dumps(loopback.client_config(case, ingress), indent=2) + "\n")
    sources = work / "fixture" / "wireguard-sources.jsonl"
    with (work / f"client-{label.replace(':', '-')}-idle.log").open("wb") as log:
        child = subprocess.Popen([str(client_binary), "run", "-config", str(path)], stdout=log, stderr=log)
        try:
            loopback.wait_listening(ingress, child)
            loopback.tcp_echo(ingress, "198.51.100.7", envelope["tcpPort"])
            since = time.time()
            time.sleep(case["idleRestartSeconds"])
            loopback.tcp_echo(ingress, "198.51.100.7", envelope["tcpPort"])
            verdict = restart.fresh_handshake(restart.read(sources), since)
            if not verdict["fresh"]:
                raise loopback.CheckFailure("no handshake from a new source after the idle time: " + json.dumps(verdict))
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    path.unlink()
    return ["idle-device-restart"]


def check_case(case, envelope, client_binary, work):
    if "sniffProbes" in case:
        return check_sniff_case(case, envelope, client_binary, work)
    result = original_check_case(case, envelope, client_binary, work)
    if IDLE_RESTART and case.get("idleRestartSeconds"):
        result["checks"] += check_idle_restart(case, envelope, client_binary, work)
    return result


loopback.check_case = check_case

if __name__ == "__main__":
    if "--idle-restart" in sys.argv:
        sys.argv.remove("--idle-restart")
        IDLE_RESTART = True
        # The idle time is seven minutes; the fixture must outlive it.
        loopback.FIXTURE_SECONDS = 1200
    sys.exit(loopback.main())
