#!/usr/bin/env python3
"""Host-only dry run of the shared scenarios' Apple fixture (shared_fixture_v09.py
--platform apple) against the candidate CLI, through the candidate's
scripts/check-v09-fixture-loopback.py checks: SOCKS ingress instead of TUN, 64 KiB
TCP echoes to 198.51.100.7 and 2001:db8::7, UDP echoes of the Apple probe's sizes,
the probe name through the client core's routed DNS and a TCP echo to its answer.

New for the v0.10 campaign; NOT a 0.9.0 tool and NOT device evidence.

A case with expectFakeDNS (ip-on-demand) is read as the Apple probe reads it: the
routed DNS answer must lie in 198.19.0.0/16 (the probe's dns-fakeip-anchor) and the
TCP echo goes to that address. --suite shared-asis is the AsIs negative control of
0.9.0 (--ip-strategy AsIs --only ip-on-demand): the literal-IP echo must pass and
the echo to the FakeDNS address must not.
"""
import importlib.util
import ipaddress
import json
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path

CANDIDATE = Path("<stand-clone>")
spec = importlib.util.spec_from_file_location("fixture_loopback", CANDIDATE / "scripts/check-v09-fixture-loopback.py")
loopback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loopback)

FIXTURE = str(Path(__file__).resolve().with_name("shared_fixture_v09.py"))
loopback.SUITES = {
    "shared": (FIXTURE, ["--platform", "apple"]),
    "shared-asis": (FIXTURE, ["--platform", "apple", "--ip-strategy", "AsIs", "--only", "ip-on-demand"]),
}
loopback.KEPT = {"server.log", "download-bridge.log"}
loopback.UDP_PAYLOADS = (1392, 1372)
FAKE_POOL = ipaddress.ip_network("198.19.0.0/16")
ASIS = "shared-asis" in sys.argv
original_check_case = loopback.check_case


def fake_dns_case(case, envelope, client_binary, work):
    Failure = loopback.CheckFailure
    label = case["label"].replace(":", "-")
    ingress = loopback.free_port()
    path = work / f"client-{label}.json"
    path.write_text(json.dumps(loopback.client_config(case, ingress), indent=2) + "\n")
    rows = []
    with (work / f"client-{label}.log").open("wb") as log:
        child = subprocess.Popen([str(client_binary), "run", "-config", str(path)], stdout=log, stderr=log)
        try:
            loopback.wait_listening(ingress, child)
            time.sleep(case.get("settleSeconds", 0))
            loopback.tcp_echo(ingress, "198.51.100.7", envelope["tcpPort"])
            rows.append("ipv4-tcp")
            if not ASIS:
                loopback.tcp_echo(ingress, "2001:db8::7", envelope["tcpPort"])
                rows.append("ipv6-tcp")
                for (kind, host), size in zip([("ipv4-udp", "198.51.100.7"), ("ipv6-udp", "2001:db8::7")],
                                              case.get("udpPayloadBytes", loopback.UDP_PAYLOADS)):
                    payload = secrets.token_bytes(size)
                    if loopback.udp_exchange(ingress, host, envelope["udpPort"], payload, 5) != payload:
                        raise Failure(f"{kind} echo missing or mismatched")
                    rows.append(kind)
            query_id, query = loopback.dns_query(envelope["probeHost"])
            reply = loopback.udp_exchange(ingress, "198.18.0.1", 53, query, 10)
            if reply is None or reply[:2] != struct.pack("!H", query_id):
                raise Failure("routed DNS answer missing")
            answer = ipaddress.ip_address(reply[-4:])
            if answer not in FAKE_POOL:
                raise Failure(f"routed DNS answered {answer}, not a FakeDNS address")
            rows.append("routed-dns-fakeip")
            try:
                loopback.tcp_echo(ingress, str(answer), envelope["tcpPort"])
                reached = True
            except (Failure, OSError):
                reached = False
            if ASIS:
                if reached:
                    raise Failure("AsIs reached the echo through the FakeDNS address")
                rows.append("domain-destination-not-routed-asis")
            else:
                if not reached:
                    raise Failure("TCP echo through the FakeDNS address failed")
                rows.append("domain-destination")
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    path.unlink()
    return {"case": case["label"], "format": case["format"], "checks": rows, "result": "passed"}


def check_case(case, envelope, client_binary, work):
    if case.get("expectFakeDNS"):
        return fake_dns_case(case, envelope, client_binary, work)
    return original_check_case(case, envelope, client_binary, work)


loopback.check_case = check_case

if __name__ == "__main__":
    sys.exit(loopback.main())
