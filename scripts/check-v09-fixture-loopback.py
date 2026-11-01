#!/usr/bin/env python3
"""Host-only preflight of the v0.9 device fixtures before a phone is involved.

Starts a device fixture on 127.0.0.1 with the pinned Xray-core server, then
runs every generated client config in the candidate CLI with a local SOCKS
ingress instead of TUN. Over it: 64 KiB TCP echoes to the synthetic IPv4 and
IPv6 targets, UDP echoes (or, for ``udp: false`` cases, proof that no datagram
is answered), an A query for the probe name answered by the client core's own
DNS, which reaches the fixture through the proxy as the TUN DNS anchor would,
and a TCP echo to the address it returned, as a device app connects by name.
The share links are not imported here; the device harnesses and the importer
tests do that. This is not device evidence and never changes host routes.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SUITES = {
    # suite: (fixture script, extra fixture arguments)
    "v09": ("run-v07-apple-protocol-fixture.py", ["--protocol", "v09"]),
    "ciphers-v09": ("run-v08-apple-acceptance-fixture.py", ["--suite", "ciphers-v09"]),
    "legacy-v09": ("run-v08-apple-acceptance-fixture.py", ["--suite", "legacy-v09"]),
}


class CheckFailure(Exception):
    pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("ascii")
        return b"\x03" + bytes([len(name)]) + name + struct.pack("!H", port)
    return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed + struct.pack("!H", port)


def socks_request(sock, command, host, port):
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise CheckFailure("SOCKS greeting refused")
    sock.sendall(b"\x05" + bytes([command]) + b"\x00" + address(host, port))
    head = recv_exact(sock, 4)
    if head[1] != 0:
        raise CheckFailure(f"SOCKS command {command} failed with reply {head[1]}")
    length = {1: 4, 4: 16}.get(head[3])
    if length is None:
        length = recv_exact(sock, 1)[0]
    bound = recv_exact(sock, length + 2)
    if head[3] == 3:
        return bound[:-2].decode(), struct.unpack("!H", bound[-2:])[0]
    family = socket.AF_INET if head[3] == 1 else socket.AF_INET6
    return socket.inet_ntop(family, bound[:-2]), struct.unpack("!H", bound[-2:])[0]


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise CheckFailure("connection closed early")
        data += chunk
    return data


def tcp_echo(ingress, host, port, size=65536):
    payload = bytes(i % 251 for i in range(size))
    with socket.create_connection(("127.0.0.1", ingress), timeout=10) as sock:
        socks_request(sock, 1, host, port)
        sock.sendall(payload)
        if recv_exact(sock, size) != payload:
            raise CheckFailure("TCP echo mismatch")


def udp_exchange(ingress, host, port, payload, timeout):
    """Returns the reply payload, or None when nothing is answered in time."""
    with socket.create_connection(("127.0.0.1", ingress), timeout=10) as control, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        relay = socks_request(control, 3, "127.0.0.1", udp.getsockname()[1])
        if relay[0] in ("0.0.0.0", "::"):
            relay = ("127.0.0.1", relay[1])
        udp.settimeout(timeout)
        udp.sendto(b"\x00\x00\x00" + address(host, port) + payload, relay)
        try:
            datagram = udp.recv(65535)
        except TimeoutError:
            return None
        if datagram[:3] != b"\x00\x00\x00":
            raise CheckFailure("malformed SOCKS UDP reply")
        # RSV(2) FRAG(1) ATYP(1) ADDR PORT(2)
        header = {1: 10, 4: 22}.get(datagram[3])
        if header is None:
            header = 7 + datagram[4]
        return datagram[header:]


def dns_query(name):
    query_id = secrets.randbits(16)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    return query_id, struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question + b"\0\1\0\1"


def client_config(case, ingress):
    config = json.loads(case["configJSON"])
    config["log"] = {"loglevel": "warning"}
    config["inbounds"] = [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
                           "port": ingress, "settings": {"udp": True}}]
    config["outbounds"].append({"tag": "dns-out", "protocol": "dns"})
    config["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["socks-in"], "network": "udp",
                                          "port": "53", "outboundTag": "dns-out"})
    return config


def wait_listening(port, child, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise CheckFailure("client exited during startup")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise CheckFailure("client SOCKS ingress did not open")


def check_case(case, envelope, client_binary, work):
    label = case.get("label", case["format"])
    ingress = free_port()
    path = work / f"client-{label.replace(':', '-')}.json"
    path.write_text(json.dumps(client_config(case, ingress), indent=2) + "\n")
    rows = []
    with (work / f"client-{label.replace(':', '-')}.log").open("wb") as log:
        child = subprocess.Popen([str(client_binary), "run", "-config", str(path)], stdout=log, stderr=log)
        try:
            wait_listening(ingress, child)
            for kind, host in [("ipv4-tcp", "198.51.100.7"), ("ipv6-tcp", "2001:db8::7")]:
                tcp_echo(ingress, host, envelope["tcpPort"])
                rows.append(kind)
            for kind, host in [("ipv4-udp", "198.51.100.7"), ("ipv6-udp", "2001:db8::7")]:
                payload = secrets.token_bytes(1200)
                reply = udp_exchange(ingress, host, envelope["udpPort"], payload,
                                     5 if case.get("udp", True) else 2)
                if case.get("udp", True):
                    if reply != payload:
                        raise CheckFailure(f"{kind} echo missing or mismatched")
                    rows.append(kind)
                else:
                    if reply is not None:
                        raise CheckFailure(f"{kind} answered through an outbound without UDP")
                    rows.append(kind + "-refused")
            query_id, query = dns_query(envelope["probeHost"])
            reply = udp_exchange(ingress, "198.18.0.1", 53, query, 10)
            if (reply is None or reply[:2] != struct.pack("!H", query_id)
                    or reply[-4:] != socket.inet_aton("198.51.100.7")):
                raise CheckFailure("routed DNS answer missing or wrong")
            rows.append("routed-dns")
            # Like a device app: connect to the address the tunnel DNS returned.
            tcp_echo(ingress, socket.inet_ntoa(reply[-4:]), envelope["tcpPort"])
            rows.append("domain-destination")
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    path.unlink()
    return {"case": label, "format": case["format"], "checks": rows, "result": "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=sorted(SUITES), required=True)
    parser.add_argument("--reference-binary", type=Path, required=True)
    parser.add_argument("--reference-sha256", help="pinned binary SHA-256 instead of a Go VCS stamp check")
    parser.add_argument("--client-binary", type=Path, required=True, help="candidate xray-rust CLI")
    parser.add_argument("--work-dir", type=Path, required=True, help="new private directory")
    args = parser.parse_args()
    os.umask(0o077)
    work = args.work_dir.absolute()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    script, extra = SUITES[args.suite]
    command = [sys.executable, str(ROOT / "scripts" / script), *extra, "--bind", "127.0.0.1",
               "--reference-binary", str(args.reference_binary), "--output", str(work / "fixture"),
               "--seconds", "600"]
    if args.reference_sha256:
        command += ["--reference-sha256", args.reference_sha256]
    fixture = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    results, failed = [], False
    try:
        line = fixture.stdout.readline()
        if not line.startswith("Fixture ready: "):
            raise CheckFailure("fixture did not start: " + line.strip())
        if args.suite == "legacy-v09":
            time.sleep(8)  # REALITY's first decoy handshake, as in run-v07-performance.py
        envelope = json.loads(Path(line.removeprefix("Fixture ready: ").strip()).read_text())
        for case in envelope["cases"]:
            try:
                results.append(check_case(case, envelope, args.client_binary.resolve(strict=True), work))
            except (CheckFailure, OSError) as error:
                failed = True
                results.append({"case": case.get("label", case["format"]), "result": "failed",
                                "error": f"{type(error).__name__}: {error}"})
            print(json.dumps(results[-1]), flush=True)
    finally:
        fixture.send_signal(signal.SIGTERM)
        try:
            fixture.wait(15)
        except subprocess.TimeoutExpired:
            fixture.kill()
            fixture.wait()
    leftovers = sorted(p.name for p in (work / "fixture").iterdir() if p.name != "server.log")
    summary = {"suite": args.suite, "cases": len(results), "failed": sum(r["result"] != "passed" for r in results),
               "fixtureSecretsRemoved": not leftovers, "scope": "host loopback through SOCKS ingress; not device evidence"}
    (work / "results.json").write_text(json.dumps({"summary": summary, "results": results}, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 1 if failed or leftovers else 0


if __name__ == "__main__":
    raise SystemExit(main())
