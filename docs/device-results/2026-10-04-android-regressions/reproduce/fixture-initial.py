#!/usr/bin/env python3
"""Bounded local Xray-core fixture for the separate-UID Android Device Probe.

Uses the Apple fixture's pin, private credentials, synthetic destination routing
and cleanup. HTTP checks availability (204), UDP verifies the probe's nonce and
exact DNS-shaped response. Neither is a throughput benchmark or a UDP MTU sweep.
"""

import argparse
import asyncio
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import socket
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "android_fixture_base", ROOT / "scripts/run-v07-apple-protocol-fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
original_write = fixture.write_fixtures


def oracle_reply(query):
    # Exactly the unique xray-<UUID>.example.com A query emitted by UdpDnsOracle.
    if (len(query) != 67 or query[2:12] != bytes.fromhex("01000001000000000000")
            or query[12] != 37 or query[13:18] != b"xray-"
            or any(c not in b"0123456789abcdef" for c in query[18:50])
            or query[50:] != b"\x07example\x03com\x00\x00\x01\x00\x01"):
        return None
    return (query[:2] + bytes.fromhex("81800001000100000000") + query[12:]
            + bytes.fromhex("c00c00010001000000000004cb007101"))


class Oracle(fixture.Echo):
    def datagram_received(self, data, address):
        response = oracle_reply(data)
        if response is not None:
            self.transport.sendto(response, address)
            print(json.dumps({"backend": "udp", "requestBytes": len(data),
                              "time": time.time(),
                              "queryTag": hashlib.sha256(data).hexdigest()[:16],
                              "responseBytes": len(response)}), flush=True)


async def http_probe(reader, writer, byte_limit=0):
    hold_id = None
    reason = "invalid-request"
    try:
        request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        hold = re.fullmatch(rb"GET /v08-hold/([1-9][0-9]{0,5}) HTTP/1\.[01]", request.split(b"\r\n", 1)[0])
        if len(request) <= 8192 and hold:
            # No response: a real HTTP request stays in flight until the core
            # closes its connection, the client times out, or this bound fires.
            hold_id = int(hold[1])
            print(json.dumps({"backend": "hold-open", "id": hold_id, "time": time.time()}), flush=True)
            data = await asyncio.wait_for(reader.read(1), 20)
            reason = "eof" if not data else "unexpected-data"
        elif len(request) <= 8192 and request.startswith(b"GET /v08-probe HTTP/1."):
            writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            await asyncio.wait_for(writer.drain(), 5)
            print(json.dumps({"backend": "http", "status": 204}), flush=True)
    except (TimeoutError, ConnectionError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError) as error:
        reason = type(error).__name__
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass
        if hold_id is not None:
            print(json.dumps({"backend": "hold-close", "id": hold_id,
                              "reason": reason, "time": time.time()}), flush=True)


def reserve_port(bind, used):
    for _ in range(64):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind((bind, 0))
            port = tcp.getsockname()[1]
            if port in used:
                continue
            try:
                udp.bind((bind, port))
            except OSError:
                continue
            used.add(port)
            return port
    raise RuntimeError("no available fixture port")


def write_fixtures(root, bind, tcp_port, udp_port, dns_port, **kwargs):
    if kwargs.get("protocol") != "v08" or kwargs.get("port") is not None:
        raise ValueError("Android fixture requires --protocol v08 without --port")
    original_write(root, bind, tcp_port, udp_port, dns_port, **kwargs)
    server = json.loads((root / "server.json").read_text())
    envelope = json.loads((root / "v07-probe.json").read_text())
    used = {x["port"] for x in server["inbounds"]}
    for index, methods in [(1, ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"]),
                           (2, ["aes-128-gcm", "chacha20-poly1305"])]:
        for method in methods:
            inbound = copy.deepcopy(server["inbounds"][index])
            case = copy.deepcopy(envelope["cases"][index])
            config = json.loads(case["configJSON"])
            settings = config["outbounds"][0]["settings"]
            port = reserve_port(bind, used)
            inbound["port"] = settings["port"] = port
            if index == 1:
                password = base64.b64encode(secrets.token_bytes(16 if "128" in method else 32)).decode()
                settings.update(method=method, password=password)
                inbound["settings"].update(method=method, password=password)
                case["text"] = f"ss://{method}:{quote(password, safe='')}@{bind}:{port}"
            else:
                settings["security"] = method
                link = json.loads(base64.b64decode(case["text"][8:]))
                link.update(scy=method, port=str(port))
                case["text"] = "vmess://" + base64.b64encode(json.dumps(link).encode()).decode()
            case["configJSON"] = json.dumps(config)
            envelope["cases"].append(case)
            server["inbounds"].append(inbound)
    for case in envelope["cases"]:
        settings = json.loads(case["configJSON"])["outbounds"][0]["settings"]
        case["caseId"] = case["format"] + "-" + settings.get("method", settings.get("security", "tls"))
    (root / "server.json").write_text(json.dumps(server, indent=2) + "\n")
    (root / "v07-probe.json").write_text(json.dumps(envelope, indent=2) + "\n")


def write_regression(root, bind, tcp_port, udp_port, dns_port, *, suite, **kwargs):
    if kwargs.get("port") is not None:
        raise ValueError("regression suites require dynamically allocated fixture ports")
    if suite == "legacy":
        spec = importlib.util.spec_from_file_location(
            "android_legacy_fixture", ROOT / "scripts/run-v08-apple-acceptance-fixture.py")
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
        legacy.write_legacy(root, bind, tcp_port, udp_port, dns_port, **kwargs)
    else:
        original_write(root, bind, tcp_port, udp_port, dns_port, **{**kwargs, "protocol": "both"})
    envelope = json.loads((root / "v07-probe.json").read_text())
    for case in envelope["cases"]:
        case["caseId"] = case.get("label", case["format"])
    (root / "v07-probe.json").write_text(json.dumps(envelope, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--suite", choices=("v08", "legacy", "v07"), default="v08")
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    fixture.Echo = Oracle
    fixture.tcp_echo = http_probe
    fixture.write_fixtures = (write_fixtures if args.suite == "v08" else
                              lambda *a, **kw: write_regression(*a, suite=args.suite, **kw))
    fixture.main()
