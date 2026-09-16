#!/usr/bin/env python3
"""Temporary echo fixture for the DEBUG-only Swift v0.7 device probe.

Requires Xray-core v26.7.28, openssl, and either Go (to inspect its clean build
identity) or an explicitly pinned binary SHA-256. Hash pinning alone does not
verify upstream provenance. Creates a new private directory containing ephemeral
credentials; removes those credentials when stopped. Never changes host routes.
"""

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess


REFERENCE = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"


def openssl(*args):
    return subprocess.check_output(["openssl", *args], stderr=subprocess.DEVNULL)


def verify_reference(binary, expected_sha256=None):
    if expected_sha256:
        if hashlib.sha256(binary.read_bytes()).hexdigest() != expected_sha256:
            raise ValueError("reference binary SHA-256 does not match the expected identity")
        return
    info = subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
    fields = [line.strip() for line in info.splitlines()]
    if f"build\tvcs.revision={REFERENCE}" not in fields or "build\tvcs.modified=false" not in fields:
        raise ValueError("reference must have the exact, clean v26.7.28 build identity")


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if len(data) <= 2048:
            self.transport.sendto(data, address)


class DNS(Echo):
    def __init__(self, probe_host="v07-probe.test"):
        self.probe_host = probe_host

    def datagram_received(self, data, address):
        if not 17 <= len(data) <= 512 or data[4:12] != b"\0\1\0\0\0\0\0\0":
            return
        offset, labels = 12, []
        try:
            while data[offset]:
                length = data[offset]
                offset += 1
                if length > 63 or offset + length >= len(data):
                    return
                labels.append(data[offset:offset + length].decode("ascii").lower())
                offset += length
            offset += 1
            query_type, query_class = struct.unpack("!HH", data[offset:offset + 4])
            end = offset + 4
        except (IndexError, UnicodeError, struct.error):
            return
        if end != len(data):
            return
        known = ".".join(labels) == self.probe_host and query_class == 1
        answer = b""
        if known and query_type in (1, 28):
            family = socket.AF_INET if query_type == 1 else socket.AF_INET6
            value = "198.51.100.7" if query_type == 1 else "2001:db8::7"
            packed = socket.inet_pton(family, value)
            answer = b"\xc0\x0c" + struct.pack("!HHIH", query_type, 1, 5, len(packed)) + packed
        flags = 0x8180 if known else 0x8183
        header = data[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0)
        self.transport.sendto(header + data[12:end] + answer, address)


async def tcp_echo(reader, writer):
    try:
        remaining = 1024 * 1024
        while remaining:
            data = await asyncio.wait_for(reader.read(min(8192, remaining)), 10)
            if not data:
                break
            remaining -= len(data)
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 10)
    except (TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


def reserve_udp(bind):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind, 0))
        return sock.getsockname()[1]


def write_fixtures(root, bind, tcp_port, udp_port, dns_port, protocol="both", port=None, mode="smoke", probe_host="v07-probe.test"):
    def save(name, value):
        (root / name).write_text(json.dumps(value, indent=2) + "\n")

    def key(name, public=False):
        der = openssl("pkey", "-in", str(root / f"{name}-wg.pem"),
                      *(["-pubout"] if public else []), "-outform", "DER")
        return base64.b64encode(der[-32:]).decode()

    for name in ("server", "client"):
        openssl("genpkey", "-algorithm", "X25519", "-out", str(root / f"{name}-wg.pem"))
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "1", "-subj", "/CN=v07-probe.test",
            "-keyout", str(root / "tls.key"), "-out", str(root / "tls.crt"))
    pin = hashlib.sha256(openssl("x509", "-in", str(root / "tls.crt"), "-outform", "DER")).hexdigest()
    auth = secrets.token_urlsafe(32)
    psk = base64.b64encode(secrets.token_bytes(32)).decode()
    wg_port, hy_port = reserve_udp(bind), reserve_udp(bind)
    while hy_port == wg_port:
        hy_port = reserve_udp(bind)
    if port is not None:
        if protocol == "wireguard":
            wg_port = port
        else:
            hy_port = port
    save("server.json", {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": bind, "port": wg_port, "protocol": "wireguard", "settings": {
                "secretKey": key("server"), "address": ["10.44.0.1/32", "fd44::1/128"],
                "mtu": 1420, "peers": [{"publicKey": key("client", True), "preSharedKey": psk,
                                       "allowedIPs": ["10.44.0.2/32", "fd44::2/128"]}]}},
            {"listen": bind, "port": hy_port, "protocol": "hysteria",
             "settings": {"version": 2, "users": [{"auth": auth}]}, "streamSettings": {
                 "network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2},
                 "tlsSettings": {"alpn": ["h3"], "certificates": [{
                     "certificateFile": str(root / "tls.crt"), "keyFile": str(root / "tls.key")} ]}}},
        ],
        "outbounds": [
            {"tag": "blocked", "protocol": "blackhole"},
            {"tag": "echo", "protocol": "freedom", "settings": {
                "redirect": "127.0.0.1:0", "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
        ],
        "routing": {"rules": [{"type": "field", "ip": ["198.51.100.0/24", "2001:db8::/32"],
                                 "outboundTag": "echo"}]},
    })
    if protocol != "both":
        server = json.loads((root / "server.json").read_text())
        server["inbounds"] = [server["inbounds"][0 if protocol == "wireguard" else 1]]
        save("server.json", server)
    common = {
        "inbounds": [{"tag": "tun-in", "protocol": "tun"}],
        "dns": {"servers": [f"198.51.100.53:{dns_port}"]},
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "domain": [f"full:{probe_host}"], "outboundTag": "proxy"},
            {"type": "field", "ip": ["198.51.100.0/24", "2001:db8::/32"], "outboundTag": "proxy"},
        ]},
    }
    wg = {"tag": "proxy", "protocol": "wireguard", "settings": {
        "secretKey": key("client"), "address": ["10.44.0.2/32", "fd44::2/128"], "mtu": 1420,
        "peers": [{"publicKey": key("server", True), "preSharedKey": psk,
                   "endpoint": f"{bind}:{wg_port}", "allowedIPs": ["198.51.100.0/24", "2001:db8::/32"],
                   "keepAlive": 1}],
    }}
    hy = {"tag": "proxy", "protocol": "hysteria", "settings": {
        "version": 2, "address": bind, "port": hy_port}, "streamSettings": {
            "network": "hysteria", "security": "tls", "tlsSettings": {
                "serverName": "v07-probe.test", "alpn": ["h3"], "pinnedPeerCertSha256": pin},
            "hysteriaSettings": {"version": 2, "auth": auth},
        }}
    wg_text = (
        f'[Interface]\nPrivateKey = {key("client")}\nAddress = 10.44.0.2/32, fd44::2/128\n'
        f'DNS = 198.51.100.53\nMTU = 1420\n[Peer]\nPublicKey = {key("server", True)}\n'
        f'PresharedKey = {psk}\nEndpoint = {bind}:{wg_port}\n'
        'AllowedIPs = 198.51.100.0/24, 2001:db8::/32\nPersistentKeepalive = 1\n'
    )
    profiles = [("wireguard", wg, wg_text),
                ("hysteria2", hy, f"hy2://{auth}@{bind}:{hy_port}?sni=v07-probe.test")]
    if protocol != "both":
        profiles = [profile for profile in profiles if profile[0] == protocol]
    cases = [{"format": fmt, "text": text, "serverAddress": bind,
              "configJSON": json.dumps({**common, "outbounds": [outbound]})}
             for fmt, outbound, text in profiles]
    save("v07-probe.json", {"cases": cases, "tcpPort": tcp_port, "udpPort": udp_port, "mode": mode, "probeHost": probe_host})


async def serve(args):
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    transports, child, tcp = [], None, None
    try:
        tcp = await asyncio.start_server(tcp_echo, "127.0.0.1", 0, limit=8192)
        # Each fixture gets a fresh name so an OS-level negative answer from a
        # previous, stopped VPN does not poison the next baseline before DNS I/O.
        probe_host = f"v07-probe-{secrets.token_hex(6)}.test"
        for protocol in (Echo, lambda: DNS(probe_host)):
            transport, _ = await loop.create_datagram_endpoint(protocol, local_addr=("127.0.0.1", 0))
            transports.append(transport)
        write_fixtures(args.output, args.bind, tcp.sockets[0].getsockname()[1],
                       *(transport.get_extra_info("sockname")[1] for transport in transports),
                       protocol=args.protocol, port=args.port, mode=args.mode, probe_host=probe_host)
        with (args.output / "server.log").open("wb") as log:
            child = await asyncio.create_subprocess_exec(
                str(args.reference_binary), "run", "-config", str(args.output / "server.json"),
                stdout=log, stderr=log)
            await asyncio.sleep(0.5)
            if child.returncode is not None:
                raise RuntimeError("reference exited; inspect private server.log")
            print(f"Fixture ready: {args.output / 'v07-probe.json'}", flush=True)
            stopper = asyncio.create_task(stop.wait())
            exited = asyncio.create_task(child.wait())
            try:
                done, _ = await asyncio.wait([stopper, exited], timeout=args.seconds,
                                             return_when=asyncio.FIRST_COMPLETED)
                if exited in done:
                    raise RuntimeError("reference exited before fixture shutdown")
            finally:
                stopper.cancel()
                exited.cancel()
                await asyncio.gather(stopper, exited, return_exceptions=True)
    finally:
        if child and child.returncode is None:
            child.terminate()
            try:
                await asyncio.wait_for(child.wait(), 5)
            except TimeoutError:
                child.kill()
                await child.wait()
        if tcp:
            tcp.close()
            await tcp.wait_closed()
        for transport in transports:
            transport.close()
        for name in ("server-wg.pem", "client-wg.pem", "tls.key", "tls.crt", "server.json", "v07-probe.json"):
            (args.output / name).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="host IPv4 address reachable from the iPhone")
    parser.add_argument("--reference-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new private directory")
    parser.add_argument("--seconds", type=int, default=600, help="maximum fixture lifetime (1..1800)")
    parser.add_argument("--protocol", choices=("both", "wireguard", "hysteria2"), default="both")
    parser.add_argument("--port", type=int, help="explicit carrier UDP port; requires a single protocol")
    parser.add_argument("--mode", choices=("smoke", "transitions", "lock-wake", "transitions-reset"), default="smoke")
    parser.add_argument("--reference-sha256", help="expected binary SHA-256, instead of a clean Go VCS stamp check")
    args = parser.parse_args()
    address = ipaddress.IPv4Address(args.bind)
    if address.is_unspecified or address.is_multicast or not 1 <= args.seconds <= 1800:
        parser.error("use a specific unicast IPv4 address and 1..1800 seconds")
    if args.port is not None and (args.protocol == "both" or not 1 <= args.port <= 65535):
        parser.error("an explicit port requires one protocol and a port in 1..65535")
    if args.reference_sha256 and (len(args.reference_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.reference_sha256)):
        parser.error("reference SHA-256 must be 64 lowercase hex characters")
    args.output = args.output.absolute()
    args.reference_binary = args.reference_binary.resolve(strict=True)
    verify_reference(args.reference_binary, args.reference_sha256)
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
