#!/usr/bin/env python3
"""Temporary echo fixture for the DEBUG-only Swift v0.7 device probe.

Requires Xray-core v26.10.21, openssl, and either Go (to inspect its clean build
identity) or an explicitly pinned binary SHA-256. Hash pinning alone does not
verify upstream provenance. Creates a new private directory containing ephemeral
credentials; removes those credentials when stopped. Never changes host routes.
--protocol v09 serves SOCKS5 (password, UDP), HTTP CONNECT (Basic, plain and
TLS) and classic Shadowsocks AEAD; see docs/v09-release-evidence.md.
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
import shutil
import signal
import socket
import struct
import subprocess
import uuid
from urllib.parse import quote


REFERENCE = "1b1647cd9ddf0abc34b981d4611fc03bcac1ca74"
V08_PROTOCOLS = ("trojan", "shadowsocks2022", "vmess")
V09_PROTOCOLS = ("socks", "http", "https", "shadowsocks-aead")
SHADOWSOCKS_AEAD_METHOD = "aes-256-gcm"
REDACTION_MARKER = "NONSECRET-V09-IMPORT-CONTROL"


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
        raise ValueError("reference must have the exact, clean v26.10.21 build identity")


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if len(data) <= 2048:
            self.transport.sendto(data, address)


def dns_answer(data, probe_host):
    if not 17 <= len(data) <= 512 or data[4:12] != b"\0\1\0\0\0\0\0\0":
        return None
    offset, labels = 12, []
    try:
        while data[offset]:
            length = data[offset]
            offset += 1
            if length > 63 or offset + length >= len(data):
                return None
            labels.append(data[offset:offset + length].decode("ascii").lower())
            offset += length
        offset += 1
        query_type, query_class = struct.unpack("!HH", data[offset:offset + 4])
        end = offset + 4
    except (IndexError, UnicodeError, struct.error):
        return None
    if end != len(data):
        return None
    known = ".".join(labels) == probe_host and query_class == 1
    answer = b""
    if known and query_type in (1, 28):
        family = socket.AF_INET if query_type == 1 else socket.AF_INET6
        value = "198.51.100.7" if query_type == 1 else "2001:db8::7"
        packed = socket.inet_pton(family, value)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", query_type, 1, 5, len(packed)) + packed
    flags = 0x8180 if known else 0x8183
    header = data[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0)
    return header + data[12:end] + answer


class DNS(Echo):
    def __init__(self, probe_host="v07-probe.test"):
        self.probe_host = probe_host

    def datagram_received(self, data, address):
        response = dns_answer(data, self.probe_host)
        if response is not None:
            self.transport.sendto(response, address)


async def tcp_dns(reader, writer, probe_host, query_limit=64):
    # HTTP CONNECT has no UDP relay, so its client fixture resolves over
    # tcp:// through the proxy. Same answers as the UDP listener, RFC 1035
    # length framing, bounded per connection.
    try:
        for _ in range(query_limit):
            try:
                prefix = await asyncio.wait_for(reader.readexactly(2), 10)
            except asyncio.IncompleteReadError:
                break
            query = await asyncio.wait_for(reader.readexactly(struct.unpack("!H", prefix)[0]), 10)
            response = dns_answer(query, probe_host)
            if response is None:
                break
            writer.write(struct.pack("!H", len(response)) + response)
            await asyncio.wait_for(writer.drain(), 10)
    except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def tcp_echo(reader, writer, byte_limit=1024 * 1024):
    try:
        remaining = byte_limit
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


def loopback_outbound():
    # Backends bind IPv4 loopback. Darwin's automatic dual-stack UDP port
    # allocation can overlap an IPv4 listener; replies then reach that listener
    # instead of Xray (#56). Keep both ends in the same address family.
    return {"tag": "echo", "protocol": "freedom", "sendThrough": "127.0.0.1", "settings": {
        "redirect": "127.0.0.1:0", "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}


def write_fixtures(root, bind, tcp_port, udp_port, dns_port, protocol="both", port=None, mode="smoke", probe_host="v07-probe.test", direct_targets=False):
    if direct_targets and protocol not in ("both", "wireguard", "hysteria2"):
        raise ValueError("direct targets require WireGuard or Hysteria")
    if protocol in ("v08", "v09", *V08_PROTOCOLS, *V09_PROTOCOLS):
        return write_client_fixtures(root, bind, tcp_port, udp_port, dns_port, protocol, port, mode, probe_host)
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
            loopback_outbound(),
        ],
        "routing": {"rules": [{"type": "field", "ip": ["198.51.100.0/24", "2001:db8::/32"],
                                 "outboundTag": "echo"}]},
    })
    if protocol != "both":
        server = json.loads((root / "server.json").read_text())
        server["inbounds"] = [server["inbounds"][0 if protocol == "wireguard" else 1]]
        save("server.json", server)
    if direct_targets:
        # Preserve #60's IPv4 binding for redirect mode only. Direct IPv6
        # targets need automatic source-family selection, without redirect.
        server = json.loads((root / "server.json").read_text())
        echo = next(outbound for outbound in server["outbounds"] if outbound["tag"] == "echo")
        echo.pop("sendThrough", None)
        echo["settings"].pop("redirect")
        echo["settings"]["finalRules"] = [{"action": "allow", "ip": [
            "198.51.100.7/32", "198.51.100.53/32", "2001:db8::7/128"]}]
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


def invalid_imports(selected):
    """Malformed links that must be rejected without echoing the marker."""
    marker = REDACTION_MARKER
    rows = {
        # Empty host literal.
        "socks": ("socks", f"socks5://v09-user:{marker}@[]:1080"),
        # Share links carry no query; dropping one could silently lose TLS policy.
        "http": ("http", f"https://v09-user:{marker}@127.0.0.1:443?sni=v09-probe.test"),
        # Stream ciphers stay rejected, as upstream. Plain userinfo keeps the
        # marker literal, so an error echoing the raw link is caught too.
        "shadowsocks-aead": ("shadowsocks2022", f"ss://rc4-md5:{marker}@127.0.0.1:8388"),
    }
    families = {"https": "http"}
    wanted = dict.fromkeys(families.get(fmt, fmt) for fmt in selected if fmt in V09_PROTOCOLS)
    return [{"scenario": name, "format": rows[name][0], "text": rows[name][1]} for name in wanted]


def write_client_fixtures(root, bind, tcp_port, udp_port, dns_port, protocol, port, mode, probe_host):
    """New client fixtures retain the existing device harness envelope.

    v0.9 cases carry a scenario-prefixed label (``scenario:variant``) and a
    ``udp`` expectation: HTTP CONNECT has no UDP relay, so its UDP checks are
    fail-closed negative controls and its DNS resolves over TCP.
    """
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "1", "-subj", "/CN=v08-probe.test",
            "-keyout", str(root / "tls.key"), "-out", str(root / "tls.crt"))
    pin = hashlib.sha256(openssl("x509", "-in", str(root / "tls.crt"), "-outform", "DER")).hexdigest()
    selected = {"v08": V08_PROTOCOLS, "v09": V09_PROTOCOLS}.get(protocol, (protocol,))
    certificates = [{"certificateFile": str(root / "tls.crt"), "keyFile": str(root / "tls.key")}]
    inbounds, cases, ports = [], [], set()
    for fmt in selected:
        if port is None:
            while True:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind((bind, 0))
                    carrier_port = sock.getsockname()[1]
                if carrier_port not in ports:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.bind((bind, carrier_port))
                    break
        else:
            carrier_port = port
        ports.add(carrier_port)
        settings = {"address": bind, "port": carrier_port}
        stream = {"network": "raw"}
        server_stream = {"network": "raw"}
        label, import_format, udp_expected = None, fmt, True
        dns_server = f"198.51.100.53:{dns_port}"
        if fmt == "trojan":
            password = secrets.token_urlsafe(32)
            name = "trojan"
            settings["password"] = password
            server_settings = {"clients": [{"password": password}]}
            stream.update(security="tls", tlsSettings={"serverName": "v08-probe.test", "pinnedPeerCertSha256": pin})
            server_stream.update(security="tls", tlsSettings={"certificates": certificates})
            text = f"trojan://{password}@{bind}:{carrier_port}?sni=v08-probe.test"
        elif fmt == "shadowsocks2022":
            password = base64.b64encode(secrets.token_bytes(32)).decode()
            name = "shadowsocks"
            settings.update(method="2022-blake3-chacha20-poly1305", password=password)
            server_settings = {"method": settings["method"], "password": password, "network": "tcp,udp"}
            text = f"ss://{settings['method']}:{quote(password, safe='')}@{bind}:{carrier_port}"
        elif fmt == "vmess":
            user = str(uuid.uuid4())
            name = "vmess"
            settings.update(id=user, security="auto", alterId=0)
            server_settings = {"clients": [{"id": user}]}
            text = "vmess://" + base64.b64encode(json.dumps({"v": "2", "ps": "device fixture", "add": bind, "port": str(carrier_port), "id": user, "aid": "0", "net": "tcp", "tls": "", "scy": "auto"}).encode()).decode()
        elif fmt == "socks":
            user, password = "v09-" + secrets.token_hex(6), secrets.token_urlsafe(32)
            name, label = "socks", "socks:password"
            settings.update({"user": user, "pass": password})
            # Xray answers UDP ASSOCIATE with "ip"; its default is loopback.
            server_settings = {"auth": "password", "accounts": [{"user": user, "pass": password}],
                               "udp": True, "ip": bind}
            text = f"socks5://{quote(user, safe='')}:{quote(password, safe='')}@{bind}:{carrier_port}"
        elif fmt in ("http", "https"):
            user, password = "v09-" + secrets.token_hex(6), secrets.token_urlsafe(32)
            name, import_format, udp_expected = "http", "http", False
            label = "http:tls" if fmt == "https" else "http:plain"
            settings.update({"user": user, "pass": password})
            server_settings = {"accounts": [{"user": user, "pass": password}]}
            if fmt == "https":
                stream.update(security="tls", tlsSettings={
                    "serverName": "v08-probe.test", "alpn": ["http/1.1"], "pinnedPeerCertSha256": pin})
                server_stream.update(security="tls", tlsSettings={
                    "alpn": ["http/1.1"], "certificates": certificates})
            text = f"{fmt}://{quote(user, safe='')}:{quote(password, safe='')}@{bind}:{carrier_port}"
            dns_server = f"tcp://198.51.100.53:{dns_port}"
        elif fmt == "shadowsocks-aead":
            method, password = SHADOWSOCKS_AEAD_METHOD, secrets.token_urlsafe(24)
            name, import_format = "shadowsocks", "shadowsocks2022"
            label = f"shadowsocks-aead:{method}"
            settings.update(method=method, password=password)
            server_settings = {"method": method, "password": password, "network": "tcp,udp"}
            text = sip002(method, password, bind, carrier_port)
        else:
            raise ValueError(f"unsupported client fixture protocol: {fmt}")
        inbounds.append({"listen": bind, "port": carrier_port, "protocol": name, "settings": server_settings, "streamSettings": server_stream})
        config = {
            "inbounds": [{"tag": "tun-in", "protocol": "tun"}],
            "dns": {"servers": [dns_server]},
            "routing": {"domainStrategy": "AsIs", "rules": [
                {"type": "field", "domain": [f"full:{probe_host}"], "outboundTag": "proxy"},
                {"type": "field", "ip": ["198.51.100.0/24", "2001:db8::/32"], "outboundTag": "proxy"}]},
            "outbounds": [{"tag": "proxy", "protocol": name, "settings": settings, "streamSettings": stream}],
        }
        case = {"format": import_format, "text": text, "serverAddress": bind, "configJSON": json.dumps(config)}
        if label:
            case.update(label=label, udp=udp_expected)
        cases.append(case)
    server = {"log": {"loglevel": "warning"}, "inbounds": inbounds,
              "outbounds": [{"tag": "blocked", "protocol": "blackhole"},
                            loopback_outbound()],
              "routing": {"rules": [{"type": "field", "ip": ["198.51.100.0/24", "2001:db8::/32"], "outboundTag": "echo"}]}}
    envelope = {"cases": cases, "tcpPort": tcp_port, "udpPort": udp_port, "mode": mode, "probeHost": probe_host}
    invalid = invalid_imports(selected)
    if invalid:
        envelope.update(redactionMarker=REDACTION_MARKER, invalidImports=invalid)
    (root / "server.json").write_text(json.dumps(server, indent=2) + "\n")
    (root / "v07-probe.json").write_text(json.dumps(envelope, indent=2) + "\n")


def sip002(method, password, host, port):
    """SIP002 requires Base64URL userinfo for AEAD-2017 methods."""
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    return f"ss://{userinfo}@{host}:{port}"


async def dns_listeners(loop, address, probe_host):
    """UDP and TCP DNS on one port number, so plain and tcp:// servers agree."""
    for _ in range(16):
        transport, _ = await loop.create_datagram_endpoint(lambda: DNS(probe_host), local_addr=(address, 0))
        try:
            server = await asyncio.start_server(lambda r, w: tcp_dns(r, w, probe_host), address,
                                                transport.get_extra_info("sockname")[1], limit=8192)
        except OSError:
            transport.close()
            continue
        return transport, server
    raise RuntimeError("no DNS port is free for both UDP and TCP")


async def serve(args):
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    direct_targets = getattr(args, "direct_targets", False)
    transports, child, tcp, tcp6, dns_tcp = [], None, None, None, None
    try:
        echo_bind = "198.51.100.7" if direct_targets else "127.0.0.1"
        dns_bind = "198.51.100.53" if direct_targets else "127.0.0.1"
        handler = lambda r, w: tcp_echo(r, w, 1024 * 1024 * 1024 if args.mode == "resources" else 1024 * 1024)
        tcp = await asyncio.start_server(handler, echo_bind, 0, limit=8192)
        # Each fixture gets a fresh name so an OS-level negative answer from a
        # previous, stopped VPN does not poison the next baseline before DNS I/O.
        probe_host = f"v07-probe-{secrets.token_hex(6)}.test"
        transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=(echo_bind, 0))
        transports.append(transport)
        transport, dns_tcp = await dns_listeners(loop, dns_bind, probe_host)
        transports.append(transport)
        tcp_port = tcp.sockets[0].getsockname()[1]
        udp_port, dns_port = (transport.get_extra_info("sockname")[1] for transport in transports)
        if direct_targets:
            tcp6 = await asyncio.start_server(handler, "2001:db8::7", tcp_port, limit=8192)
            transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("2001:db8::7", udp_port))
            transports.append(transport)
        write_fixtures(args.output, args.bind, tcp_port, udp_port, dns_port,
                       protocol=args.protocol, port=args.port, mode=args.mode, probe_host=probe_host,
                       **({"direct_targets": True} if direct_targets else {}))
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
        for server in (tcp, tcp6, dns_tcp):
            if server:
                server.close()
                await server.wait_closed()
        for transport in transports:
            transport.close()
        for name in ("server-wg.pem", "client-wg.pem", "tls.key", "tls.crt", "server.json", "v07-probe.json"):
            (args.output / name).unlink(missing_ok=True)
        # Combined suites generate each part's keys in its own directory.
        shutil.rmtree(args.output / "parts", ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="host IPv4 address reachable from the iPhone")
    parser.add_argument("--reference-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new private directory")
    parser.add_argument("--seconds", type=int, default=600, help="maximum fixture lifetime (1..1800)")
    parser.add_argument("--protocol", choices=("both", "wireguard", "hysteria2", "v08", *V08_PROTOCOLS, "v09", *V09_PROTOCOLS), default="both")
    parser.add_argument("--port", type=int, help="explicit carrier port; requires a single protocol")
    parser.add_argument("--mode", choices=("smoke", "transitions", "lock-wake", "transitions-reset", "lifecycle", "resources", "udp-sweep"), default="smoke")
    parser.add_argument("--reference-sha256", help="expected binary SHA-256, instead of a clean Go VCS stamp check")
    parser.add_argument("--direct-targets", action="store_true",
                        help="bind pre-provisioned synthetic loopback targets without Freedom redirect")
    args = parser.parse_args()
    if args.direct_targets and args.protocol not in ("both", "wireguard", "hysteria2"):
        parser.error("--direct-targets requires WireGuard or Hysteria")
    address = ipaddress.IPv4Address(args.bind)
    if address.is_unspecified or address.is_multicast or not 1 <= args.seconds <= 1800:
        parser.error("use a specific unicast IPv4 address and 1..1800 seconds")
    if args.port is not None and (args.protocol in ("both", "v08", "v09") or not 1 <= args.port <= 65535):
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
