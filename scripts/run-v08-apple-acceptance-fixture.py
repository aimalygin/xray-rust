#!/usr/bin/env python3
"""Additional ephemeral cipher and legacy fixtures for the Apple DEBUG probe.

Same safety/identity/lifetime rules as run-v07-apple-protocol-fixture.py.
The REALITY decoy uses a TLS handshake with www.google.com:443; application
traffic is restricted to local synthetic echo/DNS targets by server routing.
"""
import argparse
import base64
import copy
import importlib.util
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import uuid
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("device_fixture", ROOT / "scripts/run-v07-apple-protocol-fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
original = fixture.write_fixtures


def reserve(bind, used):
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
    raise RuntimeError("no available TCP/UDP port")


def write_ciphers(root, bind, tcp_port, udp_port, dns_port, **kwargs):
    variants = [("shadowsocks2022", "2022-blake3-aes-128-gcm"),
                ("shadowsocks2022", "2022-blake3-aes-256-gcm"),
                ("vmess", "aes-128-gcm"), ("vmess", "chacha20-poly1305")]
    used, inbounds, cases = set(), [], []
    for fmt, method in variants:
        port = reserve(bind, used)
        original(root, bind, tcp_port, udp_port, dns_port, **{**kwargs, "protocol": fmt, "port": port})
        server = json.loads((root / "server.json").read_text())
        envelope = json.loads((root / "v07-probe.json").read_text())
        case = envelope["cases"][0]
        config = json.loads(case["configJSON"])
        settings = config["outbounds"][0]["settings"]
        if fmt == "shadowsocks2022":
            password = base64.b64encode(secrets.token_bytes(16 if "128" in method else 32)).decode()
            settings.update(method=method, password=password)
            server["inbounds"][0]["settings"].update(method=method, password=password)
            case["text"] = f"ss://{method}:{quote(password, safe='')}@{bind}:{port}"
        else:
            settings["security"] = method
            link = json.loads(base64.b64decode(case["text"][len("vmess://"):]))
            link["scy"] = method
            case["text"] = "vmess://" + base64.b64encode(json.dumps(link).encode()).decode()
        case["label"] = f"{fmt}:{method}"
        case["configJSON"] = json.dumps(config)
        cases.append(case)
        inbounds.extend(server["inbounds"])
    server["inbounds"], envelope["cases"] = inbounds, cases
    save(root, server, envelope)


def write_legacy(root, bind, tcp_port, udp_port, dns_port, **kwargs):
    original(root, bind, tcp_port, udp_port, dns_port, **{**kwargs, "protocol": "trojan", "port": None})
    server = json.loads((root / "server.json").read_text())
    envelope = json.loads((root / "v07-probe.json").read_text())
    config = json.loads(envelope["cases"][0]["configJSON"])
    tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
    certificate = server["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"]
    server["inbounds"], envelope["cases"] = [], []
    used = set()
    for name, alpn, mode in [("vless-reality", None, None), ("xhttp-h1", "http/1.1", "packet-up"),
                             ("xhttp-h2", "h2", "stream-up"), ("xhttp-h3", "h3", "stream-one")]:
        port, user = reserve(bind, used), str(uuid.uuid4())
        client_user = {"id": user, "encryption": "none"}
        server_user = {"id": user}
        query = {"encryption": "none"}
        if alpn:
            stream = {"network": "xhttp", "security": "tls", "tlsSettings": {**tls, "alpn": [alpn]},
                      "xhttpSettings": {"path": "/device-check", "mode": mode}}
            inbound_stream = {"network": "xhttp", "security": "tls", "tlsSettings": {
                "alpn": [alpn], "certificates": certificate}, "xhttpSettings": {"path": "/device-check", "mode": "auto"}}
            if alpn == "h3":
                stream["finalmask"] = {"quicParams": {}}
            query.update(type="xhttp", security="tls", sni=tls["serverName"], alpn=alpn, path="/device-check", mode=mode)
        else:
            private = subprocess.check_output(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"], stderr=subprocess.DEVNULL)
            public = subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=private, stderr=subprocess.DEVNULL)
            encode = lambda value: base64.urlsafe_b64encode(value[-32:]).decode().rstrip("=")
            short = secrets.token_hex(8)
            client_user["flow"] = server_user["flow"] = "xtls-rprx-vision"
            reality = {"serverName": "www.google.com", "fingerprint": "chrome", "publicKey": encode(public), "shortId": short}
            stream = {"network": "raw", "security": "reality", "realitySettings": reality}
            inbound_stream = {"network": "raw", "security": "reality", "realitySettings": {
                "dest": "www.google.com:443", "serverNames": ["www.google.com"], "privateKey": encode(private), "shortIds": [short]}}
            query.update(type="tcp", security="reality", sni="www.google.com", fp="chrome", pbk=encode(public), sid=short, flow="xtls-rprx-vision")
        server["inbounds"].append({"listen": bind, "port": port, "protocol": "vless",
            "settings": {"clients": [server_user], "decryption": "none"}, "streamSettings": inbound_stream})
        current = copy.deepcopy(config)
        current["outbounds"] = [{"tag": "proxy", "protocol": "vless", "settings": {"vnext": [
            {"address": bind, "port": port, "users": [client_user]}]}, "streamSettings": stream}]
        envelope["cases"].append({"format": "vless", "label": name,
            "text": f"vless://{user}@{bind}:{port}?{urlencode(query)}", "serverAddress": bind, "configJSON": json.dumps(current)})
    save(root, server, envelope)


def save(root, server, envelope):
    (root / "server.json").write_text(json.dumps(server, indent=2) + "\n")
    (root / "v07-probe.json").write_text(json.dumps(envelope, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--suite", choices=("ciphers", "legacy"), default="ciphers")
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    fixture.write_fixtures = write_ciphers if args.suite == "ciphers" else write_legacy
    fixture.main()
