"""Extend the unchanged device fixture with explicit SS2022/VMess ciphers."""
import base64
import importlib.util
import json
from pathlib import Path
import secrets
import socket
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "device_fixture", ROOT / "scripts/run-v07-apple-protocol-fixture.py"
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
original = fixture.write_client_fixtures


def write(root, bind, tcp_port, udp_port, dns_port, protocol, port, mode, probe_host):
    variants = [
        ("shadowsocks2022", "2022-blake3-aes-128-gcm"),
        ("shadowsocks2022", "2022-blake3-aes-256-gcm"),
        ("vmess", "aes-128-gcm"),
        ("vmess", "chacha20-poly1305"),
    ]
    used, inbounds, cases = set(), [], []
    for fmt, method in variants:
        while True:
            with socket.socket() as tcp:
                tcp.bind((bind, 0))
                selected = tcp.getsockname()[1]
            if selected in used:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind((bind, selected))
            used.add(selected)
            break
        original(root, bind, tcp_port, udp_port, dns_port, fmt, selected, mode, probe_host)
        server = json.loads((root / "server.json").read_text())
        envelope = json.loads((root / "v07-probe.json").read_text())
        case = envelope["cases"][0]
        config = json.loads(case["configJSON"])
        settings = config["outbounds"][0]["settings"]
        if fmt == "shadowsocks2022":
            password = base64.b64encode(secrets.token_bytes(16 if "128" in method else 32)).decode()
            settings.update(method=method, password=password)
            server["inbounds"][0]["settings"].update(method=method, password=password)
            case["text"] = f"ss://{method}:{quote(password, safe='')}@{bind}:{selected}"
        else:
            settings["security"] = method
            link = json.loads(base64.b64decode(case["text"][len("vmess://"):]))
            link["scy"] = method
            case["text"] = "vmess://" + base64.b64encode(json.dumps(link).encode()).decode()
        case["configJSON"] = json.dumps(config)
        cases.append(case)
        inbounds.extend(server["inbounds"])
    server["inbounds"] = inbounds
    envelope["cases"] = cases
    (root / "server.json").write_text(json.dumps(server, indent=2) + "\n")
    (root / "v07-probe.json").write_text(json.dumps(envelope, indent=2) + "\n")
    (root / "case-order.json").write_text(json.dumps(variants, indent=2) + "\n")


fixture.write_client_fixtures = write
fixture.main()
