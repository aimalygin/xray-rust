#!/usr/bin/env python3
"""Campaign wrapper: run run-v07-apple-protocol-fixture.py inside a container
whose ephemeral port range is narrowed (docker --sysctl), so Xray-core's SOCKS
UDP ASSOCIATE relay ports (one per association, bound with port 0) fall in a
small range the owner opened on the VPS firewall.

The fixture binds the container address (--bind); clients get the public
address (XRAY_FIXTURE_ADVERTISE). The SOCKS inbound answers UDP ASSOCIATE with
"ip": "0.0.0.0", so Xray binds the relay on all addresses and replies with an
unspecified BND.ADDR, which RFC 1928 clients replace with the server address.
"""
import importlib.util, json, os, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("fixture", str(Path(__file__).with_name("fixture.py")))
fx = importlib.util.module_from_spec(spec); spec.loader.exec_module(fx)
ADVERTISE = os.environ["XRAY_FIXTURE_ADVERTISE"]
original = fx.write_client_fixtures


def write_client_fixtures(root, bind, *args, **kwargs):
    original(root, bind, *args, **kwargs)
    server = json.loads((root / "server.json").read_text())
    for inbound in server["inbounds"]:
        if inbound["protocol"] == "socks":
            inbound["settings"]["ip"] = "0.0.0.0"
    (root / "server.json").write_text(json.dumps(server, indent=2) + "\n")
    envelope = json.loads((root / "v07-probe.json").read_text())
    for case in envelope["cases"] + envelope.get("invalidImports", []):
        for key in ("text", "serverAddress", "configJSON"):
            if key in case:
                case[key] = case[key].replace(bind, ADVERTISE)
    (root / "v07-probe.json").write_text(json.dumps(envelope, indent=2) + "\n")


fx.write_client_fixtures = write_client_fixtures
fx.main()
