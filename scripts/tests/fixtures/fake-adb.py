#!/usr/bin/env python3
"""Stand-in for adb in run-v09-android-device-matrix tests.

Emulates the Device Gate and Device Probe status preferences. HTTP outbounds
fail every UDP probe unless FAKE_ADB_HTTP_UDP=leak. Records every argv.
Wi-Fi follows ``svc wifi``: each real change under a running VPN counts one rebind
request unless FAKE_ADB_REBIND=none, restarts the runtime with
FAKE_ADB_REBIND=restart, and with FAKE_ADB_CELLULAR=dead no probe passes while
Wi-Fi is off.
"""
import json
import os
from pathlib import Path
import shlex
import sys

state_path = Path(os.environ["FAKE_ADB_STATE"])
state = json.loads(state_path.read_text()) if state_path.exists() else {
    "host": {"state": "stopped", "detail": ""}, "probe": {"running": False}, "pending": {}, "argv": []}
args = sys.argv[3:]
state["argv"].append(args)
output = ""
if args[0] == "shell":
    command = shlex.split(args[1])
    if command[:2] == ["svc", "wifi"]:
        host, changed = state["host"], state.get("wifi", True) != (command[2] == "enable")
        state["wifi"] = command[2] == "enable"
        if changed and host["state"] == "running" and os.environ.get("FAKE_ADB_REBIND") != "none":
            host["network-rebinds"] = host.get("network-rebinds", 0) + 1
        if changed and host["state"] == "running" and os.environ.get("FAKE_ADB_REBIND") == "restart":
            host["runtime-generation"] = host.get("runtime-generation", 0) + 1
    elif command[:4] == ["settings", "get", "global", "wifi_on"]:
        output = "1\n" if state.get("wifi", True) else "0\n"
    elif command[:3] == ["cmd", "wifi", "status"]:
        output = 'Wifi is enabled\nWifi is connected to "fixture"\n' if state.get("wifi", True) else "Wifi is disabled\n"
    elif command[:1] == ["run-as"]:
        package, action = command[1], command[2:]
        if action[:2] == ["sh", "-c"]:
            state["pending"][action[2].split("/")[-1]] = sys.stdin.read()
        elif action[0] == "sha256sum":
            output = f"{state.get('profile', 'none')}  {action[1]}\n"
        elif action[0] == "cat":
            values = state["host"] if "devicehost" in package else state["probe"]
            rows = []
            for key, value in values.items():
                if isinstance(value, bool):
                    rows.append(f'<boolean name="{key}" value="{str(value).lower()}" />')
                elif isinstance(value, int):
                    rows.append(f'<long name="{key}" value="{value}" />')
                else:
                    rows.append(f'<string name="{key}">{value}</string>')
            output = "<map>" + "".join(rows) + "</map>"
    elif command[:2] == ["am", "start"]:
        package = command[4].split("/")[0]
        name = command[command.index("command") + 1]
        host, probe = state["host"], state["probe"]
        if "devicehost" in package:
            if name == "import-pending":
                link = state["pending"].pop("profile-import.pending")
                if "NONSECRET" in link:
                    host.update(detail="pending-profile-XrayCoreException", state="failed")
                else:
                    host.update(detail="profile-ready", state="stopped")
                    state["profile"] = str(abs(hash(link)))
            elif name == "import-pending-config":
                config = json.loads(state["pending"].pop("profile-config-import.pending"))
                state["protocol"] = config["outbounds"][0]["protocol"]
                host.update(detail="config-profile-ready", state="stopped")
            elif name == "connect":
                host["state"] = "running"
                host["runtime-generation"] = host.get("runtime-generation", 0) + 1
            elif name in ("disconnect", "rapid-stop"):
                host["state"] = "stopped"
        else:
            if name == "reset":
                probe.update({"running": False, "http-passed": 0, "http-failed": 0,
                              "udp-passed": 0, "udp-failed": 0})
            elif name == "start":
                refused = state.get("protocol") == "http" and os.environ.get("FAKE_ADB_HTTP_UDP") != "leak"
                if not state.get("wifi", True) and os.environ.get("FAKE_ADB_CELLULAR") == "dead":
                    probe.update({"running": True, "http-passed": 0, "http-failed": 3,
                                  "udp-passed": 0, "udp-failed": 3})
                else:
                    probe.update({"running": True, "http-passed": 3,
                                  "udp-passed": 0 if refused else 3, "udp-failed": 3 if refused else 0})
            elif name == "stop":
                probe["running"] = False
state_path.write_text(json.dumps(state))
sys.stdout.write(output)
