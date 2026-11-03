#!/usr/bin/env python3
"""v0.9 WAN transitions on the owner's VPS (ssh xray-vps, key auth).

Adapted from docs/device-results/2026-10-18-v081-candidate/ios-wan-manual.py:
same bounded systemd-run unit on the one test port 53053, same automatic stop
and restoration of the two pre-existing test services; x-ui is never touched.
"""
import hashlib, json, os, shlex, subprocess, sys, time
from pathlib import Path

ROOT = Path("<repo>")
OUT = ROOT / "target/release-090/campaign.noindex/ios-wan"; OUT.mkdir(exist_ok=True, mode=0o700)
REMOTE = "/tmp/xray-release-090-wan-30928ad"
REFERENCE = ROOT / "target/release-090/xray-core/xray-linux-amd64"
PIN = "9200fc92278c0f56269c0ee748acfb842c6b138fdfa73117c729e081c72da398"
SERVICES = ["xray-apple-device-probe-server.service", "xray-xhttp-device-test.service"]
PROTOCOLS = ["socks", "http", "https", "shadowsocks-aead"]
DEVICE, BUNDLE = "<iphone-udid>", "org.texforge.XrayClient"
ENV = {**os.environ, "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer"}


def remote(code):
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", "xray-vps", "python3 -c " + shlex.quote(code)],
                       capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise RuntimeError("remote failed: " + p.stderr[-800:])
    return p.stdout


def services():
    return json.loads(remote(
        "import subprocess,json;print(json.dumps({s:subprocess.check_output(['systemctl','show',s,"
        f"'--property=ActiveState,MainPID,SubState'],text=True) for s in {SERVICES + ['x-ui.service']!r}}}))"))


def host():
    for line in subprocess.check_output(["ssh", "-G", "xray-vps"], text=True).splitlines():
        if line.startswith("hostname "):
            return line.split()[1]


def dc(args):
    p = subprocess.run(["xcrun", "devicectl", "device", *args[:2], "--device", DEVICE, "--timeout", "30", *args[2:]],
                       capture_output=True, text=True, timeout=60, env=ENV)
    if p.returncode:
        raise RuntimeError(p.stdout[-400:] + p.stderr[-400:])


action = sys.argv[1]
if action == "bootstrap":
    assert hashlib.sha256(REFERENCE.read_bytes()).hexdigest() == PIN
    before = services()
    assert all("ActiveState=active" in v for v in before.values()), before
    (OUT / "services-before.json").write_text(json.dumps(before, indent=2))
    remote(f"import pathlib;pathlib.Path({REMOTE!r}).mkdir(mode=0o700,exist_ok=False)")
    for source, name in [(REFERENCE, "xray"), (ROOT / "scripts/run-v07-apple-protocol-fixture.py", "fixture.py")]:
        subprocess.run(["scp", "-q", "-o", "BatchMode=yes", str(source), f"xray-vps:{REMOTE}/{name}"], check=True, timeout=300)
    remote(f"import pathlib,hashlib;p=pathlib.Path({REMOTE!r})/'xray';assert hashlib.sha256(p.read_bytes()).hexdigest()=={PIN!r};p.chmod(0o700)")
    print("bootstrapped; services recorded:", {k: v.split()[0] for k, v in before.items()})
elif action == "start":
    protocol = sys.argv[2]; assert protocol in PROTOCOLS
    unit = f"xray-release-090-wan-{protocol}.service"; path = f"{REMOTE}/{protocol}-{int(time.time())}"
    argv = ["systemd-run", "--unit=" + unit, "--property=Type=exec", "--property=RuntimeMaxSec=900",
            "--property=TimeoutStopSec=15", "--property=ExecStartPre=/usr/bin/systemctl stop " + " ".join(SERVICES),
            "--property=ExecStopPost=/usr/bin/systemctl start " + " ".join(SERVICES),
            "python3", f"{REMOTE}/fixture.py", "--bind", host(), "--reference-binary", f"{REMOTE}/xray",
            "--reference-sha256", PIN, "--output", path, "--seconds", "840", "--protocol", protocol,
            "--port", "53053", "--mode", "transitions"]
    code = f'''import subprocess,time,pathlib,json
p=subprocess.run({argv!r},text=True,capture_output=True);assert p.returncode==0,p.stderr
path=pathlib.Path({path!r})/'v07-probe.json'
for _ in range(60):
    if path.exists():break
    time.sleep(0.5)
assert path.exists(),subprocess.check_output(['journalctl','-u',{unit!r},'-n','30','--no-pager'],text=True)
time.sleep(1)
assert subprocess.check_output(['systemctl','is-active',{unit!r}],text=True).strip()=='active'
print(path.read_text())
'''
    value = json.loads(remote(code))
    target = OUT / f"{protocol}-input.json"; target.write_text(json.dumps(value, indent=2)); target.chmod(0o600)
    (OUT / f"{protocol}-plan.json").write_text(json.dumps({
        "protocol": protocol, "unit": unit, "remotePath": path, "start": time.time(), "port": 53053,
        "referenceSha256": PIN, "referenceCommit": "1b1647cd9ddf0abc34b981d4611fc03bcac1ca74",
        "candidate": "30928ad51b4a434546cf143f8e385a8746523172", "automaticRestoration": SERVICES,
        "fixtureSeconds": 840, "unitRuntimeMaxSeconds": 900, "mode": "transitions"}, indent=2))
    print(protocol, "WAN fixture ready; bounded lifetime and automatic restoration enabled.")
elif action == "start-socks-container":
    # SOCKS over WAN: Xray-core binds one UDP relay port per association, so the
    # fixture runs in a container whose ephemeral range is 53060-53069 (UDP
    # opened by the owner); only TCP 53053 and those UDP ports are published.
    protocol = "socks"; unit = "xray-release-090-wan-socks.service"; path = f"{REMOTE}/socks-{int(time.time())}"
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", str(Path(__file__).with_name("fixture_container.py")),
                    f"xray-vps:{REMOTE}/fixture_container.py"], check=True, timeout=120)
    image = "python:3.12-slim"
    remote(f"import subprocess;subprocess.run(['docker','pull','-q',{image!r}],check=True,capture_output=True)")
    inner = (f"exec python3 {REMOTE}/fixture_container.py --bind \"$(hostname -i | cut -d' ' -f1)\" "
             f"--reference-binary {REMOTE}/xray --reference-sha256 {PIN} --output {path} --seconds 840 "
             f"--protocol socks --port 53053 --mode transitions")
    docker = ["docker", "run", "--rm", "--name", "xray-wan-socks", "--sysctl", "net.ipv4.ip_local_port_range=53060 53069",
              "-p", "53053:53053/tcp", "-p", "53060-53069:53060-53069/udp", "-v", f"{REMOTE}:{REMOTE}",
              "-e", f"XRAY_FIXTURE_ADVERTISE={host()}", image, "sh", "-c", inner]
    argv = ["systemd-run", "--unit=" + unit, "--property=Type=exec", "--property=RuntimeMaxSec=900",
            "--property=TimeoutStopSec=20", "--property=ExecStartPre=/usr/bin/systemctl stop " + " ".join(SERVICES),
            "--property=ExecStopPost=-/usr/bin/docker rm -f xray-wan-socks",
            "--property=ExecStopPost=/usr/bin/systemctl start " + " ".join(SERVICES), *docker]
    code = f'''import subprocess,time,pathlib,json
p=subprocess.run({argv!r},text=True,capture_output=True);assert p.returncode==0,p.stderr
path=pathlib.Path({path!r})/'v07-probe.json'
for _ in range(90):
    if path.exists():break
    time.sleep(0.5)
assert path.exists(),subprocess.check_output(['journalctl','-u',{unit!r},'-n','30','--no-pager'],text=True)
time.sleep(1)
assert subprocess.check_output(['systemctl','is-active',{unit!r}],text=True).strip()=='active'
print(path.read_text())
'''
    value = json.loads(remote(code))
    target = OUT / "socks-input.json"; target.write_text(json.dumps(value, indent=2)); target.chmod(0o600)
    (OUT / "socks-plan.json").write_text(json.dumps({
        "protocol": protocol, "unit": unit, "remotePath": path, "start": time.time(), "port": 53053,
        "container": {"image": image, "ephemeralPortRange": "53060-53069", "published": ["53053/tcp", "53060-53069/udp"],
                      "socksUdpAssociateIp": "0.0.0.0"},
        "referenceSha256": PIN, "referenceCommit": "1b1647cd9ddf0abc34b981d4611fc03bcac1ca74",
        "candidate": "30928ad51b4a434546cf143f8e385a8746523172", "automaticRestoration": SERVICES,
        "fixtureSeconds": 840, "unitRuntimeMaxSeconds": 900, "mode": "transitions"}, indent=2))
    print("socks container WAN fixture ready; bounded lifetime and automatic restoration enabled.")
elif action == "launch":
    protocol = sys.argv[2]
    dc(["copy", "to", "--source", str(OUT / f"{protocol}-input.json"), "--destination", "Documents/v07-probe.json",
        "--domain-type", "appDataContainer", "--domain-identifier", BUNDLE])
    after = time.time()
    dc(["process", "launch", "--terminate-existing", "--environment-variables", '{"XRAY_V07_DEVICE_PROBE":"1"}',
        "--json-output", str(OUT / f"{protocol}-launch.json"), BUNDLE])
    (OUT / "active.json").write_text(json.dumps({"name": protocol, "after": after}))
    print("Started iPhone", protocol, "transitions probe.")
elif action == "collect":
    active = json.loads((OUT / "active.json").read_text()); name = active["name"]; dest = OUT / f"{name}-result.json"
    dc(["copy", "from", "--source", "Documents/v07-result.json", "--destination", str(dest),
        "--domain-type", "appDataContainer", "--domain-identifier", BUNDLE])
    rows = json.loads(dest.read_text())
    important = [v for v in rows if v.get("event") in ("action-required", "transition-recovered", "transition-failed",
                 "lock-interval", "failure", "complete", "recovery-retry", "carrier", "carrier-route", "locked", "unlocked")]
    print(json.dumps({"name": name, "events": len(rows), "important": important[-12:], "last": rows[-1]}, ensure_ascii=False, indent=1))
elif action == "stop":
    protocol = sys.argv[2]; plan = json.loads((OUT / f"{protocol}-plan.json").read_text())
    remote(f"import subprocess;subprocess.run(['systemctl','stop',{plan['unit']!r}],check=True);subprocess.run(['systemctl','reset-failed',{plan['unit']!r}])")
    time.sleep(2)
    after = services(); (OUT / f"{protocol}-services-restored.json").write_text(json.dumps(after, indent=2))
    assert all("ActiveState=active" in v for v in after.values()), after
    print(protocol, "stopped; services:", {k: v.split()[0] for k, v in after.items()})
elif action == "cleanup":
    remote(f"import shutil,pathlib;p=pathlib.Path({REMOTE!r});shutil.rmtree(p) if p.exists() else None;print('removed')")
    after = services(); (OUT / "services-after-cleanup.json").write_text(json.dumps(after, indent=2))
    print({k: v.split() for k, v in after.items()})
