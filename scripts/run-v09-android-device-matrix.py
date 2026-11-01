#!/usr/bin/env python3
"""Drive the Android Device Gate and Device Probe through a fixture envelope.

Promoted from the 0.8.1 campaign driver (docs/device-results/
2026-10-18-v081-candidate/android/drive.py) with the same adb commands. For
each case and both TUN backends: share-link import (except WireGuard), core
JSON import, connect, IPv4/IPv6/domain traffic, close-connections recovery,
rapid start/stop and restart recovery. Cases with ``udp: false`` (HTTP CONNECT)
must see every UDP probe fail and none pass: a fail-closed negative control,
recorded as ``udp: refused`` under the transition ids ``ipv4-udp-refused`` and
``ipv6-udp-refused`` that the v0.9 profile requires for HTTP, never as UDP
coverage. Each traffic event lists the transitions it evidences. After the matrix, each of
the envelope's ``invalidImports`` must be rejected with the stored profile
ciphertext unchanged, the plaintext removed and the marker absent from the
host's log (the 0.8 controls script, generalized).

Links and configs reach the device through stdin into each app's private
no-backup directory, never through shell arguments. Requires ANDROID_SERIAL;
ADB defaults to ``adb``. Resource and cancellation runs stay separate, as in
the 0.8.1 campaign; this driver produces functional transitions only.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

BACKENDS = ("file-descriptor", "packet-pump")
TARGETS = {"ipv4": "198.51.100.7", "ipv6": "2001:db8::7"}


def traffic_transitions(target, udp_expected):
    """v0.9 profile transition ids one probe step evidences."""
    if target == "domain":
        return ["domain-destination", "routed-dns"]
    return [f"{target}-tcp", f"{target}-udp" + ("" if udp_expected else "-refused")]


class Device:
    def __init__(self, serial, adb, suffix, events):
        self.serial, self.adb, self.events = serial, adb, events
        self.host = "org.xrayrust.devicehost" + suffix
        self.probe = "org.xrayrust.deviceprobe" + suffix
        self.components = {self.host: "org.xrayrust.devicehost.MainActivity",
                           self.probe: "org.xrayrust.deviceprobe.ProbeActivity"}

    def run(self, *args, data=None, check=True):
        result = subprocess.run([self.adb, "-s", self.serial, *args], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30)
        if check and result.returncode:
            raise RuntimeError("adb command failed: " + result.stderr.decode(errors="replace")[-500:])
        return result.stdout.decode(errors="replace")

    def shell(self, *args, **kwargs):
        return self.run("shell", shlex.join(args), **kwargs)

    def command(self, package, name, extras=()):
        return self.shell("am", "start", "-W", "-n", package + "/" + self.components[package],
                          "--es", "command", name, *extras)

    def status(self, package):
        name = "device-gate-status" if package == self.host else "device-probe-status"
        raw = self.shell("run-as", package, "cat", f"shared_prefs/{name}.xml", check=False)
        if not raw.strip():
            return {}
        return {item.attrib["name"]: item.text if item.tag == "string" else item.attrib["value"]
                for item in ET.fromstring(raw)}

    def wait(self, package, ready, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.status(package)
            if ready(value):
                return value
            time.sleep(0.5)
        raise RuntimeError("status deadline: " + json.dumps(self.status(package)))

    def emit(self, kind, **values):
        row = {"hostTime": time.time(), "kind": kind, **values}
        with self.events.open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)

    def install(self, case, link):
        name = "profile-import.pending" if link else "profile-config-import.pending"
        self.shell("run-as", self.host, "mkdir", "-p", "no_backup")
        payload = case["text"] if link else case["configJSON"]
        self.shell("run-as", self.host, "sh", "-c", "cat > no_backup/" + name, data=payload.encode())
        self.command(self.host, "import-pending" if link else "import-pending-config")
        value = self.wait(self.host, lambda s: s.get("detail") in ("profile-ready", "config-profile-ready")
                          or s.get("state") == "failed")
        if value.get("state") == "failed":
            raise RuntimeError("profile rejected: " + json.dumps(value))
        if self.shell("run-as", self.host, "ls", "no_backup/" + name, check=False).strip():
            raise RuntimeError("pending profile plaintext was not removed")

    def start(self, backend):
        self.command(self.host, "connect", ("--es", "tun-backend", backend))
        value = self.wait(self.host, lambda s: s.get("state") in ("running", "failed", "fatal"))
        if value.get("state") != "running":
            raise RuntimeError("VPN did not start: " + json.dumps(value))
        return value

    def stop(self):
        self.command(self.host, "disconnect")
        self.wait(self.host, lambda s: s.get("state") == "stopped")

    def probe_stop(self):
        self.command(self.probe, "stop")
        self.wait(self.probe, lambda s: s.get("running") == "false")
        time.sleep(1)

    def traffic(self, envelope, target, udp_expected, count=3):
        self.command(self.probe, "reset")
        self.wait(self.probe, lambda s: s.get("http-passed") == "0" and s.get("udp-passed") == "0")
        host = TARGETS.get(target, envelope["probeHost"])
        url_host = f"[{host}]" if ":" in host else host
        self.command(self.probe, "start", ("--es", "http-url", f"http://{url_host}:{envelope['tcpPort']}/v08-probe",
                                           "--es", "udp-host", host, "--ei", "udp-port", str(envelope["udpPort"]),
                                           "--el", "interval-seconds", "1"))
        counter = lambda s, key: int(s.get(key, 0))
        if udp_expected:
            done = lambda s: (counter(s, "http-passed") >= count and counter(s, "udp-passed") >= count
                              or counter(s, "http-failed") or counter(s, "udp-failed"))
        else:
            # Each refused datagram waits out the probe's 5 s receive timeout.
            done = lambda s: (counter(s, "http-passed") >= count and counter(s, "udp-failed") >= count
                              or counter(s, "http-failed") or counter(s, "udp-passed"))
        try:
            self.wait(self.probe, done, 25 if udp_expected else 60)
        finally:
            self.probe_stop()
        value = self.status(self.probe)
        if counter(value, "http-failed"):
            raise RuntimeError(f"HTTP failure: {target} {json.dumps(value)}")
        if udp_expected and counter(value, "udp-failed"):
            raise RuntimeError(f"UDP failure: {target} {json.dumps(value)}")
        if not udp_expected and counter(value, "udp-passed"):
            raise RuntimeError(f"UDP answered through an outbound without UDP: {target} {json.dumps(value)}")
        return value


def invalid_imports(device, envelope):
    marker = envelope["redactionMarker"]
    device.stop()
    for item in envelope.get("invalidImports", []):
        digest = lambda: device.shell("run-as", device.host, "sha256sum",
                                      "no_backup/device-gate-profile.bin").split()[0]
        before = digest()
        device.shell("run-as", device.host, "sh", "-c", "cat > no_backup/profile-import.pending",
                     data=item["text"].encode())
        device.command(device.host, "import-pending")
        value = device.wait(device.host, lambda s: s.get("state") == "failed", 10)
        removed = not device.shell("run-as", device.host, "ls", "no_backup/profile-import.pending",
                                   check=False).strip()
        after = digest()
        pid = device.shell("pidof", device.host, check=False).strip()
        log = device.run("logcat", "-d", "-v", "epoch", *(["--pid=" + pid] if pid else []), check=False)
        passed = before == after and removed and marker not in log
        device.emit("invalid-import-control", scenario=item["scenario"], format=item["format"], passed=passed,
                    status=value, profileCiphertextUnchanged=before == after, pendingRemoved=removed,
                    markerAbsentFromHostLog=marker not in log)
        if not passed:
            raise RuntimeError("invalid import/redaction control failed")


def run_case(device, envelope, case, backend):
    identity = {"case": case.get("caseId", case.get("label", case["format"])), "backend": backend}
    udp_expected = case.get("udp", True)
    udp = "echo" if udp_expected else "refused"
    device.emit("case-start", **identity, udp=udp)
    device.stop()
    device.command(device.host, "reset")
    if case["format"] != "wireguard":
        device.install(case, link=True)
        device.emit("share-link-import", **identity, passed=True)
    else:
        device.emit("share-link-import-not-supported", **identity,
                    scope="devicehost automation accepts URI schemes; canonical JSON follows")
    device.install(case, link=False)
    device.emit("running", **identity, status=device.start(backend))
    for target in ("ipv4", "ipv6", "domain"):
        device.emit("traffic", **identity, target=target, udp=udp,
                    transitions=traffic_transitions(target, udp_expected),
                    status=device.traffic(envelope, target, udp_expected))
    device.command(device.host, "close-connections")
    device.emit("close-recovery", **identity, udp=udp, status=device.traffic(envelope, "ipv4", udp_expected, 2))
    device.stop()
    device.command(device.host, "rapid-stop", ("--es", "tun-backend", backend))
    device.wait(device.host, lambda s: s.get("state") == "stopped")
    time.sleep(1)
    if device.status(device.host).get("state") != "stopped":
        raise RuntimeError("rapid stop left the VPN running")
    device.start(backend)
    device.emit("cancel-start-recovery", **identity, udp=udp,
                status=device.traffic(envelope, "ipv4", udp_expected, 2))
    device.stop()
    device.emit("case-pass", **identity, udp=udp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True, help="the fixture's private v07-probe.json")
    parser.add_argument("--work-dir", type=Path, required=True, help="new directory for events and logcat")
    parser.add_argument("--package-suffix", default=".v09", help="deviceGateApplicationIdSuffix of both apps")
    parser.add_argument("--case", action="append", help="limit to these caseIds, in fixture order")
    args = parser.parse_args()
    os.umask(0o077)
    envelope = json.loads(args.fixture.read_text())
    cases = [case for case in envelope["cases"]
             if args.case is None or case.get("caseId", case.get("label", case["format"])) in args.case]
    if args.case and len(cases) != len(set(args.case)):
        parser.error("unknown or duplicate --case")
    args.work_dir.mkdir(parents=True, exist_ok=False)
    device = Device(os.environ["ANDROID_SERIAL"], os.environ.get("ADB", "adb"), args.package_suffix,
                    args.work_dir / "events.jsonl")
    device.emit("matrix-start", caseCount=len(cases), backends=list(BACKENDS))
    for case in cases:
        for backend in BACKENDS:
            try:
                run_case(device, envelope, case, backend)
            except Exception as error:
                device.emit("case-fail", case=case.get("caseId", case["format"]), backend=backend,
                            error=str(error))
                raise
            finally:
                for cleanup in (device.probe_stop, device.stop):
                    try:
                        cleanup()
                    except Exception as error:  # keep the original failure
                        device.emit("cleanup-warning", error=str(error))
                (args.work_dir / "device-logcat.log").write_text(device.run(
                    "logcat", "-d", "-v", "epoch", "-s", "XrayDeviceGate:I", "XrayDeviceProbe:I", "*:S",
                    check=False))
    device.emit("matrix-pass")
    if envelope.get("invalidImports"):
        invalid_imports(device, envelope)
        device.emit("controls-complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
